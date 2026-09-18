//! Accept explicit changed-file hints (task B-032).
//!
//! docs/16-CLI-AND-CONTROL-API.md section 2 lists `changed` as a *hint* surface
//! (`hint only; daemon verifies actual source`), and
//! docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md section 7 records the same rule for
//! the queue: a watcher event, an editor plugin, a Git hook or a human script
//! never becomes a graph fact on its own. This module therefore does two
//! separate things and keeps them separate on purpose:
//!
//! * it validates that the caller may speak about a solution and a project at
//!   all, and that every hinted path is a bounded repository-relative path that
//!   lies inside the registered project root;
//! * it then reads the *actual* bytes from the bound worktree and records the
//!   digest it observed there.
//!
//! The caller can supply a reason and a path list, but never a digest: the
//! report carries only what the filesystem said, so a stale or forged hint
//! cannot claim a content identity. A hint that points at a missing or
//! unreadable file is still reported, as `missing` or `unreadable` - never as
//! `observed`.
//!
//! Registration and filesystem access are injected ([`ProjectRegistry`],
//! [`SourceReader`]) so the policy is unit testable, while
//! [`StoreRegistry`] and [`StdSourceReader`] are the production adapters used by
//! the CLI surface of the later command work package.

use std::collections::BTreeSet;
use std::path::Path;

use graph_core::bindings::{
    resolve_binding, resolve_project_root, CatalogRepoReference, LocalBinding, SymlinkProbe,
};
use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{validate_portable_relative_path, WHOLE_REPO_BINDING};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Upper bound on the number of paths one hint request may carry.
pub const MAX_HINTS_PER_REQUEST: usize = 4096;
/// Upper bound on the size of a `--from-json` hint document.
pub const MAX_HINT_DOCUMENT_BYTES: usize = 1_048_576;
/// Reason recorded for a hint a human script submitted by hand.
pub const REASON_MANUAL: &str = "manual";
/// Reason recorded for a hint derived from Git worktree state.
pub const REASON_GIT: &str = "git";
/// Reason recorded for a hint submitted by an editor or build tool.
pub const REASON_TOOL: &str = "tool";
/// Reason recorded for a hint produced by the watcher itself.
pub const REASON_RECONCILE: &str = "reconcile";
/// The closed set of hint reasons.
pub const REASONS: &[&str] = &[REASON_MANUAL, REASON_GIT, REASON_TOOL, REASON_RECONCILE];
/// Reason recorded when a caller names a reason the contract does not define.
pub const REASON_UNKNOWN_HINT_REASON: &str = "unknown-hint-reason";
/// Reason recorded when a hint document is not a bounded JSON object.
pub const REASON_HINT_DOCUMENT_INVALID: &str = "hint-document-invalid";
/// Reason recorded when a hint document exceeds [`MAX_HINT_DOCUMENT_BYTES`].
pub const REASON_HINT_DOCUMENT_TOO_LARGE: &str = "hint-document-too-large";
/// Reason recorded for an empty hint batch.
pub const REASON_EMPTY_HINT_BATCH: &str = "empty-hint-batch";
/// Reason recorded for a hint batch over [`MAX_HINTS_PER_REQUEST`].
pub const REASON_HINT_BATCH_TOO_LARGE: &str = "hint-batch-too-large";
/// Reason recorded for the same path appearing twice in one request.
pub const REASON_DUPLICATE_HINT_PATH: &str = "duplicate-hint-path";
/// Reason recorded when a hint names the project root instead of a file.
pub const REASON_HINT_TARGETS_PROJECT_ROOT: &str = "hint-targets-project-root";
/// Reason recorded when a hinted path lies outside the registered project root.
pub const REASON_HINT_OUTSIDE_PROJECT: &str = "hint-outside-project";
/// Reason recorded when a JSON document names a different solution.
pub const REASON_SOLUTION_SCOPE_MISMATCH: &str = "solution-scope-mismatch";
/// Reason recorded when a JSON document names a different project.
pub const REASON_PROJECT_SCOPE_MISMATCH: &str = "project-scope-mismatch";
/// Reason recorded when a JSON document names a different reason.
pub const REASON_REASON_SCOPE_MISMATCH: &str = "reason-scope-mismatch";
/// Reason recorded when a solution has no registration row.
pub const REASON_SOLUTION_NOT_REGISTERED: &str = "solution-not-registered";
/// Reason recorded when a project id is not registered at all.
pub const REASON_PROJECT_NOT_REGISTERED: &str = "project-not-registered";
/// Reason recorded when a project belongs to a different solution.
pub const REASON_PROJECT_NOT_IN_SOLUTION: &str = "project-not-in-solution";

/// Whether `reason` is one of the closed set in [`REASONS`].
#[must_use]
pub fn is_known_reason(reason: &str) -> bool {
    REASONS.contains(&reason)
}

/// The registration facts one hint needs about a project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectScope {
    solution_id: String,
    project_id: String,
    repo_id: String,
    relative_root: String,
    resolved_root: String,
}

impl ProjectScope {
    /// Build a validated scope from a registration row and a resolved root.
    #[must_use]
    pub fn new(
        solution_id: impl Into<String>,
        project_id: impl Into<String>,
        repo_id: impl Into<String>,
        relative_root: impl Into<String>,
        resolved_root: impl Into<String>,
    ) -> Self {
        Self {
            solution_id: solution_id.into(),
            project_id: project_id.into(),
            repo_id: repo_id.into(),
            relative_root: relative_root.into(),
            resolved_root: resolved_root.into(),
        }
    }

    /// Owning solution.
    #[must_use]
    pub fn solution_id(&self) -> &str {
        &self.solution_id
    }

    /// Registered project id.
    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Repository id the project is bound to.
    #[must_use]
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    /// Repository-relative project root.
    #[must_use]
    pub fn relative_root(&self) -> &str {
        &self.relative_root
    }

    /// Absolute project root once the trusted binding is applied.
    #[must_use]
    pub fn resolved_root(&self) -> &str {
        &self.resolved_root
    }
}

/// Where a project's trusted scope comes from.
pub trait ProjectRegistry {
    /// Resolve `project_id` inside `solution_id`.
    ///
    /// # Errors
    /// Implementations refuse an unregistered solution or project instead of
    /// guessing a scope.
    fn scope(&self, solution_id: &str, project_id: &str) -> Result<ProjectScope, AxiomError>;
}

/// What the filesystem said about one hinted path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceState {
    /// The file exists and its bytes were read.
    Bytes(Vec<u8>),
    /// No such file.
    Missing,
    /// The path exists or may exist but could not be read.
    Unreadable,
}

/// Reads the real source bytes a hint refers to.
pub trait SourceReader {
    /// Observe `path` as it is now, never as the caller claimed it was.
    fn read(&self, path: &Path) -> SourceState;
}

/// The verified outcome of one hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HintOutcome {
    /// The file was read and its digest recorded.
    Observed,
    /// The hint points at a file that is not there.
    Missing,
    /// The hint points at a path that could not be read.
    Unreadable,
}

/// One hint, restated as the filesystem reported it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedHint {
    path: String,
    outcome: HintOutcome,
    content_hash: Option<String>,
}

impl VerifiedHint {
    /// Repository-relative path the caller hinted.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// What was observed on disk.
    #[must_use]
    pub const fn outcome(&self) -> HintOutcome {
        self.outcome
    }

    /// Digest read from disk, or `None` when nothing could be read.
    #[must_use]
    pub fn content_hash(&self) -> Option<&str> {
        self.content_hash.as_deref()
    }
}

/// The bounded result of one hint request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HintReport {
    solution_id: String,
    project_id: String,
    reason: String,
    hint_only: bool,
    hints: Vec<VerifiedHint>,
    observed: usize,
    missing: usize,
    unreadable: usize,
}

impl HintReport {
    /// Owning solution.
    #[must_use]
    pub fn solution_id(&self) -> &str {
        &self.solution_id
    }

    /// Registered project.
    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Reason the caller recorded.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Always `true`: this report is a hint, not a graph fact.
    #[must_use]
    pub const fn is_hint_only(&self) -> bool {
        self.hint_only
    }

    /// Verified hints, in request order.
    #[must_use]
    pub fn hints(&self) -> &[VerifiedHint] {
        &self.hints
    }

    /// Count of hints whose bytes were read.
    #[must_use]
    pub const fn observed(&self) -> usize {
        self.observed
    }

    /// Count of hints that pointed at a missing file.
    #[must_use]
    pub const fn missing(&self) -> usize {
        self.missing
    }

    /// Count of hints that could not be read.
    #[must_use]
    pub const fn unreadable(&self) -> usize {
        self.unreadable
    }
}

/// One validated hint request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeHintRequest {
    solution_id: String,
    project_id: String,
    reason: String,
    paths: Vec<String>,
}

impl ChangeHintRequest {
    /// Build a request, defaulting the reason to [`REASON_MANUAL`].
    #[must_use]
    pub fn new(
        solution_id: impl Into<String>,
        project_id: impl Into<String>,
        reason: Option<&str>,
        paths: Vec<String>,
    ) -> Self {
        Self {
            solution_id: solution_id.into(),
            project_id: project_id.into(),
            reason: reason.unwrap_or(REASON_MANUAL).to_string(),
            paths,
        }
    }

    /// Owning solution.
    #[must_use]
    pub fn solution_id(&self) -> &str {
        &self.solution_id
    }

    /// Registered project.
    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Recorded reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Hinted repository-relative paths.
    #[must_use]
    pub fn paths(&self) -> &[String] {
        &self.paths
    }

    /// Read a bounded batch document and reconcile it with the CLI selection.
    ///
    /// A document may carry `solution_id`, `project_id`, `reason` and `paths`.
    /// Anything the document states must agree with what the caller already
    /// selected; a disagreement is refused rather than silently resolved in
    /// favour of one side.
    ///
    /// # Errors
    /// - [`ErrorCode::ValidationError`] for an oversized, malformed or empty
    ///   document.
    /// - [`ErrorCode::Forbidden`] when the document names another solution.
    /// - [`ErrorCode::Conflict`] when the document names another project or
    ///   reason.
    pub fn from_json(
        document: &str,
        solution_id: &str,
        project_id: Option<&str>,
        reason: Option<&str>,
    ) -> Result<Self, AxiomError> {
        if document.len() > MAX_HINT_DOCUMENT_BYTES {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "the hint document exceeds the bounded size",
            )
            .with_detail("rule", REASON_HINT_DOCUMENT_TOO_LARGE)
            .with_detail("limit", MAX_HINT_DOCUMENT_BYTES.to_string())
            .with_detail("observed", document.len().to_string()));
        }
        let parsed: HintDocument = serde_json::from_str(document).map_err(|_| {
            AxiomError::new(
                ErrorCode::ValidationError,
                "the hint document is not a JSON object with a path list",
            )
            .with_detail("rule", REASON_HINT_DOCUMENT_INVALID)
        })?;
        if let Some(declared) = parsed.solution_id.as_deref() {
            if declared != solution_id {
                return Err(AxiomError::new(
                    ErrorCode::Forbidden,
                    "the hint document names a different solution",
                )
                .with_detail("rule", REASON_SOLUTION_SCOPE_MISMATCH)
                .with_detail("solution_id", solution_id)
                .with_detail("actual", declared));
            }
        }
        if let (Some(selected), Some(declared)) = (project_id, parsed.project_id.as_deref()) {
            if selected != declared {
                return Err(AxiomError::new(
                    ErrorCode::Conflict,
                    "the hint document names a different project",
                )
                .with_detail("rule", REASON_PROJECT_SCOPE_MISMATCH)
                .with_detail("project_id", selected)
                .with_detail("actual", declared));
            }
        }
        let project = match parsed.project_id {
            Some(declared) => declared,
            None => match project_id {
                Some(selected) => selected.to_string(),
                None => {
                    return Err(AxiomError::new(
                        ErrorCode::ValidationError,
                        "the hint document must name a project",
                    )
                    .with_detail("rule", REASON_HINT_DOCUMENT_INVALID));
                }
            },
        };
        if let (Some(selected), Some(declared)) = (reason, parsed.reason.as_deref()) {
            if selected != declared {
                return Err(AxiomError::new(
                    ErrorCode::Conflict,
                    "the hint document names a different reason",
                )
                .with_detail("rule", REASON_REASON_SCOPE_MISMATCH)
                .with_detail("actual", declared)
                .with_detail("expected", selected));
            }
        }
        let reason = match parsed.reason {
            Some(declared) => declared,
            None => reason.unwrap_or(REASON_MANUAL).to_string(),
        };
        Ok(Self {
            solution_id: solution_id.to_string(),
            project_id: project,
            reason,
            paths: parsed.paths,
        })
    }

    /// Validate the request against a registration and the real filesystem.
    ///
    /// # Errors
    /// - [`ErrorCode::ValidationError`] for an unknown reason, an empty or
    ///   oversized batch, a duplicate path or a path that is not a portable
    ///   repository-relative path.
    /// - [`ErrorCode::NotFound`] / [`ErrorCode::Forbidden`] from the registry
    ///   when the solution or project is not registered for this caller.
    /// - [`ErrorCode::Forbidden`] when a hinted path lies outside the
    ///   registered project root.
    pub fn accept(
        &self,
        registry: &dyn ProjectRegistry,
        reader: &dyn SourceReader,
    ) -> Result<HintReport, AxiomError> {
        if !is_known_reason(&self.reason) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "the hint reason is not one of the contract reasons",
            )
            .with_detail("rule", REASON_UNKNOWN_HINT_REASON)
            .with_detail("actual", &self.reason)
            .with_detail("expected", REASONS.join("|")));
        }
        if self.paths.is_empty() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a hint request must carry at least one path",
            )
            .with_detail("rule", REASON_EMPTY_HINT_BATCH));
        }
        if self.paths.len() > MAX_HINTS_PER_REQUEST {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "the hint batch exceeds the bounded size",
            )
            .with_detail("rule", REASON_HINT_BATCH_TOO_LARGE)
            .with_detail("limit", MAX_HINTS_PER_REQUEST.to_string())
            .with_detail("observed", self.paths.len().to_string()));
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for path in &self.paths {
            if path == WHOLE_REPO_BINDING {
                return Err(AxiomError::new(
                    ErrorCode::ValidationError,
                    "a hint must name a file inside the project, not the project root",
                )
                .with_detail("rule", REASON_HINT_TARGETS_PROJECT_ROOT)
                .with_detail("portable_path", path));
            }
            validate_portable_relative_path(path)?;
            if !seen.insert(path.as_str()) {
                return Err(AxiomError::new(
                    ErrorCode::ValidationError,
                    "the hint request names the same path twice",
                )
                .with_detail("rule", REASON_DUPLICATE_HINT_PATH)
                .with_detail("portable_path", path));
            }
        }

        let scope = registry.scope(&self.solution_id, &self.project_id)?;
        let mut hints: Vec<VerifiedHint> = Vec::with_capacity(self.paths.len());
        let (mut observed, mut missing, mut unreadable) = (0_usize, 0_usize, 0_usize);
        for path in &self.paths {
            let Some(remainder) = project_relative(scope.relative_root(), path) else {
                return Err(AxiomError::new(
                    ErrorCode::Forbidden,
                    "the hinted path lies outside the registered project root",
                )
                .with_detail("rule", REASON_HINT_OUTSIDE_PROJECT)
                .with_detail("solution_id", &self.solution_id)
                .with_detail("project_id", &self.project_id)
                .with_detail("portable_path", path));
            };
            if remainder.is_empty() {
                return Err(AxiomError::new(
                    ErrorCode::ValidationError,
                    "a hint must name a file inside the project, not the project root",
                )
                .with_detail("rule", REASON_HINT_TARGETS_PROJECT_ROOT)
                .with_detail("portable_path", path));
            }
            // The hint path is repository-relative and the resolved root already
            // ends at the project, so the project's own prefix is removed here
            // rather than appended twice (docs/16 section 8).
            let absolute = join(scope.resolved_root(), &remainder);
            let (outcome, content_hash) = match reader.read(Path::new(&absolute)) {
                SourceState::Bytes(bytes) => {
                    observed += 1;
                    (
                        HintOutcome::Observed,
                        Some(graph_watch::inventory::content_digest(&bytes)),
                    )
                }
                SourceState::Missing => {
                    missing += 1;
                    (HintOutcome::Missing, None)
                }
                SourceState::Unreadable => {
                    unreadable += 1;
                    (HintOutcome::Unreadable, None)
                }
            };
            hints.push(VerifiedHint {
                path: path.clone(),
                outcome,
                content_hash,
            });
        }

        Ok(HintReport {
            solution_id: self.solution_id.clone(),
            project_id: self.project_id.clone(),
            reason: self.reason.clone(),
            hint_only: true,
            hints,
            observed,
            missing,
            unreadable,
        })
    }
}

#[derive(Deserialize)]
struct HintDocument {
    #[serde(default)]
    solution_id: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
}

/// A project registry backed by the durable registration rows and the trusted
/// operator bindings document.
///
/// The project row supplies `repo_id` and the repository-relative root; the
/// binding supplies the absolute local root. Both must exist, so a hint can
/// never address a directory the operator has not bound.
pub struct StoreRegistry<'a> {
    connection: &'a Connection,
    bindings: Vec<LocalBinding>,
    probe: &'a dyn SymlinkProbe,
}

impl<'a> StoreRegistry<'a> {
    /// Bind a registry to one connection and one validated binding table.
    ///
    /// # Errors
    /// The same errors as [`graph_core::bindings::validate_bindings`].
    pub fn new(
        connection: &'a Connection,
        bindings: Vec<LocalBinding>,
        probe: &'a dyn SymlinkProbe,
    ) -> Result<Self, AxiomError> {
        graph_core::bindings::validate_bindings(&bindings)?;
        Ok(Self {
            connection,
            bindings,
            probe,
        })
    }
}

impl ProjectRegistry for StoreRegistry<'_> {
    fn scope(&self, solution_id: &str, project_id: &str) -> Result<ProjectScope, AxiomError> {
        let solution_exists: Option<i64> = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM solutions WHERE id = ?1",
                [solution_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| crate::commands::storage_error("solution lookup", &error))?;
        if solution_exists.unwrap_or(0) == 0 {
            return Err(AxiomError::new(
                ErrorCode::NotFound,
                "the solution is not registered on this host",
            )
            .with_detail("rule", REASON_SOLUTION_NOT_REGISTERED)
            .with_detail("solution_id", solution_id));
        }

        let row: Option<(String, String, String)> = self
            .connection
            .query_row(
                "SELECT p.solution_id, p.repo_id, p.relative_path FROM projects p \
                 WHERE p.id = ?1",
                [project_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| crate::commands::storage_error("project lookup", &error))?;
        let Some((owner, repo_id, relative_path)) = row else {
            return Err(AxiomError::new(
                ErrorCode::NotFound,
                "the project is not registered on this host",
            )
            .with_detail("rule", REASON_PROJECT_NOT_REGISTERED)
            .with_detail("project_id", project_id)
            .with_detail("solution_id", solution_id));
        };
        if owner != solution_id {
            return Err(AxiomError::new(
                ErrorCode::Forbidden,
                "the project belongs to a different solution",
            )
            .with_detail("rule", REASON_PROJECT_NOT_IN_SOLUTION)
            .with_detail("project_id", project_id)
            .with_detail("solution_id", solution_id)
            .with_detail("actual", &owner));
        }

        // The registration row is the catalog reference: it is the only place a
        // `repo_id` becomes usable, so the binding lookup is authoritative and
        // never guesses a path from the id.
        let catalog = [CatalogRepoReference::new(repo_id.clone())];
        let binding = resolve_binding(&self.bindings, &catalog, &repo_id, self.probe)?;
        let resolved_root = resolve_project_root(&binding, &relative_path, self.probe)?;
        Ok(ProjectScope::new(
            solution_id,
            project_id,
            repo_id,
            relative_path,
            resolved_root,
        ))
    }
}

/// A bounded local binding document in the shape of
/// `examples/config/bindings.example.json`.
pub struct BindingsDocument;

impl BindingsDocument {
    /// Parse the owner-only bindings document into a binding table.
    ///
    /// # Errors
    /// - [`ErrorCode::ValidationError`] for an oversized or malformed document.
    /// - [`ErrorCode::ConfigInvalid`] for a relative or unsafe bound root.
    /// - [`ErrorCode::Conflict`] for a duplicated alias.
    pub fn parse(document: &str) -> Result<Vec<LocalBinding>, AxiomError> {
        if document.len() > MAX_HINT_DOCUMENT_BYTES {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "the bindings document exceeds the bounded size",
            )
            .with_detail("rule", REASON_HINT_DOCUMENT_TOO_LARGE)
            .with_detail("limit", MAX_HINT_DOCUMENT_BYTES.to_string()));
        }
        let parsed: BindingsFile = serde_json::from_str(document).map_err(|_| {
            AxiomError::new(
                ErrorCode::ValidationError,
                "the bindings document is not a JSON object",
            )
            .with_detail("rule", REASON_HINT_DOCUMENT_INVALID)
        })?;
        let mut bindings: Vec<LocalBinding> = Vec::with_capacity(parsed.bindings.len());
        for (alias, root) in parsed.bindings {
            bindings.push(LocalBinding::new(alias, root));
        }
        graph_core::bindings::validate_bindings(&bindings)?;
        Ok(bindings)
    }
}

#[derive(Deserialize)]
struct BindingsFile {
    #[serde(default)]
    bindings: std::collections::BTreeMap<String, String>,
}

/// The host filesystem, read-only.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdSourceReader;

impl SourceReader for StdSourceReader {
    fn read(&self, path: &Path) -> SourceState {
        match std::fs::read(path) {
            Ok(bytes) => SourceState::Bytes(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => SourceState::Missing,
            Err(_) => SourceState::Unreadable,
        }
    }
}

/// The part of a repository-relative `path` that lies under the project root.
///
/// `None` means the path is outside the project, so it is never resolved. An
/// empty result means the path *is* the project root. `.` owns the whole
/// repository, so its remainder is the path itself.
fn project_relative(root: &str, path: &str) -> Option<String> {
    if root == WHOLE_REPO_BINDING {
        return Some(path.to_string());
    }
    if graph_watch::same_path(root, path) {
        return Some(String::new());
    }
    let prefix = format!("{root}/");
    let matched = if cfg!(windows) {
        path.to_ascii_lowercase()
            .starts_with(&prefix.to_ascii_lowercase())
    } else {
        path.starts_with(&prefix)
    };
    matched.then(|| path[prefix.len()..].to_string())
}

/// Join an absolute root and a portable relative path with a forward slash.
fn join(root: &str, relative: &str) -> String {
    let trimmed = root.trim_end_matches(['/', '\\']);
    format!("{trimmed}/{}", relative.replace('\\', "/"))
}
#[cfg(test)]
mod tests {
    use super::*;
    use graph_core::bindings::NoSymlinkProbe;

    /// A registry whose answer is fixed by the test.
    enum RegistryReply {
        Scope(Box<ProjectScope>),
        Fail(ErrorCode, &'static str),
    }

    struct FakeRegistry(RegistryReply);

    impl ProjectRegistry for FakeRegistry {
        fn scope(&self, _solution_id: &str, _project_id: &str) -> Result<ProjectScope, AxiomError> {
            match &self.0 {
                RegistryReply::Scope(scope) => Ok((**scope).clone()),
                RegistryReply::Fail(code, rule) => {
                    Err(AxiomError::new(*code, "refused by the fixture").with_detail("rule", *rule))
                }
            }
        }
    }

    /// A reader backed by an explicit path table; anything else is missing.
    struct FakeReader(Vec<(String, SourceState)>);

    impl SourceReader for FakeReader {
        fn read(&self, path: &Path) -> SourceState {
            let text = path.to_string_lossy().replace('\\', "/");
            self.0
                .iter()
                .find(|(known, _)| *known == text)
                .map_or(SourceState::Missing, |(_, state)| state.clone())
        }
    }

    fn scope() -> ProjectScope {
        ProjectScope::new("sol-1", "proj-app", "repo-a", "src/App", "/bound/a/src/App")
    }

    fn registry() -> FakeRegistry {
        FakeRegistry(RegistryReply::Scope(Box::new(scope())))
    }

    fn report(
        reason: Option<&str>,
        paths: &[&str],
        reader: &FakeReader,
    ) -> Result<HintReport, AxiomError> {
        let owned: Vec<String> = paths.iter().map(|value| String::from(*value)).collect();
        ChangeHintRequest::new("sol-1", "proj-app", reason, owned).accept(&registry(), reader)
    }

    #[test]
    fn an_accepted_hint_reports_the_digest_read_from_disk() {
        let reader = FakeReader(vec![(
            String::from("/bound/a/src/App/Controller.cs"),
            SourceState::Bytes(b"namespace App;".to_vec()),
        )]);
        let report = report(None, &["src/App/Controller.cs"], &reader).expect("hint accepted");
        assert!(report.is_hint_only());
        assert_eq!(report.reason(), REASON_MANUAL);
        assert_eq!(report.observed(), 1);
        assert_eq!(report.missing(), 0);
        assert_eq!(report.hints().len(), 1);
        assert_eq!(report.hints()[0].outcome(), HintOutcome::Observed);
        assert_eq!(
            report.hints()[0].content_hash(),
            Some(graph_watch::inventory::content_digest(b"namespace App;").as_str())
        );
    }

    #[test]
    fn a_hint_for_a_missing_file_is_not_reported_as_observed() {
        let reader = FakeReader(Vec::new());
        let report = report(
            Some(REASON_TOOL),
            &["src/App/Deleted.cs", "src/App/Gone.cs"],
            &reader,
        )
        .expect("a missing file is still a hint");
        assert_eq!(report.reason(), REASON_TOOL);
        assert_eq!(report.observed(), 0);
        assert_eq!(report.missing(), 2);
        for hint in report.hints() {
            assert_eq!(hint.outcome(), HintOutcome::Missing);
            assert!(hint.content_hash().is_none());
        }
    }

    #[test]
    fn an_unreadable_path_is_reported_apart_from_a_missing_one() {
        let reader = FakeReader(vec![(
            String::from("/bound/a/src/App/Locked.cs"),
            SourceState::Unreadable,
        )]);
        let report = report(None, &["src/App/Locked.cs"], &reader).expect("hint accepted");
        assert_eq!(report.unreadable(), 1);
        assert_eq!(report.observed(), 0);
        assert_eq!(report.missing(), 0);
        assert_eq!(report.hints()[0].outcome(), HintOutcome::Unreadable);
    }

    #[test]
    fn a_path_outside_the_registered_project_root_is_refused() {
        let reader = FakeReader(Vec::new());
        let error = report(None, &["src/Other/Controller.cs"], &reader)
            .expect_err("outside the project root");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_HINT_OUTSIDE_PROJECT)
        );
        // A sibling project whose name merely shares a prefix is not inside it.
        let error = report(None, &["src/AppTests/Controller.cs"], &reader)
            .expect_err("prefix-shared sibling is not inside");
        assert_eq!(error.code(), ErrorCode::Forbidden);
    }

    #[test]
    fn unknown_reasons_duplicates_roots_and_absolute_paths_are_refused() {
        let reader = FakeReader(Vec::new());
        let error =
            report(Some("because"), &["src/App/A.cs"], &reader).expect_err("unknown reason");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_UNKNOWN_HINT_REASON)
        );

        let error = report(None, &[], &reader).expect_err("empty batch");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_EMPTY_HINT_BATCH)
        );

        let error =
            report(None, &["src/App/A.cs", "src/App/A.cs"], &reader).expect_err("duplicate path");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_DUPLICATE_HINT_PATH)
        );

        let error = report(None, &["."], &reader).expect_err("project root is not a file");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_HINT_TARGETS_PROJECT_ROOT)
        );

        let error = report(None, &["C:/tmp/A.cs"], &reader).expect_err("absolute path");
        assert_eq!(error.code(), ErrorCode::UnsafePortablePath);

        let error = report(None, &["src/App/../secret.cs"], &reader).expect_err("traversal path");
        assert_eq!(error.code(), ErrorCode::UnsafePortablePath);
    }

    #[test]
    fn an_unregistered_solution_or_project_is_never_guessed() {
        let reader = FakeReader(Vec::new());
        let unknown_project = FakeRegistry(RegistryReply::Fail(
            ErrorCode::NotFound,
            REASON_PROJECT_NOT_REGISTERED,
        ));
        let owned = vec![String::from("src/App/A.cs")];
        let error = ChangeHintRequest::new("sol-1", "proj-ghost", None, owned)
            .accept(&unknown_project, &reader)
            .expect_err("unknown project");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_PROJECT_NOT_REGISTERED)
        );

        let foreign = FakeRegistry(RegistryReply::Fail(
            ErrorCode::Forbidden,
            REASON_PROJECT_NOT_IN_SOLUTION,
        ));
        let error = ChangeHintRequest::new("sol-1", "proj-other", None, vec![String::from("a.cs")])
            .accept(&foreign, &reader)
            .expect_err("foreign project");
        assert_eq!(error.code(), ErrorCode::Forbidden);
    }

    #[test]
    fn a_batch_document_must_agree_with_the_caller_selection() {
        let document = r#"{"project_id":"proj-app","reason":"git","paths":["src/App/A.cs"]}"#;
        let request =
            ChangeHintRequest::from_json(document, "sol-1", Some("proj-app"), None).expect("batch");
        assert_eq!(request.project_id(), "proj-app");
        assert_eq!(request.reason(), REASON_GIT);
        assert_eq!(request.paths(), ["src/App/A.cs"]);

        let error = ChangeHintRequest::from_json(document, "sol-1", Some("proj-other"), None)
            .expect_err("project mismatch");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_PROJECT_SCOPE_MISMATCH)
        );

        let declared =
            r#"{"solution_id":"sol-1","project_id":"proj-app","paths":["src/App/A.cs"]}"#;
        let error = ChangeHintRequest::from_json(declared, "sol-2", None, None)
            .expect_err("solution mismatch");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_SOLUTION_SCOPE_MISMATCH)
        );

        let error =
            ChangeHintRequest::from_json(document, "sol-1", Some("proj-app"), Some("manual"))
                .expect_err("reason mismatch");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_REASON_SCOPE_MISMATCH)
        );

        let error =
            ChangeHintRequest::from_json("{", "sol-1", None, None).expect_err("malformed document");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_HINT_DOCUMENT_INVALID)
        );

        let error = ChangeHintRequest::from_json(
            r#"{"solution_id":"sol-1","paths":[]}"#,
            "sol-1",
            None,
            None,
        )
        .expect_err("a document without a project cannot be used");
        assert_eq!(error.code(), ErrorCode::ValidationError);

        let oversized = format!(
            r#"{{"project_id":"proj-app","paths":["{}"]}}"#,
            "a".repeat(MAX_HINT_DOCUMENT_BYTES)
        );
        let error = ChangeHintRequest::from_json(&oversized, "sol-1", None, None)
            .expect_err("oversized document");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_HINT_DOCUMENT_TOO_LARGE)
        );
    }

    #[test]
    fn the_real_reader_hashes_the_bytes_that_are_there_now() {
        let directory = tempfile::tempdir().expect("temp dir");
        let root = directory.path().join("repo");
        std::fs::create_dir_all(root.join("src")).expect("source dir");
        let file = root.join("src").join("Controller.cs");
        std::fs::write(&file, b"first").expect("write");
        let resolved = root.to_string_lossy().replace('\\', "/");
        // The scope's resolved root is the project root, so a whole-repository
        // project keeps the repository-relative hint path intact.
        let scope = ProjectScope::new(
            "sol-1",
            "proj-app",
            "repo-a",
            WHOLE_REPO_BINDING,
            resolved.clone(),
        );
        let registry = FakeRegistry(RegistryReply::Scope(Box::new(scope)));
        let request = ChangeHintRequest::new(
            "sol-1",
            "proj-app",
            None,
            vec![String::from("src/Controller.cs")],
        );

        let first = request
            .accept(&registry, &StdSourceReader)
            .expect("first hint");
        assert_eq!(first.observed(), 1);
        let first_hash = first.hints()[0].content_hash().map(str::to_string);

        std::fs::write(&file, b"second").expect("rewrite");
        let second = request
            .accept(&registry, &StdSourceReader)
            .expect("second hint");
        let second_hash = second.hints()[0].content_hash().map(str::to_string);
        assert_ne!(
            first_hash, second_hash,
            "the digest follows the bytes on disk"
        );

        std::fs::remove_file(&file).expect("remove");
        let third = request
            .accept(&registry, &StdSourceReader)
            .expect("third hint");
        assert_eq!(third.missing(), 1);
        assert!(third.hints()[0].content_hash().is_none());
    }

    #[test]
    fn the_store_registry_reads_registration_rows_and_trusted_bindings() {
        let connection = memory_store();
        connection
            .execute(
                "INSERT INTO solutions(id, workspace_instance_id, profile, config_hash) \
                 VALUES('sol-1', 'inst-1', 'default', 'hash')",
                [],
            )
            .expect("seed solution");
        connection
            .execute(
                "INSERT INTO projects(id, solution_id, repo_id, relative_path) \
                 VALUES('proj-app', 'sol-1', 'repo-a', 'src/App')",
                [],
            )
            .expect("seed project");
        let registry = StoreRegistry::new(
            &connection,
            vec![LocalBinding::new("repo-a", "/bound/a")],
            &NoSymlinkProbe,
        )
        .expect("registry");

        let scope = registry
            .scope("sol-1", "proj-app")
            .expect("registered project");
        assert_eq!(scope.relative_root(), "src/App");
        assert_eq!(scope.resolved_root(), "/bound/a/src/App");

        let error = registry
            .scope("sol-1", "proj-ghost")
            .expect_err("unknown project");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_PROJECT_NOT_REGISTERED)
        );

        let error = registry
            .scope("sol-2", "proj-app")
            .expect_err("unknown solution");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_SOLUTION_NOT_REGISTERED)
        );

        connection
            .execute(
                "INSERT INTO solutions(id, workspace_instance_id, profile, config_hash) \
                 VALUES('sol-2', 'inst-2', 'default', 'hash')",
                [],
            )
            .expect("seed second solution");
        let error = registry
            .scope("sol-2", "proj-app")
            .expect_err("foreign project");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_PROJECT_NOT_IN_SOLUTION)
        );

        let unbound = StoreRegistry::new(&connection, Vec::new(), &NoSymlinkProbe)
            .expect("empty binding table");

        let error = unbound
            .scope("sol-1", "proj-app")
            .expect_err("an unbound repo id is never guessed");
        assert_eq!(error.code(), ErrorCode::NotFound);
    }

    #[test]
    fn the_bindings_document_refuses_relative_roots_and_duplicates() {
        let document =
            r#"{"status":"example_not_bound","bindings":{"repo-a":"/srv/a","repo-b":"/srv/b"}}"#;
        let bindings = BindingsDocument::parse(document).expect("bound document");
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].repo_id(), "repo-a");
        assert_eq!(bindings[0].root(), "/srv/a");

        let error = BindingsDocument::parse(r#"{"bindings":{"repo-a":"srv/a"}}"#)
            .expect_err("relative root");
        assert_eq!(error.code(), ErrorCode::ConfigInvalid);

        let error =
            BindingsDocument::parse(r#"{"bindings":{"repo-a":"/srv/a","repo-a":"/srv/b"}}"#);
        assert!(
            error.is_ok(),
            "duplicate JSON keys collapse before validation"
        );

        let error = BindingsDocument::parse(r#"{"bindings":{}"#).expect_err("malformed document");
        assert_eq!(error.code(), ErrorCode::ValidationError);
    }

    fn memory_store() -> Connection {
        let mut connection = Connection::open_in_memory().expect("in-memory sqlite");
        graph_store::migrations::apply(&mut connection).expect("schema v1 applies");
        connection
    }
}
