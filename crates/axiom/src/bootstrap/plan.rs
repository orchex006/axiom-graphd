//! The reviewable, read-only multi-repository bootstrap plan (task E-018).
//!
//! Planning is the half of bootstrap that must never write. Everything else in
//! this module tree decides *what* would happen; this module turns those
//! decisions into one document an operator can read before anything is applied:
//! per repository, the change classification, the before- and after-hash of
//! every affected file, the managed-block hash before and after, and a proposed
//! diff.
//!
//! The read-only property is structural rather than a promise.
//! [`RepositoryReader`] has exactly one method and it can only read;
//! [`LocalRepositoryReader`] is the only filesystem adapter and its only
//! filesystem call is `fs::read`. No plan path calls `create_dir`, `write` or
//! `remove`, so planning a repository that has no `.axiom` directory cannot
//! create one - which is asserted against a real temporary directory.
//!
//! Conflicts do not abort the run: a repository bootstrap will not touch becomes
//! a [`ChangeClass::Conflict`] entry carrying the stable refusal rule, while the
//! other repositories are still planned, so the operator sees the whole picture
//! and the apply step can report per-repository outcomes and exit 20 for a
//! partial run. Only an unreadable host or an unusable template is an error.
//!
//! The plan is bound to its inputs. [`BootstrapPlan::digest`] is a SHA-256 over
//! the canonical bytes of the plan body, [`BootstrapPlan::to_canonical_bytes`]
//! is what an operator reviews and approves, and [`BootstrapPlan::parse`]
//! refuses a plan whose body no longer hashes to its recorded digest.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};
use graph_export::canonical::canonical_value;
use graph_export::sha256_hex;
use serde::{Deserialize, Serialize};

use super::markers::{self, MarkerConflict};
use super::ownership::Ownership;
use super::policy;
use super::text::{self, SourceText};
use super::{refuse, BOOTSTRAP_SCHEMA_VERSION};

/// The managed pointer file, relative to a repository root.
pub const AGENTS_PATH: &str = "AGENTS.md";

/// Stable rule code: the plan body does not match its recorded digest.
pub const RULE_PLAN_DIGEST: &str = "plan-digest-mismatch";

/// Stable rule code: the plan document is not a plan this build understands.
pub const RULE_PLAN_MALFORMED: &str = "plan-malformed";

/// Stable rule code: a reader was asked for a path outside its root.
pub const RULE_PLAN_PATH: &str = "plan-path-unsafe";

/// Stable rule code: managed markers exist but no ownership manifest does.
pub const RULE_MARKERS_WITHOUT_OWNERSHIP: &str = "ownership-absent-with-markers";

/// Largest number of line-pairs the diff will align before it falls back to
/// reporting a wholesale replacement. A plan is a review document, so an
/// unbounded quadratic diff would be a denial of service against the operator.
const MAX_DIFF_CELLS: usize = 250_000;

/// The templates a plan proposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Templates {
    /// The managed block template, including its markers.
    pub block: String,
    /// The managed policy file.
    pub policy: Vec<u8>,
    /// The template version recorded in the ownership manifest.
    pub version: String,
}

impl Templates {
    /// Bind the three template inputs.
    #[must_use]
    pub fn new(
        block: impl Into<String>,
        policy: impl Into<Vec<u8>>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            block: block.into(),
            policy: policy.into(),
            version: version.into(),
        }
    }

    /// SHA-256 of the block template, as written.
    #[must_use]
    pub fn block_sha256(&self) -> String {
        sha256_hex(self.block.as_bytes())
    }

    /// SHA-256 of the policy template.
    #[must_use]
    pub fn policy_sha256(&self) -> String {
        sha256_hex(&self.policy)
    }
}

/// Read-only access to the owned artifacts of one repository.
///
/// The trait is deliberately unable to write. A `None` means "the file is not
/// there", which is a normal input to a plan rather than an error.
pub trait RepositoryReader {
    /// Read one repository-relative path.
    ///
    /// # Errors
    ///
    /// Returns a non-conflict error when the host cannot be read.
    fn read(&self, relative_path: &str) -> Result<Option<Vec<u8>>, AxiomError>;
}

/// The only filesystem adapter a plan may use: it reads and nothing else.
#[derive(Debug, Clone)]
pub struct LocalRepositoryReader {
    root: PathBuf,
}

impl LocalRepositoryReader {
    /// Bind a repository root.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The bound root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl RepositoryReader for LocalRepositoryReader {
    fn read(&self, relative_path: &str) -> Result<Option<Vec<u8>>, AxiomError> {
        if !is_safe_relative(relative_path) {
            return Err(refuse(
                RULE_PLAN_PATH,
                format!("refusing to read the unsafe repository path {relative_path}"),
            )
            .with_detail("field", "path")
            .with_detail("observed", relative_path));
        }
        let path = self.root.join(relative_path);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(AxiomError::new(
                ErrorCode::Internal,
                format!("cannot read {}: {error}", path.display()),
            )),
        }
    }
}

/// An in-memory reader for tests and for planning a repository that is not on
/// this host. It never touches a filesystem.
#[derive(Debug, Clone, Default)]
pub struct MapRepositoryReader {
    files: BTreeMap<String, Vec<u8>>,
}

impl MapRepositoryReader {
    /// An empty repository.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace one repository-relative file.
    pub fn insert(&mut self, relative_path: impl Into<String>, bytes: impl Into<Vec<u8>>) {
        self.files.insert(relative_path.into(), bytes.into());
    }
}

impl RepositoryReader for MapRepositoryReader {
    fn read(&self, relative_path: &str) -> Result<Option<Vec<u8>>, AxiomError> {
        Ok(self.files.get(relative_path).cloned())
    }
}

/// One repository to plan.
pub struct RepositoryTarget<'a> {
    /// Stable identifier of the repository.
    pub repository_id: String,
    /// Display root, for the review document.
    pub root: String,
    /// Read-only access to the repository.
    pub reader: &'a dyn RepositoryReader,
}

impl<'a> RepositoryTarget<'a> {
    /// Bind one repository to plan.
    #[must_use]
    pub fn new(
        repository_id: impl Into<String>,
        root: impl Into<String>,
        reader: &'a dyn RepositoryReader,
    ) -> Self {
        Self {
            repository_id: repository_id.into(),
            root: root.into(),
            reader,
        }
    }
}

/// How bootstrap would change one repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeClass {
    /// The owned block is added to the file.
    Append,
    /// Only the owned span of an already-managed file changes.
    Replace,
    /// The repository already matches; nothing is written.
    Unchanged,
    /// Bootstrap refuses this repository and writes nothing.
    Conflict,
}

impl ChangeClass {
    /// Stable string form, matching `fixtures/guides/bootstrap.md`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Append => "append",
            Self::Replace => "replace",
            Self::Unchanged => "unchanged",
            Self::Conflict => "conflict",
        }
    }
}

/// One file a plan proposes to write, with the hashes that make it reviewable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChange {
    /// Repository-relative destination path.
    pub path: String,
    /// SHA-256 of the file before the change, or `None` when it does not exist.
    pub before_sha256: Option<String>,
    /// SHA-256 of the file after the change.
    pub after_sha256: String,
    /// Proposed diff for review. The hashes, not the diff, are what an apply
    /// re-verifies.
    pub diff: String,
    /// The exact bytes an apply would write.
    pub bytes: Vec<u8>,
}

/// The refusal that makes one repository a conflict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    /// Stable rule code.
    pub rule: String,
    /// Operator-facing explanation.
    pub message: String,
}

/// One repository's part of a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryPlan {
    /// Stable identifier of the repository.
    pub repository_id: String,
    /// Display root.
    pub root: String,
    /// What bootstrap would do.
    pub change: ChangeClass,
    /// SHA-256 of the managed block as it exists now, if it exists.
    pub before_block_sha256: Option<String>,
    /// SHA-256 of the managed block as it would exist afterwards, if bootstrap
    /// would own one.
    pub after_block_sha256: Option<String>,
    /// The files this plan would write. Empty for `unchanged` and `conflict`.
    pub files: Vec<FileChange>,
    /// Why this repository is refused, when it is.
    pub refusal: Option<Refusal>,
}

impl RepositoryPlan {
    /// Whether this repository is refused.
    #[must_use]
    pub fn is_conflict(&self) -> bool {
        self.change == ChangeClass::Conflict
    }

    /// Whether applying this plan would write anything for this repository.
    #[must_use]
    pub fn would_write(&self) -> bool {
        !self.files.is_empty()
    }
}

/// A whole reviewable plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapPlan {
    /// Schema version of this document.
    pub schema_version: u32,
    /// Template version the plan proposes.
    pub template_version: String,
    /// SHA-256 of the block template.
    pub block_template_sha256: String,
    /// SHA-256 of the policy template.
    pub policy_template_sha256: String,
    /// Per-repository decisions, in the order they were given.
    pub repositories: Vec<RepositoryPlan>,
    /// SHA-256 over the canonical bytes of this document with `digest` empty.
    pub digest: String,
}

impl BootstrapPlan {
    /// Build a plan and bind it to its own digest.
    ///
    /// # Errors
    ///
    /// Returns a conflict when the document cannot be encoded.
    pub fn new(
        repositories: Vec<RepositoryPlan>,
        templates: &Templates,
    ) -> Result<Self, AxiomError> {
        let mut plan = Self {
            schema_version: BOOTSTRAP_SCHEMA_VERSION,
            template_version: templates.version.clone(),
            block_template_sha256: templates.block_sha256(),
            policy_template_sha256: templates.policy_sha256(),
            repositories,
            digest: String::new(),
        };
        plan.digest = plan.compute_digest()?;
        Ok(plan)
    }

    /// The canonical bytes an operator reviews and approves.
    ///
    /// # Errors
    ///
    /// Returns a conflict when the document cannot be encoded.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, AxiomError> {
        let mut bytes = self.encode_body()?.into_bytes();
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Parse a plan and refuse one whose body no longer matches its digest.
    ///
    /// # Errors
    ///
    /// Returns [`RULE_PLAN_MALFORMED`] for an unreadable document and
    /// [`RULE_PLAN_DIGEST`] for a document that was edited after approval.
    pub fn parse(bytes: &[u8]) -> Result<Self, AxiomError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|error| refuse(RULE_PLAN_MALFORMED, format!("plan is not UTF-8: {error}")))?;
        let parsed: Self = serde_json::from_str(text)
            .map_err(|error| refuse(RULE_PLAN_MALFORMED, format!("plan is malformed: {error}")))?;
        if parsed.schema_version != BOOTSTRAP_SCHEMA_VERSION {
            return Err(refuse(
                RULE_PLAN_MALFORMED,
                format!("unsupported plan schema {}", parsed.schema_version),
            )
            .with_detail("field", "schema_version"));
        }
        let expected = parsed.compute_digest()?;
        if parsed.digest != expected {
            return Err(refuse(
                RULE_PLAN_DIGEST,
                "the plan body does not match its recorded digest",
            )
            .with_detail("field", "digest")
            .with_detail("observed", parsed.digest.clone()));
        }
        Ok(parsed)
    }

    /// The repositories this plan refuses.
    #[must_use]
    pub fn conflicts(&self) -> Vec<&RepositoryPlan> {
        self.repositories
            .iter()
            .filter(|repository| repository.is_conflict())
            .collect()
    }

    /// A human-readable review document: per repository, the class, the hashes
    /// and the proposed diffs.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("bootstrap plan {}\n", self.digest));
        out.push_str(&format!(
            "schema {} template {} block {} policy {}\n",
            self.schema_version,
            self.template_version,
            self.block_template_sha256,
            self.policy_template_sha256
        ));
        for repository in &self.repositories {
            out.push_str(&format!(
                "\n== {} ({}) - {}\n",
                repository.repository_id,
                repository.root,
                repository.change.as_str()
            ));
            out.push_str(&format!(
                "   block: {} -> {}\n",
                repository
                    .before_block_sha256
                    .as_deref()
                    .unwrap_or("absent"),
                repository.after_block_sha256.as_deref().unwrap_or("absent")
            ));
            if let Some(refusal) = &repository.refusal {
                out.push_str(&format!(
                    "   refused: {} - {}\n",
                    refusal.rule, refusal.message
                ));
            }
            for file in &repository.files {
                out.push_str(&format!(
                    "   {}: {} -> {}\n",
                    file.path,
                    file.before_sha256.as_deref().unwrap_or("absent"),
                    file.after_sha256
                ));
                out.push_str(&indent(&file.diff, "      "));
            }
        }
        out
    }

    fn encode_body(&self) -> Result<String, AxiomError> {
        let value = serde_json::to_value(self).map_err(|error| {
            refuse(
                RULE_PLAN_MALFORMED,
                format!("plan cannot be encoded: {error}"),
            )
        })?;
        canonical_value(&value).map_err(|error| refuse(RULE_PLAN_MALFORMED, error.message))
    }

    /// Digest of the document with `digest` emptied, so the digest can never
    /// include itself.
    fn compute_digest(&self) -> Result<String, AxiomError> {
        let mut bare = self.clone();
        bare.digest = String::new();
        Ok(sha256_hex(bare.encode_body()?.as_bytes()))
    }
}

/// Plan every given repository.
///
/// # Errors
///
/// Returns a conflict when a template is unusable, and propagates a reader that
/// cannot read its host. Per-repository conflicts are part of the plan.
pub fn plan_all(
    targets: &[RepositoryTarget<'_>],
    templates: &Templates,
) -> Result<BootstrapPlan, AxiomError> {
    policy::ensure_block_points_at_policy(&templates.block)?;
    let mut repositories = Vec::with_capacity(targets.len());
    for target in targets {
        repositories.push(plan_repository(target, templates)?);
    }
    BootstrapPlan::new(repositories, templates)
}

/// Plan one repository.
///
/// # Errors
///
/// Returns a conflict when a template is unusable, and propagates a reader that
/// cannot read its host. A refusal that concerns only this repository is
/// returned inside the plan as [`ChangeClass::Conflict`].
pub fn plan_repository(
    target: &RepositoryTarget<'_>,
    templates: &Templates,
) -> Result<RepositoryPlan, AxiomError> {
    policy::ensure_block_points_at_policy(&templates.block)?;

    let agents_raw = target.reader.read(AGENTS_PATH)?;
    let policy_raw = target.reader.read(policy::POLICY_PATH)?;
    let ownership_raw = target.reader.read(super::ownership::OWNERSHIP_PATH)?;

    let agents = match agents_raw.as_deref() {
        Some(bytes) => SourceText::decode(bytes),
        None => Ok(SourceText::from_text(String::new())),
    };
    let agents = match agents {
        Ok(agents) => agents,
        Err(error) => return Ok(conflict(target, error, None, None)),
    };
    let ownership = match ownership_raw.as_deref() {
        Some(bytes) => match Ownership::parse(bytes) {
            Ok(ownership) => Some(ownership),
            Err(error) => return Ok(conflict(target, error, None, None)),
        },
        None => None,
    };
    let span = match markers::managed_span(agents.document()) {
        Ok(span) => span,
        Err(conflict) => return Ok(conflict_plan(target, conflict, None)),
    };

    let before_block_sha256 = span
        .and_then(|span| span.slice(agents.document()))
        .map(|block| sha256_hex(block.as_bytes()));

    // The refusal rules below follow the contract's decision order exactly: the
    // marker shape, then ownership, then the owned block, then the owned policy.
    let refusal = match &ownership {
        None => {
            if span.is_some() {
                Some(
                    refuse(
                        RULE_MARKERS_WITHOUT_OWNERSHIP,
                        "managed markers exist without ownership; refusing to adopt them implicitly",
                    )
                    .with_detail("field", "ownership")
                    .with_detail("observed", "absent"),
                )
            } else if policy_raw.is_some() {
                policy::plan_policy(policy_raw.as_deref().map(sha256_hex).as_deref(), None).err()
            } else {
                None
            }
        }
        Some(owner) => {
            let block = span.and_then(|span| span.slice(agents.document()));
            let drift = super::ownership::detect_drift(owner, block, policy_raw.as_deref());
            drift.refusal()
        }
    };
    if let Some(refusal) = refusal {
        return Ok(conflict(target, refusal, before_block_sha256, None));
    }

    let newline = agents.newline();
    let block = text::render_block(&templates.block, newline);
    let after_agents_text = match span {
        Some(span) => match agents.replace_span(span, &block) {
            Ok(text) => text,
            Err(error) => return Ok(conflict(target, error, before_block_sha256, None)),
        },
        None => agents.append_block(&block),
    };
    let after_block = match markers::managed_span(&after_agents_text) {
        Ok(Some(span)) => span.slice(&after_agents_text).unwrap_or_default(),
        Ok(None) => {
            return Ok(conflict(
                target,
                refuse(
                    RULE_PLAN_MALFORMED,
                    "planned content lost its managed block",
                ),
                before_block_sha256,
                None,
            ))
        }
        Err(conflict) => return Ok(conflict_plan(target, conflict, before_block_sha256)),
    };
    let after_block_sha256 = sha256_hex(after_block.as_bytes());

    let after_agents = after_agents_text.as_bytes().to_vec();
    let after_policy = templates.policy.clone();
    let after_ownership = if ownership.as_ref().is_some_and(|owner| {
        owner.block_hash() == after_block_sha256 && owner.policy_hash() == sha256_hex(&after_policy)
    }) {
        None
    } else {
        match Ownership::new(&templates.version, after_block, &after_policy).encode() {
            Ok(bytes) => Some(bytes),
            Err(error) => return Ok(conflict(target, error, before_block_sha256, None)),
        }
    };

    let mut files = Vec::new();
    for (path, before, after) in [
        (
            AGENTS_PATH,
            agents_raw.as_deref(),
            Some(after_agents.as_slice()),
        ),
        (
            policy::POLICY_PATH,
            policy_raw.as_deref(),
            Some(after_policy.as_slice()),
        ),
        (
            super::ownership::OWNERSHIP_PATH,
            ownership_raw.as_deref(),
            after_ownership.as_deref(),
        ),
    ] {
        let Some(after) = after else {
            continue;
        };
        if before == Some(after) {
            continue;
        }
        files.push(FileChange {
            path: path.to_owned(),
            before_sha256: before.map(sha256_hex),
            after_sha256: sha256_hex(after),
            diff: unified_diff(path, &display(before), &display(Some(after))),
            bytes: after.to_vec(),
        });
    }

    let change = if files.is_empty() {
        ChangeClass::Unchanged
    } else if ownership.is_some() {
        ChangeClass::Replace
    } else {
        ChangeClass::Append
    };
    Ok(RepositoryPlan {
        repository_id: target.repository_id.clone(),
        root: target.root.clone(),
        change,
        before_block_sha256,
        after_block_sha256: Some(after_block_sha256),
        files,
        refusal: None,
    })
}

/// A refusal that concerns one repository, reported inside the plan.
fn conflict(
    target: &RepositoryTarget<'_>,
    refusal: AxiomError,
    before_block_sha256: Option<String>,
    after_block_sha256: Option<String>,
) -> RepositoryPlan {
    RepositoryPlan {
        repository_id: target.repository_id.clone(),
        root: target.root.clone(),
        change: ChangeClass::Conflict,
        before_block_sha256,
        after_block_sha256,
        files: Vec::new(),
        refusal: Some(Refusal {
            rule: refusal
                .details()
                .get("rule")
                .cloned()
                .unwrap_or_else(|| "bootstrap-conflict".to_owned()),
            message: refusal.message().to_owned(),
        }),
    }
}

/// A marker conflict reported inside the plan.
fn conflict_plan(
    target: &RepositoryTarget<'_>,
    marker_conflict: MarkerConflict,
    before_block_sha256: Option<String>,
) -> RepositoryPlan {
    conflict(
        target,
        AxiomError::new(ErrorCode::Conflict, marker_conflict.message())
            .with_detail("rule", marker_conflict.as_str()),
        before_block_sha256,
        None,
    )
}

/// The text to show in a diff for a byte string.
fn display(bytes: Option<&[u8]>) -> String {
    bytes.map_or_else(String::new, |bytes| {
        String::from_utf8_lossy(bytes).into_owned()
    })
}

/// Whether a repository-relative path is safe to read.
#[must_use]
fn is_safe_relative(relative_path: &str) -> bool {
    !relative_path.is_empty()
        && !relative_path.starts_with('/')
        && !relative_path.starts_with('\\')
        && relative_path
            .as_bytes()
            .get(1)
            .is_none_or(|byte| *byte != b':')
        && relative_path
            .split(['/', '\\'])
            .all(|segment| !segment.is_empty() && segment != "..")
}

/// Render a reviewable unified diff between two texts.
///
/// The diff is a display artifact: it exists so an operator can read what will
/// change. Byte-exactness is carried by the before/after hashes, which is what
/// an apply re-verifies.
#[must_use]
pub fn unified_diff(path: &str, before: &str, after: &str) -> String {
    let before_lines = lines_of(before);
    let after_lines = lines_of(after);
    let mut out = format!("diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n");
    out.push_str(&format!(
        "@@ -1,{} +1,{} @@\n",
        before_lines.len(),
        after_lines.len()
    ));
    for (sign, line) in diff_ops(&before_lines, &after_lines) {
        out.push(sign);
        out.push_str(line.strip_suffix('\r').unwrap_or(&line));
        out.push('\n');
    }
    out
}

fn lines_of(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    lines
}

fn diff_ops(before: &[&str], after: &[&str]) -> Vec<(char, String)> {
    if before.len().saturating_mul(after.len()) > MAX_DIFF_CELLS {
        return before
            .iter()
            .map(|line| ('-', (*line).to_owned()))
            .chain(after.iter().map(|line| ('+', (*line).to_owned())))
            .collect();
    }
    let rows = before.len();
    let columns = after.len();
    let mut lengths = vec![vec![0_usize; columns + 1]; rows + 1];
    for row in (0..rows).rev() {
        for column in (0..columns).rev() {
            lengths[row][column] = if before[row] == after[column] {
                lengths[row + 1][column + 1] + 1
            } else {
                lengths[row + 1][column].max(lengths[row][column + 1])
            };
        }
    }
    let mut ops = Vec::new();
    let (mut row, mut column) = (0_usize, 0_usize);
    while row < rows && column < columns {
        if before[row] == after[column] {
            ops.push((' ', before[row].to_owned()));
            row += 1;
            column += 1;
        } else if lengths[row + 1][column] >= lengths[row][column + 1] {
            ops.push(('-', before[row].to_owned()));
            row += 1;
        } else {
            ops.push(('+', after[column].to_owned()));
            column += 1;
        }
    }
    while row < rows {
        ops.push(('-', before[row].to_owned()));
        row += 1;
    }
    while column < columns {
        ops.push(('+', after[column].to_owned()));
        column += 1;
    }
    ops
}

fn indent(text: &str, prefix: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        out.push_str(prefix);
        out.push_str(line);
        out.push('\n');
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{markers, TEMPLATE_VERSION};

    fn corpus_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("bootstrap")
    }

    fn templates() -> Templates {
        let root = corpus_root();
        Templates::new(
            std::fs::read_to_string(root.join("templates").join("AGENTS.block.md"))
                .expect("block template"),
            std::fs::read(root.join("templates").join("POLICY.md")).expect("policy template"),
            TEMPLATE_VERSION,
        )
    }

    fn vectors() -> serde_json::Value {
        serde_json::from_str(
            &std::fs::read_to_string(corpus_root().join("vectors.json")).expect("vectors.json"),
        )
        .expect("parse vectors")
    }

    fn plan_one(reader: &dyn RepositoryReader, templates: &Templates) -> RepositoryPlan {
        plan_repository(
            &RepositoryTarget::new("demo", "/repos/demo", reader),
            templates,
        )
        .expect("planning one repository")
    }

    /// AC1 positive: every changed file carries its before- and after-hash and a
    /// proposed diff, and the repository shows its managed-block hashes.
    #[test]
    fn a_plan_shows_before_and_after_hashes_and_a_diff() {
        let templates = templates();
        let human = "# Demo repository\n\nHuman-authored instructions live here.\n";
        let mut reader = MapRepositoryReader::new();
        reader.insert(AGENTS_PATH, human);

        let plan = plan_one(&reader, &templates);
        assert_eq!(plan.change, ChangeClass::Append);
        assert!(!plan.is_conflict());
        assert!(plan.would_write());
        assert_eq!(plan.before_block_sha256, None, "no block existed before");
        assert!(
            plan.after_block_sha256.is_some(),
            "the planned block hash is reported"
        );

        let paths: Vec<&str> = plan.files.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                AGENTS_PATH,
                policy::POLICY_PATH,
                super::super::ownership::OWNERSHIP_PATH
            ]
        );
        let agents = &plan.files[0];
        assert_eq!(
            agents.before_sha256.as_deref(),
            Some(sha256_hex(human.as_bytes()).as_str())
        );
        assert_eq!(agents.after_sha256, sha256_hex(&agents.bytes));
        assert!(agents
            .diff
            .starts_with("diff --git a/AGENTS.md b/AGENTS.md\n"));
        assert!(
            agents.diff.contains("-"),
            "the diff has removals or additions"
        );
        assert!(agents.diff.contains("+<!-- axiom-graph:begin -->"));
        assert!(agents
            .diff
            .contains(" Human-authored instructions live here."));
        assert!(agents.diff.contains(".axiom/agent/POLICY.md"));

        let policy = &plan.files[1];
        assert_eq!(policy.before_sha256, None, "the policy is created");
        assert_eq!(policy.after_sha256, templates.policy_sha256());
        let lock = &plan.files[2];
        assert_eq!(lock.before_sha256, None, "the manifest is created");

        let before = agents.before_sha256.clone().expect("before hash");
        let after = agents.after_sha256.clone();
        let bootstrap =
            BootstrapPlan::new(vec![plan], &templates).expect("the plan binds to its digest");
        let rendered = bootstrap.render();
        assert!(rendered.contains(&before));
        assert!(rendered.contains(&after));
        assert!(rendered.contains("append"));
    }

    /// AC1 boundary: planning a real repository is read-only. The adapter has no
    /// write path at all, so a repository without `.axiom` gains nothing, and an
    /// unsafe relative path is refused instead of escaping the root.
    #[test]
    fn planning_a_real_repository_creates_no_directories() {
        let templates = templates();
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path();
        std::fs::write(root.join(AGENTS_PATH), "# Human text\n").expect("write AGENTS.md");
        let before = listing(root);

        let reader = LocalRepositoryReader::new(root);
        let plan = plan_repository(
            &RepositoryTarget::new("demo", root.display().to_string(), &reader),
            &templates,
        )
        .expect("planning is read-only");
        assert_eq!(plan.change, ChangeClass::Append);
        assert_eq!(
            plan.files.len(),
            3,
            "three owned artifacts would be written"
        );

        assert!(
            !root.join(".axiom").exists(),
            "planning must not create .axiom"
        );
        assert_eq!(listing(root), before, "planning must not write anything");

        let error = reader.read("../outside").expect_err("escape refused");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(RULE_PLAN_PATH)
        );
        assert!(reader.read("/etc/passwd").is_err());
        assert!(reader.read("C:/Windows/win.ini").is_err());
        assert!(reader.read("").is_err());
        assert!(reader.read(AGENTS_PATH).expect("read").is_some());
    }

    /// AC1 negative: a repository bootstrap will not touch is reported as a
    /// conflict inside the plan, with its stable rule and with no proposed
    /// writes, and the other repositories are still planned.
    #[test]
    fn a_refused_repository_is_reported_inside_the_plan() {
        let templates = templates();
        let begin = markers::BEGIN_MARKER;
        let end = markers::END_MARKER;
        let block = format!("{begin}\nbody\n{end}");
        let policy_bytes = templates.policy.clone();

        let mut unbalanced = MapRepositoryReader::new();
        unbalanced.insert(AGENTS_PATH, format!("# Human\n{begin}\nunterminated\n"));
        let plan = plan_one(&unbalanced, &templates);
        assert_eq!(plan.change, ChangeClass::Conflict);
        assert_eq!(
            plan.refusal.as_ref().map(|refusal| refusal.rule.as_str()),
            Some("markers-unbalanced")
        );

        let mut unowned_markers = MapRepositoryReader::new();
        unowned_markers.insert(AGENTS_PATH, format!("{block}\n"));
        let plan = plan_one(&unowned_markers, &templates);
        assert_eq!(
            plan.refusal.as_ref().map(|refusal| refusal.rule.as_str()),
            Some(RULE_MARKERS_WITHOUT_OWNERSHIP)
        );

        let mut not_utf8 = MapRepositoryReader::new();
        not_utf8.insert(AGENTS_PATH, b"caf\xe9\n".to_vec());
        let plan = plan_one(&not_utf8, &templates);
        assert_eq!(
            plan.refusal.as_ref().map(|refusal| refusal.rule.as_str()),
            Some(text::RULE_ENCODING)
        );

        let mut unowned_policy = MapRepositoryReader::new();
        unowned_policy.insert(policy::POLICY_PATH, policy_bytes.clone());
        let plan = plan_one(&unowned_policy, &templates);
        assert_eq!(
            plan.refusal.as_ref().map(|refusal| refusal.rule.as_str()),
            Some(policy::RULE_UNOWNED)
        );

        let ownership = Ownership::new(TEMPLATE_VERSION, &block, &policy_bytes);
        let mut edited_block = MapRepositoryReader::new();
        edited_block.insert(AGENTS_PATH, format!("{begin}\nbody edited\n{end}\n"));
        edited_block.insert(policy::POLICY_PATH, policy_bytes.clone());
        edited_block.insert(
            super::super::ownership::OWNERSHIP_PATH,
            ownership.encode().expect("encodes"),
        );
        let plan = plan_one(&edited_block, &templates);
        assert_eq!(
            plan.refusal.as_ref().map(|refusal| refusal.rule.as_str()),
            Some(super::super::ownership::RULE_BLOCK_EDITED)
        );

        assert!(plan.is_conflict());
        assert!(plan.files.is_empty(), "a conflict proposes no writes");
        assert!(plan.after_block_sha256.is_none());
        assert!(plan.refusal.is_some());

        // The conflict does not abort the run: a clean repository is still planned.
        let mut clean = MapRepositoryReader::new();
        clean.insert(AGENTS_PATH, "# Human text\n");
        let all = plan_all(
            &[
                RepositoryTarget::new("refused", "/repos/refused", &edited_block),
                RepositoryTarget::new("clean", "/repos/clean", &clean),
            ],
            &templates,
        )
        .expect("a conflict is part of the plan");
        assert_eq!(all.repositories.len(), 2);
        assert_eq!(all.conflicts().len(), 1);
        assert_eq!(all.repositories[1].change, ChangeClass::Append);
    }

    /// AC2 boundary: the plan is bound to its inputs. The same inputs produce
    /// the same digest, a changed input changes it, and a plan whose body was
    /// edited after approval is refused.
    #[test]
    fn the_plan_digest_binds_the_approved_inputs() {
        let templates = templates();
        let mut reader = MapRepositoryReader::new();
        reader.insert(AGENTS_PATH, "# Human text\n");
        let target = RepositoryTarget::new("demo", "/repos/demo", &reader);

        let first = plan_all(std::slice::from_ref(&target), &templates).expect("plan");
        let second = plan_all(std::slice::from_ref(&target), &templates).expect("plan");
        assert_eq!(first.digest, second.digest);
        assert_eq!(first.digest.len(), 64);

        let bytes = first.to_canonical_bytes().expect("canonical bytes");
        assert!(bytes.ends_with(b"\n"));
        assert_eq!(BootstrapPlan::parse(&bytes).expect("round-trip"), first);

        let mut other = MapRepositoryReader::new();
        other.insert(AGENTS_PATH, "# Different human text\n");
        let other_target = RepositoryTarget::new("demo", "/repos/demo", &other);
        let changed = plan_all(std::slice::from_ref(&other_target), &templates).expect("plan");
        assert_ne!(
            changed.digest, first.digest,
            "a changed input changes the plan"
        );

        let text = String::from_utf8(bytes.clone()).expect("UTF-8");
        let tampered = text.replace("\"append\"", "\"replace\"");
        assert_ne!(tampered, text);
        let error = BootstrapPlan::parse(tampered.as_bytes()).expect_err("tampered plan");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(RULE_PLAN_DIGEST)
        );

        assert_eq!(
            BootstrapPlan::parse(b"not json")
                .expect_err("malformed")
                .details()
                .get("rule")
                .map(String::as_str),
            Some(RULE_PLAN_MALFORMED)
        );
    }

    /// AC2: the whole corpus is planned through the real read-only adapter, and
    /// every vector lands on the outcome `fixtures/guides/bootstrap.md` and
    /// `vectors.json` document.
    #[test]
    fn the_bootstrap_corpus_vectors_plan_to_their_documented_outcome() {
        let root = corpus_root();
        let manifest = vectors();
        let vectors = manifest["vectors"].as_array().expect("vectors array");
        let templates = templates();

        let mut outcomes: BTreeMap<String, usize> = BTreeMap::new();
        for vector in vectors {
            let id = vector["id"].as_str().expect("id");
            let reader = LocalRepositoryReader::new(root.join("vectors").join(id).join("before"));
            let plan = plan_repository(
                &RepositoryTarget::new(id, format!("fixtures/{id}"), &reader),
                &templates,
            )
            .expect("planning a corpus vector");

            let expected = vector["outcome"].as_str().expect("outcome");
            assert_eq!(
                plan.change.as_str(),
                expected,
                "{id} planned the wrong outcome"
            );
            *outcomes.entry(expected.to_owned()).or_default() += 1;

            if expected == "conflict" {
                let refusal = plan
                    .refusal
                    .as_ref()
                    .unwrap_or_else(|| panic!("{id} has no rule"));
                let needle = vector["reason_contains"].as_str().expect("reason");
                assert!(
                    refusal
                        .message
                        .to_lowercase()
                        .contains(&needle.to_lowercase()),
                    "{id}: {:?} does not mention {needle:?}",
                    refusal.message
                );
                assert!(plan.files.is_empty(), "{id} proposes no writes");
                // A drifted owned artifact is reported with the hash of the
                // block that was actually present. A malformed marker shape or a
                // repository with no managed block has no block to hash.
                let has_managed_block = matches!(
                    id,
                    "edited_managed_block" | "edited_policy_file" | "managed_policy_missing"
                );
                assert_eq!(
                    plan.before_block_sha256.is_some(),
                    has_managed_block,
                    "{id} prior-block-hash reporting"
                );
            } else if expected == "unchanged" {
                assert!(!plan.would_write(), "{id} must be a no-op");
                assert_eq!(
                    plan.before_block_sha256, plan.after_block_sha256,
                    "{id} keeps its block hash"
                );
            } else {
                assert!(plan.would_write(), "{id} must propose writes");
                for file in &plan.files {
                    assert_eq!(
                        file.after_sha256,
                        sha256_hex(&file.bytes),
                        "{id} {}",
                        file.path
                    );
                }
                let agents = plan
                    .files
                    .iter()
                    .find(|file| file.path == AGENTS_PATH)
                    .unwrap_or_else(|| panic!("{id} must change AGENTS.md"));
                if vector["expect_prefix"].as_bool().unwrap_or(false) {
                    let original = std::fs::read(
                        root.join("vectors")
                            .join(id)
                            .join("before")
                            .join(AGENTS_PATH),
                    )
                    .expect("before AGENTS.md");
                    assert!(
                        agents.bytes.starts_with(&original),
                        "{id} did not keep the original bytes as an exact prefix"
                    );
                }
                for literal in vector["preserve_literals"].as_array().into_iter().flatten() {
                    let literal = literal.as_str().expect("literal");
                    assert!(
                        String::from_utf8_lossy(&agents.bytes).contains(literal),
                        "{id} dropped {literal:?}"
                    );
                }
            }
        }

        assert_eq!(outcomes.get("append").copied(), Some(5));
        assert_eq!(outcomes.get("replace").copied(), Some(2));
        assert_eq!(outcomes.get("unchanged").copied(), Some(1));
        assert_eq!(outcomes.get("conflict").copied(), Some(8));
        assert_eq!(outcomes.values().sum::<usize>(), 16);
    }

    fn listing(root: &Path) -> Vec<String> {
        let mut found = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(directory) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    found.push(format!("dir:{}", path.display()));
                    stack.push(path);
                } else {
                    found.push(format!("file:{}", path.display()));
                }
            }
        }
        found.sort();
        found
    }
}
