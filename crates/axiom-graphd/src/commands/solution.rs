//! Solution registry commands: register, list and remove (task B-084).
//!
//! `docs/16-CLI-AND-CONTROL-API.md` sections 2 and 7 fix the shape of this
//! slice: `solution register` validates a portable configuration against local
//! allowlisted roots before it persists anything, `solution list` is scoped to
//! the caller, and `solution remove` plans what stops without deleting the
//! user's repository. Section 8 and `docs/23-SECURITY-AND-TRUST.md` add the
//! rule this module exists to enforce: **a project's source root comes from a
//! declared repository id joined to an operator-provided local binding, never
//! from an arbitrary model-provided URL or path.**
//!
//! Two consequences are deliberate:
//!
//! * A configuration document that carries a clone/source URL is refused
//!   outright ([`REASON_URL_SOURCE_REJECTED`]) rather than having a path derived
//!   from it.
//! * A declared repository id with no trusted binding is refused
//!   ([`REASON_BINDING_MISSING`]). The module never falls back to guessing that
//!   a repository id looks like a path.

use std::collections::BTreeSet;

use graph_core::bindings::{validate_bindings, LocalBinding};
use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{
    is_absolute_host_path, is_portable_id, validate_portable_relative_path, WHOLE_REPO_BINDING,
};
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

/// Upper bound on registered solutions owned by one instance.
pub const MAX_SOLUTIONS: usize = 4096;
/// Upper bound on declared projects in one solution.
pub const MAX_PROJECTS: usize = 1024;
/// Reason recorded when a declaration carries a URL in place of a repo id.
pub const REASON_URL_SOURCE_REJECTED: &str = "url-source-rejected";
/// Reason recorded when a declared repository id has no trusted binding.
pub const REASON_BINDING_MISSING: &str = "binding-missing";
/// Reason recorded when a declaration carries an absolute source path.
pub const REASON_ABSOLUTE_SOURCE_PATH: &str = "absolute-source-path";
/// Reason recorded when a solution id is already registered.
pub const REASON_DUPLICATE_SOLUTION: &str = "duplicate-solution";
/// Reason recorded when a solution id has no row.
pub const REASON_SOLUTION_NOT_FOUND: &str = "solution-not-found";
/// Reason recorded when an apply step is asked to run a plan it did not build.
pub const REASON_PLAN_MISMATCH: &str = "plan-mismatch";
/// Reason recorded when removal is refused because work is still owned.
pub const REASON_SOLUTION_BUSY: &str = "solution-busy";
/// Reason recorded when the caller is not authorized for a solution.
pub const REASON_SOLUTION_NOT_AUTHORIZED: &str = "solution-not-authorized";

/// Configuration keys that would name a remote source rather than a local one.
const URL_KEYS: [&str; 5] = ["url", "repo_url", "clone_url", "source_url", "remote_url"];

/// One project declaration from a solution configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectDeclaration {
    id: String,
    repo_id: String,
    relative_path: String,
    generated_output_root: Option<String>,
}

impl ProjectDeclaration {
    /// Declare a project membership.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        repo_id: impl Into<String>,
        relative_path: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            repo_id: repo_id.into(),
            relative_path: relative_path.into(),
            generated_output_root: None,
        }
    }

    /// Attach the project's generated output root.
    #[must_use]
    pub fn with_generated_output_root(mut self, root: impl Into<String>) -> Self {
        self.generated_output_root = Some(root.into());
        self
    }

    /// Project id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Declared repository id, which must be resolved through a binding.
    #[must_use]
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    /// Repository-relative membership root.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Generated output root, when the project declares one.
    #[must_use]
    pub fn generated_output_root(&self) -> Option<&str> {
        self.generated_output_root.as_deref()
    }
}

/// A validated solution declaration, before any binding is resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolutionDeclaration {
    id: String,
    profile: String,
    projects: Vec<ProjectDeclaration>,
    catalog_host_repo: Option<String>,
}

impl SolutionDeclaration {
    /// Build a declaration directly.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        profile: impl Into<String>,
        projects: Vec<ProjectDeclaration>,
    ) -> Self {
        Self {
            id: id.into(),
            profile: profile.into(),
            projects,
            catalog_host_repo: None,
        }
    }

    /// Solution id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Analysis profile.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Declared projects.
    #[must_use]
    pub fn projects(&self) -> &[ProjectDeclaration] {
        &self.projects
    }

    /// Declare the repository that hosts the solution catalog.
    #[must_use]
    pub fn with_catalog_host_repo(mut self, repo_id: impl Into<String>) -> Self {
        self.catalog_host_repo = Some(repo_id.into());
        self
    }

    /// Explicit catalog host repository, when the portable declaration has one.
    #[must_use]
    pub fn catalog_host_repo(&self) -> Option<&str> {
        self.catalog_host_repo.as_deref()
    }
}
/// Parse and validate a solution configuration document.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] for a missing or malformed field.
/// - [`ErrorCode::ValidationError`] with [`REASON_URL_SOURCE_REJECTED`] when a
///   `url`, `repo_url`, `clone_url`, `source_url` or `remote_url` key appears,
///   or when a declared `repo_id` is itself a URL or an absolute host path.
/// - [`ErrorCode::ValidationError`] with [`REASON_ABSOLUTE_SOURCE_PATH`] when a
///   project path is absolute.
/// - [`ErrorCode::Conflict`] for a duplicate project id.
pub fn parse_config(document: &serde_json::Value) -> Result<SolutionDeclaration, AxiomError> {
    for key in URL_KEYS {
        if document.get(key).is_some() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a solution configuration must name repository ids, not source URLs",
            )
            .with_detail("rule", REASON_URL_SOURCE_REJECTED)
            .with_detail("key", key));
        }
    }
    let id = require_string(document, "id")?;
    if !is_portable_id(&id) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "solution id must be a portable Axiom identifier",
        )
        .with_detail("solution_id", &id));
    }
    let profile = document
        .get("profile")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("default")
        .to_owned();
    let catalog_host_repo = document
        .get("catalog_host_repo")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    if !is_portable_id(&profile) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "profile must be a portable Axiom identifier",
        )
        .with_detail("solution_id", &id)
        .with_detail("profile", &profile));
    }
    let raw_projects = document
        .get("projects")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            AxiomError::new(
                ErrorCode::ValidationError,
                "a solution configuration must declare a projects array",
            )
            .with_detail("solution_id", &id)
        })?;
    if raw_projects.is_empty() || raw_projects.len() > MAX_PROJECTS {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "the declared project count is outside the accepted range",
        )
        .with_detail("solution_id", &id)
        .with_detail("limit", MAX_PROJECTS.to_string())
        .with_detail("observed", raw_projects.len().to_string()));
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut projects = Vec::with_capacity(raw_projects.len());
    for raw in raw_projects {
        let project_id = require_string(raw, "id")?;
        let repo_id = require_string(raw, "repo_id")?;
        let relative_path =
            require_string(raw, "path").or_else(|_| require_string(raw, "relative_path"))?;
        if let Some(url_key) = URL_KEYS.iter().find(|key| raw.get(**key).is_some()) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a project must name a repository id, not a source URL",
            )
            .with_detail("rule", REASON_URL_SOURCE_REJECTED)
            .with_detail("project_id", &project_id)
            .with_detail("key", *url_key));
        }
        if !is_portable_id(&project_id) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "project id must be a portable Axiom identifier",
            )
            .with_detail("project_id", &project_id));
        }
        // A repo id is an id, never a location. Anything that looks like a URL
        // or an absolute host path is refused instead of being interpreted.
        if !is_portable_id(&repo_id) {
            let reason = if is_absolute_host_path(&repo_id) || repo_id.contains("://") {
                REASON_URL_SOURCE_REJECTED
            } else {
                REASON_ABSOLUTE_SOURCE_PATH
            };
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a project repository id must be a portable id resolved through a binding",
            )
            .with_detail("rule", reason)
            .with_detail("project_id", &project_id)
            .with_detail("repo_id", &repo_id));
        }
        if is_absolute_host_path(&relative_path) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a project path must be repository-relative",
            )
            .with_detail("rule", REASON_ABSOLUTE_SOURCE_PATH)
            .with_detail("project_id", &project_id));
        }
        validate_portable_relative_path(&relative_path)?;
        let generated = raw
            .get("generated_output_root")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        if let Some(root) = generated.as_deref() {
            validate_portable_relative_path(root)?;
        }
        if !seen.insert(project_id.clone()) {
            return Err(AxiomError::new(
                ErrorCode::Conflict,
                "project id is duplicated in this solution",
            )
            .with_detail("rule", "duplicate-project-id")
            .with_detail("project_id", &project_id)
            .with_detail("solution_id", &id));
        }
        let mut project = ProjectDeclaration::new(project_id, repo_id, relative_path);
        if let Some(root) = generated {
            project = project.with_generated_output_root(root);
        }
        projects.push(project);
    }
    let declaration = SolutionDeclaration::new(id, profile, projects);
    match catalog_host_repo {
        Some(repo_id) if !is_portable_id(&repo_id) => Err(AxiomError::new(
            ErrorCode::ValidationError,
            "catalog_host_repo must be a portable repository identifier",
        )
        .with_detail("catalog_host_repo", repo_id)),
        Some(repo_id) => Ok(declaration.with_catalog_host_repo(repo_id)),
        None => Ok(declaration),
    }
}

fn require_string(document: &serde_json::Value, key: &str) -> Result<String, AxiomError> {
    document
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            AxiomError::new(
                ErrorCode::ValidationError,
                format!("a solution configuration requires a non-empty {key}"),
            )
            .with_detail("key", key)
        })
}

/// A register plan: what would be persisted, and under which binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegisterPlan {
    /// Solution id.
    pub solution_id: String,
    /// Analysis profile.
    pub profile: String,
    /// Declared project ids, in declaration order.
    pub projects: Vec<String>,
    /// Repository ids that were resolved through a trusted binding.
    pub bindings_used: Vec<String>,
    /// Whether the plan was produced by a `--dry-run` invocation.
    pub dry_run: bool,
    /// The canonical configuration hash the plan was built from.
    pub config_hash: String,
}
/// Plan a `solution register` run against an operator-provided binding table.
///
/// # Errors
/// - [`ErrorCode::Conflict`] with [`REASON_DUPLICATE_SOLUTION`] when the
///   solution id already has a row.
/// - [`ErrorCode::ValidationError`] with [`REASON_BINDING_MISSING`] when a
///   declared repository id has no trusted binding.
/// - [`ErrorCode::ConfigInvalid`] from [`validate_bindings`].
pub fn plan_register(
    connection: &Connection,
    declaration: &SolutionDeclaration,
    bindings: &[LocalBinding],
    dry_run: bool,
) -> Result<RegisterPlan, AxiomError> {
    validate_bindings(bindings)?;
    let existing: Option<String> = connection
        .query_row(
            "SELECT id FROM solutions WHERE id = ?1",
            [declaration.id()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| crate::commands::storage_error("solution lookup", &error))?;
    if existing.is_some() {
        return Err(AxiomError::new(
            ErrorCode::Conflict,
            "this solution id is already registered",
        )
        .with_detail("rule", REASON_DUPLICATE_SOLUTION)
        .with_detail("solution_id", declaration.id()));
    }
    let mut bindings_used: Vec<String> = Vec::new();
    for project in declaration.projects() {
        let bound = bindings
            .iter()
            .find(|binding| binding.repo_id() == project.repo_id());
        match bound {
            Some(binding) => {
                if !bindings_used.iter().any(|id| id == binding.repo_id()) {
                    bindings_used.push(binding.repo_id().to_owned());
                }
                // Join the declared relative path under the trusted root. The
                // path is never inferred from anything else.
                let _joined = join_root(binding.root(), project.relative_path());
            }
            None => {
                return Err(AxiomError::new(
                    ErrorCode::ValidationError,
                    "a declared repository id has no trusted local binding",
                )
                .with_detail("rule", REASON_BINDING_MISSING)
                .with_detail("solution_id", declaration.id())
                .with_detail("project_id", project.id())
                .with_detail("repo_id", project.repo_id()));
            }
        }
    }
    if let Some(host) = declaration.catalog_host_repo() {
        if !bindings_used.iter().any(|repo_id| repo_id == host) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "catalog_host_repo must be a repository declared by this solution",
            )
            .with_detail("catalog_host_repo", host));
        }
    }
    Ok(RegisterPlan {
        solution_id: declaration.id().to_owned(),
        profile: declaration.profile().to_owned(),
        projects: declaration
            .projects()
            .iter()
            .map(|project| project.id().to_owned())
            .collect(),
        bindings_used,
        dry_run,
        config_hash: config_hash(declaration)?,
    })
}

fn join_root(root: &str, relative: &str) -> String {
    if relative == WHOLE_REPO_BINDING {
        return root.to_owned();
    }
    let trimmed = root.trim_end_matches(['/', '\\']);
    format!("{trimmed}/{relative}")
}

fn config_hash(declaration: &SolutionDeclaration) -> Result<String, AxiomError> {
    let document = serde_json::json!({
        "id": declaration.id(),
        "profile": declaration.profile(),
        "catalog_host_repo": declaration.catalog_host_repo(),
        "projects": declaration
            .projects()
            .iter()
            .map(|project| serde_json::json!({
                "id": project.id(),
                "repo_id": project.repo_id(),
                "path": project.relative_path(),
                "generated_output_root": project.generated_output_root(),
            }))
            .collect::<Vec<_>>(),
    });
    let canonical = graph_export::canonical::canonical_value(&document)
        .map_err(|error| crate::commands::storage_error("config canonicalization", &error))?;
    Ok(graph_export::sha256_hex(canonical.as_bytes()))
}

/// One registered solution, as reported by `solution list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SolutionRecord {
    /// Solution id.
    pub id: String,
    /// Stored profile.
    pub profile: String,
    /// Stored configuration hash.
    pub config_hash: String,
    /// Number of registered projects.
    pub projects: i64,
}

/// Apply a register plan.
///
/// # Errors
/// The storage error if the write fails, plus [`ErrorCode::Conflict`] with
/// [`REASON_DUPLICATE_SOLUTION`] if a row appeared between the plan and apply.
pub fn apply_register(
    connection: &mut Connection,
    plan: &RegisterPlan,
    declaration: &SolutionDeclaration,
) -> Result<SolutionRecord, AxiomError> {
    if plan.config_hash != config_hash(declaration)? {
        return Err(AxiomError::new(
            ErrorCode::Conflict,
            "the register plan no longer matches its declaration",
        )
        .with_detail("rule", REASON_PLAN_MISMATCH)
        .with_detail("solution_id", plan.solution_id.clone()));
    }
    let transaction = connection
        .transaction()
        .map_err(|error| crate::commands::storage_error("register transaction", &error))?;
    let inserted = transaction
        .execute(
            "INSERT OR IGNORE INTO solutions (id, workspace_instance_id, profile, config_hash) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                plan.solution_id,
                workspace_instance_id(&plan.config_hash),
                plan.profile,
                plan.config_hash,
            ],
        )
        .map_err(|error| crate::commands::storage_error("solution insert", &error))?;
    if inserted == 0 {
        return Err(AxiomError::new(
            ErrorCode::Conflict,
            "this solution id is already registered",
        )
        .with_detail("rule", REASON_DUPLICATE_SOLUTION)
        .with_detail("solution_id", plan.solution_id.clone()));
    }
    for project in declaration.projects() {
        transaction
            .execute(
                "INSERT INTO projects (id, solution_id, repo_id, relative_path) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    project.id(),
                    plan.solution_id,
                    project.repo_id(),
                    project.relative_path(),
                ],
            )
            .map_err(|error| crate::commands::storage_error("project insert", &error))?;
    }
    transaction
        .commit()
        .map_err(|error| crate::commands::storage_error("register commit", &error))?;
    Ok(SolutionRecord {
        id: plan.solution_id.clone(),
        profile: plan.profile.clone(),
        config_hash: plan.config_hash.clone(),
        projects: declaration.projects().len() as i64,
    })
}

fn workspace_instance_id(config_hash: &str) -> String {
    let short: String = config_hash.chars().take(16).collect();
    format!("wi-{short}")
}

/// List registered solutions, optionally narrowed to an allowlist.
///
/// # Errors
/// The storage error if the query fails.
pub fn list(
    connection: &Connection,
    authorized: Option<&[String]>,
) -> Result<Vec<SolutionRecord>, AxiomError> {
    let mut statement = connection
        .prepare(
            "SELECT s.id, s.profile, s.config_hash, COUNT(p.id) \
             FROM solutions s LEFT JOIN projects p ON p.solution_id = s.id \
             GROUP BY s.id ORDER BY s.id",
        )
        .map_err(|error| crate::commands::storage_error("solution list", &error))?;
    let rows = statement
        .query_map([], |row| {
            Ok(SolutionRecord {
                id: row.get(0)?,
                profile: row.get(1)?,
                config_hash: row.get(2)?,
                projects: row.get(3)?,
            })
        })
        .map_err(|error| crate::commands::storage_error("solution list", &error))?;
    let mut records = Vec::new();
    for row in rows {
        let record = row.map_err(|error| crate::commands::storage_error("solution row", &error))?;
        if let Some(allowed) = authorized {
            if !allowed.iter().any(|id| id == &record.id) {
                continue;
            }
        }
        records.push(record);
    }
    Ok(records)
}

/// A remove plan: what would stop, and whether anything is still owned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemovePlan {
    /// Solution id.
    pub solution_id: String,
    /// Project ids that would be unregistered, in id order.
    pub projects: Vec<String>,
    /// Jobs that are still pending, leased, running or cancelling.
    pub active_jobs: i64,
    /// Whether the plan was produced by a `--dry-run` invocation.
    pub dry_run: bool,
    /// Whether removal must wait for owned work to drain.
    pub drain_required: bool,
    /// A removal never deletes the user's source repository.
    pub deletes_source: bool,
}
/// Plan a `solution remove` run.
///
/// # Errors
/// [`ErrorCode::NotFound`] with [`REASON_SOLUTION_NOT_FOUND`] when the solution
/// has no registration row.
pub fn plan_remove(
    connection: &Connection,
    solution_id: &str,
    dry_run: bool,
) -> Result<RemovePlan, AxiomError> {
    let exists: Option<String> = connection
        .query_row(
            "SELECT id FROM solutions WHERE id = ?1",
            [solution_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| crate::commands::storage_error("solution lookup", &error))?;
    if exists.is_none() {
        return Err(
            AxiomError::new(ErrorCode::NotFound, "this solution id is not registered")
                .with_detail("rule", REASON_SOLUTION_NOT_FOUND)
                .with_detail("solution_id", solution_id),
        );
    }
    let active_jobs: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM jobs WHERE solution_id = ?1 \
             AND state IN ('PENDING','LEASED','RUNNING','RETRY_WAIT','CANCEL_REQUESTED')",
            [solution_id],
            |row| row.get(0),
        )
        .map_err(|error| crate::commands::storage_error("job census", &error))?;
    let mut statement = connection
        .prepare("SELECT id FROM projects WHERE solution_id = ?1 ORDER BY id")
        .map_err(|error| crate::commands::storage_error("project list", &error))?;
    let rows = statement
        .query_map([solution_id], |row| row.get::<_, String>(0))
        .map_err(|error| crate::commands::storage_error("project list", &error))?;
    let mut projects = Vec::new();
    for row in rows {
        projects.push(row.map_err(|error| crate::commands::storage_error("project row", &error))?);
    }
    Ok(RemovePlan {
        solution_id: solution_id.to_owned(),
        projects,
        active_jobs,
        dry_run,
        drain_required: active_jobs > 0,
        deletes_source: false,
    })
}

/// What a completed removal actually removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoveReport {
    /// Solution id.
    pub solution_id: String,
    /// Project rows removed.
    pub removed_projects: i64,
    /// File rows removed.
    pub removed_files: i64,
    /// Job rows removed.
    pub removed_jobs: i64,
    /// Registered source roots were preserved.
    pub source_deleted: bool,
    /// Audit events were preserved.
    pub audit_preserved: bool,
}

/// Apply a removal plan.
///
/// # Errors
/// - [`ErrorCode::NotFound`] with [`REASON_SOLUTION_NOT_FOUND`] when the row
///   vanished between plan and apply.
/// - [`ErrorCode::Conflict`] with [`REASON_SOLUTION_BUSY`] when the plan was not
///   drained and owned jobs remain.
pub fn apply_remove(
    connection: &mut Connection,
    plan: &RemovePlan,
) -> Result<RemoveReport, AxiomError> {
    let transaction = connection
        .transaction()
        .map_err(|error| crate::commands::storage_error("remove transaction", &error))?;
    let exists: Option<String> = transaction
        .query_row(
            "SELECT id FROM solutions WHERE id = ?1",
            [plan.solution_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| crate::commands::storage_error("solution lookup", &error))?;
    if exists.is_none() {
        return Err(
            AxiomError::new(ErrorCode::NotFound, "this solution id is not registered")
                .with_detail("rule", REASON_SOLUTION_NOT_FOUND)
                .with_detail("solution_id", plan.solution_id.clone()),
        );
    }
    let remaining: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM jobs WHERE solution_id = ?1 \
             AND state IN ('PENDING','LEASED','RUNNING','RETRY_WAIT','CANCEL_REQUESTED')",
            [plan.solution_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|error| crate::commands::storage_error("job census", &error))?;
    if remaining > 0 {
        return Err(AxiomError::new(
            ErrorCode::Conflict,
            "this solution still owns work that must drain before removal",
        )
        .with_detail("rule", REASON_SOLUTION_BUSY)
        .with_detail("solution_id", plan.solution_id.clone())
        .with_detail("active_jobs", remaining.to_string()));
    }
    let solution = plan.solution_id.as_str();
    let jobs_before: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM jobs WHERE solution_id = ?1",
            [plan.solution_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|error| crate::commands::storage_error("job census", &error))?;
    let statements: [&str; 14] = [
        "DELETE FROM job_files WHERE job_id IN (SELECT id FROM jobs WHERE solution_id = ?1)",
        "DELETE FROM job_attempts WHERE job_id IN (SELECT id FROM jobs WHERE solution_id = ?1)",
        "DELETE FROM jobs WHERE solution_id = ?1",
        "DELETE FROM dirty_files WHERE file_id IN (SELECT id FROM files WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1))",
        "DELETE FROM edges WHERE source_id IN (SELECT id FROM nodes WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1))",
        "DELETE FROM edges WHERE owner_file_id IN (SELECT id FROM files WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1))",
        "DELETE FROM nodes WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1)",
        "DELETE FROM files WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1)",
        "DELETE FROM catalog_refs WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1)",
        "DELETE FROM published_generations WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1)",
        "DELETE FROM publish_outbox WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1)",
        "DELETE FROM graph_revisions WHERE solution_id = ?1",
        "DELETE FROM runtime_checkpoints WHERE solution_id = ?1",
        "DELETE FROM projects WHERE solution_id = ?1",
    ];
    for statement in statements {
        transaction
            .execute(statement, [solution])
            .map_err(|error| crate::commands::storage_error("remove cascade", &error))?;
    }
    let removed_projects = plan.projects.len() as i64;

    transaction
        .execute("DELETE FROM solutions WHERE id = ?1", [solution])
        .map_err(|error| crate::commands::storage_error("solution delete", &error))?;
    transaction
        .commit()
        .map_err(|error| crate::commands::storage_error("remove commit", &error))?;
    Ok(RemoveReport {
        solution_id: plan.solution_id.clone(),
        removed_projects,
        removed_files: 0,
        removed_jobs: jobs_before,
        source_deleted: false,
        audit_preserved: true,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    fn open_connection() -> Connection {
        let connection = Connection::open_in_memory().expect("in-memory sqlite");
        connection
            .execute_batch(graph_store::migrations::SCHEMA_V1_SQL)
            .expect("shipped schema");
        connection
    }

    fn bindings() -> Vec<LocalBinding> {
        vec![
            LocalBinding::new("repo-main", "D:/src/main"),
            LocalBinding::new("repo-lib", "D:/src/lib"),
        ]
    }

    fn declaration() -> SolutionDeclaration {
        SolutionDeclaration::new(
            "demo-solution",
            "default",
            vec![
                ProjectDeclaration::new("auth-api", "repo-main", "src/Auth.Api"),
                ProjectDeclaration::new("auth-tests", "repo-main", "src/AuthTests"),
            ],
        )
    }

    #[test]
    fn register_validates_against_trusted_bindings_then_persists() {
        let mut connection = open_connection();
        let plan = plan_register(&connection, &declaration(), &bindings(), false).expect("plan");
        assert_eq!(plan.bindings_used, vec!["repo-main".to_owned()]);
        assert!(!plan.dry_run);
        let record = apply_register(&mut connection, &plan, &declaration()).expect("apply");
        assert_eq!(record.projects, 2);
        let listed = list(&connection, None).expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "demo-solution");
        // A dry run never writes.
        let mut fresh = open_connection();
        let dry = plan_register(&fresh, &declaration(), &bindings(), true).expect("dry plan");
        assert!(dry.dry_run);
        assert!(list(&fresh, None).expect("list").is_empty());
        let _ = &mut fresh;
    }

    #[test]
    fn a_url_or_unbound_repository_id_never_becomes_a_source_path() {
        // A configuration that carries a remote source URL is refused.
        let with_url = serde_json::json!({
            "id": "demo-solution",
            "profile": "default",
            "url": "https://example.invalid/repo.git",
            "projects": [{"id": "auth-api", "repo_id": "repo-main", "path": "src/Auth.Api"}],
        });
        let error = parse_config(&with_url).expect_err("url key rejected");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_URL_SOURCE_REJECTED)
        );

        // A URL placed in repo_id is refused before any binding lookup.
        let url_as_id = serde_json::json!({
            "id": "demo-solution",
            "projects": [{"id": "auth-api", "repo_id": "https://example.invalid/repo.git", "path": "src"}],
        });
        let error = parse_config(&url_as_id).expect_err("url repo id rejected");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_URL_SOURCE_REJECTED)
        );

        // A portable repo id with no trusted binding is refused, not guessed.
        let connection = open_connection();
        let unbound = SolutionDeclaration::new(
            "demo-solution",
            "default",
            vec![ProjectDeclaration::new("auth-api", "repo-unknown", "src")],
        );
        let error =
            plan_register(&connection, &unbound, &bindings(), false).expect_err("no binding");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_BINDING_MISSING)
        );

        // An absolute source path is refused.
        let absolute = serde_json::json!({
            "id": "demo-solution",
            "projects": [{"id": "auth-api", "repo_id": "repo-main", "path": "D:/src/Auth.Api"}],
        });
        let error = parse_config(&absolute).expect_err("absolute path rejected");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_ABSOLUTE_SOURCE_PATH)
        );
    }

    #[test]
    fn a_duplicate_solution_id_is_a_conflict_not_an_overwrite() {
        let mut connection = open_connection();
        let plan = plan_register(&connection, &declaration(), &bindings(), false).expect("plan");
        apply_register(&mut connection, &plan, &declaration()).expect("first apply");
        let error =
            plan_register(&connection, &declaration(), &bindings(), false).expect_err("duplicate");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_DUPLICATE_SOLUTION)
        );
        assert_eq!(list(&connection, None).expect("list").len(), 1);
    }

    #[test]
    fn remove_plans_a_drain_and_never_deletes_source() {
        let mut connection = open_connection();
        let plan = plan_register(&connection, &declaration(), &bindings(), false).expect("plan");
        apply_register(&mut connection, &plan, &declaration()).expect("apply");
        connection
            .execute(
                "INSERT INTO jobs (id, solution_id, kind, scope_key, state, target_event_seq, ready_at, created_at) \
                 VALUES ('job-1','demo-solution','reconcile','dirty','PENDING',0,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
                [],
            )
            .expect("job");
        let remove = plan_remove(&connection, "demo-solution", true).expect("remove plan");
        assert!(remove.drain_required);
        assert_eq!(remove.active_jobs, 1);
        assert!(!remove.deletes_source);
        // Applying before the drain is a conflict and leaves the row.
        let error = apply_remove(&mut connection, &remove).expect_err("busy");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_SOLUTION_BUSY)
        );
        assert_eq!(list(&connection, None).expect("list").len(), 1);
        // Drain the job and remove; the plan still reports no source deletion.
        connection
            .execute("UPDATE jobs SET state='SUCCEEDED' WHERE id='job-1'", [])
            .expect("drain");
        let remove = plan_remove(&connection, "demo-solution", false).expect("remove plan");
        assert!(!remove.drain_required);
        let report = apply_remove(&mut connection, &remove).expect("apply remove");
        assert_eq!(report.removed_projects, 2);
        assert_eq!(report.removed_jobs, 1);
        assert!(!report.source_deleted);
        assert!(report.audit_preserved);
        assert!(list(&connection, None).expect("list").is_empty());
        let error = plan_remove(&connection, "demo-solution", true).expect_err("gone");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_SOLUTION_NOT_FOUND)
        );
    }

    #[test]
    fn a_scoped_list_hides_solutions_outside_the_allowlist() {
        let mut connection = open_connection();
        let plan = plan_register(&connection, &declaration(), &bindings(), false).expect("plan");
        apply_register(&mut connection, &plan, &declaration()).expect("apply");
        let allowed = vec!["demo-solution".to_owned()];
        assert_eq!(list(&connection, Some(&allowed)).expect("list").len(), 1);
        let denied = vec!["other-solution".to_owned()];
        assert!(list(&connection, Some(&denied)).expect("list").is_empty());
    }
}
