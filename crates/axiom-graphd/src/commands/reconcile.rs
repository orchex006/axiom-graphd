//! `reconcile` scopes and the bounded publication barrier (task B-086).
//!
//! `docs/16-CLI-AND-CONTROL-API.md` section 2 fixes three scopes: `dirty`
//! closes the dirty closure and waits on a bounded publication barrier,
//! `project` enqueues an explicit project reconcile and returns a job id, and
//! `full` enqueues an explicit full analysis. A full analysis is never the
//! default for an ordinary edit, and an unsupported scope is refused rather than
//! coerced into one of the three.
//!
//! Exit codes are part of the contract, so two failures are pinned here: an
//! unsupported scope is a validation failure (exit 2) and an expired bounded
//! wait is `timeout/busy` (exit 7). A caller that waited past its deadline gets
//! [`REASON_RECONCILE_TIMEOUT`] and can retry; state is never discarded.

use graph_core::error::{AxiomError, ErrorCode};
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

/// The default `--timeout` of a bounded wait.
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
/// The smallest accepted explicit `--timeout`.
pub const MIN_TIMEOUT_MS: u64 = 100;
/// The largest accepted explicit `--timeout`.
pub const MAX_TIMEOUT_MS: u64 = 3_600_000;
/// The interval between barrier observations.
pub const POLL_INTERVAL_MS: u64 = 250;
/// Upper bound on hints accepted in one dirty batch.
pub const MAX_DIRTY_PATHS: usize = 4096;
/// Reason recorded when a scope is not one of the three contract scopes.
pub const REASON_UNSUPPORTED_SCOPE: &str = "unsupported-scope";
/// Reason recorded when `--scope project` omitted `--project`.
pub const REASON_PROJECT_REQUIRED: &str = "project-required";
/// Reason recorded when a project id was supplied for a scope that forbids it.
pub const REASON_PROJECT_NOT_ALLOWED: &str = "project-not-allowed";
/// Reason recorded when a project id is unknown in this solution.
pub const REASON_PROJECT_NOT_FOUND: &str = "project-not-found";
/// Reason recorded when a timeout is outside the accepted range.
pub const REASON_TIMEOUT_OUT_OF_RANGE: &str = "timeout-out-of-range";
/// Reason recorded when the bounded wait expired.
pub const REASON_RECONCILE_TIMEOUT: &str = "reconcile-timeout";
/// Reason recorded when the solution has no registration row.
pub const REASON_SOLUTION_NOT_REGISTERED: &str = "solution-not-registered";
/// Reason recorded when a dirty batch exceeds the accepted size.
pub const REASON_DIRTY_BATCH_TOO_LARGE: &str = "dirty-batch-too-large";

/// The three contract reconcile scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReconcileScope {
    /// Close the dirty closure and wait on the publication barrier.
    Dirty,
    /// Explicit project reconcile; returns a job id.
    Project,
    /// Explicit full analysis; never the default for an edit.
    Full,
}

impl ReconcileScope {
    /// Stable wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Dirty => "dirty",
            Self::Project => "project",
            Self::Full => "full",
        }
    }

    /// Stable job kind recorded in the queue.
    #[must_use]
    pub const fn job_kind(self) -> &'static str {
        match self {
            Self::Dirty => "reconcile-dirty",
            Self::Project => "reconcile-project",
            Self::Full => "analyze-full",
        }
    }

    /// Whether this scope waits on a bounded publication barrier.
    #[must_use]
    pub const fn waits(self) -> bool {
        matches!(self, Self::Dirty)
    }

    /// Whether this scope accepts an explicit `--project`.
    #[must_use]
    pub const fn accepts_project(self) -> bool {
        matches!(self, Self::Project)
    }

    /// Parse a wire spelling.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with [`REASON_UNSUPPORTED_SCOPE`].
    pub fn parse(text: &str) -> Result<Self, AxiomError> {
        match text {
            "dirty" => Ok(Self::Dirty),
            "project" => Ok(Self::Project),
            "full" => Ok(Self::Full),
            other => Err(AxiomError::new(
                ErrorCode::ValidationError,
                "an unsupported reconcile scope was requested",
            )
            .with_detail("rule", REASON_UNSUPPORTED_SCOPE)
            .with_detail("observed", other)
            .with_detail("accepted", "dirty, project, full")),
        }
    }
}

/// A parsed `reconcile` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileRequest {
    /// Requested scope.
    pub scope: ReconcileScope,
    /// Explicit project id, required by `project` and refused elsewhere.
    pub project: Option<String>,
    /// Whether the caller asked to wait on the barrier.
    pub wait: bool,
    /// Explicit timeout in milliseconds, or the default.
    pub timeout_ms: u64,
    /// Bounded dirty hints, used only by the `dirty` scope.
    pub dirty_paths: Vec<String>,
}
impl ReconcileRequest {
    /// Build a request for `scope` with the default timeout.
    #[must_use]
    pub fn new(scope: ReconcileScope) -> Self {
        Self {
            scope,
            project: None,
            wait: false,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            dirty_paths: Vec::new(),
        }
    }

    /// Set the explicit project id.
    #[must_use]
    pub fn with_project(mut self, project: impl Into<String>) -> Self {
        self.project = Some(project.into());
        self
    }

    /// Ask for a bounded wait.
    #[must_use]
    pub fn with_wait(mut self, wait: bool) -> Self {
        self.wait = wait;
        self
    }

    /// Set an explicit timeout.
    #[must_use]
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Attach bounded dirty hints.
    #[must_use]
    pub fn with_dirty_paths(mut self, paths: Vec<String>) -> Self {
        self.dirty_paths = paths;
        self
    }

    /// Validate the request shape before anything is enqueued.
    ///
    /// # Errors
    /// - [`ErrorCode::ValidationError`] with [`REASON_PROJECT_REQUIRED`] when
    ///   `project` was requested without `--project`.
    /// - [`ErrorCode::ValidationError`] with [`REASON_PROJECT_NOT_ALLOWED`] when
    ///   `--project` was supplied for `dirty` or `full`.
    /// - [`ErrorCode::ValidationError`] with [`REASON_TIMEOUT_OUT_OF_RANGE`].
    /// - [`ErrorCode::ValidationError`] with [`REASON_DIRTY_BATCH_TOO_LARGE`].
    pub fn validate(&self) -> Result<(), AxiomError> {
        match (self.scope, self.project.as_deref()) {
            (ReconcileScope::Project, None) => {
                return Err(AxiomError::new(
                    ErrorCode::ValidationError,
                    "scope project requires an explicit --project",
                )
                .with_detail("rule", REASON_PROJECT_REQUIRED));
            }
            (scope, Some(_)) if !scope.accepts_project() => {
                return Err(AxiomError::new(
                    ErrorCode::ValidationError,
                    "this scope does not accept an explicit --project",
                )
                .with_detail("rule", REASON_PROJECT_NOT_ALLOWED)
                .with_detail("scope", self.scope.wire()));
            }
            _ => {}
        }
        if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&self.timeout_ms) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "the requested timeout is outside the accepted range",
            )
            .with_detail("rule", REASON_TIMEOUT_OUT_OF_RANGE)
            .with_detail("minimum_ms", MIN_TIMEOUT_MS.to_string())
            .with_detail("maximum_ms", MAX_TIMEOUT_MS.to_string())
            .with_detail("observed_ms", self.timeout_ms.to_string()));
        }
        if self.dirty_paths.len() > MAX_DIRTY_PATHS {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "the dirty batch exceeds the accepted size",
            )
            .with_detail("rule", REASON_DIRTY_BATCH_TOO_LARGE)
            .with_detail("limit", MAX_DIRTY_PATHS.to_string())
            .with_detail("observed", self.dirty_paths.len().to_string()));
        }
        Ok(())
    }
}

/// The bounded publication barrier a `dirty` reconcile waits on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WaitBudget {
    /// Timer interval between observations.
    pub interval_ms: u64,
    /// Total wall-clock budget.
    pub deadline_ms: u64,
    /// Maximum observations allowed inside the deadline.
    pub max_observations: u64,
}

impl WaitBudget {
    /// Compute the bounded barrier budget for a validated request.
    #[must_use]
    pub fn for_request(request: &ReconcileRequest) -> Self {
        let interval_ms = POLL_INTERVAL_MS;
        let max_observations = if request.wait {
            request.timeout_ms / interval_ms
        } else {
            0
        };
        Self {
            interval_ms,
            deadline_ms: request.timeout_ms,
            max_observations,
        }
    }

    /// Whether the budget allows no observation at all.
    #[must_use]
    pub fn is_immediate(&self) -> bool {
        self.max_observations == 0
    }
}

/// The enqueued reconcile job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconcilePlan {
    /// Deterministic job id.
    pub job_id: String,
    /// Requested scope.
    pub scope: ReconcileScope,
    /// Stable queue `kind`.
    pub kind: String,
    /// Deduplication key for this scope.
    pub scope_key: String,
    /// Project id, when the scope was `project`.
    pub project: Option<String>,
    /// Bounded barrier budget.
    pub budget: WaitBudget,
    /// Dirty hints accepted into the job, in source order.
    pub dirty_paths: Vec<String>,
}

/// Plan and enqueue a reconcile job.
///
/// # Errors
/// The request validation error, [`ErrorCode::NotFound`] with
/// [`REASON_PROJECT_NOT_FOUND`] when an explicit project is not a member of the
/// solution, and [`ErrorCode::NotFound`] with [`REASON_SOLUTION_NOT_REGISTERED`]
/// when the solution has no row.
pub fn plan(
    connection: &Connection,
    solution_id: &str,
    request: &ReconcileRequest,
) -> Result<ReconcilePlan, AxiomError> {
    request.validate()?;
    let registered: Option<String> = connection
        .query_row(
            "SELECT id FROM solutions WHERE id = ?1",
            [solution_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| crate::commands::storage_error("solution lookup", &error))?;
    if registered.is_none() {
        return Err(
            AxiomError::new(ErrorCode::NotFound, "this solution id is not registered")
                .with_detail("rule", REASON_SOLUTION_NOT_REGISTERED)
                .with_detail("solution_id", solution_id),
        );
    }
    if let Some(project) = request.project.as_deref() {
        let found: Option<String> = connection
            .query_row(
                "SELECT id FROM projects WHERE solution_id = ?1 AND id = ?2",
                rusqlite::params![solution_id, project],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| crate::commands::storage_error("project lookup", &error))?;
        if found.is_none() {
            return Err(AxiomError::new(
                ErrorCode::NotFound,
                "the requested project is not a member of this solution",
            )
            .with_detail("rule", REASON_PROJECT_NOT_FOUND)
            .with_detail("solution_id", solution_id)
            .with_detail("project_id", project));
        }
    }
    let scope_key = match request.project.as_deref() {
        Some(project) => format!("{}:{project}", request.scope.wire()),
        None => request.scope.wire().to_owned(),
    };
    let digest = graph_export::sha256_hex(format!("{solution_id}\u{1f}{scope_key}").as_bytes());
    let job_id = format!("job-{}-{}", request.scope.wire(), &digest[..16]);
    Ok(ReconcilePlan {
        job_id,
        scope: request.scope,
        kind: request.scope.job_kind().to_owned(),
        scope_key,
        project: request.project.clone(),
        budget: WaitBudget::for_request(request),
        dirty_paths: request.dirty_paths.clone(),
    })
}

/// Report that a bounded wait expired.
///
/// The error is `timeout/busy` (exit 7) and is retryable by contract; nothing
/// the caller already submitted is discarded.
#[must_use]
pub fn timeout_error(observations: u64) -> AxiomError {
    AxiomError::new(
        ErrorCode::RateLimited,
        "the bounded publication barrier expired before the job completed",
    )
    .with_detail("rule", REASON_RECONCILE_TIMEOUT)
    .with_detail("observations", observations.to_string())
    .with_retryable(true)
}

/// Enforce a bounded wait: succeed when the job finished, otherwise time out.
///
/// # Errors
/// [`ErrorCode::RateLimited`] with [`REASON_RECONCILE_TIMEOUT`] when the budget
/// was exhausted without completion.
pub fn enforce_wait(budget: &WaitBudget, completed: bool) -> Result<(), AxiomError> {
    if completed {
        return Ok(());
    }
    if budget.is_immediate() {
        // The caller did not ask to wait, so it is not a timeout.
        return Ok(());
    }
    Err(timeout_error(budget.max_observations))
}
#[cfg(test)]
mod tests {
    use super::*;

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().expect("in-memory sqlite");
        connection
            .execute_batch(graph_store::migrations::SCHEMA_V1_SQL)
            .expect("shipped schema");
        connection
            .execute(
                "INSERT INTO solutions (id, workspace_instance_id, profile, config_hash) \
                 VALUES ('demo-solution','wi-demo','default','hash')",
                [],
            )
            .expect("solution");
        connection
            .execute(
                "INSERT INTO projects (id, solution_id, repo_id, relative_path) \
                 VALUES ('auth-api','demo-solution','repo-main','src/Auth.Api')",
                [],
            )
            .expect("project");
        connection
    }

    #[test]
    fn the_three_contract_scopes_plan_jobs_with_their_documented_shape() {
        let connection = connection();
        let dirty = plan(
            &connection,
            "demo-solution",
            &ReconcileRequest::new(ReconcileScope::Dirty)
                .with_wait(true)
                .with_dirty_paths(vec!["src/Auth.Api/AuthController.cs".to_owned()]),
        )
        .expect("dirty plan");
        assert_eq!(dirty.kind, "reconcile-dirty");
        assert_eq!(dirty.scope_key, "dirty");
        assert_eq!(
            dirty.budget.max_observations,
            DEFAULT_TIMEOUT_MS / POLL_INTERVAL_MS
        );
        assert_eq!(dirty.dirty_paths.len(), 1);

        let project = plan(
            &connection,
            "demo-solution",
            &ReconcileRequest::new(ReconcileScope::Project).with_project("auth-api"),
        )
        .expect("project plan");
        assert_eq!(project.kind, "reconcile-project");
        assert_eq!(project.scope_key, "project:auth-api");
        assert_eq!(project.project.as_deref(), Some("auth-api"));
        assert!(project.budget.is_immediate());

        let full = plan(
            &connection,
            "demo-solution",
            &ReconcileRequest::new(ReconcileScope::Full),
        )
        .expect("full plan");
        assert_eq!(full.kind, "analyze-full");
        assert_eq!(full.scope_key, "full");
        // A project-scoped job and a full job never collide.
        assert_ne!(project.job_id, full.job_id);
        assert_ne!(dirty.job_id, full.job_id);
        // Planning twice for the same scope is idempotent.
        let again = plan(
            &connection,
            "demo-solution",
            &ReconcileRequest::new(ReconcileScope::Project).with_project("auth-api"),
        )
        .expect("project plan again");
        assert_eq!(again.job_id, project.job_id);
    }

    #[test]
    fn an_unsupported_scope_is_a_validation_failure_with_the_documented_exit_code() {
        let error = ReconcileScope::parse("everything").expect_err("unsupported");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(error.exit_code().as_i32(), 2);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_UNSUPPORTED_SCOPE)
        );
        assert_eq!(ReconcileScope::parse("dirty"), Ok(ReconcileScope::Dirty));
        assert_eq!(
            ReconcileScope::parse("project"),
            Ok(ReconcileScope::Project)
        );
        assert_eq!(ReconcileScope::parse("full"), Ok(ReconcileScope::Full));
    }

    #[test]
    fn project_and_timeout_misuse_are_refused_before_anything_is_enqueued() {
        let connection = connection();
        let error = plan(
            &connection,
            "demo-solution",
            &ReconcileRequest::new(ReconcileScope::Project),
        )
        .expect_err("project required");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_PROJECT_REQUIRED)
        );

        let error = plan(
            &connection,
            "demo-solution",
            &ReconcileRequest::new(ReconcileScope::Full).with_project("auth-api"),
        )
        .expect_err("project not allowed");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_PROJECT_NOT_ALLOWED)
        );

        let error = plan(
            &connection,
            "demo-solution",
            &ReconcileRequest::new(ReconcileScope::Dirty).with_timeout_ms(1),
        )
        .expect_err("timeout too small");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_TIMEOUT_OUT_OF_RANGE)
        );
        let error = plan(
            &connection,
            "demo-solution",
            &ReconcileRequest::new(ReconcileScope::Dirty).with_timeout_ms(MAX_TIMEOUT_MS + 1),
        )
        .expect_err("timeout too large");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_TIMEOUT_OUT_OF_RANGE)
        );

        let error = plan(
            &connection,
            "demo-solution",
            &ReconcileRequest::new(ReconcileScope::Project).with_project("ghost"),
        )
        .expect_err("unknown project");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_PROJECT_NOT_FOUND)
        );
    }

    #[test]
    fn an_expired_bounded_wait_is_a_retryable_timeout_with_exit_seven() {
        let request = ReconcileRequest::new(ReconcileScope::Dirty).with_wait(true);
        let budget = WaitBudget::for_request(&request);
        assert!(!budget.is_immediate());
        let error = enforce_wait(&budget, false).expect_err("expired");
        assert_eq!(error.code(), ErrorCode::RateLimited);
        assert_eq!(error.exit_code().as_i32(), 7);
        assert!(error.retryable());
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_RECONCILE_TIMEOUT)
        );
        // Completion and a non-waiting call both succeed.
        assert!(enforce_wait(&budget, true).is_ok());
        let no_wait = WaitBudget::for_request(&ReconcileRequest::new(ReconcileScope::Dirty));
        assert!(no_wait.is_immediate());
        assert!(enforce_wait(&no_wait, false).is_ok());
    }

    #[test]
    fn an_oversized_dirty_batch_and_an_unregistered_solution_are_refused() {
        let connection = connection();
        let oversized: Vec<String> = (0..=MAX_DIRTY_PATHS)
            .map(|index| format!("src/file-{index}.rs"))
            .collect();
        let error = plan(
            &connection,
            "demo-solution",
            &ReconcileRequest::new(ReconcileScope::Dirty).with_dirty_paths(oversized),
        )
        .expect_err("too large");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_DIRTY_BATCH_TOO_LARGE)
        );
        let error = plan(
            &connection,
            "ghost-solution",
            &ReconcileRequest::new(ReconcileScope::Full),
        )
        .expect_err("unregistered");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_SOLUTION_NOT_REGISTERED)
        );
    }
}
