//! Queue inspection, retry and cooperative cancellation (task B-043).
//!
//! docs/16-CLI-AND-CONTROL-API.md section 2 fixes three operator commands over
//! the durable queue: `queue list --solution <id> --limit <n>`, `queue retry
//! --job <id>` and `queue cancel --job <id>`; the same section requires that
//! `cancel` is cooperative - the job reaches `CANCEL_REQUESTED` and only
//! `CANCELLED` once an acknowledgement arrives - and that cancelling never
//! discards dirty state or an unprocessed generation.
//!
//! Three properties shape this module:
//!
//! * **Every answer is scoped.** A caller must be authorized for the solution
//!   before it sees, retries or cancels one of that solution's jobs, so an
//!   unrelated solution's queue is never observable and [`ErrorCode::Forbidden`]
//!   is returned instead of an empty list.
//! * **Every answer carries a stable job id and state.** List results are
//!   deterministically ordered and bounded by an explicit limit; `retry` and
//!   `cancel` answer with the job's id and its resulting state rather than a
//!   bare acknowledgement.
//! * **Nothing is inferred.** An unknown state spelling is a storage fault, and
//!   a state that changed under the caller produces a conflict rather than a
//!   silently overwritten row.
//!
//! The state machine itself is not re-implemented here: transitions are checked
//! against [`graph_queue::ensure_transition`], the frozen table of
//! `contracts/queue-state-machine.md`.

use graph_core::error::{AxiomError, ErrorCode};
use graph_queue::{ensure_transition, JobState};
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

/// Default page size of `queue list`.
pub const DEFAULT_LIST_LIMIT: usize = 50;
/// Upper bound of an explicit `queue list --limit`.
pub const MAX_LIST_LIMIT: usize = 500;
/// Reason recorded when a job id has no row.
pub const REASON_JOB_NOT_FOUND: &str = "job-not-found";
/// Reason recorded when the caller is not authorized for a solution.
pub const REASON_SOLUTION_NOT_AUTHORIZED: &str = "solution-not-authorized";
/// Reason recorded when a solution has no registration row.
pub const REASON_SOLUTION_NOT_REGISTERED: &str = "solution-not-registered";
/// Reason recorded when a stored state spelling is not a contract state.
pub const REASON_UNKNOWN_JOB_STATE: &str = "unknown-job-state";
/// Reason recorded when a job's state moved under the caller.
pub const REASON_STALE_JOB_STATE: &str = "stale-job-state";
/// Reason recorded when a retry targets a job that is already queued.
pub const REASON_ALREADY_PENDING: &str = "already-pending";
/// Reason recorded when a retry targets a job a worker is holding.
pub const REASON_JOB_ACTIVE: &str = "job-active";
/// Reason recorded when a retry targets a job whose cancellation is pending.
pub const REASON_CANCEL_PENDING: &str = "cancel-pending";
/// Reason recorded when a retry targets a job that already succeeded.
pub const REASON_ALREADY_SUCCEEDED: &str = "already-succeeded";
/// Reason recorded when a retry targets a superseded job.
pub const REASON_SUPERSEDED: &str = "superseded";

/// A queue answer is scoped to a caller, never global.
pub trait QueueAccess {
    /// Whether this caller may observe and mutate `solution_id`'s jobs.
    ///
    /// # Errors
    /// [`ErrorCode::Forbidden`] for a solution this caller is not authorized
    /// for, [`ErrorCode::NotFound`] for a solution with no registration row.
    fn authorize(&self, solution_id: &str) -> Result<(), AxiomError>;
}

/// Scoped access backed by the `solutions` registration table.
///
/// An optional allowlist narrows a caller further: when it is present and does
/// not contain the solution, the call is refused with
/// [`ErrorCode::Forbidden`] even though the row exists.
pub struct RegistrationGate<'a> {
    connection: &'a Connection,
    authorized: Option<Vec<String>>,
}

impl<'a> RegistrationGate<'a> {
    /// Authorize every registered solution.
    #[must_use]
    pub const fn registered(connection: &'a Connection) -> Self {
        Self {
            connection,
            authorized: None,
        }
    }

    /// Authorize only the listed solutions.
    #[must_use]
    pub fn scoped(connection: &'a Connection, authorized: Vec<String>) -> Self {
        Self {
            connection,
            authorized: Some(authorized),
        }
    }
}

impl QueueAccess for RegistrationGate<'_> {
    fn authorize(&self, solution_id: &str) -> Result<(), AxiomError> {
        if let Some(authorized) = self.authorized.as_deref() {
            if !authorized.iter().any(|allowed| allowed == solution_id) {
                return Err(AxiomError::new(
                    ErrorCode::Forbidden,
                    "the caller is not authorized for this solution",
                )
                .with_detail("rule", REASON_SOLUTION_NOT_AUTHORIZED)
                .with_detail("solution_id", solution_id));
            }
        }
        let count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM solutions WHERE id = ?1",
                [solution_id],
                |row| row.get(0),
            )
            .map_err(|error| crate::commands::storage_error("solution lookup", &error))?;
        if count == 0 {
            return Err(AxiomError::new(
                ErrorCode::NotFound,
                "the solution is not registered on this host",
            )
            .with_detail("rule", REASON_SOLUTION_NOT_REGISTERED)
            .with_detail("solution_id", solution_id));
        }
        Ok(())
    }
}

/// One job as the operator sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueuedJob {
    id: String,
    solution_id: String,
    kind: String,
    scope_key: String,
    state: JobState,
    priority: i64,
    target_event_seq: i64,
    attempt: i64,
    fence: i64,
    ready_at: String,
    created_at: String,
    last_error_code: Option<String>,
}

impl QueuedJob {
    /// Stable job id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Owning solution.
    #[must_use]
    pub fn solution_id(&self) -> &str {
        &self.solution_id
    }

    /// Work kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Current contract state.
    #[must_use]
    pub const fn state(&self) -> JobState {
        self.state
    }

    /// Dispatch attempts so far.
    #[must_use]
    pub const fn attempt(&self) -> i64 {
        self.attempt
    }
}

/// A bounded page of one solution's queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueuePage {
    solution_id: String,
    limit: usize,
    total: i64,
    jobs: Vec<QueuedJob>,
}

impl QueuePage {
    /// Solution the page is scoped to.
    #[must_use]
    pub fn solution_id(&self) -> &str {
        &self.solution_id
    }

    /// Applied limit.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Jobs in the solution's queue, regardless of the page size.
    #[must_use]
    pub const fn total(&self) -> i64 {
        self.total
    }

    /// The returned page.
    #[must_use]
    pub fn jobs(&self) -> &[QueuedJob] {
        &self.jobs
    }
}

/// The outcome of `queue retry` or `queue cancel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JobMutation {
    action: &'static str,
    changed: bool,
    job: QueuedJob,
}

impl JobMutation {
    /// `retry` or `cancel`.
    #[must_use]
    pub const fn action(&self) -> &'static str {
        self.action
    }

    /// Whether the stored state actually moved.
    #[must_use]
    pub const fn changed(&self) -> bool {
        self.changed
    }

    /// The job after the operation.
    #[must_use]
    pub const fn job(&self) -> &QueuedJob {
        &self.job
    }
}

const JOB_COLUMNS: &str = "id, solution_id, kind, scope_key, state, priority, \
     target_event_seq, attempt, fence, ready_at, created_at, last_error_code";

/// List a solution's jobs, deterministically ordered and bounded.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] for a limit outside
///   `1..=`[`MAX_LIST_LIMIT`].
/// - [`ErrorCode::Forbidden`] / [`ErrorCode::NotFound`] from the access gate.
/// - [`ErrorCode::Internal`] for a storage failure or an unknown state spelling.
pub fn list(
    connection: &Connection,
    access: &dyn QueueAccess,
    solution_id: &str,
    limit: usize,
) -> Result<QueuePage, AxiomError> {
    if limit == 0 || limit > MAX_LIST_LIMIT {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "the queue page limit is outside the bounded range",
        )
        .with_detail("limit", MAX_LIST_LIMIT.to_string())
        .with_detail("observed", limit.to_string()));
    }
    access.authorize(solution_id)?;
    let total: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM jobs WHERE solution_id = ?1",
            [solution_id],
            |row| row.get(0),
        )
        .map_err(|error| crate::commands::storage_error("job count", &error))?;
    let sql = format!(
        "SELECT {JOB_COLUMNS} FROM jobs WHERE solution_id = ?1 \
         ORDER BY created_at, ready_at, id LIMIT ?2"
    );
    let mut statement = connection
        .prepare(&sql)
        .map_err(|error| crate::commands::storage_error("job list", &error))?;
    let bound = i64::try_from(limit).unwrap_or(i64::MAX);
    let rows = statement
        .query_map(rusqlite::params![solution_id, bound], job_from_row)
        .map_err(|error| crate::commands::storage_error("job list", &error))?;
    let mut jobs = Vec::with_capacity(limit);
    for row in rows {
        let job = row.map_err(|error| crate::commands::storage_error("job list row", &error))??;
        jobs.push(job);
    }
    Ok(QueuePage {
        solution_id: solution_id.to_string(),
        limit,
        total,
        jobs,
    })
}

/// Return a failed, retry-waiting or cancelled job to `PENDING`.
///
/// The attempt counter advances so the retry is auditable, the lease fields are
/// cleared and the last error code is forgotten, because the new attempt has not
/// failed yet. A job whose state moved since the operator looked at it is
/// refused rather than overwritten.
///
/// # Errors
/// - [`ErrorCode::NotFound`] when `job_id` has no row.
/// - [`ErrorCode::Forbidden`] when the caller is not authorized for the owning
///   solution.
/// - [`ErrorCode::Conflict`] for a job that is not retryable, or whose stored
///   state moved under the caller.
pub fn retry(
    connection: &Connection,
    access: &dyn QueueAccess,
    job_id: &str,
    ready_at: &str,
) -> Result<JobMutation, AxiomError> {
    let current = load_job(connection, job_id)?;
    access.authorize(&current.solution_id)?;
    match current.state {
        JobState::Failed | JobState::RetryWait | JobState::Cancelled => {}
        JobState::Pending => {
            return Err(conflict(
                REASON_ALREADY_PENDING,
                "the job is already queued",
                JobState::Pending,
            ));
        }
        JobState::Leased | JobState::Running => {
            return Err(conflict(
                REASON_JOB_ACTIVE,
                "a worker is holding this job",
                current.state,
            ));
        }
        JobState::CancelRequested => {
            return Err(conflict(
                REASON_CANCEL_PENDING,
                "the job has a pending cancellation",
                JobState::CancelRequested,
            ));
        }
        JobState::Succeeded => {
            return Err(conflict(
                REASON_ALREADY_SUCCEEDED,
                "the job already succeeded",
                JobState::Succeeded,
            ));
        }
        JobState::Superseded => {
            return Err(conflict(
                REASON_SUPERSEDED,
                "newer work superseded this job",
                JobState::Superseded,
            ));
        }
    }
    let changed = connection
        .execute(
            "UPDATE jobs SET state = ?1, attempt = attempt + 1, ready_at = ?2, \
             lease_owner = NULL, lease_until = NULL, last_error_code = NULL \
             WHERE id = ?3 AND state = ?4",
            rusqlite::params![
                JobState::Pending.as_str(),
                ready_at,
                job_id,
                current.state.as_str()
            ],
        )
        .map_err(|error| crate::commands::storage_error("job retry", &error))?;
    if changed != 1 {
        return Err(conflict(
            REASON_STALE_JOB_STATE,
            "the job state changed while the retry was prepared",
            current.state,
        ));
    }
    let job = load_job(connection, job_id)?;
    Ok(JobMutation {
        action: "retry",
        changed: true,
        job,
    })
}

/// Request cooperative cancellation of a job.
///
/// The state moves to `CANCEL_REQUESTED`; only an acknowledgement from the
/// lease owner moves it to `CANCELLED`. No dirty row, job file or unprocessed
/// generation is touched here. A repeat request on a job that is already
/// `CANCEL_REQUESTED` is idempotent and reports `changed = false`.
///
/// # Errors
/// - [`ErrorCode::NotFound`] when `job_id` has no row.
/// - [`ErrorCode::Forbidden`] when the caller is not authorized for the owning
///   solution.
/// - [`ErrorCode::Conflict`] for a terminal job, or when the stored state moved
///   under the caller.
pub fn cancel(
    connection: &Connection,
    access: &dyn QueueAccess,
    job_id: &str,
) -> Result<JobMutation, AxiomError> {
    let current = load_job(connection, job_id)?;
    access.authorize(&current.solution_id)?;
    if current.state == JobState::CancelRequested {
        return Ok(JobMutation {
            action: "cancel",
            changed: false,
            job: current,
        });
    }
    ensure_transition(current.state, JobState::CancelRequested)?;
    let changed = connection
        .execute(
            "UPDATE jobs SET state = ?1, lease_owner = NULL, lease_until = NULL \
             WHERE id = ?2 AND state = ?3",
            rusqlite::params![
                JobState::CancelRequested.as_str(),
                job_id,
                current.state.as_str()
            ],
        )
        .map_err(|error| crate::commands::storage_error("job cancel", &error))?;
    if changed != 1 {
        return Err(conflict(
            REASON_STALE_JOB_STATE,
            "the job state changed while the cancellation was prepared",
            current.state,
        ));
    }
    let job = load_job(connection, job_id)?;
    Ok(JobMutation {
        action: "cancel",
        changed: true,
        job,
    })
}

/// Load one job by its stable id.
///
/// # Errors
/// [`ErrorCode::NotFound`] when the id has no row, [`ErrorCode::Internal`] for a
/// storage failure or an unknown stored state.
pub fn load_job(connection: &Connection, job_id: &str) -> Result<QueuedJob, AxiomError> {
    let sql = format!("SELECT {JOB_COLUMNS} FROM jobs WHERE id = ?1");
    let row: Option<Result<QueuedJob, AxiomError>> = connection
        .query_row(&sql, [job_id], job_from_row)
        .optional()
        .map_err(|error| crate::commands::storage_error("job lookup", &error))?;
    match row {
        Some(job) => job,
        None => Err(AxiomError::new(ErrorCode::NotFound, "no such job")
            .with_detail("rule", REASON_JOB_NOT_FOUND)
            .with_detail("job_id", job_id)),
    }
}

fn job_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<QueuedJob, AxiomError>> {
    let id: String = row.get(0)?;
    let state_text: String = row.get(4)?;
    let Some(state) = JobState::parse(&state_text) else {
        return Ok(Err(AxiomError::new(
            ErrorCode::Internal,
            "the stored job state is not a contract state",
        )
        .with_detail("rule", REASON_UNKNOWN_JOB_STATE)
        .with_detail("job_id", id)
        .with_detail("actual", state_text)));
    };
    Ok(Ok(QueuedJob {
        id,
        solution_id: row.get(1)?,
        kind: row.get(2)?,
        scope_key: row.get(3)?,
        state,
        priority: row.get(5)?,
        target_event_seq: row.get(6)?,
        attempt: row.get(7)?,
        fence: row.get(8)?,
        ready_at: row.get(9)?,
        created_at: row.get(10)?,
        last_error_code: row.get(11)?,
    }))
}

fn conflict(rule: &str, message: &str, actual: JobState) -> AxiomError {
    AxiomError::new(ErrorCode::Conflict, message)
        .with_detail("rule", rule)
        .with_detail("actual", actual.as_str())
}
#[cfg(test)]
mod tests {
    use super::*;

    const SOLVED: &str = "2026-09-18T00:00:00Z";

    fn memory_store() -> Connection {
        let mut connection = Connection::open_in_memory().expect("in-memory sqlite");
        graph_store::migrations::apply(&mut connection).expect("schema v1 applies");
        connection
    }

    fn seed_solution(connection: &Connection, id: &str, instance: &str) {
        connection
            .execute(
                "INSERT INTO solutions(id, workspace_instance_id, profile, config_hash) \
                 VALUES(?1, ?2, 'default', 'hash')",
                rusqlite::params![id, instance],
            )
            .expect("seed solution");
    }

    fn seed_project(connection: &Connection, id: &str, solution_id: &str) {
        connection
            .execute(
                "INSERT INTO projects(id, solution_id, repo_id, relative_path) \
                 VALUES(?1, ?2, ?1, '.')",
                rusqlite::params![id, solution_id],
            )
            .expect("seed project");
    }

    fn seed_job(connection: &Connection, id: &str, solution_id: &str, state: &str, created: &str) {
        connection
            .execute(
                "INSERT INTO jobs(id, solution_id, kind, scope_key, state, priority, \
                 target_event_seq, attempt, fence, ready_at, created_at, last_error_code) \
                 VALUES(?1, ?2, 'ParseBatch', ?3, ?4, 3, 7, 2, 4, ?5, ?5, 'transient')",
                rusqlite::params![id, solution_id, id, state, created],
            )
            .expect("seed job");
    }

    fn fixture() -> Connection {
        let connection = memory_store();
        seed_solution(&connection, "sol-1", "inst-1");
        seed_solution(&connection, "sol-2", "inst-2");
        seed_project(&connection, "proj-app", "sol-1");
        seed_project(&connection, "proj-web", "sol-2");
        seed_job(
            &connection,
            "job-a",
            "sol-1",
            "PENDING",
            "2026-09-18T00:00:03Z",
        );
        seed_job(
            &connection,
            "job-b",
            "sol-1",
            "FAILED",
            "2026-09-18T00:00:01Z",
        );
        seed_job(
            &connection,
            "job-c",
            "sol-1",
            "CANCEL_REQUESTED",
            "2026-09-18T00:00:02Z",
        );
        seed_job(
            &connection,
            "job-x",
            "sol-2",
            "RUNNING",
            "2026-09-18T00:00:00Z",
        );
        connection
    }

    #[test]
    fn list_reports_stable_ids_and_states_in_a_deterministic_order() {
        let connection = fixture();
        let access = RegistrationGate::registered(&connection);
        let page = list(&connection, &access, "sol-1", DEFAULT_LIST_LIMIT).expect("page");
        assert_eq!(page.solution_id(), "sol-1");
        assert_eq!(page.total(), 3);
        assert_eq!(page.jobs().len(), 3);
        let ids: Vec<&str> = page.jobs().iter().map(QueuedJob::id).collect();
        assert_eq!(ids, ["job-b", "job-c", "job-a"], "ordered by creation time");
        let states: Vec<JobState> = page.jobs().iter().map(QueuedJob::state).collect();
        assert_eq!(
            states,
            [
                JobState::Failed,
                JobState::CancelRequested,
                JobState::Pending
            ]
        );
        assert_eq!(page.jobs()[0].attempt(), 2);

        let bounded = list(&connection, &access, "sol-1", 2).expect("bounded page");
        assert_eq!(bounded.limit(), 2);
        assert_eq!(bounded.total(), 3);
        assert_eq!(bounded.jobs().len(), 2);
    }

    #[test]
    fn list_refuses_a_solution_the_caller_is_not_authorized_for() {
        let connection = fixture();
        let access = RegistrationGate::scoped(&connection, vec![String::from("sol-2")]);
        let error = list(&connection, &access, "sol-1", DEFAULT_LIST_LIMIT)
            .expect_err("sol-1 is outside the scope");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_SOLUTION_NOT_AUTHORIZED)
        );
        assert_eq!(
            list(&connection, &access, "sol-2", DEFAULT_LIST_LIMIT)
                .expect("in scope")
                .total(),
            1
        );

        let registered = RegistrationGate::registered(&connection);
        let error = list(&connection, &registered, "sol-ghost", DEFAULT_LIST_LIMIT)
            .expect_err("unregistered solution");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_SOLUTION_NOT_REGISTERED)
        );
    }

    #[test]
    fn list_refuses_a_limit_outside_the_bounded_range() {
        let connection = fixture();
        let access = RegistrationGate::registered(&connection);
        for limit in [0_usize, MAX_LIST_LIMIT + 1] {
            let error = list(&connection, &access, "sol-1", limit).expect_err("limit refused");
            assert_eq!(error.code(), ErrorCode::ValidationError, "limit {limit}");
            assert_eq!(
                error.details().get("limit").map(String::as_str),
                Some(MAX_LIST_LIMIT.to_string().as_str())
            );
        }
    }

    #[test]
    fn retry_returns_a_failed_job_to_pending_with_a_new_attempt() {
        let connection = fixture();
        let access = RegistrationGate::registered(&connection);
        let mutation = retry(&connection, &access, "job-b", "2026-09-18T01:00:00Z").expect("retry");
        assert_eq!(mutation.action(), "retry");
        assert!(mutation.changed());
        assert_eq!(mutation.job().state(), JobState::Pending);
        assert_eq!(
            mutation.job().attempt(),
            3,
            "the retry advances the attempt"
        );
        assert_eq!(mutation.job().id(), "job-b");

        let stored = load_job(&connection, "job-b").expect("reload");
        assert_eq!(stored.state(), JobState::Pending);
        assert_eq!(stored.ready_at, "2026-09-18T01:00:00Z");
        assert!(stored.last_error_code.is_none(), "the new attempt is clean");
        assert_eq!(stored.fence, 4, "the fence is only advanced by a claim");

        let cancelled = retry(&connection, &access, "job-c", SOLVED);
        assert_eq!(
            cancelled
                .expect_err("a pending cancellation is not retryable")
                .details()
                .get("rule")
                .map(String::as_str),
            Some(REASON_CANCEL_PENDING)
        );
    }

    #[test]
    fn retry_refuses_states_that_are_not_retryable() {
        let connection = fixture();
        let access = RegistrationGate::registered(&connection);
        seed_job(
            &connection,
            "job-run",
            "sol-1",
            "RUNNING",
            "2026-09-18T00:00:04Z",
        );
        seed_job(
            &connection,
            "job-done",
            "sol-1",
            "SUCCEEDED",
            "2026-09-18T00:00:05Z",
        );
        seed_job(
            &connection,
            "job-super",
            "sol-1",
            "SUPERSEDED",
            "2026-09-18T00:00:06Z",
        );
        for (job, rule) in [
            ("job-a", REASON_ALREADY_PENDING),
            ("job-run", REASON_JOB_ACTIVE),
            ("job-done", REASON_ALREADY_SUCCEEDED),
            ("job-super", REASON_SUPERSEDED),
        ] {
            let error = retry(&connection, &access, job, SOLVED).expect_err("not retryable");
            assert_eq!(error.code(), ErrorCode::Conflict, "job {job}");
            assert_eq!(
                error.details().get("rule").map(String::as_str),
                Some(rule),
                "job {job}"
            );
        }

        let error = retry(&connection, &access, "job-ghost", SOLVED).expect_err("unknown job");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_JOB_NOT_FOUND)
        );

        let scoped = RegistrationGate::scoped(&connection, vec![String::from("sol-1")]);
        let error = retry(&connection, &scoped, "job-x", SOLVED).expect_err("foreign job");
        assert_eq!(error.code(), ErrorCode::Forbidden);
    }

    #[test]
    fn cancel_is_cooperative_and_preserves_unprocessed_state() {
        let connection = fixture();
        let access = RegistrationGate::registered(&connection);
        connection
            .execute(
                "INSERT INTO files(project_id, path, observed_hash, indexed_hash, \
                 desired_generation, indexed_generation) \
                 VALUES('proj-app', 'src/A.cs', 'a', 'b', 3, 1)",
                [],
            )
            .expect("seed file");
        let file_id = connection.last_insert_rowid();
        connection
            .execute(
                "INSERT INTO dirty_files(file_id, target_generation, first_seen, last_seen, reason) \
                 VALUES(?1, 3, '2026-09-18T00:00:00Z', '2026-09-18T00:00:00Z', 'content-change')",
                [file_id],
            )
            .expect("seed dirty row");

        let mutation = cancel(&connection, &access, "job-a").expect("cancel");
        assert_eq!(mutation.action(), "cancel");
        assert!(mutation.changed());
        assert_eq!(
            mutation.job().state(),
            JobState::CancelRequested,
            "cancellation is a request until a worker acknowledges it"
        );
        assert_eq!(mutation.job().id(), "job-a");
        let _ = &file_id;

        let dirty: i64 = connection
            .query_row("SELECT COUNT(*) FROM dirty_files", [], |row| row.get(0))
            .expect("dirty count");
        assert_eq!(
            dirty, 1,
            "cancelling never discards unprocessed dirty state"
        );
        let stored = load_job(&connection, "job-a").expect("reload");
        assert_ne!(stored.state(), JobState::Cancelled);

        let repeat = cancel(&connection, &access, "job-a").expect("idempotent cancel");
        assert!(!repeat.changed(), "a repeated request is a no-op");
        assert_eq!(repeat.job().state(), JobState::CancelRequested);

        let lease_owner: Option<String> = connection
            .query_row(
                "SELECT lease_owner FROM jobs WHERE id = 'job-a'",
                [],
                |row| row.get(0),
            )
            .expect("lease owner");
        assert!(lease_owner.is_none());
    }

    #[test]
    fn cancel_refuses_terminal_jobs_and_reports_the_running_state() {
        let connection = fixture();
        let access = RegistrationGate::registered(&connection);
        seed_job(
            &connection,
            "job-done",
            "sol-1",
            "SUCCEEDED",
            "2026-09-18T00:00:07Z",
        );
        let error = cancel(&connection, &access, "job-done").expect_err("terminal job");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("terminal_state")
        );

        let running = cancel(&connection, &access, "job-x").expect("running job is cancellable");
        assert_eq!(running.job().state(), JobState::CancelRequested);

        let error = cancel(&connection, &access, "job-ghost").expect_err("unknown job");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_JOB_NOT_FOUND)
        );
    }
}
