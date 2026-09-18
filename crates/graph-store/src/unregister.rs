//! Removing a solution binding without harming anything else (task B-020).
//!
//! `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` sections 4 and 10 describe how
//! work stops: stop claiming new work, then cancel in a defined order. Removing a
//! binding is the same shape. A busy instance is refused unless the caller
//! explicitly chooses a cancellation policy, pending jobs are cancelled rather
//! than abandoned, and a running worker is asked to stop instead of being left
//! with a lease nobody owns. The delete is scoped to one `solution_id`: files,
//! nodes, edges, jobs, revisions and checkpoints of every other instance survive,
//! and user source is never touched because no step of this module reads or
//! writes the filesystem.

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::is_portable_id;
use rusqlite::{params, Connection};

use crate::storage_error;

/// What to do about work that is still queued or running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainPolicy {
    /// Refuse the unregister while any job is leased or running.
    RefuseWhenBusy,
    /// Cancel queued work, and refuse while anything is running.
    CancelPending,
    /// Cancel queued work and ask running workers to stop.
    CancelRunning,
}

/// The binding to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnregisterRequest {
    solution_id: String,
    instance_key: String,
    policy: DrainPolicy,
}

impl UnregisterRequest {
    /// Remove the solution identified by `solution_id` and `instance_key`.
    #[must_use]
    pub fn new(
        solution_id: impl Into<String>,
        instance_key: impl Into<String>,
        policy: DrainPolicy,
    ) -> Self {
        Self {
            solution_id: solution_id.into(),
            instance_key: instance_key.into(),
            policy,
        }
    }

    /// Solution id.
    #[must_use]
    pub fn solution_id(&self) -> &str {
        &self.solution_id
    }

    /// Instance key the caller believes the solution is bound to.
    #[must_use]
    pub fn instance_key(&self) -> &str {
        &self.instance_key
    }

    /// Chosen drain policy.
    #[must_use]
    pub const fn policy(&self) -> DrainPolicy {
        self.policy
    }
}

/// What removing the binding changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnregisterOutcome {
    /// Queued jobs cancelled.
    pub cancelled_jobs: usize,
    /// Running jobs asked to stop.
    pub cancel_requested_jobs: usize,
    /// File rows removed with the solution.
    pub deleted_files: usize,
    /// Node rows removed with the solution.
    pub deleted_nodes: usize,
    /// Edge rows removed with the solution.
    pub deleted_edges: usize,
    /// Checkpoints belonging to other solutions, verified untouched.
    pub preserved_other_checkpoints: usize,
}

/// Remove one solution binding and everything it owns.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] for a non-portable solution id or key.
/// - [`ErrorCode::NotFound`] when the solution is not registered.
/// - [`ErrorCode::Conflict`] when the instance key does not match the stored
///   binding, so one worktree can never remove another worktree's state.
/// - [`ErrorCode::WorktreeBusy`] when the policy refuses a busy instance.
/// - [`ErrorCode::Internal`] for a storage failure.
pub fn unregister_solution(
    connection: &mut Connection,
    request: &UnregisterRequest,
) -> Result<UnregisterOutcome, AxiomError> {
    let solution_id = request.solution_id();
    if !is_portable_id(solution_id) || !is_portable_id(request.instance_key()) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "solution id and instance key must be portable Axiom identifiers",
        )
        .with_detail("solution_id", solution_id));
    }

    let transaction = connection
        .transaction()
        .map_err(|error| storage_error("unregister transaction", &error))?;

    let stored_key: Option<String> = transaction
        .query_row(
            "SELECT workspace_instance_id FROM solutions WHERE id = ?1",
            [solution_id],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .map_err(|error| storage_error("unregister solution lookup", &error))?;
    let Some(stored_key) = stored_key else {
        return Err(
            AxiomError::new(ErrorCode::NotFound, "solution is not registered")
                .with_detail("solution_id", solution_id),
        );
    };
    if stored_key != request.instance_key() {
        return Err(AxiomError::new(
            ErrorCode::Conflict,
            "instance key does not match the registered binding",
        )
        .with_detail("rule", "instance-key-mismatch")
        .with_detail("solution_id", solution_id)
        .with_detail("expected", stored_key));
    }

    let pending = scalar(
        &transaction,
        "SELECT COUNT(*) FROM jobs WHERE solution_id = ?1 AND state IN ('PENDING','RETRY_WAIT')",
        &[&solution_id as &dyn rusqlite::ToSql],
    )?;
    let running = scalar(
        &transaction,
        "SELECT COUNT(*) FROM jobs WHERE solution_id = ?1 AND state IN ('LEASED','RUNNING')",
        &[&solution_id as &dyn rusqlite::ToSql],
    )?;
    if running > 0 && request.policy() == DrainPolicy::RefuseWhenBusy {
        return Err(AxiomError::new(
            ErrorCode::WorktreeBusy,
            "solution still has running jobs; unregister refused",
        )
        .with_detail("rule", "running-jobs")
        .with_detail("solution_id", solution_id)
        .with_detail("observed", running.to_string()));
    }
    if running > 0 && request.policy() == DrainPolicy::CancelPending {
        return Err(AxiomError::new(
            ErrorCode::WorktreeBusy,
            "solution still has running jobs; cancel them first",
        )
        .with_detail("rule", "running-jobs")
        .with_detail("solution_id", solution_id)
        .with_detail("observed", running.to_string()));
    }

    let mut outcome = UnregisterOutcome {
        preserved_other_checkpoints: usize::try_from(scalar(
            &transaction,
            "SELECT COUNT(*) FROM runtime_checkpoints WHERE solution_id <> ?1",
            &[&solution_id as &dyn rusqlite::ToSql],
        )?)
        .unwrap_or(usize::MAX),
        ..UnregisterOutcome::default()
    };

    if pending > 0 {
        outcome.cancelled_jobs = transaction
            .execute(
                "UPDATE jobs SET state = 'CANCELLED' WHERE solution_id = ?1 \
                 AND state IN ('PENDING','RETRY_WAIT')",
                [solution_id],
            )
            .map_err(|error| storage_error("unregister cancel pending", &error))?;
    }
    if running > 0 {
        outcome.cancel_requested_jobs = transaction
            .execute(
                "UPDATE jobs SET state = 'CANCEL_REQUESTED' WHERE solution_id = ?1 \
                 AND state IN ('LEASED','RUNNING')",
                [solution_id],
            )
            .map_err(|error| storage_error("unregister cancel running", &error))?;
    }

    outcome.deleted_edges = delete_scoped(
        &transaction,
        "DELETE FROM edges WHERE owner_file_id IN \
         (SELECT id FROM files WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1)) \
         OR source_id IN \
         (SELECT id FROM nodes WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1))",
        solution_id,
        "unregister edges",
    )?;
    outcome.deleted_nodes = delete_scoped(
        &transaction,
        "DELETE FROM nodes WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1)",
        solution_id,
        "unregister nodes",
    )?;
    delete_scoped(
        &transaction,
        "DELETE FROM dirty_files WHERE file_id IN \
         (SELECT id FROM files WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1))",
        solution_id,
        "unregister dirty files",
    )?;
    delete_scoped(
        &transaction,
        "DELETE FROM job_files WHERE job_id IN (SELECT id FROM jobs WHERE solution_id = ?1) \
         OR file_id IN \
         (SELECT id FROM files WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1))",
        solution_id,
        "unregister job files",
    )?;
    delete_scoped(
        &transaction,
        "DELETE FROM job_attempts WHERE job_id IN (SELECT id FROM jobs WHERE solution_id = ?1)",
        solution_id,
        "unregister job attempts",
    )?;
    delete_scoped(
        &transaction,
        "DELETE FROM catalog_refs WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1)",
        solution_id,
        "unregister catalog refs",
    )?;
    delete_scoped(
        &transaction,
        "DELETE FROM published_generations WHERE project_id IN \
         (SELECT id FROM projects WHERE solution_id = ?1)",
        solution_id,
        "unregister published generations",
    )?;
    delete_scoped(
        &transaction,
        "DELETE FROM publish_outbox WHERE project_id IN \
         (SELECT id FROM projects WHERE solution_id = ?1) \
         OR revision_id IN (SELECT id FROM graph_revisions WHERE solution_id = ?1)",
        solution_id,
        "unregister publish outbox",
    )?;
    delete_scoped(
        &transaction,
        "DELETE FROM jobs WHERE solution_id = ?1",
        solution_id,
        "unregister jobs",
    )?;
    delete_scoped(
        &transaction,
        "DELETE FROM graph_revisions WHERE solution_id = ?1",
        solution_id,
        "unregister revisions",
    )?;
    delete_scoped(
        &transaction,
        "DELETE FROM runtime_checkpoints WHERE solution_id = ?1",
        solution_id,
        "unregister checkpoints",
    )?;
    outcome.deleted_files = delete_scoped(
        &transaction,
        "DELETE FROM files WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1)",
        solution_id,
        "unregister files",
    )?;
    delete_scoped(
        &transaction,
        "DELETE FROM projects WHERE solution_id = ?1",
        solution_id,
        "unregister projects",
    )?;
    delete_scoped(
        &transaction,
        "DELETE FROM solutions WHERE id = ?1",
        solution_id,
        "unregister solution",
    )?;
    transaction
        .commit()
        .map_err(|error| storage_error("unregister commit", &error))?;
    Ok(outcome)
}

fn scalar(
    transaction: &rusqlite::Transaction<'_>,
    sql: &str,
    args: &[&dyn rusqlite::ToSql],
) -> Result<i64, AxiomError> {
    transaction
        .query_row(sql, args, |row| row.get(0))
        .map_err(|error| storage_error("unregister count", &error))
}

fn delete_scoped(
    transaction: &rusqlite::Transaction<'_>,
    sql: &str,
    solution_id: &str,
    context: &str,
) -> Result<usize, AxiomError> {
    transaction
        .execute(sql, params![solution_id])
        .map_err(|error| storage_error(context, &error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        memory_store, seed_checkpoint, seed_file, seed_job, seed_node, seed_project, seed_solution,
    };

    fn count(connection: &Connection, sql: &str) -> i64 {
        connection
            .query_row(sql, [], |row| row.get(0))
            .expect("count")
    }

    #[test]
    fn unregister_cancels_queued_work_and_preserves_other_solutions() {
        let mut connection = memory_store();
        seed_solution(&connection, "sol-one", "inst-one");
        seed_solution(&connection, "sol-two", "inst-two");
        seed_project(&connection, "proj-one", "sol-one");
        seed_project(&connection, "proj-two", "sol-two");
        let file_one = seed_file(&connection, "proj-one", "src/App.cs");
        let file_two = seed_file(&connection, "proj-two", "src/Other.cs");
        seed_node(&connection, "node-one", "proj-one", file_one, "App.Run");
        seed_node(&connection, "node-two", "proj-two", file_two, "Other.Run");
        seed_job(&connection, "job-pending", "sol-one", "PENDING");
        seed_checkpoint(&connection, "cp-one", "sol-one");
        seed_checkpoint(&connection, "cp-two", "sol-two");

        let request = UnregisterRequest::new("sol-one", "inst-one", DrainPolicy::CancelPending);
        let outcome = unregister_solution(&mut connection, &request).expect("unregister");
        assert_eq!(outcome.cancelled_jobs, 1);
        assert_eq!(outcome.cancel_requested_jobs, 0);
        assert_eq!(outcome.deleted_files, 1);
        assert_eq!(outcome.deleted_nodes, 1);
        assert_eq!(outcome.preserved_other_checkpoints, 1);

        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM solutions WHERE id='sol-one'"
            ),
            0
        );
        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM solutions WHERE id='sol-two'"
            ),
            1
        );
        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM files WHERE project_id='proj-two'"
            ),
            1
        );
        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM nodes WHERE id='node-two'"
            ),
            1
        );
        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM runtime_checkpoints WHERE solution_id='sol-two'"
            ),
            1
        );
        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM runtime_checkpoints WHERE solution_id='sol-one'"
            ),
            0
        );
    }

    #[test]
    fn a_busy_or_mismatched_binding_is_refused() {
        let mut connection = memory_store();
        seed_solution(&connection, "sol-one", "inst-one");
        seed_project(&connection, "proj-one", "sol-one");
        seed_job(&connection, "job-running", "sol-one", "RUNNING");

        let busy = UnregisterRequest::new("sol-one", "inst-one", DrainPolicy::RefuseWhenBusy);
        assert_eq!(
            unregister_solution(&mut connection, &busy)
                .expect_err("busy instance")
                .code(),
            ErrorCode::WorktreeBusy
        );
        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM solutions WHERE id='sol-one'"
            ),
            1
        );

        let soft = UnregisterRequest::new("sol-one", "inst-one", DrainPolicy::CancelPending);
        assert_eq!(
            unregister_solution(&mut connection, &soft)
                .expect_err("running job")
                .code(),
            ErrorCode::WorktreeBusy
        );

        let mismatched = UnregisterRequest::new("sol-one", "inst-two", DrainPolicy::CancelRunning);
        assert_eq!(
            unregister_solution(&mut connection, &mismatched)
                .expect_err("instance key mismatch")
                .code(),
            ErrorCode::Conflict
        );

        let forced = UnregisterRequest::new("sol-one", "inst-one", DrainPolicy::CancelRunning);
        let outcome = unregister_solution(&mut connection, &forced).expect("forced unregister");
        assert_eq!(outcome.cancel_requested_jobs, 1);
        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM solutions WHERE id='sol-one'"
            ),
            0
        );
    }
}
