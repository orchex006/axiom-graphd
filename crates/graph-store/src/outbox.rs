//! Durable publication outbox (task B-076).
//!
//! docs/sqlite-schema-v1.sql already carries `publish_outbox`, so this module
//! uses the shipped table rather than inventing a second one. The contract has
//! two halves:
//!
//! * the analysis revision and the publish intent are written inside one
//!   `BEGIN IMMEDIATE` transaction, so a crash cannot commit the analysis while
//!   losing the intent, or record an intent for analysis that was rolled back;
//! * `idempotency_key` is unique, so a crashed publisher replays the same
//!   intent as many times as it likes and publishes the generation once.

use graph_core::error::{AxiomError, ErrorCode};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::storage_error;

/// Operation recorded for a single-project publication.
pub const OPERATION_PROJECT: &str = "project";
/// Operation recorded for a whole-solution catalog publication.
pub const OPERATION_CATALOG: &str = "catalog";

/// What is being published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// One project's generation.
    Project,
    /// The pinned multi-project catalog.
    Catalog,
}

impl Operation {
    /// The stable database spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Operation::Project => OPERATION_PROJECT,
            Operation::Catalog => OPERATION_CATALOG,
        }
    }

    /// Parse the database spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            OPERATION_PROJECT => Some(Operation::Project),
            OPERATION_CATALOG => Some(Operation::Catalog),
            _ => None,
        }
    }
}

/// Where an outbox row is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxState {
    /// The intent is durable and not yet published.
    Pending,
    /// The generation is staged and waiting for the pointer switch.
    Staged,
    /// The generation is published and must never be replayed.
    Published,
    /// Publication failed and is reported rather than retried blindly.
    Failed,
}

impl OutboxState {
    /// The stable database spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            OutboxState::Pending => "PENDING",
            OutboxState::Staged => "STAGED",
            OutboxState::Published => "PUBLISHED",
            OutboxState::Failed => "FAILED",
        }
    }

    /// Parse the database spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "PENDING" => Some(OutboxState::Pending),
            "STAGED" => Some(OutboxState::Staged),
            "PUBLISHED" => Some(OutboxState::Published),
            "FAILED" => Some(OutboxState::Failed),
            _ => None,
        }
    }

    /// Whether a publisher still has to act on this row.
    #[must_use]
    pub const fn is_actionable(self) -> bool {
        matches!(self, OutboxState::Pending | OutboxState::Staged)
    }
}

/// The analysis revision the intent publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisCommit {
    /// The solution the revision belongs to.
    pub solution_id: String,
    /// The event sequence the revision was computed at.
    pub event_seq: i64,
    /// The profile the analysis ran under.
    pub profile: String,
    /// The fingerprint of the analysed source.
    pub source_fingerprint: String,
    /// The commit or worktree revision string.
    pub created_at: String,
}

/// A durable intent to publish one generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishIntent {
    /// Stable row identity.
    pub id: String,
    /// The project published, absent for a catalog publication.
    pub project_id: Option<String>,
    /// What is published.
    pub operation: Operation,
    /// The unique key that makes replay idempotent.
    pub idempotency_key: String,
    /// The generation published.
    pub generation_id: Option<String>,
}

/// A stored outbox row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    /// Stable row identity.
    pub id: String,
    /// The revision the intent belongs to.
    pub revision_id: i64,
    /// The project published, absent for a catalog publication.
    pub project_id: Option<String>,
    /// What is published.
    pub operation: Operation,
    /// Where the row is in its lifecycle.
    pub state: OutboxState,
    /// The replay key.
    pub idempotency_key: String,
    /// The generation published.
    pub generation_id: Option<String>,
    /// The last recorded error.
    pub last_error: Option<String>,
}

/// What one replay pass found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReplayReport {
    /// Intents the publisher must act on, oldest first.
    pub replayed: Vec<OutboxRow>,
    /// Intents already published, which replay must not touch.
    pub already_published: usize,
}

impl ReplayReport {
    /// Whether there is nothing left to do.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.replayed.is_empty()
    }
}

/// Write the analysis revision and its publish intent in one transaction.
///
/// # Errors
///
/// * [`ErrorCode::Conflict`] when the analysis revision already exists, because
///   the caller is reusing an event sequence;
/// * [`ErrorCode::Conflict`] when the idempotency key already exists with a
///   different intent;
/// * [`ErrorCode::Internal`] for any other storage failure.
///
/// Nothing is written when either half fails: the transaction is rolled back.
pub fn commit_analysis_and_intent(
    connection: &mut Connection,
    commit: &AnalysisCommit,
    intent: &PublishIntent,
) -> Result<i64, AxiomError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| storage_error("begin publish transaction", &error))?;
    transaction
        .execute(
            "INSERT INTO graph_revisions(solution_id, event_seq, profile, source_fingerprint, created_at) \
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                commit.solution_id,
                commit.event_seq,
                commit.profile,
                commit.source_fingerprint,
                commit.created_at
            ],
        )
        .map_err(|error| storage_error("insert graph revision", &error))?;
    let revision_id = transaction.last_insert_rowid();
    let existing: Option<String> = transaction
        .query_row(
            "SELECT id FROM publish_outbox WHERE idempotency_key = ?1",
            params![intent.idempotency_key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| storage_error("read publish intent", &error))?;
    if let Some(existing) = existing {
        if existing != intent.id {
            return Err(AxiomError::new(
                ErrorCode::Conflict,
                format!(
                    "idempotency key {} already belongs to intent {existing}",
                    intent.idempotency_key
                ),
            ));
        }
    } else {
        transaction
            .execute(
                "INSERT INTO publish_outbox(id, revision_id, project_id, operation, state, idempotency_key, generation_id) \
                 VALUES(?1, ?2, ?3, ?4, 'PENDING', ?5, ?6)",
                params![
                    intent.id,
                    revision_id,
                    intent.project_id,
                    intent.operation.as_str(),
                    intent.idempotency_key,
                    intent.generation_id
                ],
            )
            .map_err(|error| storage_error("insert publish intent", &error))?;
    }
    transaction
        .commit()
        .map_err(|error| storage_error("commit publish transaction", &error))?;
    Ok(revision_id)
}

/// Record an intent for an already-committed revision.
///
/// Returns `false` when the idempotency key was already present, which is what
/// makes a repeated call safe.
///
/// # Errors
///
/// Returns [`ErrorCode::Internal`] for a storage failure.
pub fn enqueue(
    connection: &Connection,
    revision_id: i64,
    intent: &PublishIntent,
) -> Result<bool, AxiomError> {
    let changed = connection
        .execute(
            "INSERT OR IGNORE INTO publish_outbox(id, revision_id, project_id, operation, state, idempotency_key, generation_id) \
             VALUES(?1, ?2, ?3, ?4, 'PENDING', ?5, ?6)",
            params![
                intent.id,
                revision_id,
                intent.project_id,
                intent.operation.as_str(),
                intent.idempotency_key,
                intent.generation_id
            ],
        )
        .map_err(|error| storage_error("enqueue publish intent", &error))?;
    Ok(changed == 1)
}

/// Move an intent to a new state.
///
/// # Errors
///
/// * [`ErrorCode::NotFound`] when the intent does not exist;
/// * [`ErrorCode::Conflict`] when the transition would reopen a published row,
///   because a published generation must never be replayed.
pub fn mark(
    connection: &Connection,
    id: &str,
    state: OutboxState,
    error: Option<&str>,
) -> Result<(), AxiomError> {
    let current: Option<String> = connection
        .query_row(
            "SELECT state FROM publish_outbox WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|failure| storage_error("read publish intent", &failure))?;
    let Some(current) = current else {
        return Err(AxiomError::new(
            ErrorCode::NotFound,
            format!("publish intent {id} does not exist"),
        ));
    };
    if current == OutboxState::Published.as_str() && state != OutboxState::Published {
        return Err(AxiomError::new(
            ErrorCode::Conflict,
            format!("publish intent {id} is already published and cannot be reopened"),
        ));
    }
    connection
        .execute(
            "UPDATE publish_outbox SET state = ?2, last_error = ?3 WHERE id = ?1",
            params![id, state.as_str(), error],
        )
        .map_err(|failure| storage_error("update publish intent", &failure))?;
    Ok(())
}

/// Every stored intent, oldest first.
///
/// # Errors
///
/// Returns [`ErrorCode::Internal`] for a storage failure or an unreadable row.
pub fn all(connection: &Connection) -> Result<Vec<OutboxRow>, AxiomError> {
    read_rows(connection, "")
}

/// The intents a publisher still has to act on.
///
/// # Errors
///
/// Returns [`ErrorCode::Internal`] for a storage failure or an unreadable row.
pub fn pending(connection: &Connection) -> Result<Vec<OutboxRow>, AxiomError> {
    read_rows(
        connection,
        "AND state IN ('PENDING','STAGED','FAILED') ORDER BY rowid",
    )
}

/// Replay after a crash.
///
/// Rows that are already published are counted but not returned, so replaying
/// twice publishes once.
///
/// # Errors
///
/// The same errors as [`all`].
pub fn replay(connection: &Connection) -> Result<ReplayReport, AxiomError> {
    let rows = all(connection)?;
    let already_published = rows
        .iter()
        .filter(|row| row.state == OutboxState::Published)
        .count();
    let replayed = rows
        .into_iter()
        .filter(|row| row.state != OutboxState::Published)
        .collect();
    Ok(ReplayReport {
        replayed,
        already_published,
    })
}

fn read_rows(connection: &Connection, tail: &str) -> Result<Vec<OutboxRow>, AxiomError> {
    let sql = format!(
        "SELECT id, revision_id, project_id, operation, state, idempotency_key, generation_id, last_error \
         FROM publish_outbox WHERE 1 = 1 {tail}"
    );
    let mut statement = connection
        .prepare(&sql)
        .map_err(|error| storage_error("prepare outbox query", &error))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        })
        .map_err(|error| storage_error("query outbox", &error))?;
    let mut out = Vec::new();
    for row in rows {
        let (
            id,
            revision_id,
            project_id,
            operation,
            state,
            idempotency_key,
            generation_id,
            last_error,
        ) = row.map_err(|error| storage_error("read outbox row", &error))?;
        let operation = Operation::parse(&operation).ok_or_else(|| {
            AxiomError::new(
                ErrorCode::Internal,
                format!("publish_outbox row {id} has unknown operation {operation}"),
            )
        })?;
        let state = OutboxState::parse(&state).ok_or_else(|| {
            AxiomError::new(
                ErrorCode::Internal,
                format!("publish_outbox row {id} has unknown state {state}"),
            )
        })?;
        out.push(OutboxRow {
            id,
            revision_id,
            project_id,
            operation,
            state,
            idempotency_key,
            generation_id,
            last_error,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{memory_store, seed_project, seed_solution};

    fn revision(profile: &str) -> AnalysisCommit {
        AnalysisCommit {
            solution_id: String::from("sol-1"),
            event_seq: 7,
            profile: profile.to_owned(),
            source_fingerprint: String::from("fp-1"),
            created_at: String::from("2026-09-18T00:00:00Z"),
        }
    }

    fn intent(id: &str, key: &str) -> PublishIntent {
        PublishIntent {
            id: id.to_owned(),
            project_id: Some(String::from("proj-1")),
            operation: Operation::Project,
            idempotency_key: key.to_owned(),
            generation_id: Some("a".repeat(64)),
        }
    }

    fn seeded() -> Connection {
        let connection = memory_store();
        seed_solution(&connection, "sol-1", "instance-1");
        seed_project(&connection, "proj-1", "sol-1");
        connection
    }

    #[test]
    fn the_analysis_commit_and_the_publish_intent_are_written_together() {
        let mut connection = seeded();
        let revision_id = commit_analysis_and_intent(
            &mut connection,
            &revision("default"),
            &intent("outbox-1", "key-1"),
        )
        .expect("commit");
        let rows = all(&connection).expect("rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].revision_id, revision_id);
        assert_eq!(rows[0].state, OutboxState::Pending);
        assert_eq!(rows[0].operation, Operation::Project);
        assert!(rows[0].state.is_actionable());
    }

    #[test]
    fn a_failed_analysis_commit_leaves_no_publish_intent() {
        let mut connection = seeded();
        commit_analysis_and_intent(
            &mut connection,
            &revision("default"),
            &intent("outbox-1", "key-1"),
        )
        .expect("first commit");
        // A second publication of the same revision must not be recorded, and
        // must not leave a dangling intent behind.
        let mut duplicate = revision("default");
        duplicate.event_seq = 8;
        let failure =
            commit_analysis_and_intent(&mut connection, &duplicate, &intent("outbox-2", "key-1"))
                .expect_err("a conflicting key must fail");
        assert_eq!(failure.code(), ErrorCode::Conflict);

        let rows = all(&connection).expect("rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "outbox-1");
        let revisions: i64 = connection
            .query_row("SELECT COUNT(*) FROM graph_revisions", [], |row| row.get(0))
            .expect("count");
        assert_eq!(revisions, 1);
    }

    #[test]
    fn replaying_a_crashed_publication_is_idempotent() {
        let mut connection = seeded();
        commit_analysis_and_intent(
            &mut connection,
            &revision("default"),
            &intent("outbox-1", "key-1"),
        )
        .expect("commit");

        let first = replay(&connection).expect("first replay");
        assert_eq!(first.replayed.len(), 1);
        assert_eq!(first.already_published, 0);

        mark(&connection, "outbox-1", OutboxState::Published, None).expect("publish");
        let second = replay(&connection).expect("second replay");
        assert!(second.is_empty());
        assert_eq!(second.already_published, 1);

        let reopened = mark(&connection, "outbox-1", OutboxState::Pending, None)
            .expect_err("a published intent must not be reopened");
        assert_eq!(reopened.code(), ErrorCode::Conflict);
    }

    #[test]
    fn a_repeated_enqueue_does_not_create_a_second_row() {
        let mut connection = seeded();
        let revision_id = commit_analysis_and_intent(
            &mut connection,
            &revision("default"),
            &intent("outbox-1", "key-1"),
        )
        .expect("commit");
        assert!(!enqueue(&connection, revision_id, &intent("outbox-1", "key-1")).expect("repeat"));
        assert_eq!(all(&connection).expect("rows").len(), 1);

        mark(
            &connection,
            "outbox-1",
            OutboxState::Failed,
            Some("disk budget"),
        )
        .expect("fail");
        let pending_rows = pending(&connection).expect("pending");
        assert_eq!(pending_rows.len(), 1);
        assert_eq!(pending_rows[0].last_error.as_deref(), Some("disk budget"));

        let missing =
            mark(&connection, "outbox-9", OutboxState::Pending, None).expect_err("unknown intent");
        assert_eq!(missing.code(), ErrorCode::NotFound);
    }
}
