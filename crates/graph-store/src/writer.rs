//! Serializing mutations through the single writer actor (task B-011).
//!
//! docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md section 1 allows exactly one
//! writer connection per instance: SQLite WAL permits reader/writer concurrency
//! but still admits a single writer, so worker threads hand their results to a
//! writer actor instead of opening competing connections. Section 4 forbids
//! holding a database transaction while parsing, so the actor applies each
//! queued mutation inside its own short `BEGIN IMMEDIATE` transaction and never
//! spans a parse.
//!
//! The queue is bounded. Overload is reported to the caller as
//! [`SubmitOutcome::Backpressure`] rather than growing without limit or
//! blocking a worker indefinitely.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

use graph_core::error::{AxiomError, ErrorCode};
use rusqlite::Connection;

use crate::storage_error;

/// Default bounded queue depth for the writer actor.
pub const DEFAULT_WRITER_CAPACITY: usize = 128;

/// A unit of work applied by the actor inside one short transaction.
///
/// The closure receives the writer connection inside an already-open
/// `BEGIN IMMEDIATE` transaction; returning `Err` rolls that mutation back
/// without affecting the queue or the mutations after it.
pub type Mutation = Box<dyn FnOnce(&Connection) -> Result<(), AxiomError> + Send>;

/// Result of offering a mutation to the actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// The mutation was queued for the next drain.
    Accepted,
    /// The bounded queue is full; the caller must apply backpressure and retry.
    Backpressure {
        /// Queue depth observed when the mutation was refused.
        depth: usize,
        /// Configured queue capacity.
        capacity: usize,
    },
}

impl SubmitOutcome {
    /// Whether the mutation was queued.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// Outcome of draining the queue.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DrainReport {
    /// Mutations committed.
    pub applied: usize,
    /// Mutations that returned an error and were rolled back.
    pub failed: usize,
    /// Queue depth after the drain; a value above zero means new work arrived
    /// while the drain was running.
    pub depth_after: usize,
    /// Message of the first failed mutation, when any failed.
    pub first_error: Option<String>,
}

struct WriterState {
    connection: Connection,
    queue: VecDeque<Mutation>,
    capacity: usize,
    applied_total: u64,
    failed_total: u64,
    rejected_total: u64,
}

/// Single-writer actor owning the mutable connection of one instance.
pub struct WriterActor {
    state: Mutex<WriterState>,
}

impl WriterActor {
    /// Take ownership of `connection` with a bounded mutation queue.
    ///
    /// # Errors
    /// Returns [`ErrorCode::ValidationError`] when `capacity` is zero: an
    /// unbounded and a never-accepting queue are both defects, so zero is
    /// refused instead of silently meaning either one.
    pub fn new(connection: Connection, capacity: usize) -> Result<Self, AxiomError> {
        if capacity == 0 {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "writer queue capacity must be at least one",
            ));
        }
        Ok(Self {
            state: Mutex::new(WriterState {
                connection,
                queue: VecDeque::new(),
                capacity,
                applied_total: 0,
                failed_total: 0,
                rejected_total: 0,
            }),
        })
    }

    /// Configured queue capacity.
    ///
    /// # Errors
    /// Returns [`ErrorCode::Internal`] when the actor mutex was poisoned.
    pub fn capacity(&self) -> Result<usize, AxiomError> {
        Ok(self.lock()?.capacity)
    }

    /// Current queue depth.
    ///
    /// # Errors
    /// Returns [`ErrorCode::Internal`] when the actor mutex was poisoned.
    pub fn depth(&self) -> Result<usize, AxiomError> {
        Ok(self.lock()?.queue.len())
    }

    /// Total mutations committed by this actor.
    ///
    /// # Errors
    /// Returns [`ErrorCode::Internal`] when the actor mutex was poisoned.
    pub fn applied_total(&self) -> Result<u64, AxiomError> {
        Ok(self.lock()?.applied_total)
    }

    /// Total mutations rolled back by this actor.
    ///
    /// # Errors
    /// Returns [`ErrorCode::Internal`] when the actor mutex was poisoned.
    pub fn failed_total(&self) -> Result<u64, AxiomError> {
        Ok(self.lock()?.failed_total)
    }

    /// Total mutations refused because the queue was full.
    ///
    /// # Errors
    /// Returns [`ErrorCode::Internal`] when the actor mutex was poisoned.
    pub fn rejected_total(&self) -> Result<u64, AxiomError> {
        Ok(self.lock()?.rejected_total)
    }

    /// Offer a mutation to the actor.
    ///
    /// # Errors
    /// Returns [`ErrorCode::Internal`] when the actor mutex was poisoned.
    pub fn submit(&self, mutation: Mutation) -> Result<SubmitOutcome, AxiomError> {
        let mut state = self.lock()?;
        if state.queue.len() >= state.capacity {
            state.rejected_total += 1;
            return Ok(SubmitOutcome::Backpressure {
                depth: state.queue.len(),
                capacity: state.capacity,
            });
        }
        state.queue.push_back(mutation);
        Ok(SubmitOutcome::Accepted)
    }

    /// Apply every queued mutation in submission order.
    ///
    /// Each mutation runs in its own `BEGIN IMMEDIATE` transaction, so a failed
    /// mutation is rolled back on its own and the remaining queue still runs.
    ///
    /// # Errors
    /// Returns [`ErrorCode::Internal`] when the actor mutex was poisoned. A
    /// mutation's own failure is reported in [`DrainReport`], not returned.
    pub fn drain(&self) -> Result<DrainReport, AxiomError> {
        let mut state = self.lock()?;
        let mut report = DrainReport::default();
        while let Some(mutation) = state.queue.pop_front() {
            match apply_one(&state.connection, mutation) {
                Ok(()) => {
                    report.applied += 1;
                    state.applied_total += 1;
                }
                Err(error) => {
                    report.failed += 1;
                    state.failed_total += 1;
                    if report.first_error.is_none() {
                        report.first_error = Some(error.to_string());
                    }
                }
            }
        }
        report.depth_after = state.queue.len();
        Ok(report)
    }

    /// Run a read-only closure against the actor connection.
    ///
    /// The closure runs under the same lock as a drain, so it observes a
    /// consistent point between two mutations. Long-lived production readers
    /// keep their own connection; this is actor-owned inspection.
    ///
    /// # Errors
    /// Returns [`ErrorCode::Internal`] when the actor mutex was poisoned, or
    /// whatever the closure returns.
    pub fn with_connection<T>(
        &self,
        query: impl FnOnce(&Connection) -> Result<T, AxiomError>,
    ) -> Result<T, AxiomError> {
        let state = self.lock()?;
        query(&state.connection)
    }

    fn lock(&self) -> Result<MutexGuard<'_, WriterState>, AxiomError> {
        self.state.lock().map_err(|_| {
            AxiomError::new(
                ErrorCode::Internal,
                "writer actor mutex was poisoned by a panicking mutation",
            )
        })
    }
}

impl std::fmt::Debug for WriterActor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.state.lock() {
            Ok(state) => formatter
                .debug_struct("WriterActor")
                .field("capacity", &state.capacity)
                .field("depth", &state.queue.len())
                .field("applied_total", &state.applied_total)
                .field("failed_total", &state.failed_total)
                .field("rejected_total", &state.rejected_total)
                .finish_non_exhaustive(),
            Err(_) => formatter.write_str("WriterActor(<poisoned>)"),
        }
    }
}

/// Apply one mutation in its own short transaction.
fn apply_one(connection: &Connection, mutation: Mutation) -> Result<(), AxiomError> {
    connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|error| storage_error("writer begin", &error))?;
    match mutation(connection) {
        Ok(()) => connection
            .execute_batch("COMMIT")
            .map_err(|error| storage_error("writer commit", &error)),
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;
    use crate::test_support::memory_store;

    #[test]
    fn writer_actor_serialises_results_and_reports_backpressure() {
        let actor = WriterActor::new(memory_store(), 2).expect("actor");
        assert_eq!(actor.capacity().expect("capacity"), 2);

        let applied = Arc::new(AtomicUsize::new(0));
        for expected in 0..2 {
            let counter = Arc::clone(&applied);
            let outcome = actor
                .submit(Box::new(move |connection| {
                    assert_eq!(counter.fetch_add(1, Ordering::SeqCst), expected);
                    connection
                        .execute_batch("CREATE TABLE IF NOT EXISTS probe(value TEXT)")
                        .map_err(|error| storage_error("probe", &error))
                }))
                .expect("submit");
            assert!(outcome.is_accepted());
        }

        match actor.submit(Box::new(|_| Ok(()))).expect("submit") {
            SubmitOutcome::Backpressure { depth, capacity } => {
                assert_eq!(depth, 2);
                assert_eq!(capacity, 2);
            }
            other => panic!("expected backpressure, got {other:?}"),
        }

        let report = actor.drain().expect("drain");
        assert_eq!((report.applied, report.failed), (2, 0));
        assert_eq!(actor.depth().expect("depth"), 0);
        assert_eq!(actor.applied_total().expect("applied total"), 2);
        assert_eq!(actor.rejected_total().expect("rejected total"), 1);
    }

    #[test]
    fn failed_mutation_rolls_back_and_the_queue_continues() {
        let actor = WriterActor::new(memory_store(), 4).expect("actor");
        actor
            .submit(Box::new(|connection| {
                connection
                    .execute_batch("CREATE TABLE probe(value TEXT)")
                    .map_err(|error| storage_error("probe", &error))
            }))
            .expect("submit");
        actor
            .submit(Box::new(|connection| {
                connection
                    .execute("INSERT INTO probe(value) VALUES('rolled-back')", [])
                    .map_err(|error| storage_error("probe", &error))?;
                Err(AxiomError::new(ErrorCode::Conflict, "injected failure"))
            }))
            .expect("submit");
        actor
            .submit(Box::new(|connection| {
                connection
                    .execute("INSERT INTO probe(value) VALUES('kept')", [])
                    .map_err(|error| storage_error("probe", &error))?;
                Ok(())
            }))
            .expect("submit");

        let report = actor.drain().expect("drain");
        assert_eq!((report.applied, report.failed), (2, 1));
        assert!(report.first_error.is_some());

        let values = actor
            .with_connection(|connection| {
                let mut statement = connection
                    .prepare("SELECT value FROM probe ORDER BY rowid")
                    .map_err(|error| storage_error("probe", &error))?;
                let rows = statement
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(|error| storage_error("probe", &error))?;
                let mut values = Vec::new();
                for row in rows {
                    values.push(row.map_err(|error| storage_error("probe", &error))?);
                }
                Ok(values)
            })
            .expect("query");
        assert_eq!(values, vec!["kept".to_string()]);
    }

    #[test]
    fn zero_capacity_is_refused() {
        let error = WriterActor::new(memory_store(), 0).expect_err("zero capacity");
        assert_eq!(error.code(), ErrorCode::ValidationError);
    }
}
