//! Idempotent pending work intents and scope coalescing (task B-033).
//!
//! The durable dedup key is `(solution instance, job kind, scope)` and the
//! database enforces it with the partial unique index `jobs_pending_dedup`
//! (`contracts/sqlite/schema-v1.sql`). A repeated intent for a scope that already
//! has a `PENDING` or `RETRY_WAIT` row must not create a second row, because a
//! second row would double-claim the same work.
//!
//! A job that is already `LEASED` or `RUNNING` is never mutated by a later
//! enqueue (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 4): its targets
//! were fixed when the worker read its input, so raising them mid-analysis would
//! let one result be credited to a generation it never read. The new intent is
//! recorded as a separate pending row instead, and the newer dirty generation is
//! reconciled by the next batch.

use std::collections::BTreeMap;

use graph_core::error::{AxiomError, ErrorCode};

use crate::{JobKind, JobRecord};

/// Field separator of the durable dedup key.
///
/// The unit separator `0x1F` cannot appear in a portable path or a solution id,
/// so two different triples cannot be confused by concatenation.
pub const DEDUP_SEPARATOR: char = '\u{1f}';

/// Build the durable dedup key `(solution_id, kind, scope_key)`.
#[must_use]
pub fn dedup_key(solution_id: &str, kind: JobKind, scope_key: &str) -> String {
    format!(
        "{solution_id}{sep}{kind}{sep}{scope_key}",
        sep = DEDUP_SEPARATOR,
        kind = kind.as_str()
    )
}

/// A request to make some scope dirty or to verify some scope fresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnqueueRequest {
    job_id: String,
    solution_id: String,
    kind: JobKind,
    scope_key: String,
    priority: i32,
    target_event_seq: i64,
    ready_at: i64,
}

impl EnqueueRequest {
    /// The job id used when this intent creates a new row.
    #[must_use]
    pub fn new(
        job_id: impl Into<String>,
        solution_id: impl Into<String>,
        kind: JobKind,
        scope_key: impl Into<String>,
        target_event_seq: i64,
        ready_at: i64,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            solution_id: solution_id.into(),
            kind,
            scope_key: scope_key.into(),
            priority: 0,
            target_event_seq,
            ready_at,
        }
    }

    /// Set the pre-aging priority class.
    #[must_use]
    pub const fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// The dedup key this request resolves to.
    #[must_use]
    pub fn dedup_key(&self) -> String {
        dedup_key(&self.solution_id, self.kind, &self.scope_key)
    }

    /// Solution instance the intent belongs to.
    #[must_use]
    pub fn solution_id(&self) -> &str {
        &self.solution_id
    }

    /// Kind of work requested.
    #[must_use]
    pub const fn kind(&self) -> JobKind {
        self.kind
    }

    /// Dedup scope inside the solution.
    #[must_use]
    pub fn scope_key(&self) -> &str {
        &self.scope_key
    }

    /// Event sequence the job must cover.
    #[must_use]
    pub const fn target_event_seq(&self) -> i64 {
        self.target_event_seq
    }

    fn validate(&self) -> Result<(), AxiomError> {
        if self.solution_id.is_empty() || self.scope_key.is_empty() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a work intent needs a solution id and a non-empty scope",
            )
            .with_detail("actual", self.scope_key.clone())
            .with_detail("solution_id", self.solution_id.clone()));
        }
        if self.target_event_seq < 0 {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a work intent target event sequence must not be negative",
            )
            .with_detail("actual", self.target_event_seq.to_string()));
        }
        Ok(())
    }
}

/// What happened to one enqueue request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnqueueDecision {
    /// No pending row existed; a new pending row was created.
    Created {
        /// Id of the created job.
        job_id: String,
    },
    /// An equivalent pending row already existed and absorbed the intent.
    Coalesced {
        /// Id of the existing pending job.
        job_id: String,
        /// Highest event sequence now covered by the pending job.
        target_event_seq: i64,
    },
    /// The scope is already leased or running, so the intent became a new
    /// pending row instead of mutating the running job's targets.
    Deferred {
        /// Id of the job that owns the running scope.
        running_job_id: String,
        /// Id of the newly created pending job for the next batch.
        job_id: String,
    },
}

impl EnqueueDecision {
    /// The id the caller can address afterwards.
    #[must_use]
    pub fn job_id(&self) -> &str {
        match self {
            Self::Created { job_id }
            | Self::Coalesced { job_id, .. }
            | Self::Deferred { job_id, .. } => job_id,
        }
    }

    /// Whether the decision created a new pending row.
    #[must_use]
    pub const fn created_a_row(&self) -> bool {
        matches!(self, Self::Created { .. } | Self::Deferred { .. })
    }
}

/// In-memory mirror of the durable pending rows plus the live running scopes.
#[derive(Debug, Default)]
pub struct PendingIndex {
    pending: BTreeMap<String, JobRecord>,
    running: BTreeMap<String, String>,
}

impl PendingIndex {
    /// An empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of pending rows currently indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether no pending row is indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// The pending row for a dedup key, if any.
    #[must_use]
    pub fn pending(&self, key: &str) -> Option<&JobRecord> {
        self.pending.get(key)
    }

    /// All pending rows, ordered by dedup key.
    pub fn pending_rows(&self) -> impl Iterator<Item = &JobRecord> {
        self.pending.values()
    }

    /// Record that a pending row has been leased or is running.
    ///
    /// Returns the row that left the pending set.
    pub fn mark_started(&mut self, key: &str, job_id: &str) -> Option<JobRecord> {
        let row = self.pending.remove(key)?;
        self.running.insert(key.to_string(), job_id.to_string());
        Some(row)
    }

    /// Record that the running scope finished, failed or was superseded.
    pub fn mark_finished(&mut self, key: &str) {
        self.running.remove(key);
    }

    /// Whether a live lease currently owns this dedup key.
    #[must_use]
    pub fn running(&self, key: &str) -> Option<&str> {
        self.running.get(key).map(String::as_str)
    }

    /// Apply one enqueue request.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] when the request has an empty solution or
    /// scope, or a negative target event sequence.
    pub fn enqueue(&mut self, request: &EnqueueRequest) -> Result<EnqueueDecision, AxiomError> {
        request.validate()?;
        let key = request.dedup_key();
        if let Some(existing) = self.pending.get_mut(&key) {
            coalesce(existing, request);
            return Ok(EnqueueDecision::Coalesced {
                job_id: existing.id.clone(),
                target_event_seq: existing.target_event_seq,
            });
        }
        let mut job = JobRecord::new(
            request.job_id.clone(),
            request.solution_id.clone(),
            request.kind,
            request.scope_key.clone(),
            request.priority,
            request.target_event_seq,
            request.ready_at,
        );
        job.priority = request.priority;
        let decision = match self.running.get(&key) {
            Some(running_job_id) => EnqueueDecision::Deferred {
                running_job_id: running_job_id.clone(),
                job_id: job.id.clone(),
            },
            None => EnqueueDecision::Created {
                job_id: job.id.clone(),
            },
        };
        self.pending.insert(key, job);
        Ok(decision)
    }
}

/// Fold a repeated intent into an existing pending row.
///
/// Only fields that cannot change what a worker reads are raised: the covered
/// event sequence, the pre-aging priority and the earliest ready time. The job
/// id, solution, kind and scope stay exactly as first recorded so the durable
/// row is untouched apart from being made no-less-urgent.
pub fn coalesce(existing: &mut JobRecord, request: &EnqueueRequest) {
    existing.target_event_seq = existing.target_event_seq.max(request.target_event_seq);
    existing.priority = existing.priority.max(request.priority);
    existing.ready_at = existing.ready_at.min(request.ready_at);
}

#[cfg(test)]
mod tests {
    use super::{dedup_key, EnqueueDecision, EnqueueRequest, PendingIndex};
    use crate::JobKind;

    fn request(id: &str, seq: i64, at: i64) -> EnqueueRequest {
        EnqueueRequest::new(id, "sol-1", JobKind::ParseBatch, "project:a", seq, at)
    }

    #[test]
    fn equivalent_pending_scopes_coalesce_into_one_row() {
        let mut index = PendingIndex::new();
        let first = index.enqueue(&request("job-1", 5, 100)).expect("created");
        assert_eq!(
            first,
            EnqueueDecision::Created {
                job_id: "job-1".to_string()
            }
        );
        assert_eq!(index.len(), 1);

        let second = index.enqueue(&request("job-2", 9, 80)).expect("coalesced");
        assert_eq!(
            second,
            EnqueueDecision::Coalesced {
                job_id: "job-1".to_string(),
                target_event_seq: 9
            }
        );
        assert_eq!(index.len(), 1, "a coalesced intent must not add a row");
        let row = index.pending(&request("x", 0, 0).dedup_key()).expect("row");
        assert_eq!(row.id, "job-1");
        assert_eq!(row.target_event_seq, 9);
        assert_eq!(row.ready_at, 80, "the earlier ready time wins");
        assert!(!second.created_a_row());
    }

    #[test]
    fn coalescing_never_lowers_the_covered_event_sequence() {
        let mut index = PendingIndex::new();
        index.enqueue(&request("job-1", 42, 100)).expect("created");
        let older = index.enqueue(&request("job-2", 7, 100)).expect("coalesced");
        assert_eq!(
            older,
            EnqueueDecision::Coalesced {
                job_id: "job-1".to_string(),
                target_event_seq: 42
            }
        );
    }

    #[test]
    fn a_running_scope_is_not_mutated_by_a_later_enqueue() {
        let mut index = PendingIndex::new();
        index.enqueue(&request("job-1", 5, 100)).expect("created");
        let key = request("x", 0, 0).dedup_key();
        let started = index.mark_started(&key, "job-1").expect("running");
        assert_eq!(started.target_event_seq, 5);
        assert_eq!(index.running(&key), Some("job-1"));
        assert!(index.is_empty());

        let decision = index.enqueue(&request("job-2", 6, 110)).expect("deferred");
        assert_eq!(
            decision,
            EnqueueDecision::Deferred {
                running_job_id: "job-1".to_string(),
                job_id: "job-2".to_string()
            }
        );
        assert!(decision.created_a_row());
        assert_eq!(
            index.len(),
            1,
            "the intent is parked, not merged into running work"
        );
        assert_eq!(index.pending(&key).expect("parked").target_event_seq, 6);
        assert_eq!(
            index.running(&key),
            Some("job-1"),
            "the running owner is unchanged"
        );

        let again = index.enqueue(&request("job-3", 8, 120)).expect("coalesced");
        assert_eq!(
            again,
            EnqueueDecision::Coalesced {
                job_id: "job-2".to_string(),
                target_event_seq: 8
            }
        );
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn finishing_a_running_scope_frees_the_key_for_a_fresh_create() {
        let mut index = PendingIndex::new();
        index.enqueue(&request("job-1", 5, 100)).expect("created");
        let key = request("x", 0, 0).dedup_key();
        index.mark_started(&key, "job-1");
        index.mark_finished(&key);
        let decision = index.enqueue(&request("job-2", 6, 200)).expect("created");
        assert_eq!(
            decision,
            EnqueueDecision::Created {
                job_id: "job-2".to_string()
            }
        );
    }

    #[test]
    fn dedup_keys_do_not_collide_across_fields() {
        let a = dedup_key("sol-1", JobKind::ParseBatch, "ab");
        let b = dedup_key("sol-1", JobKind::ParseBatch, "a\u{1f}b");
        assert_ne!(a, b);
        assert_ne!(
            dedup_key("s", JobKind::ParseBatch, "x"),
            dedup_key("s", JobKind::InventoryScan, "x")
        );
    }

    #[test]
    fn empty_scope_and_negative_sequence_are_refused() {
        let mut index = PendingIndex::new();
        let empty = EnqueueRequest::new("j", "sol-1", JobKind::ParseBatch, "", 1, 0);
        assert!(index.enqueue(&empty).is_err());
        let negative = EnqueueRequest::new("j", "sol-1", JobKind::ParseBatch, "x", -1, 0);
        assert!(index.enqueue(&negative).is_err());
        assert!(index.is_empty());
    }
}
