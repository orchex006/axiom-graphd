//! Durable work queue for the Axiom graph engine (`axiom-graphd`).
//!
//! This crate owns the durable-queue work package (B-033 - B-044). It implements
//! the state and fencing semantics frozen by
//! `axiom-specs/contracts/queue-state-machine.md` and the scheduling defaults of
//! `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 6.
//!
//! The queue is durable state, not an in-memory channel: a daemon restart must be
//! able to reconstruct the work that should happen
//! (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 1). The modules here are
//! the pure decision layer: they compute *what the durable row must become* for a
//! given event. No module opens a database, spawns a worker or runs a repository
//! script; persistence stays behind `graph-store` and `graph-store::writer`.
//!
//! * B-033 ([`enqueue`]) - idempotent pending work intents and scope coalescing.
//! * B-034 ([`claim`]) - atomic claim, one owner, strictly increasing fence.
//! * B-035 ([`heartbeat`]) - lease renewal by the live fence owner only.
//! * B-036 ([`ack`]) - reject stale results; a newer generation stays dirty.
//! * B-037 ([`schedule`]) - priority with bounded aging.
//! * B-038 ([`budget`]) - hard worker, file-count and input-byte caps.
//! * B-039 ([`retry`]) - classified transient retry with bounded backoff.
//! * B-040 ([`cancel`]) - queued and running cancellation that keeps dirty state.
//! * B-041 ([`recover`]) - reclaim leases left by a dead process.
//! * B-042 ([`pressure`]) - queue high-water handling without silent loss.
//! * B-044 ([`barrier`]) - bounded freshness barrier that never fakes freshness.
//!
//! Timestamps are integer milliseconds on one monotonic timeline supplied by the
//! caller. Nothing here reads the system clock, so every decision is reproducible
//! in a test.

pub mod ack;
pub mod barrier;
pub mod budget;
pub mod cancel;
pub mod claim;
pub mod enqueue;
pub mod heartbeat;
pub mod pressure;
pub mod recover;
pub mod retry;
pub mod schedule;

use graph_core::error::{AxiomError, ErrorCode};
use serde::{Deserialize, Serialize};

/// Reason recorded when an event is not one of the allowed transitions.
pub const REASON_TRANSITION_NOT_ALLOWED: &str = "transition_not_allowed";
/// Reason recorded when the job is already in a terminal state.
pub const REASON_TERMINAL_STATE: &str = "terminal_state";
/// Reason recorded when an event carries a fence lower than the live lease.
pub const REASON_STALE_FENCE: &str = "stale_fence";
/// Reason recorded when an event carries a fence higher than the live lease.
pub const REASON_FENCE_OUT_OF_ORDER: &str = "fence_out_of_order";
/// Reason recorded when the event owner is not the recorded lease owner.
pub const REASON_LEASE_OWNER_MISMATCH: &str = "lease_owner_mismatch";
/// Reason recorded when the lease deadline has already passed.
pub const REASON_LEASE_EXPIRED: &str = "lease_expired";
/// Reason recorded when a fence value cannot be represented.
pub const REASON_FENCE_OVERFLOW: &str = "fence_overflow";
/// Reason recorded when a job is not eligible for the requested operation.
pub const REASON_NOT_ELIGIBLE: &str = "not_eligible";
/// Reason recorded when a lease has not expired yet and cannot be reclaimed.
pub const REASON_LEASE_NOT_EXPIRED: &str = "lease_not_expired";

/// The nine contract states of a durable job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobState {
    /// Queued and eligible for a claim; durable across a restart.
    Pending,
    /// A worker holds the lease and has not started work.
    Leased,
    /// The lease owner is executing the job.
    Running,
    /// A classified-transient failure put the job back with a delay.
    RetryWait,
    /// Cooperative cancellation requested but not yet acknowledged.
    CancelRequested,
    /// Terminal: the result was accepted by the live fence owner.
    Succeeded,
    /// Terminal: a non-retryable failure ended the job.
    Failed,
    /// Terminal: cancellation was acknowledged.
    Cancelled,
    /// Terminal: newer work made the job obsolete.
    Superseded,
}

impl JobState {
    /// Stable wire spelling, matching `job.schema.json` and the `jobs.state` CHECK.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Leased => "LEASED",
            Self::Running => "RUNNING",
            Self::RetryWait => "RETRY_WAIT",
            Self::CancelRequested => "CANCEL_REQUESTED",
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::Superseded => "SUPERSEDED",
        }
    }

    /// Parse the stable spelling; `None` for anything else.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::all().iter().copied().find(|s| s.as_str() == value)
    }

    /// Whether the state accepts no further event.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Superseded
        )
    }

    /// Whether the state still holds a live lease that can be reclaimed.
    #[must_use]
    pub const fn holds_lease(self) -> bool {
        matches!(self, Self::Leased | Self::Running)
    }

    /// Every state, in declaration order.
    #[must_use]
    pub const fn all() -> &'static [JobState] {
        &[
            Self::Pending,
            Self::Leased,
            Self::Running,
            Self::RetryWait,
            Self::CancelRequested,
            Self::Succeeded,
            Self::Failed,
            Self::Cancelled,
            Self::Superseded,
        ]
    }
}

impl core::fmt::Display for JobState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The closed set of job kinds (`docs/13-SQLite section 5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum JobKind {
    /// Walk a project root and reconcile the file inventory.
    InventoryScan,
    /// Analyze a bounded batch of changed files.
    ParseBatch,
    /// Invalidate and rebuild the affected closure of a parsed result.
    ResolveAffected,
    /// Publish one project generation.
    PublishProject,
    /// Publish the pinned multi-project catalog.
    PublishCatalog,
    /// Export a worktree/staged source checkpoint.
    CheckpointExport,
    /// Verify a merged-source checkpoint.
    VerifyCheckpoint,
    /// Garbage-collect unreferenced generations.
    SnapshotGc,
    /// Quarantine corrupt state and schedule a rebuild.
    Repair,
}

impl JobKind {
    /// Stable wire spelling, matching `job.schema.json`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InventoryScan => "InventoryScan",
            Self::ParseBatch => "ParseBatch",
            Self::ResolveAffected => "ResolveAffected",
            Self::PublishProject => "PublishProject",
            Self::PublishCatalog => "PublishCatalog",
            Self::CheckpointExport => "CheckpointExport",
            Self::VerifyCheckpoint => "VerifyCheckpoint",
            Self::SnapshotGc => "SnapshotGC",
            Self::Repair => "Repair",
        }
    }

    /// Parse the stable spelling; `None` for anything else.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::all().iter().copied().find(|k| k.as_str() == value)
    }

    /// Every kind, in declaration order.
    #[must_use]
    pub const fn all() -> &'static [JobKind] {
        &[
            Self::InventoryScan,
            Self::ParseBatch,
            Self::ResolveAffected,
            Self::PublishProject,
            Self::PublishCatalog,
            Self::CheckpointExport,
            Self::VerifyCheckpoint,
            Self::SnapshotGc,
            Self::Repair,
        ]
    }
}

/// The frozen transition table of `contracts/queue-state-machine.md` section 3.
pub const ALLOWED_TRANSITIONS: &[(JobState, JobState)] = &[
    (JobState::Pending, JobState::Leased),
    (JobState::Pending, JobState::CancelRequested),
    (JobState::Pending, JobState::Superseded),
    (JobState::Leased, JobState::Running),
    (JobState::Leased, JobState::Pending),
    (JobState::Leased, JobState::CancelRequested),
    (JobState::Running, JobState::Succeeded),
    (JobState::Running, JobState::Failed),
    (JobState::Running, JobState::RetryWait),
    (JobState::Running, JobState::Pending),
    (JobState::Running, JobState::CancelRequested),
    (JobState::Running, JobState::Superseded),
    (JobState::RetryWait, JobState::Pending),
    (JobState::RetryWait, JobState::CancelRequested),
    (JobState::RetryWait, JobState::Superseded),
    (JobState::CancelRequested, JobState::Cancelled),
];

/// Whether `from -> to` is one of the exactly legal transitions.
#[must_use]
pub fn transition_allowed(from: JobState, to: JobState) -> bool {
    ALLOWED_TRANSITIONS
        .iter()
        .any(|(a, b)| *a == from && *b == to)
}

/// Refuse a transition that the contract does not allow.
///
/// # Errors
/// [`ErrorCode::Conflict`] with `transition_not_allowed`, or
/// [`ErrorCode::Conflict`] with `terminal_state` when `from` is terminal.
pub fn ensure_transition(from: JobState, to: JobState) -> Result<(), AxiomError> {
    if from.is_terminal() {
        return Err(
            AxiomError::new(ErrorCode::Conflict, "job is in a terminal state")
                .with_detail("rule", REASON_TERMINAL_STATE)
                .with_detail("actual", from.as_str()),
        );
    }
    if !transition_allowed(from, to) {
        return Err(
            AxiomError::new(ErrorCode::Conflict, "transition is not allowed")
                .with_detail("rule", REASON_TRANSITION_NOT_ALLOWED)
                .with_detail("actual", from.as_str())
                .with_detail("expected", to.as_str()),
        );
    }
    Ok(())
}

/// A durable job row, mirroring the `jobs` table of `sqlite-schema-v1.sql`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    /// Stable job id.
    pub id: String,
    /// Owning solution instance.
    pub solution_id: String,
    /// Work kind.
    pub kind: JobKind,
    /// Dedup scope; see [`enqueue::dedup_key`].
    pub scope_key: String,
    /// Current contract state.
    pub state: JobState,
    /// Scheduling priority class before aging.
    pub priority: i32,
    /// Event sequence the job must cover before it may publish.
    pub target_event_seq: i64,
    /// Dispatch attempts, independent of the fence.
    pub attempt: u32,
    /// Ownership changes; strictly increases on every accepted claim.
    pub fence: i64,
    /// Live lease owner, or `None`.
    pub lease_owner: Option<String>,
    /// Live lease deadline in milliseconds, or `None`.
    pub lease_until: Option<i64>,
    /// Earliest time the job may be claimed.
    pub ready_at: i64,
    /// Creation time.
    pub created_at: i64,
    /// Last classified failure code, or `None`.
    pub last_error_code: Option<String>,
}

impl JobRecord {
    /// A new `PENDING` job with no lease and fence zero.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        solution_id: impl Into<String>,
        kind: JobKind,
        scope_key: impl Into<String>,
        priority: i32,
        target_event_seq: i64,
        now: i64,
    ) -> Self {
        Self {
            id: id.into(),
            solution_id: solution_id.into(),
            kind,
            scope_key: scope_key.into(),
            state: JobState::Pending,
            priority,
            target_event_seq,
            attempt: 0,
            fence: 0,
            lease_owner: None,
            lease_until: None,
            ready_at: now,
            created_at: now,
            last_error_code: None,
        }
    }

    /// The live lease identity tuple `(job_id, fence, owner)` when a lease exists.
    #[must_use]
    pub fn lease_identity(&self) -> Option<(String, i64, String)> {
        match (&self.lease_owner, self.state) {
            (Some(owner), state) if state.holds_lease() => {
                Some((self.id.clone(), self.fence, owner.clone()))
            }
            _ => None,
        }
    }

    /// Whether the job is eligible to be claimed at `now`.
    #[must_use]
    pub fn is_claimable_at(&self, now: i64) -> bool {
        matches!(self.state, JobState::Pending | JobState::RetryWait) && self.ready_at <= now
    }

    /// Clear the live lease without touching the fence (F8).
    pub(crate) fn release_lease(&mut self) {
        self.lease_owner = None;
        self.lease_until = None;
    }
}

/// Validate that a fence value is a non-negative integer (F1).
///
/// # Errors
/// [`ErrorCode::ValidationError`] with `invalid_fence` detail.
pub fn ensure_valid_fence(fence: i64) -> Result<(), AxiomError> {
    if fence < 0 {
        return Err(
            AxiomError::new(ErrorCode::ValidationError, "a fence must not be negative")
                .with_detail("rule", REASON_INVALID_FENCE)
                .with_detail("actual", fence.to_string()),
        );
    }
    Ok(())
}

/// Reason recorded when a fence value is negative.
pub const REASON_INVALID_FENCE: &str = "invalid_fence";

/// Compute the fence of the next claim: strictly greater than the current one.
///
/// # Errors
/// [`ErrorCode::Conflict`] with `fence_overflow` when the fence cannot increase.
pub fn next_fence(current: i64) -> Result<i64, AxiomError> {
    ensure_valid_fence(current)?;
    current.checked_add(1).ok_or_else(|| {
        AxiomError::new(ErrorCode::Conflict, "the fence cannot increase further")
            .with_detail("rule", REASON_FENCE_OVERFLOW)
    })
}

/// Clamp a requested duration into `[0, max]`.
#[must_use]
pub const fn clamp_duration(requested: i64, max: i64) -> i64 {
    if requested < 0 {
        0
    } else if requested > max {
        max
    } else {
        requested
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_transition, next_fence, transition_allowed, JobKind, JobRecord, JobState,
        ALLOWED_TRANSITIONS, REASON_TERMINAL_STATE, REASON_TRANSITION_NOT_ALLOWED,
    };
    use graph_core::error::ErrorCode;

    #[test]
    fn state_spellings_round_trip_and_match_the_schema() {
        for state in JobState::all() {
            assert_eq!(JobState::parse(state.as_str()), Some(*state));
        }
        assert_eq!(JobState::all().len(), 9);
        assert_eq!(JobKind::all().len(), 9);
        for kind in JobKind::all() {
            assert_eq!(JobKind::parse(kind.as_str()), Some(*kind));
        }
        assert_eq!(JobState::parse("pending"), None);
    }

    #[test]
    fn terminal_states_and_lease_states_are_disjoint() {
        for state in JobState::all() {
            assert!(!(state.is_terminal() && state.holds_lease()));
        }
        assert!(JobState::Succeeded.is_terminal());
        assert!(JobState::Superseded.is_terminal());
        assert!(JobState::Cancelled.is_terminal());
        assert!(JobState::Failed.is_terminal());
    }

    #[test]
    fn exactly_the_contract_transitions_are_allowed() {
        for from in JobState::all() {
            for to in JobState::all() {
                let expected = ALLOWED_TRANSITIONS
                    .iter()
                    .any(|(a, b)| a == from && b == to);
                assert_eq!(transition_allowed(*from, *to), expected);
            }
        }
        assert!(transition_allowed(JobState::Pending, JobState::Leased));
        assert!(!transition_allowed(JobState::Pending, JobState::Running));
        assert!(!transition_allowed(
            JobState::CancelRequested,
            JobState::Running
        ));
    }

    #[test]
    fn terminal_states_reject_every_event() {
        for terminal in [
            JobState::Succeeded,
            JobState::Failed,
            JobState::Cancelled,
            JobState::Superseded,
        ] {
            for to in JobState::all() {
                let error = ensure_transition(terminal, *to).expect_err("terminal must reject");
                assert_eq!(error.code(), ErrorCode::Conflict);
                assert_eq!(terminal_reason(&error), Some(REASON_TERMINAL_STATE));
            }
        }
    }

    #[test]
    fn illegal_transitions_report_the_contract_reason() {
        let error =
            ensure_transition(JobState::Pending, JobState::Succeeded).expect_err("not allowed");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(terminal_reason(&error), Some(REASON_TRANSITION_NOT_ALLOWED));
    }

    fn terminal_reason(error: &graph_core::error::AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    #[test]
    fn every_state_is_reachable_from_pending_by_the_allowed_table() {
        // The contract table must be able to reach all nine states from PENDING;
        // otherwise a state would be dead code in the durable model.
        let mut reached = vec![JobState::Pending];
        loop {
            let mut grew = false;
            for (from, to) in ALLOWED_TRANSITIONS {
                if reached.contains(from) && !reached.contains(to) {
                    reached.push(*to);
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        assert_eq!(reached.len(), JobState::all().len());
    }

    #[test]
    fn fences_increase_strictly_and_never_overflow_silently() {
        assert_eq!(next_fence(0).expect("fence"), 1);
        assert_eq!(next_fence(41).expect("fence"), 42);
        let error = next_fence(i64::MAX).expect_err("overflow");
        assert_eq!(error.code(), ErrorCode::Conflict);
    }

    #[test]
    fn a_new_job_starts_pending_with_no_lease() {
        let job = JobRecord::new("job-1", "sol-1", JobKind::ParseBatch, "p:1", 0, 7, 100);
        assert_eq!(job.state, JobState::Pending);
        assert_eq!(job.fence, 0);
        assert!(job.lease_identity().is_none());
        assert!(job.is_claimable_at(100));
        assert!(!job.is_claimable_at(99));
    }
}
