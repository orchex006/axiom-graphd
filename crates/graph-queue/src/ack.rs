//! Reject stale worker result commits (task B-036).
//!
//! A result may only be committed by the live fence owner of a `RUNNING` job
//! (`contracts/queue-state-machine.md` F2, F4 and section 5). Two things must
//! hold before a result is accepted:
//!
//! 1. the fence and owner must still be the live lease, so a worker whose job was
//!    reclaimed cannot commit; and
//! 2. the analysis generation must match the generation the worker actually read.
//!
//! The second rule is the one that prevents a lost update. A file can be edited
//! while its previous version is being analysed, so the result is committed
//! against the analysed generation and the file stays dirty for the newer one
//! (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 3). A rejection is a
//! no-op (F6): it never advances the job and never clears the dirty state.

use graph_core::error::{AxiomError, ErrorCode};

use crate::claim::ensure_live_owner;
use crate::{JobRecord, JobState};

/// The result a worker asks to commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultCommit {
    job_id: String,
    fence: i64,
    owner: String,
    analyzed_generation: i64,
    desired_generation: i64,
}

impl ResultCommit {
    /// Describe one result commit request.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] when either generation is negative.
    pub fn new(
        job_id: impl Into<String>,
        fence: i64,
        owner: impl Into<String>,
        analyzed_generation: i64,
        desired_generation: i64,
    ) -> Result<Self, AxiomError> {
        if analyzed_generation < 0 || desired_generation < 0 {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a result generation must not be negative",
            )
            .with_detail("job_id", job_id.into())
            .with_detail(
                "actual",
                format!("{analyzed_generation}/{desired_generation}"),
            ));
        }
        Ok(Self {
            job_id: job_id.into(),
            fence,
            owner: owner.into(),
            analyzed_generation,
            desired_generation,
        })
    }

    /// Job the result belongs to.
    #[must_use]
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    /// Generation of the input the worker actually read.
    #[must_use]
    pub const fn analyzed_generation(&self) -> i64 {
        self.analyzed_generation
    }

    /// Generation the store currently wants.
    #[must_use]
    pub const fn desired_generation(&self) -> i64 {
        self.desired_generation
    }
}

/// The decision the store must apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitDecision {
    /// The result was accepted for the analysed generation.
    Accepted {
        /// Generation the result is now indexed at.
        indexed_generation: i64,
        /// Whether a newer generation arrived while the worker was analysing, so
        /// the same scope must be reconciled again.
        remains_dirty: bool,
    },
    /// The result was refused and nothing was written.
    Rejected {
        /// Contract reason code.
        reason: &'static str,
    },
}

impl CommitDecision {
    /// Whether the result was written.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    /// Whether the scope must be reconciled again.
    #[must_use]
    pub const fn keeps_dirty(&self) -> bool {
        matches!(
            self,
            Self::Accepted {
                remains_dirty: true,
                ..
            }
        )
    }
}

/// Whether a result leaves the file dirty because a newer generation exists.
#[must_use]
pub const fn remains_dirty(analyzed_generation: i64, desired_generation: i64) -> bool {
    desired_generation > analyzed_generation
}

/// Apply a result commit to `job`.
///
/// # Errors
/// [`ErrorCode::ValidationError`] when the commit names a different job.
pub fn commit_result(
    job: &mut JobRecord,
    commit: &ResultCommit,
    now: i64,
) -> Result<CommitDecision, AxiomError> {
    if job.id != commit.job_id {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "the result commit names a different job",
        )
        .with_detail("job_id", job.id.clone())
        .with_detail("actual", commit.job_id.clone()));
    }
    if job.state.is_terminal() {
        return Ok(CommitDecision::Rejected {
            reason: crate::REASON_TERMINAL_STATE,
        });
    }
    if job.state != JobState::Running {
        return Ok(CommitDecision::Rejected {
            reason: crate::REASON_TRANSITION_NOT_ALLOWED,
        });
    }
    let lease = crate::claim::Lease::restore(
        job.id.clone(),
        commit.fence,
        commit.owner.clone(),
        job.lease_until.unwrap_or(now),
    );
    if ensure_live_owner(job, &lease, now).is_err() {
        return Ok(CommitDecision::Rejected {
            reason: rejection_reason(job, commit, now),
        });
    }
    let remains = remains_dirty(commit.analyzed_generation, commit.desired_generation);
    job.state = JobState::Succeeded;
    job.release_lease();
    job.last_error_code = None;
    Ok(CommitDecision::Accepted {
        indexed_generation: commit.analyzed_generation,
        remains_dirty: remains,
    })
}

/// The contract reason a commit must be refused for.
#[must_use]
pub fn rejection_reason(job: &JobRecord, commit: &ResultCommit, now: i64) -> &'static str {
    if commit.fence < job.fence {
        return crate::REASON_STALE_FENCE;
    }
    if commit.fence > job.fence {
        return crate::REASON_FENCE_OUT_OF_ORDER;
    }
    if job.lease_owner.as_deref() != Some(commit.owner.as_str()) {
        return crate::REASON_LEASE_OWNER_MISMATCH;
    }
    if job.lease_until.is_none_or(|until| until <= now) {
        return crate::REASON_LEASE_EXPIRED;
    }
    crate::REASON_NOT_ELIGIBLE
}

#[cfg(test)]
mod tests {
    use super::{commit_result, remains_dirty, CommitDecision, ResultCommit};
    use crate::claim::{claim, start_running, ClaimOutcome, Lease};
    use crate::{JobKind, JobRecord, JobState, REASON_STALE_FENCE};

    fn running() -> (JobRecord, Lease) {
        let mut job = JobRecord::new("job-1", "sol-1", JobKind::ParseBatch, "p:a", 0, 3, 0);
        let lease = match claim(&mut job, "worker-a", 1_000, 30_000).expect("claim") {
            ClaimOutcome::Claimed(lease) => lease,
            ClaimOutcome::NotEligible { .. } => panic!("claim"),
        };
        start_running(&mut job, &lease, 1_000).expect("running");
        (job, lease)
    }

    fn rule(decision: &CommitDecision) -> Option<&'static str> {
        match decision {
            CommitDecision::Rejected { reason } => Some(reason),
            CommitDecision::Accepted { .. } => None,
        }
    }

    #[test]
    fn a_current_owner_commits_and_clears_the_lease() {
        let (mut job, lease) = running();
        let commit = ResultCommit::new("job-1", lease.fence(), "worker-a", 41, 41).expect("commit");
        let decision = commit_result(&mut job, &commit, 2_000).expect("decision");
        assert_eq!(
            decision,
            CommitDecision::Accepted {
                indexed_generation: 41,
                remains_dirty: false
            }
        );
        assert!(decision.is_accepted());
        assert!(!decision.keeps_dirty());
        assert_eq!(job.state, JobState::Succeeded);
        assert!(job.lease_owner.is_none());
        assert!(job.lease_until.is_none());
    }

    #[test]
    fn a_newer_generation_keeps_the_scope_dirty() {
        let (mut job, lease) = running();
        assert!(remains_dirty(41, 42));
        assert!(!remains_dirty(42, 42));
        let commit = ResultCommit::new("job-1", lease.fence(), "worker-a", 41, 42).expect("commit");
        let decision = commit_result(&mut job, &commit, 2_000).expect("decision");
        assert_eq!(
            decision,
            CommitDecision::Accepted {
                indexed_generation: 41,
                remains_dirty: true
            }
        );
        assert!(decision.keeps_dirty());
        // The job itself succeeded; the *file* remains dirty for the next batch.
        assert_eq!(job.state, JobState::Succeeded);
    }

    #[test]
    fn a_worker_reclaimed_by_a_new_fence_cannot_commit() {
        let (mut job, lease) = running();
        let old = ResultCommit::new("job-1", lease.fence(), "worker-a", 41, 41).expect("commit");
        // Another worker reclaims the job: a fresh claim takes the next fence.
        job.state = JobState::Pending;
        job.release_lease();
        let newer = match claim(&mut job, "worker-b", 3_000, 30_000).expect("claim") {
            ClaimOutcome::Claimed(lease) => lease,
            ClaimOutcome::NotEligible { .. } => panic!("claim"),
        };
        start_running(&mut job, &newer, 3_000).expect("running");
        let before = job.clone();

        let decision = commit_result(&mut job, &old, 3_100).expect("decision");
        assert_eq!(rule(&decision), Some(REASON_STALE_FENCE));
        assert_eq!(job, before, "a rejected commit never advances the job");
        assert_eq!(job.state, JobState::Running);

        // The live owner still can.
        let current =
            ResultCommit::new("job-1", newer.fence(), "worker-b", 42, 42).expect("commit");
        assert!(commit_result(&mut job, &current, 3_100)
            .expect("decision")
            .is_accepted());
    }

    #[test]
    fn a_result_from_a_pending_job_is_refused_and_changes_nothing() {
        let mut job = JobRecord::new("job-1", "sol-1", JobKind::ParseBatch, "p:a", 0, 3, 0);
        let before = job.clone();
        let commit = ResultCommit::new("job-1", 0, "worker-a", 1, 1).expect("commit");
        let decision = commit_result(&mut job, &commit, 1).expect("decision");
        assert_eq!(rule(&decision), Some(crate::REASON_TRANSITION_NOT_ALLOWED));
        assert_eq!(job, before);
    }

    #[test]
    fn a_terminal_job_rejects_every_commit() {
        let (mut job, lease) = running();
        job.state = JobState::Cancelled;
        job.release_lease();
        let commit = ResultCommit::new("job-1", lease.fence(), "worker-a", 1, 1).expect("commit");
        let decision = commit_result(&mut job, &commit, 2_000).expect("decision");
        assert_eq!(rule(&decision), Some(crate::REASON_TERMINAL_STATE));
    }

    #[test]
    fn a_commit_for_another_job_is_a_validation_error() {
        let (mut job, lease) = running();
        let commit = ResultCommit::new("job-2", lease.fence(), "worker-a", 1, 1).expect("commit");
        assert!(commit_result(&mut job, &commit, 2_000).is_err());
    }

    #[test]
    fn negative_generations_are_refused_at_construction() {
        assert!(ResultCommit::new("job-1", 0, "worker-a", -1, 0).is_err());
        assert!(ResultCommit::new("job-1", 0, "worker-a", 0, -1).is_err());
    }

    #[test]
    fn an_out_of_order_fence_cannot_skip_ahead() {
        let (mut job, lease) = running();
        let ahead = Lease::restore("job-1", lease.fence() + 1, "worker-a", lease.lease_until());
        let commit = ResultCommit::new("job-1", ahead.fence(), "worker-a", 1, 1).expect("commit");
        let decision = commit_result(&mut job, &commit, 2_000).expect("decision");
        assert_eq!(rule(&decision), Some(crate::REASON_FENCE_OUT_OF_ORDER));
        assert_eq!(job.state, JobState::Running);
    }
}
