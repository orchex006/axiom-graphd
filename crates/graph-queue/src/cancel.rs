//! Queued and running cancellation (task B-040).
//!
//! Cancellation is cooperative (`contracts/queue-state-machine.md` section 5).
//! A job that has not been leased is moved to `CANCEL_REQUESTED` and acknowledged
//! immediately, because no worker has to notice anything. A job that a worker
//! already holds cannot be stopped from the scheduler thread: the request is
//! recorded, a shared [`CancelToken`] is raised, and the job reaches `CANCELLED`
//! only when the owner acknowledges.
//!
//! Cancelling never discards the dirty state that caused the job to be queued.
//! This module enforces that structurally: every cancel entry point takes the
//! dirty ledger by shared reference, so a cancellation cannot remove an entry
//! even by mistake. The work that the cancelled job would have done is still owed
//! and must be reconciled by a later batch.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use graph_core::error::{AxiomError, ErrorCode};

use crate::{JobRecord, JobState};

/// Distinct dirty portable paths that a cancelled job still owes.
pub type DirtyLedger = BTreeSet<String>;

/// What a cancellation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelOutcome {
    /// The job is now `CANCELLED`.
    Cancelled {
        /// Dirty paths still owed after the cancellation.
        outstanding_dirty: usize,
    },
    /// The job is now `CANCEL_REQUESTED` and awaits its owner.
    Requested {
        /// Whether the request reached a worker that holds a lease.
        worker_notified: bool,
    },
    /// The request was already recorded; the call is idempotent.
    AlreadyRequested,
    /// The job was already `CANCELLED`.
    AlreadyCancelled,
    /// The job is in a different terminal state and cannot be cancelled.
    Terminal {
        /// The terminal state that refused the request.
        state: JobState,
    },
}

impl CancelOutcome {
    /// Whether the job is in a terminal state afterwards.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Cancelled { .. } | Self::AlreadyCancelled)
    }
}

/// A cooperative cancellation flag shared with a running worker.
#[derive(Debug, Clone, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    /// A token that is not cancelled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Raise the flag. Idempotent.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// A second handle to the same flag, for the worker thread.
    #[must_use]
    pub fn handle(&self) -> Self {
        Self {
            flag: Arc::clone(&self.flag),
        }
    }
}

/// Record a cancellation request for `job`.
///
/// A pending job is acknowledged in the same call, because there is no worker to
/// wait for. A leased or running job is left in `CANCEL_REQUESTED` and its token
/// is raised.
///
/// # Errors
/// [`ErrorCode::Conflict`] when the contract does not allow the transition.
pub fn request_cancel(
    job: &mut JobRecord,
    dirty: &DirtyLedger,
    token: &CancelToken,
) -> Result<CancelOutcome, AxiomError> {
    if job.state == JobState::Cancelled {
        return Ok(CancelOutcome::AlreadyCancelled);
    }
    if job.state.is_terminal() {
        return Ok(CancelOutcome::Terminal { state: job.state });
    }
    if job.state == JobState::CancelRequested {
        return Ok(CancelOutcome::AlreadyRequested);
    }
    let holds_lease = job.state.holds_lease();
    crate::ensure_transition(job.state, JobState::CancelRequested)?;
    job.state = JobState::CancelRequested;
    if holds_lease {
        token.cancel();
        return Ok(CancelOutcome::Requested {
            worker_notified: true,
        });
    }
    acknowledge_cancel(job, dirty)
}

/// Acknowledge a recorded cancellation request.
///
/// # Errors
/// [`ErrorCode::Conflict`] when the job is not currently `CANCEL_REQUESTED`.
pub fn acknowledge_cancel(
    job: &mut JobRecord,
    dirty: &DirtyLedger,
) -> Result<CancelOutcome, AxiomError> {
    if job.state == JobState::Cancelled {
        return Ok(CancelOutcome::AlreadyCancelled);
    }
    crate::ensure_transition(job.state, JobState::Cancelled)?;
    job.state = JobState::Cancelled;
    job.release_lease();
    Ok(CancelOutcome::Cancelled {
        outstanding_dirty: dirty.len(),
    })
}

/// Cancel a job that no worker holds, in one step.
///
/// # Errors
/// [`ErrorCode::Conflict`] when the job holds a lease or is terminal.
pub fn cancel_pending_now(
    job: &mut JobRecord,
    dirty: &DirtyLedger,
) -> Result<CancelOutcome, AxiomError> {
    if job.state.is_terminal() {
        return Ok(CancelOutcome::Terminal { state: job.state });
    }
    if job.state.holds_lease() {
        return Err(AxiomError::new(
            ErrorCode::Conflict,
            "a leased job must be cancelled cooperatively",
        )
        .with_detail("rule", crate::REASON_NOT_ELIGIBLE)
        .with_detail("job_id", job.id.clone()));
    }
    crate::ensure_transition(job.state, JobState::CancelRequested)?;
    crate::ensure_transition(JobState::CancelRequested, JobState::Cancelled)?;
    job.state = JobState::Cancelled;
    job.release_lease();
    Ok(CancelOutcome::Cancelled {
        outstanding_dirty: dirty.len(),
    })
}

/// How many dirty paths remain owed after cancelling `jobs`.
#[must_use]
pub fn outstanding_after_cancel(dirty: &DirtyLedger, cancelled: usize) -> usize {
    // Cancellation never removes a dirty entry, so every distinct path that was
    // owed before the cancellation is still owed afterwards.
    let _ = cancelled;
    dirty.len()
}

#[cfg(test)]
mod tests {
    use super::{
        acknowledge_cancel, cancel_pending_now, outstanding_after_cancel, request_cancel,
        CancelOutcome, CancelToken, DirtyLedger,
    };
    use crate::claim::{claim, start_running, ClaimOutcome};
    use crate::{JobKind, JobRecord, JobState};

    fn pending() -> JobRecord {
        JobRecord::new("job-1", "sol-1", JobKind::ParseBatch, "p:a", 0, 3, 0)
    }

    fn dirty() -> DirtyLedger {
        ["src/a.cs", "src/b.cs"]
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }

    #[test]
    fn a_pending_job_cancels_immediately() {
        let mut job = pending();
        let ledger = dirty();
        let outcome = request_cancel(&mut job, &ledger, &CancelToken::new()).expect("cancel");
        assert_eq!(
            outcome,
            CancelOutcome::Cancelled {
                outstanding_dirty: 2
            }
        );
        assert!(outcome.is_terminal());
        assert_eq!(job.state, JobState::Cancelled);
        assert!(job.lease_owner.is_none());
        assert_eq!(
            outstanding_after_cancel(&ledger, 1),
            2,
            "the dirty ledger is untouched by cancellation"
        );
    }

    #[test]
    fn a_running_job_observes_the_cancel_token() {
        let mut job = pending();
        let ledger = dirty();
        let lease = match claim(&mut job, "worker-a", 0, 30_000).expect("claim") {
            ClaimOutcome::Claimed(lease) => lease,
            ClaimOutcome::NotEligible { .. } => panic!("claim"),
        };
        start_running(&mut job, &lease, 0).expect("running");
        let token = CancelToken::new();
        let worker = token.handle();
        assert!(!worker.is_cancelled());

        let outcome = request_cancel(&mut job, &ledger, &token).expect("request");
        assert_eq!(
            outcome,
            CancelOutcome::Requested {
                worker_notified: true
            }
        );
        assert!(
            worker.is_cancelled(),
            "the worker sees cooperative cancellation"
        );
        assert_eq!(job.state, JobState::CancelRequested);
        assert!(
            !outcome.is_terminal(),
            "the worker has not acknowledged yet"
        );

        // The job never returns to a running state from CANCEL_REQUESTED.
        let before = job.clone();
        assert!(start_running(&mut job, &lease, 1).is_err());
        assert_eq!(job.state, before.state);

        let ack = acknowledge_cancel(&mut job, &ledger).expect("ack");
        assert_eq!(
            ack,
            CancelOutcome::Cancelled {
                outstanding_dirty: 2
            }
        );
        assert_eq!(job.state, JobState::Cancelled);
    }

    #[test]
    fn cancellation_is_idempotent_while_requested() {
        let mut job = pending();
        let ledger = dirty();
        let token = CancelToken::new();
        let lease = match claim(&mut job, "worker-a", 0, 30_000).expect("claim") {
            ClaimOutcome::Claimed(lease) => lease,
            ClaimOutcome::NotEligible { .. } => panic!("claim"),
        };
        start_running(&mut job, &lease, 0).expect("running");
        assert_eq!(
            request_cancel(&mut job, &ledger, &token).expect("first"),
            CancelOutcome::Requested {
                worker_notified: true
            }
        );
        assert_eq!(
            request_cancel(&mut job, &ledger, &token).expect("second"),
            CancelOutcome::AlreadyRequested
        );
        acknowledge_cancel(&mut job, &ledger).expect("ack");
        assert_eq!(
            request_cancel(&mut job, &ledger, &token).expect("third"),
            CancelOutcome::AlreadyCancelled
        );
    }

    #[test]
    fn a_succeeded_job_cannot_be_cancelled() {
        let mut job = pending();
        let ledger = dirty();
        job.state = JobState::Succeeded;
        let outcome = request_cancel(&mut job, &ledger, &CancelToken::new()).expect("decision");
        assert_eq!(
            outcome,
            CancelOutcome::Terminal {
                state: JobState::Succeeded
            }
        );
        assert_eq!(job.state, JobState::Succeeded);
    }

    #[test]
    fn cancel_pending_now_refuses_a_leased_job() {
        let mut job = pending();
        let ledger = dirty();
        claim(&mut job, "worker-a", 0, 30_000).expect("claim");
        assert!(cancel_pending_now(&mut job, &ledger).is_err());
        assert_eq!(job.state, JobState::Leased);
    }

    #[test]
    fn a_retry_waiting_job_cancels_immediately() {
        let mut job = pending();
        job.state = JobState::RetryWait;
        let ledger = dirty();
        let outcome = cancel_pending_now(&mut job, &ledger).expect("cancel");
        assert!(outcome.is_terminal());
        assert_eq!(job.state, JobState::Cancelled);
    }

    #[test]
    fn a_superseded_job_is_terminal_not_cancellable() {
        let mut job = pending();
        job.state = JobState::Superseded;
        let ledger = dirty();
        let outcome = cancel_pending_now(&mut job, &ledger).expect("decision");
        assert_eq!(
            outcome,
            CancelOutcome::Terminal {
                state: JobState::Superseded
            }
        );
    }
}
