//! Atomic claim with one owner and a strictly increasing fence (task B-034).
//!
//! The durable claim runs in one `BEGIN IMMEDIATE` transaction
//! (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 4): choose an eligible
//! job, bump the attempt and the fence, record the lease owner and deadline, then
//! commit. This module computes that decision; it never holds a transaction while
//! anything is parsed.
//!
//! The lease identity is the tuple `(job_id, fence, owner)`
//! (`contracts/queue-state-machine.md` section 4). Because the fence strictly
//! increases on every claim, two claimers that race cannot both be the live owner:
//! the later claim takes a higher fence and every event from the earlier lease is
//! then rejected as stale (F3/F4).

use graph_core::error::{AxiomError, ErrorCode};

use crate::{ensure_transition, next_fence, JobRecord, JobState};

/// Default lease duration used before the runtime configuration supplies one.
pub const DEFAULT_LEASE_MS: i64 = 30_000;
/// Longest lease this build will grant, so a crashed owner is reclaimable.
pub const MAX_LEASE_MS: i64 = 300_000;

/// A live claim on a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    job_id: String,
    fence: i64,
    owner: String,
    lease_until: i64,
}

impl Lease {
    /// The job this lease covers.
    #[must_use]
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    /// Ownership generation.
    #[must_use]
    pub const fn fence(&self) -> i64 {
        self.fence
    }

    /// Lease owner identity.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Deadline in milliseconds on the caller's timeline.
    #[must_use]
    pub const fn lease_until(&self) -> i64 {
        self.lease_until
    }

    /// Whether this lease is still live at `now`.
    #[must_use]
    pub const fn is_live_at(&self, now: i64) -> bool {
        self.lease_until > now
    }

    /// Whether this lease is the live one recorded on `job`.
    #[must_use]
    pub fn matches(&self, job: &JobRecord) -> bool {
        job.fence == self.fence && job.lease_owner.as_deref() == Some(self.owner.as_str())
    }

    /// Rebuild a lease from the durable row after a restart.
    ///
    /// Recovery reads `(fence, lease_owner, lease_until)` back out of the `jobs`
    /// table; it must not invent a new fence, because F5 says the fence only
    /// advances through an accepted claim.
    #[must_use]
    pub fn restore(
        job_id: impl Into<String>,
        fence: i64,
        owner: impl Into<String>,
        lease_until: i64,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            fence,
            owner: owner.into(),
            lease_until,
        }
    }
}

/// The outcome of a claim attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// The job was claimed; the returned lease is the live one.
    Claimed(Lease),
    /// The job exists but is not eligible at this time.
    NotEligible {
        /// The state that made the job ineligible.
        state: JobState,
    },
}

/// Claim `job` for `owner`, granting a lease of `lease_ms` from `now`.
///
/// # Errors
/// [`ErrorCode::ValidationError`] when the owner is empty, and
/// [`ErrorCode::Conflict`] when the fence cannot increase further.
pub fn claim(
    job: &mut JobRecord,
    owner: &str,
    now: i64,
    lease_ms: i64,
) -> Result<ClaimOutcome, AxiomError> {
    if owner.is_empty() {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "a lease owner identity must not be empty",
        )
        .with_detail("job_id", job.id.clone()));
    }
    if !job.is_claimable_at(now) {
        return Ok(ClaimOutcome::NotEligible { state: job.state });
    }
    let fence = next_fence(job.fence)?;
    let from = job.state;
    ensure_transition(from, JobState::Leased)?;
    job.fence = fence;
    job.state = JobState::Leased;
    job.attempt = job.attempt.saturating_add(1);
    job.lease_owner = Some(owner.to_string());
    let duration = crate::clamp_duration(lease_ms, MAX_LEASE_MS);
    job.lease_until = Some(now.saturating_add(duration));
    Ok(ClaimOutcome::Claimed(Lease {
        job_id: job.id.clone(),
        fence,
        owner: owner.to_string(),
        lease_until: now.saturating_add(duration),
    }))
}

/// Move a `LEASED` job into `RUNNING`.
///
/// # Errors
/// [`ErrorCode::Conflict`] when the transition is not allowed, when the lease is
/// expired, or when the caller does not hold the live lease (F2/F5).
pub fn start_running(job: &mut JobRecord, lease: &Lease, now: i64) -> Result<(), AxiomError> {
    ensure_transition(job.state, JobState::Running)?;
    ensure_live_owner(job, lease, now)?;
    job.state = JobState::Running;
    Ok(())
}

/// Refuse anything that is not the live lease owner.
///
/// # Errors
/// [`ErrorCode::Conflict`] whose `rule` detail is `stale_fence`,
/// `fence_out_of_order`, `lease_owner_mismatch` or `lease_expired`.
pub fn ensure_live_owner(job: &JobRecord, lease: &Lease, now: i64) -> Result<(), AxiomError> {
    if job.state.is_terminal() {
        return Err(
            AxiomError::new(ErrorCode::Conflict, "job is in a terminal state")
                .with_detail("rule", crate::REASON_TERMINAL_STATE)
                .with_detail("job_id", job.id.clone()),
        );
    }
    if lease.fence < job.fence {
        return Err(AxiomError::new(ErrorCode::Conflict, "lease fence is stale")
            .with_detail("rule", crate::REASON_STALE_FENCE)
            .with_detail("job_id", job.id.clone())
            .with_detail("actual", lease.fence.to_string())
            .with_detail("expected", job.fence.to_string()));
    }
    if lease.fence > job.fence {
        return Err(
            AxiomError::new(ErrorCode::Conflict, "lease fence is ahead of the job")
                .with_detail("rule", crate::REASON_FENCE_OUT_OF_ORDER)
                .with_detail("job_id", job.id.clone())
                .with_detail("actual", lease.fence.to_string())
                .with_detail("expected", job.fence.to_string()),
        );
    }
    if job.lease_owner.as_deref() != Some(lease.owner.as_str()) {
        return Err(
            AxiomError::new(ErrorCode::Conflict, "caller does not own the live lease")
                .with_detail("rule", crate::REASON_LEASE_OWNER_MISMATCH)
                .with_detail("job_id", job.id.clone()),
        );
    }
    if job.lease_until.is_none_or(|until| until <= now) {
        return Err(
            AxiomError::new(ErrorCode::Conflict, "the lease has expired")
                .with_detail("rule", crate::REASON_LEASE_EXPIRED)
                .with_detail("job_id", job.id.clone()),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{claim, ensure_live_owner, start_running, ClaimOutcome, DEFAULT_LEASE_MS};
    use crate::{JobKind, JobRecord, JobState, REASON_LEASE_EXPIRED, REASON_STALE_FENCE};

    fn job() -> JobRecord {
        JobRecord::new("job-1", "sol-1", JobKind::ParseBatch, "p:a", 0, 3, 0)
    }

    fn rule(error: &graph_core::error::AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    #[test]
    fn a_claim_takes_one_owner_and_the_next_fence() {
        let mut record = job();
        let outcome = claim(&mut record, "worker-a", 1_000, DEFAULT_LEASE_MS).expect("claim");
        let ClaimOutcome::Claimed(lease) = outcome else {
            panic!("expected a claim");
        };
        assert_eq!(lease.fence(), 1);
        assert_eq!(lease.owner(), "worker-a");
        assert_eq!(lease.lease_until(), 1_000 + DEFAULT_LEASE_MS);
        assert_eq!(record.state, JobState::Leased);
        assert_eq!(record.attempt, 1);
        assert_eq!(record.lease_owner.as_deref(), Some("worker-a"));
        assert!(lease.matches(&record));
        assert!(lease.is_live_at(1_000));
    }

    #[test]
    fn concurrent_claimers_cannot_share_a_fence() {
        let mut record = job();
        let first = match claim(&mut record, "worker-a", 0, DEFAULT_LEASE_MS).expect("first") {
            ClaimOutcome::Claimed(lease) => lease,
            ClaimOutcome::NotEligible { .. } => panic!("first claim must succeed"),
        };
        // The second claimer must wait for eligibility; force the row back to a
        // claimable state the way lease expiry would, then claim again.
        record.state = JobState::Pending;
        record.release_lease();
        let second = match claim(&mut record, "worker-b", 1, DEFAULT_LEASE_MS).expect("second") {
            ClaimOutcome::Claimed(lease) => lease,
            ClaimOutcome::NotEligible { .. } => panic!("second claim must succeed"),
        };
        assert_eq!(first.fence(), 1);
        assert_eq!(second.fence(), 2);
        assert!(second.matches(&record), "the later claim is the live lease");
        // The first lease is now stale: F3 rejects it without advancing the job.
        let before = record.clone();
        let error = ensure_live_owner(&record, &first, 2).expect_err("stale lease");
        assert_eq!(rule(&error), Some(REASON_STALE_FENCE));
        assert_eq!(record, before, "a rejected event never advances the job");
    }

    #[test]
    fn a_running_job_requires_the_live_lease() {
        let mut record = job();
        let lease = match claim(&mut record, "worker-a", 0, DEFAULT_LEASE_MS).expect("claim") {
            ClaimOutcome::Claimed(lease) => lease,
            ClaimOutcome::NotEligible { .. } => panic!("claim"),
        };
        start_running(&mut record, &lease, 10).expect("start");
        assert_eq!(record.state, JobState::Running);

        let foreign = super::Lease {
            job_id: "job-1".to_string(),
            fence: lease.fence(),
            owner: "worker-b".to_string(),
            lease_until: lease.lease_until(),
        };
        let error = ensure_live_owner(&record, &foreign, 10).expect_err("wrong owner");
        assert_eq!(rule(&error), Some(crate::REASON_LEASE_OWNER_MISMATCH));

        let error = ensure_live_owner(&record, &lease, lease.lease_until()).expect_err("expired");
        assert_eq!(rule(&error), Some(REASON_LEASE_EXPIRED));
    }

    #[test]
    fn an_ineligible_job_is_reported_without_mutation() {
        let mut record = job();
        record.state = JobState::Running;
        let before = record.clone();
        let outcome = claim(&mut record, "worker-a", 0, DEFAULT_LEASE_MS).expect("decision");
        assert_eq!(
            outcome,
            ClaimOutcome::NotEligible {
                state: JobState::Running
            }
        );
        assert_eq!(record, before);
    }

    #[test]
    fn a_ready_at_in_the_future_delays_the_claim() {
        let mut record = job();
        record.ready_at = 500;
        let outcome = claim(&mut record, "worker-a", 499, DEFAULT_LEASE_MS).expect("decision");
        assert!(matches!(outcome, ClaimOutcome::NotEligible { .. }));
        assert!(claim(&mut record, "worker-a", 500, DEFAULT_LEASE_MS).is_ok());
    }

    #[test]
    fn an_empty_owner_is_refused_before_any_state_change() {
        let mut record = job();
        let before = record.clone();
        assert!(claim(&mut record, "", 0, DEFAULT_LEASE_MS).is_err());
        assert_eq!(record, before);
    }

    #[test]
    fn a_requested_lease_is_clamped_to_the_maximum() {
        let mut record = job();
        let lease = match claim(&mut record, "worker-a", 0, i64::MAX).expect("claim") {
            ClaimOutcome::Claimed(lease) => lease,
            ClaimOutcome::NotEligible { .. } => panic!("claim"),
        };
        assert_eq!(lease.lease_until(), super::MAX_LEASE_MS);
    }
}
