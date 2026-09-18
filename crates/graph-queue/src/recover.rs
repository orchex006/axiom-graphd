//! Recover leases left behind by a dead process (task B-041).
//!
//! When a daemon stops mid-job its lease row survives
//! (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 10). The restart path
//! must make that work eligible again without letting the vanished owner come
//! back and publish: the row is returned to `PENDING` with the fence unchanged
//! (F8) and the next claim takes a strictly higher fence, so any late result from
//! the dead process fails F3/F4.
//!
//! Recovery must also not duplicate a completed publication. Staging is
//! idempotent by `(project, generation, lane)` and the durable record of that is
//! `published_generations` plus the `publish_outbox.idempotency_key` unique index.
//! [`PublicationLedger`] is the decision-side mirror of that record.

use std::collections::BTreeMap;

use graph_core::error::AxiomError;

use crate::claim::{claim, ClaimOutcome, Lease};
use crate::{JobRecord, JobState};

/// Which published track a generation belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Lane {
    /// The current live graph.
    Live,
    /// An archived checkpoint.
    Checkpoint,
}

impl Lane {
    /// Stable wire spelling, matching `published_generations.lane`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Checkpoint => "checkpoint",
        }
    }
}

/// Identity of one published generation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicationKey {
    project_id: String,
    generation_id: String,
    lane: Lane,
}

impl PublicationKey {
    /// Name one published generation.
    #[must_use]
    pub fn new(
        project_id: impl Into<String>,
        generation_id: impl Into<String>,
        lane: Lane,
    ) -> Self {
        Self {
            project_id: project_id.into(),
            generation_id: generation_id.into(),
            lane,
        }
    }

    /// Owning project.
    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Generation identity.
    #[must_use]
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    /// Published lane.
    #[must_use]
    pub const fn lane(&self) -> Lane {
        self.lane
    }
}

/// The set of publications already recorded as complete.
#[derive(Debug, Default, Clone)]
pub struct PublicationLedger {
    published: BTreeMap<PublicationKey, String>,
}

impl PublicationLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a publication. Returns `false` when it was already recorded, so a
    /// recovery replay never publishes the same generation twice.
    pub fn record(&mut self, key: PublicationKey, revision_id: impl Into<String>) -> bool {
        if self.published.contains_key(&key) {
            return false;
        }
        self.published.insert(key, revision_id.into());
        true
    }

    /// Whether a publication is already complete.
    #[must_use]
    pub fn contains(&self, key: &PublicationKey) -> bool {
        self.published.contains_key(key)
    }

    /// Number of recorded publications.
    #[must_use]
    pub fn len(&self) -> usize {
        self.published.len()
    }

    /// Whether nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.published.is_empty()
    }

    /// The revision recorded for a publication.
    #[must_use]
    pub fn revision(&self, key: &PublicationKey) -> Option<&str> {
        self.published.get(key).map(String::as_str)
    }
}

/// Whether a publication still has to be performed.
#[must_use]
pub fn needs_publication(ledger: &PublicationLedger, key: &PublicationKey) -> bool {
    !ledger.contains(key)
}

/// What happened while reclaiming a lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReclaimOutcome {
    /// The abandoned lease was replaced by a new one with a higher fence.
    Reclaimed {
        /// The new live lease.
        lease: Lease,
        /// Owner that vanished.
        previous_owner: String,
        /// Fence the vanished owner held.
        previous_fence: i64,
    },
    /// The lease is still live or the job cannot be reclaimed.
    NotReclaimable {
        /// Stable reason code.
        reason: &'static str,
    },
}

impl ReclaimOutcome {
    /// Whether a new lease was granted.
    #[must_use]
    pub const fn is_reclaimed(&self) -> bool {
        matches!(self, Self::Reclaimed { .. })
    }
}

/// Whether a job holds a lease that has already expired.
#[must_use]
pub fn is_reclaimable(job: &JobRecord, now: i64) -> bool {
    if !job.state.holds_lease() {
        return false;
    }
    match job.lease_until {
        Some(until) => until <= now,
        None => true,
    }
}

/// The reason a job cannot be reclaimed, or `None` when it can.
#[must_use]
pub fn refusal_reason(job: &JobRecord, now: i64) -> Option<&'static str> {
    if job.state.is_terminal() {
        return Some(crate::REASON_TERMINAL_STATE);
    }
    if !job.state.holds_lease() {
        return Some(crate::REASON_NOT_ELIGIBLE);
    }
    if !is_reclaimable(job, now) {
        return Some(crate::REASON_LEASE_NOT_EXPIRED);
    }
    None
}

/// Replace an expired lease with a fresh one for `new_owner`.
///
/// # Errors
/// [`ErrorCode::Conflict`] when the fence cannot increase.
pub fn reclaim_expired(
    job: &mut JobRecord,
    now: i64,
    new_owner: &str,
    lease_ms: i64,
) -> Result<ReclaimOutcome, AxiomError> {
    if let Some(reason) = refusal_reason(job, now) {
        return Ok(ReclaimOutcome::NotReclaimable { reason });
    }
    let previous_owner = job.lease_owner.clone().unwrap_or_default();
    let previous_fence = job.fence;
    // F8: the lease expires without changing the fence, and only an accepted
    // claim advances it.
    job.state = JobState::Pending;
    job.ready_at = now;
    job.release_lease();
    match claim(job, new_owner, now, lease_ms)? {
        ClaimOutcome::Claimed(lease) => Ok(ReclaimOutcome::Reclaimed {
            lease,
            previous_owner,
            previous_fence,
        }),
        ClaimOutcome::NotEligible { state } => Ok(ReclaimOutcome::NotReclaimable {
            reason: match state {
                JobState::Pending => crate::REASON_NOT_ELIGIBLE,
                _ => crate::REASON_NOT_ELIGIBLE,
            },
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        needs_publication, reclaim_expired, Lane, PublicationKey, PublicationLedger, ReclaimOutcome,
    };
    use crate::claim::{claim, start_running, ClaimOutcome};
    use crate::{JobKind, JobRecord, JobState, REASON_LEASE_NOT_EXPIRED, REASON_TERMINAL_STATE};

    fn leased(lease_until: i64) -> JobRecord {
        let mut job = JobRecord::new("job-1", "sol-1", JobKind::ParseBatch, "p:a", 0, 3, 0);
        let lease = match claim(&mut job, "worker-a", 0, lease_until).expect("claim") {
            ClaimOutcome::Claimed(lease) => lease,
            ClaimOutcome::NotEligible { .. } => panic!("claim"),
        };
        start_running(&mut job, &lease, 0).expect("running");
        job
    }

    fn rule(outcome: &ReclaimOutcome) -> Option<&'static str> {
        match outcome {
            ReclaimOutcome::NotReclaimable { reason } => Some(reason),
            ReclaimOutcome::Reclaimed { .. } => None,
        }
    }

    #[test]
    fn an_expired_lease_becomes_eligible_with_a_new_fence() {
        let mut job = leased(1_000);
        let outcome = reclaim_expired(&mut job, 1_000, "worker-b", 30_000).expect("reclaim");
        assert!(outcome.is_reclaimed());
        let ReclaimOutcome::Reclaimed {
            lease,
            previous_owner,
            previous_fence,
        } = outcome
        else {
            panic!("expected a reclaim");
        };
        assert_eq!(previous_owner, "worker-a");
        assert_eq!(previous_fence, 1);
        assert_eq!(lease.fence(), 2, "the fence must strictly increase");
        assert_eq!(lease.owner(), "worker-b");
        assert_eq!(job.state, JobState::Leased);
        assert_eq!(job.attempt, 2, "a reclaim is a new dispatch attempt");
    }

    #[test]
    fn a_live_lease_is_not_reclaimed() {
        let mut job = leased(10_000);
        let before = job.clone();
        let outcome = reclaim_expired(&mut job, 999, "worker-b", 30_000).expect("decision");
        assert_eq!(rule(&outcome), Some(REASON_LEASE_NOT_EXPIRED));
        assert_eq!(job, before, "a refusal must not touch the row");
    }

    #[test]
    fn a_terminal_job_is_not_reclaimed() {
        let mut job = leased(1_000);
        job.state = JobState::Succeeded;
        job.release_lease();
        let outcome = reclaim_expired(&mut job, 5_000, "worker-b", 30_000).expect("decision");
        assert_eq!(rule(&outcome), Some(REASON_TERMINAL_STATE));
    }

    #[test]
    fn a_pending_job_needs_no_reclaim() {
        let mut job = JobRecord::new("job-1", "sol-1", JobKind::ParseBatch, "p:a", 0, 3, 0);
        let outcome = reclaim_expired(&mut job, 5_000, "worker-b", 30_000).expect("decision");
        assert_eq!(rule(&outcome), Some(crate::REASON_NOT_ELIGIBLE));
    }

    #[test]
    fn a_late_result_from_the_dead_owner_is_stale_after_reclaim() {
        let mut job = leased(1_000);
        let dead_lease = crate::claim::Lease::restore("job-1", job.fence, "worker-a", 1_000);
        reclaim_expired(&mut job, 1_000, "worker-b", 30_000).expect("reclaim");
        let error = crate::claim::ensure_live_owner(&job, &dead_lease, 1_001)
            .expect_err("the dead owner must be rejected");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(crate::REASON_STALE_FENCE)
        );
    }

    #[test]
    fn a_recovered_lease_with_no_deadline_is_reclaimable() {
        let mut job = JobRecord::new("job-1", "sol-1", JobKind::ParseBatch, "p:a", 0, 3, 0);
        job.state = JobState::Running;
        job.fence = 4;
        job.lease_owner = Some("worker-a".to_string());
        job.lease_until = None;
        assert!(super::is_reclaimable(&job, 0));
        let outcome = reclaim_expired(&mut job, 0, "worker-b", 30_000).expect("reclaim");
        assert!(outcome.is_reclaimed());
        assert_eq!(job.fence, 5);
    }

    #[test]
    fn a_completed_publication_is_not_repeated() {
        let mut ledger = PublicationLedger::new();
        let key = PublicationKey::new("proj-1", "gen-1", Lane::Live);
        assert!(needs_publication(&ledger, &key));
        assert!(ledger.record(key.clone(), "rev-7"));
        assert!(
            !ledger.record(key.clone(), "rev-7"),
            "a replay must be a no-op"
        );
        assert!(!needs_publication(&ledger, &key));
        assert_eq!(ledger.revision(&key), Some("rev-7"));
        assert_eq!(ledger.len(), 1);

        let checkpoint = PublicationKey::new("proj-1", "gen-1", Lane::Checkpoint);
        assert!(needs_publication(&ledger, &checkpoint));
        assert!(ledger.record(checkpoint, "rev-8"));
        assert_eq!(ledger.len(), 2);
    }

    #[test]
    fn an_empty_ledger_reports_empty() {
        let ledger = PublicationLedger::new();
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn lane_spellings_match_the_schema() {
        assert_eq!(Lane::Live.as_str(), "live");
        assert_eq!(Lane::Checkpoint.as_str(), "checkpoint");
    }
}
