//! Priority scheduling with bounded aging (task B-037).
//!
//! `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 6 fixes the ordering:
//! explicit checkpoint or on-demand freshness work runs before interactive
//! changed-file work, which runs before inventory, which runs before garbage
//! collection - but a wait bonus must be applied so a low-priority job cannot be
//! starved forever by a stream of higher-priority work.
//!
//! The bonus is bounded, so a very old maintenance job can be selected over a
//! brand new verification job, and a brand new verification job still beats a
//! brand new inventory job. Ordering is total and deterministic: ties break on
//! ready time, then creation time, then job id, so two schedulers with the same
//! input always pick the same job.

use crate::JobKind;

/// Priority class of explicit checkpoint, export and freshness verification work.
pub const PRIORITY_VERIFICATION: i32 = 300;
/// Priority class of interactive changed-file work.
pub const PRIORITY_INTERACTIVE: i32 = 200;
/// Priority class of periodic and recovery inventory scans.
pub const PRIORITY_INVENTORY: i32 = 100;
/// Priority class of background maintenance such as snapshot garbage collection.
pub const PRIORITY_MAINTENANCE: i32 = 0;

/// Milliseconds of waiting that earn one priority point.
pub const AGING_INTERVAL_MS: i64 = 1_000;
/// Maximum priority points a job can earn by waiting.
///
/// The bound is what keeps the ordering total: without it, the lowest class could
/// eventually outrank everything by an unbounded margin, which would make the
/// declared class ordering meaningless.
pub const MAX_AGING_BONUS: i64 = 500;

/// The declared class of a job kind.
#[must_use]
pub const fn base_priority(kind: JobKind) -> i32 {
    match kind {
        JobKind::VerifyCheckpoint | JobKind::CheckpointExport => PRIORITY_VERIFICATION,
        JobKind::ParseBatch | JobKind::ResolveAffected | JobKind::PublishProject => {
            PRIORITY_INTERACTIVE
        }
        JobKind::InventoryScan | JobKind::Repair | JobKind::PublishCatalog => PRIORITY_INVENTORY,
        JobKind::SnapshotGc => PRIORITY_MAINTENANCE,
    }
}

/// A job the scheduler may consider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    job_id: String,
    kind: JobKind,
    priority: i32,
    ready_at: i64,
    created_at: i64,
}

impl Candidate {
    /// Describe one schedulable job.
    #[must_use]
    pub fn new(
        job_id: impl Into<String>,
        kind: JobKind,
        priority: i32,
        ready_at: i64,
        created_at: i64,
    ) -> Self {
        Self {
            job_id: job_id.into(),
            kind,
            priority,
            ready_at,
            created_at,
        }
    }

    /// A candidate that uses the declared class of its kind.
    #[must_use]
    pub fn of_kind(
        job_id: impl Into<String>,
        kind: JobKind,
        ready_at: i64,
        created_at: i64,
    ) -> Self {
        Self::new(job_id, kind, base_priority(kind), ready_at, created_at)
    }

    /// Stable job id.
    #[must_use]
    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    /// Work kind.
    #[must_use]
    pub const fn kind(&self) -> JobKind {
        self.kind
    }

    /// Earliest time the job may run.
    #[must_use]
    pub const fn ready_at(&self) -> i64 {
        self.ready_at
    }

    /// Whether the job may run at `now`.
    #[must_use]
    pub const fn is_ready_at(&self, now: i64) -> bool {
        self.ready_at <= now
    }
}

/// Priority points earned by waiting from `created_at` until `now`.
#[must_use]
pub fn aging_bonus(created_at: i64, now: i64) -> i64 {
    if now <= created_at {
        return 0;
    }
    let waited = now - created_at;
    (waited / AGING_INTERVAL_MS).min(MAX_AGING_BONUS)
}

/// Effective priority of a candidate at `now`, including the bounded wait bonus.
#[must_use]
pub fn effective_priority(candidate: &Candidate, now: i64) -> i64 {
    i64::from(candidate.priority) + aging_bonus(candidate.created_at, now)
}

/// The order in which ready candidates should run at `now`.
#[must_use]
pub fn order(candidates: &[Candidate], now: i64) -> Vec<&Candidate> {
    let mut ready: Vec<&Candidate> = candidates.iter().filter(|c| c.is_ready_at(now)).collect();
    ready.sort_by(|a, b| {
        effective_priority(b, now)
            .cmp(&effective_priority(a, now))
            .then_with(|| a.ready_at.cmp(&b.ready_at))
            .then_with(|| a.created_at.cmp(&b.created_at))
            .then_with(|| a.job_id.cmp(&b.job_id))
    });
    ready
}

/// The next job to run at `now`, if any is ready.
#[must_use]
pub fn select_next(candidates: &[Candidate], now: i64) -> Option<&Candidate> {
    order(candidates, now).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::{
        aging_bonus, base_priority, effective_priority, order, select_next, Candidate,
        MAX_AGING_BONUS, PRIORITY_INTERACTIVE, PRIORITY_INVENTORY, PRIORITY_VERIFICATION,
    };
    use crate::JobKind;

    #[test]
    fn the_declared_class_ordering_is_verification_then_interactive_then_inventory_then_maintenance(
    ) {
        assert_eq!(
            base_priority(JobKind::VerifyCheckpoint),
            PRIORITY_VERIFICATION
        );
        assert_eq!(
            base_priority(JobKind::CheckpointExport),
            PRIORITY_VERIFICATION
        );
        assert_eq!(base_priority(JobKind::ParseBatch), PRIORITY_INTERACTIVE);
        assert_eq!(base_priority(JobKind::InventoryScan), PRIORITY_INVENTORY);
        assert!(base_priority(JobKind::SnapshotGc) < PRIORITY_INVENTORY);
        assert!(base_priority(JobKind::InventoryScan) < PRIORITY_VERIFICATION);
    }

    #[test]
    fn explicit_verification_runs_ahead_of_inventory() {
        let candidates = vec![
            Candidate::of_kind("inv", JobKind::InventoryScan, 0, 0),
            Candidate::of_kind("verify", JobKind::VerifyCheckpoint, 0, 0),
        ];
        let next = select_next(&candidates, 0).expect("a ready job");
        assert_eq!(next.job_id(), "verify");
    }

    #[test]
    fn inventory_is_not_starved_indefinitely() {
        let candidates = vec![
            Candidate::of_kind("inv", JobKind::InventoryScan, 0, 0),
            Candidate::of_kind("verify-fresh", JobKind::VerifyCheckpoint, 600_000, 600_000),
        ];
        // Both are ready; the inventory job has waited the whole aging window.
        let next = select_next(&candidates, 600_000).expect("a ready job");
        assert_eq!(
            next.job_id(),
            "inv",
            "an old inventory job must eventually overtake a new verification job"
        );
    }

    #[test]
    fn garbage_collection_is_not_starved_indefinitely() {
        let candidates = vec![
            Candidate::of_kind("gc", JobKind::SnapshotGc, 0, 0),
            Candidate::of_kind("verify-fresh", JobKind::VerifyCheckpoint, 500_000, 500_000),
        ];
        let next = select_next(&candidates, 500_000).expect("a ready job");
        assert_eq!(next.job_id(), "gc");
    }

    #[test]
    fn the_wait_bonus_is_bounded() {
        assert_eq!(aging_bonus(0, 0), 0);
        assert_eq!(aging_bonus(1_000, 0), 0, "no negative aging");
        assert_eq!(aging_bonus(0, 4_999), 4);
        assert_eq!(aging_bonus(0, 10_000_000_000), MAX_AGING_BONUS);
        // With the bonus capped, the declared classes still separate a fresh
        // verification job from a permanently-waiting maintenance job.
        let now = 1_000_000_000;
        assert!(
            effective_priority(
                &Candidate::of_kind("v", JobKind::VerifyCheckpoint, now, now),
                now
            ) > effective_priority(&Candidate::of_kind("g", JobKind::SnapshotGc, now, now), now),
            "a fresh maintenance job must still rank below a fresh verification job"
        );
    }

    #[test]
    fn a_job_whose_ready_at_is_in_the_future_is_not_selected() {
        let candidates = vec![Candidate::of_kind(
            "later",
            JobKind::VerifyCheckpoint,
            500,
            0,
        )];
        assert!(select_next(&candidates, 499).is_none());
        assert!(select_next(&candidates, 500).is_some());
    }

    #[test]
    fn ordering_is_total_and_deterministic() {
        let candidates = vec![
            Candidate::of_kind("b", JobKind::ParseBatch, 0, 0),
            Candidate::of_kind("a", JobKind::ParseBatch, 0, 0),
        ];
        let forward = order(&candidates, 0);
        let mut shuffled = candidates.clone();
        shuffled.reverse();
        let reverse = order(&shuffled, 0);
        assert_eq!(
            forward.iter().map(|c| c.job_id()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert_eq!(
            forward.iter().map(|c| c.job_id()).collect::<Vec<_>>(),
            reverse.iter().map(|c| c.job_id()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_explicit_priority_override_is_honoured() {
        let candidates = vec![
            Candidate::new("low", JobKind::SnapshotGc, -10, 0, 0),
            Candidate::new("high", JobKind::SnapshotGc, 999, 0, 0),
        ];
        assert_eq!(select_next(&candidates, 0).expect("ready").job_id(), "high");
    }
}
