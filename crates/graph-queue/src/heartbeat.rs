//! Lease renewal by the live fence owner only (task B-035).
//!
//! A heartbeat extends a lease. It must therefore be refused unless the caller is
//! the owner recorded for the highest fence and the lease has not already expired
//! (`contracts/queue-state-machine.md` section 4, F2 and F5). A refused heartbeat
//! is a no-op: F6 says a rejected event never advances the job and never clears
//! the live lease.
//!
//! The extension is bounded. If a renewal could push the deadline arbitrarily far
//! into the future, a stuck worker would keep a lease forever and a crashed
//! process would never be reclaimable by [`crate::recover`].

use graph_core::error::{AxiomError, ErrorCode};

use crate::claim::{Lease, MAX_LEASE_MS};
use crate::{JobRecord, JobState};

/// Longest single renewal this build will grant.
pub const MAX_HEARTBEAT_EXTENSION_MS: i64 = 120_000;

/// The result of a heartbeat attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatOutcome {
    /// The lease was renewed; the new deadline is present.
    Renewed {
        /// New lease deadline.
        lease_until: i64,
    },
    /// The heartbeat was refused and the job was not changed.
    Refused {
        /// Contract reason code for the refusal.
        reason: &'static str,
    },
}

impl HeartbeatOutcome {
    /// Whether the lease is still live after this attempt.
    #[must_use]
    pub const fn renewed(&self) -> bool {
        matches!(self, Self::Renewed { .. })
    }
}

/// Renew the lease held by `lease` for `extension_ms` from `now`.
///
/// # Errors
/// [`ErrorCode::ValidationError`] when the extension is negative. A refusal that
/// is a normal part of the protocol is not an error; it is
/// [`HeartbeatOutcome::Refused`].
pub fn heartbeat(
    job: &mut JobRecord,
    lease: &Lease,
    now: i64,
    extension_ms: i64,
) -> Result<HeartbeatOutcome, AxiomError> {
    if extension_ms < 0 {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "a heartbeat extension must not be negative",
        )
        .with_detail("actual", extension_ms.to_string())
        .with_detail("job_id", job.id.clone()));
    }
    if let Some(reason) = refusal_reason(job, lease, now) {
        return Ok(HeartbeatOutcome::Refused { reason });
    }
    let extension = crate::clamp_duration(extension_ms, MAX_HEARTBEAT_EXTENSION_MS);
    let current = job.lease_until.unwrap_or(now);
    let deadline = current
        .saturating_add(extension)
        .min(now.saturating_add(MAX_LEASE_MS));
    job.lease_until = Some(deadline);
    Ok(HeartbeatOutcome::Renewed {
        lease_until: deadline,
    })
}

/// Why a heartbeat would be refused, or `None` when it may be applied.
#[must_use]
pub fn refusal_reason(job: &JobRecord, lease: &Lease, now: i64) -> Option<&'static str> {
    if job.state.is_terminal() {
        return Some(crate::REASON_TERMINAL_STATE);
    }
    if !job.state.holds_lease() {
        return Some(crate::REASON_NOT_ELIGIBLE);
    }
    if lease.fence() < job.fence {
        return Some(crate::REASON_STALE_FENCE);
    }
    if lease.fence() > job.fence {
        return Some(crate::REASON_FENCE_OUT_OF_ORDER);
    }
    if job.lease_owner.as_deref() != Some(lease.owner()) {
        return Some(crate::REASON_LEASE_OWNER_MISMATCH);
    }
    match job.lease_until {
        Some(until) if until <= now => Some(crate::REASON_LEASE_EXPIRED),
        None => Some(crate::REASON_LEASE_EXPIRED),
        _ => None,
    }
}

/// Whether a job is in a state that could accept a heartbeat at all.
#[must_use]
pub const fn accepts_heartbeat(state: JobState) -> bool {
    state.holds_lease()
}

#[cfg(test)]
mod tests {
    use super::{heartbeat, HeartbeatOutcome, MAX_HEARTBEAT_EXTENSION_MS};
    use crate::claim::{claim, ClaimOutcome, Lease};
    use crate::{JobKind, JobRecord, JobState};

    fn leased() -> (JobRecord, Lease) {
        let mut job = JobRecord::new("job-1", "sol-1", JobKind::ParseBatch, "p:a", 0, 3, 0);
        let lease = match claim(&mut job, "worker-a", 1_000, 30_000).expect("claim") {
            ClaimOutcome::Claimed(lease) => lease,
            ClaimOutcome::NotEligible { .. } => panic!("claim"),
        };
        (job, lease)
    }

    #[test]
    fn the_current_owner_renews_within_bounds() {
        let (mut job, lease) = leased();
        let before = job.lease_until.expect("deadline");
        let outcome = heartbeat(&mut job, &lease, 2_000, 10_000).expect("renew");
        assert_eq!(
            outcome,
            HeartbeatOutcome::Renewed {
                lease_until: before + 10_000
            }
        );
        assert!(outcome.renewed());
        assert_eq!(job.state, JobState::Leased);
    }

    #[test]
    fn an_over_long_extension_is_clamped() {
        let (mut job, lease) = leased();
        let before = job.lease_until.expect("deadline");
        let outcome = heartbeat(&mut job, &lease, 2_000, i64::MAX).expect("renew");
        assert_eq!(
            outcome,
            HeartbeatOutcome::Renewed {
                lease_until: before + MAX_HEARTBEAT_EXTENSION_MS
            }
        );
        // Repeated renewals can never exceed the absolute lease ceiling.
        let mut now = 2_000;
        for _ in 0..50 {
            heartbeat(&mut job, &lease, now, MAX_HEARTBEAT_EXTENSION_MS).expect("renew");
            now += 1_000;
        }
        assert!(job.lease_until.expect("deadline") <= now + crate::claim::MAX_LEASE_MS);
    }

    #[test]
    fn a_mismatched_owner_cannot_extend_the_lease() {
        let (mut job, lease) = leased();
        let before = job.clone();
        let foreign = Lease::restore("job-1", lease.fence(), "worker-b", lease.lease_until());
        let outcome = heartbeat(&mut job, &foreign, 2_000, 10_000).expect("decision");
        assert_eq!(
            outcome,
            HeartbeatOutcome::Refused {
                reason: crate::REASON_LEASE_OWNER_MISMATCH
            }
        );
        assert_eq!(job, before, "a refused heartbeat is a no-op");
    }

    #[test]
    fn an_expired_or_stale_lease_cannot_be_extended() {
        let (mut job, lease) = leased();
        let outcome = heartbeat(&mut job, &lease, lease.lease_until(), 10_000).expect("decision");
        assert_eq!(
            outcome,
            HeartbeatOutcome::Refused {
                reason: crate::REASON_LEASE_EXPIRED
            }
        );

        let mut newer = job.clone();
        newer.fence = lease.fence() + 1;
        let outcome = heartbeat(&mut newer, &lease, 2_000, 10_000).expect("decision");
        assert_eq!(
            outcome,
            HeartbeatOutcome::Refused {
                reason: crate::REASON_STALE_FENCE
            }
        );
    }

    #[test]
    fn a_terminal_job_refuses_every_heartbeat() {
        let (mut job, lease) = leased();
        job.state = JobState::Cancelled;
        job.release_lease();
        let before = job.clone();
        let outcome = heartbeat(&mut job, &lease, 2_000, 10_000).expect("decision");
        assert_eq!(
            outcome,
            HeartbeatOutcome::Refused {
                reason: crate::REASON_TERMINAL_STATE
            }
        );
        assert_eq!(job, before);
    }

    #[test]
    fn a_pending_job_has_no_lease_to_renew() {
        let mut job = JobRecord::new("job-1", "sol-1", JobKind::ParseBatch, "p:a", 0, 3, 0);
        let lease = Lease::restore("job-1", 0, "worker-a", 30_000);
        let outcome = heartbeat(&mut job, &lease, 1, 10).expect("decision");
        assert_eq!(
            outcome,
            HeartbeatOutcome::Refused {
                reason: crate::REASON_NOT_ELIGIBLE
            }
        );
    }

    #[test]
    fn accepts_heartbeat_tracks_the_lease_holding_states() {
        for state in JobState::all() {
            assert_eq!(super::accepts_heartbeat(*state), state.holds_lease());
        }
    }

    #[test]
    fn a_negative_extension_is_a_validation_error() {
        let (mut job, lease) = leased();
        assert!(heartbeat(&mut job, &lease, 2_000, -1).is_err());
    }
}
