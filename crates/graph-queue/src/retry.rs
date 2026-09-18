//! Classified transient retry with bounded backoff (task B-039).
//!
//! `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 6 separates two very
//! different failures:
//!
//! * a transient I/O or lock failure is retried at most five times with an
//!   exponential backoff that starts at 250 ms, is capped at 10 s and carries
//!   jitter so a fleet of workers does not retry in lockstep; and
//! * a parse failure or an unsupported syntax is *not* retried until the input
//!   changes, because retrying identical bytes produces the identical diagnostic.
//!
//! Retrying an unsupported construct forever would spin the queue and never
//! converge, so [`RetryDecision::GiveUp`] records that a new input is required.
//! The backoff is deterministic given the jitter seed, so a schedule can be
//! replayed exactly in a test.

use graph_core::error::ErrorCode;

/// Attempts allowed for a transient failure, counting the first failure.
pub const MAX_TRANSIENT_ATTEMPTS: u32 = 5;
/// First backoff delay.
pub const BASE_BACKOFF_MS: u64 = 250;
/// Ceiling for any single backoff delay.
pub const MAX_BACKOFF_MS: u64 = 10_000;
/// Maximum jitter added to a delay.
pub const MAX_JITTER_MS: u64 = 250;

/// Why a job failed, at the granularity that decides whether to retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailureClass {
    /// A transient I/O failure: the same input may succeed later.
    TransientIo,
    /// A transient lock or busy condition: the same input may succeed later.
    TransientLock,
    /// Syntax this build does not support: retrying identical input cannot help.
    UnsupportedSyntax,
    /// A non-retryable failure, including an Axiom internal defect.
    Permanent,
}

impl FailureClass {
    /// Whether a retry of the identical input could succeed.
    #[must_use]
    pub const fn is_transient(self) -> bool {
        matches!(self, Self::TransientIo | Self::TransientLock)
    }

    /// Whether the only way forward is a new or changed input.
    #[must_use]
    pub const fn needs_new_input(self) -> bool {
        matches!(self, Self::UnsupportedSyntax)
    }

    /// Stable reason code recorded on the job.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::TransientIo => "transient_io",
            Self::TransientLock => "transient_lock",
            Self::UnsupportedSyntax => "unsupported_syntax",
            Self::Permanent => "permanent",
        }
    }
}

/// Classify a stable Axiom error code.
#[must_use]
pub const fn classify_error_code(code: ErrorCode) -> FailureClass {
    match code {
        ErrorCode::NotReady
        | ErrorCode::RateLimited
        | ErrorCode::Conflict
        | ErrorCode::WorktreeBusy
        | ErrorCode::ShuttingDown => FailureClass::TransientLock,
        ErrorCode::Internal => FailureClass::Permanent,
        ErrorCode::ValidationError
        | ErrorCode::Unauthenticated
        | ErrorCode::Forbidden
        | ErrorCode::NotFound
        | ErrorCode::IncompatibleInput
        | ErrorCode::WriterAlreadyRunning
        | ErrorCode::MigrationChecksumMismatch
        | ErrorCode::MigrationOrderConflict
        | ErrorCode::SchemaNewerThanBinary
        | ErrorCode::SqliteUnsupportedVersion
        | ErrorCode::SqliteNetworkStorageUnsupported
        | ErrorCode::UnsafeHomePath
        | ErrorCode::UnsafePortablePath
        | ErrorCode::ConfigInvalid => FailureClass::Permanent,
    }
}

/// Backoff curve for a transient failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    base_ms: u64,
    cap_ms: u64,
    jitter_ms: u64,
}

impl BackoffPolicy {
    /// A policy whose curve is clamped to the documented defaults.
    #[must_use]
    pub const fn new(base_ms: u64, cap_ms: u64, jitter_ms: u64) -> Self {
        Self {
            base_ms: if base_ms < 1 {
                BASE_BACKOFF_MS
            } else if base_ms > MAX_BACKOFF_MS {
                MAX_BACKOFF_MS
            } else {
                base_ms
            },
            cap_ms: if cap_ms < 1 || cap_ms > MAX_BACKOFF_MS {
                MAX_BACKOFF_MS
            } else {
                cap_ms
            },
            jitter_ms: if jitter_ms > MAX_JITTER_MS {
                MAX_JITTER_MS
            } else {
                jitter_ms
            },
        }
    }

    /// The documented default curve: 250 ms doubling to a 10 s cap plus jitter.
    #[must_use]
    pub const fn documented_default() -> Self {
        Self::new(BASE_BACKOFF_MS, MAX_BACKOFF_MS, MAX_JITTER_MS)
    }

    /// Ceiling for any single delay.
    #[must_use]
    pub const fn cap_ms(&self) -> u64 {
        self.cap_ms
    }

    /// The exponential delay for a 1-based attempt, before jitter.
    #[must_use]
    pub const fn exponential_ms(&self, attempt: u32) -> u64 {
        if attempt < 1 {
            return if self.base_ms < self.cap_ms {
                self.base_ms
            } else {
                self.cap_ms
            };
        }
        let shift = if attempt > 32 { 32 } else { attempt - 1 };
        let scaled = (self.base_ms as u128) << shift;
        if scaled > self.cap_ms as u128 {
            self.cap_ms
        } else {
            scaled as u64
        }
    }

    /// The delay for an attempt, including deterministic jitter.
    #[must_use]
    pub const fn delay_ms(&self, attempt: u32, jitter_seed: u64) -> u64 {
        let exponential = self.exponential_ms(attempt);
        let base = if exponential < self.cap_ms {
            exponential
        } else {
            self.cap_ms
        };
        if self.jitter_ms == 0 {
            return base;
        }
        let jitter = noise(jitter_seed) % (self.jitter_ms + 1);
        base.saturating_add(jitter)
    }
}

/// A small deterministic mixer, so the same seed always yields the same jitter.
const fn noise(seed: u64) -> u64 {
    let mut x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 29;
    x
}

/// What the scheduler must do with a classified failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Requeue the same target after `delay_ms`.
    Retry {
        /// Delay before the job becomes eligible again.
        delay_ms: u64,
        /// The attempt that just failed.
        attempt: u32,
    },
    /// Stop retrying.
    GiveUp {
        /// Stable reason code.
        reason: &'static str,
        /// Whether only new or changed input can make the job runnable again.
        needs_new_input: bool,
    },
}

impl RetryDecision {
    /// Whether the job is requeued.
    #[must_use]
    pub const fn is_retry(&self) -> bool {
        matches!(self, Self::Retry { .. })
    }

    /// The delay, if the job is requeued.
    #[must_use]
    pub const fn delay_ms(&self) -> Option<u64> {
        match self {
            Self::Retry { delay_ms, .. } => Some(*delay_ms),
            Self::GiveUp { .. } => None,
        }
    }
}

/// Decide what to do after attempt number `attempt` failed with `class`.
#[must_use]
pub fn decide(
    class: FailureClass,
    attempt: u32,
    policy: &BackoffPolicy,
    jitter_seed: u64,
) -> RetryDecision {
    if !class.is_transient() {
        return RetryDecision::GiveUp {
            reason: class.reason(),
            needs_new_input: class.needs_new_input(),
        };
    }
    if attempt == 0 || attempt >= MAX_TRANSIENT_ATTEMPTS {
        return RetryDecision::GiveUp {
            reason: class.reason(),
            needs_new_input: false,
        };
    }
    RetryDecision::Retry {
        delay_ms: policy.delay_ms(attempt, jitter_seed),
        attempt,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_error_code, decide, BackoffPolicy, FailureClass, RetryDecision, BASE_BACKOFF_MS,
        MAX_BACKOFF_MS, MAX_TRANSIENT_ATTEMPTS,
    };
    use graph_core::error::ErrorCode;

    #[test]
    fn transient_io_gets_a_bounded_exponential_backoff() {
        let policy = BackoffPolicy::documented_default();
        let mut previous = 0;
        for attempt in 1..MAX_TRANSIENT_ATTEMPTS {
            let decision = decide(FailureClass::TransientIo, attempt, &policy, 7);
            assert!(decision.is_retry(), "attempt {attempt} must retry");
            let delay = decision.delay_ms().expect("delay");
            assert!(delay >= previous, "the curve must not shrink");
            assert!(delay <= MAX_BACKOFF_MS + super::MAX_JITTER_MS);
            previous = delay;
        }
        assert_eq!(policy.exponential_ms(1), BASE_BACKOFF_MS);
        assert_eq!(policy.exponential_ms(2), 500);
        assert_eq!(policy.exponential_ms(3), 1_000);
        assert_eq!(policy.exponential_ms(30), MAX_BACKOFF_MS);
    }

    #[test]
    fn the_backoff_cap_is_enforced_for_any_attempt_count() {
        let policy = BackoffPolicy::new(250, 10_000, 0);
        assert_eq!(policy.exponential_ms(u32::MAX), MAX_BACKOFF_MS);
        assert_eq!(policy.cap_ms(), MAX_BACKOFF_MS);
    }

    #[test]
    fn a_transient_failure_gives_up_after_the_attempt_budget() {
        let policy = BackoffPolicy::documented_default();
        let decision = decide(
            FailureClass::TransientIo,
            MAX_TRANSIENT_ATTEMPTS,
            &policy,
            3,
        );
        assert_eq!(
            decision,
            RetryDecision::GiveUp {
                reason: "transient_io",
                needs_new_input: false
            }
        );
        assert!(decide(FailureClass::TransientLock, 0, &policy, 3)
            .delay_ms()
            .is_none());
    }

    #[test]
    fn unsupported_syntax_is_never_retried_without_new_input() {
        let policy = BackoffPolicy::documented_default();
        for attempt in 1..50 {
            let decision = decide(
                FailureClass::UnsupportedSyntax,
                attempt,
                &policy,
                attempt as u64,
            );
            assert_eq!(
                decision,
                RetryDecision::GiveUp {
                    reason: "unsupported_syntax",
                    needs_new_input: true
                },
                "attempt {attempt}"
            );
            assert!(!decision.is_retry());
        }
    }

    #[test]
    fn a_permanent_failure_gives_up_immediately() {
        let policy = BackoffPolicy::documented_default();
        for attempt in 1..5 {
            let decision = decide(FailureClass::Permanent, attempt, &policy, 1);
            assert_eq!(
                decision,
                RetryDecision::GiveUp {
                    reason: "permanent",
                    needs_new_input: false
                }
            );
        }
    }

    #[test]
    fn jitter_is_deterministic_for_a_seed_and_bounded() {
        let policy = BackoffPolicy::new(250, 10_000, 100);
        let a = policy.delay_ms(1, 42);
        let b = policy.delay_ms(1, 42);
        assert_eq!(a, b);
        assert!(a >= 250);
        assert!(a <= 350);
        let c = policy.delay_ms(1, 43);
        assert!((250..=350).contains(&c));
    }

    #[test]
    fn error_codes_map_to_the_right_class() {
        assert_eq!(
            classify_error_code(ErrorCode::NotReady),
            FailureClass::TransientLock
        );
        assert_eq!(
            classify_error_code(ErrorCode::Conflict),
            FailureClass::TransientLock
        );
        assert_eq!(
            classify_error_code(ErrorCode::ValidationError),
            FailureClass::Permanent
        );
        assert_eq!(
            classify_error_code(ErrorCode::Internal),
            FailureClass::Permanent
        );
        assert!(FailureClass::UnsupportedSyntax.needs_new_input());
        assert!(!FailureClass::TransientIo.needs_new_input());
        assert!(FailureClass::TransientLock.is_transient());
        assert!(!FailureClass::Permanent.is_transient());
    }

    #[test]
    fn a_zero_jitter_policy_is_exactly_exponential() {
        let policy = BackoffPolicy::new(250, 10_000, 0);
        assert_eq!(policy.delay_ms(1, 999), 250);
        assert_eq!(policy.delay_ms(4, 999), 2_000);
    }
}
