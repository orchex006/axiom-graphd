//! Cooperative shutdown and cancellation (task B-006).
//!
//! Shutdown is a *state transition owned by one token*, not a flag scattered
//! through worker threads. The contract from docs/13-SQLite section 10 is:
//!
//! 1. stop claiming new work,
//! 2. allow a bounded grace period for in-flight work,
//! 3. flush dirty state and the publication outbox,
//! 4. close connections.
//!
//! [`ShutdownToken`] owns steps 1 and 2. A worker that must not outlive the
//! deadline holds a [`ClaimGuard`]: claiming after shutdown was requested fails
//! with [`ErrorCode::ShuttingDown`] (exit code `4`, "not ready/stale"), and the
//! daemon can observe how many claims are still in flight before it flushes.
//!
//! Requesting shutdown twice is idempotent and returns the *same* deadline, so a
//! second signal, a control request and an internal failure all produce one
//! consistent grace period instead of extending it.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use graph_core::error::{AxiomError, ErrorCode, ExitCode};

/// Default bounded grace period: 90 seconds.
pub const DEFAULT_SHUTDOWN_DEADLINE_MS: u64 = 90_000;

/// Result of asking the token to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownRequest {
    /// This call started the shutdown.
    Requested {
        /// Grace period granted to in-flight work.
        deadline: Duration,
    },
    /// Shutdown had already been requested; the deadline is unchanged.
    AlreadyRequested {
        /// The deadline granted by the first request.
        deadline: Duration,
    },
}

impl ShutdownRequest {
    /// Grace period in effect.
    #[must_use]
    pub const fn deadline(self) -> Duration {
        match self {
            Self::Requested { deadline } | Self::AlreadyRequested { deadline } => deadline,
        }
    }

    /// True when this call was the first request.
    #[must_use]
    pub const fn is_first(self) -> bool {
        matches!(self, Self::Requested { .. })
    }
}

/// How much of the grace period remains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainState {
    /// Shutdown has not been requested; work may still be claimed.
    Running,
    /// Shutdown was requested and in-flight work is still draining.
    Draining {
        /// Claims not yet released.
        in_flight: usize,
        /// Time left before the deadline.
        remaining: Duration,
    },
    /// In-flight work finished inside the grace period.
    Drained,
    /// The grace period expired with work still in flight.
    DeadlineExpired {
        /// Claims still outstanding when the deadline expired.
        in_flight: usize,
    },
}

#[derive(Debug, Default)]
struct State {
    requested_at: Option<Instant>,
    deadline: Duration,
    in_flight: usize,
}

/// Cloneable shutdown and cancellation token.
#[derive(Debug, Clone)]
pub struct ShutdownToken {
    state: Arc<Mutex<State>>,
}

impl Default for ShutdownToken {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownToken {
    /// A token with the default 90 s grace period.
    #[must_use]
    pub fn new() -> Self {
        Self::generate(Duration::from_millis(DEFAULT_SHUTDOWN_DEADLINE_MS))
    }

    /// A token with an explicit grace period.
    ///
    /// A zero deadline is legal and means "stop immediately after in-flight work
    /// reaches a safe point"; it is not treated as "no deadline".
    #[must_use]
    pub fn generate(deadline: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                requested_at: None,
                deadline,
                in_flight: 0,
            })),
        }
    }

    /// Grace period configured for this token.
    #[must_use]
    pub fn deadline(&self) -> Duration {
        self.lock().deadline
    }

    /// True once shutdown has been requested.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.lock().requested_at.is_some()
    }

    /// Request shutdown. Idempotent.
    pub fn request_shutdown(&self) -> ShutdownRequest {
        self.request_shutdown_at(Instant::now())
    }

    /// Request shutdown against an explicit clock (test seam).
    pub fn request_shutdown_at(&self, now: Instant) -> ShutdownRequest {
        let mut state = self.lock();
        match state.requested_at {
            Some(_) => ShutdownRequest::AlreadyRequested {
                deadline: state.deadline,
            },
            None => {
                state.requested_at = Some(now);
                ShutdownRequest::Requested {
                    deadline: state.deadline,
                }
            }
        }
    }

    /// Claim the right to perform work.
    ///
    /// # Errors
    /// Returns [`ErrorCode::ShuttingDown`] once shutdown was requested. The
    /// caller must not start new analysis, reconciliation or publication.
    pub fn claim(&self) -> Result<ClaimGuard, AxiomError> {
        let mut state = self.lock();
        if state.requested_at.is_some() {
            return Err(AxiomError::new(
                ErrorCode::ShuttingDown,
                "the daemon is shutting down and no longer accepts new work",
            )
            .with_detail("component", "axiom-graphd"));
        }
        state.in_flight += 1;
        Ok(ClaimGuard {
            token: self.clone(),
            released: false,
        })
    }

    /// Number of claims currently held.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.lock().in_flight
    }

    /// Observe drain progress against an explicit clock.
    #[must_use]
    pub fn drain_state(&self, now: Instant) -> DrainState {
        let state = self.lock();
        let Some(requested_at) = state.requested_at else {
            return DrainState::Running;
        };
        if state.in_flight == 0 {
            return DrainState::Drained;
        }
        let elapsed = now.saturating_duration_since(requested_at);
        if elapsed >= state.deadline {
            return DrainState::DeadlineExpired {
                in_flight: state.in_flight,
            };
        }
        DrainState::Draining {
            in_flight: state.in_flight,
            remaining: state.deadline.saturating_sub(elapsed),
        }
    }

    /// True when the grace period has elapsed with work still in flight.
    #[must_use]
    pub fn deadline_expired(&self, now: Instant) -> bool {
        matches!(self.drain_state(now), DrainState::DeadlineExpired { .. })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A panic while holding the token must not wedge shutdown, so a poisoned
        // lock is taken rather than propagated.
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }
}

/// A single in-flight claim. Dropping it releases the claim.
#[derive(Debug)]
pub struct ClaimGuard {
    token: ShutdownToken,
    released: bool,
}

impl ClaimGuard {
    /// Release the claim before the guard is dropped.
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let mut state = self.token.lock();
        state.in_flight = state.in_flight.saturating_sub(1);
    }
}

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        self.release_inner();
    }
}

/// Process exit code used when shutdown refuses work.
pub const SHUTDOWN_EXIT_CODE: ExitCode = ExitCode::NotReady;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_grace_period_is_ninety_seconds() {
        let token = ShutdownToken::new();
        assert_eq!(token.deadline(), Duration::from_millis(90_000));
        assert!(!token.is_shutting_down());
        assert_eq!(token.in_flight(), 0);
    }

    #[test]
    fn generate_overrides_the_grace_period() {
        let token = ShutdownToken::generate(Duration::from_millis(5));
        assert_eq!(token.deadline(), Duration::from_millis(5));
    }

    #[test]
    fn shutdown_is_idempotent_and_keeps_the_first_deadline() {
        let token = ShutdownToken::generate(Duration::from_millis(1_000));
        let base = Instant::now();
        let first = token.request_shutdown_at(base);
        assert!(first.is_first());
        assert_eq!(first.deadline(), Duration::from_millis(1_000));
        // A later request must not extend or restart the grace period.
        let second = token.request_shutdown_at(base + Duration::from_millis(900));
        assert!(!second.is_first());
        assert_eq!(second.deadline(), Duration::from_millis(1_000));
        assert!(matches!(second, ShutdownRequest::AlreadyRequested { .. }));
        assert!(token.is_shutting_down());
    }

    #[test]
    fn new_claims_are_rejected_after_shutdown() {
        let token = ShutdownToken::new();
        let claim = token.claim().expect("claims are allowed before shutdown");
        assert_eq!(token.in_flight(), 1);
        token.request_shutdown();
        let error = token.claim().expect_err("claims must be refused");
        assert_eq!(error.code(), ErrorCode::ShuttingDown);
        assert_eq!(error.exit_code(), SHUTDOWN_EXIT_CODE);
        assert_eq!(error.exit_code().as_i32(), 4);
        drop(claim);
        assert_eq!(token.in_flight(), 0);
    }

    #[test]
    fn drain_reports_progress_and_deadline_expiry() {
        let token = ShutdownToken::generate(Duration::from_millis(200));
        let base = Instant::now();
        assert_eq!(token.drain_state(base), DrainState::Running);
        token.request_shutdown_at(base);
        assert_eq!(token.drain_state(base), DrainState::Drained);

        let claim = token.claim_in_flight_for_test();
        assert_eq!(
            token.drain_state(base + Duration::from_millis(50)),
            DrainState::Draining {
                in_flight: 1,
                remaining: Duration::from_millis(150),
            }
        );
        assert!(token.deadline_expired(base + Duration::from_millis(200)));
        assert_eq!(
            token.drain_state(base + Duration::from_millis(500)),
            DrainState::DeadlineExpired { in_flight: 1 }
        );
        drop(claim);
        assert_eq!(
            token.drain_state(base + Duration::from_millis(500)),
            DrainState::Drained
        );
    }

    #[test]
    fn explicit_release_is_equivalent_to_drop() {
        let token = ShutdownToken::new();
        let claim = token.claim().expect("claim");
        claim.release();
        assert_eq!(token.in_flight(), 0);
    }

    #[test]
    fn clone_shares_one_state() {
        let token = ShutdownToken::new();
        let clone = token.clone();
        clone.request_shutdown();
        assert!(token.is_shutting_down());
        assert!(clone.is_shutting_down());
    }

    impl ShutdownToken {
        /// Test-only helper: a claim that survives shutdown, to model work that
        /// was already in flight when the signal arrived.
        fn claim_in_flight_for_test(&self) -> ClaimGuard {
            {
                let mut state = self.lock();
                state.in_flight += 1;
            }
            ClaimGuard {
                token: self.clone(),
                released: false,
            }
        }
    }
}
