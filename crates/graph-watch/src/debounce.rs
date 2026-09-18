//! Debounce with a hard maximum wait (task B-026).
//!
//! An editor writes a file through a burst of events (write, rename, metadata,
//! adjacent temporary file). Reconciling each event separately would put the
//! same path in the queue many times. The debouncer therefore holds paths until
//! the burst goes quiet, but it never postpones reconciliation forever: once the
//! oldest pending path has waited `max_debounce_ms`, the batch is released even
//! though hints are still arriving
//! (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 6;
//! `graph_core::config::{DEFAULT_DEBOUNCE_MS, DEFAULT_MAX_DEBOUNCE_MS}`).
//!
//! Time is supplied by the caller as an [`Instant`] so the behaviour is
//! deterministic in tests and independent of a sleeping timer.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use crate::portable_relative_path;
use graph_core::error::{AxiomError, ErrorCode};

/// Upper bound on paths held by one debouncer.
///
/// A burst larger than this is a notification overflow, which recovery answers
/// with a full scan instead of an unbounded in-memory buffer.
pub const MAX_DEBOUNCED_PATHS: usize = 65_536;

/// Debounce bounds for one project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebouncePolicy {
    debounce: Duration,
    max_debounce: Duration,
}

impl Default for DebouncePolicy {
    fn default() -> Self {
        Self {
            debounce: Duration::from_millis(graph_core::config::DEFAULT_DEBOUNCE_MS),
            max_debounce: Duration::from_millis(graph_core::config::DEFAULT_MAX_DEBOUNCE_MS),
        }
    }
}

impl DebouncePolicy {
    /// Build a policy from the runtime configuration values.
    ///
    /// # Errors
    /// [`ErrorCode::ConfigInvalid`] when either bound is zero or the maximum wait
    /// is shorter than the quiet period.
    pub fn new(debounce_ms: u64, max_debounce_ms: u64) -> Result<Self, AxiomError> {
        if debounce_ms == 0 || max_debounce_ms == 0 {
            return Err(AxiomError::new(
                ErrorCode::ConfigInvalid,
                "debounce bounds must be positive",
            )
            .with_detail("debounce_ms", debounce_ms.to_string())
            .with_detail("max_debounce_ms", max_debounce_ms.to_string()));
        }
        if max_debounce_ms < debounce_ms {
            return Err(AxiomError::new(
                ErrorCode::ConfigInvalid,
                "the maximum debounce wait must not be shorter than the quiet period",
            )
            .with_detail("debounce_ms", debounce_ms.to_string())
            .with_detail("max_debounce_ms", max_debounce_ms.to_string()));
        }
        Ok(Self {
            debounce: Duration::from_millis(debounce_ms),
            max_debounce: Duration::from_millis(max_debounce_ms),
        })
    }

    /// Quiet period before a batch is released.
    #[must_use]
    pub const fn debounce(&self) -> Duration {
        self.debounce
    }

    /// Longest a path may stay pending.
    #[must_use]
    pub const fn max_debounce(&self) -> Duration {
        self.max_debounce
    }
}

/// Why a batch was released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushTrigger {
    /// The burst went quiet for the debounce period.
    QuietPeriod,
    /// The oldest pending path reached the maximum wait.
    MaximumWait,
}

/// One coalesced reconciliation batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebouncedBatch {
    paths: Vec<String>,
    trigger: FlushTrigger,
}

impl DebouncedBatch {
    /// Paths to reconcile, in stable sorted order and each appearing once.
    #[must_use]
    pub fn paths(&self) -> &[String] {
        &self.paths
    }

    /// Why the batch was released.
    #[must_use]
    pub const fn trigger(&self) -> FlushTrigger {
        self.trigger
    }
}

/// Per-project hint coalescer.
#[derive(Debug, Clone)]
pub struct Debouncer {
    policy: DebouncePolicy,
    pending: BTreeSet<String>,
    first_pending_at: Option<Instant>,
    last_hint_at: Option<Instant>,
}

impl Default for Debouncer {
    fn default() -> Self {
        Self::new(DebouncePolicy::default())
    }
}

impl Debouncer {
    /// Create an empty debouncer.
    #[must_use]
    pub fn new(policy: DebouncePolicy) -> Self {
        Self {
            policy,
            pending: BTreeSet::new(),
            first_pending_at: None,
            last_hint_at: None,
        }
    }

    /// Record a change to `path`.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] when the path is not portable or the
    /// pending set would exceed [`MAX_DEBOUNCED_PATHS`].
    pub fn note(&mut self, path: &str, now: Instant) -> Result<(), AxiomError> {
        let path = portable_relative_path(path)?;
        if !self.pending.contains(&path) && self.pending.len() >= MAX_DEBOUNCED_PATHS {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "debounce buffer exceeded its bound; a full scan is required",
            )
            .with_detail("limit", MAX_DEBOUNCED_PATHS.to_string()));
        }
        if self.pending.is_empty() {
            self.first_pending_at = Some(now);
        }
        self.pending.insert(path);
        self.last_hint_at = Some(now);
        Ok(())
    }

    /// Paths currently held.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Whether nothing is pending.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.pending.is_empty()
    }

    /// When the batch is due, or `None` when nothing is pending.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        if self.pending.is_empty() {
            return None;
        }
        let quiet = self.last_hint_at?.checked_add(self.policy.debounce)?;
        let maximum = self
            .first_pending_at?
            .checked_add(self.policy.max_debounce)?;
        Some(if quiet < maximum { quiet } else { maximum })
    }

    /// Release the batch when it is due, otherwise keep holding.
    #[must_use]
    pub fn take(&mut self, now: Instant) -> Option<DebouncedBatch> {
        let deadline = self.next_deadline()?;
        if now < deadline {
            return None;
        }
        let maximum = self
            .first_pending_at
            .and_then(|first| first.checked_add(self.policy.max_debounce));
        let trigger = match maximum {
            Some(maximum) if now >= maximum => FlushTrigger::MaximumWait,
            _ => FlushTrigger::QuietPeriod,
        };
        self.flush(trigger)
    }

    /// Release the batch regardless of the deadline.
    #[must_use]
    pub fn flush_now(&mut self) -> Option<DebouncedBatch> {
        self.flush(FlushTrigger::MaximumWait)
    }

    fn flush(&mut self, trigger: FlushTrigger) -> Option<DebouncedBatch> {
        if self.pending.is_empty() {
            return None;
        }
        let paths: Vec<String> = self.pending.iter().cloned().collect();
        self.pending.clear();
        self.first_pending_at = None;
        self.last_hint_at = None;
        Some(DebouncedBatch { paths, trigger })
    }
}

#[cfg(test)]
mod tests {
    use super::{DebouncePolicy, Debouncer, FlushTrigger, MAX_DEBOUNCED_PATHS};
    use graph_core::error::ErrorCode;
    use std::time::{Duration, Instant};

    #[test]
    fn repeated_saves_coalesce_into_one_batch() {
        let start = Instant::now();
        let policy = DebouncePolicy::new(750, 3000).expect("valid bounds");
        let mut debouncer = Debouncer::new(policy);
        debouncer.note("src/App.cs", start).expect("portable");
        debouncer
            .note("src/App.cs", start + Duration::from_millis(50))
            .expect("portable");
        debouncer
            .note("src/Other.cs", start + Duration::from_millis(60))
            .expect("portable");
        assert_eq!(debouncer.pending_count(), 2);

        assert!(
            debouncer.take(start + Duration::from_millis(700)).is_none(),
            "the quiet period has not elapsed"
        );
        let batch = debouncer
            .take(start + Duration::from_millis(900))
            .expect("due batch");
        assert_eq!(
            batch.paths(),
            vec!["src/App.cs".to_string(), "src/Other.cs".to_string()]
        );
        assert_eq!(batch.trigger(), FlushTrigger::QuietPeriod);
        assert!(debouncer.is_idle());
    }

    #[test]
    fn continuous_writes_cannot_postpone_reconciliation_forever() {
        let start = Instant::now();
        let policy = DebouncePolicy::new(750, 3000).expect("valid bounds");
        let mut debouncer = Debouncer::new(policy);
        for step in 0..12 {
            debouncer
                .note("src/Hot.cs", start + Duration::from_millis(step * 200))
                .expect("portable");
        }
        let now = start + Duration::from_millis(2500);
        assert!(
            debouncer.take(now).is_none(),
            "hints are still arriving inside the maximum wait"
        );
        let batch = debouncer
            .take(start + Duration::from_millis(3000))
            .expect("maximum wait forces the batch");
        assert_eq!(batch.trigger(), FlushTrigger::MaximumWait);
        assert_eq!(batch.paths(), vec!["src/Hot.cs".to_string()]);
    }

    #[test]
    fn invalid_bounds_and_non_portable_paths_are_refused() {
        assert_eq!(
            DebouncePolicy::new(0, 3000)
                .expect_err("zero quiet period")
                .code(),
            ErrorCode::ConfigInvalid
        );
        assert_eq!(
            DebouncePolicy::new(1500, 1000)
                .expect_err("maximum shorter than quiet period")
                .code(),
            ErrorCode::ConfigInvalid
        );
        let mut debouncer = Debouncer::default();
        assert_eq!(
            debouncer
                .note("../escape.cs", Instant::now())
                .expect_err("traversal refused")
                .code(),
            ErrorCode::ValidationError
        );
        assert_eq!(MAX_DEBOUNCED_PATHS, 65_536);
    }
}
