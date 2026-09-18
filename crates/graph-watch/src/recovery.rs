//! Full rescan after overflow, reconnect or branch change (task B-029).
//!
//! A native backend can lose events: the kernel queue overflows while the
//! process is busy, the backend disconnects and reconnects, or the user switches
//! branch so the working tree is replaced wholesale. None of those conditions
//! can be repaired by replaying the events that were delivered, because the
//! interesting events are exactly the ones that were not. The only correct
//! response is to persist `full_scan_required` and let a real inventory scan
//! establish the truth (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 9).
//!
//! The flag is sticky: it is cleared only by an explicit acknowledgement from a
//! completed scan, never by the arrival of further hints.

use crate::normalize::{normalize, NormalizedHint, RawHint};
use graph_core::error::AxiomError;

/// Why a complete rescan is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FullScanReason {
    /// The backend dropped events faster than they were drained.
    Overflow,
    /// The backend lost its connection and recovered it.
    Reconnect,
    /// The Git worktree head or branch changed.
    BranchChange,
    /// The configured backend changed (native to polling or back).
    BackendSwitch,
    /// The debounce or hint buffer exceeded its bound.
    BufferOverflow,
}

impl FullScanReason {
    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Overflow => "backend_overflow",
            Self::Reconnect => "backend_reconnect",
            Self::BranchChange => "branch_change",
            Self::BackendSwitch => "backend_switch",
            Self::BufferOverflow => "buffer_overflow",
        }
    }
}

/// One event delivered by a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendEvent {
    /// A flush of raw hints.
    Hints(Vec<RawHint>),
    /// The backend reports that it dropped `dropped` events.
    Overflow {
        /// Number of lost events, when the backend can estimate it.
        dropped: u64,
    },
    /// The backend connection was lost.
    Disconnected,
    /// The backend connection was re-established.
    Reconnected,
    /// The observed worktree epoch moved to a new value.
    BranchChanged {
        /// New epoch identifier.
        epoch: String,
    },
    /// The configured backend changed.
    BackendSwitched,
}

/// What the caller may do with one backend event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryDecision {
    /// Apply these normalized hints; the hint stream is trustworthy.
    Apply(Vec<NormalizedHint>),
    /// Do not act on hints; run a complete inventory first.
    FullScan(FullScanReason),
}

impl RecoveryDecision {
    /// Whether the decision requires a complete inventory scan.
    #[must_use]
    pub const fn requires_full_scan(&self) -> bool {
        matches!(self, Self::FullScan(_))
    }
}

/// Sticky recovery state of one project.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryState {
    full_scan_required: Option<FullScanReason>,
    epoch: Option<String>,
}

impl RecoveryState {
    /// A clean state with no rescan outstanding.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            full_scan_required: None,
            epoch: None,
        }
    }

    /// Whether a complete inventory is still required.
    #[must_use]
    pub const fn requires_full_scan(&self) -> bool {
        self.full_scan_required.is_some()
    }

    /// Reason of the outstanding rescan.
    #[must_use]
    pub const fn reason(&self) -> Option<FullScanReason> {
        self.full_scan_required
    }

    /// Current worktree epoch, when one was observed.
    #[must_use]
    pub fn epoch(&self) -> Option<&str> {
        self.epoch.as_deref()
    }

    /// Persist the rescan requirement without losing a stronger earlier reason.
    pub fn require_full_scan(&mut self, reason: FullScanReason) -> FullScanReason {
        match self.full_scan_required {
            Some(existing) => existing,
            None => {
                self.full_scan_required = Some(reason);
                reason
            }
        }
    }

    /// Confirm that a complete inventory scan finished successfully.
    pub fn acknowledge_scan(&mut self) {
        self.full_scan_required = None;
    }

    /// Record the observed worktree epoch, reporting a branch change.
    ///
    /// A first observation is not a change: the epoch is simply recorded.
    pub fn observe_epoch(&mut self, epoch: &str) -> bool {
        match &self.epoch {
            Some(previous) if previous == epoch => false,
            Some(_) => {
                self.epoch = Some(epoch.to_string());
                true
            }
            None => {
                self.epoch = Some(epoch.to_string());
                false
            }
        }
    }

    /// Absorb one backend event and decide what may be applied.
    ///
    /// # Errors
    /// Propagates [`normalize`] path validation failures.
    pub fn absorb(&mut self, event: BackendEvent) -> Result<RecoveryDecision, AxiomError> {
        match event {
            BackendEvent::Hints(hints) => {
                let normalized = normalize(&hints)?;
                match self.full_scan_required {
                    Some(existing) => Ok(RecoveryDecision::FullScan(existing)),
                    None => Ok(RecoveryDecision::Apply(normalized.hints().to_vec())),
                }
            }
            BackendEvent::Overflow { .. } => Ok(RecoveryDecision::FullScan(
                self.require_full_scan(FullScanReason::Overflow),
            )),
            BackendEvent::Disconnected => Ok(RecoveryDecision::FullScan(
                self.require_full_scan(FullScanReason::Reconnect),
            )),
            BackendEvent::Reconnected => Ok(RecoveryDecision::FullScan(
                self.require_full_scan(FullScanReason::Reconnect),
            )),
            BackendEvent::BackendSwitched => Ok(RecoveryDecision::FullScan(
                self.require_full_scan(FullScanReason::BackendSwitch),
            )),
            BackendEvent::BranchChanged { epoch } => {
                self.observe_epoch(&epoch);
                Ok(RecoveryDecision::FullScan(
                    self.require_full_scan(FullScanReason::BranchChange),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BackendEvent, FullScanReason, RecoveryDecision, RecoveryState};
    use crate::normalize::{FileAction, RawHint, RawKind};

    #[test]
    fn lost_events_persist_a_rescan_that_hints_cannot_clear() {
        let mut state = RecoveryState::new();
        let decision = state
            .absorb(BackendEvent::Overflow { dropped: 12 })
            .expect("absorbed");
        assert_eq!(
            decision,
            RecoveryDecision::FullScan(FullScanReason::Overflow)
        );
        assert!(state.requires_full_scan());

        let later = state
            .absorb(BackendEvent::Hints(vec![RawHint::new(
                "src/App.cs",
                RawKind::Modified,
            )]))
            .expect("absorbed");
        assert_eq!(
            later,
            RecoveryDecision::FullScan(FullScanReason::Overflow),
            "hints must not be applied while a rescan is outstanding"
        );
        assert_eq!(
            state.reason(),
            Some(FullScanReason::Overflow),
            "the first, strongest reason is preserved"
        );

        state.acknowledge_scan();
        assert!(!state.requires_full_scan());
        let decision = state
            .absorb(BackendEvent::Hints(vec![RawHint::new(
                "src/App.cs",
                RawKind::Modified,
            )]))
            .expect("absorbed");
        assert!(matches!(decision, RecoveryDecision::Apply(_)));
        if let RecoveryDecision::Apply(hints) = decision {
            assert_eq!(hints.len(), 1);
            assert_eq!(hints[0].action(), FileAction::Upsert);
        }
    }

    #[test]
    fn reconnect_and_branch_change_require_the_same_treatment() {
        let mut state = RecoveryState::new();
        assert!(
            !state.observe_epoch("head-a"),
            "the first epoch is not a change"
        );
        assert!(state
            .absorb(BackendEvent::Disconnected)
            .expect("absorbed")
            .requires_full_scan());
        state.acknowledge_scan();
        assert!(
            state.observe_epoch("head-b"),
            "a different epoch is a change"
        );
        assert_eq!(
            state
                .absorb(BackendEvent::BranchChanged {
                    epoch: "head-b".to_string(),
                })
                .expect("absorbed"),
            RecoveryDecision::FullScan(FullScanReason::BranchChange)
        );
        assert_eq!(state.epoch(), Some("head-b"));
        assert_eq!(FullScanReason::BackendSwitch.as_str(), "backend_switch");
    }

    #[test]
    fn an_overflow_reason_is_not_downgraded_and_hints_remain_validated() {
        let mut state = RecoveryState::new();
        state
            .absorb(BackendEvent::BackendSwitched)
            .expect("absorbed");
        let reason = state.require_full_scan(FullScanReason::Overflow);
        assert_eq!(
            reason,
            FullScanReason::BackendSwitch,
            "a weaker later reason must not replace the persisted one"
        );
        let error = state
            .absorb(BackendEvent::Hints(vec![RawHint::new(
                "C:/outside/App.cs",
                RawKind::Modified,
            )]))
            .expect_err("an invalid path is still refused");
        assert_eq!(error.code(), graph_core::error::ErrorCode::ValidationError);
    }
}
