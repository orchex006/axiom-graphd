//! Queue high-water handling without silent state loss (task B-042).
//!
//! `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 6 sets a high-water mark
//! of 10,000 distinct dirty paths. Above it the queue must not keep growing one
//! entry per path: it persists the `solutions.full_scan_required` intent and
//! coalesces the in-memory hint set, because a full inventory scan discovers
//! every path anyway.
//!
//! The important guarantee is that this is *not* a silent drop. When the mark is
//! crossed, [`DirtyPressure::note`] reports
//! [`PressureDecision::HighWater`] with the persisted intent, the overflow is
//! counted, and the caller must record that a full scan is required before the
//! hint set is cleared. Only [`DirtyPressure::acknowledge_full_scan`] may clear
//! the intent, and it does so after the scan has been persisted.

use std::collections::BTreeSet;

/// Distinct dirty paths that trigger the full-scan intent.
pub const HIGH_WATER_DISTINCT_DIRTY_PATHS: usize = 10_000;

/// What one recorded hint did to the pressure tracker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PressureDecision {
    /// The hint was stored as a distinct path.
    Normal {
        /// Distinct paths currently held in memory.
        distinct: usize,
    },
    /// The high-water mark was crossed; a full scan is now required.
    HighWater {
        /// Always `true`: the full-scan intent was persisted before coalescing.
        persisted_full_scan: bool,
    },
    /// A full scan is already required, so this hint is subsumed by it.
    Coalesced,
}

impl PressureDecision {
    /// Whether memory was coalesced because a full scan supersedes the hint set.
    #[must_use]
    pub const fn coalesced(&self) -> bool {
        matches!(self, Self::HighWater { .. } | Self::Coalesced)
    }
}

/// A snapshot of the intents the tracker currently holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PressureBatch {
    /// Whether a full scan must run.
    pub full_scan_required: bool,
    /// Distinct paths held in memory, drained by [`DirtyPressure::take`].
    pub paths: Vec<String>,
    /// How many times the high-water mark has been crossed since the last
    /// acknowledgement.
    pub overflow_events: u64,
    /// How many hints have been observed in total.
    pub observed_hints: u64,
}

/// Bounded in-memory dirty-pressure tracker.
#[derive(Debug, Clone)]
pub struct DirtyPressure {
    high_water: usize,
    distinct: BTreeSet<String>,
    full_scan_required: bool,
    overflow_events: u64,
    observed_hints: u64,
}

impl DirtyPressure {
    /// A tracker with the documented high-water mark.
    #[must_use]
    pub fn documented_default() -> Self {
        Self::new(HIGH_WATER_DISTINCT_DIRTY_PATHS)
    }

    /// A tracker with an explicit high-water mark; `0` is treated as `1`.
    #[must_use]
    pub fn new(high_water: usize) -> Self {
        Self {
            high_water: if high_water < 1 { 1 } else { high_water },
            distinct: BTreeSet::new(),
            full_scan_required: false,
            overflow_events: 0,
            observed_hints: 0,
        }
    }

    /// The mark in force.
    #[must_use]
    pub const fn high_water(&self) -> usize {
        self.high_water
    }

    /// Distinct paths currently held in memory.
    #[must_use]
    pub fn distinct_len(&self) -> usize {
        self.distinct.len()
    }

    /// Whether a full scan must run.
    #[must_use]
    pub const fn full_scan_required(&self) -> bool {
        self.full_scan_required
    }

    /// Times the mark has been crossed since the last acknowledgement.
    #[must_use]
    pub const fn overflow_events(&self) -> u64 {
        self.overflow_events
    }

    /// Total hints observed.
    #[must_use]
    pub const fn observed_hints(&self) -> u64 {
        self.observed_hints
    }

    /// Whether the in-memory set is bounded by the high-water mark.
    #[must_use]
    pub fn memory_is_bounded(&self) -> bool {
        self.distinct.len() <= self.high_water
    }

    /// Whether every observed hint is either stored or covered by the intent.
    ///
    /// This is the property that makes coalescing honest: no hint is dropped
    /// without a persisted full scan that will rediscover its path.
    #[must_use]
    pub fn is_accounted_for(&self) -> bool {
        self.full_scan_required
            || self.distinct.len() as u64 == self.observed_hints
            || self.overflow_events == 0 && self.distinct.len() as u64 <= self.observed_hints
    }

    /// Record one dirty path.
    pub fn note(&mut self, portable_path: &str) -> PressureDecision {
        self.observed_hints = self.observed_hints.saturating_add(1);
        if self.full_scan_required {
            return PressureDecision::Coalesced;
        }
        self.distinct.insert(portable_path.to_string());
        if self.distinct.len() >= self.high_water {
            // Persist the intent first, then bound memory.
            self.full_scan_required = true;
            self.overflow_events = self.overflow_events.saturating_add(1);
            self.distinct.clear();
            return PressureDecision::HighWater {
                persisted_full_scan: true,
            };
        }
        PressureDecision::Normal {
            distinct: self.distinct.len(),
        }
    }

    /// Take the current intents, leaving the path set empty.
    ///
    /// The full-scan intent stays set until [`Self::acknowledge_full_scan`],
    /// because clearing it before the scan is persisted would lose the guarantee.
    pub fn take(&mut self) -> PressureBatch {
        PressureBatch {
            full_scan_required: self.full_scan_required,
            paths: core::mem::take(&mut self.distinct).into_iter().collect(),
            overflow_events: self.overflow_events,
            observed_hints: self.observed_hints,
        }
    }

    /// Record that the full scan has been persisted and scheduled.
    pub fn acknowledge_full_scan(&mut self) {
        self.full_scan_required = false;
        self.overflow_events = 0;
        self.observed_hints = 0;
        self.distinct.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{DirtyPressure, PressureDecision, HIGH_WATER_DISTINCT_DIRTY_PATHS};

    #[test]
    fn the_documented_mark_is_ten_thousand_distinct_paths() {
        assert_eq!(HIGH_WATER_DISTINCT_DIRTY_PATHS, 10_000);
        let tracker = DirtyPressure::documented_default();
        assert_eq!(tracker.high_water(), 10_000);
    }

    #[test]
    fn hints_below_the_mark_are_stored_distinctly() {
        let mut tracker = DirtyPressure::new(3);
        assert_eq!(tracker.note("a"), PressureDecision::Normal { distinct: 1 });
        assert_eq!(
            tracker.note("a"),
            PressureDecision::Normal { distinct: 1 },
            "a duplicate path is not a new distinct path"
        );
        assert_eq!(tracker.note("b"), PressureDecision::Normal { distinct: 2 });
        assert!(!tracker.full_scan_required());
        assert!(tracker.memory_is_bounded());
    }

    #[test]
    fn crossing_the_mark_persists_a_full_scan_and_bounds_memory() {
        let mut tracker = DirtyPressure::new(3);
        tracker.note("a");
        tracker.note("b");
        let decision = tracker.note("c");
        assert_eq!(
            decision,
            PressureDecision::HighWater {
                persisted_full_scan: true
            }
        );
        assert!(decision.coalesced());
        assert!(tracker.full_scan_required());
        assert_eq!(tracker.distinct_len(), 0, "memory is coalesced, not grown");
        assert!(tracker.memory_is_bounded());
        assert!(
            tracker.is_accounted_for(),
            "the full scan covers every hint"
        );
    }

    #[test]
    fn hints_after_the_mark_are_subsumed_not_dropped() {
        let mut tracker = DirtyPressure::new(2);
        tracker.note("a");
        tracker.note("b");
        assert_eq!(tracker.note("c"), PressureDecision::Coalesced);
        assert_eq!(tracker.note("d"), PressureDecision::Coalesced);
        assert!(tracker.full_scan_required());
        assert_eq!(tracker.distinct_len(), 0);
        let batch = tracker.take();
        assert!(batch.full_scan_required);
        assert!(batch.paths.is_empty());
        assert_eq!(batch.observed_hints, 4);
        assert_eq!(batch.overflow_events, 1);
    }

    #[test]
    fn taking_intents_does_not_clear_the_persisted_full_scan() {
        let mut tracker = DirtyPressure::new(1);
        tracker.note("a");
        let batch = tracker.take();
        assert!(batch.full_scan_required);
        assert!(tracker.full_scan_required());
        tracker.acknowledge_full_scan();
        assert!(!tracker.full_scan_required());
        assert_eq!(tracker.overflow_events(), 0);
        assert_eq!(tracker.observed_hints(), 0);
        // After the acknowledgement a fresh hint is stored normally again.
        assert_eq!(
            tracker.note("z"),
            PressureDecision::HighWater {
                persisted_full_scan: true
            }
        );
    }

    #[test]
    fn a_zero_mark_is_clamped_so_the_tracker_still_works() {
        let mut tracker = DirtyPressure::new(0);
        assert_eq!(tracker.high_water(), 1);
        assert!(matches!(
            tracker.note("a"),
            PressureDecision::HighWater { .. }
        ));
    }

    #[test]
    fn a_large_burst_stays_within_bounded_memory() {
        let mut tracker = DirtyPressure::new(100);
        for index in 0..5_000 {
            tracker.note(&format!("src/f{index}.cs"));
        }
        assert!(tracker.memory_is_bounded());
        assert!(tracker.distinct_len() <= 100);
        assert!(tracker.full_scan_required());
        assert!(tracker.is_accounted_for());
    }
}
