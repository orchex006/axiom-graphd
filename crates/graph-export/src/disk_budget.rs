//! Publication disk budgets (task B-081).
//!
//! The budget is a publication gate, not a deletion policy. When the retention
//! roots already exceed it, publication is deferred and reported with the exact
//! shortfall. This module deliberately exposes no delete operation, so no code
//! path here can remove active data to make room.

use crate::{ExportError, Result};
use std::path::Path;

/// Reason recorded when the retention roots exceed the budget.
pub const REASON_RETENTION_EXCEEDS_BUDGET: &str =
    "publication-deferred-retention-roots-exceed-budget";

/// A publication budget in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskBudget {
    /// Hard ceiling for the retention roots.
    pub max_bytes: u64,
    /// Space kept free for readers and the database.
    pub headroom_bytes: u64,
}

impl DiskBudget {
    /// A budget with no headroom.
    #[must_use]
    pub const fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            headroom_bytes: 0,
        }
    }

    /// Bytes publication may use before the headroom is consumed.
    #[must_use]
    pub const fn available_bytes(&self) -> u64 {
        self.max_bytes.saturating_sub(self.headroom_bytes)
    }
}

/// What the budget says about one publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetDecision {
    /// The publication fits.
    Publish,
    /// The publication is deferred and reported.
    Defer {
        /// Why it was deferred.
        reason: &'static str,
        /// How many bytes would have to be freed by someone else.
        shortfall_bytes: u64,
    },
}

impl BudgetDecision {
    /// Whether publication was deferred.
    #[must_use]
    pub const fn is_deferred(&self) -> bool {
        matches!(self, BudgetDecision::Defer { .. })
    }

    /// The recorded shortfall, if any.
    #[must_use]
    pub const fn shortfall_bytes(&self) -> u64 {
        match self {
            BudgetDecision::Publish => 0,
            BudgetDecision::Defer {
                shortfall_bytes, ..
            } => *shortfall_bytes,
        }
    }
}

/// Decide whether a publication of `incoming_bytes` may proceed.
#[must_use]
pub const fn decide(budget: &DiskBudget, used_bytes: u64, incoming_bytes: u64) -> BudgetDecision {
    let projected = used_bytes.saturating_add(incoming_bytes);
    let available = budget.available_bytes();
    if projected <= available {
        BudgetDecision::Publish
    } else {
        BudgetDecision::Defer {
            reason: REASON_RETENTION_EXCEEDS_BUDGET,
            shortfall_bytes: projected - available,
        }
    }
}

/// Bytes used by the named retention roots.
///
/// # Errors
///
/// Returns [`crate::ERR_IO`] when a generation directory cannot be walked.
pub fn usage(root: &Path, generations: &[String]) -> Result<u64> {
    let layout = crate::staging::StagingLayout::new(root);
    let mut total = 0_u64;
    for generation_id in generations {
        let dir = layout.generation_dir(generation_id);
        if !dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&dir).map_err(|error| ExportError::io(&error))? {
            let entry = entry.map_err(|error| ExportError::io(&error))?;
            let metadata = entry.metadata().map_err(|error| ExportError::io(&error))?;
            if metadata.is_file() {
                total += metadata.len();
            }
        }
    }
    Ok(total)
}

/// A human-readable report of a budget decision, for the operator surface.
#[must_use]
pub fn report(budget: &DiskBudget, used_bytes: u64, incoming_bytes: u64) -> String {
    match decide(budget, used_bytes, incoming_bytes) {
        BudgetDecision::Publish => format!(
            "publication of {incoming_bytes} bytes fits: {used_bytes} used of {} available",
            budget.available_bytes()
        ),
        BudgetDecision::Defer {
            reason,
            shortfall_bytes,
        } => format!(
            "{reason}: {used_bytes} bytes are already retained, {incoming_bytes} would be added, {shortfall_bytes} bytes short of {}; no active data was deleted",
            budget.available_bytes()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_publication_inside_the_budget_is_allowed() {
        let budget = DiskBudget::new(1000);
        assert_eq!(decide(&budget, 100, 200), BudgetDecision::Publish);
        assert!(!decide(&budget, 100, 200).is_deferred());
        assert!(report(&budget, 100, 200).contains("fits"));
    }

    #[test]
    fn headroom_is_reserved_before_the_hard_budget() {
        let budget = DiskBudget {
            max_bytes: 1000,
            headroom_bytes: 250,
        };
        assert_eq!(budget.available_bytes(), 750);
        assert_eq!(decide(&budget, 700, 50), BudgetDecision::Publish);
        assert_eq!(decide(&budget, 700, 51).shortfall_bytes(), 1);
        assert_eq!(crate::ERR_BUDGET, "export-budget");
    }

    #[test]
    fn a_retention_root_over_the_budget_defers_publication_instead_of_deleting_data() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = crate::staging::StagingLayout::new(dir.path());
        let generation = "a".repeat(64);
        std::fs::create_dir_all(layout.generation_dir(&generation)).expect("mkdir");
        std::fs::write(
            layout.generation_dir(&generation).join("bucket-000"),
            vec![b'x'; 64],
        )
        .expect("shard");
        let used = usage(dir.path(), std::slice::from_ref(&generation)).expect("usage");
        assert_eq!(used, 64);

        let budget = DiskBudget::new(100);
        let decision = decide(&budget, used, 100);
        assert!(decision.is_deferred());
        assert_eq!(decision.shortfall_bytes(), 64);
        let text = report(&budget, used, 100);
        assert!(text.contains(REASON_RETENTION_EXCEEDS_BUDGET));
        assert!(text.contains("no active data was deleted"));

        // The deferral changed nothing on disk.
        assert!(layout
            .generation_dir(&generation)
            .join("bucket-000")
            .is_file());
        assert_eq!(
            usage(dir.path(), std::slice::from_ref(&generation)).expect("usage"),
            used
        );
    }

    #[test]
    fn a_deferred_publication_reports_the_shortfall_rather_than_throwing_it_away() {
        let budget = DiskBudget::new(10);
        let decision = decide(&budget, 9, 5);
        assert_eq!(decision.shortfall_bytes(), 4);
        assert_eq!(
            decision,
            BudgetDecision::Defer {
                reason: REASON_RETENTION_EXCEEDS_BUDGET,
                shortfall_bytes: 4
            }
        );
        let saturated = DiskBudget {
            max_bytes: u64::MAX,
            headroom_bytes: 1,
        };
        assert_eq!(decide(&saturated, u64::MAX, u64::MAX).shortfall_bytes(), 1);
    }
}
