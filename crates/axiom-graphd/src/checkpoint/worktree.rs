//! Certify a worktree checkpoint as stable (task B-089).
//!
//! `docs/19-GIT-SNAPSHOTS-AND-MERGES.md` section 2 states the contract for
//! `--source worktree --verify-stable`: take a source inventory before and after
//! the export, apply a dirty barrier, and if the source changed in between,
//! retry or report `WORKTREE_BUSY`. Section 4 adds that the checkpoint is not
//! guaranteed to match the staged source until it is verified again.
//!
//! The module therefore treats the certificate as evidence rather than a claim:
//! a [`CertifiedSnapshot`] can only be produced from two inventories that are
//! equal, and an exhausted retry budget is `WORKTREE_BUSY` (exit 6) with
//! [`REASON_WORKTREE_BUSY`] and the attempt count, never a best-effort
//! certificate.

use std::collections::BTreeMap;

use graph_core::error::{AxiomError, ErrorCode};
use serde::Serialize;

/// Default number of before/after attempts before the source is called busy.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;
/// Largest accepted attempt budget.
pub const MAX_ATTEMPTS: u32 = 10;
/// Reason recorded when the source changed between the two inventories.
pub const REASON_WORKTREE_BUSY: &str = "worktree-busy";
/// Reason recorded when the attempt budget is outside the accepted range.
pub const REASON_ATTEMPT_BUDGET: &str = "attempt-budget";
/// Reason recorded when a path is not repository-relative.
pub const REASON_PATH_NOT_PORTABLE: &str = "path-not-portable";
/// Reason recorded when the inventory probe failed.
pub const REASON_INVENTORY_UNREADABLE: &str = "inventory-unreadable";

/// A path-to-digest inventory of a worktree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct Inventory {
    entries: BTreeMap<String, String>,
}

impl Inventory {
    /// Build an inventory from path/digest pairs.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with [`REASON_PATH_NOT_PORTABLE`] for a
    /// non-portable path.
    pub fn from_pairs(
        pairs: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, AxiomError> {
        let mut entries = BTreeMap::new();
        for (path, digest) in pairs {
            graph_core::paths::validate_portable_relative_path(&path).map_err(|error| {
                AxiomError::new(
                    ErrorCode::ValidationError,
                    "an inventory path must be repository-relative",
                )
                .with_detail("rule", REASON_PATH_NOT_PORTABLE)
                .with_detail("path", path.clone())
                .with_detail("cause", error.message())
            })?;
            if digest.len() != 64 {
                return Err(AxiomError::new(
                    ErrorCode::ValidationError,
                    "an inventory digest must be a SHA-256 hex digest",
                )
                .with_detail("rule", REASON_INVENTORY_UNREADABLE)
                .with_detail("path", path));
            }
            entries.insert(path, digest);
        }
        Ok(Self { entries })
    }

    /// Build an inventory by hashing raw file contents.
    pub fn from_contents(
        contents: impl IntoIterator<Item = (String, Vec<u8>)>,
    ) -> Result<Self, AxiomError> {
        Self::from_pairs(
            contents
                .into_iter()
                .map(|(path, bytes)| (path, graph_export::sha256_hex(&bytes))),
        )
    }

    /// Number of inventoried files.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the inventory is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The digest recorded for `path`.
    #[must_use]
    pub fn digest_of(&self, path: &str) -> Option<&str> {
        self.entries.get(path).map(String::as_str)
    }

    /// Every inventoried path, in deterministic order.
    #[must_use]
    pub fn paths(&self) -> Vec<&str> {
        self.entries.keys().map(String::as_str).collect()
    }

    /// Whether two inventories describe exactly the same tree.
    #[must_use]
    pub fn is_stable_with(&self, other: &Self) -> bool {
        self.entries == other.entries
    }

    /// Paths that differ between two inventories, in deterministic order.
    #[must_use]
    pub fn differences(&self, other: &Self) -> Vec<String> {
        let mut changed: Vec<String> = Vec::new();
        for (path, digest) in &self.entries {
            match other.entries.get(path) {
                Some(other_digest) if other_digest == digest => {}
                Some(_) => changed.push(format!("modified:{path}")),
                None => changed.push(format!("removed:{path}")),
            }
        }
        for path in other.entries.keys() {
            if !self.entries.contains_key(path) {
                changed.push(format!("added:{path}"));
            }
        }
        changed
    }

    /// The SHA-256 of the canonical inventory text.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut buffer = String::new();
        for (path, digest) in &self.entries {
            buffer.push_str(path);
            buffer.push('\u{1f}');
            buffer.push_str(digest);
            buffer.push('\n');
        }
        graph_export::sha256_hex(buffer.as_bytes())
    }
}

/// Observation of the worktree under certification.
pub trait WorktreeProbe {
    /// Take one inventory.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`] with [`REASON_INVENTORY_UNREADABLE`].
    fn inventory(&self) -> Result<Inventory, AxiomError>;
}

/// A worktree checkpoint that two inventories agree on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertifiedSnapshot {
    /// The agreed inventory.
    pub inventory: Inventory,
    /// Attempts spent reaching agreement.
    pub attempts: u32,
    /// The certification is evidence, not a claim about the staged source.
    pub also_matches_staged: bool,
}

/// Certify a worktree as unchanged across the export, with bounded retries.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] with [`REASON_ATTEMPT_BUDGET`] when the
///   attempt budget is zero or above [`MAX_ATTEMPTS`].
/// - [`ErrorCode::WorktreeBusy`] with [`REASON_WORKTREE_BUSY`] when the source
///   kept changing, carrying the attempt count and the differing-file count
///   as allowlisted details (the differing paths themselves are redaction
///   candidates and are not surfaced).
pub fn certify_stable(
    probe: &dyn WorktreeProbe,
    max_attempts: u32,
) -> Result<CertifiedSnapshot, AxiomError> {
    if max_attempts == 0 || max_attempts > MAX_ATTEMPTS {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "the stability attempt budget is outside the accepted range",
        )
        .with_detail("rule", REASON_ATTEMPT_BUDGET)
        .with_detail("minimum", "1")
        .with_detail("maximum", MAX_ATTEMPTS.to_string())
        .with_detail("observed", max_attempts.to_string()));
    }
    let mut last_differences: Vec<String> = Vec::new();
    for attempt in 1..=max_attempts {
        let before = probe.inventory()?;
        let after = probe.inventory()?;
        if before.is_stable_with(&after) {
            return Ok(CertifiedSnapshot {
                inventory: after,
                attempts: attempt,
                also_matches_staged: false,
            });
        }
        last_differences = before.differences(&after);
    }
    Err(AxiomError::new(
        ErrorCode::WorktreeBusy,
        "the worktree changed during every bounded attempt",
    )
    .with_detail("rule", REASON_WORKTREE_BUSY)
    .with_detail("observed", max_attempts.to_string())
    .with_detail("file_count", last_differences.len().to_string())
    .with_retryable(true))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A probe that returns one scripted inventory per call, staying on the last.
    struct ScriptedProbe {
        observations: Vec<Inventory>,
        index: Cell<usize>,
    }

    impl ScriptedProbe {
        fn new(observations: Vec<Inventory>) -> Self {
            Self {
                observations,
                index: Cell::new(0),
            }
        }
    }

    impl WorktreeProbe for ScriptedProbe {
        fn inventory(&self) -> Result<Inventory, AxiomError> {
            let index = self.index.get();
            self.index.set(index + 1);
            let position = index.min(self.observations.len().saturating_sub(1));
            Ok(self.observations[position].clone())
        }
    }

    fn inventory(pairs: &[(&str, &str)]) -> Inventory {
        Inventory::from_pairs(pairs.iter().map(|(path, bytes)| {
            (
                (*path).to_owned(),
                graph_export::sha256_hex(bytes.as_bytes()),
            )
        }))
        .expect("inventory")
    }

    #[test]
    fn matching_before_and_after_inventories_produce_a_certificate() {
        let stable = inventory(&[("src/a.rs", "a"), ("src/b.rs", "b")]);
        let probe = ScriptedProbe::new(vec![stable.clone(), stable.clone()]);
        let certified = certify_stable(&probe, DEFAULT_MAX_ATTEMPTS).expect("certified");
        assert_eq!(certified.attempts, 1);
        assert_eq!(certified.inventory.len(), 2);
        assert!(certified.inventory.digest_of("src/a.rs").is_some());
        assert!(!certified.also_matches_staged);
        assert_eq!(probe.index.get(), 2);
    }

    #[test]
    fn a_changing_worktree_retries_then_reports_worktree_busy() {
        let first = inventory(&[("src/a.rs", "a")]);
        let second = inventory(&[("src/a.rs", "a-changed")]);
        // every pair of observations differs
        let probe = ScriptedProbe::new(vec![
            first.clone(),
            second.clone(),
            first.clone(),
            second.clone(),
            first.clone(),
            second.clone(),
        ]);
        let error = certify_stable(&probe, 3).expect_err("busy");
        assert_eq!(error.code(), ErrorCode::WorktreeBusy);
        assert_eq!(error.exit_code().as_i32(), 6);
        assert!(error.retryable());
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_WORKTREE_BUSY)
        );
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("3")
        );
        assert_eq!(
            error.details().get("file_count").map(String::as_str),
            Some("1")
        );
        assert_eq!(probe.index.get(), 6);
    }

    #[test]
    fn a_change_on_the_second_attempt_still_certifies_within_budget() {
        let stable = inventory(&[("src/a.rs", "a")]);
        let changed = inventory(&[("src/a.rs", "b")]);
        let probe = ScriptedProbe::new(vec![changed.clone(), stable.clone(), stable.clone()]);
        let certified = certify_stable(&probe, DEFAULT_MAX_ATTEMPTS).expect("certified");
        assert_eq!(certified.attempts, 2);
    }

    #[test]
    fn inventory_differences_and_boundaries_are_explicit() {
        let left = inventory(&[("src/removed.rs", "x"), ("src/kept.rs", "k")]);
        let right = inventory(&[("src/kept.rs", "k2"), ("src/added.rs", "y")]);
        assert!(!left.is_stable_with(&right));
        let differences = left.differences(&right);
        assert!(differences.contains(&"added:src/added.rs".to_owned()));
        assert!(differences.contains(&"modified:src/kept.rs".to_owned()));
        assert!(differences.contains(&"removed:src/removed.rs".to_owned()));
        assert_eq!(left.paths(), vec!["src/kept.rs", "src/removed.rs"]);
        assert!(Inventory::default().is_empty());
        // A non-portable path and a short digest are refused.
        assert_eq!(
            Inventory::from_pairs([("D:/src/a.rs".to_owned(), "0".repeat(64))])
                .expect_err("path")
                .details()
                .get("rule")
                .map(String::as_str),
            Some(REASON_PATH_NOT_PORTABLE)
        );
        assert_eq!(
            Inventory::from_pairs([("src/a.rs".to_owned(), "abc".to_owned())])
                .expect_err("digest")
                .details()
                .get("rule")
                .map(String::as_str),
            Some(REASON_INVENTORY_UNREADABLE)
        );
    }

    #[test]
    fn an_out_of_range_attempt_budget_is_refused_before_probing() {
        let stable = inventory(&[("src/a.rs", "a")]);
        let probe = ScriptedProbe::new(vec![stable]);
        for budget in [0, MAX_ATTEMPTS + 1] {
            let error = certify_stable(&probe, budget).expect_err("budget");
            assert_eq!(error.code(), ErrorCode::ValidationError);
            assert_eq!(
                error.details().get("rule").map(String::as_str),
                Some(REASON_ATTEMPT_BUDGET)
            );
        }
        assert_eq!(probe.index.get(), 0);
    }
}
