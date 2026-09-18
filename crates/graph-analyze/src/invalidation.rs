//! Exported-signature invalidation (task B-055).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 5 requires three things when
//! source changes: a changed exported fingerprint invalidates dependents; a
//! removed symbol clears the incoming resolved edges and leaves an unresolved
//! diagnostic while a caller still exists; and a newly added reference is found
//! by parsing the new source, not by trusting the old reverse edges.
//!
//! This module plans that work from two signature snapshots and the reverse
//! dependency index the importer module produced. It never deletes a caller's
//! facts: it reports which files must be re-analysed and which edges must be
//! cleared, so the caller can re-parse before the graph claims freshness.

use std::collections::{BTreeMap, BTreeSet};

use crate::identity::digest;

/// Reason recorded when a file depended on a symbol that no longer exists.
pub const REASON_REMOVED_TARGET: &str = "invalidation-removed-target";
/// Reason recorded when an exported fingerprint changed.
pub const REASON_SIGNATURE_CHANGED: &str = "invalidation-signature-changed";

/// The exported fingerprint of one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSignature {
    /// Portably relative file path.
    pub file: String,
    /// Fingerprint over the sorted exported keys.
    pub fingerprint: String,
    /// Exported keys that produced the fingerprint, sorted.
    pub exported: Vec<String>,
}

impl ExportSignature {
    /// Compute the signature of `file` from its exported keys.
    #[must_use]
    pub fn compute(file: impl Into<String>, exported: impl IntoIterator<Item = String>) -> Self {
        let mut exported: Vec<String> = exported.into_iter().collect();
        exported.sort();
        exported.dedup();
        let parts: Vec<&str> = exported.iter().map(String::as_str).collect();
        Self {
            file: file.into(),
            fingerprint: digest(&parts),
            exported,
        }
    }

    /// Whether two signatures describe the same exported surface.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.fingerprint == other.fingerprint
    }
}

/// A snapshot of every file's exported surface.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SignatureIndex {
    signatures: BTreeMap<String, ExportSignature>,
}

impl SignatureIndex {
    /// An empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a signature.
    pub fn insert(&mut self, signature: ExportSignature) {
        self.signatures.insert(signature.file.clone(), signature);
    }

    /// Build from a list of signatures.
    #[must_use]
    pub fn from_signatures(signatures: impl IntoIterator<Item = ExportSignature>) -> Self {
        let mut index = Self::new();
        for signature in signatures {
            index.insert(signature);
        }
        index
    }

    /// A file's signature.
    #[must_use]
    pub fn get(&self, file: &str) -> Option<&ExportSignature> {
        self.signatures.get(file)
    }

    /// Every indexed file, sorted.
    #[must_use]
    pub fn files(&self) -> Vec<&str> {
        self.signatures.keys().map(String::as_str).collect()
    }

    /// Whether the index holds `file`.
    #[must_use]
    pub fn contains(&self, file: &str) -> bool {
        self.signatures.contains_key(file)
    }
}

/// The reverse dependency index: target file to the files that depend on it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DependencyIndex {
    dependents: BTreeMap<String, BTreeSet<String>>,
}

impl DependencyIndex {
    /// An empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `dependent` depends on `target`.
    pub fn add(&mut self, target: impl Into<String>, dependent: impl Into<String>) {
        self.dependents
            .entry(target.into())
            .or_default()
            .insert(dependent.into());
    }

    /// Direct dependents of `target`, sorted.
    #[must_use]
    pub fn direct(&self, target: &str) -> Vec<&str> {
        self.dependents
            .get(target)
            .map(|set| set.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Every dependent reachable from `roots`, sorted and deduplicated.
    #[must_use]
    pub fn transitive(&self, roots: &[String]) -> Vec<String> {
        let mut seen = BTreeSet::new();
        let mut queue: Vec<String> = roots.to_vec();
        while let Some(current) = queue.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            for dependent in self.direct(&current) {
                queue.push(dependent.to_string());
            }
        }
        for root in roots {
            seen.remove(root);
        }
        seen.into_iter().collect()
    }
}

/// One resolved edge that must be cleared because its target disappeared.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClearedEdge {
    /// Caller or importer that held the edge.
    pub from: String,
    /// Target file that was removed.
    pub to: String,
}

/// One unresolved diagnostic produced by the removal of a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidationDiagnostic {
    /// File that must be re-analysed.
    pub file: String,
    /// The target that disappeared.
    pub target: String,
    /// One of the `REASON_*` constants.
    pub reason: String,
    /// Human-readable explanation.
    pub message: String,
}

/// The planned invalidation work.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InvalidationPlan {
    /// Files that must be re-analysed before the graph claims freshness.
    pub stale_files: Vec<String>,
    /// Files whose exported fingerprint changed.
    pub changed_files: Vec<String>,
    /// Files removed between the two snapshots.
    pub removed_files: Vec<String>,
    /// Files added between the two snapshots; they must be parsed, because the
    /// old reverse edges cannot know about them.
    pub added_files: Vec<String>,
    /// Incoming resolved edges that must be cleared.
    pub cleared_edges: Vec<ClearedEdge>,
    /// Diagnostics left for callers that still exist.
    pub diagnostics: Vec<InvalidationDiagnostic>,
}

impl InvalidationPlan {
    /// Whether this plan requires any rework.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stale_files.is_empty()
            && self.cleared_edges.is_empty()
            && self.diagnostics.is_empty()
            && self.added_files.is_empty()
    }
}

/// Plan the invalidation between two signature snapshots.
#[must_use]
pub fn plan(
    previous: &SignatureIndex,
    current: &SignatureIndex,
    dependencies: &DependencyIndex,
) -> InvalidationPlan {
    let mut plan = InvalidationPlan::default();

    let changed: Vec<String> = previous
        .files()
        .iter()
        .filter(|file| {
            current
                .get(file)
                .is_some_and(|current| !current.matches(previous.get(file).expect("previous")))
        })
        .map(|file| (*file).to_string())
        .collect();
    let removed: Vec<String> = previous
        .files()
        .into_iter()
        .filter(|file| !current.contains(file))
        .map(str::to_string)
        .collect();
    let added: Vec<String> = current
        .files()
        .into_iter()
        .filter(|file| !previous.contains(file))
        .map(str::to_string)
        .collect();

    let mut stale = BTreeSet::new();
    stale.extend(dependencies.transitive(&changed));
    stale.extend(dependencies.transitive(&removed));
    // A file that no longer exists cannot be re-analysed, and a file with a
    // changed signature is already known to be stale.
    for file in removed.iter().chain(changed.iter()) {
        stale.remove(file);
    }
    plan.changed_files = changed;
    plan.removed_files = removed.clone();
    plan.added_files = added;
    plan.stale_files = stale.into_iter().collect();

    for target in &plan.removed_files {
        for dependent in dependencies.direct(target) {
            plan.cleared_edges.push(ClearedEdge {
                from: dependent.to_string(),
                to: target.clone(),
            });
            if current.contains(dependent) {
                plan.diagnostics.push(InvalidationDiagnostic {
                    file: dependent.to_string(),
                    target: target.clone(),
                    reason: REASON_REMOVED_TARGET.to_string(),
                    message: format!(
                        "{dependent} still resolves an edge to {target}, which no longer exists; \
                         the edge is cleared and the caller must be re-analysed"
                    ),
                });
            }
        }
    }
    plan.cleared_edges.sort();
    plan.cleared_edges.dedup();
    plan.diagnostics
        .sort_by(|left, right| (&left.file, &left.target).cmp(&(&right.file, &right.target)));
    plan
}

#[cfg(test)]
mod tests {
    use super::{plan, DependencyIndex, ExportSignature, SignatureIndex, REASON_REMOVED_TARGET};

    fn signature(file: &str, exported: &[&str]) -> ExportSignature {
        ExportSignature::compute(file, exported.iter().map(|key| (*key).to_string()))
    }

    fn deps(pairs: &[(&str, &str)]) -> DependencyIndex {
        let mut index = DependencyIndex::new();
        for (target, dependent) in pairs {
            index.add(*target, *dependent);
        }
        index
    }

    #[test]
    fn a_changed_exported_signature_invalidates_dependents_transitively() {
        let previous = SignatureIndex::from_signatures(vec![signature("src/Base.cs", &["Run"])]);
        let current =
            SignatureIndex::from_signatures(vec![signature("src/Base.cs", &["Run", "Stop"])]);
        let dependencies = deps(&[
            ("src/Base.cs", "src/Mid.cs"),
            ("src/Mid.cs", "src/Top.cs"),
            ("src/Unrelated.cs", "src/Other.cs"),
        ]);
        let plan = plan(&previous, &current, &dependencies);
        assert_eq!(plan.changed_files, vec!["src/Base.cs".to_string()]);
        assert_eq!(
            plan.stale_files,
            vec!["src/Mid.cs".to_string(), "src/Top.cs".to_string()]
        );
        assert!(plan.diagnostics.is_empty());
    }

    #[test]
    fn an_unchanged_signature_invalidates_nothing() {
        let previous = SignatureIndex::from_signatures(vec![
            signature("src/Base.cs", &["Run"]),
            signature("src/Other.cs", &["Stop"]),
        ]);
        let current = SignatureIndex::from_signatures(vec![
            signature("src/Base.cs", &["Run"]),
            signature("src/Other.cs", &["Stop"]),
        ]);
        let plan = plan(&previous, &current, &deps(&[("src/Base.cs", "src/Mid.cs")]));
        assert!(plan.is_empty());
    }

    #[test]
    fn removing_a_target_clears_incoming_edges_and_leaves_a_diagnostic_for_a_living_caller() {
        let previous = SignatureIndex::from_signatures(vec![signature("src/Gone.cs", &["Run"])]);
        let current = SignatureIndex::from_signatures(vec![signature("src/Caller.cs", &["Main"])]);
        let plan = plan(
            &previous,
            &current,
            &deps(&[("src/Gone.cs", "src/Caller.cs")]),
        );
        assert_eq!(plan.removed_files, vec!["src/Gone.cs".to_string()]);
        assert_eq!(
            plan.cleared_edges,
            vec![super::ClearedEdge {
                from: "src/Caller.cs".to_string(),
                to: "src/Gone.cs".to_string()
            }]
        );
        assert_eq!(plan.diagnostics.len(), 1);
        assert_eq!(plan.diagnostics[0].file, "src/Caller.cs");
        assert_eq!(plan.diagnostics[0].target, "src/Gone.cs");
        assert_eq!(plan.diagnostics[0].reason, REASON_REMOVED_TARGET);
        assert_eq!(plan.stale_files, vec!["src/Caller.cs".to_string()]);
    }

    #[test]
    fn a_removed_caller_produces_no_living_diagnostic() {
        let previous = SignatureIndex::from_signatures(vec![
            signature("src/Gone.cs", &["Run"]),
            signature("src/Caller.cs", &["Main"]),
        ]);
        let current = SignatureIndex::new();
        let plan = plan(
            &previous,
            &current,
            &deps(&[("src/Gone.cs", "src/Caller.cs")]),
        );
        assert_eq!(plan.cleared_edges.len(), 1);
        assert!(plan.diagnostics.is_empty());
        assert!(plan.stale_files.is_empty());
    }

    #[test]
    fn a_newly_added_file_is_parsed_instead_of_trusting_old_reverse_edges() {
        let previous = SignatureIndex::from_signatures(vec![signature("src/Base.cs", &["Run"])]);
        let current = SignatureIndex::from_signatures(vec![
            signature("src/Base.cs", &["Run"]),
            signature("src/New.cs", &["CallRun"]),
        ]);
        let plan = plan(&previous, &current, &deps(&[("src/Base.cs", "src/Old.cs")]));
        assert_eq!(plan.added_files, vec!["src/New.cs".to_string()]);
        assert!(plan.stale_files.is_empty());
        assert!(plan.diagnostics.is_empty());
        assert!(!plan.is_empty());
    }

    #[test]
    fn the_fingerprint_is_order_independent_and_content_sensitive() {
        assert_eq!(
            signature("src/A.cs", &["b", "a"]).fingerprint,
            signature("src/A.cs", &["a", "b"]).fingerprint
        );
        assert_ne!(
            signature("src/A.cs", &["a"]).fingerprint,
            signature("src/A.cs", &["a", "b"]).fingerprint
        );
    }
}
