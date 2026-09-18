//! Incremental file replacement (task B-054).
//!
//! The queue and reconciliation design (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md`
//! section 7) re-parses a single changed file and replaces only that owner's
//! facts. This module is the in-memory half of that rule: replacing a file
//! removes exactly the facts that belonged to the previous parse of that file,
//! keeps every other file's keys byte-for-byte, and reports what changed so the
//! caller can invalidate dependents (B-055) instead of assuming the whole graph
//! is fresh.
//!
//! The equivalence test at the bottom is the guard the coverage document asks
//! for: an incrementally updated set must contain exactly the keys a full
//! rebuild over the same final inputs would contain.

use std::collections::{BTreeMap, BTreeSet};

/// One fact row: a stable key plus its kind spelling.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FactRow {
    /// Stable key from [`crate::identity`].
    pub key: String,
    /// Kind spelling, e.g. `method` or `class`.
    pub kind: String,
}

impl FactRow {
    /// Build a fact row.
    #[must_use]
    pub fn new(key: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            kind: kind.into(),
        }
    }
}

/// The facts extracted from one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFacts {
    /// Portably relative file path.
    pub file: String,
    /// Content digest the facts were extracted from.
    pub digest: String,
    /// Facts in source order.
    pub facts: Vec<FactRow>,
}

impl FileFacts {
    /// Build file facts.
    #[must_use]
    pub fn new(
        file: impl Into<String>,
        digest: impl Into<String>,
        facts: impl IntoIterator<Item = FactRow>,
    ) -> Self {
        Self {
            file: file.into(),
            digest: digest.into(),
            facts: facts.into_iter().collect(),
        }
    }

    /// Sorted, deduplicated keys of this file.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.facts.iter().map(|fact| fact.key.clone()).collect();
        keys.sort();
        keys.dedup();
        keys
    }
}

/// What one replacement changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    /// The file that was replaced or added.
    pub file: String,
    /// Whether the set already had facts for this file.
    pub replaced: bool,
    /// Whether the digest matched the stored one and the work was skipped.
    pub skipped: bool,
    /// Keys removed by the replacement, sorted.
    pub removed_keys: Vec<String>,
    /// Keys added by the replacement, sorted.
    pub added_keys: Vec<String>,
    /// Keys present before and after, sorted.
    pub retained_keys: Vec<String>,
    /// Every other file whose facts were left untouched, sorted.
    pub untouched_files: Vec<String>,
}

/// What removing a file changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removal {
    /// The removed file.
    pub file: String,
    /// Whether the file was present.
    pub removed: bool,
    /// Keys removed from the set, sorted.
    pub removed_keys: Vec<String>,
    /// Every other file whose facts were left untouched, sorted.
    pub untouched_files: Vec<String>,
}

/// The incrementally maintained set of file facts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnalysisSet {
    files: BTreeMap<String, FileFacts>,
}

impl AnalysisSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of files the set holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether the set holds no file.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The stored facts of one file.
    #[must_use]
    pub fn file(&self, file: &str) -> Option<&FileFacts> {
        self.files.get(file)
    }

    /// Every stored file, sorted.
    #[must_use]
    pub fn files(&self) -> Vec<&str> {
        self.files.keys().map(String::as_str).collect()
    }

    /// Every stored key, sorted and deduplicated.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        let mut keys = BTreeSet::new();
        for facts in self.files.values() {
            for key in facts.keys() {
                keys.insert(key);
            }
        }
        keys.into_iter().collect()
    }

    /// Replace one file's facts, or add them when the file is new.
    ///
    /// Replacing a file with an identical digest is refused as skipped work so
    /// a redelivered queue message cannot churn the graph.
    pub fn replace(&mut self, facts: FileFacts) -> Replacement {
        let untouched_before: Vec<String> = self
            .files
            .keys()
            .filter(|file| **file != facts.file)
            .cloned()
            .collect();
        let added = facts.keys();
        let previous = self.files.remove(&facts.file);
        let (replaced, previous_keys) = match previous {
            Some(previous) => {
                if previous.digest == facts.digest {
                    let retained = previous.keys();
                    self.files.insert(facts.file.clone(), previous);
                    return Replacement {
                        file: facts.file,
                        replaced: true,
                        skipped: true,
                        removed_keys: Vec::new(),
                        added_keys: Vec::new(),
                        retained_keys: retained,
                        untouched_files: untouched_before,
                    };
                }
                (true, previous.keys())
            }
            None => (false, Vec::new()),
        };
        let previous_set: BTreeSet<&String> = previous_keys.iter().collect();
        let added_set: BTreeSet<&String> = added.iter().collect();
        let removed_keys = previous_set
            .difference(&added_set)
            .map(|key| (*key).clone())
            .collect();
        let added_keys = added_set
            .difference(&previous_set)
            .map(|key| (*key).clone())
            .collect();
        let retained_keys = previous_set
            .intersection(&added_set)
            .map(|key| (*key).clone())
            .collect();
        let file_name = facts.file.clone();
        self.files.insert(file_name.clone(), facts);
        Replacement {
            file: file_name,
            replaced,
            skipped: false,
            removed_keys,
            added_keys,
            retained_keys,
            untouched_files: untouched_before,
        }
    }

    /// Remove one file's facts and report which keys disappeared.
    pub fn remove(&mut self, file: &str) -> Removal {
        let untouched: Vec<String> = self
            .files
            .keys()
            .filter(|candidate| candidate.as_str() != file)
            .cloned()
            .collect();
        match self.files.remove(file) {
            Some(previous) => Removal {
                file: file.to_string(),
                removed: true,
                removed_keys: previous.keys(),
                untouched_files: untouched,
            },
            None => Removal {
                file: file.to_string(),
                removed: false,
                removed_keys: Vec::new(),
                untouched_files: untouched,
            },
        }
    }

    /// Build a set from a complete file list, as a full analysis would.
    #[must_use]
    pub fn from_files(files: impl IntoIterator<Item = FileFacts>) -> Self {
        let mut set = Self::new();
        for facts in files {
            set.files.insert(facts.file.clone(), facts);
        }
        set
    }
}

#[cfg(test)]
mod tests {
    use super::{AnalysisSet, FactRow, FileFacts};

    fn facts(file: &str, digest: &str, keys: &[(&str, &str)]) -> FileFacts {
        FileFacts::new(
            file,
            digest,
            keys.iter()
                .map(|(key, kind)| FactRow::new(*key, *kind))
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn replacing_one_file_leaves_every_other_file_key_untouched() {
        let mut set = AnalysisSet::from_files(vec![
            facts("src/A.cs", "d1", &[("a-1", "class"), ("a-2", "method")]),
            facts("src/B.cs", "d2", &[("b-1", "class")]),
        ]);
        let before_b = set.file("src/B.cs").cloned().expect("b facts");
        let replacement = set.replace(facts(
            "src/A.cs",
            "d3",
            &[("a-1", "class"), ("a-3", "method")],
        ));
        assert!(replacement.replaced);
        assert!(!replacement.skipped);
        assert_eq!(replacement.removed_keys, vec!["a-2".to_string()]);
        assert_eq!(replacement.added_keys, vec!["a-3".to_string()]);
        assert_eq!(replacement.retained_keys, vec!["a-1".to_string()]);
        assert_eq!(replacement.untouched_files, vec!["src/B.cs".to_string()]);
        assert_eq!(set.file("src/B.cs").cloned(), Some(before_b));
        assert_eq!(
            set.keys(),
            vec!["a-1".to_string(), "a-3".to_string(), "b-1".to_string()]
        );
    }

    #[test]
    fn a_redelivered_identical_digest_is_skipped_instead_of_churned() {
        let mut set = AnalysisSet::new();
        set.replace(facts("src/A.cs", "d1", &[("a-1", "class")]));
        let second = set.replace(facts("src/A.cs", "d1", &[("a-1", "class")]));
        assert!(second.skipped);
        assert!(second.added_keys.is_empty());
        assert!(second.removed_keys.is_empty());
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn a_new_file_is_an_addition_and_removal_reports_only_its_keys() {
        let mut set = AnalysisSet::from_files(vec![facts("src/A.cs", "d1", &[("a-1", "class")])]);
        let addition = set.replace(facts("src/C.cs", "d9", &[("c-1", "class")]));
        assert!(!addition.replaced);
        assert_eq!(addition.added_keys, vec!["c-1".to_string()]);
        assert_eq!(addition.untouched_files, vec!["src/A.cs".to_string()]);

        let removal = set.remove("src/C.cs");
        assert!(removal.removed);
        assert_eq!(removal.removed_keys, vec!["c-1".to_string()]);
        assert_eq!(removal.untouched_files, vec!["src/A.cs".to_string()]);
        assert_eq!(set.keys(), vec!["a-1".to_string()]);

        let again = set.remove("src/C.cs");
        assert!(!again.removed);
        assert!(again.removed_keys.is_empty());
    }

    #[test]
    fn an_empty_reparse_drops_the_previous_facts_instead_of_retaining_them_as_fresh() {
        let mut set = AnalysisSet::from_files(vec![facts(
            "src/A.cs",
            "d1",
            &[("a-1", "class"), ("a-2", "method")],
        )]);
        let replacement = set.replace(facts("src/A.cs", "d2", &[]));
        assert_eq!(
            replacement.removed_keys,
            vec!["a-1".to_string(), "a-2".to_string()]
        );
        assert!(replacement.added_keys.is_empty());
        assert!(set.keys().is_empty());
    }

    #[test]
    fn incremental_update_matches_a_full_rebuild() {
        let initial = vec![
            facts("src/A.cs", "d1", &[("a-1", "class"), ("a-2", "method")]),
            facts("src/B.cs", "d2", &[("b-1", "class"), ("b-2", "method")]),
            facts("src/C.cs", "d3", &[("c-1", "class")]),
        ];
        let final_a = facts("src/A.cs", "d4", &[("a-2", "method"), ("a-4", "class")]);
        let final_b = facts("src/B.cs", "d5", &[("b-2", "method")]);

        let mut incremental = AnalysisSet::from_files(initial.clone());
        incremental.replace(final_a.clone());
        incremental.replace(final_b.clone());
        incremental.remove("src/C.cs");

        let full = AnalysisSet::from_files(vec![final_a, final_b]);
        assert_eq!(incremental.keys(), full.keys());
        assert_eq!(incremental.files(), full.files());
    }

    #[test]
    fn replacement_reports_the_file_it_actually_changed() {
        let mut set = AnalysisSet::new();
        let replacement = set.replace(facts("src/A.cs", "d1", &[("a-1", "class")]));
        assert_eq!(replacement.file, "src/A.cs");
        assert!(!replacement.replaced);
    }
}
