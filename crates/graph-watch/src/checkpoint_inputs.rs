//! Distinguish the Git input classes a checkpoint must keep apart (task F-009).
//!
//! `docs/19-GIT-SNAPSHOTS-AND-MERGES.md` lets a checkpoint be materialized from
//! the Git index (`--source staged`). Four situations change what "the staged
//! source" means and each one must be named rather than flattened into a single
//! "dirty worktree" flag:
//!
//! * **partial staging** - the index and the working tree disagree about the
//!   same path, so the checkpoint input is the index blob only
//!   (`docs/24-TEST-STRATEGY-AND-RELEASE-GATES.md`, CF-012);
//! * **rename** - `git status` reports a delete plus an add of identical bytes
//!   as one `R` record, so the old path disappears from the index and the new
//!   path appears;
//! * **merge** - `HEAD` is a merge commit with more than one parent, so the
//!   snapshot has a merge relationship the checkpoint has to record;
//! * **untracked** - the path is on disk but in neither the index nor `HEAD`,
//!   so it is never a staged checkpoint input.
//!
//! Classification is deliberately derived from the already-parsed, read-only
//! observation in [`crate::git_observer`]; it never runs Git itself and never
//! guesses a rename out of an unrelated delete plus add pair. When rename
//! detection is disabled Git reports `D` and `A` records instead of `R`, and
//! this module reports only the two literal records rather than inventing a
//! rename.

use crate::git_observer::{ChangeStatus, PathChange};
use crate::same_path;

/// One Git input class a checkpoint must distinguish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CheckpointInputClass {
    /// The index holds bytes that differ from the working tree for one path.
    PartialStaging,
    /// A path moved: a delete plus an add of identical bytes.
    Rename,
    /// `HEAD` is a merge commit with more than one parent.
    Merge,
    /// A path exists only on disk.
    Untracked,
}

impl CheckpointInputClass {
    /// Every class, in a stable order.
    pub const ALL: [Self; 4] = [
        Self::PartialStaging,
        Self::Rename,
        Self::Merge,
        Self::Untracked,
    ];

    /// Stable spelling used in diagnostics and fixtures.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PartialStaging => "partial-staging",
            Self::Rename => "rename",
            Self::Merge => "merge",
            Self::Untracked => "untracked",
        }
    }
}

/// One distinguished class together with the paths that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distinction {
    class: CheckpointInputClass,
    paths: Vec<String>,
}

impl Distinction {
    /// The distinguished class.
    #[must_use]
    pub const fn class(&self) -> CheckpointInputClass {
        self.class
    }

    /// Paths that made the class observable, deduplicated and sorted.
    #[must_use]
    pub fn paths(&self) -> &[String] {
        &self.paths
    }
}

/// Count the `parent` headers of a `git cat-file commit` object.
///
/// A rooted commit has zero parents and an ordinary commit has one; two or more
/// mean `HEAD` is a merge commit.
#[must_use]
pub fn merge_parent_count(commit_object: &str) -> usize {
    commit_object
        .lines()
        .filter(|line| line.starts_with("parent "))
        .count()
}

/// Classify one parsed worktree observation.
///
/// `staged`, `unstaged` and `untracked` come from
/// [`crate::git_observer::parse_porcelain_v1_z`]; `merge_parents` comes from
/// [`merge_parent_count`]. The result contains one [`Distinction`] per class the
/// observation actually shows, in [`CheckpointInputClass::ALL`] order.
#[must_use]
pub fn classify(
    staged: &[PathChange],
    unstaged: &[PathChange],
    untracked: &[PathChange],
    merge_parents: usize,
) -> Vec<Distinction> {
    let mut distinctions = Vec::new();

    let mut partial = Vec::new();
    for change in staged {
        if unstaged
            .iter()
            .any(|other| same_path(other.path(), change.path()))
        {
            record_path(&mut partial, change.path());
        }
    }
    if !partial.is_empty() {
        distinctions.push(Distinction {
            class: CheckpointInputClass::PartialStaging,
            paths: partial,
        });
    }

    let mut renamed = Vec::new();
    for change in staged {
        if change.status() == ChangeStatus::Renamed {
            record_path(&mut renamed, change.path());
        }
    }
    if !renamed.is_empty() {
        distinctions.push(Distinction {
            class: CheckpointInputClass::Rename,
            paths: renamed,
        });
    }

    if merge_parents >= 2 {
        distinctions.push(Distinction {
            class: CheckpointInputClass::Merge,
            paths: Vec::new(),
        });
    }

    if !untracked.is_empty() {
        let mut paths = Vec::new();
        for change in untracked {
            record_path(&mut paths, change.path());
        }
        distinctions.push(Distinction {
            class: CheckpointInputClass::Untracked,
            paths,
        });
    }

    distinctions
}

fn record_path(paths: &mut Vec<String>, path: &str) {
    if paths.iter().any(|existing| same_path(existing, path)) {
        return;
    }
    paths.push(path.to_owned());
    paths.sort();
}

#[cfg(test)]
mod tests {
    use super::{classify, merge_parent_count, CheckpointInputClass};
    use crate::git_observer::ChangeStatus;
    use crate::git_observer::PathChange;

    fn change(status: ChangeStatus, path: &str) -> PathChange {
        PathChange::new(status, path, None)
    }

    #[test]
    fn a_path_in_both_buckets_is_partial_staging() {
        let staged = [change(ChangeStatus::Modified, "src/app.rs")];
        let unstaged = [change(ChangeStatus::Deleted, "src/app.rs")];
        let distinctions = classify(&staged, &unstaged, &[], 0);
        assert_eq!(distinctions.len(), 1);
        assert_eq!(
            distinctions[0].class(),
            CheckpointInputClass::PartialStaging,
            "a staged path the worktree also changed must be partial staging"
        );
        assert_eq!(distinctions[0].paths(), ["src/app.rs".to_string()]);
    }

    #[test]
    fn a_rename_record_is_distinguished_and_an_unrelated_pair_is_not() {
        let renamed = [PathChange::new(
            ChangeStatus::Renamed,
            "src/new.rs",
            Some("src/old.rs".to_string()),
        )];
        let distinctions = classify(&renamed, &[], &[], 1);
        assert_eq!(distinctions.len(), 1);
        assert_eq!(distinctions[0].class(), CheckpointInputClass::Rename);

        // Rename detection disabled: Git reports a delete plus an add instead.
        let split = [
            change(ChangeStatus::Deleted, "src/old.rs"),
            change(ChangeStatus::Added, "src/new.rs"),
        ];
        let distinctions = classify(&split, &[], &[], 1);
        assert!(
            distinctions.is_empty(),
            "an unpaired delete plus add must not be guessed into a rename"
        );
    }

    #[test]
    fn two_or_more_parents_are_a_merge_and_untracked_is_reported() {
        let untracked = [change(ChangeStatus::Untracked, "notes/new.txt")];
        let distinctions = classify(&[], &[], &untracked, 2);
        assert_eq!(distinctions.len(), 2);
        assert_eq!(distinctions[0].class(), CheckpointInputClass::Merge);
        assert!(distinctions[0].paths().is_empty());
        assert_eq!(distinctions[1].class(), CheckpointInputClass::Untracked);
        assert_eq!(distinctions[1].paths(), ["notes/new.txt".to_string()]);

        let linear = classify(&[], &[], &[], 1);
        assert!(
            linear
                .iter()
                .all(|d| d.class() != CheckpointInputClass::Merge),
            "one parent is an ordinary commit"
        );
    }

    #[test]
    fn merge_parent_count_reads_the_commit_object_headers() {
        let merge = "tree 0\nparent a\nparent b\nauthor x\n\nmsg\n";
        assert_eq!(merge_parent_count(merge), 2);
        assert_eq!(merge_parent_count("tree 0\nparent a\n\nmsg\n"), 1);
        assert_eq!(merge_parent_count("tree 0\n\nroot\n"), 0);
    }
}
