//! Complete startup input inventory (task B-028).
//!
//! A stopped daemon sees nothing. When it starts again the database still holds
//! the previous observation, but the working tree may have gained, changed or
//! lost files while the process was down, and `HEAD` may not have moved at all.
//! Enumerating only the paths whose stored digest differs from a re-read of the
//! same paths is not enough: the *set* of paths must be walked and compared to
//! the stored set, so new, untracked and deleted files are discovered
//! (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 9).
//!
//! The walk itself is behind [`DirentSource`]. That keeps the reconciliation
//! logic pure and testable, and it keeps the module free of assumptions about
//! how a particular platform reports directories, symlinks and denied entries.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use crate::ignore::{IgnoreDecision, IgnorePolicy, IgnoreReason};
use crate::input_policy::{InputDecision, InputPolicy, InputSkip, WatchedEntry};
use crate::portable_relative_path;
use graph_core::error::{AxiomError, ErrorCode};
use sha2::{Digest, Sha256};

/// Upper bound on entries accepted from one walk.
pub const MAX_INVENTORY_ENTRIES: usize = 500_000;

/// What the filesystem reported about one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScannedKind {
    /// A regular file.
    File,
    /// A directory; directories are not analyzed but bound the walk.
    Directory,
    /// A symbolic link with an optional resolved target.
    Symlink {
        /// Resolved absolute target, when resolution succeeded.
        resolved_target: Option<String>,
    },
}

/// One entry observed by a walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedEntry {
    path: String,
    kind: ScannedKind,
    size_bytes: u64,
    content_hash: Option<String>,
}

impl ScannedEntry {
    /// Record one observed entry.
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        kind: ScannedKind,
        size_bytes: u64,
        content_hash: Option<String>,
    ) -> Self {
        Self {
            path: path.into(),
            kind,
            size_bytes,
            content_hash,
        }
    }

    /// Project-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Observed kind.
    #[must_use]
    pub const fn kind(&self) -> &ScannedKind {
        &self.kind
    }

    /// Observed size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Content digest, absent when the entry could not be read.
    #[must_use]
    pub fn content_hash(&self) -> Option<&str> {
        self.content_hash.as_deref()
    }
}

/// One completed walk.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalkReport {
    entries: Vec<ScannedEntry>,
    permission_errors: Vec<String>,
    truncated: bool,
}

impl WalkReport {
    /// Build a walk result.
    #[must_use]
    pub fn new(
        entries: Vec<ScannedEntry>,
        permission_errors: Vec<String>,
        truncated: bool,
    ) -> Self {
        Self {
            entries,
            permission_errors,
            truncated,
        }
    }

    /// Entries the walk observed.
    #[must_use]
    pub fn entries(&self) -> &[ScannedEntry] {
        &self.entries
    }

    /// Project-relative paths the walk could not read.
    #[must_use]
    pub fn permission_errors(&self) -> &[String] {
        &self.permission_errors
    }

    /// Whether the walk stopped early and the caller must widen the scan.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }
}

/// A source of directory observations.
pub trait DirentSource {
    /// Walk `root` and report everything the source could observe.
    ///
    /// # Errors
    /// Implementations report an unrecoverable failure; individual denied
    /// entries belong in [`WalkReport::permission_errors`].
    fn walk(&self, root: &Path) -> Result<WalkReport, AxiomError>;
}

/// The digest set the database already holds for one project.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownInventory {
    entries: BTreeMap<String, String>,
}

impl KnownInventory {
    /// Build a known set from stored `(path, content_hash)` pairs.
    #[must_use]
    pub fn from_pairs<I, P, H>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (P, H)>,
        P: Into<String>,
        H: Into<String>,
    {
        Self {
            entries: pairs
                .into_iter()
                .map(|(path, hash)| (path.into(), hash.into()))
                .collect(),
        }
    }

    /// Number of stored observations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the project has no stored observations yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Stored digest for `path`.
    #[must_use]
    pub fn hash_of(&self, path: &str) -> Option<&str> {
        self.entries.get(path).map(String::as_str)
    }

    /// Stored paths in stable order.
    #[must_use]
    pub fn paths(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }
}

/// One actionable difference between the walk and the stored set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryEvent {
    /// The path is new or reappeared after deletion.
    Added {
        /// Project-relative path.
        path: String,
        /// Digest observed now.
        content_hash: String,
    },
    /// The stored digest differs from the digest observed now.
    Modified {
        /// Project-relative path.
        path: String,
        /// Digest observed now.
        content_hash: String,
    },
    /// The stored path was not observed at all.
    Deleted {
        /// Project-relative path.
        path: String,
    },
}

impl InventoryEvent {
    /// Project-relative path the event applies to.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Added { path, .. } | Self::Modified { path, .. } | Self::Deleted { path } => path,
        }
    }
}

/// A path the walk saw but the ignore policy excludes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExcludedPath {
    path: String,
    reason: IgnoreReason,
}

impl ExcludedPath {
    /// Project-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Exclusion category.
    #[must_use]
    pub const fn reason(&self) -> IgnoreReason {
        self.reason
    }
}

/// A path the walk saw but the input policy withholds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithheldPath {
    path: String,
    reason: InputSkip,
}

impl WithheldPath {
    /// Project-relative path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Why the path is withheld.
    #[must_use]
    pub const fn reason(&self) -> &InputSkip {
        &self.reason
    }
}

/// The complete difference between a walk and the stored inventory.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InventoryPlan {
    events: Vec<InventoryEvent>,
    excluded: Vec<ExcludedPath>,
    withheld: Vec<WithheldPath>,
    unreadable: Vec<String>,
    unchanged: usize,
    full_scan_required: bool,
}

impl InventoryPlan {
    /// Actionable differences in application order: deletions, then additions,
    /// then modifications.
    #[must_use]
    pub fn events(&self) -> &[InventoryEvent] {
        &self.events
    }

    /// Paths excluded by the ignore policy.
    #[must_use]
    pub fn excluded(&self) -> &[ExcludedPath] {
        &self.excluded
    }

    /// Paths withheld by the input policy.
    #[must_use]
    pub fn withheld(&self) -> &[WithheldPath] {
        &self.withheld
    }

    /// Paths the walk could not read.
    #[must_use]
    pub fn unreadable(&self) -> &[String] {
        &self.unreadable
    }

    /// Paths whose digest matched the stored observation.
    #[must_use]
    pub const fn unchanged(&self) -> usize {
        self.unchanged
    }

    /// Whether the walk was incomplete and a wider scan is still required.
    #[must_use]
    pub const fn requires_full_scan(&self) -> bool {
        self.full_scan_required
    }

    /// Whether the plan changed nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Digests of every analyzed path, suitable for the durable inventory write.
    #[must_use]
    pub fn observed_files(&self, known: &KnownInventory) -> Vec<(String, String)> {
        let mut observed: BTreeMap<String, String> = BTreeMap::new();
        for path in known.paths() {
            if let Some(hash) = known.hash_of(&path) {
                observed.insert(path, hash.to_string());
            }
        }
        for event in &self.events {
            match event {
                InventoryEvent::Added { path, content_hash }
                | InventoryEvent::Modified { path, content_hash } => {
                    observed.insert(path.clone(), content_hash.clone());
                }
                InventoryEvent::Deleted { path } => {
                    observed.remove(path);
                }
            }
        }
        observed.into_iter().collect()
    }
}

/// Compare one walk against the stored inventory.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] for a non-portable entry path, a duplicated
///   entry, or a walk larger than [`MAX_INVENTORY_ENTRIES`].
pub fn plan_inventory(
    source: &dyn DirentSource,
    root: &Path,
    known: &KnownInventory,
    ignore: &IgnorePolicy,
    input: &InputPolicy,
) -> Result<InventoryPlan, AxiomError> {
    let report = source.walk(root)?;
    if report.entries().len() > MAX_INVENTORY_ENTRIES {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "inventory walk exceeded its bound",
        )
        .with_detail("limit", MAX_INVENTORY_ENTRIES.to_string())
        .with_detail("entries", report.entries().len().to_string()));
    }

    let mut plan = InventoryPlan {
        full_scan_required: report.is_truncated(),
        ..InventoryPlan::default()
    };
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut added = Vec::new();
    let mut modified = Vec::new();

    for entry in report.entries() {
        let path = portable_relative_path(entry.path())?;
        if !seen.insert(path.clone()) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "inventory walk reported the same path twice",
            )
            .with_detail("portable_path", path));
        }
        match ignore.classify(&path)? {
            IgnoreDecision::Ignored { reason, .. } => {
                plan.excluded.push(ExcludedPath { path, reason });
                continue;
            }
            IgnoreDecision::Tracked => {}
        }
        let watched = match entry.kind() {
            ScannedKind::Directory => continue,
            ScannedKind::File => WatchedEntry::File,
            ScannedKind::Symlink { resolved_target } => match resolved_target {
                Some(target) => WatchedEntry::ResolvedSymlink {
                    target: target.clone(),
                },
                None => WatchedEntry::UnresolvedSymlink,
            },
        };
        match input.decide(&path, &watched)? {
            InputDecision::Skipped(reason) => {
                plan.withheld.push(WithheldPath { path, reason });
                continue;
            }
            InputDecision::Parsable => {}
        }
        let Some(content_hash) = entry.content_hash() else {
            plan.unreadable.push(path);
            continue;
        };
        match known.hash_of(&path) {
            Some(stored) if stored == content_hash => plan.unchanged += 1,
            Some(_) => modified.push(InventoryEvent::Modified {
                path,
                content_hash: content_hash.to_string(),
            }),
            None => added.push(InventoryEvent::Added {
                path,
                content_hash: content_hash.to_string(),
            }),
        }
    }

    let mut deleted = Vec::new();
    for path in known.paths() {
        if !seen.contains(&path) {
            deleted.push(InventoryEvent::Deleted { path });
        }
    }

    plan.unreadable
        .extend(report.permission_errors().iter().cloned());
    plan.events = deleted.into_iter().chain(added).chain(modified).collect();
    Ok(plan)
}

/// Digest of a file-like byte sequence, as used for `content_hash`.
#[must_use]
pub fn content_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut text = String::with_capacity(64);
    for byte in digest {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// A [`DirentSource`] backed by the host filesystem.
///
/// The walk never follows a symlink into another directory; a symlink is
/// reported as an entry and its resolved target is handed to the input policy,
/// which decides whether following it is acceptable.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdDirentSource;

impl DirentSource for StdDirentSource {
    fn walk(&self, root: &Path) -> Result<WalkReport, AxiomError> {
        let mut entries = Vec::new();
        let mut errors = Vec::new();
        let mut stack = vec![(root.to_path_buf(), String::new())];
        while let Some((directory, prefix)) = stack.pop() {
            let listing = match std::fs::read_dir(&directory) {
                Ok(listing) => listing,
                Err(error) => {
                    let is_root = prefix.is_empty();
                    errors.push(if is_root { ".".to_string() } else { prefix });
                    if error.kind() == std::io::ErrorKind::NotFound && is_root {
                        return Err(AxiomError::new(
                            ErrorCode::NotFound,
                            "the project root does not exist",
                        )
                        .with_detail("root", root.display().to_string()));
                    }
                    continue;
                }
            };
            for item in listing {
                let item = match item {
                    Ok(item) => item,
                    Err(_) => {
                        if !prefix.is_empty() {
                            errors.push(prefix.clone());
                        }
                        continue;
                    }
                };
                let name = item.file_name().to_string_lossy().into_owned();
                let relative = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                let metadata = match std::fs::symlink_metadata(item.path()) {
                    Ok(metadata) => metadata,
                    Err(_) => {
                        errors.push(relative);
                        continue;
                    }
                };
                let file_type = metadata.file_type();
                if file_type.is_symlink() {
                    let resolved = std::fs::canonicalize(item.path())
                        .ok()
                        .map(|path| path.to_string_lossy().into_owned());
                    let size = std::fs::metadata(item.path())
                        .map(|target| target.len())
                        .unwrap_or(0);
                    entries.push(ScannedEntry::new(
                        relative,
                        ScannedKind::Symlink {
                            resolved_target: resolved,
                        },
                        size,
                        None,
                    ));
                } else if file_type.is_dir() {
                    entries.push(ScannedEntry::new(
                        relative.clone(),
                        ScannedKind::Directory,
                        0,
                        None,
                    ));
                    stack.push((item.path(), relative));
                } else {
                    let size = metadata.len();
                    match std::fs::read(item.path()) {
                        Ok(bytes) => {
                            let digest = content_digest(&bytes);
                            entries.push(ScannedEntry::new(
                                relative,
                                ScannedKind::File,
                                size,
                                Some(digest),
                            ));
                        }
                        Err(_) => {
                            entries.push(ScannedEntry::new(
                                relative.clone(),
                                ScannedKind::File,
                                size,
                                None,
                            ));
                            errors.push(relative);
                        }
                    }
                }
            }
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        errors.sort();
        errors.dedup();
        Ok(WalkReport::new(entries, errors, false))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        plan_inventory, DirentSource, InventoryEvent, KnownInventory, ScannedEntry, ScannedKind,
        StdDirentSource, WalkReport, MAX_INVENTORY_ENTRIES,
    };
    use crate::ignore::IgnorePolicy;
    use crate::input_policy::InputPolicy;
    use graph_core::error::ErrorCode;

    #[derive(Debug, Clone, Default)]
    struct CannedSource {
        report: WalkReport,
    }

    impl DirentSource for CannedSource {
        fn walk(
            &self,
            _root: &std::path::Path,
        ) -> Result<WalkReport, graph_core::error::AxiomError> {
            Ok(self.report.clone())
        }
    }

    fn file(path: &str, hash: &str) -> ScannedEntry {
        ScannedEntry::new(path, ScannedKind::File, 10, Some(hash.to_string()))
    }

    fn policies() -> (IgnorePolicy, InputPolicy) {
        (IgnorePolicy::default(), InputPolicy::new("D:/repo/Project"))
    }

    #[test]
    fn offline_additions_changes_and_deletions_are_discovered() {
        let source = CannedSource {
            report: WalkReport::new(
                vec![
                    file("src/Kept.cs", "hash-kept"),
                    file("src/Changed.cs", "hash-new"),
                    file("src/Untracked.cs", "hash-untracked"),
                    file("src/bin/Generated.dll", "hash-build"),
                    file("live/manifest.json", "hash-live"),
                ],
                Vec::new(),
                false,
            ),
        };
        let known = KnownInventory::from_pairs([
            ("src/Kept.cs", "hash-kept"),
            ("src/Changed.cs", "hash-old"),
            ("src/Deleted.cs", "hash-deleted"),
        ]);
        let (ignore, input) = policies();
        let plan = plan_inventory(
            &source,
            std::path::Path::new("D:/repo/Project"),
            &known,
            &ignore,
            &input,
        )
        .expect("planned");

        let events: Vec<(String, &str)> = plan
            .events()
            .iter()
            .map(|event| (event.path().to_string(), event_kind(event)))
            .collect();
        assert_eq!(
            events,
            vec![
                ("src/Deleted.cs".to_string(), "deleted"),
                ("src/Untracked.cs".to_string(), "added"),
                ("src/Changed.cs".to_string(), "modified"),
            ],
            "a deletion, a content change and an untracked file are all discovered"
        );
        assert_eq!(plan.unchanged(), 1);
        assert_eq!(plan.excluded().len(), 2);
        assert!(!plan.requires_full_scan());
        assert_eq!(
            plan.observed_files(&known),
            vec![
                ("src/Changed.cs".to_string(), "hash-new".to_string()),
                ("src/Kept.cs".to_string(), "hash-kept".to_string()),
                ("src/Untracked.cs".to_string(), "hash-untracked".to_string()),
            ]
        );
    }

    #[test]
    fn a_truncated_or_unreadable_walk_never_claims_a_complete_inventory() {
        let source = CannedSource {
            report: WalkReport::new(
                vec![file("src/Denied.cs", "hash")],
                vec!["src/Denied.cs".to_string()],
                true,
            ),
        };
        let (ignore, input) = policies();
        let plan = plan_inventory(
            &source,
            std::path::Path::new("D:/repo/Project"),
            &KnownInventory::default(),
            &ignore,
            &input,
        )
        .expect("planned");
        assert!(
            plan.requires_full_scan(),
            "a truncated walk stays incomplete"
        );
        assert_eq!(plan.unreadable(), ["src/Denied.cs".to_string()]);

        let denied = ScannedEntry::new("src/Locked.cs", ScannedKind::File, 1, None);
        let source = CannedSource {
            report: WalkReport::new(vec![denied], Vec::new(), false),
        };
        let plan = plan_inventory(
            &source,
            std::path::Path::new("D:/repo/Project"),
            &KnownInventory::default(),
            &ignore,
            &input,
        )
        .expect("planned");
        assert!(plan.is_empty());
        assert_eq!(plan.unreadable(), ["src/Locked.cs".to_string()]);
    }

    #[test]
    fn the_host_walk_reports_a_real_offline_edit() {
        let directory = tempfile::tempdir().expect("temp dir");
        let root = directory.path();
        std::fs::create_dir_all(root.join("src")).expect("create src");
        std::fs::write(root.join("src/App.cs"), "class App {}").expect("write");
        let source = StdDirentSource;
        let first = source.walk(root).expect("first walk");
        let known = KnownInventory::from_pairs(first.entries().iter().filter_map(|entry| {
            entry
                .content_hash()
                .map(|hash| (entry.path().to_string(), hash.to_string()))
        }));

        std::fs::write(root.join("src/App.cs"), "class App { int X; }").expect("edit");
        std::fs::write(root.join("src/New.cs"), "class New {}").expect("add");
        std::fs::create_dir_all(root.join("obj")).expect("create obj");
        std::fs::write(root.join("obj/App.g.cs"), "generated").expect("generated output");

        let (ignore, input) = policies();
        let plan = plan_inventory(&source, root, &known, &ignore, &input).expect("planned");
        assert_eq!(plan.events().len(), 2);
        assert_eq!(event_kind(&plan.events()[0]), "added");
        assert_eq!(plan.events()[0].path(), "src/New.cs");
        assert_eq!(event_kind(&plan.events()[1]), "modified");
        assert_eq!(plan.events()[1].path(), "src/App.cs");
        assert!(
            plan.excluded()
                .iter()
                .any(|entry| entry.path() == "obj/App.g.cs"),
            "a generated build output is excluded even though it is new"
        );

        std::fs::remove_file(root.join("src/New.cs")).expect("remove offline addition");
        let after_delete = plan_inventory(&source, root, &known, &ignore, &input).expect("planned");
        assert_eq!(after_delete.events().len(), 1);
        assert_eq!(event_kind(&after_delete.events()[0]), "modified");

        let duplicates = WalkReport::new(
            vec![file("src/App.cs", "a"), file("src/App.cs", "b")],
            Vec::new(),
            false,
        );
        let error = plan_inventory(
            &CannedSource { report: duplicates },
            root,
            &KnownInventory::default(),
            &ignore,
            &input,
        )
        .expect_err("duplicate paths are a walker defect");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(MAX_INVENTORY_ENTRIES, 500_000);
    }

    fn event_kind(event: &InventoryEvent) -> &'static str {
        match event {
            InventoryEvent::Added { .. } => "added",
            InventoryEvent::Modified { .. } => "modified",
            InventoryEvent::Deleted { .. } => "deleted",
        }
    }
}
