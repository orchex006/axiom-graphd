//! Create/write/rename/delete normalization (task B-023).
//!
//! A native backend reports one physical operation as several events, in an
//! order that is not guaranteed to match the order in which the program made the
//! changes. The graph must never be mutated from raw events: every backend event
//! is reduced to a small closed set of actions first, and a rename is expanded
//! into the removal of the old path plus the creation of the new one
//! (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 3: a rename stays
//! old-path-delete plus new-path-create until a mapping is proven).
//!
//! The case-only rename is the reason this is not a trivial mapping. On Windows a
//! rename that only changes the case of a path is a real rename, but the old and
//! the new spelling compare equal under the local filesystem rules. Emitting only
//! the new path would leave the graph claiming that a file with the new name is
//! already indexed while the tombstone for the old spelling was never written, so
//! both actions are emitted and the pair is marked as a case-only rename.

use crate::{portable_relative_path, same_path};
use graph_core::error::{AxiomError, ErrorCode};

/// Upper bound on hints accepted from one backend flush.
///
/// A backend that reports more than this has overflowed, which the recovery
/// module turns into a full rescan instead of replaying a partial event stream.
pub const MAX_HINTS_PER_BATCH: usize = 4096;

/// Raw event kind as the native or polling backend observed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RawKind {
    /// A path appeared.
    Created,
    /// The metadata or the content of a path changed.
    Modified,
    /// A path disappeared.
    Removed,
    /// The origin side of a rename, when the backend reports both sides.
    RenamedFrom,
    /// The destination side of a rename.
    RenamedTo,
    /// The backend reported something this adapter does not model.
    Other,
}

/// One unnormalized event as a backend produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHint {
    path: String,
    kind: RawKind,
}

impl RawHint {
    /// Record one backend event.
    #[must_use]
    pub fn new(path: impl Into<String>, kind: RawKind) -> Self {
        Self {
            path: path.into(),
            kind,
        }
    }

    /// Path exactly as the backend spelled it.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Kind exactly as the backend reported it.
    #[must_use]
    pub const fn kind(&self) -> RawKind {
        self.kind
    }
}

/// Normalized action the graph and the queue may act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileAction {
    /// Analyse this path (new or changed).
    Upsert,
    /// Tombstone this path and invalidate references to it.
    Remove,
}

/// One normalized, actionable hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedHint {
    action: FileAction,
    path: String,
    origin: Option<String>,
    case_only_rename: bool,
}

impl NormalizedHint {
    /// Action to apply.
    #[must_use]
    pub const fn action(&self) -> FileAction {
        self.action
    }

    /// Canonical portable path the action applies to.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Previous path of a rename, when the backend reported the origin side.
    #[must_use]
    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }

    /// Whether this rename only changed the case of the path.
    #[must_use]
    pub const fn is_case_only_rename(&self) -> bool {
        self.case_only_rename
    }
}

/// Result of normalizing one backend flush.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NormalizationOutcome {
    hints: Vec<NormalizedHint>,
    unmatched_renames_from: Vec<String>,
    dropped: usize,
}

impl NormalizationOutcome {
    /// Normalized hints in application order: removals before upserts.
    #[must_use]
    pub fn hints(&self) -> &[NormalizedHint] {
        &self.hints
    }

    /// Renames whose origin side was never paired with a destination.
    ///
    /// The origin is still reported as a removal by [`normalize`]; this list
    /// exists so the caller can widen the next inventory instead of assuming the
    /// backend reported everything.
    #[must_use]
    pub fn unmatched_renames_from(&self) -> &[String] {
        &self.unmatched_renames_from
    }

    /// Hints the adapter refuses to model (access-only and similar noise).
    #[must_use]
    pub const fn dropped(&self) -> usize {
        self.dropped
    }
}

/// Reduce one backend flush to actionable hints.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] when a path is not a canonical portable
///   relative path, or when one flush carries more than [`MAX_HINTS_PER_BATCH`]
///   entries (the caller must rescan instead of applying a partial batch).
pub fn normalize(hints: &[RawHint]) -> Result<NormalizationOutcome, AxiomError> {
    if hints.len() > MAX_HINTS_PER_BATCH {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "one watcher flush reported more hints than the bounded batch allows",
        )
        .with_detail("hints", hints.len().to_string())
        .with_detail("limit", MAX_HINTS_PER_BATCH.to_string()));
    }

    let mut outcome = NormalizationOutcome::default();
    // The flush is reduced into ordered groups: every removal first, then every
    // creation or update, then the paired renames. Removals therefore always
    // precede creations even though the backend order is not guaranteed.
    let mut removals: Vec<String> = Vec::new();
    let mut upserts: Vec<String> = Vec::new();
    let mut rename_origins: Vec<String> = Vec::new();
    let mut pending_renames_to: Vec<String> = Vec::new();

    for hint in hints {
        let path = portable_relative_path(hint.path()).map_err(|error| {
            error
                .with_detail("hint_kind", format!("{:?}", hint.kind()))
                .with_detail("hint_path", hint.path())
        })?;
        match hint.kind() {
            RawKind::Created | RawKind::Modified => upserts.push(path),
            RawKind::Removed => removals.push(path),
            RawKind::RenamedFrom => {
                removals.push(path.clone());
                rename_origins.push(path);
            }
            RawKind::RenamedTo => pending_renames_to.push(path),
            RawKind::Other => outcome.dropped += 1,
        }
    }

    let mut paired_origins: Vec<String> = Vec::new();
    let mut paired: Vec<NormalizedHint> = Vec::new();
    for path in pending_renames_to {
        // Pair the destination with an origin that names the same file under the
        // host filesystem rules, so a case-only rename is not read as an
        // unrelated new file.
        // A rename normally changes the file name, so the origin cannot be
        // matched by path equality alone. The backend reports both sides of one
        // rename adjacently, so the first unpaired origin is the correct partner;
        // a same-path match is preferred because it also identifies the
        // case-only rename.
        let mut origin: Option<String> = None;
        for candidate in &rename_origins {
            if paired_origins.iter().any(|used| used == candidate) {
                continue;
            }
            if same_path(candidate, &path) {
                origin = Some(candidate.clone());
                break;
            }
        }
        if origin.is_none() {
            origin = rename_origins
                .iter()
                .find(|candidate| !paired_origins.iter().any(|used| used == *candidate))
                .cloned();
        }
        let case_only = origin
            .as_deref()
            .is_some_and(|origin| origin != path && same_path(origin, &path));
        if let Some(origin) = &origin {
            paired_origins.push(origin.clone());
        }
        paired.push(NormalizedHint {
            action: FileAction::Upsert,
            path,
            origin,
            case_only_rename: case_only,
        });
    }

    outcome.unmatched_renames_from = rename_origins
        .into_iter()
        .filter(|origin| !paired_origins.contains(origin))
        .collect();
    outcome.hints = removals
        .into_iter()
        .map(|path| NormalizedHint {
            action: FileAction::Remove,
            path,
            origin: None,
            case_only_rename: false,
        })
        .chain(upserts.into_iter().map(|path| NormalizedHint {
            action: FileAction::Upsert,
            path,
            origin: None,
            case_only_rename: false,
        }))
        .chain(paired)
        .collect();

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::{normalize, FileAction, RawHint, RawKind, MAX_HINTS_PER_BATCH};
    use graph_core::error::ErrorCode;

    fn paths(outcome: &super::NormalizationOutcome) -> Vec<(FileAction, &str)> {
        outcome
            .hints()
            .iter()
            .map(|hint| (hint.action(), hint.path()))
            .collect()
    }

    #[test]
    fn create_write_and_delete_map_to_one_action_each() {
        let outcome = normalize(&[
            RawHint::new("src/App.cs", RawKind::Created),
            RawHint::new("src/Other.cs", RawKind::Modified),
            RawHint::new("src/Gone.cs", RawKind::Removed),
            RawHint::new("src/App.cs.tmp", RawKind::Other),
        ])
        .expect("normalized");

        assert_eq!(
            paths(&outcome),
            vec![
                (FileAction::Remove, "src/Gone.cs"),
                (FileAction::Upsert, "src/App.cs"),
                (FileAction::Upsert, "src/Other.cs"),
            ]
        );
        assert_eq!(outcome.dropped(), 1);
    }

    #[test]
    fn a_rename_covers_the_old_and_the_new_path() {
        let outcome = normalize(&[
            RawHint::new("src/old.cs", RawKind::RenamedFrom),
            RawHint::new("src/new.cs", RawKind::RenamedTo),
        ])
        .expect("normalized");

        assert_eq!(
            paths(&outcome),
            vec![
                (FileAction::Remove, "src/old.cs"),
                (FileAction::Upsert, "src/new.cs"),
            ],
            "the tombstone for the origin must be emitted before the destination"
        );
        let destination = outcome
            .hints()
            .iter()
            .find(|hint| hint.path() == "src/new.cs")
            .expect("destination hint");
        assert_eq!(destination.origin(), Some("src/old.cs"));
        assert!(!destination.is_case_only_rename());
        assert!(outcome.unmatched_renames_from().is_empty());
    }

    #[test]
    fn a_case_only_rename_keeps_the_tombstone_and_the_new_state() {
        let outcome = normalize(&[
            RawHint::new("src/App.cs", RawKind::RenamedFrom),
            RawHint::new("src/app.cs", RawKind::RenamedTo),
        ])
        .expect("normalized");

        assert_eq!(outcome.hints().len(), 2);
        assert_eq!(outcome.hints()[0].action(), FileAction::Remove);
        assert_eq!(outcome.hints()[0].path(), "src/App.cs");
        let destination = &outcome.hints()[1];
        assert_eq!(destination.action(), FileAction::Upsert);
        assert_eq!(destination.path(), "src/app.cs");
        assert_eq!(destination.origin(), Some("src/App.cs"));
        assert_eq!(
            destination.is_case_only_rename(),
            cfg!(windows),
            "a case-only rename is only observable where the host compares paths case-insensitively"
        );
    }

    #[test]
    fn a_lone_destination_is_a_creation_and_a_lone_origin_is_a_removal() {
        let destination_only =
            normalize(&[RawHint::new("src/new.cs", RawKind::RenamedTo)]).expect("normalized");
        assert_eq!(
            paths(&destination_only),
            vec![(FileAction::Upsert, "src/new.cs")]
        );
        assert_eq!(destination_only.hints()[0].origin(), None);

        let origin_only =
            normalize(&[RawHint::new("src/old.cs", RawKind::RenamedFrom)]).expect("normalized");
        assert_eq!(
            paths(&origin_only),
            vec![(FileAction::Remove, "src/old.cs")]
        );
        assert_eq!(
            origin_only.unmatched_renames_from(),
            ["src/old.cs".to_string()]
        );
    }

    #[test]
    fn non_portable_paths_and_oversized_flushes_are_refused() {
        let error = normalize(&[RawHint::new("C:/tmp/App.cs", RawKind::Modified)])
            .expect_err("absolute path must be refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);

        let oversized: Vec<RawHint> = (0..=MAX_HINTS_PER_BATCH)
            .map(|index| RawHint::new(format!("src/File{index}.cs"), RawKind::Modified))
            .collect();
        let error = normalize(&oversized).expect_err("oversized flush must be refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
    }
}
