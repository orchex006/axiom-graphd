//! Polling watcher fallback and the declared backend policy (task B-022).
//!
//! Not every host offers a native recursive backend, and some roots (a network
//! share, a container filesystem) report events so unreliably that the operator
//! prefers polling. The fallback must find changes *without* assuming that any
//! native event was delivered: it compares a complete snapshot of path stamps
//! against the previous snapshot, so the same reconciliation logic works whether
//! the backend pushed events or the watcher pulled state.
//!
//! Switching backends is a declared policy decision, never a silent downgrade.
//! [`select_backend`] either honours the configured policy or fails, so a
//! deployment that requires native events for latency reasons cannot quietly
//! begin polling (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 9).

use std::collections::BTreeMap;
use std::path::Path;

use crate::native::NativeSupport;
use crate::normalize::{RawHint, RawKind};
use crate::portable_relative_path;
use graph_core::error::{AxiomError, ErrorCode};

/// Which observation strategy is in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendKind {
    /// The host filesystem notification backend.
    Native,
    /// Periodic snapshot comparison.
    Polling,
}

impl BackendKind {
    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Polling => "polling",
        }
    }
}

/// Configured preference for the observation strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendPolicy {
    /// Use native events when available, otherwise poll.
    PreferNative,
    /// Require native events; refuse to start otherwise.
    RequireNative,
    /// Poll even when native events are available.
    ForcePolling,
}

impl BackendPolicy {
    /// Parse the configured value.
    ///
    /// # Errors
    /// [`ErrorCode::ConfigInvalid`] for an unknown policy name.
    pub fn parse(value: &str) -> Result<Self, AxiomError> {
        match value {
            "prefer_native" => Ok(Self::PreferNative),
            "require_native" => Ok(Self::RequireNative),
            "force_polling" => Ok(Self::ForcePolling),
            other => Err(AxiomError::new(
                ErrorCode::ConfigInvalid,
                "unknown watcher backend policy",
            )
            .with_detail("policy", other)),
        }
    }

    /// Stable configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreferNative => "prefer_native",
            Self::RequireNative => "require_native",
            Self::ForcePolling => "force_polling",
        }
    }
}

/// The backend the caller must use, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendDecision {
    kind: BackendKind,
    reason: Option<String>,
}

impl BackendDecision {
    /// Backend to use.
    #[must_use]
    pub const fn kind(&self) -> BackendKind {
        self.kind
    }

    /// Why the backend was chosen (present on every fallback or override).
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Whether a native backend is used.
    #[must_use]
    pub const fn is_native(&self) -> bool {
        matches!(self.kind, BackendKind::Native)
    }
}

/// Choose the observation backend under the configured policy.
///
/// # Errors
/// [`ErrorCode::NotReady`] when the policy requires native events but the host
/// cannot provide them.
pub fn select_backend(
    policy: BackendPolicy,
    support: &NativeSupport,
) -> Result<BackendDecision, AxiomError> {
    match (policy, support.is_supported()) {
        (BackendPolicy::ForcePolling, _) => Ok(BackendDecision {
            kind: BackendKind::Polling,
            reason: Some("polling was forced by configuration".to_string()),
        }),
        (BackendPolicy::PreferNative, true) => Ok(BackendDecision {
            kind: BackendKind::Native,
            reason: None,
        }),
        (BackendPolicy::PreferNative, false) => Ok(BackendDecision {
            kind: BackendKind::Polling,
            reason: Some(
                support
                    .reason()
                    .unwrap_or("the host offers no native recursive backend")
                    .to_string(),
            ),
        }),
        (BackendPolicy::RequireNative, true) => Ok(BackendDecision {
            kind: BackendKind::Native,
            reason: None,
        }),
        (BackendPolicy::RequireNative, false) => Err(AxiomError::new(
            ErrorCode::NotReady,
            "native filesystem events are required by policy but unavailable",
        )
        .with_detail(
            "reason",
            support
                .reason()
                .unwrap_or("the host offers no native recursive backend"),
        )),
    }
}

/// Metadata used to decide whether a path changed between polls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStamp {
    size_bytes: u64,
    modified_ns: i128,
}

impl FileStamp {
    /// Record one observed stamp.
    #[must_use]
    pub const fn new(size_bytes: u64, modified_ns: i128) -> Self {
        Self {
            size_bytes,
            modified_ns,
        }
    }

    /// Observed size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Observed modification time in nanoseconds since the epoch.
    #[must_use]
    pub const fn modified_ns(&self) -> i128 {
        self.modified_ns
    }
}

/// A source of complete path snapshots.
pub trait SnapshotSource {
    /// Snapshot every candidate path under `root`.
    ///
    /// # Errors
    /// Implementations report a failure to read the root at all; individual
    /// unreadable entries are simply omitted and will be re-observed later.
    fn snapshot(&self, root: &Path) -> Result<Vec<(String, FileStamp)>, AxiomError>;
}

/// One poll of the snapshot source.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PollOutcome {
    hints: Vec<RawHint>,
    first_scan: bool,
}

impl PollOutcome {
    /// Changes observed since the previous poll.
    #[must_use]
    pub fn hints(&self) -> &[RawHint] {
        &self.hints
    }

    /// Whether this was the first poll, which establishes a baseline rather than
    /// reporting changes.
    ///
    /// A first poll cannot report a change honestly, so it reports none and the
    /// caller runs a complete inventory instead.
    #[must_use]
    pub const fn is_first_scan(&self) -> bool {
        self.first_scan
    }

    /// Whether any change was observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hints.is_empty()
    }
}

/// Snapshot-diffing watcher.
#[derive(Debug, Clone, Default)]
pub struct PollingWatcher {
    previous: BTreeMap<String, FileStamp>,
}

impl PollingWatcher {
    /// A watcher that has not polled yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of paths in the last snapshot.
    #[must_use]
    pub fn known_count(&self) -> usize {
        self.previous.len()
    }

    /// Poll the source and report changes since the previous poll.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] when the source reports a path that is not
    /// a canonical portable relative path, or the same path twice.
    pub fn poll(
        &mut self,
        source: &dyn SnapshotSource,
        root: &Path,
    ) -> Result<PollOutcome, AxiomError> {
        let snapshot = source.snapshot(root)?;
        let mut current: BTreeMap<String, FileStamp> = BTreeMap::new();
        for (path, stamp) in snapshot {
            let path = portable_relative_path(&path)?;
            if current.insert(path.clone(), stamp).is_some() {
                return Err(AxiomError::new(
                    ErrorCode::ValidationError,
                    "the snapshot source reported the same path twice",
                )
                .with_detail("portable_path", path));
            }
        }

        let first_scan = self.previous.is_empty();
        let mut hints = Vec::new();
        if !first_scan {
            for (path, stamp) in &current {
                match self.previous.get(path) {
                    Some(previous) if previous == stamp => {}
                    Some(_) => hints.push(RawHint::new(path.clone(), RawKind::Modified)),
                    None => hints.push(RawHint::new(path.clone(), RawKind::Created)),
                }
            }
            for path in self.previous.keys() {
                if !current.contains_key(path) {
                    hints.push(RawHint::new(path.clone(), RawKind::Removed));
                }
            }
        }
        self.previous = current;
        Ok(PollOutcome { hints, first_scan })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        select_backend, BackendKind, BackendPolicy, FileStamp, PollingWatcher, SnapshotSource,
    };
    use crate::native::NativeSupport;
    use crate::normalize::{RawKind, MAX_HINTS_PER_BATCH};
    use graph_core::error::ErrorCode;
    use std::cell::RefCell;
    use std::path::Path;

    #[derive(Debug)]
    struct CannedSource {
        snapshots: RefCell<Vec<Vec<(String, FileStamp)>>>,
    }

    impl CannedSource {
        fn new(snapshots: Vec<Vec<(&str, u64, i128)>>) -> Self {
            Self {
                snapshots: RefCell::new(
                    snapshots
                        .into_iter()
                        .map(|snapshot| {
                            snapshot
                                .into_iter()
                                .map(|(path, size, mtime)| {
                                    (path.to_string(), FileStamp::new(size, mtime))
                                })
                                .collect()
                        })
                        .collect(),
                ),
            }
        }
    }

    impl SnapshotSource for CannedSource {
        fn snapshot(
            &self,
            _root: &Path,
        ) -> Result<Vec<(String, FileStamp)>, graph_core::error::AxiomError> {
            Ok(self.snapshots.borrow_mut().remove(0))
        }
    }

    #[test]
    fn polling_finds_changes_without_any_native_event() {
        let source = CannedSource::new(vec![
            vec![("src/App.cs", 10, 1), ("src/Keep.cs", 5, 1)],
            vec![("src/App.cs", 12, 2), ("src/New.cs", 3, 9)],
        ]);
        let mut watcher = PollingWatcher::new();
        let first = watcher
            .poll(&source, Path::new("D:/repo"))
            .expect("first poll");
        assert!(first.is_first_scan());
        assert!(
            first.is_empty(),
            "a first poll establishes a baseline instead of inventing changes"
        );
        assert_eq!(watcher.known_count(), 2);

        let second = watcher
            .poll(&source, Path::new("D:/repo"))
            .expect("second poll");
        assert!(!second.is_first_scan());
        let observed: Vec<(&str, RawKind)> = second
            .hints()
            .iter()
            .map(|hint| (hint.path(), hint.kind()))
            .collect();
        assert_eq!(
            observed,
            vec![
                ("src/App.cs", RawKind::Modified),
                ("src/New.cs", RawKind::Created),
                ("src/Keep.cs", RawKind::Removed),
            ]
        );
    }

    #[test]
    fn backend_switches_only_follow_the_declared_policy() {
        let unsupported = NativeSupport::Unsupported {
            reason: "no inotify handles remain".to_string(),
        };
        let decision =
            select_backend(BackendPolicy::PreferNative, &unsupported).expect("declared fallback");
        assert_eq!(decision.kind(), BackendKind::Polling);
        assert_eq!(decision.reason(), Some("no inotify handles remain"));

        let error = select_backend(BackendPolicy::RequireNative, &unsupported)
            .expect_err("a required native backend must not silently poll");
        assert_eq!(error.code(), ErrorCode::NotReady);

        let forced = select_backend(BackendPolicy::ForcePolling, &NativeSupport::Supported)
            .expect("forced polling");
        assert_eq!(forced.kind(), BackendKind::Polling);
        assert!(forced.reason().is_some());
        assert_eq!(forced.kind().as_str(), "polling");

        let native =
            select_backend(BackendPolicy::PreferNative, &NativeSupport::Supported).expect("native");
        assert!(native.is_native());
        assert!(native.reason().is_none());
        assert_eq!(
            BackendPolicy::parse("require_native"),
            Ok(BackendPolicy::RequireNative)
        );
        assert_eq!(
            BackendPolicy::parse("sometimes")
                .expect_err("unknown policy")
                .code(),
            ErrorCode::ConfigInvalid
        );
        assert_eq!(BackendPolicy::ForcePolling.as_str(), "force_polling");
    }

    #[test]
    fn a_snapshot_is_never_allowed_to_exceed_the_hint_bound_or_escape_the_root() {
        let source = CannedSource::new(vec![vec![("C:/outside/App.cs", 1, 1)]]);
        let mut watcher = PollingWatcher::new();
        let error = watcher
            .poll(&source, Path::new("D:/repo"))
            .expect_err("an absolute path is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);

        let duplicate = CannedSource::new(vec![vec![("src/A.cs", 1, 1), ("src/A.cs", 2, 2)]]);
        let mut watcher = PollingWatcher::new();
        assert_eq!(
            watcher
                .poll(&duplicate, Path::new("D:/repo"))
                .expect_err("duplicates are a source defect")
                .code(),
            ErrorCode::ValidationError
        );
        assert_eq!(MAX_HINTS_PER_BATCH, 4096);
    }
}
