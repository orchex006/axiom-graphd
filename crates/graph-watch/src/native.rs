//! The `notify`-backed native watcher adapter (task B-021).
//!
//! The native backend is the only way to observe a directory without polling it,
//! but its events are raw and backend-specific. This module contains the single
//! place where a backend event is translated into [`RawHint`], so no other module
//! depends on `notify` types and the translation can be tested without a
//! filesystem.
//!
//! Editor saves are the reason translation is not a one-to-one mapping. Word,
//! Visual Studio and most editors implement a save as "write a temporary file,
//! then rename it over the target". A watcher that only follows the target file
//! would see nothing; a recursive directory watch sees the rename, and
//! [`RenameMode::Both`] carries both the scratch path and the target. The
//! translation emits the removal of the scratch path and the upsert of the
//! target, which is exactly what [`crate::normalize`] expects.
//!
//! Classification and debouncing happen after translation, so a path that is not
//! under the bound root is dropped here rather than guessed at.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::Duration;

use graph_core::error::{AxiomError, ErrorCode};
use notify::event::{ModifyKind, RenameMode};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::normalize::{RawHint, RawKind};

/// Whether the host offers a usable native backend for a root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeSupport {
    /// A native recursive watch could be registered.
    Supported,
    /// No native backend could be registered for this root.
    Unsupported {
        /// Diagnostic reason.
        reason: String,
    },
}

impl NativeSupport {
    /// Whether a native watch is available.
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        matches!(self, Self::Supported)
    }

    /// Diagnostic reason, when the backend is unavailable.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Supported => None,
            Self::Unsupported { reason } => Some(reason),
        }
    }
}

/// Number of hints accepted from one drain before the flush is declared an
/// overflow and a complete scan is required instead.
pub const MAX_DRAIN_HINTS: usize = 4096;

/// One drain of the native backend.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NativeFlush {
    hints: Vec<RawHint>,
    overflowed: bool,
}

impl NativeFlush {
    /// Translated hints, in backend order.
    #[must_use]
    pub fn hints(&self) -> &[RawHint] {
        &self.hints
    }

    /// Whether the backend delivered more than [`MAX_DRAIN_HINTS`] events.
    ///
    /// An overflowed flush is not trustworthy on its own; the caller must run a
    /// complete inventory instead of acting on the partial stream.
    #[must_use]
    pub const fn is_overflowed(&self) -> bool {
        self.overflowed
    }
}

/// Translate one backend event into relative hints.
///
/// Paths outside `root`, and the root itself, produce no hint: the watcher is
/// bound to one project and must not widen its scope from a stray event.
#[must_use]
pub fn translate_event(event: &Event, root: &Path) -> Vec<RawHint> {
    let relative = |path: &PathBuf| relative_hint(root, path.as_path());
    if let EventKind::Modify(ModifyKind::Name(mode)) = &event.kind {
        return match mode {
            RenameMode::Both => {
                let mut hints = Vec::new();
                if let Some(origin) = event.paths.first().and_then(relative) {
                    hints.push(RawHint::new(origin, RawKind::RenamedFrom));
                }
                if let Some(destination) = event.paths.get(1).and_then(relative) {
                    hints.push(RawHint::new(destination, RawKind::RenamedTo));
                }
                hints
            }
            RenameMode::From => event
                .paths
                .iter()
                .filter_map(relative)
                .map(|path| RawHint::new(path, RawKind::RenamedFrom))
                .collect(),
            RenameMode::To => event
                .paths
                .iter()
                .filter_map(relative)
                .map(|path| RawHint::new(path, RawKind::RenamedTo))
                .collect(),
            _ => event
                .paths
                .iter()
                .filter_map(relative)
                .map(|path| RawHint::new(path, RawKind::Modified))
                .collect(),
        };
    }
    if matches!(event.kind, EventKind::Create(_)) {
        return event
            .paths
            .iter()
            .filter_map(relative)
            .map(|path| RawHint::new(path, RawKind::Created))
            .collect();
    }
    if matches!(event.kind, EventKind::Remove(_)) {
        return event
            .paths
            .iter()
            .filter_map(relative)
            .map(|path| RawHint::new(path, RawKind::Removed))
            .collect();
    }
    if matches!(event.kind, EventKind::Access(_) | EventKind::Other) {
        return event
            .paths
            .iter()
            .filter_map(relative)
            .map(|path| RawHint::new(path, RawKind::Other))
            .collect();
    }
    // `Modify` data/metadata and the conservative `Any` catch-all are both
    // treated as a change, never as a deletion.
    event
        .paths
        .iter()
        .filter_map(relative)
        .map(|path| RawHint::new(path, RawKind::Modified))
        .collect()
}

fn relative_hint(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    if relative.as_os_str().is_empty() {
        return None;
    }
    let text = relative.to_string_lossy().replace('\\', "/");
    crate::portable_relative_path(&text).ok()
}

/// Probe whether a native recursive watch can be registered for `root`.
#[must_use]
pub fn probe(root: &Path) -> NativeSupport {
    match NativeWatcher::start(root) {
        Ok(_) => NativeSupport::Supported,
        Err(error) => NativeSupport::Unsupported {
            reason: error.message().to_string(),
        },
    }
}

/// A running native recursive watch.
pub struct NativeWatcher {
    root: PathBuf,
    watcher: RecommendedWatcher,
    receiver: Receiver<Result<Event, notify::Error>>,
}

impl NativeWatcher {
    /// Start a recursive watch on `root`.
    ///
    /// # Errors
    /// [`ErrorCode::NotFound`] when the root does not exist;
    /// [`ErrorCode::NotReady`] when no native backend can be registered.
    pub fn start(root: &Path) -> Result<Self, AxiomError> {
        if !root.is_dir() {
            return Err(AxiomError::new(
                ErrorCode::NotFound,
                "the watched root does not exist or is not a directory",
            )
            .with_detail("root", root.display().to_string()));
        }
        let (sender, receiver) = channel();
        let mut watcher = RecommendedWatcher::new(
            move |event| {
                let _ = sender.send(event);
            },
            Config::default(),
        )
        .map_err(|error| {
            AxiomError::new(
                ErrorCode::NotReady,
                "no native filesystem backend could be created",
            )
            .with_detail("reason", error.to_string())
        })?;
        watcher
            .watch(root, RecursiveMode::Recursive)
            .map_err(|error| {
                AxiomError::new(
                    ErrorCode::NotReady,
                    "the native filesystem backend refused the recursive watch",
                )
                .with_detail("reason", error.to_string())
            })?;
        Ok(Self {
            root: root.to_path_buf(),
            watcher,
            receiver,
        })
    }

    /// Project root the watch is bound to.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Wait up to `timeout` for the first event, then drain what is already
    /// queued.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`] when the backend reports an event error.
    pub fn drain(&mut self, timeout: Duration) -> Result<NativeFlush, AxiomError> {
        let mut flush = NativeFlush::default();
        let first = match self.receiver.recv_timeout(timeout) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => return Ok(flush),
            Err(RecvTimeoutError::Disconnected) => {
                return Err(AxiomError::new(
                    ErrorCode::Internal,
                    "the native filesystem backend disconnected",
                ))
            }
        };
        self.collect(first, &mut flush)?;
        while let Ok(event) = self.receiver.try_recv() {
            if flush.hints.len() >= MAX_DRAIN_HINTS {
                flush.overflowed = true;
                break;
            }
            self.collect(event, &mut flush)?;
        }
        Ok(flush)
    }

    fn collect(
        &self,
        event: Result<Event, notify::Error>,
        flush: &mut NativeFlush,
    ) -> Result<(), AxiomError> {
        let event = event.map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the native filesystem backend reported an event error",
            )
            .with_detail("reason", error.to_string())
        })?;
        flush.hints.extend(translate_event(&event, &self.root));
        Ok(())
    }

    /// Stop watching; dropping the watcher is the documented way to stop it.
    pub fn stop(self) {
        drop(self.watcher);
    }
}

#[cfg(test)]
mod tests {
    use super::{probe, translate_event, NativeSupport, NativeWatcher, MAX_DRAIN_HINTS};
    use crate::normalize::{normalize, FileAction, RawKind};
    use notify::event::{CreateKind, DataChange, ModifyKind, RenameMode};
    use notify::{Event, EventKind};
    use std::path::Path;
    use std::time::Duration;

    fn event(kind: EventKind, paths: &[&str]) -> Event {
        Event {
            kind,
            paths: paths.iter().map(std::path::PathBuf::from).collect(),
            attrs: notify::event::EventAttributes::default(),
        }
    }

    #[test]
    fn a_recursive_directory_save_emits_a_normalized_hint() {
        let root = Path::new("D:/repo/Project");
        let hints = translate_event(
            &event(
                EventKind::Modify(ModifyKind::Data(DataChange::Content)),
                &["D:/repo/Project/src/App.cs"],
            ),
            root,
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].path(), "src/App.cs");
        assert_eq!(hints[0].kind(), RawKind::Modified);

        let outcome = normalize(&hints).expect("normalized");
        assert_eq!(outcome.hints().len(), 1);
        assert_eq!(outcome.hints()[0].action(), FileAction::Upsert);
        assert_eq!(outcome.hints()[0].path(), "src/App.cs");
    }

    #[test]
    fn an_editor_atomic_replace_is_detected_without_losing_the_target() {
        let root = Path::new("D:/repo/Project");
        let event = event(
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            &[
                "D:/repo/Project/src/.App.cs.tmp",
                "D:/repo/Project/src/App.cs",
            ],
        );
        let hints = translate_event(&event, root);
        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].kind(), RawKind::RenamedFrom);
        assert_eq!(hints[1].kind(), RawKind::RenamedTo);

        let outcome = normalize(&hints).expect("normalized");
        let actions: Vec<(FileAction, &str)> = outcome
            .hints()
            .iter()
            .map(|hint| (hint.action(), hint.path()))
            .collect();
        assert_eq!(
            actions,
            vec![
                (FileAction::Remove, "src/.App.cs.tmp"),
                (FileAction::Upsert, "src/App.cs"),
            ],
            "the scratch file is tombstoned and the target is re-analyzed"
        );
    }

    #[test]
    fn events_outside_the_root_are_dropped_and_the_flush_is_bounded() {
        let root = Path::new("D:/repo/Project");
        assert!(translate_event(
            &event(
                EventKind::Create(CreateKind::File),
                &["D:/elsewhere/App.cs", "D:/repo/Project"]
            ),
            root
        )
        .is_empty());

        let hints = translate_event(
            &event(
                EventKind::Remove(notify::event::RemoveKind::File),
                &["D:/repo/Project/src/Gone.cs"],
            ),
            root,
        );
        assert_eq!(hints[0].kind(), RawKind::Removed);

        let access = translate_event(
            &event(
                EventKind::Access(notify::event::AccessKind::Read),
                &["D:/repo/Project/src/App.cs"],
            ),
            root,
        );
        assert_eq!(access[0].kind(), RawKind::Other);
        assert_eq!(normalize(&access).expect("normalized").dropped(), 1);
        assert_eq!(MAX_DRAIN_HINTS, 4096);
    }

    #[test]
    fn starting_a_watch_on_a_missing_root_is_an_explicit_failure() {
        let missing = std::path::Path::new("D:/repo/DefinitelyMissingRoot");
        let error = NativeWatcher::start(missing).err().expect("missing root");
        assert_eq!(error.code(), graph_core::error::ErrorCode::NotFound);
        assert!(!probe(missing).is_supported());
        if let NativeSupport::Unsupported { reason } = probe(missing) {
            assert!(!reason.is_empty());
        }
        let directory = tempfile::tempdir().expect("temp dir");
        assert!(probe(directory.path()).is_supported());
        let mut watcher = NativeWatcher::start(directory.path()).expect("watcher");
        assert_eq!(watcher.root(), directory.path());
        let flush = watcher
            .drain(Duration::from_millis(0))
            .expect("an empty drain is not an error");
        assert!(flush.hints().is_empty());
        assert!(!flush.is_overflowed());
    }
}
