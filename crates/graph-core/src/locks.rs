//! Cross-process shared/exclusive solution guard (tasks B-073 and B-074).
//!
//! One invariant: a reader and the publisher must observe the same exclusion
//! even when they are different processes. A mutex, a thread-local flag or a
//! "lock file exists" marker that only one process reads cannot provide that,
//! so [`Backend::LocalOnly`] is refused instead of being accepted as a guard.
//!
//! The policy lives here; the operating-system primitive lives in
//! [`crate::locks_posix`] (`flock`) and [`crate::locks_windows`]
//! (`LockFileEx`).

use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Error code: another participant holds a conflicting lock.
pub const ERR_LOCKED: &str = "solution-guard-locked";
/// Error code: this platform cannot provide the requested lock.
pub const ERR_UNSUPPORTED: &str = "solution-guard-unsupported";
/// The record of why an in-process-only lock is not a solution guard.
pub const LOCAL_ONLY_DETAIL: &str = "an in-process-only lock is not a solution guard: the shared reader lock and the exclusive writer lock must be enforced by the operating system so that a second process observes the same exclusion";

/// The lock one participant asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// A reader lock: several shared holders coexist.
    Shared,
    /// The writer lock: no other holder, shared or exclusive, coexists.
    Exclusive,
}

impl LockMode {
    /// Both modes, for exhaustive policy checks.
    pub const ALL: [LockMode; 2] = [LockMode::Shared, LockMode::Exclusive];

    /// Whether this mode is a reader lock.
    #[must_use]
    pub const fn is_shared(self) -> bool {
        matches!(self, LockMode::Shared)
    }

    /// Whether a holder in this mode refuses a new request in `other` mode.
    #[must_use]
    pub const fn excludes(self, other: LockMode) -> bool {
        match (self, other) {
            (LockMode::Exclusive, _) => true,
            (LockMode::Shared, LockMode::Exclusive) => true,
            (LockMode::Shared, LockMode::Shared) => false,
        }
    }
}

/// Which mechanism a caller asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// The operating-system lock of this platform.
    Native,
    /// A lock only one process can observe; refused on purpose.
    LocalOnly,
}

/// Why a guard could not be taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError {
    /// Another participant already holds a conflicting lock.
    Locked {
        /// The lock file that is held elsewhere.
        path: String,
    },
    /// This host cannot provide the requested lock.
    Unsupported {
        /// A stable record of what is unavailable and why.
        detail: &'static str,
    },
    /// The lock file could not be opened or the primitive failed.
    Io {
        /// The lock file involved.
        path: String,
        /// The underlying error description.
        message: String,
    },
}

impl GuardError {
    /// The stable, greppable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            GuardError::Locked { .. } => ERR_LOCKED,
            _ => ERR_UNSUPPORTED,
        }
    }

    /// The path involved, when one is known.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        match self {
            GuardError::Locked { path } | GuardError::Io { path, .. } => Some(path),
            GuardError::Unsupported { .. } => None,
        }
    }
}

impl fmt::Display for GuardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardError::Locked { path } => write!(formatter, "{ERR_LOCKED}: {path}"),
            GuardError::Unsupported { detail } => write!(formatter, "{ERR_UNSUPPORTED}: {detail}"),
            GuardError::Io { path, message } => {
                write!(formatter, "{ERR_UNSUPPORTED}: {path}: {message}")
            }
        }
    }
}

impl std::error::Error for GuardError {}

/// The conventional lock file inside a solution checkpoint root.
#[must_use]
pub fn default_lock_path(root: &Path) -> PathBuf {
    root.join("solution.lock")
}

/// A held lock. Dropping it releases the lock, because the operating-system
/// lock is owned by the open handle.
#[derive(Debug)]
pub struct SolutionGuard {
    file: File,
    mode: LockMode,
    path: PathBuf,
}

impl SolutionGuard {
    /// Take the platform lock on `path`.
    ///
    /// # Errors
    ///
    /// Returns [`GuardError::Locked`] when another participant holds a
    /// conflicting lock and [`GuardError::Io`] when the file cannot be used.
    pub fn acquire(path: &Path, mode: LockMode) -> Result<Self, GuardError> {
        Self::acquire_with(Backend::Native, path, mode)
    }

    /// Take a lock through an explicitly chosen mechanism.
    ///
    /// # Errors
    ///
    /// [`Backend::LocalOnly`] always returns [`GuardError::Unsupported`] with
    /// [`LOCAL_ONLY_DETAIL`], because a single-process lock cannot be observed
    /// by the other participants.
    pub fn acquire_with(backend: Backend, path: &Path, mode: LockMode) -> Result<Self, GuardError> {
        match backend {
            Backend::LocalOnly => Err(GuardError::Unsupported {
                detail: LOCAL_ONLY_DETAIL,
            }),
            Backend::Native => {
                let file = native::open_and_lock(path, mode)?;
                Ok(Self {
                    file,
                    mode,
                    path: path.to_path_buf(),
                })
            }
        }
    }

    /// The mode this guard holds.
    #[must_use]
    pub const fn mode(&self) -> LockMode {
        self.mode
    }

    /// Whether this guard is a reader lock.
    #[must_use]
    pub const fn is_shared(&self) -> bool {
        self.mode.is_shared()
    }

    /// The lock file this guard holds.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether another guard would be refused while this one is held.
    #[must_use]
    pub const fn excludes(&self, other: &Self) -> bool {
        self.mode.excludes(other.mode)
    }

    /// Release the lock explicitly. Dropping the guard does the same.
    ///
    /// # Errors
    ///
    /// Returns [`GuardError::Io`] when the platform refuses to release it.
    pub fn release(self) -> Result<(), GuardError> {
        native::unlock(&self.file)
    }
}

#[cfg(unix)]
use crate::locks_posix as native;
#[cfg(windows)]
use crate::locks_windows as native;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_readers_coexist_and_only_the_exclusive_writer_is_refused() {
        for held in LockMode::ALL {
            for asked in LockMode::ALL {
                let expected =
                    matches!(held, LockMode::Exclusive) || matches!(asked, LockMode::Exclusive);
                assert_eq!(held.excludes(asked), expected, "{held:?} then {asked:?}");
            }
        }
        assert!(!LockMode::Shared.excludes(LockMode::Shared));
    }

    #[test]
    fn an_in_process_only_lock_is_refused_as_a_solution_guard() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = default_lock_path(dir.path());
        let error = SolutionGuard::acquire_with(Backend::LocalOnly, &path, LockMode::Exclusive)
            .expect_err("local-only lock must be refused");
        assert_eq!(error.code(), ERR_UNSUPPORTED);
        assert_eq!(
            error,
            GuardError::Unsupported {
                detail: LOCAL_ONLY_DETAIL
            }
        );
        assert!(error.to_string().contains("in-process-only"));
    }

    #[test]
    fn a_second_conflicting_guard_is_refused_even_inside_one_process() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = default_lock_path(dir.path());
        let held = SolutionGuard::acquire(&path, LockMode::Shared).expect("first reader");
        assert!(held.is_shared());
        let second = SolutionGuard::acquire(&path, LockMode::Shared).expect("readers coexist");
        assert!(!held.excludes(&second));
        let blocked = SolutionGuard::acquire(&path, LockMode::Exclusive)
            .expect_err("writer must exclude readers");
        assert_eq!(blocked.code(), ERR_LOCKED);
        assert_eq!(blocked.path(), Some(path.to_string_lossy().as_ref()));
        drop(second);
        drop(held);
        let writer =
            SolutionGuard::acquire(&path, LockMode::Exclusive).expect("writer after release");
        assert_eq!(writer.mode(), LockMode::Exclusive);
    }

    #[test]
    fn releasing_a_guard_lets_the_next_participant_in() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("solution.lock");
        let guard = SolutionGuard::acquire(&path, LockMode::Exclusive).expect("writer");
        assert!(SolutionGuard::acquire(&path, LockMode::Shared).is_err());
        guard.release().expect("release");
        assert!(SolutionGuard::acquire(&path, LockMode::Shared).is_ok());
    }
}
