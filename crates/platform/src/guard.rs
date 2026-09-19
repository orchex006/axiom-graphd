//! Publisher, reader and collector guards (V2-018).
//!
//! This module implements the frozen ABI in
//! `contracts/native-reader-writer-guards.md` (contract v1). The cross-process
//! primitive itself is `graph_core::locks::SolutionGuard`, which is already
//! exercised by its own tests; everything the ABI adds on top lives here:
//!
//! - the exact lock-file names, acquisition and release order, and the bounded
//!   wait policy (`DEFAULT_TIMEOUT_MS` .. `MAX_TIMEOUT_MS`, retry 25 -> 250 ms);
//! - the one participant plan for publisher, collector and reader, including the
//!   reader's early admission release;
//! - all-or-nothing acquisition that releases every acquired guard in reverse
//!   order before reporting a bounded lock timeout;
//! - the retention GC decision that protects a reader-pinned generation and the
//!   current pointer.
//!
//! Two normative ABI details cannot be delegated to the shared primitive, so
//! they are enforced here:
//!
//! 1. the Windows share mode must be `FILE_SHARE_READ | FILE_SHARE_WRITE`
//!    *without* `FILE_SHARE_DELETE`, so no participant can replace a guard file
//!    while it is in use. A pinning handle opened with exactly that share mode is
//!    held for the whole guard lifetime.
//! 2. a reader releases admission before reading, so the payload copy does not
//!    hold admission against a publisher.
//!
//! Locks are OS-owned: a crash releases them because the kernel closes the
//! handles. No file content, PID record or `*.lock` body ever grants ownership.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::locks::{GuardError as NativeGuardError, LockMode, SolutionGuard};
use graph_core::paths::AxiomHome;

// ---------------------------------------------------------------------------
// Frozen ABI constants (contracts/native-reader-writer-guards.md, section 3).
// `tools/guard_contract_check.py` re-derives these from the contract file.
// ---------------------------------------------------------------------------

/// `contract_id` of the frozen block.
pub const CONTRACT_ID: &str = "axiom-native-reader-writer-guards";
/// `contract_version` of the frozen block.
pub const CONTRACT_VERSION: u32 = 1;
/// `spec_version` of the frozen block.
pub const SPEC_VERSION: &str = "2.0.0-draft.1";
/// The trusted private guard directory name (section 1).
pub const GUARD_DIR_NAME: &str = "solution.guard";
/// Admission lock file name.
pub const ADMISSION_LOCK_NAME: &str = "admission.lock";
/// Data lock file name.
pub const DATA_LOCK_NAME: &str = "data.lock";
/// Normative acquisition order: admission, then data.
pub const ACQUISITION_ORDER: [&str; 2] = [ADMISSION_LOCK_NAME, DATA_LOCK_NAME];
/// Normative release order: data, then admission.
pub const RELEASE_ORDER: [&str; 2] = [DATA_LOCK_NAME, ADMISSION_LOCK_NAME];
/// POSIX primitive.
pub const POSIX_PRIMITIVE: &str = "flock";
/// POSIX scope.
pub const POSIX_SCOPE: &str = "whole-file";
/// POSIX shared mode.
pub const POSIX_SHARED: &str = "LOCK_SH";
/// POSIX exclusive mode.
pub const POSIX_EXCLUSIVE: &str = "LOCK_EX";
/// Windows primitive.
pub const WINDOWS_PRIMITIVE: &str = "LockFileEx";
/// Windows byte range.
pub const WINDOWS_BYTE_RANGE: &str = "offset 0, length 1";
/// Windows open mode.
pub const WINDOWS_OPEN_MODE: &str = "OPEN_ALWAYS";
/// Windows share mode that must be used.
pub const WINDOWS_SHARE_MODE: &str = "FILE_SHARE_READ | FILE_SHARE_WRITE";
/// Windows share-mode bit that must be excluded.
pub const WINDOWS_SHARE_EXCLUDES: &str = "FILE_SHARE_DELETE";
/// Windows exclusive flag.
pub const WINDOWS_EXCLUSIVE_FLAG: &str = "LOCKFILE_EXCLUSIVE_LOCK";
/// Windows non-blocking flag.
pub const WINDOWS_CANCEL_FLAG: &str = "LOCKFILE_FAIL_IMMEDIATELY";
/// Windows release step.
pub const WINDOWS_RELEASE: &str = "UnlockFileEx matching range, then close every handle";
/// No shared -> exclusive upgrade is permitted.
pub const NO_UPGRADE: bool = true;
/// No recursive acquisition of the same instance in one path.
pub const NO_RECURSIVE_ACQUIRE: bool = true;
/// The default operation holds one solution guard.
pub const SINGLE_GUARD_DEFAULT: bool = true;
/// Unbounded blocking is not permitted.
pub const UNBOUNDED_BLOCKING_ALLOWED: bool = false;
/// Cancellation is supported between attempts.
pub const CANCEL_SUPPORTED: bool = true;
/// Default acquisition timeout.
pub const DEFAULT_TIMEOUT_MS: u64 = 5_000;
/// Largest permitted single wait.
pub const MAX_TIMEOUT_MS: u64 = 60_000;
/// First retry interval.
pub const RETRY_INITIAL_MS: u64 = 25;
/// Largest retry interval.
pub const RETRY_MAX_MS: u64 = 250;
/// A PID file is not ownership.
pub const PID_FILE_IS_OWNERSHIP: bool = false;
/// Lock-file content is not ownership.
pub const LOCK_FILE_CONTENT_IS_OWNERSHIP: bool = false;
/// A stale PID is not a live holder.
pub const STALE_PID_IS_LIVE_HOLDER: bool = false;
/// Stable empty lock files may persist.
pub const STABLE_EMPTY_FILES_MAY_PERSIST: bool = true;
/// Removing a guard file requires every participating process to have stopped.
pub const REMOVAL_REQUIRES_ALL_STOPPED: bool = true;
/// Crash release mechanism.
pub const CRASH_RELEASE_MECHANISM: &str = "process termination releases OS-owned locks";
/// What a timeout must do.
pub const ON_TIMEOUT: &str = "release every acquired guard in reverse acquisition order, report a bounded lock-timeout and retry from the start of the acquisition order";
/// Languages that must interoperate over the same files.
pub const INTEROP_LANGUAGES: [&str; 2] = ["rust", "python"];
/// Interoperability must be observed in distinct processes.
pub const INTEROP_DISTINCT_PROCESSES: bool = true;
/// SHA-256 of the frozen `frozen_fields` subset.
pub const PROTOCOL_DIGEST: &str =
    "06fadbdcd8ef4fba9573b10f838f060bc23652286ba757061249737b1d717f8a";
/// Retention GC protects referenced generations.
pub const GC_PROTECTS_REFERENCED_GENERATIONS: bool = true;
/// Retention GC never recursively follows a link.
pub const GC_NEVER_FOLLOWS_LINKS: bool = true;

/// Stable error code: a bounded lock timeout.
pub const ERR_GUARD_TIMEOUT: &str = "guard-lock-timeout";
/// Stable error code: the wait was cancelled.
pub const ERR_GUARD_CANCELLED: &str = "guard-cancelled";
/// Stable error code: the guard directory could not be prepared.
pub const ERR_GUARD_DIR: &str = "guard-directory";
/// Stable error code: the ABI share-mode pin could not be held.
pub const ERR_GUARD_PIN: &str = "guard-share-mode-pin";

/// One of the two stable lock files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GuardRole {
    /// `admission.lock` - acquired first.
    Admission,
    /// `data.lock` - acquired second.
    Data,
}

impl GuardRole {
    /// Both roles, in acquisition order.
    pub const ALL: [GuardRole; 2] = [GuardRole::Admission, GuardRole::Data];

    /// The lock file name for this role.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::Admission => ADMISSION_LOCK_NAME,
            Self::Data => DATA_LOCK_NAME,
        }
    }

    /// The `role` value used by the frozen contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::Data => "data",
        }
    }
}

/// One step of a participant's acquisition plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardRequest {
    /// Which lock file.
    pub role: GuardRole,
    /// Shared or exclusive.
    pub mode: LockMode,
}

/// Who is taking guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Participant {
    /// Publishes a new generation: exclusive admission, then exclusive data.
    Publisher,
    /// Retention GC: exclusive admission, then exclusive data.
    Collector,
    /// Reads a pinned generation: shared admission, then shared data.
    Reader,
}

impl Participant {
    /// Stable name used in diagnostics and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Publisher => "publisher",
            Self::Collector => "collector",
            Self::Reader => "reader",
        }
    }

    /// The acquisition plan, in the one normative order.
    #[must_use]
    pub const fn plan(self) -> [GuardRequest; 2] {
        let admission_exclusive = GuardRequest {
            role: GuardRole::Admission,
            mode: LockMode::Exclusive,
        };
        let admission_shared = GuardRequest {
            role: GuardRole::Admission,
            mode: LockMode::Shared,
        };
        let data_exclusive = GuardRequest {
            role: GuardRole::Data,
            mode: LockMode::Exclusive,
        };
        let data_shared = GuardRequest {
            role: GuardRole::Data,
            mode: LockMode::Shared,
        };
        match self {
            Self::Publisher | Self::Collector => [admission_exclusive, data_exclusive],
            Self::Reader => [admission_shared, data_shared],
        }
    }

    /// True when the participant releases admission before using the payload
    /// (the reader, contract section 5).
    #[must_use]
    pub const fn releases_admission_before_payload(self) -> bool {
        matches!(self, Self::Reader)
    }
}

/// The bound on one acquisition attempt sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedWait {
    timeout_ms: u64,
    retry_initial_ms: u64,
    retry_max_ms: u64,
}

impl Default for BoundedWait {
    fn default() -> Self {
        Self::standard()
    }
}

impl BoundedWait {
    /// The ABI default: 5000 ms, retrying from 25 ms up to 250 ms.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            timeout_ms: DEFAULT_TIMEOUT_MS,
            retry_initial_ms: RETRY_INITIAL_MS,
            retry_max_ms: RETRY_MAX_MS,
        }
    }

    /// A bounded wait with an explicit timeout.
    ///
    /// # Errors
    /// Returns [`AcquireError::TimeoutOutOfRange`] for `0` or anything above
    /// [`MAX_TIMEOUT_MS`]: unbounded blocking is not permitted.
    pub fn new(timeout_ms: u64) -> Result<Self, AcquireError> {
        if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
            return Err(AcquireError::TimeoutOutOfRange { timeout_ms });
        }
        Ok(Self {
            timeout_ms,
            ..Self::standard()
        })
    }

    /// The configured timeout.
    #[must_use]
    pub const fn timeout_ms(self) -> u64 {
        self.timeout_ms
    }

    /// The retry backoff, starting at the initial interval and doubling to the
    /// cap. The iterator is unbounded by design: the caller stops on the timeout
    /// or on cancellation, never on an attempt count.
    #[must_use]
    pub const fn retry_delays(self) -> RetryDelays {
        RetryDelays {
            next_ms: self.retry_initial_ms,
            max_ms: self.retry_max_ms,
        }
    }

    /// What a timeout must do.
    #[must_use]
    pub const fn on_timeout(self) -> &'static str {
        ON_TIMEOUT
    }
}

/// Doubling retry backoff capped at the configured maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryDelays {
    next_ms: u64,
    max_ms: u64,
}

impl Iterator for RetryDelays {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next_ms.min(self.max_ms);
        self.next_ms = self.next_ms.saturating_mul(2).min(self.max_ms);
        Some(current)
    }
}

/// Monotonic clock in milliseconds since the wait began.
pub trait Clock {
    /// Milliseconds since this wait started.
    fn elapsed_ms(&self) -> u64;
}

/// The real monotonic clock.
#[derive(Debug)]
pub struct RealClock {
    start: Instant,
}

impl Default for RealClock {
    fn default() -> Self {
        Self::new()
    }
}

impl RealClock {
    /// Start the clock now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Clock for RealClock {
    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// The wait between attempts, injected so the bounded wait is testable.
pub trait Sleeper {
    /// Wait for `ms` milliseconds.
    fn sleep_ms(&mut self, ms: u64);
}

/// Sleeps for real.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealSleeper;

impl Sleeper for RealSleeper {
    fn sleep_ms(&mut self, ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

/// Records the requested waits without sleeping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordingSleeper {
    /// Every requested interval, in order.
    pub waits: Vec<u64>,
    /// The accumulated wait.
    pub total_ms: u64,
}

impl Sleeper for RecordingSleeper {
    fn sleep_ms(&mut self, ms: u64) {
        self.waits.push(ms);
        self.total_ms = self.total_ms.saturating_add(ms);
    }
}

/// Cancellation observed between attempts.
pub trait CancelToken {
    /// True when the wait must stop.
    fn is_cancelled(&self) -> bool;
}

/// A token that is never cancelled.
#[derive(Debug, Clone, Copy, Default)]
pub struct NeverCancelled;

impl CancelToken for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// A token another thread can trip.
#[derive(Debug, Default)]
pub struct CancelFlag {
    cancelled: std::sync::atomic::AtomicBool,
}

impl CancelFlag {
    /// A fresh, un-cancelled flag.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark the wait as cancelled.
    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl CancelToken for CancelFlag {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Why a guard could not be held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquireError {
    /// The requested bound is outside the ABI range.
    TimeoutOutOfRange {
        /// The rejected value.
        timeout_ms: u64,
    },
    /// The bounded wait expired; every acquired guard was already released.
    LayerTimedOut {
        /// The guard that could not be taken.
        role: GuardRole,
        /// The bound that expired.
        timeout_ms: u64,
    },
    /// The wait was cancelled; every acquired guard was already released.
    Cancelled {
        /// The guard that could not be taken.
        role: GuardRole,
    },
    /// The native primitive refused or failed.
    Native {
        /// The guard involved.
        role: GuardRole,
        /// The primitive error.
        error: NativeGuardError,
    },
    /// The ABI share-mode pin could not be held for the guard lifetime.
    AbiPin {
        /// The guard involved.
        role: GuardRole,
        /// The lock file.
        path: String,
        /// What the host reported.
        message: String,
    },
    /// The guard directory could not be prepared.
    GuardDir {
        /// The guard directory.
        path: String,
        /// What the host reported.
        message: String,
    },
}

impl AcquireError {
    /// The stable, greppable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TimeoutOutOfRange { .. } | Self::LayerTimedOut { .. } => ERR_GUARD_TIMEOUT,
            Self::Cancelled { .. } => ERR_GUARD_CANCELLED,
            Self::Native { error, .. } => error.code(),
            Self::AbiPin { .. } => ERR_GUARD_PIN,
            Self::GuardDir { .. } => ERR_GUARD_DIR,
        }
    }

    /// The guard role involved.
    #[must_use]
    pub const fn role(&self) -> Option<GuardRole> {
        match self {
            Self::TimeoutOutOfRange { .. } => None,
            Self::LayerTimedOut { role, .. }
            | Self::Cancelled { role }
            | Self::Native { role, .. }
            | Self::AbiPin { role, .. } => Some(*role),
            Self::GuardDir { .. } => None,
        }
    }

    /// The shared typed error for this failure.
    #[must_use]
    pub fn to_axiom_error(&self) -> AxiomError {
        match self {
            Self::TimeoutOutOfRange { timeout_ms } => AxiomError::new(
                ErrorCode::Internal,
                "guard timeout is outside the supported bound",
            )
            .with_detail("observed", timeout_ms.to_string())
            .with_detail("expected", format!("<= {MAX_TIMEOUT_MS}")),
            Self::LayerTimedOut { role, timeout_ms } => AxiomError::new(
                ErrorCode::WriterAlreadyRunning,
                "another participant holds the solution guard",
            )
            .with_detail("component", role.as_str())
            .with_detail("observed", format!("{timeout_ms} ms"))
            .with_detail("rule", ON_TIMEOUT),
            Self::Cancelled { role } => {
                AxiomError::new(ErrorCode::ShuttingDown, "guard wait cancelled")
                    .with_detail("component", role.as_str())
            }
            Self::Native { role, error } => {
                AxiomError::new(ErrorCode::WriterAlreadyRunning, error.to_string())
                    .with_detail("component", role.as_str())
                    .with_detail("rule", error.code())
            }
            Self::AbiPin {
                role,
                path,
                message,
            } => AxiomError::new(
                ErrorCode::Internal,
                "guard share-mode pin could not be held",
            )
            .with_detail("role", role.as_str())
            .with_detail("observed", format!("{path}: {message}")),
            Self::GuardDir { path, message } => {
                AxiomError::new(ErrorCode::ConfigInvalid, "guard directory is unusable")
                    .with_detail("observed", format!("{path}: {message}"))
            }
        }
    }
}

impl std::fmt::Display for AcquireError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimeoutOutOfRange { timeout_ms } => write!(
                formatter,
                "{}: {timeout_ms} ms is outside the supported bound",
                self.code()
            ),
            Self::LayerTimedOut { role, timeout_ms } => write!(
                formatter,
                "{}: {} timed out after {timeout_ms} ms",
                self.code(),
                role.as_str()
            ),
            Self::Cancelled { role } => {
                write!(
                    formatter,
                    "{}: {} wait cancelled",
                    self.code(),
                    role.as_str()
                )
            }
            Self::Native { role, error } => {
                write!(formatter, "{}: {}: {error}", self.code(), role.as_str())
            }
            Self::AbiPin { role, message, .. } => {
                write!(formatter, "{}: {}: {message}", self.code(), role.as_str())
            }
            Self::GuardDir { message, .. } => write!(formatter, "{}: {message}", self.code()),
        }
    }
}

impl std::error::Error for AcquireError {}

/// The trusted private guard directory of one registered solution instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardDir {
    path: PathBuf,
}

impl GuardDir {
    /// `<AXIOM_HOME>/instances/<workspace-instance-id>/solution.guard`.
    ///
    /// # Errors
    /// Returns [`ErrorCode::ValidationError`] for a non-portable instance id.
    pub fn from_home(home: &AxiomHome, instance_id: &str) -> Result<Self, AxiomError> {
        Ok(Self {
            path: home.instance_guard(instance_id)?,
        })
    }

    /// A guard directory at an explicit path (tests and adapters).
    #[must_use]
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The guard directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The lock file path for one role.
    #[must_use]
    pub fn lock_path(&self, role: GuardRole) -> PathBuf {
        self.path.join(role.file_name())
    }

    /// Both lock file paths, in acquisition order.
    #[must_use]
    pub fn lock_paths(&self) -> [PathBuf; 2] {
        [
            self.lock_path(GuardRole::Admission),
            self.lock_path(GuardRole::Data),
        ]
    }

    /// Create the guard directory when it does not exist.
    ///
    /// # Errors
    /// Returns [`AcquireError::GuardDir`] when the path exists and is not a
    /// directory, or when the directory cannot be created.
    pub fn ensure(&self) -> Result<(), AcquireError> {
        match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.is_dir() => return Ok(()),
            Ok(_) => {
                return Err(AcquireError::GuardDir {
                    path: self.path.display().to_string(),
                    message: "guard path exists and is not a directory".to_string(),
                });
            }
            Err(_) => {}
        }
        std::fs::create_dir_all(&self.path).map_err(|error| AcquireError::GuardDir {
            path: self.path.display().to_string(),
            message: error.to_string(),
        })
    }

    /// Take one native guard without waiting.
    ///
    /// # Errors
    /// Returns [`AcquireError::Native`] with the primitive's refusal, or
    /// [`AcquireError::AbiPin`] when the ABI share-mode pin cannot be held.
    pub fn try_acquire(&self, role: GuardRole, mode: LockMode) -> Result<HeldGuard, AcquireError> {
        self.ensure()?;
        let path = self.lock_path(role);
        let pin = hold_share_mode_pin(role, &path)?;
        let native = SolutionGuard::acquire(&path, mode)
            .map_err(|error| AcquireError::Native { role, error })?;
        Ok(HeldGuard {
            role,
            mode,
            path,
            native,
            pin,
        })
    }

    /// Take one native guard under the bounded wait policy.
    ///
    /// # Errors
    /// Returns [`AcquireError::LayerTimedOut`] or [`AcquireError::Cancelled`]
    /// when the wait ends without the guard; nothing is left held.
    pub fn acquire_bounded(
        &self,
        role: GuardRole,
        mode: LockMode,
        wait: BoundedWait,
        clock: &dyn Clock,
        sleeper: &mut dyn Sleeper,
        cancel: &dyn CancelToken,
    ) -> Result<HeldGuard, AcquireError> {
        let mut delays = wait.retry_delays();
        loop {
            if cancel.is_cancelled() {
                return Err(AcquireError::Cancelled { role });
            }
            match self.try_acquire(role, mode) {
                Ok(guard) => return Ok(guard),
                Err(AcquireError::Native {
                    error: NativeGuardError::Locked { .. },
                    ..
                }) => {
                    let elapsed = clock.elapsed_ms();
                    if elapsed >= wait.timeout_ms() {
                        return Err(AcquireError::LayerTimedOut {
                            role,
                            timeout_ms: wait.timeout_ms(),
                        });
                    }
                    let delay = delays.next().unwrap_or(RETRY_MAX_MS);
                    sleeper.sleep_ms(delay.min(wait.timeout_ms().saturating_sub(elapsed)));
                }
                Err(other) => return Err(other),
            }
        }
    }

    /// The publisher/collector plan: exclusive admission, then exclusive data.
    ///
    /// All-or-nothing: on any failure every already-acquired guard is released in
    /// reverse acquisition order before the error is returned.
    ///
    /// # Errors
    /// Returns the failure of the first step that could not be completed.
    pub fn acquire_exclusive(
        &self,
        wait: BoundedWait,
        clock: &dyn Clock,
        sleeper: &mut dyn Sleeper,
        cancel: &dyn CancelToken,
    ) -> Result<ExclusiveGuardSet, AcquireError> {
        let mut held: Vec<HeldGuard> = Vec::with_capacity(2);
        for request in Participant::Publisher.plan() {
            match self.acquire_bounded(request.role, request.mode, wait, clock, sleeper, cancel) {
                Ok(guard) => held.push(guard),
                Err(error) => {
                    release_in_reverse_order(held);
                    return Err(error);
                }
            }
        }
        Ok(ExclusiveGuardSet { guards: held })
    }

    /// The reader plan: shared admission, then shared data.
    ///
    /// # Errors
    /// Returns the failure of the first step that could not be completed; on
    /// failure the admission guard is released before returning.
    pub fn acquire_reader(
        &self,
        wait: BoundedWait,
        clock: &dyn Clock,
        sleeper: &mut dyn Sleeper,
        cancel: &dyn CancelToken,
    ) -> Result<ReaderGuards, AcquireError> {
        let admission = self.acquire_bounded(
            GuardRole::Admission,
            LockMode::Shared,
            wait,
            clock,
            sleeper,
            cancel,
        )?;
        match self.acquire_bounded(
            GuardRole::Data,
            LockMode::Shared,
            wait,
            clock,
            sleeper,
            cancel,
        ) {
            Ok(data) => Ok(ReaderGuards {
                admission: Some(admission),
                data,
            }),
            Err(error) => {
                release_in_reverse_order(vec![admission]);
                Err(error)
            }
        }
    }
}

/// Hold a handle on `path` whose share mode is exactly the ABI share mode.
///
/// On Windows the ABI share mode excludes `FILE_SHARE_DELETE`, so holding a
/// handle opened that way for the whole guard lifetime is what refuses a delete
/// or rename of a guard file that is in use. `OPEN_ALWAYS` is expressed as
/// `create(true)` on an existing-or-new file. POSIX has no share mode: a
/// whole-file `flock` plus normal directory permissions is the ABI behaviour.
#[cfg(windows)]
fn hold_share_mode_pin(
    role: GuardRole,
    path: &Path,
) -> Result<Option<std::fs::File>, AcquireError> {
    use std::os::windows::fs::OpenOptionsExt;

    /// `FILE_SHARE_READ | FILE_SHARE_WRITE`, deliberately without
    /// `FILE_SHARE_DELETE`.
    const ABI_SHARE_MODE: u32 = 0x0000_0001 | 0x0000_0002;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .share_mode(ABI_SHARE_MODE)
        .open(path)
        .map_err(|error| AcquireError::AbiPin {
            role,
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    Ok(Some(file))
}

#[cfg(not(windows))]
fn hold_share_mode_pin(
    _role: GuardRole,
    _path: &Path,
) -> Result<Option<std::fs::File>, AcquireError> {
    Ok(None)
}

/// One held guard.
#[derive(Debug)]
pub struct HeldGuard {
    role: GuardRole,
    mode: LockMode,
    path: PathBuf,
    native: SolutionGuard,
    pin: Option<std::fs::File>,
}

impl HeldGuard {
    /// Which lock file is held.
    #[must_use]
    pub const fn role(&self) -> GuardRole {
        self.role
    }

    /// The holding mode.
    #[must_use]
    pub const fn mode(&self) -> LockMode {
        self.mode
    }

    /// The lock file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True when the ABI share-mode pin is held.
    ///
    /// The pin is required and therefore always held on Windows; on POSIX the
    /// ABI uses a whole-file `flock` and there is no share mode to pin.
    #[must_use]
    pub fn share_mode_pinned(&self) -> bool {
        cfg!(windows) && self.pin.is_some()
    }

    /// True when this host's ABI requires a share-mode pin.
    #[must_use]
    pub const fn share_mode_pin_required() -> bool {
        cfg!(windows)
    }

    /// Release explicitly. Dropping is equivalent: the OS owns the lock.
    ///
    /// # Errors
    /// Returns the primitive error when the unlock call fails; the handle is
    /// closed either way.
    pub fn release(self) -> Result<(), NativeGuardError> {
        self.native.release()
    }
}

/// Release a set of guards in the normative reverse acquisition order.
fn release_in_reverse_order(mut guards: Vec<HeldGuard>) {
    while let Some(guard) = guards.pop() {
        let _ = guard.release();
    }
}

/// The publisher/collector guard set: both guards are exclusive.
#[derive(Debug)]
pub struct ExclusiveGuardSet {
    guards: Vec<HeldGuard>,
}

impl ExclusiveGuardSet {
    /// The held roles, in acquisition order.
    #[must_use]
    pub fn roles(&self) -> Vec<GuardRole> {
        self.guards.iter().map(HeldGuard::role).collect()
    }

    /// The data guard, the one a publication phase runs under.
    ///
    /// # Panics
    /// Panics only if the set was constructed without the data guard, which
    /// [`GuardDir::acquire_exclusive`] does not do.
    #[must_use]
    pub fn data(&self) -> &HeldGuard {
        self.guards
            .last()
            .expect("the exclusive set always holds the data guard")
    }

    /// True when both guards are held exclusively.
    #[must_use]
    pub fn holds_both_exclusive(&self) -> bool {
        self.guards.len() == 2
            && self
                .guards
                .iter()
                .all(|guard| guard.mode() == LockMode::Exclusive)
    }

    /// Release in the normative order: data, then admission.
    pub fn release(self) {
        release_in_reverse_order(self.guards);
    }
}

/// The reader's guards: admission is released before the payload is copied.
#[derive(Debug)]
pub struct ReaderGuards {
    admission: Option<HeldGuard>,
    data: HeldGuard,
}

impl ReaderGuards {
    /// The admission mode still held, or `None` after the early release.
    #[must_use]
    pub fn admission_mode(&self) -> Option<LockMode> {
        self.admission.as_ref().map(HeldGuard::mode)
    }

    /// The data guard.
    #[must_use]
    pub fn data(&self) -> &HeldGuard {
        &self.data
    }

    /// Release admission while the data guard stays held (contract section 5).
    ///
    /// # Errors
    /// Returns the primitive error when the unlock call fails.
    pub fn release_admission(&mut self) -> Result<(), NativeGuardError> {
        match self.admission.take() {
            Some(guard) => guard.release(),
            None => Ok(()),
        }
    }

    /// Release the remaining guard.
    ///
    /// # Errors
    /// Returns the primitive error when the unlock call fails.
    pub fn release(self) -> Result<(), NativeGuardError> {
        let Self { admission, data } = self;
        let early = admission.map_or(Ok(()), HeldGuard::release);
        let remaining = data.release();
        early.and(remaining)
    }
}

/// The guard observation a retention decision is made under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuardObservation {
    /// The admission mode currently held, if any.
    pub admission: Option<LockMode>,
    /// The data mode currently held, if any.
    pub data: Option<LockMode>,
}

impl GuardObservation {
    /// The observation of a held exclusive guard set.
    #[must_use]
    pub const fn exclusive() -> Self {
        Self {
            admission: Some(LockMode::Exclusive),
            data: Some(LockMode::Exclusive),
        }
    }

    /// True when both guards are held exclusively.
    #[must_use]
    pub const fn is_exclusive_on_both(self) -> bool {
        matches!(self.admission, Some(LockMode::Exclusive))
            && matches!(self.data, Some(LockMode::Exclusive))
    }
}

/// What a retention pass must never delete.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcProtection {
    /// The generation the currently published pointer names.
    pub current_pointer: Option<String>,
    /// Generations a live reader pinned.
    pub reader_pinned: Vec<String>,
    /// Any partially exposed pointer target: the publication is not complete, so
    /// no retention pass may run.
    pub partially_exposed: Vec<String>,
}

/// Why a retention pass refused to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcRefusal {
    /// No guard is held at all.
    NoGuard,
    /// A guard is held, but not exclusively on both lock files.
    NotExclusive,
    /// The current pointer is only partially exposed.
    PointerPartiallyExposed,
}

impl GcRefusal {
    /// Stable name used in diagnostics and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoGuard => "gc-without-guard",
            Self::NotExclusive => "gc-guard-not-exclusive",
            Self::PointerPartiallyExposed => "gc-pointer-partially-exposed",
        }
    }

    /// The shared typed error for this refusal.
    #[must_use]
    pub fn to_axiom_error(self) -> AxiomError {
        AxiomError::new(
            ErrorCode::Conflict,
            "retention refused: the guard protocol forbids this deletion",
        )
        .with_detail("rule", self.as_str())
    }
}

impl std::fmt::Display for GcRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.as_str())
    }
}

/// The deletion decision of a retention pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcPlan {
    /// Candidates that are unreferenced and may be removed.
    pub deletable: Vec<String>,
    /// Candidates that are referenced and must be kept.
    pub retained: Vec<String>,
}

/// Decide which candidate generations a retention pass may remove.
///
/// The caller must already hold the exclusive guard set; the observation is part
/// of the input so a caller that skipped the guard cannot delete by accident. The
/// pass itself never recursively follows a link (`GC_NEVER_FOLLOWS_LINKS`): the
/// deletion of `deletable` happens at the returned path only.
///
/// # Errors
/// Returns [`GcRefusal`] when the guard is insufficient or the pointer is only
/// partially exposed.
pub fn plan_gc(
    observation: GuardObservation,
    protection: &GcProtection,
    candidates: &[String],
) -> Result<GcPlan, GcRefusal> {
    if observation.admission.is_none() && observation.data.is_none() {
        return Err(GcRefusal::NoGuard);
    }
    if !observation.is_exclusive_on_both() {
        return Err(GcRefusal::NotExclusive);
    }
    if !protection.partially_exposed.is_empty() {
        return Err(GcRefusal::PointerPartiallyExposed);
    }

    let mut protected: Vec<&str> = Vec::new();
    if let Some(current) = protection.current_pointer.as_deref() {
        protected.push(current);
    }
    protected.extend(protection.reader_pinned.iter().map(String::as_str));

    let mut deletable = Vec::new();
    let mut retained = Vec::new();
    for candidate in candidates {
        if protected.contains(&candidate.as_str()) {
            retained.push(candidate.clone());
        } else {
            deletable.push(candidate.clone());
        }
    }
    Ok(GcPlan {
        deletable,
        retained,
    })
}
