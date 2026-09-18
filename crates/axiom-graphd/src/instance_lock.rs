//! Single-owner instance lock and dead-owner recovery (task B-004).
//!
//! The Axiom architecture keeps exactly one writer per Axiom home, and one
//! writer per bound output namespace. This module implements the first half: the
//! home-level daemon lock.
//!
//! The lock is a real cross-process object, not a convention:
//!
//! * `run/daemon.lock` is opened exclusively and held open for the whole
//!   lifetime of the daemon. On Windows the handle is opened with
//!   `share_mode(0)`, so the operating system refuses a second open and releases
//!   the claim automatically when the owning process exits, including after a
//!   crash.
//! * `run/daemon.owner.json` is a *readable* record (`format`, `holder`, `pid`,
//!   `started_at`, `host`) so a refused daemon can report who holds the home
//!   instead of failing anonymously.
//!
//! Recovery never terminates another process. A stale claim is only taken over
//! when the operating system reports the recorded owner as gone; if liveness
//! cannot be determined the claim is respected and the caller is told to inspect
//! it. Recovering an abandoned lock and killing an unrelated process are
//! different operations, and only the first one is allowed here.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::AxiomHome;
use serde::{Deserialize, Serialize};

/// Format marker of the lock record.
pub const LOCK_FORMAT: &str = "axiom-daemon-lock-v1";

/// Name of the readable owner record next to the lock file.
pub const OWNER_RECORD_FILE: &str = "daemon.owner.json";

/// The readable owner record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockRecord {
    /// Always [`LOCK_FORMAT`]; another value means the file is not an Axiom lock.
    pub format: String,
    /// Instance or operator that owns the home.
    pub holder: String,
    /// Process id of the owner; diagnostics only, never a termination target.
    pub pid: u32,
    /// UTC time the owner took the lock.
    pub started_at: String,
    /// Host the owner runs on.
    pub host: String,
}

impl LockRecord {
    /// Build a record.
    #[must_use]
    pub fn new(holder: &str, pid: u32, started_at: &str, host: &str) -> Self {
        Self {
            format: String::from(LOCK_FORMAT),
            holder: holder.to_string(),
            pid,
            started_at: started_at.to_string(),
            host: host.to_string(),
        }
    }

    /// Whether this file is an Axiom lock record.
    #[must_use]
    pub fn is_axiom_record(&self) -> bool {
        self.format == LOCK_FORMAT
    }
}

/// The held instance lock.
///
/// Dropping the value releases the claim: the exclusive handle closes and the
/// readable record is removed.
#[derive(Debug)]
pub struct DaemonLock {
    lock_path: PathBuf,
    record_path: PathBuf,
    handle: File,
    record: LockRecord,
}

impl DaemonLock {
    /// Take the single-owner lock for `home`.
    ///
    /// # Errors
    /// - [`ErrorCode::WriterAlreadyRunning`] when another live owner holds the
    ///   home, or when a claim exists whose owner liveness cannot be determined.
    /// - [`ErrorCode::Internal`] when the run directory or the lock files cannot
    ///   be created.
    pub fn acquire(home: &AxiomHome, holder: &str) -> Result<Self, AxiomError> {
        let lock_path = home.daemon_lock();
        let record_path = owner_record_path(&lock_path);
        let run_dir = home.run_dir();
        std::fs::create_dir_all(&run_dir)
            .map_err(|error| storage_error("create the run directory", &error))?;

        let record = LockRecord::new(
            holder,
            std::process::id(),
            &graph_store::migrations::utc_timestamp(),
            &host_name(),
        );

        let mut handle = match open_exclusive(&lock_path) {
            Ok(handle) => handle,
            Err(error) => {
                if recover_stale_claim(&lock_path)? {
                    open_exclusive(&lock_path)
                        .map_err(|retry| conflict_error(&record_path, &retry))?
                } else {
                    return Err(conflict_error(&record_path, &error));
                }
            }
        };

        write_record(&mut handle, &record)?;
        write_owner_record(&record_path, &record)?;
        Ok(Self {
            lock_path,
            record_path,
            handle,
            record,
        })
    }

    /// Read the owner record for `home` without taking the lock.
    #[must_use]
    pub fn inspect(home: &AxiomHome) -> Option<LockRecord> {
        read_owner_record(&home.daemon_lock())
    }

    /// The record this owner published.
    #[must_use]
    pub fn record(&self) -> &LockRecord {
        &self.record
    }

    /// Path of the exclusive lock file.
    #[must_use]
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    /// Path of the readable owner record.
    #[must_use]
    pub fn record_path(&self) -> &Path {
        &self.record_path
    }

    /// The held exclusive handle; dropping it releases the claim.
    #[must_use]
    pub fn handle(&self) -> &File {
        &self.handle
    }
}

impl Drop for DaemonLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.record_path);
        #[cfg(not(windows))]
        {
            // The claim *is* the lock file where no exclusive share mode exists.
            let _ = std::fs::remove_file(&self.lock_path);
        }
    }
}

/// `run/daemon.owner.json` for a `run/daemon.lock` path.
#[must_use]
pub fn owner_record_path(lock_path: &Path) -> PathBuf {
    lock_path.with_file_name(OWNER_RECORD_FILE)
}

/// Open the lock file exclusively.
///
/// On Windows a zero share mode makes the kernel enforce uniqueness, so the
/// claim disappears automatically when the owner dies. On other platforms the
/// file is created exclusively, which is atomic on every supported filesystem.
#[cfg(windows)]
fn open_exclusive(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        // The record is rewritten in place through the held handle, so the
        // open must never truncate what a refusal diagnosis could still read.
        .truncate(false)
        .share_mode(0)
        .open(path)
}

#[cfg(not(windows))]
fn open_exclusive(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

/// Whether an abandoned claim could be taken over.
#[cfg(windows)]
fn recover_stale_claim(_lock_path: &Path) -> Result<bool, AxiomError> {
    // The exclusive handle is released by the kernel when the owner exits, so a
    // failed open already means a live owner. Nothing to recover, and nothing to
    // terminate.
    Ok(false)
}

#[cfg(not(windows))]
fn recover_stale_claim(lock_path: &Path) -> Result<bool, AxiomError> {
    let Some(record) = read_owner_record(lock_path) else {
        return Ok(false);
    };
    match owner_is_alive(record.pid) {
        Some(false) => {
            std::fs::remove_file(lock_path)
                .map_err(|error| storage_error("remove an abandoned lock file", &error))?;
            Ok(true)
        }
        // Alive, or undeterminable: respect the claim. Never kill a process.
        _ => Ok(false),
    }
}

/// Whether `pid` is alive, when the host can tell without side effects.
#[cfg(target_os = "linux")]
fn owner_is_alive(pid: u32) -> Option<bool> {
    Some(Path::new(&format!("/proc/{pid}")).exists())
}

/// Liveness is not determinable on this host, so a claim is always respected.
#[cfg(all(not(windows), not(target_os = "linux")))]
fn owner_is_alive(_pid: u32) -> Option<bool> {
    None
}

fn conflict_error(record_path: &Path, cause: &std::io::Error) -> AxiomError {
    let error = AxiomError::new(
        ErrorCode::WriterAlreadyRunning,
        "another axiom-graphd process already owns this Axiom home; refusing to become a second writer",
    );
    match read_record(record_path) {
        Some(record) => error.with_detail(
            "observed",
            format!(
                "holder={} pid={} host={} started_at={}",
                record.holder, record.pid, record.host, record.started_at
            ),
        ),
        None => error.with_detail("observed", format!("owner record unreadable: {cause}")),
    }
}

fn host_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| String::from("unknown"))
}

fn write_record(handle: &mut File, record: &LockRecord) -> Result<(), AxiomError> {
    let bytes = encode(record)?;
    handle
        .set_len(0)
        .map_err(|error| storage_error("truncate the lock file", &error))?;
    handle
        .seek(SeekFrom::Start(0))
        .map_err(|error| storage_error("rewind the lock file", &error))?;
    handle
        .write_all(&bytes)
        .map_err(|error| storage_error("write the lock record", &error))?;
    handle
        .sync_all()
        .map_err(|error| storage_error("flush the lock record", &error))
}

fn write_owner_record(path: &Path, record: &LockRecord) -> Result<(), AxiomError> {
    let bytes = encode(record)?;
    std::fs::write(path, bytes).map_err(|error| storage_error("write the owner record", &error))
}

fn encode(record: &LockRecord) -> Result<Vec<u8>, AxiomError> {
    let mut json = serde_json::to_string_pretty(record)
        .map_err(|error| storage_error("encode the lock record", &error))?;
    json.push('\n');
    Ok(json.into_bytes())
}

fn read_owner_record(lock_path: &Path) -> Option<LockRecord> {
    read_record(&owner_record_path(lock_path))
}

fn read_record(path: &Path) -> Option<LockRecord> {
    let text = std::fs::read_to_string(path).ok()?;
    let record: LockRecord = serde_json::from_str(&text).ok()?;
    record.is_axiom_record().then_some(record)
}

fn storage_error(context: &str, error: &dyn std::fmt::Display) -> AxiomError {
    AxiomError::new(ErrorCode::Internal, format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_core::error::ExitCode;
    use graph_core::paths::{PathEnvironment, Platform};

    fn home(directory: &tempfile::TempDir) -> AxiomHome {
        let environment = PathEnvironment {
            platform: Platform::Windows,
            axiom_home: Some(directory.path().to_string_lossy().into_owned()),
            ..PathEnvironment::default()
        };
        AxiomHome::resolve(&environment).expect("a temporary directory is a usable Axiom home")
    }

    #[test]
    fn a_second_owner_of_the_same_home_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let home = home(&directory);
        let first = DaemonLock::acquire(&home, "agent-01").expect("the first owner takes the lock");

        let error =
            DaemonLock::acquire(&home, "agent-02").expect_err("a second owner must be refused");
        assert_eq!(error.code(), ErrorCode::WriterAlreadyRunning);
        assert_eq!(error.exit_code(), ExitCode::LockUnavailable);
        assert_eq!(error.exit_code().as_i32(), 10);
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some(
                format!(
                    "holder=agent-01 pid={} host={} started_at={}",
                    std::process::id(),
                    first.record().host,
                    first.record().started_at
                )
                .as_str()
            )
        );

        drop(first);
        let third = DaemonLock::acquire(&home, "agent-03").expect("the claim is released on drop");
        assert_eq!(third.record().holder, "agent-03");
    }

    #[test]
    fn an_abandoned_record_is_recovered_without_killing_anything() {
        let directory = tempfile::tempdir().expect("temp dir");
        let home = home(&directory);
        std::fs::create_dir_all(home.run_dir()).expect("run dir");
        let ghost_pid = u32::MAX;
        let stale = LockRecord::new("crashed-agent", ghost_pid, "1970-01-01T00:00:00Z", "ghost");
        write_owner_record(&owner_record_path(&home.daemon_lock()), &stale)
            .expect("simulate a crashed owner");

        let lock = DaemonLock::acquire(&home, "agent-01").expect("a dead owner must not block");
        assert_eq!(lock.record().holder, "agent-01");
        assert_eq!(lock.record().pid, std::process::id());
        let observed = DaemonLock::inspect(&home).expect("the owner record is readable");
        assert_eq!(observed.holder, "agent-01");
        assert!(observed.is_axiom_record());
        // Recovery never signals a process: the claim is enforced by the
        // exclusive handle, so a second exclusive open fails while the owner
        // lives and succeeds once the owner releases it.
        assert!(
            open_exclusive(&home.daemon_lock()).is_err(),
            "a held claim must refuse a second exclusive open"
        );
        drop(lock);
        assert!(
            open_exclusive(&home.daemon_lock()).is_ok(),
            "releasing the owner must release the claim"
        );
    }

    #[test]
    fn the_lock_lives_under_the_home_that_owns_it() {
        let directory = tempfile::tempdir().expect("temp dir");
        let other_directory = tempfile::tempdir().expect("second temp dir");
        let first_home = home(&directory);
        let other = home(&other_directory);
        let lock = DaemonLock::acquire(&first_home, "agent-01").expect("lock");
        assert!(lock.lock_path().starts_with(first_home.run_dir()));
        assert!(lock.lock_path().ends_with("daemon.lock"));
        assert!(lock.record_path().ends_with(OWNER_RECORD_FILE));

        // A different home is a different registry: it is not blocked.
        let second = DaemonLock::acquire(&other, "agent-01").expect("a different home is free");
        assert_ne!(second.lock_path(), lock.lock_path());
    }

    #[test]
    fn foreign_or_unreadable_records_are_not_claimed_as_locks() {
        let directory = tempfile::tempdir().expect("temp dir");
        let home = home(&directory);
        assert!(DaemonLock::inspect(&home).is_none());
        std::fs::create_dir_all(home.run_dir()).expect("run dir");
        let path = owner_record_path(&home.daemon_lock());
        std::fs::write(&path, b"not json").expect("write");
        assert!(DaemonLock::inspect(&home).is_none());
        let foreign = LockRecord::new("x", 1, "t", "h");
        let json = serde_json::to_string(&foreign).expect("json");
        std::fs::write(&path, json.replace(LOCK_FORMAT, "other-format")).expect("write");
        assert!(DaemonLock::inspect(&home).is_none());
    }
}
