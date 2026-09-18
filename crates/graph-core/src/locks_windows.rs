#![allow(unsafe_code)]
//! Windows shared/exclusive solution guard (task B-074).
//!
//! `LockFileEx` is the only Windows primitive that provides both a shared
//! reader lock and an exclusive writer lock over one byte range of one file,
//! enforced by the kernel and therefore visible to every process.
//!
//! The file is opened with `FILE_SHARE_READ | FILE_SHARE_WRITE |
//! FILE_SHARE_DELETE` so that the intended readers can still open it and so
//! that a controlled replacement of the lock file is not blocked by the handle
//! share mode. Exclusion is provided by the byte-range lock, never by the
//! share mode.
//!
//! The lock is requested with `LOCKFILE_FAIL_IMMEDIATELY` so a conflicting
//! holder is reported as [`GuardError::Locked`] instead of blocking.
//!
//! `unsafe` is confined to these four FFI calls. `windows-sys` has no safe
//! wrapper, and the workspace lints deny `unsafe_code`, so this module carries
//! an explicit, recorded `#[allow(unsafe_code)]` and nothing else in the crate
//! may use `unsafe`.

use crate::locks::{GuardError, LockMode};
use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    LockFileEx, UnlockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
/// `ERROR_LOCK_VIOLATION`: the requested range is held by another handle.
const ERROR_LOCK_VIOLATION: i32 = 33;
/// One byte is enough to represent the whole-file lock.
const LOCK_BYTES: u32 = 1;

fn flags(mode: LockMode) -> u32 {
    let mut value = LOCKFILE_FAIL_IMMEDIATELY;
    if mode == LockMode::Exclusive {
        value |= LOCKFILE_EXCLUSIVE_LOCK;
    }
    value
}

fn blank_overlapped() -> OVERLAPPED {
    // SAFETY: `OVERLAPPED` is a plain-old-data structure; an all-zero value is
    // its documented "no offset, no event" form.
    unsafe { std::mem::zeroed() }
}

/// Open (creating if needed) and lock `path`.
pub fn open_and_lock(path: &Path, mode: LockMode) -> Result<File, GuardError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
        .map_err(|error| GuardError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    let mut overlapped = blank_overlapped();
    // SAFETY: the handle comes from an open `File` that outlives the call, the
    // range is one byte inside the file, and `overlapped` is a valid, exclusively
    // borrowed structure for the duration of the call.
    let acquired = unsafe {
        LockFileEx(
            file.as_raw_handle() as HANDLE,
            flags(mode),
            0,
            LOCK_BYTES,
            0,
            &mut overlapped,
        )
    };
    if acquired != 0 {
        return Ok(file);
    }
    let error = std::io::Error::last_os_error();
    Err(if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION) {
        GuardError::Locked {
            path: path.display().to_string(),
        }
    } else {
        GuardError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        }
    })
}

/// Release the lock held by `file`.
pub fn unlock(file: &File) -> Result<(), GuardError> {
    let mut overlapped = blank_overlapped();
    // SAFETY: the handle comes from an open `File` that outlives the call, the
    // same one-byte range is released, and `overlapped` is valid for the call.
    let released = unsafe {
        UnlockFileEx(
            file.as_raw_handle() as HANDLE,
            0,
            LOCK_BYTES,
            0,
            &mut overlapped,
        )
    };
    if released != 0 {
        Ok(())
    } else {
        Err(GuardError::Io {
            path: String::from("<released handle>"),
            message: std::io::Error::last_os_error().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locks::{SolutionGuard, ERR_LOCKED};
    use std::process::Command;

    /// Environment variable that turns a test binary into a lock probe.
    const PROBE_ENV: &str = "AXIOM_GUARD_PROBE";
    /// Exact test name of the probe child.
    const PROBE_TEST: &str = "locks_windows::tests::lock_probe_child";

    fn probe(path: &Path, mode: LockMode) -> String {
        let output = Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", PROBE_TEST, "--nocapture"])
            .env(
                PROBE_ENV,
                format!(
                    "{}:{}",
                    if mode.is_shared() {
                        "shared"
                    } else {
                        "exclusive"
                    },
                    path.display()
                ),
            )
            .output()
            .expect("spawn probe");
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        text
    }

    #[test]
    fn lock_probe_child() {
        let Some(spec) = std::env::var(PROBE_ENV).ok() else {
            return;
        };
        let (mode, path) = spec.split_once(':').expect("probe spec");
        let mode = if mode == "shared" {
            LockMode::Shared
        } else {
            LockMode::Exclusive
        };
        match SolutionGuard::acquire(Path::new(path), mode) {
            Ok(guard) => {
                println!("guard-probe:acquired");
                drop(guard);
            }
            Err(error) => println!("guard-probe:{}", error.code()),
        }
        std::process::exit(0);
    }

    #[test]
    fn lock_file_ex_interoperates_across_processes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("solution.lock");

        // An exclusive writer excludes a second process.
        let writer = SolutionGuard::acquire(&path, LockMode::Exclusive).expect("writer");
        let blocked = probe(&path, LockMode::Exclusive);
        assert!(blocked.contains(ERR_LOCKED), "child output: {blocked}");
        assert!(
            !blocked.contains("guard-probe:acquired"),
            "child output: {blocked}"
        );

        // The writer also excludes a reader in another process.
        let reader_blocked = probe(&path, LockMode::Shared);
        assert!(
            reader_blocked.contains(ERR_LOCKED),
            "child output: {reader_blocked}"
        );
        drop(writer);

        // After release a reader in another process is admitted again, which
        // shows the refusal was the lock and not a stale file.
        let admitted = probe(&path, LockMode::Shared);
        assert!(
            admitted.contains("guard-probe:acquired"),
            "child output: {admitted}"
        );
    }

    #[test]
    fn shared_readers_coexist_across_processes_while_the_writer_waits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("solution.lock");
        let reader = SolutionGuard::acquire(&path, LockMode::Shared).expect("reader");
        let second = probe(&path, LockMode::Shared);
        assert!(
            second.contains("guard-probe:acquired"),
            "child output: {second}"
        );
        let writer = probe(&path, LockMode::Exclusive);
        assert!(writer.contains(ERR_LOCKED), "child output: {writer}");
        drop(reader);
        let writer = probe(&path, LockMode::Exclusive);
        assert!(
            writer.contains("guard-probe:acquired"),
            "child output: {writer}"
        );
    }
}
