#![allow(unsafe_code)]
//! POSIX shared/exclusive solution guard (task B-073).
//!
//! `flock(2)` is used rather than `fcntl` record locks: it has the shared
//! reader / exclusive writer semantics this contract needs and it is released
//! when the file description is closed, so a crashed holder cannot leave a
//! permanent lock behind.
//!
//! The lock is taken with `LOCK_NB` so a conflicting holder is reported as
//! [`GuardError::Locked`] instead of blocking the caller forever.

use crate::locks::{GuardError, LockMode};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::Path;

fn operation(mode: LockMode) -> i32 {
    let base = match mode {
        LockMode::Shared => libc::LOCK_SH,
        LockMode::Exclusive => libc::LOCK_EX,
    };
    base | libc::LOCK_NB
}

/// Open (creating if needed) and lock `path`.
pub fn open_and_lock(path: &Path, mode: LockMode) -> Result<File, GuardError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|error| GuardError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    // SAFETY: `file` owns a valid open descriptor for the duration of the call.
    let result = unsafe { libc::flock(file.as_raw_fd(), operation(mode)) };
    if result == 0 {
        return Ok(file);
    }
    let error = std::io::Error::last_os_error();
    Err(if error.kind() == std::io::ErrorKind::WouldBlock {
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
    // SAFETY: `file` owns a valid open descriptor for the duration of the call.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if result == 0 {
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

    #[test]
    fn the_shared_and_exclusive_operations_differ() {
        assert_eq!(operation(LockMode::Shared) & libc::LOCK_NB, libc::LOCK_NB);
        assert_ne!(operation(LockMode::Shared), operation(LockMode::Exclusive));
    }

    #[test]
    fn readers_coexist_and_the_writer_is_refused_on_posix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("solution.lock");
        let reader = open_and_lock(&path, LockMode::Shared).expect("reader");
        let reader2 = open_and_lock(&path, LockMode::Shared).expect("second reader");
        assert!(open_and_lock(&path, LockMode::Exclusive).is_err());
        unlock(&reader).expect("unlock");
        unlock(&reader2).expect("unlock");
        let writer = open_and_lock(&path, LockMode::Exclusive).expect("writer");
        unlock(&writer).expect("unlock");
    }
}
