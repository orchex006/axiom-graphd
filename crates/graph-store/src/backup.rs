//! Consistent backups and restores (task B-018).
//!
//! `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 10 requires the upgrade
//! path to use the SQLite backup API or an equivalent consistent backup, and
//! explicitly forbids copying only the `.db` file while WAL is active. This
//! module therefore never copies bytes: [`backup_to`] runs `VACUUM INTO`, which
//! produces one self-contained database file that already includes every
//! committed WAL frame, and [`restore_into`] streams that file back through the
//! SQLite backup API into the target connection.

use std::path::Path;

use graph_core::error::{AxiomError, ErrorCode};
use rusqlite::{Connection, OpenFlags};

use crate::storage_error;

/// Outcome of a consistent backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReport {
    /// Destination path as recorded in the report.
    pub destination: String,
    /// Size of the produced file in bytes.
    pub bytes: u64,
    /// `PRAGMA user_version` of the backup.
    pub schema_version: u32,
    /// `PRAGMA integrity_check` result of the backup.
    pub integrity: String,
}

/// Outcome of a restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    /// Schema version the restored database carries.
    pub schema_version: u32,
    /// `PRAGMA integrity_check` result after the restore.
    pub integrity: String,
}

/// Take a consistent backup of `connection` into `destination`.
///
/// # Errors
/// - [`ErrorCode::Conflict`] when `destination` already exists, so an existing
///   backup or a human file is never overwritten.
/// - [`ErrorCode::Internal`] for a storage failure, including a failed integrity
///   check of the produced file.
pub fn backup_to(connection: &Connection, destination: &Path) -> Result<BackupReport, AxiomError> {
    if destination.exists() {
        return Err(
            AxiomError::new(ErrorCode::Conflict, "backup destination already exists")
                .with_detail("rule", "backup-destination-exists")
                .with_detail(
                    "observed",
                    destination.file_name().map_or_else(
                        || "<unnamed>".to_string(),
                        |name| name.to_string_lossy().into_owned(),
                    ),
                ),
        );
    }
    let destination_text = destination.to_string_lossy().into_owned();
    connection
        .execute("VACUUM INTO ?1", [destination_text.as_str()])
        .map_err(|error| storage_error("backup vacuum into", &error))?;

    let backup = open_read_only(destination)?;
    let integrity = integrity_check(&backup)?;
    if integrity != "ok" {
        return Err(
            AxiomError::new(ErrorCode::Internal, "backup failed its own integrity check")
                .with_detail("rule", "backup-integrity")
                .with_detail("observed", integrity),
        );
    }
    let schema_version = user_version(&backup)?;
    let bytes = std::fs::metadata(destination)
        .map_err(|error| storage_error("backup metadata", &error))?
        .len();
    Ok(BackupReport {
        destination: destination_text,
        bytes,
        schema_version,
        integrity,
    })
}

/// Restore `backup_path` into `target` through the SQLite backup API.
///
/// # Errors
/// - [`ErrorCode::NotFound`] when the backup file does not exist.
/// - [`ErrorCode::Internal`] when the backup fails its integrity check or the
///   copy fails.
pub fn restore_into(
    target: &mut Connection,
    backup_path: &Path,
) -> Result<RestoreReport, AxiomError> {
    if !backup_path.exists() {
        return Err(AxiomError::new(
            ErrorCode::NotFound,
            "backup file does not exist",
        ));
    }
    let source = open_read_only(backup_path)?;
    let integrity = integrity_check(&source)?;
    if integrity != "ok" {
        return Err(AxiomError::new(
            ErrorCode::Internal,
            "refusing to restore a backup that fails its integrity check",
        )
        .with_detail("rule", "backup-integrity")
        .with_detail("observed", integrity));
    }
    {
        let backup = rusqlite::backup::Backup::new(&source, target)
            .map_err(|error| storage_error("restore backup init", &error))?;
        backup
            .run_to_completion(128, std::time::Duration::from_millis(0), None)
            .map_err(|error| storage_error("restore backup run", &error))?;
    }
    let integrity = integrity_check(target)?;
    let schema_version = user_version(target)?;
    Ok(RestoreReport {
        schema_version,
        integrity,
    })
}

/// Verify a backup file standalone, without a target connection.
///
/// # Errors
/// - [`ErrorCode::NotFound`] when the file does not exist.
/// - [`ErrorCode::Internal`] when the file cannot be opened or is corrupt.
pub fn verify_backup(path: &Path) -> Result<BackupReport, AxiomError> {
    if !path.exists() {
        return Err(AxiomError::new(
            ErrorCode::NotFound,
            "backup file does not exist",
        ));
    }
    let backup = open_read_only(path)?;
    let integrity = integrity_check(&backup)?;
    if integrity != "ok" {
        return Err(
            AxiomError::new(ErrorCode::Internal, "backup fails its integrity check")
                .with_detail("rule", "backup-integrity")
                .with_detail("observed", integrity),
        );
    }
    let bytes = std::fs::metadata(path)
        .map_err(|error| storage_error("backup metadata", &error))?
        .len();
    Ok(BackupReport {
        destination: path.to_string_lossy().into_owned(),
        bytes,
        schema_version: user_version(&backup)?,
        integrity,
    })
}

fn open_read_only(path: &Path) -> Result<Connection, AxiomError> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| storage_error("backup open", &error))
}

fn integrity_check(connection: &Connection) -> Result<String, AxiomError> {
    connection
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .map_err(|error| storage_error("backup integrity check", &error))
}

fn user_version(connection: &Connection) -> Result<u32, AxiomError> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| storage_error("backup user_version", &error))?;
    Ok(u32::try_from(version).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wal_database(path: &Path) -> Connection {
        let connection = Connection::open(path).expect("open live database");
        let mode: String = connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .expect("enable WAL");
        assert_eq!(mode.to_lowercase(), "wal");
        connection
            .execute_batch(
                "CREATE TABLE probe(value TEXT); \
                 INSERT INTO probe(value) VALUES('committed');",
            )
            .expect("seed live database");
        connection
    }

    #[test]
    fn backup_of_wal_traffic_restores_cleanly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let live = dir.path().join("live.sqlite");
        let destination = dir.path().join("backup.sqlite");
        let connection = wal_database(&live);

        // The committed row is still only in the -wal file, so a raw copy of the
        // `.db` file would lose it. The backup must still restore it.
        assert!(
            dir.path().join("live.sqlite-wal").exists(),
            "WAL frames must exist for this test to prove anything"
        );

        let report = backup_to(&connection, &destination).expect("consistent backup");
        assert_eq!(report.integrity, "ok");
        assert!(report.bytes > 0);
        assert_eq!(report.schema_version, 0);
        verify_backup(&destination).expect("standalone verify");

        let mut target = Connection::open_in_memory().expect("target database");
        let restored = restore_into(&mut target, &destination).expect("restore");
        assert_eq!(restored.integrity, "ok");
        let value: String = target
            .query_row("SELECT value FROM probe", [], |row| row.get(0))
            .expect("restored row");
        assert_eq!(value, "committed");
    }

    #[test]
    fn backup_never_overwrites_and_restore_refuses_missing_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let live = dir.path().join("live.sqlite");
        let existing = dir.path().join("existing.sqlite");
        let connection = Connection::open(&live).expect("open live database");
        std::fs::write(&existing, b"human data").expect("write human file");

        assert_eq!(
            backup_to(&connection, &existing)
                .expect_err("existing destination")
                .code(),
            ErrorCode::Conflict
        );
        assert_eq!(
            std::fs::read(&existing).expect("read human file"),
            b"human data"
        );
        assert_eq!(
            verify_backup(&dir.path().join("missing.sqlite"))
                .expect_err("missing backup")
                .code(),
            ErrorCode::NotFound
        );

        let mut target = Connection::open_in_memory().expect("target database");
        assert_eq!(
            restore_into(&mut target, &dir.path().join("missing.sqlite"))
                .expect_err("missing backup")
                .code(),
            ErrorCode::NotFound
        );
    }
}
