//! Ordered, checksum-verified schema migrations (task B-010).
//!
//! The shipped DDL is the canonical `docs/sqlite-schema-v1.sql`, which is
//! byte-identical to `contracts/sqlite/schema-v1.sql` in the pinned
//! specification. Migrations are applied in version order and each one runs in
//! its own transaction, so a migration that fails rolls back and leaves the
//! previous database usable (docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md section
//! 3 and section 8).
//!
//! Reconciliation is a read-only check first:
//!
//! * the applied rows must be an ordered prefix of the shipped migrations,
//! * every applied checksum must match the shipped SQL byte for byte,
//! * `PRAGMA user_version` must equal the highest applied version,
//! * a database newer than this binary is refused, never downgraded.

use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

use graph_core::error::{AxiomError, ErrorCode};

use crate::storage_error;

/// Schema version this binary writes and understands.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Canonical schema DDL, embedded so binary and file cannot drift apart.
pub const SCHEMA_V1_SQL: &str = include_str!("../../../docs/sqlite-schema-v1.sql");

/// One shipped migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// Schema version this migration produces.
    pub version: u32,
    /// Stable, filesystem-safe migration name.
    pub name: &'static str,
    /// Exact SQL applied for this version.
    pub sql: &'static str,
}

/// Shipped migrations, in application order.
#[must_use]
pub fn shipped_migrations() -> &'static [Migration] {
    &[Migration {
        version: 1,
        name: "initial-graph-schema",
        sql: SCHEMA_V1_SQL,
    }]
}

/// `sha256` of a migration's exact SQL bytes, lowercase hexadecimal.
#[must_use]
pub fn checksum(sql: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    hex(&hasher.finalize())
}

/// Deterministic file name of a migration, for example
/// `0001-initial-graph-schema.sql`.
#[must_use]
pub fn migration_filename(migration: &Migration) -> String {
    format!("{:04}-{}.sql", migration.version, migration.name)
}

/// One applied row of `schema_migrations`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedMigration {
    /// Applied schema version.
    pub version: u32,
    /// Recorded migration name.
    pub name: String,
    /// Recorded SQL checksum.
    pub checksum: String,
    /// Recorded application timestamp (UTC).
    pub applied_at: String,
}

/// Read-only assessment of the database against the shipped migrations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaVerification {
    /// `PRAGMA user_version`.
    pub version: u32,
    /// Number of applied migrations.
    pub applied: usize,
    /// Number of shipped migrations.
    pub shipped: usize,
    /// Versions still pending, in application order.
    pub pending: Vec<u32>,
}

impl SchemaVerification {
    /// Whether the database is exactly at the shipped schema.
    #[must_use]
    pub fn is_current(&self) -> bool {
        self.pending.is_empty()
    }
}

/// What an [`apply`] call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    /// Schema version before the call.
    pub from_version: u32,
    /// Schema version after the call.
    pub to_version: u32,
    /// Names of the migrations applied by this call, in order.
    pub applied: Vec<String>,
}

/// Applied migrations in ascending version order.
///
/// # Errors
/// Returns [`ErrorCode::Internal`] when `schema_migrations` cannot be read.
pub fn applied_migrations(connection: &Connection) -> Result<Vec<AppliedMigration>, AxiomError> {
    if !table_exists(connection, "schema_migrations")? {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare(
            "SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version ASC",
        )
        .map_err(|error| storage_error("read applied migrations", &error))?;
    let rows = statement
        .query_map([], |row| {
            Ok(AppliedMigration {
                version: row.get(0)?,
                name: row.get(1)?,
                checksum: row.get(2)?,
                applied_at: row.get(3)?,
            })
        })
        .map_err(|error| storage_error("read applied migrations", &error))?;
    let mut applied = Vec::new();
    for row in rows {
        applied.push(row.map_err(|error| storage_error("read an applied migration", &error))?);
    }
    Ok(applied)
}

/// Read `PRAGMA user_version`.
///
/// # Errors
/// Returns [`ErrorCode::Internal`] when the pragma cannot be read or holds a
/// value outside the supported range.
pub fn user_version(connection: &Connection) -> Result<u32, AxiomError> {
    let raw = connection
        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .map_err(|error| storage_error("read PRAGMA user_version", &error))?;
    u32::try_from(raw).map_err(|_| {
        AxiomError::new(
            ErrorCode::Internal,
            "PRAGMA user_version is outside the supported range",
        )
        .with_detail("observed", raw.to_string())
    })
}

/// Verify checksums and version ordering without changing the database.
///
/// # Errors
/// - [`ErrorCode::MigrationChecksumMismatch`] when an applied migration does not
///   match the shipped SQL.
/// - [`ErrorCode::MigrationOrderConflict`] when applied rows are not an ordered
///   prefix, or `user_version` disagrees with them.
/// - [`ErrorCode::SchemaNewerThanBinary`] when the database is newer than this
///   binary.
pub fn verify(connection: &Connection) -> Result<SchemaVerification, AxiomError> {
    let shipped = shipped_migrations();
    let applied = applied_migrations(connection)?;
    reconcile(&applied, shipped)?;
    let version = user_version(connection)?;
    let highest_applied = applied.last().map_or(0, |record| record.version);
    if version > CURRENT_SCHEMA_VERSION {
        return Err(AxiomError::new(
            ErrorCode::SchemaNewerThanBinary,
            "the database schema is newer than this binary knows about; upgrade the binary instead of downgrading the database",
        )
        .with_detail("expected", CURRENT_SCHEMA_VERSION.to_string())
        .with_detail("actual", version.to_string()));
    }
    if version != highest_applied {
        return Err(AxiomError::new(
            ErrorCode::MigrationOrderConflict,
            "PRAGMA user_version disagrees with schema_migrations",
        )
        .with_detail("expected", highest_applied.to_string())
        .with_detail("actual", version.to_string()));
    }
    Ok(SchemaVerification {
        version,
        applied: applied.len(),
        shipped: shipped.len(),
        pending: shipped[applied.len()..]
            .iter()
            .map(|migration| migration.version)
            .collect(),
    })
}

/// Pending migrations, in application order.
///
/// # Errors
/// Returns the same errors as [`verify`].
pub fn plan(connection: &Connection) -> Result<Vec<Migration>, AxiomError> {
    // `verify` owns every compatibility decision, so planning can never accept a
    // database that `verify` would reject -- notably one whose `user_version` is
    // newer than this binary, which must never be migrated downwards.
    let verification = verify(connection)?;
    let shipped = shipped_migrations();
    Ok(shipped[verification.applied..].to_vec())
}

/// Apply every pending migration, one transaction each.
///
/// # Errors
/// Returns the same errors as [`verify`], plus [`ErrorCode::Internal`] when a
/// migration fails. A failing migration is rolled back, so the database keeps
/// the schema it had before the call.
pub fn apply(connection: &mut Connection) -> Result<MigrationReport, AxiomError> {
    let from_version = user_version(connection)?;
    let pending = plan(connection)?;
    let mut applied = Vec::with_capacity(pending.len());
    for migration in &pending {
        apply_one(connection, migration)?;
        applied.push(migration.name.to_string());
    }
    Ok(MigrationReport {
        from_version,
        to_version: user_version(connection)?,
        applied,
    })
}

/// Apply exactly one migration inside its own transaction.
///
/// # Errors
/// Returns [`ErrorCode::Internal`] when the SQL fails or the bookkeeping row
/// cannot be written; nothing is committed in that case.
pub fn apply_one(connection: &mut Connection, migration: &Migration) -> Result<(), AxiomError> {
    let transaction = connection
        .transaction()
        .map_err(|error| storage_error("begin a migration transaction", &error))?;
    transaction.execute_batch(migration.sql).map_err(|error| {
        storage_error(
            &format!("apply migration {}", migration_filename(migration)),
            &error,
        )
    })?;
    transaction
        .pragma_update(None, "user_version", migration.version)
        .map_err(|error| storage_error("record the schema version", &error))?;
    transaction
        .execute(
            "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                migration.version,
                migration.name,
                checksum(migration.sql),
                utc_timestamp()
            ],
        )
        .map_err(|error| storage_error("record the applied migration", &error))?;
    transaction
        .commit()
        .map_err(|error| storage_error("commit a migration", &error))
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
#[must_use]
pub fn utc_timestamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    format_timestamp(seconds)
}

fn format_timestamp(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let time = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        (time % 3600) / 60,
        time % 60
    )
}

/// Days since 1970-01-01 to civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn reconcile(applied: &[AppliedMigration], shipped: &[Migration]) -> Result<(), AxiomError> {
    for (index, record) in applied.iter().enumerate() {
        let Some(expected) = shipped.get(index) else {
            return Err(AxiomError::new(
                ErrorCode::SchemaNewerThanBinary,
                "the database contains a migration this binary does not ship",
            )
            .with_detail("migration_version", record.version.to_string())
            .with_detail("migration_name", record.name.as_str()));
        };
        if record.version != expected.version || record.name != expected.name {
            return Err(AxiomError::new(
                ErrorCode::MigrationOrderConflict,
                "applied migrations are not an ordered prefix of the shipped migrations",
            )
            .with_detail(
                "expected",
                format!("{:04} {}", expected.version, expected.name),
            )
            .with_detail("actual", format!("{:04} {}", record.version, record.name)));
        }
        let expected_checksum = checksum(expected.sql);
        if record.checksum != expected_checksum {
            return Err(AxiomError::new(
                ErrorCode::MigrationChecksumMismatch,
                "an applied migration does not match the shipped SQL byte for byte",
            )
            .with_detail("migration_name", expected.name)
            .with_detail("migration_version", expected.version.to_string())
            .with_detail("expected", expected_checksum.as_str())
            .with_detail("actual", record.checksum.as_str()));
        }
    }
    Ok(())
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool, AxiomError> {
    connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |_| Ok(()),
        )
        .map(|()| true)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(false),
            other => Err(storage_error("inspect sqlite_master", &other)),
        })
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const BROKEN_SQL: &str = "CREATE TABLE duplicate(x); CREATE TABLE duplicate(x);";

    fn memory() -> Connection {
        let connection = Connection::open_in_memory().expect("in-memory database");
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .expect("foreign keys");
        connection
    }

    #[test]
    fn timestamps_are_utc_iso8601() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_timestamp(86_400), "1970-01-02T00:00:00Z");
        assert_eq!(format_timestamp(951_782_400), "2000-02-29T00:00:00Z");
        assert!(utc_timestamp().ends_with('Z'));
    }

    #[test]
    fn migration_names_have_deterministic_filenames() {
        let shipped = shipped_migrations();
        assert_eq!(
            shipped.len(),
            usize::try_from(CURRENT_SCHEMA_VERSION).unwrap_or(0)
        );
        assert_eq!(
            migration_filename(&shipped[0]),
            "0001-initial-graph-schema.sql"
        );
        assert_eq!(checksum(SCHEMA_V1_SQL).len(), 64);
        assert_ne!(checksum(SCHEMA_V1_SQL), checksum(BROKEN_SQL));
    }

    #[test]
    fn fresh_database_applies_the_shipped_schema() {
        let mut connection = memory();
        let report = apply(&mut connection).expect("apply the shipped schema");
        assert_eq!(report.from_version, 0);
        assert_eq!(report.to_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(report.applied, vec![String::from("initial-graph-schema")]);

        let verification = verify(&connection).expect("verify");
        assert!(verification.is_current());
        assert_eq!(verification.version, CURRENT_SCHEMA_VERSION);
        assert_eq!(verification.applied, 1);
        assert_eq!(verification.shipped, 1);

        let applied = applied_migrations(&connection).expect("applied rows");
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].checksum, checksum(SCHEMA_V1_SQL));
        assert!(applied[0].applied_at.ends_with('Z'));

        assert!(table_exists(&connection, "jobs").expect("jobs table"));
        assert!(table_exists(&connection, "published_generations").expect("generations"));
        assert!(table_exists(&connection, "schema_migrations").expect("migrations table"));

        let second = apply(&mut connection).expect("re-apply is a no-op");
        assert!(second.applied.is_empty());
        assert_eq!(second.from_version, second.to_version);
    }

    #[test]
    fn tampered_checksum_is_refused() {
        let mut connection = memory();
        apply(&mut connection).expect("apply");
        connection
            .execute_batch("UPDATE schema_migrations SET checksum = '00';")
            .expect("tamper");
        let error = verify(&connection).expect_err("tampered checksum must fail");
        assert_eq!(error.code(), ErrorCode::MigrationChecksumMismatch);
        assert!(plan(&connection).is_err());
    }

    #[test]
    fn applied_migrations_must_be_an_ordered_prefix() {
        let mut connection = memory();
        apply(&mut connection).expect("apply");
        connection
            .execute_batch("UPDATE schema_migrations SET name = 'rogue';")
            .expect("rename");
        let error = verify(&connection).expect_err("reordered migrations must fail");
        assert_eq!(error.code(), ErrorCode::MigrationOrderConflict);

        let mut future = memory();
        apply(&mut future).expect("apply");
        future
            .execute_batch(
                "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (7, 'future', 'ff', 't');",
            )
            .expect("insert a future migration");
        let error = verify(&future).expect_err("a future migration must fail");
        assert_eq!(error.code(), ErrorCode::SchemaNewerThanBinary);
    }

    #[test]
    fn a_newer_database_is_never_downgraded() {
        let mut connection = memory();
        apply(&mut connection).expect("apply");
        connection
            .execute_batch("PRAGMA user_version = 99;")
            .expect("bump");
        let error = verify(&connection).expect_err("newer schema must fail");
        assert_eq!(error.code(), ErrorCode::SchemaNewerThanBinary);
        assert!(apply(&mut connection).is_err());
        assert_eq!(user_version(&connection).expect("user version"), 99);
    }

    #[test]
    fn a_failed_migration_leaves_the_previous_database_usable() {
        let mut connection = memory();
        apply(&mut connection).expect("apply");
        let broken = Migration {
            version: 2,
            name: "broken",
            sql: BROKEN_SQL,
        };
        let error = apply_one(&mut connection, &broken).expect_err("the migration must fail");
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(user_version(&connection).expect("user version"), 1);
        assert_eq!(
            applied_migrations(&connection).expect("applied rows").len(),
            1
        );
        assert!(!table_exists(&connection, "duplicate").expect("no partial table"));
        assert!(verify(&connection).expect("verify").is_current());
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM solutions", [], |row| row
                    .get::<_, i64>(0))
                .expect("the previous schema is still usable"),
            0
        );
    }
}
