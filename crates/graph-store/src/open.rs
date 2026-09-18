//! Opening the Axiom SQLite store and enforcing its pragmas (task B-009).
//!
//! docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md section 1 fixes the durable-state
//! baseline: WAL on local disk, `foreign_keys = ON`, a bounded `busy_timeout`
//! and `synchronous = FULL`, with one writer connection per instance. SQLite WAL
//! allows concurrent readers but still only one writer, and is not suitable for
//! network filesystems, so mutable state on shared storage is refused unless the
//! operator explicitly degrades to `journal_mode = DELETE`.
//!
//! The version gate is a *runtime* check. `SELECT sqlite_version()` is read back
//! from the opened database instead of trusting the Rust crate version, because
//! a bundled or system library can differ from the crate metadata.

use std::path::{Path, PathBuf};
use std::time::Duration;

use graph_core::config::{JournalMode, SyncMode};
use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{classify_storage_lexically, StorageClass};

use crate::storage_error;
use rusqlite::Connection;

/// Lowest SQLite runtime accepted for WAL-backed mutable state.
///
/// docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md section 1: the runtime must carry
/// the WAL-reset fix; the accepted baseline is 3.51.3 or a verified backport
/// that is listed in the lock.
pub const MIN_SQLITE_VERSION: SqliteVersion = SqliteVersion::new(3, 51, 3);

/// Verified backports accepted below [`MIN_SQLITE_VERSION`].
///
/// The list is empty in this build: no backport is pinned by a reviewed
/// specification revision yet, so only the published 3.51.3 floor is accepted.
/// Adding an entry requires a reviewed contract change, never a local edit.
pub const WAL_RESET_BACKPORTS: &[SqliteVersion] = &[];

/// A parsed SQLite runtime version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SqliteVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl SqliteVersion {
    /// Build a version from its numeric components.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Major component.
    #[must_use]
    pub const fn major(self) -> u32 {
        self.major
    }

    /// Minor component.
    #[must_use]
    pub const fn minor(self) -> u32 {
        self.minor
    }

    /// Patch component.
    #[must_use]
    pub const fn patch(self) -> u32 {
        self.patch
    }

    /// Parse `sqlite_version()` output such as `3.51.3` or `3.51.3 (2025-04-01)`.
    ///
    /// # Errors
    /// Returns [`ErrorCode::Internal`] when the runtime reports text this binary
    /// cannot interpret, which must be surfaced rather than silently ignored.
    pub fn parse(text: &str) -> Result<Self, AxiomError> {
        let head = text.split_whitespace().next().unwrap_or_default();
        let mut fields = head.split('.');
        let major = fields.next().and_then(|value| value.parse::<u32>().ok());
        let minor = fields.next().and_then(|value| value.parse::<u32>().ok());
        let patch = match fields.next() {
            Some(value) => value.parse::<u32>().ok(),
            None => Some(0),
        };
        let parsed = match (major, minor, patch) {
            (Some(major), Some(minor), Some(patch)) if fields.next().is_none() => {
                Self::new(major, minor, patch)
            }
            _ => {
                return Err(AxiomError::new(
                    ErrorCode::Internal,
                    "SQLite reported an unparsable runtime version",
                )
                .with_detail("sqlite_version", head))
            }
        };
        Ok(parsed)
    }

    /// Whether this runtime may carry the WAL-backed durable queue.
    #[must_use]
    pub fn is_supported_for_wal(self) -> bool {
        self >= MIN_SQLITE_VERSION || WAL_RESET_BACKPORTS.contains(&self)
    }
}

impl std::fmt::Display for SqliteVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Where a path physically lives. Injected so tests can model a share without
/// mounting one.
pub trait VolumeProbe {
    /// Classify the storage behind `path`.
    fn classify(&self, path: &Path) -> StorageClass;
}

/// Lexical probe used when no native volume information is available.
///
/// A share can also be mounted on a drive letter, so this is deliberately the
/// conservative pre-probe policy from `graph_core::paths`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LexicalVolumeProbe;

impl VolumeProbe for LexicalVolumeProbe {
    fn classify(&self, path: &Path) -> StorageClass {
        classify_storage_lexically(&path.to_string_lossy())
    }
}

/// What to open.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// A file-backed database.
    File(PathBuf),
    /// A private in-memory database, used by tests and probes.
    Memory,
}

/// Frozen options for opening the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOptions {
    target: Target,
    journal_mode: JournalMode,
    busy_timeout_ms: u64,
    synchronous: SyncMode,
    require_local_storage: bool,
    create_parent: bool,
}

impl OpenOptions {
    /// Open (or create) the database at `path` with the durable-state defaults.
    #[must_use]
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self {
            target: Target::File(path.into()),
            ..Self::default()
        }
    }

    /// Open a private in-memory database with the durable-state defaults.
    #[must_use]
    pub fn memory() -> Self {
        Self {
            target: Target::Memory,
            ..Self::default()
        }
    }

    /// Requested `journal_mode`.
    #[must_use]
    pub fn with_journal_mode(mut self, journal_mode: JournalMode) -> Self {
        self.journal_mode = journal_mode;
        self
    }

    /// Requested `busy_timeout` in milliseconds.
    #[must_use]
    pub fn with_busy_timeout_ms(mut self, busy_timeout_ms: u64) -> Self {
        self.busy_timeout_ms = busy_timeout_ms;
        self
    }

    /// Requested `synchronous` value.
    #[must_use]
    pub fn with_synchronous(mut self, synchronous: SyncMode) -> Self {
        self.synchronous = synchronous;
        self
    }

    /// Whether shared/remote storage is refused instead of degraded.
    #[must_use]
    pub fn with_require_local_storage(mut self, require_local_storage: bool) -> Self {
        self.require_local_storage = require_local_storage;
        self
    }

    /// Whether missing parent directories are created.
    #[must_use]
    pub fn with_create_parent(mut self, create_parent: bool) -> Self {
        self.create_parent = create_parent;
        self
    }

    /// Database path, or `None` for an in-memory database.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match &self.target {
            Target::File(path) => Some(path.as_path()),
            Target::Memory => None,
        }
    }

    /// Requested `journal_mode`.
    #[must_use]
    pub const fn journal_mode(&self) -> JournalMode {
        self.journal_mode
    }

    /// Requested `busy_timeout` in milliseconds.
    #[must_use]
    pub const fn busy_timeout_ms(&self) -> u64 {
        self.busy_timeout_ms
    }

    /// Requested `synchronous` value.
    #[must_use]
    pub const fn synchronous(&self) -> SyncMode {
        self.synchronous
    }

    /// Whether shared/remote storage is refused instead of degraded.
    #[must_use]
    pub const fn require_local_storage(&self) -> bool {
        self.require_local_storage
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            target: Target::Memory,
            journal_mode: JournalMode::Wal,
            busy_timeout_ms: graph_core::config::DEFAULT_BUSY_TIMEOUT_MS,
            synchronous: SyncMode::Full,
            require_local_storage: true,
            create_parent: true,
        }
    }
}

/// The effective pragma state of an open store, for diagnostics and evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PragmaReport {
    /// Runtime `sqlite_version()`.
    pub sqlite_version: String,
    /// Effective `journal_mode`.
    pub journal_mode: String,
    /// Effective `synchronous` (2 is FULL).
    pub synchronous: i64,
    /// Effective `busy_timeout` in milliseconds.
    pub busy_timeout_ms: i64,
    /// Effective `foreign_keys` (1 is on).
    pub foreign_keys: i64,
    /// Database `user_version`, the applied schema version.
    pub user_version: i64,
}

/// An open database plus the identity of the runtime that opened it.
#[derive(Debug)]
pub struct Store {
    connection: Connection,
    path: Option<PathBuf>,
    version: SqliteVersion,
    journal_mode: JournalMode,
    busy_timeout_ms: u64,
}

impl Store {
    /// Borrow the connection.
    #[must_use]
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Mutably borrow the connection.
    #[must_use]
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    /// Database path, or `None` for an in-memory database.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Runtime SQLite version read back from this connection.
    #[must_use]
    pub const fn sqlite_version(&self) -> SqliteVersion {
        self.version
    }

    /// Effective journal mode.
    #[must_use]
    pub const fn journal_mode(&self) -> JournalMode {
        self.journal_mode
    }

    /// Effective busy timeout in milliseconds.
    #[must_use]
    pub const fn busy_timeout_ms(&self) -> u64 {
        self.busy_timeout_ms
    }

    /// Consume the store and return the connection.
    #[must_use]
    pub fn into_connection(self) -> Connection {
        self.connection
    }

    /// Read the effective pragma state back from the connection.
    ///
    /// # Errors
    /// Returns [`ErrorCode::Internal`] when SQLite cannot report a pragma.
    pub fn pragma_report(&self) -> Result<PragmaReport, AxiomError> {
        Ok(PragmaReport {
            sqlite_version: runtime_sqlite_version(&self.connection)?.to_string(),
            journal_mode: pragma_text(&self.connection, "PRAGMA journal_mode")?,
            synchronous: pragma_int(&self.connection, "PRAGMA synchronous")?,
            busy_timeout_ms: pragma_int(&self.connection, "PRAGMA busy_timeout")?,
            foreign_keys: pragma_int(&self.connection, "PRAGMA foreign_keys")?,
            user_version: pragma_int(&self.connection, "PRAGMA user_version")?,
        })
    }
}

/// Open the store and enforce the durable-state contract.
///
/// Order of operations, all before the caller can use the connection:
///
/// 1. classify the storage behind the requested path,
/// 2. refuse shared/remote storage for mutable state (or require explicit
///    degradation to `journal_mode = DELETE`),
/// 3. open the database,
/// 4. read `sqlite_version()` and enforce the WAL baseline,
/// 5. apply `journal_mode`, `busy_timeout`, `synchronous` and `foreign_keys`.
///
/// # Errors
/// - [`ErrorCode::SqliteNetworkStorageUnsupported`] for mutable state on
///   shared/remote storage.
/// - [`ErrorCode::SqliteUnsupportedVersion`] when WAL is requested on a runtime
///   below the accepted baseline.
/// - [`ErrorCode::Internal`] when the database cannot be opened or a pragma
///   cannot be applied.
pub fn open(options: &OpenOptions, probe: &dyn VolumeProbe) -> Result<Store, AxiomError> {
    let path = options.path().map(Path::to_path_buf);
    let storage = match &path {
        Some(path) => probe.classify(path),
        None => StorageClass::LocalDisk,
    };

    if let Some(path) = &path {
        if storage.is_unsafe_for_mutable_state() {
            if options.require_local_storage() {
                return Err(AxiomError::new(
                    ErrorCode::SqliteNetworkStorageUnsupported,
                    "mutable Axiom state must stay on local storage; shared, remote or cloud-synchronised storage is refused",
                )
                .with_detail("storage_class", storage.as_str())
                .with_detail("rule", "mutable-state-local-storage-only"));
            }
            if options.journal_mode() == JournalMode::Wal {
                return Err(AxiomError::new(
                    ErrorCode::SqliteNetworkStorageUnsupported,
                    "WAL is not supported on shared or remote storage; set journalMode to DELETE to degrade explicitly",
                )
                .with_detail("storage_class", storage.as_str())
                .with_detail("rule", "wal-local-storage-only"));
            }
        }
        if options.create_parent {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .map_err(|error| storage_error("create the database directory", &error))?;
                }
            }
        }
    }

    let connection = match &path {
        Some(path) => Connection::open(path),
        None => Connection::open_in_memory(),
    }
    .map_err(|error| storage_error("open the SQLite database", &error))?;

    let version = runtime_sqlite_version(&connection)?;
    if options.journal_mode() == JournalMode::Wal && !version.is_supported_for_wal() {
        return Err(AxiomError::new(
            ErrorCode::SqliteUnsupportedVersion,
            format!("the SQLite runtime {version} is below the {MIN_SQLITE_VERSION} WAL baseline; pin a supported runtime or set journalMode to DELETE"),
        )
        .with_detail("sqlite_version", version.to_string())
        .with_detail("required_version", MIN_SQLITE_VERSION.to_string())
        .with_detail("rule", "sqlite-wal-reset-baseline"));
    }

    let journal_mode = apply_pragmas(&connection, options)?;

    Ok(Store {
        connection,
        path,
        version,
        journal_mode,
        busy_timeout_ms: options.busy_timeout_ms(),
    })
}

/// Read `sqlite_version()` from an already-open connection.
///
/// # Errors
/// Returns [`ErrorCode::Internal`] when the query fails or the answer is not a
/// version this binary understands.
pub fn runtime_sqlite_version(connection: &Connection) -> Result<SqliteVersion, AxiomError> {
    let text = pragma_text(connection, "SELECT sqlite_version()")?;
    SqliteVersion::parse(&text)
}

/// Read the runtime SQLite version without opening a durable database.
///
/// # Errors
/// Returns [`ErrorCode::Internal`] when a private in-memory connection cannot be
/// opened, which means the linked library is unusable.
pub fn runtime_version_probe() -> Result<SqliteVersion, AxiomError> {
    let connection = Connection::open_in_memory()
        .map_err(|error| storage_error("open a probe connection", &error))?;
    runtime_sqlite_version(&connection)
}

fn apply_pragmas(
    connection: &Connection,
    options: &OpenOptions,
) -> Result<JournalMode, AxiomError> {
    connection
        .busy_timeout(Duration::from_millis(options.busy_timeout_ms()))
        .map_err(|error| storage_error("set the SQLite busy timeout", &error))?;

    // foreign_keys is per connection and must be re-applied after every open.
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .map_err(|error| storage_error("enable SQLite foreign keys", &error))?;

    let synchronous = options.synchronous().as_str();
    connection
        .execute_batch(&format!("PRAGMA synchronous = {synchronous};"))
        .map_err(|error| storage_error("set the SQLite synchronous mode", &error))?;

    let requested = options.journal_mode().as_str();
    let applied = pragma_text(connection, &format!("PRAGMA journal_mode = {requested}"))?;
    let journal_mode = match applied.to_ascii_lowercase().as_str() {
        "wal" => JournalMode::Wal,
        "delete" | "truncate" | "persist" | "memory" | "off" => JournalMode::Delete,
        other => {
            return Err(AxiomError::new(
                ErrorCode::Internal,
                "SQLite reported a journal mode this binary does not model",
            )
            .with_detail("observed", other))
        }
    };
    if journal_mode != options.journal_mode() {
        return Err(AxiomError::new(
            ErrorCode::Internal,
            "SQLite refused the requested journal mode",
        )
        .with_detail("expected", options.journal_mode().as_str())
        .with_detail("actual", applied.as_str()));
    }
    Ok(journal_mode)
}

fn pragma_text(connection: &Connection, sql: &str) -> Result<String, AxiomError> {
    connection
        .query_row(sql, [], |row| row.get::<_, String>(0))
        .map_err(|error| storage_error("read a SQLite pragma", &error))
}

fn pragma_int(connection: &Connection, sql: &str) -> Result<i64, AxiomError> {
    connection
        .query_row(sql, [], |row| row.get::<_, i64>(0))
        .map_err(|error| storage_error("read a SQLite pragma", &error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy)]
    struct FixedProbe(StorageClass);

    impl VolumeProbe for FixedProbe {
        fn classify(&self, _path: &Path) -> StorageClass {
            self.0
        }
    }

    fn degraded_memory() -> OpenOptions {
        OpenOptions::memory()
            .with_journal_mode(JournalMode::Delete)
            .with_require_local_storage(false)
    }

    #[test]
    fn runtime_version_parses_and_orders() {
        assert_eq!(
            SqliteVersion::parse("3.51.3"),
            Ok(SqliteVersion::new(3, 51, 3))
        );
        assert_eq!(
            SqliteVersion::parse("3.51.3 2025-04-01").unwrap(),
            SqliteVersion::new(3, 51, 3)
        );
        assert_eq!(
            SqliteVersion::parse("3.51"),
            Ok(SqliteVersion::new(3, 51, 0))
        );
        assert!(SqliteVersion::parse("3.9.2").unwrap() < SqliteVersion::parse("3.51.2").unwrap());
        assert!(SqliteVersion::parse("not-a-version").is_err());
        assert!(SqliteVersion::parse("").is_err());
    }

    #[test]
    fn wal_gate_boundary_is_the_published_floor() {
        assert_eq!(MIN_SQLITE_VERSION.to_string(), "3.51.3");
        assert!(!SqliteVersion::new(3, 51, 2).is_supported_for_wal());
        assert!(SqliteVersion::new(3, 51, 3).is_supported_for_wal());
        assert!(SqliteVersion::new(3, 52, 0).is_supported_for_wal());
        // No backport is pinned in this build, so nothing below the floor passes.
        assert_eq!(WAL_RESET_BACKPORTS.len(), 0);
        assert!(!SqliteVersion::new(3, 50, 2).is_supported_for_wal());
    }

    #[test]
    fn bundled_runtime_version_is_reported_honestly() {
        let probe = match runtime_version_probe() {
            Ok(version) => version,
            Err(error) => panic!("the linked SQLite runtime is unusable: {error}"),
        };
        assert_eq!(probe.to_string(), rusqlite::version());
        assert_eq!(
            open(&degraded_memory(), &LexicalVolumeProbe)
                .expect("in-memory open")
                .sqlite_version(),
            probe
        );
    }

    #[test]
    fn wal_decision_matches_the_actual_runtime_version() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("index.sqlite");
        let version = runtime_version_probe().expect("probe");
        let result = open(&OpenOptions::file(&path), &LexicalVolumeProbe);
        if version.is_supported_for_wal() {
            let store = result.expect("WAL must open on a supported runtime");
            assert_eq!(store.journal_mode(), JournalMode::Wal);
        } else {
            let error = result.expect_err("WAL must fail below the baseline");
            assert_eq!(error.code(), ErrorCode::SqliteUnsupportedVersion);
            assert_eq!(error.exit_code(), graph_core::error::ExitCode::Incompatible);
        }
        // The explicit degradation always opens, and reports the real pragmas.
        let degraded = open(
            &OpenOptions::file(&path)
                .with_journal_mode(JournalMode::Delete)
                .with_require_local_storage(false),
            &LexicalVolumeProbe,
        )
        .expect("explicit degradation must open");
        let report = degraded.pragma_report().expect("pragma report");
        assert_eq!(report.journal_mode.to_ascii_lowercase(), "delete");
        assert_eq!(report.foreign_keys, 1);
        assert_eq!(report.synchronous, 2);
        assert_eq!(report.busy_timeout_ms, 5_000);
        assert_eq!(report.sqlite_version, version.to_string());
    }

    #[test]
    fn shared_storage_is_refused_for_wal_and_degradable_for_delete() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("index.sqlite");
        let share = FixedProbe(StorageClass::NetworkShare);

        let refused = open(&OpenOptions::file(&path), &share)
            .expect_err("mutable state on a share must be refused");
        assert_eq!(refused.code(), ErrorCode::SqliteNetworkStorageUnsupported);

        let wal_on_share = open(
            &OpenOptions::file(&path).with_require_local_storage(false),
            &share,
        )
        .expect_err("WAL on a share must be refused even when degraded");
        assert_eq!(
            wal_on_share.code(),
            ErrorCode::SqliteNetworkStorageUnsupported
        );

        let degraded = open(
            &OpenOptions::file(&path)
                .with_journal_mode(JournalMode::Delete)
                .with_require_local_storage(false),
            &share,
        )
        .expect("explicit DELETE degradation must open");
        assert_eq!(degraded.journal_mode(), JournalMode::Delete);
    }
}
