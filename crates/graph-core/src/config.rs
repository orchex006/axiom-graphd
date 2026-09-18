//! Validated, immutable runtime configuration (task B-005).
//!
//! Configuration is a *start-up gate*: [`ServiceConfig::load`] validates every
//! value before the service binds a socket, takes a lock or opens a database, so
//! an invalid configuration can never leave a half-started service behind
//! (docs/10-ARCHITECTURE.md section D, docs/16-CLI-AND-CONTROL-API.md section 1).
//!
//! Design rules enforced here:
//!
//! * The serialized document uses `camelCase` keys and rejects unknown keys
//!   (`additionalProperties: false`), because a typo that is silently ignored is
//!   how a stale value keeps controlling a live service.
//! * Discovery is first-existing-source-wins: an explicit `--registry` path
//!   wins, otherwise the per-user `config/registry.json` under `AXIOM_HOME`,
//!   otherwise built-in defaults.
//! * Environment overrides may only *narrow* the allowed source roots. An
//!   environment variable can never widen the set of directories the daemon is
//!   permitted to read, so a hostile or stale environment cannot silently
//!   re-authorise a source tree.
//! * [`ServiceConfig`] is immutable: its fields are private, it does not
//!   implement `Deserialize`, and the only constructors run [`ServiceConfig::validate`].
//!   Deserialization happens against a private, unvalidated raw shape.
//!
//! Values that must be host paths are validated as absolute *without* touching
//! the filesystem, so validation is deterministic and safe in a unit test.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{AxiomError, ErrorCode};
use crate::paths::{is_absolute_host_path, AxiomHome, PathEnvironment};

/// Repository-relative name of the default runtime configuration source.
///
/// Resolved under [`AxiomHome::root`], matching the state layout in
/// docs/10-ARCHITECTURE.md section D.
pub const RUNTIME_CONFIG: &str = "config/registry.json";

/// Environment variable that may narrow the allowed source roots.
pub const ENV_ALLOWED_SOURCE_ROOTS: &str = "AXIOM_ALLOWED_SOURCE_ROOTS";

/// Minimum accepted `runtime.workerCount`.
pub const MIN_WORKER_COUNT: usize = 1;
/// Maximum accepted `runtime.workerCount`.
pub const MAX_WORKER_COUNT: usize = 4;
/// Maximum accepted `storage.busyTimeoutMs`.
pub const MAX_BUSY_TIMEOUT_MS: u64 = 60_000;
/// Default busy timeout, matching the bounded wait in docs/13-SQLite section 1.
pub const DEFAULT_BUSY_TIMEOUT_MS: u64 = 5_000;
/// Maximum accepted parser batch size in files (docs/13-SQLite section 6).
pub const MAX_PARSER_BATCH_FILES: usize = 64;
/// Maximum accepted parser batch size in bytes (16 MiB).
pub const MAX_PARSER_BATCH_BYTES: u64 = 16 * 1024 * 1024;
/// Default shutdown deadline in milliseconds (90 s bounded grace).
pub const DEFAULT_SHUTDOWN_DEADLINE_MS: u64 = 90_000;
/// Maximum accepted shutdown deadline in milliseconds (10 min).
pub const MAX_SHUTDOWN_DEADLINE_MS: u64 = 600_000;
/// Default maximum debounce wait in milliseconds (docs/13-SQLite section 6).
pub const DEFAULT_MAX_DEBOUNCE_MS: u64 = 3_000;
/// Default debounce window in milliseconds (docs/13-SQLite section 6).
pub const DEFAULT_DEBOUNCE_MS: u64 = 750;

/// Which foreground entry point the process is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DaemonMode {
    /// Long-running per-user daemon.
    Serve,
    /// One-shot diagnostics.
    Doctor,
    /// Print version/build information and exit.
    Version,
}

impl DaemonMode {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Serve => "serve",
            Self::Doctor => "doctor",
            Self::Version => "version",
        }
    }
}

impl Default for DaemonMode {
    fn default() -> Self {
        Self::Serve
    }
}

impl fmt::Display for DaemonMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// SQLite `synchronous` pragma. `FULL` is the durable-state baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SyncMode {
    /// Fsync on every commit.
    Full,
    /// Fsync at checkpoints only; not the durable-state baseline.
    Normal,
}

impl SyncMode {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "FULL",
            Self::Normal => "NORMAL",
        }
    }
}

impl Default for SyncMode {
    fn default() -> Self {
        Self::Full
    }
}

/// SQLite `journal_mode` pragma.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum JournalMode {
    /// Write-ahead logging; requires local storage.
    Wal,
    /// Rollback journal; the only mode supported on shared/network storage.
    Delete,
}

impl JournalMode {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Wal => "WAL",
            Self::Delete => "DELETE",
        }
    }
}

impl Default for JournalMode {
    fn default() -> Self {
        Self::Wal
    }
}

/// Diagnostic level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Failures only.
    Error,
    /// Failures and degraded behaviour.
    Warn,
    /// Normal lifecycle events.
    Info,
    /// Per-operation detail.
    Debug,
    /// Parser and watcher detail.
    Trace,
}

impl LogLevel {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    /// Numeric severity, used for filtering. Lower values are more severe.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Error => 0,
            Self::Warn => 1,
            Self::Info => 2,
            Self::Debug => 3,
            Self::Trace => 4,
        }
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::Info
    }
}

/// Diagnostic record encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// One JSON object per line (the machine-readable default).
    Json,
    /// Human-readable single line.
    Text,
}

impl LogFormat {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Text => "text",
        }
    }
}

impl Default for LogFormat {
    fn default() -> Self {
        Self::Json
    }
}

/// Process-level settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    mode: DaemonMode,
    instance_id: String,
    control_host: String,
    control_port: u16,
    token_file: Option<String>,
}

impl DaemonConfig {
    /// Foreground entry point.
    #[must_use]
    pub const fn mode(&self) -> DaemonMode {
        self.mode
    }

    /// Workspace instance id owning this daemon's state.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Loopback interface the control API binds.
    #[must_use]
    pub fn control_host(&self) -> &str {
        &self.control_host
    }

    /// Control API port; `0` asks the OS for a free port.
    #[must_use]
    pub const fn control_port(&self) -> u16 {
        self.control_port
    }

    /// Absolute path of the owner-only control token file, when configured.
    #[must_use]
    pub fn token_file(&self) -> Option<&str> {
        self.token_file.as_deref()
    }
}

/// Scheduling and batching settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    worker_count: usize,
    debounce_ms: u64,
    max_debounce_ms: u64,
    shutdown_deadline_ms: u64,
    parser_batch_files: usize,
    parser_batch_bytes: u64,
}

impl RuntimeConfig {
    /// Parallel analysis workers.
    #[must_use]
    pub const fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Debounce window before a change is reconciled.
    #[must_use]
    pub const fn debounce_ms(&self) -> u64 {
        self.debounce_ms
    }

    /// Maximum time a continuously edited file may be deferred.
    #[must_use]
    pub const fn max_debounce_ms(&self) -> u64 {
        self.max_debounce_ms
    }

    /// Bounded grace period for a clean shutdown.
    #[must_use]
    pub const fn shutdown_deadline_ms(&self) -> u64 {
        self.shutdown_deadline_ms
    }

    /// Files per parser batch.
    #[must_use]
    pub const fn parser_batch_files(&self) -> usize {
        self.parser_batch_files
    }

    /// Bytes per parser batch.
    #[must_use]
    pub const fn parser_batch_bytes(&self) -> u64 {
        self.parser_batch_bytes
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            worker_count: 1,
            debounce_ms: DEFAULT_DEBOUNCE_MS,
            max_debounce_ms: DEFAULT_MAX_DEBOUNCE_MS,
            shutdown_deadline_ms: DEFAULT_SHUTDOWN_DEADLINE_MS,
            parser_batch_files: MAX_PARSER_BATCH_FILES,
            parser_batch_bytes: MAX_PARSER_BATCH_BYTES,
        }
    }
}

/// Storage settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageConfig {
    database_path: Option<String>,
    allowed_source_roots: Vec<String>,
    busy_timeout_ms: u64,
    synchronous: SyncMode,
    journal_mode: JournalMode,
    require_local_storage: bool,
}

impl StorageConfig {
    /// Absolute database path override; `None` uses the instance layout.
    #[must_use]
    pub fn database_path(&self) -> Option<&str> {
        self.database_path.as_deref()
    }

    /// Absolute directories the daemon may read source from.
    #[must_use]
    pub fn allowed_source_roots(&self) -> &[String] {
        &self.allowed_source_roots
    }

    /// Bounded SQLite busy timeout.
    #[must_use]
    pub const fn busy_timeout_ms(&self) -> u64 {
        self.busy_timeout_ms
    }

    /// `synchronous` pragma value.
    #[must_use]
    pub const fn synchronous(&self) -> SyncMode {
        self.synchronous
    }

    /// `journal_mode` pragma value.
    #[must_use]
    pub const fn journal_mode(&self) -> JournalMode {
        self.journal_mode
    }

    /// Whether shared/network storage is refused instead of degraded.
    #[must_use]
    pub const fn require_local_storage(&self) -> bool {
        self.require_local_storage
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_path: None,
            allowed_source_roots: Vec::new(),
            busy_timeout_ms: DEFAULT_BUSY_TIMEOUT_MS,
            synchronous: SyncMode::Full,
            journal_mode: JournalMode::Wal,
            require_local_storage: true,
        }
    }
}

/// Diagnostics settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingConfig {
    level: LogLevel,
    format: LogFormat,
    rate_limit_per_minute: u32,
}

impl LoggingConfig {
    /// Minimum recorded level.
    #[must_use]
    pub const fn level(&self) -> LogLevel {
        self.level
    }

    /// Record encoding.
    #[must_use]
    pub const fn format(&self) -> LogFormat {
        self.format
    }

    /// Per-target rate limit for repeated records.
    #[must_use]
    pub const fn rate_limit_per_minute(&self) -> u32 {
        self.rate_limit_per_minute
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Json,
            rate_limit_per_minute: 600,
        }
    }
}

/// Validated, immutable runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    daemon: DaemonConfig,
    runtime: RuntimeConfig,
    storage: StorageConfig,
    logging: LoggingConfig,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            daemon: DaemonConfig {
                mode: DaemonMode::default(),
                instance_id: "default".to_string(),
                control_host: "127.0.0.1".to_string(),
                control_port: 0,
                token_file: None,
            },
            runtime: RuntimeConfig::default(),
            storage: StorageConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

/// Environment inputs that may refine a loaded configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigEnvironment {
    /// Raw value of [`ENV_ALLOWED_SOURCE_ROOTS`], when set.
    pub allowed_source_roots: Option<String>,
}

impl ConfigEnvironment {
    /// Read the process environment.
    #[must_use]
    pub fn for_current_process() -> Self {
        Self {
            allowed_source_roots: std::env::var(ENV_ALLOWED_SOURCE_ROOTS).ok(),
        }
    }
}

impl ServiceConfig {
    /// Configuration for the process's own entry point.
    #[must_use]
    pub fn daemon(&self) -> &DaemonConfig {
        &self.daemon
    }

    /// Scheduling and batching configuration.
    #[must_use]
    pub fn runtime(&self) -> &RuntimeConfig {
        &self.runtime
    }

    /// Storage configuration.
    #[must_use]
    pub fn storage(&self) -> &StorageConfig {
        &self.storage
    }

    /// Diagnostics configuration.
    #[must_use]
    pub fn logging(&self) -> &LoggingConfig {
        &self.logging
    }

    /// Absolute database path override, when configured.
    #[must_use]
    pub fn database_path(&self) -> Option<&str> {
        self.storage.database_path()
    }

    /// Parse, validate and freeze a configuration document.
    ///
    /// # Errors
    /// Returns [`ErrorCode::ConfigInvalid`] for any malformed, unknown,
    /// out-of-range or non-absolute value.
    pub fn from_json_str(document: &str) -> Result<Self, AxiomError> {
        Self::from_json_str_with(document, &ConfigEnvironment::default())
    }

    /// Parse and validate using an explicit environment (test seam).
    ///
    /// # Errors
    /// As [`ServiceConfig::from_json_str`], plus [`ErrorCode::ConfigInvalid`]
    /// when an environment override would widen the allowed source roots.
    pub fn from_json_str_with(
        document: &str,
        environment: &ConfigEnvironment,
    ) -> Result<Self, AxiomError> {
        let raw: RawServiceConfig = serde_json::from_str(document)
            .map_err(|error| invalid("config", format!("configuration is not valid: {error}")))?;
        let mut config = raw.into_validated()?;
        config.apply_environment(environment)?;
        config.validate()?;
        Ok(config)
    }

    /// Load the first existing configuration source, else built-in defaults.
    ///
    /// `daemon` is the explicit `--registry <path>` value. Sources are tried in
    /// order and the first that exists wins; a source that exists but is
    /// unreadable or invalid is an error, never silently skipped.
    ///
    /// # Errors
    /// Returns the underlying [`AxiomError`] when `AXIOM_HOME` cannot be
    /// resolved, a discovered source cannot be read, or validation fails.
    pub fn load(daemon: Option<&Path>) -> Result<Self, AxiomError> {
        let environment = ConfigEnvironment::for_current_process();
        let home = AxiomHome::resolve(&PathEnvironment::for_current_process())?;
        home.verify_destination()?;
        let mut sources: Vec<PathBuf> = Vec::new();
        if let Some(explicit) = daemon {
            sources.push(explicit.to_path_buf());
        }
        sources.push(home.config_registry());
        for source in &sources {
            if source.is_file() {
                let document = std::fs::read_to_string(source).map_err(|error| {
                    invalid(
                        "config_source",
                        format!("configuration source could not be read: {error}"),
                    )
                })?;
                return Self::from_json_str_with(&document, &environment);
            }
        }
        Self::from_json_str_with("{}", &environment)
    }

    /// Deterministic canonical JSON of the frozen configuration.
    ///
    /// Keys are emitted in sorted order, so two equal configurations always
    /// produce byte-identical text and the value can be fingerprinted.
    #[must_use]
    pub fn canonical_json(&self) -> String {
        let raw = RawServiceConfig::from(self);
        serde_json::to_string(&raw).unwrap_or_else(|_| String::from("{}"))
    }

    fn apply_environment(&mut self, environment: &ConfigEnvironment) -> Result<(), AxiomError> {
        let Some(raw) = environment.allowed_source_roots.as_deref() else {
            return Ok(());
        };
        let requested: Vec<String> = raw
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if requested.is_empty() {
            return Err(invalid(
                "storage.allowedSourceRoots",
                format!("{ENV_ALLOWED_SOURCE_ROOTS} was set but named no directory"),
            ));
        }
        for root in &requested {
            if !is_absolute_host_path(root) {
                return Err(invalid(
                    "storage.allowedSourceRoots",
                    format!("{ENV_ALLOWED_SOURCE_ROOTS} names a non-absolute directory"),
                ));
            }
        }
        let narrowing = requested.iter().all(|candidate| {
            self.storage
                .allowed_source_roots
                .iter()
                .any(|root| same_root(root, candidate))
        });
        if !narrowing {
            return Err(invalid(
                "storage.allowedSourceRoots",
                format!(
                    "{ENV_ALLOWED_SOURCE_ROOTS} may only narrow the configured source roots; \
                     widening the read scope must be an explicit configuration change"
                ),
            ));
        }
        self.storage.allowed_source_roots = requested;
        Ok(())
    }

    fn validate(&self) -> Result<(), AxiomError> {
        if !crate::paths::is_portable_id(&self.daemon.instance_id) {
            return Err(invalid(
                "daemon.instanceId",
                "instanceId must be a portable slug (lowercase letters, digits, hyphen)",
            ));
        }
        if !is_loopback_host(&self.daemon.control_host) {
            return Err(invalid(
                "daemon.controlHost",
                "controlHost must be a loopback address; the control API is never bound to a public interface",
            ));
        }
        if let Some(token_file) = &self.daemon.token_file {
            if !is_absolute_host_path(token_file) {
                return Err(invalid(
                    "daemon.tokenFile",
                    "tokenFile must be an absolute path",
                ));
            }
        }
        if !(MIN_WORKER_COUNT..=MAX_WORKER_COUNT).contains(&self.runtime.worker_count) {
            return Err(invalid(
                "runtime.workerCount",
                format!("workerCount must be between {MIN_WORKER_COUNT} and {MAX_WORKER_COUNT}"),
            ));
        }
        if self.runtime.max_debounce_ms < self.runtime.debounce_ms {
            return Err(invalid(
                "runtime.maxDebounceMs",
                "maxDebounceMs must be greater than or equal to debounceMs",
            ));
        }
        if self.runtime.debounce_ms == 0 {
            return Err(invalid("runtime.debounceMs", "debounceMs must be positive"));
        }
        if self.runtime.shutdown_deadline_ms == 0
            || self.runtime.shutdown_deadline_ms > MAX_SHUTDOWN_DEADLINE_MS
        {
            return Err(invalid(
                "runtime.shutdownDeadlineMs",
                format!("shutdownDeadlineMs must be between 1 and {MAX_SHUTDOWN_DEADLINE_MS}"),
            ));
        }
        if self.runtime.parser_batch_files == 0
            || self.runtime.parser_batch_files > MAX_PARSER_BATCH_FILES
        {
            return Err(invalid(
                "runtime.parserBatchFiles",
                format!("parserBatchFiles must be between 1 and {MAX_PARSER_BATCH_FILES}"),
            ));
        }
        if self.runtime.parser_batch_bytes == 0
            || self.runtime.parser_batch_bytes > MAX_PARSER_BATCH_BYTES
        {
            return Err(invalid(
                "runtime.parserBatchBytes",
                "parserBatchBytes must be between 1 and 16777216",
            ));
        }
        if let Some(database_path) = &self.storage.database_path {
            if !is_absolute_host_path(database_path) {
                return Err(invalid(
                    "storage.databasePath",
                    "databasePath must be an absolute path",
                ));
            }
        }
        for root in &self.storage.allowed_source_roots {
            if !is_absolute_host_path(root) {
                return Err(invalid(
                    "storage.allowedSourceRoots",
                    "every allowed source root must be an absolute path",
                ));
            }
            if is_filesystem_root(root) {
                return Err(invalid(
                    "storage.allowedSourceRoots",
                    "a whole filesystem is never an allowed source root",
                ));
            }
        }
        if self.storage.busy_timeout_ms == 0 || self.storage.busy_timeout_ms > MAX_BUSY_TIMEOUT_MS {
            return Err(invalid(
                "storage.busyTimeoutMs",
                format!("busyTimeoutMs must be between 1 and {MAX_BUSY_TIMEOUT_MS}"),
            ));
        }
        if self.storage.journal_mode == JournalMode::Wal && !self.storage.require_local_storage {
            return Err(invalid(
                "storage.requireLocalStorage",
                "WAL requires local storage; set journalMode to DELETE to allow degraded shared storage",
            ));
        }
        if self.logging.rate_limit_per_minute == 0 {
            return Err(invalid(
                "logging.rateLimitPerMinute",
                "rateLimitPerMinute must be positive",
            ));
        }
        Ok(())
    }
}

/// Unvalidated wire shape. Kept private so no caller can build a
/// [`ServiceConfig`] that skipped validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawServiceConfig {
    #[serde(default)]
    daemon: RawDaemonConfig,
    #[serde(default)]
    runtime: RawRuntimeConfig,
    #[serde(default)]
    storage: RawStorageConfig,
    #[serde(default)]
    logging: RawLoggingConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawDaemonConfig {
    #[serde(default)]
    mode: DaemonMode,
    #[serde(default = "default_instance_id")]
    instance_id: String,
    #[serde(default = "default_control_host")]
    control_host: String,
    #[serde(default)]
    control_port: u16,
    #[serde(default)]
    token_file: Option<String>,
}

impl Default for RawDaemonConfig {
    fn default() -> Self {
        Self {
            mode: DaemonMode::default(),
            instance_id: default_instance_id(),
            control_host: default_control_host(),
            control_port: 0,
            token_file: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRuntimeConfig {
    #[serde(default = "default_worker_count")]
    worker_count: usize,
    #[serde(default = "default_debounce_ms")]
    debounce_ms: u64,
    #[serde(default = "default_max_debounce_ms")]
    max_debounce_ms: u64,
    #[serde(default = "default_shutdown_deadline_ms")]
    shutdown_deadline_ms: u64,
    #[serde(default = "default_parser_batch_files")]
    parser_batch_files: usize,
    #[serde(default = "default_parser_batch_bytes")]
    parser_batch_bytes: u64,
}

impl Default for RawRuntimeConfig {
    fn default() -> Self {
        let validated = RuntimeConfig::default();
        Self {
            worker_count: validated.worker_count,
            debounce_ms: validated.debounce_ms,
            max_debounce_ms: validated.max_debounce_ms,
            shutdown_deadline_ms: validated.shutdown_deadline_ms,
            parser_batch_files: validated.parser_batch_files,
            parser_batch_bytes: validated.parser_batch_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawStorageConfig {
    #[serde(default)]
    database_path: Option<String>,
    #[serde(default)]
    allowed_source_roots: Vec<String>,
    #[serde(default = "default_busy_timeout_ms")]
    busy_timeout_ms: u64,
    #[serde(default)]
    synchronous: SyncMode,
    #[serde(default)]
    journal_mode: JournalMode,
    #[serde(default = "default_true")]
    require_local_storage: bool,
}

impl Default for RawStorageConfig {
    fn default() -> Self {
        Self {
            database_path: None,
            allowed_source_roots: Vec::new(),
            busy_timeout_ms: DEFAULT_BUSY_TIMEOUT_MS,
            synchronous: SyncMode::default(),
            journal_mode: JournalMode::default(),
            require_local_storage: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawLoggingConfig {
    #[serde(default)]
    level: LogLevel,
    #[serde(default)]
    format: LogFormat,
    #[serde(default = "default_rate_limit")]
    rate_limit_per_minute: u32,
}

impl Default for RawLoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::default(),
            format: LogFormat::default(),
            rate_limit_per_minute: default_rate_limit(),
        }
    }
}

fn default_instance_id() -> String {
    "default".to_string()
}

fn default_control_host() -> String {
    "127.0.0.1".to_string()
}

fn default_worker_count() -> usize {
    RuntimeConfig::default().worker_count
}

fn default_debounce_ms() -> u64 {
    DEFAULT_DEBOUNCE_MS
}

fn default_max_debounce_ms() -> u64 {
    DEFAULT_MAX_DEBOUNCE_MS
}

fn default_shutdown_deadline_ms() -> u64 {
    DEFAULT_SHUTDOWN_DEADLINE_MS
}

fn default_parser_batch_files() -> usize {
    MAX_PARSER_BATCH_FILES
}

fn default_parser_batch_bytes() -> u64 {
    MAX_PARSER_BATCH_BYTES
}

fn default_busy_timeout_ms() -> u64 {
    DEFAULT_BUSY_TIMEOUT_MS
}

fn default_rate_limit() -> u32 {
    LoggingConfig::default().rate_limit_per_minute
}

fn default_true() -> bool {
    true
}

impl RawServiceConfig {
    fn into_validated(self) -> Result<ServiceConfig, AxiomError> {
        Ok(ServiceConfig {
            daemon: DaemonConfig {
                mode: self.daemon.mode,
                instance_id: self.daemon.instance_id,
                control_host: self.daemon.control_host,
                control_port: self.daemon.control_port,
                token_file: self.daemon.token_file,
            },
            runtime: RuntimeConfig {
                worker_count: self.runtime.worker_count,
                debounce_ms: self.runtime.debounce_ms,
                max_debounce_ms: self.runtime.max_debounce_ms,
                shutdown_deadline_ms: self.runtime.shutdown_deadline_ms,
                parser_batch_files: self.runtime.parser_batch_files,
                parser_batch_bytes: self.runtime.parser_batch_bytes,
            },
            storage: StorageConfig {
                database_path: self.storage.database_path,
                allowed_source_roots: self.storage.allowed_source_roots,
                busy_timeout_ms: self.storage.busy_timeout_ms,
                synchronous: self.storage.synchronous,
                journal_mode: self.storage.journal_mode,
                require_local_storage: self.storage.require_local_storage,
            },
            logging: LoggingConfig {
                level: self.logging.level,
                format: self.logging.format,
                rate_limit_per_minute: self.logging.rate_limit_per_minute,
            },
        })
    }
}

impl From<&ServiceConfig> for RawServiceConfig {
    fn from(value: &ServiceConfig) -> Self {
        Self {
            daemon: RawDaemonConfig {
                mode: value.daemon.mode,
                instance_id: value.daemon.instance_id.clone(),
                control_host: value.daemon.control_host.clone(),
                control_port: value.daemon.control_port,
                token_file: value.daemon.token_file.clone(),
            },
            runtime: RawRuntimeConfig {
                worker_count: value.runtime.worker_count,
                debounce_ms: value.runtime.debounce_ms,
                max_debounce_ms: value.runtime.max_debounce_ms,
                shutdown_deadline_ms: value.runtime.shutdown_deadline_ms,
                parser_batch_files: value.runtime.parser_batch_files,
                parser_batch_bytes: value.runtime.parser_batch_bytes,
            },
            storage: RawStorageConfig {
                database_path: value.storage.database_path.clone(),
                allowed_source_roots: value.storage.allowed_source_roots.clone(),
                busy_timeout_ms: value.storage.busy_timeout_ms,
                synchronous: value.storage.synchronous,
                journal_mode: value.storage.journal_mode,
                require_local_storage: value.storage.require_local_storage,
            },
            logging: RawLoggingConfig {
                level: value.logging.level,
                format: value.logging.format,
                rate_limit_per_minute: value.logging.rate_limit_per_minute,
            },
        }
    }
}

/// Case-insensitive equality of two absolute roots after separator normalisation.
fn same_root(left: &str, right: &str) -> bool {
    normalise_root(left).eq_ignore_ascii_case(&normalise_root(right))
}

fn normalise_root(value: &str) -> String {
    value.trim_end_matches(['/', '\\']).replace('\\', "/")
}

/// A bare `/` or `C:` names a whole filesystem, never a project root.
fn is_filesystem_root(path: &str) -> bool {
    let normalised = path.replace('\\', "/");
    let trimmed = normalised.trim_end_matches('/');
    trimmed.is_empty() || (trimmed.len() == 2 && trimmed.ends_with(':'))
}

/// Only loopback addresses may host the control API (docs/10-ARCHITECTURE.md E).
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(address) => address.is_loopback(),
        Err(_) => false,
    }
}

fn invalid(config_key: &str, message: impl AsRef<str>) -> AxiomError {
    AxiomError::new(ErrorCode::ConfigInvalid, message).with_detail("config_key", config_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid_key(error: &AxiomError) -> &str {
        assert_eq!(error.code(), ErrorCode::ConfigInvalid, "{error}");
        error
            .details()
            .get("config_key")
            .map(String::as_str)
            .expect("every rejection names the offending key")
    }

    #[test]
    fn an_empty_document_is_the_documented_baseline() {
        let config = ServiceConfig::from_json_str("{}").expect("empty document is valid");
        assert_eq!(config, ServiceConfig::default());
        assert_eq!(config.daemon().mode(), DaemonMode::Serve);
        assert_eq!(config.daemon().instance_id(), "default");
        assert_eq!(config.daemon().control_host(), "127.0.0.1");
        assert_eq!(config.daemon().control_port(), 0);
        assert_eq!(config.daemon().token_file(), None);
        assert_eq!(config.runtime().worker_count(), MIN_WORKER_COUNT);
        assert_eq!(config.runtime().debounce_ms(), DEFAULT_DEBOUNCE_MS);
        assert_eq!(config.runtime().max_debounce_ms(), DEFAULT_MAX_DEBOUNCE_MS);
        assert_eq!(
            config.runtime().shutdown_deadline_ms(),
            DEFAULT_SHUTDOWN_DEADLINE_MS
        );
        assert_eq!(
            config.runtime().parser_batch_files(),
            MAX_PARSER_BATCH_FILES
        );
        assert_eq!(
            config.runtime().parser_batch_bytes(),
            MAX_PARSER_BATCH_BYTES
        );
        assert_eq!(config.storage().database_path(), None);
        assert!(config.storage().allowed_source_roots().is_empty());
        assert_eq!(config.storage().busy_timeout_ms(), DEFAULT_BUSY_TIMEOUT_MS);
        assert_eq!(config.storage().synchronous(), SyncMode::Full);
        assert_eq!(config.storage().journal_mode(), JournalMode::Wal);
        assert!(config.storage().require_local_storage());
        assert_eq!(config.logging().level(), LogLevel::Info);
        assert_eq!(config.logging().format(), LogFormat::Json);
        assert_eq!(config.logging().rate_limit_per_minute(), 600);
    }

    #[test]
    fn a_full_document_round_trips_through_canonical_json() {
        let document = r#"{
            "daemon": {
                "mode": "doctor",
                "instanceId": "axiom-main",
                "controlHost": "localhost",
                "controlPort": 8123,
                "tokenFile": "C:\\ProgramData\\Axiom\\control.token"
            },
            "runtime": {
                "workerCount": 2,
                "debounceMs": 250,
                "maxDebounceMs": 1000,
                "shutdownDeadlineMs": 30000,
                "parserBatchFiles": 8,
                "parserBatchBytes": 1048576
            },
            "storage": {
                "databasePath": "C:\\ProgramData\\Axiom\\index.sqlite",
                "allowedSourceRoots": ["C:\\src\\axiom", "C:\\src\\tools"],
                "busyTimeoutMs": 2500,
                "synchronous": "NORMAL",
                "journalMode": "WAL",
                "requireLocalStorage": true
            },
            "logging": { "level": "debug", "format": "text", "rateLimitPerMinute": 120 }
        }"#;
        let config = ServiceConfig::from_json_str(document).expect("document is valid");
        assert_eq!(config.daemon().mode(), DaemonMode::Doctor);
        assert_eq!(config.daemon().instance_id(), "axiom-main");
        assert_eq!(config.daemon().control_port(), 8123);
        assert_eq!(config.runtime().worker_count(), 2);
        assert_eq!(config.runtime().debounce_ms(), 250);
        assert_eq!(config.storage().allowed_source_roots().len(), 2);
        assert_eq!(config.storage().synchronous(), SyncMode::Normal);
        assert_eq!(config.logging().level(), LogLevel::Debug);
        assert_eq!(config.logging().format(), LogFormat::Text);

        // Canonical JSON is byte-stable and re-parses to an equal configuration,
        // which is what lets a frozen configuration be fingerprinted.
        let canonical = config.canonical_json();
        assert_eq!(canonical, config.canonical_json());
        assert_eq!(
            ServiceConfig::from_json_str(&canonical).expect("canonical JSON re-parses"),
            config
        );
    }

    #[test]
    fn unknown_keys_are_rejected_at_every_level() {
        let top = ServiceConfig::from_json_str(r#"{"registry": {}}"#)
            .expect_err("an unknown top-level key must be rejected");
        assert_eq!(invalid_key(&top), "config");
        let nested = ServiceConfig::from_json_str(r#"{"runtime": {"workers": 2}}"#)
            .expect_err("an unknown nested key must be rejected");
        assert_eq!(invalid_key(&nested), "config");
        // Wire spelling is case sensitive, so a near-miss is an unknown key.
        let cased = ServiceConfig::from_json_str(r#"{"daemon": {"instanceid": "x"}}"#)
            .expect_err("only the documented camelCase spelling is accepted");
        assert_eq!(invalid_key(&cased), "config");
    }

    #[test]
    fn wrong_types_and_unparseable_wire_values_are_rejected() {
        for document in [
            r#"{"runtime": {"workerCount": "two"}}"#,
            r#"{"runtime": {"workerCount": -1}}"#,
            r#"{"daemon": {"controlPort": 70000}}"#,
            r#"{"storage": {"journalMode": "wal"}}"#,
            r#"{"storage": {"synchronous": "full"}}"#,
            r#"{"logging": {"level": "verbose"}}"#,
            r#"{"daemon": {"mode": "worker"}}"#,
            r#"{"storage": {"requireLocalStorage": "yes"}}"#,
        ] {
            let error = ServiceConfig::from_json_str(document)
                .expect_err("a malformed value must be rejected");
            assert_eq!(error.code(), ErrorCode::ConfigInvalid, "{document}");
        }
        let not_json = ServiceConfig::from_json_str("{").expect_err("truncated JSON");
        assert_eq!(invalid_key(&not_json), "config");
    }

    #[test]
    fn every_range_boundary_is_enforced() {
        let accepted = format!(
            r#"{{"runtime": {{"workerCount": {max_workers}, "parserBatchFiles": {max_files}, "parserBatchBytes": {max_bytes}}}, "storage": {{"busyTimeoutMs": {max_busy}}}}}"#,
            max_workers = MAX_WORKER_COUNT,
            max_files = MAX_PARSER_BATCH_FILES,
            max_bytes = MAX_PARSER_BATCH_BYTES,
            max_busy = MAX_BUSY_TIMEOUT_MS,
        );
        ServiceConfig::from_json_str(&accepted).expect("the documented maxima are inclusive");

        let cases = [
            (r#"{"runtime": {"workerCount": 0}}"#, "runtime.workerCount"),
            (r#"{"runtime": {"workerCount": 5}}"#, "runtime.workerCount"),
            (r#"{"runtime": {"debounceMs": 0}}"#, "runtime.debounceMs"),
            (
                r#"{"runtime": {"debounceMs": 500, "maxDebounceMs": 499}}"#,
                "runtime.maxDebounceMs",
            ),
            (
                r#"{"runtime": {"shutdownDeadlineMs": 0}}"#,
                "runtime.shutdownDeadlineMs",
            ),
            (
                r#"{"runtime": {"shutdownDeadlineMs": 600001}}"#,
                "runtime.shutdownDeadlineMs",
            ),
            (
                r#"{"runtime": {"parserBatchFiles": 65}}"#,
                "runtime.parserBatchFiles",
            ),
            (
                r#"{"runtime": {"parserBatchBytes": 16777217}}"#,
                "runtime.parserBatchBytes",
            ),
            (
                r#"{"storage": {"busyTimeoutMs": 0}}"#,
                "storage.busyTimeoutMs",
            ),
            (
                r#"{"storage": {"busyTimeoutMs": 60001}}"#,
                "storage.busyTimeoutMs",
            ),
            (
                r#"{"logging": {"rateLimitPerMinute": 0}}"#,
                "logging.rateLimitPerMinute",
            ),
        ];
        for (document, key) in cases {
            let error = ServiceConfig::from_json_str(document)
                .expect_err("an out-of-range value must be rejected");
            assert_eq!(invalid_key(&error), key, "{document}");
        }
    }

    #[test]
    fn paths_must_be_absolute_and_never_a_whole_filesystem() {
        let relative =
            ServiceConfig::from_json_str(r#"{"storage": {"databasePath": "data/index.sqlite"}}"#)
                .expect_err("a relative database path must be rejected");
        assert_eq!(invalid_key(&relative), "storage.databasePath");
        let relative_token =
            ServiceConfig::from_json_str(r#"{"daemon": {"tokenFile": "control.token"}}"#)
                .expect_err("a relative token file must be rejected");
        assert_eq!(invalid_key(&relative_token), "daemon.tokenFile");
        let relative_root =
            ServiceConfig::from_json_str(r#"{"storage": {"allowedSourceRoots": ["src/"]}}"#)
                .expect_err("a relative source root must be rejected");
        assert_eq!(invalid_key(&relative_root), "storage.allowedSourceRoots");

        // An explicit empty scope is valid: it reads nothing.
        ServiceConfig::from_json_str(r#"{"storage": {"allowedSourceRoots": []}}"#)
            .expect("declaring no source root is valid");

        for root in [r#"["C:\\"]"#, r#"["/"]"#, r#"["\\"]"#] {
            let document = format!(r#"{{"storage": {{"allowedSourceRoots": {root}}}}}"#);
            let error = ServiceConfig::from_json_str(&document)
                .expect_err("a whole filesystem is never a source root");
            assert_eq!(
                invalid_key(&error),
                "storage.allowedSourceRoots",
                "{document}"
            );
        }
    }

    #[test]
    fn only_loopback_may_host_the_control_api() {
        for host in ["127.0.0.1", "::1", "localhost", "LOCALHOST", "[::1]"] {
            let document = format!(r#"{{"daemon": {{"controlHost": "{host}"}}}}"#);
            ServiceConfig::from_json_str(&document).expect("loopback is accepted");
        }
        for host in ["0.0.0.0", "::", "192.168.1.5", "10.0.0.1", "example.com"] {
            let document = format!(r#"{{"daemon": {{"controlHost": "{host}"}}}}"#);
            let error = ServiceConfig::from_json_str(&document)
                .expect_err("a non-loopback control host must be rejected");
            assert_eq!(invalid_key(&error), "daemon.controlHost", "{host}");
        }
    }

    #[test]
    fn wal_requires_local_storage_but_delete_may_degrade() {
        let widened = ServiceConfig::from_json_str(
            r#"{"storage": {"journalMode": "WAL", "requireLocalStorage": false}}"#,
        )
        .expect_err("WAL over shared storage must be refused");
        assert_eq!(invalid_key(&widened), "storage.requireLocalStorage");

        let degraded = ServiceConfig::from_json_str(
            r#"{"storage": {"journalMode": "DELETE", "requireLocalStorage": false}}"#,
        )
        .expect("the documented degradation is valid");
        assert_eq!(degraded.storage().journal_mode(), JournalMode::Delete);
        assert!(!degraded.storage().require_local_storage());
    }

    #[test]
    fn instance_ids_must_be_portable_slugs() {
        ServiceConfig::from_json_str(r#"{"daemon": {"instanceId": "axiom-main-01"}}"#)
            .expect("a portable slug is accepted");
        for instance_id in ["Axiom", "axiom_main", "axiom main", "", "-leading"] {
            let document = format!(r#"{{"daemon": {{"instanceId": "{instance_id}"}}}}"#);
            let error = ServiceConfig::from_json_str(&document)
                .expect_err("a non-portable instance id must be rejected");
            assert_eq!(invalid_key(&error), "daemon.instanceId", "{instance_id}");
        }
    }

    #[test]
    fn the_environment_may_only_narrow_the_configured_source_roots() {
        let document =
            r#"{"storage": {"allowedSourceRoots": ["C:\\src\\axiom", "C:\\src\\tools"]}}"#;

        let narrowed = ServiceConfig::from_json_str_with(
            document,
            &ConfigEnvironment {
                allowed_source_roots: Some(String::from(r"C:\src\tools")),
            },
        )
        .expect("narrowing is allowed");
        assert_eq!(narrowed.storage().allowed_source_roots().len(), 1);
        assert_eq!(
            narrowed.storage().allowed_source_roots()[0],
            r"C:\src\tools"
        );

        // An unrelated absolute root, a whole filesystem, a relative root and an
        // empty list are all widenings or non-answers, and are refused.
        for raw in [r"C:\src\other", r"C:\\", "src", " , "] {
            let error = ServiceConfig::from_json_str_with(
                document,
                &ConfigEnvironment {
                    allowed_source_roots: Some(String::from(raw)),
                },
            )
            .expect_err("only a narrowing subset is accepted");
            assert_eq!(invalid_key(&error), "storage.allowedSourceRoots", "{raw}");
        }

        // The environment is inert when the variable is unset.
        let untouched = ServiceConfig::from_json_str_with(document, &ConfigEnvironment::default())
            .expect("an unset environment changes nothing");
        assert_eq!(untouched.storage().allowed_source_roots().len(), 2);
    }

    #[test]
    fn a_configured_root_may_grow_by_explicit_configuration_not_by_environment() {
        let document = r#"{"storage": {"allowedSourceRoots": ["C:\\src\\axiom"]}}"#;
        let grown = ServiceConfig::from_json_str_with(
            document,
            &ConfigEnvironment {
                allowed_source_roots: Some(String::from(r"C:\src\axiom\crates")),
            },
        )
        .expect_err("a subdirectory is still an unrelated root, not a narrowing");
        assert_eq!(invalid_key(&grown), "storage.allowedSourceRoots");

        let explicit = ServiceConfig::from_json_str(
            r#"{"storage": {"allowedSourceRoots": ["C:\\src\\axiom", "C:\\src\\axiom\\crates"]}}"#,
        )
        .expect("configuration itself may declare the wider scope");
        assert_eq!(explicit.storage().allowed_source_roots().len(), 2);
    }
}
