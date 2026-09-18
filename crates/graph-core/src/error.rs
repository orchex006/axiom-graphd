//! Stable error codes, the error envelope and process exit codes (task B-002).
//!
//! Every failure that crosses a process boundary carries an [`ErrorCode`] whose
//! string form is stable, plus redacted [`AxiomError::details`]. In JSON mode the
//! process writes the envelope `{code,message,retryable,details,request_id}`
//! (contracts/control-api-v1.md) to stdout and nothing else: diagnostic prose
//! goes to stderr through `axiom-graphd::telemetry`.
//!
//! Exit codes are a stable CLI contract documented in `docs/CLI-EXIT-CODES.md`.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::redact;

/// Schema identifier of the error envelope payload.
pub const ERROR_ENVELOPE_SCHEMA: &str = "urn:axiom:graph:error:1";

/// Stable, machine-readable failure codes.
///
/// The wire form (used in JSON, control responses and support bundles) is the
/// `SCREAMING_SNAKE_CASE` spelling, which must not change without a contract
/// change in `axiom-specs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// Input was structurally valid but did not satisfy validation rules.
    ValidationError,
    /// The caller is not authenticated to the daemon control API.
    Unauthenticated,
    /// The caller is authenticated but not permitted for this scope.
    Forbidden,
    /// A referenced entity does not exist.
    NotFound,
    /// The request conflicts with current state.
    Conflict,
    /// Input cannot be used by this binary (for example a newer schema).
    IncompatibleInput,
    /// The caller exceeded a bounded rate or budget.
    RateLimited,
    /// The daemon is not ready to serve the request.
    NotReady,
    /// Another writer already owns this instance or output namespace.
    WriterAlreadyRunning,
    /// The Git worktree is in a state that cannot be checkpointed safely.
    WorktreeBusy,
    /// An applied migration's checksum does not match the shipped SQL.
    MigrationChecksumMismatch,
    /// Applied migrations are not an ordered prefix of the shipped migrations.
    MigrationOrderConflict,
    /// The database schema is newer than this binary knows about.
    SchemaNewerThanBinary,
    /// The SQLite runtime lacks a required fix.
    SqliteUnsupportedVersion,
    /// Mutable state was requested on unsupported (network/shared) storage.
    SqliteNetworkStorageUnsupported,
    /// `AXIOM_HOME` resolved to an unsafe shared/remote location.
    UnsafeHomePath,
    /// A portable repository-relative path violated the portability policy.
    UnsafePortablePath,
    /// Configuration was invalid; the service must not start.
    ConfigInvalid,
    /// Work was refused because shutdown has started.
    ShuttingDown,
    /// An invariant failed; this is an Axiom defect, not caller error.
    Internal,
}

impl ErrorCode {
    /// Stable wire spelling of the code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidationError => "VALIDATION_ERROR",
            Self::Unauthenticated => "UNAUTHENTICATED",
            Self::Forbidden => "FORBIDDEN",
            Self::NotFound => "NOT_FOUND",
            Self::Conflict => "CONFLICT",
            Self::IncompatibleInput => "INCOMPATIBLE_INPUT",
            Self::RateLimited => "RATE_LIMITED",
            Self::NotReady => "NOT_READY",
            Self::WriterAlreadyRunning => "WRITER_ALREADY_RUNNING",
            Self::WorktreeBusy => "WORKTREE_BUSY",
            Self::MigrationChecksumMismatch => "MIGRATION_CHECKSUM_MISMATCH",
            Self::MigrationOrderConflict => "MIGRATION_ORDER_CONFLICT",
            Self::SchemaNewerThanBinary => "SCHEMA_NEWER_THAN_BINARY",
            Self::SqliteUnsupportedVersion => "SQLITE_UNSUPPORTED_VERSION",
            Self::SqliteNetworkStorageUnsupported => "SQLITE_NETWORK_STORAGE_UNSUPPORTED",
            Self::UnsafeHomePath => "UNSAFE_HOME_PATH",
            Self::UnsafePortablePath => "UNSAFE_PORTABLE_PATH",
            Self::ConfigInvalid => "CONFIG_INVALID",
            Self::ShuttingDown => "SHUTTING_DOWN",
            Self::Internal => "INTERNAL",
        }
    }

    /// Whether retrying the same request later can plausibly succeed.
    #[must_use]
    pub const fn default_retryable(self) -> bool {
        matches!(
            self,
            Self::Conflict
                | Self::RateLimited
                | Self::NotReady
                | Self::WorktreeBusy
                | Self::ShuttingDown
        )
    }

    /// Every code, in declaration order, for contract tests.
    #[must_use]
    pub const fn all() -> &'static [ErrorCode] {
        &[
            Self::ValidationError,
            Self::Unauthenticated,
            Self::Forbidden,
            Self::NotFound,
            Self::Conflict,
            Self::IncompatibleInput,
            Self::RateLimited,
            Self::NotReady,
            Self::WriterAlreadyRunning,
            Self::WorktreeBusy,
            Self::MigrationChecksumMismatch,
            Self::MigrationOrderConflict,
            Self::SchemaNewerThanBinary,
            Self::SqliteUnsupportedVersion,
            Self::SqliteNetworkStorageUnsupported,
            Self::UnsafeHomePath,
            Self::UnsafePortablePath,
            Self::ConfigInvalid,
            Self::ShuttingDown,
            Self::Internal,
        ]
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Process exit codes. Frozen CLI contract; see `docs/CLI-EXIT-CODES.md` and
/// `axiom-specs` docs/16-CLI-AND-CONTROL-API.md section 6.
///
/// The numbers are a stable interface: `0` success, `2` validation, `3` not
/// found, `4` not ready/stale, `5` authorization, `6` conflict, `7`
/// timeout/busy, `8` I/O internal, `9` incompatible, `10` lock unavailable and
/// `20` partial multi-repository operation.
///
/// `1` is deliberately unused. A bare `exit(1)` must never be reachable from a
/// mapped Axiom failure, so a caller cannot confuse a crash with a real
/// diagnostic; the spec's table skips it and so does this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExitCode {
    /// `0` - command completed successfully.
    Success,
    /// `2` - flags, arguments or configuration were rejected.
    Validation,
    /// `3` - a referenced entity does not exist.
    NotFound,
    /// `4` - the service is not ready, or the requested state is stale.
    NotReady,
    /// `5` - the caller is not authenticated or not permitted for this scope.
    Authorization,
    /// `6` - the request conflicts with current state.
    Conflict,
    /// `7` - a bounded wait expired or the resource is busy; retry may work.
    TimeoutOrBusy,
    /// `8` - I/O failure or an internal Axiom defect.
    IoInternal,
    /// `9` - input, runtime or schema is incompatible with this binary.
    Incompatible,
    /// `10` - a required cross-process lock is held by another owner.
    LockUnavailable,
    /// `20` - a multi-repository operation partially succeeded.
    PartialOperation,
}

impl ExitCode {
    /// Numeric exit status handed to the operating system.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::Validation => 2,
            Self::NotFound => 3,
            Self::NotReady => 4,
            Self::Authorization => 5,
            Self::Conflict => 6,
            Self::TimeoutOrBusy => 7,
            Self::IoInternal => 8,
            Self::Incompatible => 9,
            Self::LockUnavailable => 10,
            Self::PartialOperation => 20,
        }
    }

    /// Short human-readable meaning, used by `--help` and the exit-code document.
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Validation => "validation",
            Self::NotFound => "not found",
            Self::NotReady => "not ready/stale",
            Self::Authorization => "authorization",
            Self::Conflict => "conflict",
            Self::TimeoutOrBusy => "timeout/busy",
            Self::IoInternal => "I/O internal",
            Self::Incompatible => "incompatible",
            Self::LockUnavailable => "lock unavailable",
            Self::PartialOperation => "partial multi-repo operation",
        }
    }

    /// Every mapped exit code, in ascending numeric order, for contract tests
    /// and documentation generation.
    #[must_use]
    pub const fn all() -> &'static [ExitCode] {
        &[
            Self::Success,
            Self::Validation,
            Self::NotFound,
            Self::NotReady,
            Self::Authorization,
            Self::Conflict,
            Self::TimeoutOrBusy,
            Self::IoInternal,
            Self::Incompatible,
            Self::LockUnavailable,
            Self::PartialOperation,
        ]
    }
}

impl fmt::Display for ExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.as_i32(), self.meaning())
    }
}

/// Map a stable error code onto its process exit code.
///
/// [`ExitCode::PartialOperation`] intentionally has no [`ErrorCode`] source: it
/// is produced by the multi-repository operation summary, not by a single
/// failure.
#[must_use]
pub const fn exit_code_for(code: ErrorCode) -> ExitCode {
    match code {
        ErrorCode::ValidationError
        | ErrorCode::ConfigInvalid
        | ErrorCode::UnsafeHomePath
        | ErrorCode::UnsafePortablePath => ExitCode::Validation,
        ErrorCode::NotFound => ExitCode::NotFound,
        ErrorCode::NotReady | ErrorCode::ShuttingDown => ExitCode::NotReady,
        ErrorCode::Unauthenticated | ErrorCode::Forbidden => ExitCode::Authorization,
        ErrorCode::Conflict | ErrorCode::WorktreeBusy => ExitCode::Conflict,
        ErrorCode::RateLimited => ExitCode::TimeoutOrBusy,
        ErrorCode::WriterAlreadyRunning => ExitCode::LockUnavailable,
        ErrorCode::Internal => ExitCode::IoInternal,
        ErrorCode::IncompatibleInput
        | ErrorCode::MigrationChecksumMismatch
        | ErrorCode::MigrationOrderConflict
        | ErrorCode::SchemaNewerThanBinary
        | ErrorCode::SqliteUnsupportedVersion
        | ErrorCode::SqliteNetworkStorageUnsupported => ExitCode::Incompatible,
    }
}

/// JSON payload returned for a failed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelope {
    /// Stable failure code.
    pub code: ErrorCode,
    /// Redacted, single-line description.
    pub message: String,
    /// Whether a later retry can plausibly succeed.
    pub retryable: bool,
    /// Redacted structured context, restricted to allowlisted keys.
    pub details: BTreeMap<String, String>,
    /// Correlation id for this request, when one exists.
    pub request_id: Option<String>,
}

/// A typed Axiom failure with a stable code and redacted context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AxiomError {
    code: ErrorCode,
    message: String,
    retryable: bool,
    details: BTreeMap<String, String>,
    dropped_details: usize,
    request_id: Option<String>,
}

impl AxiomError {
    /// Create an error, scrubbing the message before it is stored.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl AsRef<str>) -> Self {
        let scrubbed = redact::scrub(message.as_ref());
        let message = if scrubbed.trim().is_empty() {
            code.as_str().to_string()
        } else {
            scrubbed
        };
        Self {
            code,
            message,
            retryable: code.default_retryable(),
            details: BTreeMap::new(),
            dropped_details: 0,
            request_id: None,
        }
    }

    /// Attach redacted context.
    ///
    /// Keys outside [`redact::ALLOWED_DETAIL_KEYS`] are dropped and counted in
    /// [`AxiomError::dropped_details`]; values are always scrubbed.
    #[must_use]
    pub fn with_detail(mut self, key: &str, value: impl AsRef<str>) -> Self {
        if !redact::is_allowed_detail_key(key) {
            self.dropped_details += 1;
            return self;
        }
        let key = key.to_ascii_lowercase();
        self.details.insert(key, redact::scrub(value.as_ref()));
        self
    }

    /// Override the retryability derived from the code.
    #[must_use]
    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    /// Attach the request correlation id.
    #[must_use]
    pub fn with_request_id(mut self, request_id: impl AsRef<str>) -> Self {
        self.request_id = Some(redact::scrub(request_id.as_ref()));
        self
    }

    /// Stable code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// Redacted description.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether a later retry can plausibly succeed.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    /// Redacted structured context.
    #[must_use]
    pub fn details(&self) -> &BTreeMap<String, String> {
        &self.details
    }

    /// Number of detail keys rejected by the allowlist.
    #[must_use]
    pub const fn dropped_details(&self) -> usize {
        self.dropped_details
    }

    /// Request correlation id, when one exists.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    /// Process exit code for this failure.
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        exit_code_for(self.code)
    }

    /// Borrow the wire envelope.
    #[must_use]
    pub fn envelope(&self) -> ErrorEnvelope {
        ErrorEnvelope {
            code: self.code,
            message: self.message.clone(),
            retryable: self.retryable,
            details: self.details.clone(),
            request_id: self.request_id.clone(),
        }
    }

    /// Serialize the wire envelope as JSON.
    ///
    /// # Errors
    /// Returns an [`ErrorCode::Internal`] error if serialization fails, which
    /// would indicate a defect in the envelope type rather than caller input.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        serde_json::to_string(&self.envelope())
            .map_err(|err| AxiomError::new(ErrorCode::Internal, format!("serialize error: {err}")))
    }
}

impl fmt::Display for AxiomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AxiomError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_codes_are_stable() {
        let expected = [
            (ErrorCode::ValidationError, "VALIDATION_ERROR"),
            (ErrorCode::Unauthenticated, "UNAUTHENTICATED"),
            (ErrorCode::Forbidden, "FORBIDDEN"),
            (ErrorCode::NotFound, "NOT_FOUND"),
            (ErrorCode::Conflict, "CONFLICT"),
            (ErrorCode::IncompatibleInput, "INCOMPATIBLE_INPUT"),
            (ErrorCode::RateLimited, "RATE_LIMITED"),
            (ErrorCode::NotReady, "NOT_READY"),
            (ErrorCode::WriterAlreadyRunning, "WRITER_ALREADY_RUNNING"),
            (ErrorCode::WorktreeBusy, "WORKTREE_BUSY"),
            (
                ErrorCode::MigrationChecksumMismatch,
                "MIGRATION_CHECKSUM_MISMATCH",
            ),
            (
                ErrorCode::MigrationOrderConflict,
                "MIGRATION_ORDER_CONFLICT",
            ),
            (ErrorCode::SchemaNewerThanBinary, "SCHEMA_NEWER_THAN_BINARY"),
            (
                ErrorCode::SqliteUnsupportedVersion,
                "SQLITE_UNSUPPORTED_VERSION",
            ),
            (
                ErrorCode::SqliteNetworkStorageUnsupported,
                "SQLITE_NETWORK_STORAGE_UNSUPPORTED",
            ),
            (ErrorCode::UnsafeHomePath, "UNSAFE_HOME_PATH"),
            (ErrorCode::UnsafePortablePath, "UNSAFE_PORTABLE_PATH"),
            (ErrorCode::ConfigInvalid, "CONFIG_INVALID"),
            (ErrorCode::ShuttingDown, "SHUTTING_DOWN"),
            (ErrorCode::Internal, "INTERNAL"),
        ];
        assert_eq!(expected.len(), ErrorCode::all().len());
        for (code, wire) in expected {
            assert_eq!(code.as_str(), wire);
            assert!(ErrorCode::all().contains(&code));
        }
    }

    #[test]
    fn exit_codes_are_a_stable_table() {
        // The numbers are frozen by docs/16-CLI-AND-CONTROL-API.md section 6.
        let expected = [
            (ErrorCode::ValidationError, 2),
            (ErrorCode::ConfigInvalid, 2),
            (ErrorCode::UnsafeHomePath, 2),
            (ErrorCode::UnsafePortablePath, 2),
            (ErrorCode::NotFound, 3),
            (ErrorCode::NotReady, 4),
            (ErrorCode::ShuttingDown, 4),
            (ErrorCode::Unauthenticated, 5),
            (ErrorCode::Forbidden, 5),
            (ErrorCode::Conflict, 6),
            (ErrorCode::WorktreeBusy, 6),
            (ErrorCode::RateLimited, 7),
            (ErrorCode::Internal, 8),
            (ErrorCode::IncompatibleInput, 9),
            (ErrorCode::MigrationChecksumMismatch, 9),
            (ErrorCode::MigrationOrderConflict, 9),
            (ErrorCode::SchemaNewerThanBinary, 9),
            (ErrorCode::SqliteUnsupportedVersion, 9),
            (ErrorCode::SqliteNetworkStorageUnsupported, 9),
            (ErrorCode::WriterAlreadyRunning, 10),
        ];
        assert_eq!(expected.len(), ErrorCode::all().len());
        for (code, number) in expected {
            assert_eq!(exit_code_for(code).as_i32(), number, "code {code}");
        }
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::PartialOperation.as_i32(), 20);
        // 1 and every other unnamed value stay unassigned.
        assert!(!ExitCode::all().iter().any(|c| c.as_i32() == 1));
        assert_eq!(ExitCode::all().len(), 11);
    }

    #[test]
    fn exit_code_table_is_frozen_and_documented() {
        let expected = [
            (0, "success"),
            (2, "validation"),
            (3, "not found"),
            (4, "not ready/stale"),
            (5, "authorization"),
            (6, "conflict"),
            (7, "timeout/busy"),
            (8, "I/O internal"),
            (9, "incompatible"),
            (10, "lock unavailable"),
            (20, "partial multi-repo operation"),
        ];
        assert_eq!(ExitCode::all().len(), expected.len());
        for (code, (number, meaning)) in ExitCode::all().iter().zip(expected) {
            assert_eq!(code.as_i32(), number);
            assert_eq!(code.meaning(), meaning);
        }
        // Ascending numeric order keeps the published table copy-pasteable.
        let mut numbers: Vec<i32> = ExitCode::all().iter().map(|c| c.as_i32()).collect();
        let sorted = numbers.clone();
        numbers.sort_unstable();
        assert_eq!(numbers, sorted);
    }

    #[test]
    fn retryable_defaults_are_per_code() {
        assert!(ErrorCode::NotReady.default_retryable());
        assert!(ErrorCode::WorktreeBusy.default_retryable());
        assert!(!ErrorCode::ValidationError.default_retryable());
        assert!(!ErrorCode::SqliteUnsupportedVersion.default_retryable());
    }

    #[test]
    fn non_allowlisted_details_are_dropped() {
        let err = AxiomError::new(ErrorCode::ValidationError, "bad input")
            .with_detail("job_id", "job-1")
            .with_detail("token", "super-secret")
            .with_detail("source_body", "fn main() {}");
        assert_eq!(
            err.details().get("job_id").map(String::as_str),
            Some("job-1")
        );
        assert!(!err.details().contains_key("token"));
        assert!(!err.details().contains_key("source_body"));
        assert_eq!(err.dropped_details(), 2);
        let json = err.to_json().expect("serializable");
        assert!(!json.contains("super-secret"));
        assert!(!json.contains("fn main"));
    }

    #[test]
    fn detail_values_are_scrubbed() {
        let err = AxiomError::new(ErrorCode::ConfigInvalid, "config rejected")
            .with_detail("config_key", "source_root")
            .with_detail("observsed", "x")
            .with_detail("observed", r"C:\Users\me\repo");
        assert_eq!(
            err.details().get("observed").map(String::as_str),
            Some(redact::REDACTED_PATH)
        );
        assert!(!err
            .to_json()
            .expect("serializable")
            .contains(r"C:\Users\me"));
    }

    #[test]
    fn messages_are_scrubbed_and_never_empty() {
        let err = AxiomError::new(ErrorCode::UnsafeHomePath, r"refused C:\Users\me\share");
        assert!(!err.message().contains("Users"));
        let empty = AxiomError::new(ErrorCode::Internal, "   ");
        assert_eq!(empty.message(), "INTERNAL");
    }

    #[test]
    fn json_envelope_has_exactly_the_contract_fields() {
        let err = AxiomError::new(ErrorCode::Conflict, "writer already running")
            .with_detail("solution_id", "demo")
            .with_request_id("req-1");
        let json = err.to_json().expect("serializable");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        let object = value.as_object().expect("object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["code", "details", "message", "request_id", "retryable"]
        );
        assert_eq!(object["code"], serde_json::Value::from("CONFLICT"));
        assert_eq!(object["retryable"], serde_json::Value::from(true));
        // No diagnostic prose, stack traces or prose-only fields leak into JSON.
        assert!(!json.contains("at src/"));
        assert!(err.envelope().request_id.as_deref() == Some("req-1"));
    }

    #[test]
    fn display_is_code_then_message() {
        let err = AxiomError::new(ErrorCode::NotFound, "project missing");
        assert_eq!(err.to_string(), "NOT_FOUND: project missing");
        assert_eq!(err.exit_code(), ExitCode::NotFound);
    }
}
