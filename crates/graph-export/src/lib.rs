//! Publication of the analysed graph: canonical bytes, shards, manifests and
//! the atomic generation pointer (tasks B-067 - B-082).
//!
//! The export package has one invariant. A reader either sees a complete
//! generation or it sees the previous one; it never sees a half-written
//! generation, and it never sees a generation whose bytes do not match the
//! hashes its manifest recorded. Every module here works towards that
//! invariant, and every failure is reported as an [`ExportError`] with a stable
//! code rather than as a partial result.
//!
//! The modules, in publication order:
//!
//! * [`canonical`] - B-067, the canonical byte form every artifact uses.
//! * [`shard`] - B-068, deterministic sharding under a byte cap.
//! * [`indexes`] - B-069, shard locators for each edge.
//! * [`manifest`] - B-070, byte-accurate inventory and generation identity.
//! * [`staging`] - B-071, writes that are not yet visible to readers.
//! * [`validate`] - B-072, the gate a staged generation must pass.
//! * [`pointer`] - B-075, the atomic current-generation switch.
//! * [`recovery`] - B-077, resuming a crashed publication.
//! * [`catalog`] - B-078, the pinned generation vector.
//! * [`reader`] - B-079, guarded reads of one generation.
//! * [`gc`] - B-080, deleting only what nothing retains.
//! * [`disk_budget`] - B-081, refusing to publish past the budget.
//! * [`archive`] - B-082, verifying a snapshot without claiming freshness.

pub mod archive;
pub mod canonical;
pub mod catalog;
pub mod disk_budget;
pub mod gc;
pub mod indexes;
pub mod manifest;
pub mod pointer;
pub mod reader;
pub mod recovery;
pub mod shard;
pub mod staging;
pub mod validate;

use std::fmt;

/// Error code for a filesystem failure.
pub const ERR_IO: &str = "export-io";
/// Error code for a document that cannot be canonically encoded.
pub const ERR_CANONICAL: &str = "export-canonical";
/// Error code for bytes that do not match their recorded hash.
pub const ERR_INTEGRITY: &str = "export-integrity";
/// Error code for a generation that is missing or incomplete.
pub const ERR_MISSING: &str = "export-missing";
/// Error code for an operation the platform cannot perform safely.
pub const ERR_UNSUPPORTED: &str = "export-unsupported";
/// Error code for a publication that would exceed the disk budget.
pub const ERR_BUDGET: &str = "export-budget";
/// Error code for a lock that is held by someone else.
pub const ERR_LOCKED: &str = "export-locked";

/// A publication failure with a stable code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportError {
    /// Stable, greppable code such as `export-integrity`.
    pub code: &'static str,
    /// Human-readable explanation.
    pub message: String,
}

impl ExportError {
    /// Build an error with a stable code.
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Build an I/O error with the underlying description.
    #[must_use]
    pub fn io(error: &std::io::Error) -> Self {
        Self::new(ERR_IO, error.to_string())
    }
}

impl fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ExportError {}

/// Result of a publication operation.
pub type Result<T> = std::result::Result<T, ExportError>;

/// Raw SHA-256 digest of `bytes`.
#[must_use]
pub fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Lowercase hex of a SHA-256 digest.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha256_bytes(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// One value in the exported graph, addressable by a stable key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GraphRecord {
    /// Stable record key.
    pub key: String,
    /// Record kind, for example `edge` or `symbol`.
    pub kind: String,
    /// Record body. Its shape belongs to the producer, not to this crate.
    pub body: serde_json::Value,
}

impl GraphRecord {
    /// Build a record.
    #[must_use]
    pub fn new(key: impl Into<String>, kind: impl Into<String>, body: serde_json::Value) -> Self {
        Self {
            key: key.into(),
            kind: kind.into(),
            body,
        }
    }
}
