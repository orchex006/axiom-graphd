//! Durable SQLite storage for the Axiom graph engine.
//!
//! This crate owns the two storage tasks of the rust-runtime-foundation work
//! package:
//!
//! * B-009 ([`open`]) - open the database through the patched SQLite runtime,
//!   enforce the local-disk WAL baseline and apply the pragmas that make the
//!   durable queue safe.
//! * B-010 ([`migrations`]) - verify schema checksums and version ordering and
//!   apply ordered migrations transactionally, so a failed migration leaves the
//!   previous database usable.
//!
//! Both modules keep native I/O behind small injected interfaces (a volume probe
//! and a plain connection), so the behaviour is unit testable on any host.

pub mod migrations;
pub mod open;

pub use migrations::{CURRENT_SCHEMA_VERSION, SCHEMA_V1_SQL};
pub use open::{
    runtime_sqlite_version, runtime_version_probe, LexicalVolumeProbe, OpenOptions, SqliteVersion,
    Store, VolumeProbe, MIN_SQLITE_VERSION, WAL_RESET_BACKPORTS,
};

/// Open the store with the durable-state defaults (WAL on local storage).
///
/// # Errors
/// Returns the same errors as [`open::open`].
pub fn open(
    options: &OpenOptions,
    probe: &dyn VolumeProbe,
) -> Result<Store, graph_core::error::AxiomError> {
    open::open(options, probe)
}

/// Map an underlying storage or I/O failure onto the shared internal code.
pub(crate) fn storage_error(
    context: &str,
    error: &dyn std::fmt::Display,
) -> graph_core::error::AxiomError {
    graph_core::error::AxiomError::new(
        graph_core::error::ErrorCode::Internal,
        format!("{context}: {error}"),
    )
}
