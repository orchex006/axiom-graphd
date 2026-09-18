//! Durable SQLite storage for the Axiom graph engine.
//!
//! This crate owns the storage tasks of the runtime foundation (B-009, B-010)
//! and the store-side tasks of the solution/registration work package (B-011,
//! B-012, B-015 - B-020):
//!
//! * B-009 ([`open`]) - open the database through the patched SQLite runtime,
//!   enforce the local-disk WAL baseline and apply the pragmas that make the
//!   durable queue safe.
//! * B-010 ([`migrations`]) - verify schema checksums and version ordering and
//!   apply ordered migrations transactionally, so a failed migration leaves the
//!   previous database usable.
//! * B-011 ([`writer`]) - serialize worker results through a single bounded
//!   writer actor, so one connection mutates and no parse runs inside a
//!   transaction.
//! * B-012 ([`solutions`]) - bind a profile and worktree to a stable instance
//!   key so two worktrees never share mutable state.
//! * B-015 ([`files`]) - generation-aware inventory and tombstone reconciliation,
//!   so a deleted file is never reported clean.
//! * B-016 ([`graph_rows`]) - replace one file's facts while preserving other
//!   owners and invalidating references to removed targets.
//! * B-017 ([`reverse_index`]) - answer incoming-reference queries across
//!   projects without mistaking an unindexed scope for "no callers".
//! * B-018 ([`backup`]) - take consistent backups through the SQLite backup
//!   path, never by copying a live `.db` file.
//! * B-019 ([`repair`]) - quarantine corrupt state, schedule a rebuild and never
//!   modify user source.
//! * B-020 ([`unregister`]) - remove a binding while stopping scheduling and
//!   preserving source and unrelated checkpoints.
//!
//! Both modules keep native I/O behind small injected interfaces (a volume probe
//! and a plain connection), so the behaviour is unit testable on any host.

pub mod backup;
pub mod files;
pub mod graph_rows;
pub mod migrations;
pub mod open;
pub mod outbox;
pub mod repair;
pub mod reverse_index;
pub mod solutions;
pub mod unregister;
pub mod writer;

#[cfg(test)]
mod test_support;

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
