//! Command implementations that live in the binary crate.
//!
//! Each module owns one operator-facing slice and is compiled with the library
//! so it is unit testable without spawning a process. The argv surface, the
//! single-JSON-object stdout contract and the exit-code mapping stay in
//! [`crate::cli`]; task H-001 wires every module below into it through
//! [`crate::cli::OPERATOR_SLICES`], and the compile-time link table
//! (`slice_links`) fails to build if a module is unwired or missing.
//!
//! Wiring is not implementation. Every wired verb parses its full documented
//! argument surface, rejects an unknown flag or a malformed argument with
//! `VALIDATION_ERROR` (exit 2), and then answers `NOT_READY` (exit 4) with the
//! reason that names the binding it still needs, until the work package that
//! owns that binding lands. No wired verb answers an empty success.
//!
//! * [`changed`] - accept explicit changed-file hints (task B-032).
//! * [`queue`] - queue inspection, retry and cooperative cancellation
//!   (task B-043).
//! * [`solution`] - solution registry administration (task B-084).
//! * [`doctor`] - doctor and status health reports (task B-085).
//! * [`reconcile`] - the three reconcile scopes and the bounded wait
//!   (task B-086).
//! * [`query`] - bounded context and impact over a pinned snapshot
//!   (task B-087).
//! * [`update`] - delegated, approval-bound update apply (task B-092).

pub mod changed;
pub mod doctor;
pub mod query;
pub mod queue;
pub mod reconcile;
pub mod solution;
pub mod update;

/// Map an underlying storage or I/O failure onto the shared internal code.
///
/// `graph-store` keeps its own helper crate-private, and the daemon crate
/// deliberately does not widen that surface, so the command layer owns the same
/// mapping instead of depending on a private item.
pub(crate) fn storage_error(
    context: &str,
    error: &dyn std::fmt::Display,
) -> graph_core::error::AxiomError {
    graph_core::error::AxiomError::new(
        graph_core::error::ErrorCode::Internal,
        format!("{context}: {error}"),
    )
}
