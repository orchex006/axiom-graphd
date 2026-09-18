//! Command implementations that live in the binary crate.
//!
//! Each module owns one operator-facing slice and is compiled with the library
//! so it is unit testable without spawning a process. The argv surface, the
//! single-JSON-object stdout contract and the exit-code mapping stay in
//! [`crate::cli`]; the command work package wires these modules into it.
//!
//! * [`changed`] - accept explicit changed-file hints (task B-032).
//! * [`queue`] - queue inspection, retry and cooperative cancellation
//!   (task B-043).

pub mod changed;
pub mod queue;

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
