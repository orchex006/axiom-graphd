//! Platform-independent domain logic for the Axiom graph engine.
//!
//! This crate owns Axiom's typed errors and exit-code mapping (task B-002),
//! platform state-home and portable-path resolution (B-003), and validated,
//! immutable runtime configuration (B-005). It keeps native I/O behind narrow
//! caller-supplied interfaces (CP-02) so the logic stays testable on any host.

pub mod bindings;
pub mod config;
pub mod error;
pub mod paths;
pub mod redact;
pub mod solution;
