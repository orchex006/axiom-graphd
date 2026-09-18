//! The Axiom graph daemon and its core CLI.
//!
//! The crate is split so the process-level behaviour is testable without
//! spawning a process and without capturing the caller's own streams:
//!
//! * [`cli`] - argv parsing, the single-JSON-object stdout contract and the
//!   frozen exit codes (tasks B-001, B-002),
//! * [`instance_lock`] - one writer per Axiom home and dead-owner recovery
//!   (task B-004),
//! * [`lifecycle`] - cooperative shutdown and bounded drain (task B-006),
//! * [`telemetry`] - redacted, rate-limited diagnostics on stderr (task B-007),
//! * [`version`] - the frozen version report plus runtime facts (task B-008),
//! * [`commands`] - the operator command slices: explicit changed-file hints
//!   (task B-032) and queue inspection/retry/cancel (task B-043).

pub mod cli;
pub mod commands;
pub mod instance_lock;
pub mod lifecycle;
pub mod telemetry;
pub mod version;
