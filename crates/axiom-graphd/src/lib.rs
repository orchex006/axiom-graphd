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
//!   (task B-032), queue inspection/retry/cancel (task B-043), the solution
//!   registry (task B-084), doctor/status (task B-085), reconcile (task
//!   B-086), bounded query (task B-087) and update delegation (task B-092),
//! * [`control`] - loopback control authentication (task B-083),
//! * [`runtime`] - the shared store/registry/bindings opening that every
//!   operator command and the foreground daemon reuse (task H-002),
//! * [`serve`] - the foreground reconcile worker loop: inventory, analyse,
//!   stage and publish a generation under the publication barrier (task H-002),
//! * [`checkpoint`] - staged, worktree, export and CI verification of a
//!   checkpoint (tasks B-088 - B-091),
//! * [`release`] - the release artifact publication gate (task B-093),
//! * [`update_guard`] - update and migration safe-refusal admission for the
//!   portable update fixtures (task F-010).

pub mod checkpoint;
pub mod cli;
pub mod commands;
pub mod control;
pub mod instance_lock;
pub mod lifecycle;
pub mod release;
pub mod runtime;
pub mod serve;
pub mod telemetry;
pub mod update_guard;
pub mod version;
