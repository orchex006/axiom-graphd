//! Installation, bootstrap and operations core for the Axiom core release.
//!
//! `crates/axiom-cli` is the thin `axiom` executable; behaviour lives here so it
//! is testable without spawning a process, mirroring `crates/axiom-graphd`.
//!
//! Ownership: `SOURCE-OF-TRUST.md` section 1 places the installer, the bootstrap
//! engine, the service adapters and the standalone `axiom` executable in
//! `axiom-graphd`, and `specs/v2/B-axiom-graphd.md` requires the daemon and the
//! CLI to be published from one locked Rust workspace and one core version. This
//! crate is that CLI's core, never a second repository or a second release.
//!
//! Each module records the bounded task that added it, so every behaviour maps
//! back to one reviewable task card.

pub mod cli;
pub mod discovery;
pub mod install;
pub mod plan;
pub mod service;
pub mod update;
pub mod version;
