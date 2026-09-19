//! Activation, post-update verification, rollback, update policy and the core
//! release manifest (tasks E-042 - E-048).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 6 fixes the order of one
//! update transaction: acquire the coordinator lock, download, verify, preflight,
//! drain, back up, migrate, **stage versioned directories**, smoke check, swap the
//! active install manifest, restart, probe, resume and finalize. The install
//! pipeline in [`crate::install`] owns planning, trust verification and the
//! approved activation of a staged payload; the modules here own the half that
//! runs *after* a payload exists:
//!
//! * [`rust_binary`] -- activation of the Rust binaries through versioned
//!   directories and a pointer move, which is the only shape that works when the
//!   executable being replaced may still be running (task E-042).
//! * [`python_env`] -- activation of the MCP interpreter environment from a
//!   locked, versioned build, never by mutating the active environment in place
//!   (task E-043).
//! * [`verify`] -- the post-update doctor: health, handshake and schema probes
//!   whose failure raises a *bounded* rollback instead of accepting a superficial
//!   success (task E-044).
//! * [`rollback`] -- state-aware rollback of binary, database schema and policy as
//!   one compatible set, with unsupported downgrades explicitly blocked
//!   (task E-045).
//! * [`policy`] -- the update policy that decides whether a candidate may be
//!   applied automatically, defaulting to explicit approval (task E-046).
//!
//! Two more deliverables of the same work package live outside this module
//! because their owning paths are fixed by their cards: [`crate::support`] builds
//! the redacted support bundle (task E-047) and `release/core-manifest.json` plus
//! `tests/core_manifest.py` carry the one core release manifest and its
//! regression check (task E-048).
//!
//! ## What these modules refuse to do
//!
//! Every module here is deliberately pure with respect to the host: mutations go
//! through a small trait, the production implementation is the only one that
//! touches the filesystem, and the tests drive in-memory doubles. None of them
//! contacts the network, spawns a shell, writes a release tag or publishes
//! anything. `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 9 keeps tag
//! creation, release publication and signing under an authorized maintenance
//! workflow, so no function in this module can perform them.

pub mod rust_binary;
