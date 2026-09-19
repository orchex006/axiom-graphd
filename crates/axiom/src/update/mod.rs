//! Update policy, activation, verification and rollback (tasks E-035..E-048).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` splits the updater into one check
//! route and one update route per component, and it fixes the trust rule that
//! decides everything else: production updates come from published releases in
//! repositories the user actually allowlisted, and a checksum plus the
//! transport is completeness, never proof of publisher. Section 6 fixes the
//! order of one update transaction: acquire the coordinator lock, download,
//! verify, preflight, drain, back up, migrate, stage versioned directories,
//! smoke check, swap the active install manifest, restart, probe, resume and
//! finalize. The modules here are that policy and that transaction, one bounded
//! task each.
//!
//! ## Check, compatibility and plan (E-035..E-041)
//!
//! * [`source`] -- the configured owner/repo/channel an update may come from,
//!   with no default invented from a component name (task E-035).
//! * [`trust`] -- signed metadata freshness with rollback and freeze
//!   protection against configured trust roots (task E-036).
//! * [`check`] -- the cached, TTL- and offline-aware version check, which can
//!   never download or run an installer (task E-037).
//! * [`resolve`] -- the ecosystem compatibility set, so "latest" is never
//!   assumed compatible (task E-038).
//! * [`plan`] -- the update and migration plan, including backups, service
//!   drain and rollback feasibility (task E-039).
//! * [`drain`] -- bounded service drain before activation, where a forced kill
//!   is never the default (task E-040).
//! * [`backup`] -- consistent, hash-verified DB and managed-state backups,
//!   without which an irreversible migration is refused (task E-041).
//!
//! ## Activation, verification, rollback and policy (E-042..E-046)
//!
//! The install pipeline in [`crate::install`] owns planning, trust verification
//! and the approved activation of a staged payload; the modules below own the
//! half that runs *after* a payload exists:
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
//! Two further deliverables of the same work package live outside this module
//! because their owning paths are fixed by their cards: [`crate::support`] builds
//! the redacted support bundle (task E-047) and `release/core-manifest.json` plus
//! `tests/core_manifest.py` carry the one core release manifest and its
//! regression check (task E-048).
//!
//! Nothing in this module tree opens a socket, spawns a process or writes
//! outside a caller-supplied target: mutations go through a small trait, the
//! production implementation is the only one that touches the filesystem, and
//! the tests drive in-memory doubles. `docs/20-VERSION-CHECK-UPDATE-RELEASE.md`
//! section 9 keeps tag creation, release publication and signing under an
//! authorized maintenance workflow, so no function in this module can perform
//! them.

pub mod backup;
pub mod check;
pub mod drain;
pub mod plan;
pub mod policy;
pub mod python_env;
pub mod resolve;
pub mod rollback;
pub mod rust_binary;
pub mod source;
pub mod trust;
pub mod verify;
