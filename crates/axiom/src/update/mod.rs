//! Update source, trust, check, compatibility, plan, drain and backup
//! (tasks E-035..E-041).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` splits the updater into one check
//! route and one update route per component, and it fixes the trust rule that
//! decides everything else: production updates come from published releases in
//! repositories the user actually allowlisted, and a checksum plus the
//! transport is completeness, never proof of publisher. The modules here are
//! that policy, one bounded task each:
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
//! Nothing in this module tree opens a socket, spawns a process or writes
//! outside a caller-supplied target. The `update apply` transaction, the
//! platform activation steps, the post-update doctor and the state-aware
//! rollback are later tasks (E-042..E-045) and are deliberately absent here.

pub mod backup;
pub mod check;
pub mod drain;
pub mod plan;
pub mod resolve;
pub mod source;
pub mod trust;
