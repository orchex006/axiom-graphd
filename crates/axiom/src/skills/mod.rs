//! Skill bundle installation and update surfaces (tasks E-032, E-033).
//!
//! `specs/v2/B-axiom-graphd.md` puts the installer in `axiom-graphd` while the
//! canonical skill and policy bytes are produced by `axiom-skills` and consumed
//! from a pinned package. The modules here own the *consumer* half:
//!
//! * [`install`] -- install a versioned skill bundle, where only the paths the
//!   bundle declares are written and an unexpected executable needs an explicit
//!   capability review (task E-032).
//! * [`update`] -- the read-only skills version check and the approved-plan
//!   update path, which never claims a Markdown-only bundle updates itself
//!   (task E-033).
//!
//! Both modules are pure policy plus a small injected mutation surface: the
//! tests drive in-memory doubles, the only filesystem writer is the production
//! [`install::LocalInstallFs`], and nothing here contacts the network, spawns a
//! process or infers a version from a timestamp.

pub mod install;
pub mod update;
