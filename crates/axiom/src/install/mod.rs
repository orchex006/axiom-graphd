//! Installation planning, verification and activation (tasks E-004..E-006).
//!
//! `docs/16-CLI-AND-CONTROL-API.md` section 4 splits installation into a
//! reviewable dry run (`install plan`) and an approved activation
//! (`install apply`), and `21-INSTALLATION.md` section C fixes what a reviewer
//! must see in between. The modules here follow that split, so the dry run is
//! testable without a host, a download or a service manager:
//!
//! * [`plan`] -- the dry-run plan: component versions, destinations, download
//!   sources, required permissions, service changes and planned network access
//!   (task E-004).
//!
//! Verification and activation land as their own work packages and record their
//! own task ids, the same way every module in this crate does.

pub mod plan;
