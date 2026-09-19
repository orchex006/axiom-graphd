//! Agent-host adaptation: detection, per-host config plans and host verification.
//!
//! `axiom host detect --json` answers which agent host is installed and at which
//! version (task E-026); one adapter per host renders that host's own config and
//! instruction fragment shape instead of copying a single JSON blob to every host
//! (tasks E-027..E-030), and `verify` proves an applied host config really speaks
//! MCP before it is called integrated (task E-031).
//!
//! Every adapter in this module is a *planner*: it renders bounded fragments and
//! refuses unsafe input, and none of them writes to a real host installation. The
//! writes stay in the bootstrap/install path that owns them, which is why the
//! per-host plans here can be reviewed as pure byte transformations.

pub mod antigravity;
pub mod claude;
pub mod codex;
pub mod detect;
pub mod gemini;
