//! Managed multi-repository bootstrap engine (tasks E-013 .. E-021).
//!
//! `docs/18-BOOTSTRAP-AND-MANAGED-INSTRUCTIONS.md` and the operations guide
//! `docs/guides/bootstrap.md` fix what bootstrap owns inside a repository and
//! nothing else:
//!
//! * a small managed pointer block between
//!   [`markers::BEGIN_MARKER`] and [`markers::END_MARKER`] in `AGENTS.md`,
//! * the canonical policy file `.axiom/agent/POLICY.md`,
//! * the ownership manifest `.axiom/agent/bootstrap.lock.json`.
//!
//! Every module here records the bounded task that added it:
//!
//! * [`repos`] - E-013: the explicitly bound approved repository set.
//! * [`markers`] - E-014: fence-aware, fail-closed marker parsing.
//! * [`text`] - E-015: byte-, BOM- and newline-preserving text handling.
//! * [`policy`] - E-016: the separate managed policy file.
//! * [`ownership`] - E-017: the ownership manifest and template version.
//! * [`plan`] - E-018: the reviewable, read-only multi-repo plan.
//! * [`preconditions`] - E-019: before-hash re-verification and the apply lock.
//! * [`apply`] - E-020: journaled, backup-protected application.
//! * [`verify`] - E-021: idempotence and drift reporting.
//!
//! The engine is deliberately host-free in its policy half: planning, marker
//! parsing, encoding and ownership are pure functions over bytes, so the same
//! verdict is produced in tests, in the CLI and on any platform. Only the
//! explicitly named host adapters ([`repos::LocalRepoProbe`],
//! [`plan::LocalRepositoryReader`], [`apply::LocalBootstrapHost`]) touch a
//! filesystem, and each of them only does what its name says.
//!
//! Bootstrap never truncates, never relocates, never appends a second block,
//! never recursively deletes `.axiom` or `.agrimap-agent`, never overwrites
//! unowned content, never auto-discovers every repository under `HOME` and
//! never force-pushes a repository to make a plan pass. A conflict always means
//! refuse-and-preserve.

use graph_core::error::{AxiomError, ErrorCode};

pub mod markers;
pub mod ownership;
pub mod policy;
pub mod repos;
pub mod text;

/// Schema version of the bootstrap documents this build writes.
///
/// The ownership manifest carries its own version
/// (`ownership::OWNERSHIP_SCHEMA_VERSION`); this constant is the version of the
/// plan and report envelopes, so a plan produced by a later build is refused
/// instead of being half-understood.
pub const BOOTSTRAP_SCHEMA_VERSION: u32 = 1;

/// Template version this build ships for the managed block and the policy.
///
/// `fixtures/bootstrap/vectors.json` pins the same version, so a re-apply that
/// changes the template version fails the corpus instead of silently rewriting
/// every repository.
pub const TEMPLATE_VERSION: &str = "2.0.0-draft.1";

/// Build the refusal every bootstrap slice returns for a state it will not own.
///
/// One stable `rule` detail is attached, so a caller can tell *why* bootstrap
/// refused without parsing a prose message; the message itself stays readable
/// for an operator.
pub fn refuse(rule: &'static str, message: impl Into<String>) -> AxiomError {
    AxiomError::new(ErrorCode::Conflict, message.into()).with_detail("rule", rule)
}

/// Build a refusal that names the field and the observed value, like the rest
/// of the installer does.
pub fn refuse_field(rule: &'static str, field: &str, observed: &str) -> AxiomError {
    refuse(rule, format!("refused {field}"))
        .with_detail("field", field)
        .with_detail("observed", observed)
}
