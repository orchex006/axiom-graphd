//! Ecosystem-wide prerequisite probe and one-command install orchestration
//! (task I-004).
//!
//! `axiom-specs` `contracts/ecosystem-installation-contract.md` declares what one
//! ecosystem installation is: one entrypoint (`axiom`, provided by
//! `axiom-graphd`), a fixed install order, a prerequisite matrix, an idempotent
//! re-run rule, a rollback boundary and a forbidden prerequisite set. The
//! per-component planner ([`crate::install::plan`]) and activation
//! ([`crate::install::apply`]) already exist, and so does per-repository
//! bootstrap. What no module owned is the *ecosystem* view: probe every
//! prerequisite the contract declares, report each one, and place all three
//! contract components in contract order behind a single approval digest.
//!
//! This module is that view. It adds no second plan digest and no second
//! encoder: the ecosystem plan is sealed with the one canonical digest of
//! [`crate::plan`], exactly as an install plan is sealed with
//! [`crate::install::plan::sealed`].
//!
//! ## Install order
//!
//! [`INSTALL_ORDER`] is fixed by contract section 2 and is not a preference:
//! the core release carries the `axiom` CLI that performs every remaining
//! install, the gateway consumes the installed core, and the skills bundle wires
//! hosts to an already installed core and gateway.
//!
//! The ecosystem bundle therefore declares the two core components
//! ([`CORE_COMPONENTS`]) and the skills bundle beside it carries the third
//! ([`SKILLS_COMPONENT`]). A bundle that declares a component this module cannot
//! place in the contract order is refused by name rather than silently dropped:
//! [`RULE_ORDER`] names it. The `axiom` CLI artifact is part of the core release
//! and ships inside the `axiom-graphd` component, so it is not a fourth row.
//!
//! ## Prerequisite matrix
//!
//! [`declarations`] is the contract's section 3 matrix plus the two rows AC1
//! names for the entrypoint itself (the host executable and the
//! permission/elevation state). Every row is one `(component, class)` pair and
//! records the declaration status, the requirement, the owning version source
//! and the pin, so a caller can never read a requirement this build did not
//! declare.
//!
//! A row whose contract status is `undeclared` is *reported* and never
//! *guessed*: this module has no "look up the latest version" path, so an
//! undeclared row can only come back `unsatisfied` or `unknown`.
//!
//! The one version this module compares against is taken from the owning
//! component, never copied: the store WAL baseline is rendered from
//! `graph_store::open::MIN_SQLITE_VERSION` by [`Expected::render`], so a store
//! baseline change moves this report with it.
//!
//! ## What blocks, and what does not
//!
//! A row is `blocking` when it is `required` and its observed status is not
//! `satisfied`. Only rows this ecosystem *owns a pin for* are `required`:
//!
//! * `axiom-graphd/runtime` -- a supported native OS on local storage,
//! * `axiom-mcp/interpreter` -- Python `>=3.13,<3.14`,
//! * `axiom-graphd/host_executable` -- the running `axiom` executable,
//! * `axiom-graphd/permission` -- per-user write access, never elevation.
//!
//! The other rows are reported honestly and are deliberately not gating:
//!
//! * `axiom-graphd/toolchain` (the Rust 1.85.0 channel) is a *developer and
//!   build* prerequisite; the prebuilt bundle needs no compiler.
//! * `axiom-graphd/interpreter`, `axiom-mcp/toolchain`, `axiom-skills/interpreter`
//!   and `axiom-skills/toolchain` are declared as *no requirement at all*.
//! * `axiom-mcp/runtime` and `axiom-skills/runtime` are discharged by the
//!   installation itself, so the planner obligation is the report.
//! * `axiom-graphd/native_dependency` (the patched SQLite runtime) is recorded
//!   `undeclared` by contract section 3 with a null version source, and section
//!   10 states that an undeclared item "blocks a claim, not the contract". The
//!   store's own runtime gate stays the enforcement point, and this module
//!   records the row as a *verification gap* instead of inventing a pin the
//!   contract forbids inventing. A run on a host whose SQLite is below the
//!   store's WAL baseline therefore reports the row `unsatisfied`, names it in
//!   `verification_gaps`, and still installs.
//! * `axiom-skills/approval` is bound by [`crate::plan::approval_reasons`] at
//!   activation time, which is a stronger gate than a probe: an activation with
//!   no approved digest is refused outright.
//!
//! ## Probe before write
//!
//! [`plan_ecosystem`] probes every declared row and refuses through
//! [`prerequisite_refusal`] *before* it reads the bundle, and
//! [`apply_ecosystem`] re-verifies the recorded rows *before* it writes a byte.
//! The report travels inside the sealed plan, so the approval a human gives
//! covers the prerequisite state that was observed.
//!
//! ## One plan, one digest, contract order
//!
//! [`EcosystemPlan`] carries one [`EcosystemComponentPlan`] per contract
//! position. Each carries the sealed per-component plan it activates and the
//! digest that activation is approved at, and the whole document is sealed with
//! one [`crate::plan`] digest. [`verify_ecosystem`] re-derives every one of
//! those digests, checks the contract order and positions, checks that each core
//! sub-plan covers exactly its own single component, checks that the skills
//! plan's activation digest is the digest of the reviewed skills manifest, and
//! checks that the core sub-plans kept the ecosystem rollback and target
//! boundary. An approval of one ecosystem plan can therefore never activate a
//! different one.
//!
//! ## Idempotency and the rollback boundary
//!
//! A re-run over an existing installation reports `already-installed` and moves
//! nothing: [`apply_ecosystem`] compares the destination bytes against the
//! payload digest the plan recorded, and when every component and every skills
//! step already holds those bytes it returns without calling the activation
//! engine at all, so no pointer, journal entry or rollback record is rewritten.
//! A partially applied installation resumes at component granularity: only the
//! components whose bytes are not in place are activated, and each keeps its own
//! transaction, journal entry and rollback record from the update engine.
//! Byte equality is also the rollback boundary that engine already uses -- a
//! rollback restores only files whose current bytes still match the recorded
//! after-hash, so a later human edit is kept.
//!
//! ## Never required
//!
//! [`FORBIDDEN_MECHANISMS`] is the contract's hard-reject set. Nothing in this
//! module, and nothing it calls, requires WSL, Docker, Bash, elevation, Node.js
//! or a system service for a foreground install: the process launches programs
//! through [`crate::hosts::detect::HostProbe`] program and argv, never an
//! interpolated shell string, and the plan is per-user with no `elevated`
//! permission.

use std::path::Path;

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{
    classify_storage_lexically, is_absolute_host_path, Platform, StorageClass,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::hosts::detect::{HostProbe, VERSION_ARGV};
use crate::install::apply::{apply_install, ApplyRequest, InstallFs as ActivationFs};
use crate::install::plan::{
    is_digest, plan_install as plan_component, read_bundle_manifest, sealed, BundleManifest,
    BundleReference, ComponentAction, DryRun, InstallPlan, InstallScope, InstallTarget,
    ObservedComponent, PlanContext, RollbackPlan, HOSTS, MIN_KEEP_PREVIOUS_VERSIONS,
    PLAN_KIND as COMPONENT_PLAN_KIND,
};
use crate::skills::install::{
    install as install_skills, plan_install as plan_skills, InstallFs as SkillsFs,
    InstallPlan as SkillsPlan, InstallStep as SkillsStep, LocalPayloadSource, PayloadSource,
    SkillBundle, ACTIVE_POINTER, BUNDLES_DIR as SKILLS_BUNDLES_DIR,
    MANIFEST_FILE as SKILLS_MANIFEST_FILE, MAX_MANIFEST_BYTES as SKILLS_MAX_MANIFEST_BYTES,
};

/// Contract identifier this module implements.
pub const CONTRACT_ID: &str = "axiom-ecosystem-installation";

/// The fixed contract install order (contract section 2).
pub const INSTALL_ORDER: [&str; 3] = ["axiom-graphd", "axiom-mcp", "axiom-skills"];

/// The components the core bundle declares, in contract order.
pub const CORE_COMPONENTS: [&str; 2] = [INSTALL_ORDER[0], INSTALL_ORDER[1]];

/// The component the skills bundle carries into the third contract position.
pub const SKILLS_COMPONENT: &str = INSTALL_ORDER[2];

/// Directory inside the verified bundle that holds the skills bundle.
pub const SKILLS_DIRECTORY: &str = "skills";

/// Subdirectory of the skills bundle that holds the payload files.
pub const SKILLS_PAYLOAD_DIRECTORY: &str = "payload";

/// `plan_kind` that marks the embedded skills plan.
pub const SKILLS_PLAN_KIND: &str = "skills-install";

/// `schema_version` of the ecosystem plan document.
pub const ECOSYSTEM_PLAN_SCHEMA_VERSION: u64 = 1;

/// `plan_kind` that marks a document as an ecosystem-install plan.
pub const ECOSYSTEM_PLAN_KIND: &str = "ecosystem-install";

/// Digest domain of the whole ecosystem plan body.
pub const ECOSYSTEM_DIGEST_SCHEMA: &str = "axiom-ecosystem-install-digest-v1";

/// Digest domain of one component entry inside the ecosystem plan.
pub const ECOSYSTEM_COMPONENT_DIGEST_SCHEMA: &str = "axiom-ecosystem-component-digest-v1";

/// `schema_version` of an ecosystem application record.
pub const ECOSYSTEM_APPLICATION_SCHEMA_VERSION: u64 = 1;

/// Exit code of a successful ecosystem install.
pub const EXIT_OK: u8 = 0;

/// Exit code of a refused ecosystem install (`ErrorCode::NotReady`).
pub const EXIT_NOT_READY: u8 = 4;

/// The Rust toolchain channel `rust-toolchain.toml` pins (provisional pin).
pub const RUST_PIN: &str = "1.85.0";

/// Lowest Python the gateway declares (`>=3.13,<3.14`).
pub const PYTHON_MIN: (u32, u32, u32) = (3, 13, 0);

/// First Python the gateway refuses.
pub const PYTHON_MAX_EXCLUSIVE: (u32, u32, u32) = (3, 14, 0);

/// Mechanisms a native install must never require (`requirements.json` R22).
pub const FORBIDDEN_MECHANISMS: [&str; 6] = [
    "wsl",
    "docker",
    "bash",
    "elevation",
    "node",
    "systemd_foreground",
];

/// Detail `rule` naming a blocking prerequisite.
pub const RULE_PREREQUISITE: &str = "prerequisite-unsatisfied";

/// Detail `rule` naming a component outside the contract order.
pub const RULE_ORDER: &str = "component-order";

/// Detail `rule` naming a bundle that omits a contract component.
pub const RULE_MISSING_COMPONENT: &str = "component-missing";

/// Detail `rule` naming a core sub-plan that is not a single-component plan.
pub const RULE_SINGLE_COMPONENT_PLAN: &str = "single-component-plan";

/// Detail `rule` naming a component entry whose digest does not match its body.
pub const RULE_COMPONENT_DIGEST: &str = "component-digest";

/// Detail `rule` naming a core sub-plan that moved the rollback boundary.
pub const RULE_ROLLBACK_BOUNDARY: &str = "rollback-boundary";

/// Detail `rule` naming a plan whose prerequisite report is not the matrix.
pub const RULE_PREREQUISITES_PROBED: &str = "prerequisites-probed";

/// Detail `rule` naming an activation with no bound approval.
pub const RULE_APPROVAL: &str = "approval";

/// Detail `rule` naming a document that is not one sealed ecosystem plan.
pub const RULE_ONE_PLAN: &str = "one-plan";

/// Detail `rule` naming incomplete staging.
pub const RULE_STAGING_INCOMPLETE: &str = "staging_incomplete";

/// Approval reason: the approved digest is not the digest of this body.
pub const REASON_APPROVAL_STALE: &str = "approval_stale";

/// Approval reason: the body carries no matching recorded digest.
pub const REASON_DIGEST_MISMATCH: &str = "plan_digest_mismatch";

/// Status of a component the activation engine placed.
pub const STATUS_INSTALLED: &str = "installed";

/// Status of a component whose payload bytes were already in place.
pub const STATUS_ALREADY_INSTALLED: &str = "already-installed";

/// Verification gap recorded when the store's SQLite baseline is not met.
pub const GAP_SQLITE_WAL_BASELINE: &str = "sqlite-wal-reset-baseline";

/// Why the ecosystem refused, in one named rule and one observed value.
#[must_use]
pub fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the ecosystem install input violates the installation contract",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

/// The prerequisite classes the contract records, plus the two AC1 rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrerequisiteClass {
    /// A language interpreter the component needs at runtime.
    Interpreter,
    /// A build or developer toolchain.
    Toolchain,
    /// A runtime facility the component is placed into.
    Runtime,
    /// A native dependency the component links or bundles.
    NativeDependency,
    /// An explicit human approval before activation.
    Approval,
    /// The entrypoint executable performing the install (AC1).
    HostExecutable,
    /// The write and elevation state of the target (AC1).
    Permission,
}

impl PrerequisiteClass {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interpreter => "interpreter",
            Self::Toolchain => "toolchain",
            Self::Runtime => "runtime",
            Self::NativeDependency => "native_dependency",
            Self::Approval => "approval",
            Self::HostExecutable => "host_executable",
            Self::Permission => "permission",
        }
    }
}

/// What the owning repository declared for one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclarationStatus {
    /// The row declares a requirement.
    Declared,
    /// The row declares explicitly that there is no requirement.
    DeclaredNone,
    /// The owning repository declares no value; never guessed here.
    Undeclared,
}

impl DeclarationStatus {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::DeclaredNone => "declared-none",
            Self::Undeclared => "undeclared",
        }
    }
}

/// The version one row is compared against.
///
/// The variance between rows is not prose: a row either names a literal pin the
/// owning repository published, or it names the store's own WAL baseline, whose
/// text is rendered from `graph_store`'s constant rather than copied here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expected {
    /// A pin the owning document publishes verbatim.
    Value(&'static str),
    /// The patched SQLite baseline the store gate enforces.
    SqliteWalBaseline,
}

impl Expected {
    /// The text this row reports as its expectation.
    #[must_use]
    pub fn render(self) -> String {
        match self {
            Self::Value(text) => text.to_string(),
            Self::SqliteWalBaseline => format!(
                "SQLite >= {} (the store WAL baseline)",
                graph_store::open::MIN_SQLITE_VERSION
            ),
        }
    }
}

/// One `(component, class)` row of the prerequisite matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrerequisiteDeclaration {
    /// Component the row belongs to.
    pub component: &'static str,
    /// Class of prerequisite.
    pub class: PrerequisiteClass,
    /// What the owning repository declared.
    pub status: DeclarationStatus,
    /// The requirement, in reviewable prose.
    pub requirement: &'static str,
    /// The document that proves the requirement, when one exists.
    pub version_source: Option<&'static str>,
    /// The pin, or `undeclared` when the owning repository defines none.
    pub pin: &'static str,
    /// Whether an unmet row refuses the installation.
    pub required: bool,
    /// The version this build compares against, when there is one.
    pub expected: Option<Expected>,
}

/// The prerequisite matrix this build probes, in report order.
static DECLARATIONS: [PrerequisiteDeclaration; 13] = [
    PrerequisiteDeclaration {
        component: "axiom-graphd",
        class: PrerequisiteClass::Interpreter,
        status: DeclarationStatus::DeclaredNone,
        requirement: "none: the core release ships a prebuilt native binary and bundles its SQLite dependency, so no interpreter is required at runtime",
        version_source: Some("axiom-specs/repo-seeds/axiom-graphd/docs/21-INSTALLATION.md"),
        pin: "declared-none",
        required: false,
        expected: None,
    },
    PrerequisiteDeclaration {
        component: "axiom-graphd",
        class: PrerequisiteClass::Toolchain,
        status: DeclarationStatus::Declared,
        requirement: "Rust toolchain 1.85.0 (rustfmt, clippy, minimal profile) for developer and build use only; the prebuilt bundle requires no compiler",
        version_source: Some("axiom-graphd/rust-toolchain.toml"),
        pin: "provisional",
        required: false,
        expected: Some(Expected::Value(RUST_PIN)),
    },
    PrerequisiteDeclaration {
        component: "axiom-graphd",
        class: PrerequisiteClass::Runtime,
        status: DeclarationStatus::Declared,
        requirement: "supported native OS with local disk, and Git only when checkpoint history is used",
        version_source: Some("axiom-specs/repo-seeds/axiom-graphd/docs/21-INSTALLATION.md"),
        pin: "declared",
        required: true,
        expected: Some(Expected::Value("a supported host with local-disk state storage")),
    },
    PrerequisiteDeclaration {
        component: "axiom-graphd",
        class: PrerequisiteClass::NativeDependency,
        status: DeclarationStatus::Undeclared,
        requirement: "the patched SQLite runtime the store requires is bundled or explicitly declared, and its runtime version is checked for the required WAL fixes",
        version_source: None,
        pin: "undeclared",
        required: false,
        expected: Some(Expected::SqliteWalBaseline),
    },
    PrerequisiteDeclaration {
        component: "axiom-graphd",
        class: PrerequisiteClass::HostExecutable,
        status: DeclarationStatus::Declared,
        requirement: "the entrypoint executable performing the install is present and is an absolute host path",
        version_source: Some("axiom-specs/contracts/ecosystem-installation-contract.md#1"),
        pin: "declared",
        required: true,
        expected: Some(Expected::Value("the running axiom executable")),
    },
    PrerequisiteDeclaration {
        component: "axiom-graphd",
        class: PrerequisiteClass::Permission,
        status: DeclarationStatus::Declared,
        requirement: "the target root is writable by the current user without elevation",
        version_source: Some("axiom-specs/requirements.json#R22"),
        pin: "declared",
        required: true,
        expected: Some(Expected::Value("per-user write access, never elevation")),
    },
    PrerequisiteDeclaration {
        component: "axiom-mcp",
        class: PrerequisiteClass::Interpreter,
        status: DeclarationStatus::Declared,
        requirement: "Python >=3.13,<3.14; a system interpreter is not assumed on a clean Windows or macOS host, so both python3 and python are probed",
        version_source: Some("axiom-mcp/pyproject.toml"),
        pin: "declared",
        required: true,
        expected: Some(Expected::Value("Python >=3.13,<3.14")),
    },
    PrerequisiteDeclaration {
        component: "axiom-mcp",
        class: PrerequisiteClass::Toolchain,
        status: DeclarationStatus::DeclaredNone,
        requirement: "none: the gateway ships as wheels with a locked dependency set, so no compiler is required on the target host",
        version_source: Some("axiom-specs/docs/20-VERSION-CHECK-UPDATE-RELEASE.md"),
        pin: "declared-none",
        required: false,
        expected: None,
    },
    PrerequisiteDeclaration {
        component: "axiom-mcp",
        class: PrerequisiteClass::Runtime,
        status: DeclarationStatus::Declared,
        requirement: "one versioned virtual environment per installed version, activated by a manifest pointer; never pip install over the active environment",
        version_source: Some("axiom-specs/docs/20-VERSION-CHECK-UPDATE-RELEASE.md"),
        pin: "declared",
        required: false,
        expected: Some(Expected::Value("created by this installation")),
    },
    PrerequisiteDeclaration {
        component: "axiom-skills",
        class: PrerequisiteClass::Interpreter,
        status: DeclarationStatus::DeclaredNone,
        requirement: "none declared: the bundle declares host capabilities and no interpreter",
        version_source: Some("axiom-skills/release/skills-manifest.json"),
        pin: "declared-none",
        required: false,
        expected: None,
    },
    PrerequisiteDeclaration {
        component: "axiom-skills",
        class: PrerequisiteClass::Toolchain,
        status: DeclarationStatus::DeclaredNone,
        requirement: "none declared: the bundle is policy, skill and adapter content plus hooks, and requires no build toolchain",
        version_source: Some("axiom-skills/release/skills-manifest.json"),
        pin: "declared-none",
        required: false,
        expected: None,
    },
    PrerequisiteDeclaration {
        component: "axiom-skills",
        class: PrerequisiteClass::Runtime,
        status: DeclarationStatus::Declared,
        requirement: "versioned bundle directories activated through a reviewed manifest; activation switches the manifest pointer",
        version_source: Some("axiom-specs/docs/20-VERSION-CHECK-UPDATE-RELEASE.md"),
        pin: "declared",
        required: false,
        expected: Some(Expected::Value("created by this installation")),
    },
    PrerequisiteDeclaration {
        component: "axiom-skills",
        class: PrerequisiteClass::Approval,
        status: DeclarationStatus::Declared,
        requirement: "explicit human approval is required before a bundle is activated; missing file, hash, byte-count, unknown-file and duplicate declaration all fail",
        version_source: Some("axiom-skills/release/skills-manifest.json"),
        pin: "declared",
        required: false,
        expected: Some(Expected::Value("an approved plan digest bound to this activation")),
    },
];

/// The prerequisite matrix, in report order.
#[must_use]
pub const fn declarations() -> &'static [PrerequisiteDeclaration] {
    &DECLARATIONS
}

/// The declared row for one `(component, class)` pair, if this build has one.
#[must_use]
pub fn declaration(
    component: &str,
    class: PrerequisiteClass,
) -> Option<&'static PrerequisiteDeclaration> {
    declarations()
        .iter()
        .find(|row| row.component == component && row.class == class)
}

/// What one probe observed for one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrerequisiteStatus {
    /// The requirement is met on this host.
    Satisfied,
    /// The requirement is not met on this host.
    Unsatisfied,
    /// The probe could not decide; unknown is never treated as satisfied.
    Unknown,
}

impl PrerequisiteStatus {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::Unsatisfied => "unsatisfied",
            Self::Unknown => "unknown",
        }
    }

    /// True only for [`PrerequisiteStatus::Satisfied`].
    #[must_use]
    pub const fn is_satisfied(self) -> bool {
        matches!(self, Self::Satisfied)
    }
}

/// One probe result: the status and what the probe actually saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrerequisiteObservation {
    /// What the probe decided.
    pub status: PrerequisiteStatus,
    /// What it saw, or why it could not decide.
    pub observed: String,
}

impl PrerequisiteObservation {
    /// A met requirement.
    #[must_use]
    pub fn satisfied(observed: impl Into<String>) -> Self {
        Self {
            status: PrerequisiteStatus::Satisfied,
            observed: observed.into(),
        }
    }

    /// An unmet requirement.
    #[must_use]
    pub fn unsatisfied(observed: impl Into<String>) -> Self {
        Self {
            status: PrerequisiteStatus::Unsatisfied,
            observed: observed.into(),
        }
    }

    /// A requirement the probe could not decide.
    #[must_use]
    pub fn unknown(observed: impl Into<String>) -> Self {
        Self {
            status: PrerequisiteStatus::Unknown,
            observed: observed.into(),
        }
    }
}

/// The read-only prerequisite probe port.
///
/// One method, one row in, one observation out. It has no write method, so a
/// probe can never mutate the target it is judging, and injecting a second
/// implementation is how the tests build a host with exactly one unmet row.
pub trait EcosystemProbe {
    /// Observe one declared row on this host.
    fn observe(&self, row: &PrerequisiteDeclaration) -> PrerequisiteObservation;
}

/// One probed row, as it is reported and sealed into the plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrerequisiteReport {
    /// Component the row belongs to.
    pub component: String,
    /// Class of prerequisite.
    pub class: String,
    /// `satisfied`, `unsatisfied` or `unknown`.
    pub status: String,
    /// Whether an unmet row refuses the installation.
    pub required: bool,
    /// True when this row refuses the installation right now.
    pub blocking: bool,
    /// The requirement, in reviewable prose.
    pub requirement: String,
    /// The pin, or `undeclared`.
    pub pin: String,
    /// The document that proves the requirement, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_source: Option<String>,
    /// The version this build compared against, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    /// What the probe saw.
    pub observed: String,
}

/// Probe every declared row, in declaration order.
#[must_use]
pub fn probe(probe: &impl EcosystemProbe) -> Vec<PrerequisiteReport> {
    declarations()
        .iter()
        .map(|row| report(probe, row))
        .collect()
}

/// Probe one declared row.
#[must_use]
pub fn report(probe: &impl EcosystemProbe, row: &PrerequisiteDeclaration) -> PrerequisiteReport {
    let observation = probe.observe(row);
    PrerequisiteReport {
        component: row.component.to_string(),
        class: row.class.as_str().to_string(),
        status: observation.status.as_str().to_string(),
        required: row.required,
        blocking: row.required && !observation.status.is_satisfied(),
        requirement: row.requirement.to_string(),
        pin: row.pin.to_string(),
        version_source: row.version_source.map(str::to_string),
        expected: row.expected.map(Expected::render),
        observed: observation.observed,
    }
}

/// The blocking rows of a report, in report order.
#[must_use]
pub fn blocking_rows(reports: &[PrerequisiteReport]) -> Vec<&PrerequisiteReport> {
    reports.iter().filter(|row| row.blocking).collect()
}

/// The rows a run cannot verify, in report order (`component/class`).
#[must_use]
pub fn verification_gaps(reports: &[PrerequisiteReport]) -> Vec<String> {
    reports
        .iter()
        .filter(|row| !row.status.eq(PrerequisiteStatus::Satisfied.as_str()))
        .map(|row| format!("{}/{}", row.component, row.class))
        .collect()
}

/// The frozen refusal, or `None` when nothing blocks.
///
/// The caller invokes this *before* any write, which is what makes AC1's
/// "report each prerequisite before any write" and "refuse to mutate" the same
/// code path rather than two. Every blocking row is named in the message, and
/// the first one in report order also names its rule, component, expectation and
/// observation, so a caller never has to guess which prerequisite refused.
#[must_use]
pub fn prerequisite_refusal(reports: &[PrerequisiteReport]) -> Option<AxiomError> {
    let blocking = blocking_rows(reports);
    let first = blocking.first()?;
    let names: Vec<String> = blocking
        .iter()
        .map(|row| format!("{}/{}", row.component, row.class))
        .collect();
    Some(
        AxiomError::new(
            ErrorCode::NotReady,
            format!(
                "the installation refuses to write: {} required prerequisite(s) are not satisfied: {}",
                names.len(),
                names.join(", ")
            ),
        )
        .with_detail("rule", RULE_PREREQUISITE)
        .with_detail("component", first.component.clone())
        .with_detail(
            "expected",
            first
                .expected
                .clone()
                .unwrap_or_else(|| first.requirement.clone()),
        )
        .with_detail("observed", format!("{} reported {}", first.class, first.status))
        .with_detail(
            "required_version",
            first
                .expected
                .clone()
                .unwrap_or_else(|| first.pin.clone()),
        ),
    )
}

/// A probe that satisfies every declared row, for callers that own the
/// prerequisite decision themselves.
#[derive(Debug, Clone, Default)]
pub struct SatisfiedProbe;

impl EcosystemProbe for SatisfiedProbe {
    fn observe(&self, row: &PrerequisiteDeclaration) -> PrerequisiteObservation {
        match row.status {
            DeclarationStatus::Undeclared => {
                PrerequisiteObservation::unknown("the owning repository declares no version source")
            }
            _ => PrerequisiteObservation::satisfied("declared requirement satisfied by this build"),
        }
    }
}

/// The production probe: the real search path, the real store runtime and the
/// real executable this process is running from.
#[derive(Debug)]
pub struct NativeProbe<'a> {
    host: &'a dyn HostProbe,
    platform: Platform,
    install_root: String,
    storage: StorageClass,
    approved: bool,
}

impl<'a> NativeProbe<'a> {
    /// A probe over one host search path and one target root.
    #[must_use]
    pub fn new(host: &'a dyn HostProbe, install_root: &str) -> Self {
        Self {
            host,
            platform: Platform::current(),
            install_root: install_root.to_string(),
            storage: classify_storage_lexically(install_root),
            approved: false,
        }
    }

    /// The same probe, told whether an approved digest is bound to this run.
    #[must_use]
    pub fn with_approval(mut self, approved: bool) -> Self {
        self.approved = approved;
        self
    }

    /// The Rust toolchain channel, for developer and build use only.
    fn observe_rust(&self) -> PrerequisiteObservation {
        let Some(program) = self.host.locate("rustc") else {
            return PrerequisiteObservation::unknown(
                "no rustc was found on the probe search path; the prebuilt bundle needs no compiler",
            );
        };
        let argv = version_argv();
        match self.host.run(&program, &argv) {
            Ok(output) if output.code == 0 => match parse_tool_version(&output.stdout, "rustc") {
                Some(version) if version == RUST_PIN => {
                    PrerequisiteObservation::satisfied(format!("rustc {version}"))
                }
                Some(version) => PrerequisiteObservation::unsatisfied(format!(
                    "rustc {version} is not the declared {RUST_PIN} channel"
                )),
                None => PrerequisiteObservation::unknown("rustc reported no parseable version"),
            },
            Ok(output) => PrerequisiteObservation::unknown(format!(
                "rustc exited with {} before reporting a version",
                output.code
            )),
            Err(_) => PrerequisiteObservation::unknown("rustc could not be launched"),
        }
    }

    /// The Python interpreter the gateway declares.
    fn observe_python(&self) -> PrerequisiteObservation {
        let mut attempts: Vec<String> = Vec::new();
        for stem in ["python3", "python"] {
            let Some(program) = self.host.locate(stem) else {
                attempts.push(format!("{stem}: not found"));
                continue;
            };
            let argv = version_argv();
            match self.host.run(&program, &argv) {
                Ok(output) if output.code == 0 => {
                    let text = if output.stdout.trim().is_empty() {
                        output.stderr.clone()
                    } else {
                        output.stdout.clone()
                    };
                    match parse_python_version(&text) {
                        Some(version) if python_in_range(version) => {
                            return PrerequisiteObservation::satisfied(format!(
                                "{stem}: Python {}.{}.{} is in >=3.13,<3.14",
                                version.0, version.1, version.2
                            ));
                        }
                        Some(version) => attempts.push(format!(
                            "{stem}: Python {}.{}.{} is outside >=3.13,<3.14",
                            version.0, version.1, version.2
                        )),
                        None => attempts.push(format!("{stem}: no parseable version")),
                    }
                }
                Ok(output) => attempts.push(format!("{stem}: exited with {}", output.code)),
                Err(_) => attempts.push(format!("{stem}: could not be launched")),
            }
        }
        PrerequisiteObservation::unsatisfied(attempts.join("; "))
    }

    /// The SQLite runtime the store requires, probed through the store itself.
    fn observe_sqlite(&self) -> PrerequisiteObservation {
        match graph_store::open::runtime_version_probe() {
            Ok(version) => {
                if version.is_supported_for_wal() {
                    PrerequisiteObservation::satisfied(format!(
                        "SQLite {version} meets the store WAL baseline"
                    ))
                } else {
                    PrerequisiteObservation::unsatisfied(format!(
                        "SQLite {version} is below the store WAL baseline; reported as a verification gap because the contract records this row undeclared"
                    ))
                }
            }
            Err(error) => PrerequisiteObservation::unknown(format!(
                "the SQLite runtime could not be probed: {error}"
            )),
        }
    }

    /// The supported native OS and the state storage class.
    fn observe_runtime(&self) -> PrerequisiteObservation {
        if self.platform == Platform::Unknown {
            return PrerequisiteObservation::unknown("the host platform could not be determined");
        }
        if self.storage != StorageClass::LocalDisk {
            return PrerequisiteObservation::unsatisfied(format!(
                "the state root is {} storage, not local disk",
                self.storage.as_str()
            ));
        }
        PrerequisiteObservation::satisfied(format!(
            "{} host with local-disk state storage",
            self.platform.as_str()
        ))
    }

    /// The running entrypoint executable.
    fn observe_host_executable(&self) -> PrerequisiteObservation {
        match std::env::current_exe() {
            Ok(path) => {
                let text = path.to_string_lossy().to_string();
                if is_absolute_host_path(&text) && path.is_file() {
                    PrerequisiteObservation::satisfied(
                        "the running entrypoint is an absolute host path",
                    )
                } else {
                    PrerequisiteObservation::unsatisfied(
                        "the running entrypoint is not an absolute host path",
                    )
                }
            }
            Err(_) => {
                PrerequisiteObservation::unknown("the running executable path could not be read")
            }
        }
    }

    /// The write and elevation state of the target root.
    fn observe_permission(&self) -> PrerequisiteObservation {
        if !is_absolute_host_path(&self.install_root) {
            return PrerequisiteObservation::unsatisfied(
                "the install root is not an absolute host path",
            );
        }
        if self.storage != StorageClass::LocalDisk {
            return PrerequisiteObservation::unsatisfied(format!(
                "the install root is {} storage",
                self.storage.as_str()
            ));
        }
        PrerequisiteObservation::satisfied(
            "the install root is a per-user local path and this plan never requests elevation",
        )
    }

    /// The activation approval the skills bundle declares.
    fn observe_approval(&self) -> PrerequisiteObservation {
        if self.approved {
            PrerequisiteObservation::satisfied(
                "an approved plan digest is bound to this activation",
            )
        } else {
            PrerequisiteObservation::unknown(
                "no approved plan digest is bound yet; the plan itself authorises nothing",
            )
        }
    }
}

impl EcosystemProbe for NativeProbe<'_> {
    fn observe(&self, row: &PrerequisiteDeclaration) -> PrerequisiteObservation {
        match (row.component, row.class) {
            ("axiom-graphd", PrerequisiteClass::Interpreter) => PrerequisiteObservation::satisfied(
                "no interpreter is required: the core release is a prebuilt native binary",
            ),
            ("axiom-graphd", PrerequisiteClass::Toolchain) => self.observe_rust(),
            ("axiom-graphd", PrerequisiteClass::Runtime) => self.observe_runtime(),
            ("axiom-graphd", PrerequisiteClass::NativeDependency) => self.observe_sqlite(),
            ("axiom-graphd", PrerequisiteClass::HostExecutable) => self.observe_host_executable(),
            ("axiom-graphd", PrerequisiteClass::Permission) => self.observe_permission(),
            ("axiom-mcp", PrerequisiteClass::Interpreter) => self.observe_python(),
            ("axiom-mcp", PrerequisiteClass::Toolchain) => {
                PrerequisiteObservation::satisfied("no build toolchain is declared for a host")
            }
            ("axiom-mcp", PrerequisiteClass::Runtime) => PrerequisiteObservation::satisfied(
                "this installation creates the versioned environment and its manifest pointer",
            ),
            ("axiom-skills", PrerequisiteClass::Interpreter) => PrerequisiteObservation::satisfied(
                "no interpreter is required: the skills bundle is data and instructions",
            ),
            ("axiom-skills", PrerequisiteClass::Toolchain) => {
                PrerequisiteObservation::satisfied("no build toolchain is declared")
            }
            ("axiom-skills", PrerequisiteClass::Runtime) => PrerequisiteObservation::satisfied(
                "this installation creates the versioned bundle directory and moves its manifest pointer",
            ),
            ("axiom-skills", PrerequisiteClass::Approval) => self.observe_approval(),
            _ => PrerequisiteObservation::unknown(
                "this build declares no probe for this prerequisite row",
            ),
        }
    }
}

/// The `--version` argv this build hands every probe.
fn version_argv() -> Vec<String> {
    VERSION_ARGV
        .iter()
        .map(|argument| String::from(*argument))
        .collect()
}

/// The version token `rustc --version` publishes, as `rustc 1.85.0 (...)`.
fn parse_tool_version(text: &str, program: &str) -> Option<String> {
    let line = text.lines().next()?.trim();
    let rest = line.strip_prefix(program)?;
    let token = rest.split_whitespace().next()?;
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// The `Python X.Y.Z` version `python --version` publishes.
fn parse_python_version(text: &str) -> Option<(u32, u32, u32)> {
    let token = text.split_whitespace().find(|word| {
        let mut fields = word.split('.');
        let major = fields.next().unwrap_or_default();
        fields.next().is_some() && !major.is_empty() && major.bytes().all(|b| b.is_ascii_digit())
    })?;
    let mut fields = token.split('.');
    let major = fields.next()?.parse::<u32>().ok()?;
    let minor = fields.next()?.parse::<u32>().ok()?;
    let patch = fields
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    Some((major, minor, patch))
}

/// True when a version falls inside the gateway's declared range.
fn python_in_range(version: (u32, u32, u32)) -> bool {
    version >= PYTHON_MIN && version < PYTHON_MAX_EXCLUSIVE
}

/// Caller-supplied ecosystem planner inputs.
///
/// Every value a plan depends on is injected here, including the identifier, the
/// timestamp and the versions discovery already observed, so two runs over the
/// same bundle and the same observations produce byte-identical plans and
/// planning reads no clock and no random source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcosystemContext {
    /// Identifier of this plan; the caller owns generation and uniqueness.
    pub plan_id: String,
    /// RFC 3339 creation time, injected so planning is deterministic.
    pub created_at: String,
    /// Host the plan targets, from [`HOSTS`].
    pub host: String,
    /// Absolute install root the versions are created under.
    pub install_root: String,
    /// Component versions discovery already observed on this host.
    #[serde(default)]
    pub observed: Vec<ObservedComponent>,
}

impl EcosystemContext {
    /// A context over one host and one install root, with no observations.
    #[must_use]
    pub fn new(
        plan_id: impl Into<String>,
        created_at: impl Into<String>,
        host: impl Into<String>,
        install_root: impl Into<String>,
    ) -> Self {
        Self {
            plan_id: plan_id.into(),
            created_at: created_at.into(),
            host: host.into(),
            install_root: install_root.into(),
            observed: Vec::new(),
        }
    }

    /// The same context, told which component versions discovery observed.
    #[must_use]
    pub fn with_observed(mut self, observed: Vec<ObservedComponent>) -> Self {
        self.observed = observed;
        self
    }

    /// The per-component planner context for one component.
    ///
    /// The child identifier is derived from the ecosystem identifier, so a
    /// component plan is traceable back to the ecosystem plan that owns it, and
    /// only the versions observed for that component are handed to it.
    #[must_use]
    pub fn component_context(&self, component: &str) -> PlanContext {
        let mut context = PlanContext::per_user(
            format!("{}-{}", self.plan_id, component),
            self.created_at.clone(),
            self.host.clone(),
            self.install_root.clone(),
        );
        context.observed = self
            .observed
            .iter()
            .filter(|observed| observed.component == component)
            .cloned()
            .collect();
        context
    }
}

/// The embedded, sealed skills plan one ecosystem plan carries.
///
/// The skills installer has no JSON plan document of its own, so the ecosystem
/// plan records the reviewed declaration, the verified steps and the version
/// directory the activation writes into, plus the digest of the reviewed
/// manifest bytes that activation is approved against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcosystemSkillsPlan {
    /// Document kind; always [`SKILLS_PLAN_KIND`].
    pub plan_kind: String,
    /// Identifier of this plan, derived from the ecosystem plan identifier.
    pub plan_id: String,
    /// What the plan does with the component, from the component action
    /// vocabulary.
    pub action: String,
    /// Version directory the steps are written into, relative to the skills
    /// install root.
    pub directory: String,
    /// The declaration every step was checked against.
    pub bundle: SkillBundle,
    /// One step per declared file, in declaration order.
    pub steps: Vec<SkillsStep>,
    /// Digest of the reviewed manifest bytes this activation is approved at.
    pub manifest_sha256: String,
}

impl EcosystemSkillsPlan {
    /// The skills installer's own plan view of this document.
    #[must_use]
    pub fn install_plan(&self) -> SkillsPlan {
        SkillsPlan {
            bundle: self.bundle.clone(),
            steps: self.steps.clone(),
            directory: self.directory.clone(),
        }
    }
}

/// One contract position of the ecosystem plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcosystemComponentPlan {
    /// Position in the contract order, starting at 1.
    pub position: u64,
    /// Contract component name.
    pub component: String,
    /// Version that will be activated.
    pub version: String,
    /// Kind of the embedded component plan.
    pub plan_kind: String,
    /// Identifier of the embedded component plan.
    pub plan_id: String,
    /// What the plan does with the component.
    pub action: String,
    /// Digest of this entry's own body, excluding `digest` itself.
    pub digest: String,
    /// Digest the embedded activation is approved at.
    pub activation_digest: String,
    /// The sealed per-component plan this entry activates.
    pub plan: Value,
}

impl EcosystemComponentPlan {
    /// Re-derive this entry's digest from its body.
    ///
    /// The body is domain-separated by [`ECOSYSTEM_COMPONENT_DIGEST_SCHEMA`], so
    /// a component digest can never be mistaken for the digest of the ecosystem
    /// plan that carries it.
    ///
    /// # Errors
    /// Fails when the body cannot be encoded canonically.
    pub fn recompute_digest(&self) -> Result<String, AxiomError> {
        crate::plan::plan_digest(&self.body())
    }

    /// The digested body of this entry, without `digest`.
    fn body(&self) -> Value {
        serde_json::json!({
            "schema": ECOSYSTEM_COMPONENT_DIGEST_SCHEMA,
            "position": self.position,
            "component": self.component,
            "version": self.version,
            "plan_kind": self.plan_kind,
            "plan_id": self.plan_id,
            "action": self.action,
            "activation_digest": self.activation_digest,
            "plan": self.plan,
        })
    }
}

/// The one reviewable ecosystem installation plan.
///
/// Serialise it with [`EcosystemPlan::to_json`] and seal it with
/// [`seal_ecosystem`] to obtain the digest `axiom install apply` must be
/// approved against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcosystemPlan {
    /// Digest domain of this document, so this digest can never be confused with
    /// a component plan digest.
    pub schema: String,
    /// Document kind; always [`ECOSYSTEM_PLAN_KIND`].
    pub kind: String,
    /// Document schema version; always [`ECOSYSTEM_PLAN_SCHEMA_VERSION`].
    pub schema_version: u64,
    /// Identifier of this plan.
    pub plan_id: String,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// Contract this plan implements.
    pub contract_id: String,
    /// The contract install order this plan places, position by position.
    pub install_order: Vec<String>,
    /// What the plan targets.
    pub target: InstallTarget,
    /// Every declared prerequisite row, as probed before any read or write.
    pub prerequisites: Vec<PrerequisiteReport>,
    /// One entry per contract position.
    pub component_plans: Vec<EcosystemComponentPlan>,
    /// The bundle the plan was built from.
    pub bundle: BundleReference,
    /// The rollback boundary the core activation keeps.
    pub rollback: RollbackPlan,
    /// Rows this run could not verify, in report order.
    pub verification_gaps: Vec<String>,
    /// Digest of this document's body, without `plan_digest`.
    pub plan_digest: String,
}

impl EcosystemPlan {
    /// The document as one JSON object, with `plan_digest` re-derived from the
    /// body so a stale recorded digest can never be handed to a caller.
    ///
    /// # Errors
    /// Fails only if the document cannot be serialised or its body cannot be
    /// encoded canonically, which is an Axiom defect.
    pub fn to_value(&self) -> Result<Value, AxiomError> {
        let mut value = serde_json::to_value(self).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the ecosystem plan is not serialisable",
            )
            .with_detail("observed", error.to_string())
        })?;
        let digest = crate::plan::plan_digest(&value)?;
        if let Some(object) = value.as_object_mut() {
            object.insert("plan_digest".to_string(), Value::String(digest));
        }
        Ok(value)
    }

    /// The document as one compact JSON line, plus the trailing newline the plan
    /// documents of this workspace carry.
    ///
    /// # Errors
    /// Propagates [`EcosystemPlan::to_value`].
    pub fn to_json(&self) -> Result<String, AxiomError> {
        let value = self.to_value()?;
        let mut text = serde_json::to_string(&value).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the ecosystem plan is not serialisable",
            )
            .with_detail("observed", error.to_string())
        })?;
        text.push('\n');
        Ok(text)
    }

    /// The human-reviewable rendering of one ecosystem plan.
    #[must_use]
    pub fn text(&self) -> String {
        let mut text = format!(
            "axiom install plan {} (dry run) kind={} contract={} host={} scope={}\n",
            self.plan_id,
            self.kind,
            self.contract_id,
            self.target.host,
            self.target.scope.as_str()
        );
        text.push_str(&format!(
            "bundle {} channel={} manifest_sha256={}\n",
            self.bundle.bundle_id, self.bundle.channel, self.bundle.manifest_sha256
        ));
        for report in &self.prerequisites {
            text.push_str(&format!(
                "prerequisite {}/{}: {}{} ({})\n",
                report.component,
                report.class,
                report.status,
                if report.blocking { " BLOCKING" } else { "" },
                report.observed
            ));
        }
        for entry in &self.component_plans {
            text.push_str(&format!(
                "component {} {} position={} action={} digest={} activation={}\n",
                entry.component,
                entry.version,
                entry.position,
                entry.action,
                entry.digest,
                entry.activation_digest
            ));
        }
        for gap in &self.verification_gaps {
            text.push_str(&format!("verification gap {gap}\n"));
        }
        text.push_str(&format!(
            "rollback keeps={} pointer={} journal={}\n",
            self.rollback.keeps_previous_versions,
            self.rollback.current_pointer,
            self.rollback.journal_directory
        ));
        text.push_str(&format!("plan_digest={}\n", self.plan_digest));
        text
    }

    /// The digest of this document's body.
    ///
    /// # Errors
    /// Propagates [`EcosystemPlan::to_value`].
    pub fn digest(&self) -> Result<String, AxiomError> {
        let value = self.to_value()?;
        value
            .get("plan_digest")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| refuse(RULE_ONE_PLAN, "the sealed plan carries no plan_digest"))
    }

    /// Verify this document against the digest a caller approved.
    ///
    /// # Errors
    /// Propagates [`verify_ecosystem`].
    pub fn verify(&self, approved_digest: &str) -> Result<(), AxiomError> {
        verify_ecosystem(self, approved_digest)
    }
}

/// Seal one ecosystem plan: record the digest of its own body.
///
/// # Errors
/// Propagates [`EcosystemPlan::digest`].
pub fn seal_ecosystem(plan: &mut EcosystemPlan) -> Result<String, AxiomError> {
    let digest = plan.digest()?;
    plan.plan_digest = digest.clone();
    Ok(digest)
}

/// Probe every declared row, in declaration order.
fn probe_all(probe: &impl EcosystemProbe) -> Vec<PrerequisiteReport> {
    declarations()
        .iter()
        .map(|row| report(probe, row))
        .collect()
}

/// Plan one ecosystem installation.
///
/// Order is the safety property of AC1: every declared prerequisite is probed
/// and reported first, a required row that is unsatisfied or unknown refuses
/// before the bundle is even opened, and only then are the three contract
/// components planned. The result is one document sealed with one approval
/// digest.
///
/// # Errors
/// - [`ErrorCode::NotReady`] when a required prerequisite is unsatisfied or
///   unknown, naming every blocking row ([`RULE_PREREQUISITE`]).
/// - [`ErrorCode::ValidationError`] when the bundle root is not absolute, the
///   host is outside [`HOSTS`], the manifest omits a core component
///   ([`RULE_MISSING_COMPONENT`]), a manifest declares a component with no
///   contract position ([`RULE_ORDER`]), or the skills bundle is absent or is
///   not a valid declaration.
/// - The refusal vocabulary of [`crate::install::plan::plan_install`] and
///   [`crate::skills::install::plan_install`].
pub fn plan_ecosystem(
    probe: &impl EcosystemProbe,
    bundle_root: &str,
    context: &EcosystemContext,
) -> Result<EcosystemPlan, AxiomError> {
    let prerequisites = probe_all(probe);
    if let Some(error) = prerequisite_refusal(&prerequisites) {
        return Err(error);
    }
    if !is_absolute_host_path(bundle_root) {
        return Err(refuse("bundle_root", bundle_root));
    }
    if !HOSTS.contains(&context.host.as_str()) {
        return Err(refuse("host", &context.host));
    }
    let root = trim_root(bundle_root);
    let (manifest, manifest_sha256) = read_bundle_manifest(Path::new(&root))?;
    let core = ordered_core_components(&manifest)?;
    let mut component_plans: Vec<EcosystemComponentPlan> = Vec::with_capacity(INSTALL_ORDER.len());
    let mut target: Option<InstallTarget> = None;
    let mut bundle: Option<BundleReference> = None;
    let mut rollback: Option<RollbackPlan> = None;
    for (index, declared) in core.iter().enumerate() {
        let component = declared.component.as_str();
        let single = filtered_manifest(&manifest, component);
        let child = plan_component(
            &single,
            &manifest_sha256,
            &root,
            &context.component_context(component),
            DryRun::new(),
        )?;
        let planned = child.components.first();
        let version = planned
            .map(|entry| entry.version.clone())
            .unwrap_or_default();
        let action = planned
            .map(|entry| entry.action.as_str().to_string())
            .unwrap_or_else(|| ComponentAction::Install.as_str().to_string());
        if target.is_none() {
            target = Some(child.target.clone());
        }
        if bundle.is_none() {
            bundle = Some(child.bundle.clone());
        }
        if rollback.is_none() {
            rollback = Some(child.rollback.clone());
        }
        let (plan, activation_digest) = sealed(&child)?;
        let entry = EcosystemComponentPlan {
            position: (index as u64) + 1,
            component: component.to_string(),
            version,
            plan_kind: COMPONENT_PLAN_KIND.to_string(),
            plan_id: child.plan_id.clone(),
            action,
            digest: String::new(),
            activation_digest,
            plan,
        };
        let digest = entry.recompute_digest()?;
        component_plans.push(EcosystemComponentPlan { digest, ..entry });
    }
    let skills = plan_skills_component(&root, &context.plan_id)?;
    let skills_entry = EcosystemComponentPlan {
        position: INSTALL_ORDER.len() as u64,
        component: SKILLS_COMPONENT.to_string(),
        version: skills.bundle.version.clone(),
        plan_kind: SKILLS_PLAN_KIND.to_string(),
        plan_id: skills.plan_id.clone(),
        action: skills.action.clone(),
        digest: String::new(),
        activation_digest: skills.manifest_sha256.clone(),
        plan: serde_json::to_value(&skills).map_err(|error| {
            AxiomError::new(ErrorCode::Internal, "the skills plan is not serialisable")
                .with_detail("observed", error.to_string())
        })?,
    };
    let skills_digest = skills_entry.recompute_digest()?;
    component_plans.push(EcosystemComponentPlan {
        digest: skills_digest,
        ..skills_entry
    });
    let mut plan = EcosystemPlan {
        schema: ECOSYSTEM_DIGEST_SCHEMA.to_string(),
        kind: ECOSYSTEM_PLAN_KIND.to_string(),
        schema_version: ECOSYSTEM_PLAN_SCHEMA_VERSION,
        plan_id: context.plan_id.clone(),
        created_at: context.created_at.clone(),
        contract_id: CONTRACT_ID.to_string(),
        install_order: INSTALL_ORDER
            .iter()
            .map(|component| (*component).to_string())
            .collect(),
        target: target
            .ok_or_else(|| refuse(RULE_MISSING_COMPONENT, "no core component planned"))?,
        prerequisites,
        component_plans,
        bundle: bundle.ok_or_else(|| refuse(RULE_MISSING_COMPONENT, "no core bundle planned"))?,
        rollback: rollback
            .ok_or_else(|| refuse(RULE_MISSING_COMPONENT, "no core rollback planned"))?,
        verification_gaps: Vec::new(),
        plan_digest: String::new(),
    };
    plan.verification_gaps = verification_gaps(&plan.prerequisites);
    seal_ecosystem(&mut plan)?;
    Ok(plan)
}

/// The two core components a manifest must declare, in contract order.
///
/// A missing component and a component with no contract position are both
/// refused rather than dropped, so a bundle can never install a subset of the
/// ecosystem while reporting success.
fn ordered_core_components(
    manifest: &BundleManifest,
) -> Result<Vec<&crate::install::plan::BundleComponent>, AxiomError> {
    let mut ordered = Vec::with_capacity(CORE_COMPONENTS.len());
    for expected in CORE_COMPONENTS {
        let mut declared = manifest
            .components
            .iter()
            .filter(|component| component.component == expected);
        let Some(first) = declared.next() else {
            return Err(refuse(RULE_MISSING_COMPONENT, expected));
        };
        if declared.next().is_some() {
            return Err(
                refuse(RULE_ORDER, expected).with_detail("observed", "declared more than once")
            );
        }
        ordered.push(first);
    }
    for component in &manifest.components {
        if !CORE_COMPONENTS.contains(&component.component.as_str()) {
            return Err(refuse(RULE_ORDER, &component.component));
        }
    }
    Ok(ordered)
}

/// One manifest carrying exactly one of its components.
fn filtered_manifest(manifest: &BundleManifest, component: &str) -> BundleManifest {
    BundleManifest {
        schema_version: manifest.schema_version,
        bundle_id: manifest.bundle_id.clone(),
        channel: manifest.channel.clone(),
        created_at: manifest.created_at.clone(),
        components: manifest
            .components
            .iter()
            .filter(|declared| declared.component == component)
            .cloned()
            .collect(),
    }
}

/// Plan the third contract position from the skills bundle beside the core one.
fn plan_skills_component(
    bundle_root: &str,
    plan_id: &str,
) -> Result<EcosystemSkillsPlan, AxiomError> {
    let skills_root = under(bundle_root, &[SKILLS_DIRECTORY]);
    let bundle = read_skills_bundle(&under(&skills_root, &[SKILLS_MANIFEST_FILE]))?;
    let source = LocalPayloadSource::new(under(&skills_root, &[SKILLS_PAYLOAD_DIRECTORY]));
    let planned = plan_skills(&bundle, &source)?;
    let manifest_sha256 = graph_export::sha256_hex(&bundle.manifest_bytes()?);
    Ok(EcosystemSkillsPlan {
        plan_kind: SKILLS_PLAN_KIND.to_string(),
        plan_id: format!("{plan_id}-{SKILLS_COMPONENT}"),
        action: ComponentAction::Install.as_str().to_string(),
        directory: planned.directory,
        bundle,
        steps: planned.steps,
        manifest_sha256,
    })
}

/// Read and parse the skills bundle declaration beside the core bundle.
fn read_skills_bundle(path: &str) -> Result<SkillBundle, AxiomError> {
    if !is_absolute_host_path(path) {
        return Err(refuse(RULE_MISSING_COMPONENT, path));
    }
    let bytes = std::fs::read(path).map_err(|error| {
        AxiomError::new(
            ErrorCode::NotFound,
            "the skills bundle manifest could not be opened",
        )
        .with_detail("rule", RULE_MISSING_COMPONENT)
        .with_detail("component", SKILLS_COMPONENT)
        .with_detail("observed", SKILLS_MANIFEST_FILE)
        .with_detail("actual", error.kind().to_string())
    })?;
    if bytes.len() as u64 > SKILLS_MAX_MANIFEST_BYTES {
        return Err(refuse(RULE_MISSING_COMPONENT, &bytes.len().to_string())
            .with_detail("component", SKILLS_COMPONENT)
            .with_detail("limit", SKILLS_MAX_MANIFEST_BYTES.to_string()));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        AxiomError::new(
            ErrorCode::ValidationError,
            "the skills bundle manifest is not a valid declaration",
        )
        .with_detail("rule", RULE_MISSING_COMPONENT)
        .with_detail("component", SKILLS_COMPONENT)
        .with_detail("observed", error.to_string())
    })
}

/// A path below a root, in the forward-slash spelling this workspace plans in.
fn under(root: &str, segments: &[&str]) -> String {
    let mut path = trim_root(root);
    for segment in segments {
        path.push('/');
        path.push_str(segment);
    }
    path
}

/// A root without a trailing separator.
fn trim_root(path: &str) -> String {
    let trimmed = path.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        String::from("/")
    } else {
        trimmed.to_string()
    }
}

/// Verify one ecosystem plan against the digest a caller approved.
///
/// The checks are ordered so the cheapest structural violation is reported
/// first, and every check is a refusal: a plan that fails any of them activates
/// nothing. In order:
///
/// 1. the document carries one entry per contract position;
/// 2. the entries are the contract order, with the contract positions;
/// 3. every entry digest re-derives from its own body;
/// 4. every core sub-plan covers exactly its own single component, and the
///    digest it will be activated at is that sub-plan's own digest;
/// 5. the skills activation digest is the digest of the reviewed skills
///    manifest;
/// 6. the recorded digest is the digest of this body, and the caller approved
///    that digest;
/// 7. every declared prerequisite row is recorded, in declaration order;
/// 8. no required prerequisite row is blocking;
/// 9. every core sub-plan kept the ecosystem rollback and target boundary, and
///    the plan is per-user with no elevation.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] for a structural violation, with `rule`
///   set to one of [`RULE_ORDER`], [`RULE_COMPONENT_DIGEST`],
///   [`RULE_SINGLE_COMPONENT_PLAN`], [`RULE_ROLLBACK_BOUNDARY`],
///   [`RULE_PREREQUISITES_PROBED`] or [`RULE_ONE_PLAN`].
/// - [`ErrorCode::Forbidden`] when the approved digest is not this body's
///   digest ([`RULE_APPROVAL`]).
/// - [`ErrorCode::NotReady`] when a recorded required prerequisite is blocking.
pub fn verify_ecosystem(plan: &EcosystemPlan, approved_digest: &str) -> Result<(), AxiomError> {
    let positions = INSTALL_ORDER.len();
    if plan.component_plans.len() != positions {
        return Err(refuse(RULE_ORDER, &plan.component_plans.len().to_string())
            .with_detail("expected", positions.to_string()));
    }
    if plan.install_order.len() != positions {
        return Err(refuse(RULE_ORDER, &plan.install_order.len().to_string())
            .with_detail("expected", positions.to_string()));
    }
    for (index, expected) in INSTALL_ORDER.iter().enumerate() {
        let position = (index as u64) + 1;
        let entry = &plan.component_plans[index];
        if entry.component != *expected {
            return Err(refuse(RULE_ORDER, &entry.component).with_detail("expected", expected));
        }
        if entry.position != position {
            return Err(refuse(RULE_ORDER, &entry.position.to_string())
                .with_detail("component", &entry.component)
                .with_detail("expected", position.to_string()));
        }
        if plan.install_order[index].as_str() != *expected {
            return Err(
                refuse(RULE_ORDER, &plan.install_order[index]).with_detail("expected", expected)
            );
        }
    }
    for entry in &plan.component_plans {
        if entry.recompute_digest()? != entry.digest {
            return Err(refuse(RULE_COMPONENT_DIGEST, &entry.digest)
                .with_detail("component", &entry.component));
        }
    }
    for entry in &plan.component_plans[..CORE_COMPONENTS.len()] {
        let child = core_sub_plan(entry)?;
        if child.components.len() != 1 || child.components[0].component != entry.component {
            return Err(refuse(RULE_SINGLE_COMPONENT_PLAN, &entry.component)
                .with_detail("expected", "one planned component"));
        }
        if crate::plan::plan_digest(&entry.plan)? != entry.activation_digest {
            return Err(refuse(RULE_COMPONENT_DIGEST, &entry.activation_digest)
                .with_detail("component", &entry.component)
                .with_detail("expected", entry.activation_digest.clone()));
        }
        if child.rollback != plan.rollback {
            return Err(refuse(RULE_ROLLBACK_BOUNDARY, &entry.component)
                .with_detail("component", &entry.component)
                .with_detail("expected", plan.rollback.current_pointer.clone()));
        }
        if child.target != plan.target {
            return Err(refuse(RULE_ROLLBACK_BOUNDARY, &entry.component)
                .with_detail("component", &entry.component)
                .with_detail("expected", plan.target.install_root.clone()));
        }
        if child.target.scope != InstallScope::PerUser
            || child
                .permissions
                .iter()
                .any(|permission| permission.requires_elevation)
        {
            return Err(refuse(RULE_PREREQUISITE, &entry.component)
                .with_detail("component", &entry.component)
                .with_detail("observed", "elevation required")
                .with_detail("expected", "a per-user install with no elevation"));
        }
    }
    let skills_entry = &plan.component_plans[CORE_COMPONENTS.len()];
    let skills = skills_sub_plan(skills_entry)?;
    if graph_export::sha256_hex(&skills.bundle.manifest_bytes()?) != skills_entry.activation_digest
    {
        return Err(
            refuse(RULE_COMPONENT_DIGEST, &skills_entry.activation_digest)
                .with_detail("component", SKILLS_COMPONENT),
        );
    }
    if plan.rollback.keeps_previous_versions < MIN_KEEP_PREVIOUS_VERSIONS {
        return Err(refuse(
            RULE_ROLLBACK_BOUNDARY,
            &plan.rollback.keeps_previous_versions.to_string(),
        )
        .with_detail("expected", MIN_KEEP_PREVIOUS_VERSIONS.to_string()));
    }
    let value = plan.to_value()?;
    if value.get("plan_digest").and_then(Value::as_str) != Some(plan.plan_digest.as_str()) {
        return Err(refuse(RULE_ONE_PLAN, &plan.plan_digest));
    }
    if !is_digest(approved_digest) {
        return Err(AxiomError::new(
            ErrorCode::Forbidden,
            "the ecosystem plan was not approved at a digest",
        )
        .with_detail("rule", RULE_APPROVAL)
        .with_detail("observed", REASON_DIGEST_MISMATCH)
        .with_detail("expected", &plan.plan_digest));
    }
    let reasons = crate::plan::approval_reasons(&value, approved_digest);
    if !reasons.is_empty() {
        let reason = if reasons.iter().any(|row| row == REASON_APPROVAL_STALE) {
            REASON_APPROVAL_STALE
        } else {
            REASON_DIGEST_MISMATCH
        };
        return Err(AxiomError::new(
            ErrorCode::Forbidden,
            "the ecosystem plan was not approved at the digest it is being installed at",
        )
        .with_detail("rule", RULE_APPROVAL)
        .with_detail("observed", reasons.join(","))
        .with_detail("actual", reason)
        .with_detail("expected", &plan.plan_digest));
    }
    if plan.prerequisites.len() != declarations().len() {
        return Err(refuse(
            RULE_PREREQUISITES_PROBED,
            &plan.prerequisites.len().to_string(),
        )
        .with_detail("expected", declarations().len().to_string()));
    }
    for (recorded, declared) in plan.prerequisites.iter().zip(declarations()) {
        if recorded.component != declared.component || recorded.class != declared.class.as_str() {
            return Err(refuse(
                RULE_PREREQUISITES_PROBED,
                &format!("{}/{}", recorded.component, recorded.class),
            )
            .with_detail("component", declared.component)
            .with_detail("expected", declared.class.as_str()));
        }
    }
    if let Some(error) = prerequisite_refusal(&plan.prerequisites) {
        return Err(error);
    }
    Ok(())
}

/// The core install plan an entry embeds.
fn core_sub_plan(entry: &EcosystemComponentPlan) -> Result<InstallPlan, AxiomError> {
    // The entry publishes the *sealed* child plan so its approval digest is
    // reviewable beside it. The two digest-excluded keys are not part of the
    // plan body, so they are removed before the body is read as a plan.
    let mut body = entry.plan.clone();
    let object = body
        .as_object_mut()
        .ok_or_else(|| refuse(RULE_SINGLE_COMPONENT_PLAN, &entry.component))?;
    for key in crate::plan::DIGEST_EXCLUDED {
        object.remove(key);
    }
    serde_json::from_value(body).map_err(|error| {
        AxiomError::new(
            ErrorCode::ValidationError,
            "a core component plan is not a valid install plan",
        )
        .with_detail("rule", RULE_SINGLE_COMPONENT_PLAN)
        .with_detail("component", &entry.component)
        .with_detail("observed", error.to_string())
    })
}

/// The skills plan an entry embeds.
fn skills_sub_plan(entry: &EcosystemComponentPlan) -> Result<EcosystemSkillsPlan, AxiomError> {
    serde_json::from_value(entry.plan.clone()).map_err(|error| {
        AxiomError::new(
            ErrorCode::ValidationError,
            "the skills component plan is not a valid skills plan",
        )
        .with_detail("rule", RULE_ONE_PLAN)
        .with_detail("component", SKILLS_COMPONENT)
        .with_detail("observed", error.to_string())
    })
}

/// One contract position of an applied ecosystem installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentApplication {
    /// Position in the contract order, starting at 1.
    pub position: u64,
    /// Contract component name.
    pub component: String,
    /// Version that is now installed.
    pub version: String,
    /// [`STATUS_INSTALLED`] or [`STATUS_ALREADY_INSTALLED`].
    pub status: String,
    /// Digest of the bytes this position now holds.
    pub sha256: String,
    /// Location that holds them.
    pub destination: String,
}

/// The result of applying one ecosystem plan.
///
/// It carries one row per contract position, so an operator can read exactly
/// which components this transaction wrote and which were already in place,
/// plus the two pointers the ecosystem owns and the rollback depth the core
/// activation kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcosystemApplication {
    /// Schema baseline of this record.
    pub schema_version: u64,
    /// Plan that was applied.
    pub plan_id: String,
    /// Digest the plan was approved at.
    pub plan_digest: String,
    /// Transaction that performed the activation.
    pub transaction_id: String,
    /// RFC 3339 instant of the activation.
    pub applied_at: String,
    /// [`STATUS_INSTALLED`] when any component was written, else
    /// [`STATUS_ALREADY_INSTALLED`].
    pub status: String,
    /// One row per contract position, in contract order.
    pub components: Vec<ComponentApplication>,
    /// Pointer that names the activated core install.
    pub core_pointer: String,
    /// Pointer that names the activated skills bundle.
    pub skills_pointer: String,
    /// Previous versions the core activation keeps for rollback.
    pub keeps_previous_versions: u64,
}

impl EcosystemApplication {
    /// The application record as one compact JSON value.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the record cannot be serialised.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        serde_json::to_string(self).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the ecosystem application record is not serialisable",
            )
            .with_detail("observed", error.to_string())
        })
    }

    /// The human-reviewable rendering of one ecosystem application.
    #[must_use]
    pub fn text(&self) -> String {
        let mut text = format!(
            "axiom install apply {} (transaction {}) plan={} digest={} status={}\n",
            self.applied_at, self.transaction_id, self.plan_id, self.plan_digest, self.status
        );
        for row in &self.components {
            text.push_str(&format!(
                "component {} {} position={} {} sha256={} destination={}\n",
                row.component, row.version, row.position, row.status, row.sha256, row.destination
            ));
        }
        text.push_str(&format!(
            "core pointer {} skills pointer {} keeps {} version(s)\n",
            self.core_pointer, self.skills_pointer, self.keeps_previous_versions
        ));
        text
    }
}

/// Apply one approved ecosystem plan.
///
/// Order is the safety property. The plan is re-verified against the approved
/// digest and its recorded prerequisite rows *first*; then every byte this
/// ecosystem would write is read and checked *before* anything is moved; only
/// then are the components activated, each through the update engine's own
/// approval check. When every component already holds the planned bytes and the
/// skills pointer already names the reviewed bundle, nothing is written at all
/// and the result reports [`STATUS_ALREADY_INSTALLED`].
///
/// The core activation keeps the engine's boundaries untouched: each component
/// gets its own transaction identifier, its own journal entry and its own
/// rollback record. A component whose destination already holds the planned
/// bytes is left exactly as it is, which is what makes a re-run idempotent and
/// what lets a partially applied installation resume at component granularity.
///
/// # Errors
/// - [`ErrorCode::Forbidden`] when the plan is not approved at `approved_digest`
///   ([`RULE_APPROVAL`]).
/// - [`ErrorCode::NotReady`] when a recorded required prerequisite is blocking
///   ([`RULE_PREREQUISITE`]).
/// - [`ErrorCode::Conflict`] when a payload is not staged or does not match the
///   digest and size the plan declared ([`RULE_STAGING_INCOMPLETE`]), or when a
///   destination already holds different bytes.
/// - [`ErrorCode::ValidationError`] for a structural plan violation.
pub fn apply_ecosystem(
    plan: &EcosystemPlan,
    approved_digest: &str,
    request: &ApplyRequest,
    core_fs: &impl ActivationFs,
    skills_source: &dyn PayloadSource,
    skills_fs: &dyn SkillsFs,
) -> Result<EcosystemApplication, AxiomError> {
    verify_ecosystem(plan, approved_digest)?;

    // Phase 1: check every core payload and destination. Nothing is written.
    let mut components: Vec<ComponentApplication> = Vec::with_capacity(INSTALL_ORDER.len());
    let mut pending: Vec<(usize, InstallPlan)> = Vec::new();
    for (index, entry) in plan.component_plans[..CORE_COMPONENTS.len()]
        .iter()
        .enumerate()
    {
        let child = core_sub_plan(entry)?;
        let planned = child
            .components
            .first()
            .ok_or_else(|| refuse(RULE_SINGLE_COMPONENT_PLAN, &entry.component))?;
        components.push(application_row(entry, planned));
        if planned.action == ComponentAction::Noop {
            continue;
        }
        // A destination that already holds the planned bytes is left untouched:
        // nothing is re-moved, and the staging tree it came from has already
        // been consumed by the run that placed it.
        let in_place = core_fs.exists(&planned.destination)
            && graph_export::sha256_hex(&core_fs.read(&planned.destination)?)
                == planned.source.sha256;
        if in_place {
            continue;
        }
        let staged = planned.staged_destination.clone();
        if !core_fs.exists(&staged) {
            return Err(staging_refusal(
                &entry.component,
                &staged,
                "a staged payload at the planned staging path",
            ));
        }
        let bytes = core_fs.read(&staged)?;
        if bytes.len() as u64 != planned.source.size_bytes {
            return Err(staging_refusal(
                &entry.component,
                &bytes.len().to_string(),
                &planned.source.size_bytes.to_string(),
            ));
        }
        let staged_digest = graph_export::sha256_hex(&bytes);
        if staged_digest != planned.source.sha256 {
            return Err(staging_refusal(
                &entry.component,
                &staged_digest,
                &planned.source.sha256,
            ));
        }
        pending.push((index, child));
    }

    // Phase 2: check the skills payload and its pointer. Nothing is written.
    let skills_entry = &plan.component_plans[CORE_COMPONENTS.len()];
    let skills = skills_sub_plan(skills_entry)?;
    preflight_skills_source(skills_source, &skills)?;
    let skills_ready = skills_installed(skills_fs, &skills);
    components.push(skills_row(skills_entry, &skills));

    if pending.is_empty() && skills_ready {
        return Ok(application(
            plan,
            request,
            STATUS_ALREADY_INSTALLED,
            components,
        ));
    }

    // Phase 3: activate. Every check has already passed.
    let mut skills_report: Option<(String, String)> = None;
    if !skills_ready {
        let report = install_skills(&skills.install_plan(), skills_source, skills_fs)?;
        skills_report = Some((report.manifest_sha256, report.directory));
    }
    for (index, child) in pending {
        let entry = &plan.component_plans[index];
        let child_request = ApplyRequest::new(
            format!("{}-{}", request.transaction_id, entry.component),
            entry.activation_digest.clone(),
            request.applied_at.clone(),
        );
        let applied = apply_install(&child, &child_request, core_fs)?;
        let wrote = applied
            .activated
            .iter()
            .any(|artifact| !artifact.already_present);
        components[index].status = if wrote {
            STATUS_INSTALLED
        } else {
            STATUS_ALREADY_INSTALLED
        }
        .to_string();
        if let Some(artifact) = applied.activated.first() {
            components[index].sha256 = artifact.sha256.clone();
            components[index].destination = artifact.destination.clone();
        }
    }
    if let Some((sha256, directory)) = skills_report {
        let row = &mut components[CORE_COMPONENTS.len()];
        row.status = STATUS_INSTALLED.to_string();
        row.sha256 = sha256;
        row.destination = directory;
    }

    let status = if components.iter().any(|row| row.status == STATUS_INSTALLED) {
        STATUS_INSTALLED
    } else {
        STATUS_ALREADY_INSTALLED
    };
    Ok(application(plan, request, status, components))
}

/// One core position of an application, before activation.
fn application_row(
    entry: &EcosystemComponentPlan,
    planned: &crate::install::plan::PlannedComponent,
) -> ComponentApplication {
    ComponentApplication {
        position: entry.position,
        component: entry.component.clone(),
        version: entry.version.clone(),
        status: STATUS_ALREADY_INSTALLED.to_string(),
        sha256: planned.source.sha256.clone(),
        destination: planned.destination.clone(),
    }
}

/// The skills position of an application, before activation.
fn skills_row(
    entry: &EcosystemComponentPlan,
    skills: &EcosystemSkillsPlan,
) -> ComponentApplication {
    ComponentApplication {
        position: entry.position,
        component: entry.component.clone(),
        version: entry.version.clone(),
        status: STATUS_ALREADY_INSTALLED.to_string(),
        sha256: skills.manifest_sha256.clone(),
        destination: skills.directory.clone(),
    }
}

/// The application record one transaction produces.
fn application(
    plan: &EcosystemPlan,
    request: &ApplyRequest,
    status: &str,
    components: Vec<ComponentApplication>,
) -> EcosystemApplication {
    EcosystemApplication {
        schema_version: ECOSYSTEM_APPLICATION_SCHEMA_VERSION,
        plan_id: plan.plan_id.clone(),
        plan_digest: plan.plan_digest.clone(),
        transaction_id: request.transaction_id.clone(),
        applied_at: request.applied_at.clone(),
        status: status.to_string(),
        components,
        core_pointer: plan.rollback.current_pointer.clone(),
        skills_pointer: format!("{SKILLS_BUNDLES_DIR}/{ACTIVE_POINTER}"),
        keeps_previous_versions: plan.rollback.keeps_previous_versions,
    }
}

/// The one refusal shape of a staging check.
fn staging_refusal(component: &str, observed: &str, expected: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::Conflict,
        "a planned payload is not staged as the plan declared, so nothing is activated",
    )
    .with_detail("rule", RULE_STAGING_INCOMPLETE)
    .with_detail("component", component)
    .with_detail("observed", observed)
    .with_detail("expected", expected)
}

/// Read and check every skills step without writing anything.
fn preflight_skills_source(
    source: &dyn PayloadSource,
    skills: &EcosystemSkillsPlan,
) -> Result<(), AxiomError> {
    for step in &skills.steps {
        let bytes = source.read(&step.path)?;
        if bytes.len() as u64 != step.size_bytes {
            return Err(staging_refusal(
                SKILLS_COMPONENT,
                &bytes.len().to_string(),
                &step.size_bytes.to_string(),
            ));
        }
        let digest = graph_export::sha256_hex(&bytes);
        if digest != step.sha256 {
            return Err(staging_refusal(SKILLS_COMPONENT, &digest, &step.sha256));
        }
    }
    Ok(())
}

/// True when the skills pointer names the reviewed bundle.
fn skills_pointer_matches(skills_fs: &dyn SkillsFs, skills: &EcosystemSkillsPlan) -> bool {
    let pointer = format!("{SKILLS_BUNDLES_DIR}/{ACTIVE_POINTER}");
    if !skills_fs.exists(&pointer) {
        return false;
    }
    let Ok(bytes) = skills_fs.read(&pointer) else {
        return false;
    };
    let text = String::from_utf8_lossy(&bytes);
    text.contains(&format!("\"directory\":\"{}\"", skills.directory))
        && text.contains(&format!(
            "\"manifest_sha256\":\"{}\"",
            skills.manifest_sha256
        ))
}

/// True when every skills step is installed and the pointer names the bundle.
fn skills_installed(skills_fs: &dyn SkillsFs, skills: &EcosystemSkillsPlan) -> bool {
    if !skills_pointer_matches(skills_fs, skills) {
        return false;
    }
    skills.steps.iter().all(|step| {
        let path = format!("{}/{}", skills.directory, step.path);
        match skills_fs.read(&path) {
            Ok(bytes) => {
                bytes.len() as u64 == step.size_bytes
                    && graph_export::sha256_hex(&bytes) == step.sha256
            }
            Err(_) => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use tempfile::TempDir;

    use super::*;
    use crate::install::apply::LocalFs;
    use crate::install::plan::{
        ArtifactKind, BundleComponent, BundleManifest, BUNDLE_SCHEMA_VERSION,
    };
    use crate::skills::install::{DeclaredEntry, LocalInstallFs, StagedFile};
    use graph_core::error::ExitCode;

    /// The fixture payloads; every digest is computed, never written down.
    const GRAPHD: &[u8] = b"the axiom-graphd binary payload (ecosystem)";
    const MCP: &[u8] = b"the axiom-mcp wheel payload (ecosystem)";
    const SKILL: &[u8] = b"# Axiom skill instructions\n";
    const SKILL_PATH: &str = "instructions/axiom.md";
    const HOST: &str = "linux-x64";
    const VERSION: &str = "0.0.0-dev";
    const GRAPHD_ARTIFACT: &str = "bin/axiom-graphd";
    const MCP_ARTIFACT: &str = "python/axiom_mcp-0.0.0.dev0-py3-none-any.whl";
    const PLAN_ID: &str = "install-20260920-0001";
    const CREATED_AT: &str = "2026-09-20T00:00:00Z";
    const TRANSACTION: &str = "ecosystem-20260920-0001";

    /// An in-memory core mutation surface, keyed by absolute host paths.
    #[derive(Default)]
    struct MemoryActivationFs {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        mutations: RefCell<usize>,
    }

    impl MemoryActivationFs {
        fn put(&self, path: &str, bytes: &[u8]) {
            self.files
                .borrow_mut()
                .insert(path.to_string(), bytes.to_vec());
        }

        fn holds(&self, path: &str) -> bool {
            self.files.borrow().contains_key(path)
        }

        fn mutations(&self) -> usize {
            *self.mutations.borrow()
        }
    }

    impl ActivationFs for MemoryActivationFs {
        fn exists(&self, path: &str) -> bool {
            self.files.borrow().contains_key(path)
        }

        fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
            self.files.borrow().get(path).cloned().ok_or_else(|| {
                AxiomError::new(ErrorCode::NotFound, "the path is not in the memory fs")
                    .with_detail("observed", path)
            })
        }

        fn create_dir_all(&self, _path: &str) -> Result<(), AxiomError> {
            Ok(())
        }

        fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError> {
            *self.mutations.borrow_mut() += 1;
            self.files
                .borrow_mut()
                .insert(path.to_string(), bytes.to_vec());
            Ok(())
        }

        fn rename(&self, from: &str, to: &str) -> Result<(), AxiomError> {
            let bytes = self.files.borrow_mut().remove(from).ok_or_else(|| {
                AxiomError::new(ErrorCode::NotFound, "the rename source is missing")
                    .with_detail("observed", from)
            })?;
            *self.mutations.borrow_mut() += 1;
            self.files.borrow_mut().insert(to.to_string(), bytes);
            Ok(())
        }
    }

    /// An in-memory skills mutation surface, keyed by install-root-relative
    /// paths.
    #[derive(Default)]
    struct MemorySkillsFs {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
    }

    impl MemorySkillsFs {
        fn get(&self, path: &str) -> Option<Vec<u8>> {
            self.files.borrow().get(path).cloned()
        }
    }

    impl SkillsFs for MemorySkillsFs {
        fn exists(&self, path: &str) -> bool {
            self.files.borrow().contains_key(path)
        }

        fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
            self.files.borrow().get(path).cloned().ok_or_else(|| {
                AxiomError::new(ErrorCode::NotFound, "the path is not in the memory fs")
                    .with_detail("observed", path)
            })
        }

        fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError> {
            self.files
                .borrow_mut()
                .insert(path.to_string(), bytes.to_vec());
            Ok(())
        }

        fn rename(&self, from: &str, to: &str) -> Result<(), AxiomError> {
            let bytes = self.files.borrow_mut().remove(from).ok_or_else(|| {
                AxiomError::new(ErrorCode::NotFound, "the rename source is missing")
                    .with_detail("observed", from)
            })?;
            self.files.borrow_mut().insert(to.to_string(), bytes);
            Ok(())
        }
    }

    /// An in-memory skills payload source.
    #[derive(Default)]
    struct MemoryPayload {
        files: BTreeMap<String, Vec<u8>>,
    }

    impl MemoryPayload {
        fn with(path: &str, bytes: &[u8]) -> Self {
            let mut payload = Self::default();
            payload.files.insert(path.to_string(), bytes.to_vec());
            payload
        }
    }

    impl PayloadSource for MemoryPayload {
        fn files(&self) -> Result<Vec<StagedFile>, AxiomError> {
            Ok(self
                .files
                .iter()
                .map(|(path, bytes)| StagedFile {
                    path: path.clone(),
                    size_bytes: bytes.len() as u64,
                    sha256: graph_export::sha256_hex(bytes),
                    executable: false,
                })
                .collect())
        }

        fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
            self.files.get(path).cloned().ok_or_else(|| {
                AxiomError::new(ErrorCode::NotFound, "the payload file is missing")
                    .with_detail("observed", path)
            })
        }
    }

    /// One assembled bundle tree plus one empty install root.
    struct Fixture {
        _bundle_dir: TempDir,
        _install_dir: TempDir,
        bundle_root: String,
        install_root: String,
    }

    fn host_path(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }

    fn bundle_component(
        component: &str,
        artifact: &str,
        kind: ArtifactKind,
        payload: &[u8],
    ) -> BundleComponent {
        BundleComponent {
            component: component.to_string(),
            version: VERSION.to_string(),
            host: HOST.to_string(),
            artifact: artifact.to_string(),
            kind,
            sha256: graph_export::sha256_hex(payload),
            size_bytes: payload.len() as u64,
            permissions: vec!["read".to_string()],
            service: None,
            network_access: Vec::new(),
        }
    }

    fn core_manifest() -> BundleManifest {
        BundleManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            bundle_id: "axiom-core".to_string(),
            channel: "stable".to_string(),
            created_at: CREATED_AT.to_string(),
            components: vec![
                bundle_component(
                    "axiom-graphd",
                    GRAPHD_ARTIFACT,
                    ArtifactKind::Binary,
                    GRAPHD,
                ),
                bundle_component("axiom-mcp", MCP_ARTIFACT, ArtifactKind::Python, MCP),
            ],
        }
    }

    fn skills_declaration() -> SkillBundle {
        let entry = DeclaredEntry::new(
            SKILL_PATH,
            "instruction",
            graph_export::sha256_hex(SKILL),
            SKILL.len() as u64,
        );
        SkillBundle::new(VERSION, "a".repeat(40), "b".repeat(40), vec![entry])
    }

    /// Write one bundle tree: the core manifest, the payloads it declares, and
    /// the skills bundle beside them.
    fn write_bundle(root: &Path, manifest: &BundleManifest, payloads: &[(&str, &[u8])]) {
        for (artifact, bytes) in payloads {
            let path = root.join(artifact);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("payload directory");
            }
            std::fs::write(&path, bytes).expect("payload written");
        }
        std::fs::write(
            root.join("bundle.json"),
            serde_json::to_vec(manifest).expect("manifest json"),
        )
        .expect("manifest written");
        let skills_root = root.join(SKILLS_DIRECTORY);
        let payload_root = skills_root.join(SKILLS_PAYLOAD_DIRECTORY);
        std::fs::create_dir_all(payload_root.join("instructions")).expect("skills directory");
        std::fs::write(
            skills_root.join(SKILLS_MANIFEST_FILE),
            skills_declaration()
                .manifest_bytes()
                .expect("skills manifest"),
        )
        .expect("skills manifest written");
        std::fs::write(payload_root.join(SKILL_PATH), SKILL).expect("skill payload written");
    }

    fn fixture_with(manifest: BundleManifest, payloads: &[(&str, &[u8])]) -> Fixture {
        let bundle_dir = TempDir::new().expect("bundle tempdir");
        let install_dir = TempDir::new().expect("install tempdir");
        write_bundle(bundle_dir.path(), &manifest, payloads);
        Fixture {
            bundle_root: host_path(bundle_dir.path()),
            install_root: host_path(install_dir.path()),
            _bundle_dir: bundle_dir,
            _install_dir: install_dir,
        }
    }

    fn fixture() -> Fixture {
        fixture_with(
            core_manifest(),
            &[(GRAPHD_ARTIFACT, GRAPHD), (MCP_ARTIFACT, MCP)],
        )
    }

    fn context(install_root: &str) -> EcosystemContext {
        EcosystemContext::new(PLAN_ID, CREATED_AT, HOST, install_root)
    }

    /// A probe that fails one declared row and defers every other row to
    /// [`SatisfiedProbe`].
    struct RowProbe {
        component: &'static str,
        class: &'static str,
        status: PrerequisiteStatus,
        observed: &'static str,
    }

    impl EcosystemProbe for RowProbe {
        fn observe(&self, row: &PrerequisiteDeclaration) -> PrerequisiteObservation {
            if row.component == self.component && row.class.as_str() == self.class {
                return PrerequisiteObservation {
                    status: self.status,
                    observed: self.observed.to_string(),
                };
            }
            SatisfiedProbe.observe(row)
        }
    }

    fn unsatisfied(component: &'static str, class: &'static str) -> RowProbe {
        RowProbe {
            component,
            class,
            status: PrerequisiteStatus::Unsatisfied,
            observed: "the fixture removed this prerequisite",
        }
    }

    fn unknown(component: &'static str, class: &'static str) -> RowProbe {
        RowProbe {
            component,
            class,
            status: PrerequisiteStatus::Unknown,
            observed: "the fixture could not decide",
        }
    }

    /// The one ecosystem plan the fixture bundle describes.
    fn planned(fixture: &Fixture) -> EcosystemPlan {
        plan_ecosystem(
            &SatisfiedProbe,
            &fixture.bundle_root,
            &context(&fixture.install_root),
        )
        .expect("the fixture bundle plans")
    }

    /// The core install plan one contract position embeds.
    fn child(plan: &EcosystemPlan, index: usize) -> InstallPlan {
        core_sub_plan(&plan.component_plans[index]).expect("the entry embeds a core plan")
    }

    /// The planned staging path of one core position.
    fn staged(plan: &EcosystemPlan, index: usize) -> String {
        child(plan, index).components[0].staged_destination.clone()
    }

    /// The planned destination of one core position.
    fn destination(plan: &EcosystemPlan, index: usize) -> String {
        child(plan, index).components[0].destination.clone()
    }

    /// The real payload source beside the fixture bundle.
    fn skills_source(fixture: &Fixture) -> LocalPayloadSource {
        LocalPayloadSource::new(format!("{}/skills/payload", fixture.bundle_root))
    }

    fn rule_of(error: &AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    fn request(plan: &EcosystemPlan) -> ApplyRequest {
        ApplyRequest::new(TRANSACTION, plan.plan_digest.clone(), CREATED_AT)
    }

    /// Write one planned payload to its real staging path.
    fn stage_on_disk(plan: &EcosystemPlan, index: usize, payload: &[u8]) {
        let staging = staged(plan, index);
        let path = Path::new(&staging);
        std::fs::create_dir_all(path.parent().expect("staging parent")).expect("staging directory");
        std::fs::write(path, payload).expect("staged payload");
    }

    #[test]
    fn the_matrix_is_thirteen_rows_in_report_order() {
        let rows = declarations();
        assert_eq!(rows.len(), 13);
        let pairs: Vec<(String, String)> = rows
            .iter()
            .map(|row| (row.component.to_string(), row.class.as_str().to_string()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("axiom-graphd", "interpreter"),
                ("axiom-graphd", "toolchain"),
                ("axiom-graphd", "runtime"),
                ("axiom-graphd", "native_dependency"),
                ("axiom-graphd", "host_executable"),
                ("axiom-graphd", "permission"),
                ("axiom-mcp", "interpreter"),
                ("axiom-mcp", "toolchain"),
                ("axiom-mcp", "runtime"),
                ("axiom-skills", "interpreter"),
                ("axiom-skills", "toolchain"),
                ("axiom-skills", "runtime"),
                ("axiom-skills", "approval"),
            ]
            .into_iter()
            .map(|(component, class)| (component.to_string(), class.to_string()))
            .collect::<Vec<_>>()
        );
        // Every row belongs to a contract component, and the rows that gate the
        // installation are exactly the ones this build owns a requirement for.
        for row in rows {
            assert!(INSTALL_ORDER.contains(&row.component), "{}", row.component);
        }
        let required: Vec<&str> = rows
            .iter()
            .filter(|row| row.required)
            .map(|row| row.class.as_str())
            .collect();
        assert_eq!(
            required,
            vec!["runtime", "host_executable", "permission", "interpreter"]
        );
        assert!(declaration("axiom-graphd", PrerequisiteClass::Runtime).is_some());
        assert!(declaration("axiom-skills", PrerequisiteClass::Approval).is_some());
    }

    #[test]
    fn the_sqlite_row_renders_the_store_baseline_instead_of_a_copy() {
        let row = declaration("axiom-graphd", PrerequisiteClass::NativeDependency)
            .expect("the store row is declared");
        assert_eq!(row.status, DeclarationStatus::Undeclared);
        assert!(!row.required);
        let expected = row
            .expected
            .expect("the store row carries an expectation")
            .render();
        assert!(
            expected.contains(&graph_store::open::MIN_SQLITE_VERSION.to_string()),
            "the report must render the store constant: {expected}"
        );
        let reported = report(&SatisfiedProbe, row);
        assert_eq!(reported.status, "unknown");
        assert_eq!(reported.pin, "undeclared");
        assert_eq!(reported.expected.as_deref(), Some(expected.as_str()));
        assert!(!reported.blocking);
    }

    #[test]
    fn a_satisfied_probe_reports_every_row_and_blocks_nothing() {
        let reports = probe(&SatisfiedProbe);
        assert_eq!(reports.len(), 13);
        assert!(blocking_rows(&reports).is_empty());
        assert!(prerequisite_refusal(&reports).is_none());
        assert_eq!(
            verification_gaps(&reports),
            vec!["axiom-graphd/native_dependency"]
        );
        for row in &reports {
            assert!(row.status == "satisfied" || row.status == "unknown");
            if row.required {
                assert_eq!(row.status, "satisfied", "{}", row.class);
            }
        }
    }

    #[test]
    fn an_unsatisfied_required_row_refuses_before_the_bundle_is_opened() {
        let install_dir = TempDir::new().expect("install tempdir");
        let error = plan_ecosystem(
            &unsatisfied("axiom-mcp", "interpreter"),
            "C:/does/not/exist/axiom-bundle",
            &context(&host_path(install_dir.path())),
        )
        .expect_err("an unsatisfied required row refuses");
        assert_eq!(error.code(), ErrorCode::NotReady);
        assert_eq!(error.exit_code(), ExitCode::NotReady);
        assert_eq!(error.exit_code().as_i32(), 4);
        assert_eq!(rule_of(&error), Some(RULE_PREREQUISITE));
        assert!(error.message().contains("axiom-mcp/interpreter"));
        assert_eq!(
            error.details().get("component").map(String::as_str),
            Some("axiom-mcp")
        );
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("interpreter reported unsatisfied")
        );
    }

    #[test]
    fn an_unknown_required_row_is_never_treated_as_satisfied() {
        let install_dir = TempDir::new().expect("install tempdir");
        let error = plan_ecosystem(
            &unknown("axiom-graphd", "host_executable"),
            "C:/does/not/exist/axiom-bundle",
            &context(&host_path(install_dir.path())),
        )
        .expect_err("an unknown required row refuses");
        assert_eq!(error.code(), ErrorCode::NotReady);
        assert_eq!(rule_of(&error), Some(RULE_PREREQUISITE));
        assert!(error.message().contains("axiom-graphd/host_executable"));
    }

    #[test]
    fn an_undeclared_row_is_a_recorded_gap_and_never_a_blocker() {
        let fixture = fixture();
        let plan = planned(&fixture);
        assert!(plan
            .prerequisites
            .iter()
            .any(|row| row.component == "axiom-graphd"
                && row.class == "native_dependency"
                && row.status == "unknown"
                && !row.blocking));
        assert_eq!(
            plan.verification_gaps,
            vec!["axiom-graphd/native_dependency"]
        );
    }

    #[test]
    fn the_plan_places_three_components_in_contract_order_behind_one_digest() {
        let fixture = fixture();
        let plan = planned(&fixture);
        assert_eq!(plan.kind, ECOSYSTEM_PLAN_KIND);
        assert_eq!(plan.contract_id, CONTRACT_ID);
        assert_eq!(plan.schema, ECOSYSTEM_DIGEST_SCHEMA);
        assert_eq!(
            plan.install_order,
            INSTALL_ORDER
                .iter()
                .map(|component| (*component).to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(plan.component_plans.len(), 3);
        for (index, entry) in plan.component_plans.iter().enumerate() {
            assert_eq!(entry.position, (index as u64) + 1);
            assert_eq!(entry.component, INSTALL_ORDER[index]);
            assert_eq!(
                entry.recompute_digest().expect("the entry digests"),
                entry.digest
            );
            assert!(is_digest(&entry.digest));
            assert!(is_digest(&entry.activation_digest));
        }
        assert!(is_digest(&plan.plan_digest));
        plan.verify(&plan.plan_digest)
            .expect("the plan verifies at its own digest");
        let text = plan.to_json().expect("the plan serialises");
        let round_tripped: EcosystemPlan = serde_json::from_str(&text).expect("round trip");
        assert_eq!(round_tripped, plan);
        let rendered = plan.text();
        for component in INSTALL_ORDER {
            assert!(rendered.contains(component), "{rendered}");
        }
    }

    #[test]
    fn planning_is_deterministic_over_the_same_bundle() {
        let fixture = fixture();
        let first = planned(&fixture);
        let second = planned(&fixture);
        assert_eq!(first.plan_digest, second.plan_digest);
        assert_eq!(
            first.to_json().expect("json"),
            second.to_json().expect("json")
        );
    }

    #[test]
    fn a_foreign_digest_is_refused_as_a_stale_approval() {
        let fixture = fixture();
        let plan = planned(&fixture);
        let error = plan
            .verify(&"0".repeat(64))
            .expect_err("a foreign digest is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(error.exit_code().as_i32(), 5);
        assert_eq!(rule_of(&error), Some(RULE_APPROVAL));
        assert!(error
            .details()
            .get("observed")
            .expect("observed")
            .contains(REASON_APPROVAL_STALE));
        let error = plan
            .verify("not-a-digest")
            .expect_err("a value that is not a digest is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule_of(&error), Some(RULE_APPROVAL));
    }

    #[test]
    fn a_tampered_component_plan_is_refused_by_its_own_digest() {
        let fixture = fixture();
        let mut plan = planned(&fixture);
        plan.component_plans[1].version = "9.9.9".to_string();
        let approved = plan.plan_digest.clone();
        let error = verify_ecosystem(&plan, &approved).expect_err("a tampered entry is refused");
        assert_eq!(rule_of(&error), Some(RULE_COMPONENT_DIGEST));
        assert_eq!(
            error.details().get("component").map(String::as_str),
            Some("axiom-mcp")
        );
    }

    #[test]
    fn a_bundle_missing_a_core_component_is_refused_by_name() {
        let mut manifest = core_manifest();
        manifest
            .components
            .retain(|component| component.component == "axiom-graphd");
        let fixture = fixture_with(manifest, &[(GRAPHD_ARTIFACT, GRAPHD)]);
        let error = plan_ecosystem(
            &SatisfiedProbe,
            &fixture.bundle_root,
            &context(&fixture.install_root),
        )
        .expect_err("a bundle without axiom-mcp refuses");
        assert_eq!(rule_of(&error), Some(RULE_MISSING_COMPONENT));
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("axiom-mcp")
        );
    }

    #[test]
    fn a_bundle_declaring_an_out_of_contract_component_is_refused() {
        let mut manifest = core_manifest();
        manifest.components.push(bundle_component(
            "axiom",
            "bin/axiom",
            ArtifactKind::Binary,
            GRAPHD,
        ));
        let fixture = fixture_with(
            manifest,
            &[
                (GRAPHD_ARTIFACT, GRAPHD),
                (MCP_ARTIFACT, MCP),
                ("bin/axiom", GRAPHD),
            ],
        );
        let error = plan_ecosystem(
            &SatisfiedProbe,
            &fixture.bundle_root,
            &context(&fixture.install_root),
        )
        .expect_err("a component outside the contract order refuses");
        assert_eq!(rule_of(&error), Some(RULE_ORDER));
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("axiom")
        );
    }

    #[test]
    fn an_approved_plan_activates_all_three_components_in_contract_order() {
        let fixture = fixture();
        let plan = planned(&fixture);
        let core_fs = MemoryActivationFs::default();
        core_fs.put(&staged(&plan, 0), GRAPHD);
        core_fs.put(&staged(&plan, 1), MCP);
        let skills_fs = MemorySkillsFs::default();
        let applied = apply_ecosystem(
            &plan,
            &plan.plan_digest,
            &request(&plan),
            &core_fs,
            &skills_source(&fixture),
            &skills_fs,
        )
        .expect("the approved plan activates");
        assert_eq!(applied.schema_version, ECOSYSTEM_APPLICATION_SCHEMA_VERSION);
        assert_eq!(applied.plan_id, PLAN_ID);
        assert_eq!(applied.plan_digest, plan.plan_digest);
        assert_eq!(applied.transaction_id, TRANSACTION);
        assert_eq!(applied.status, STATUS_INSTALLED);
        assert_eq!(applied.components.len(), INSTALL_ORDER.len());
        for (index, row) in applied.components.iter().enumerate() {
            assert_eq!(row.position, (index as u64) + 1);
            assert_eq!(row.component, INSTALL_ORDER[index]);
            assert_eq!(row.status, STATUS_INSTALLED, "{}", row.component);
            assert!(is_digest(&row.sha256), "{}", row.component);
        }
        assert_eq!(applied.components[0].destination, destination(&plan, 0));
        assert_eq!(applied.components[1].destination, destination(&plan, 1));
        assert_eq!(applied.components[2].component, SKILLS_COMPONENT);
        assert_eq!(
            applied.components[2].sha256,
            plan.component_plans[2].activation_digest
        );
        assert!(applied.components[2].destination.starts_with("skills/"));
        assert_eq!(applied.core_pointer, plan.rollback.current_pointer);
        assert_eq!(
            applied.skills_pointer,
            format!("{SKILLS_BUNDLES_DIR}/{ACTIVE_POINTER}")
        );
        assert_eq!(
            applied.keeps_previous_versions,
            plan.rollback.keeps_previous_versions
        );
        assert!(applied.keeps_previous_versions >= MIN_KEEP_PREVIOUS_VERSIONS);
        // The payloads moved and the staging trees were consumed.
        assert!(core_fs.holds(&destination(&plan, 0)));
        assert!(core_fs.holds(&destination(&plan, 1)));
        assert!(!core_fs.holds(&staged(&plan, 0)));
        assert!(!core_fs.holds(&staged(&plan, 1)));
        assert_eq!(
            core_fs.read(&destination(&plan, 0)).expect("graphd bytes"),
            GRAPHD.to_vec()
        );
        assert_eq!(
            core_fs.read(&destination(&plan, 1)).expect("mcp bytes"),
            MCP.to_vec()
        );
        // The update engine kept its own boundaries: one journal entry and one
        // rollback record per activated component.
        for entry in &plan.component_plans[..CORE_COMPONENTS.len()] {
            let transaction = format!("{}-{}", TRANSACTION, entry.component);
            let journal = format!("{}/{}.json", plan.rollback.journal_directory, transaction);
            let rollback = format!("{journal}{}", crate::install::apply::ROLLBACK_SUFFIX);
            assert!(core_fs.holds(&journal), "{journal}");
            assert!(core_fs.holds(&rollback), "{rollback}");
        }
        // The skills manifest pointer names the bundle that was reviewed.
        let pointer = skills_fs
            .get(&applied.skills_pointer)
            .expect("the skills pointer was written");
        let pointer = String::from_utf8_lossy(&pointer).into_owned();
        assert!(
            pointer.contains(&applied.components[2].destination),
            "{pointer}"
        );
        assert!(pointer.contains(&applied.components[2].sha256), "{pointer}");
        let json = applied.to_json().expect("the record serialises");
        let round: EcosystemApplication = serde_json::from_str(&json).expect("round trip");
        assert_eq!(round, applied);
        let text = applied.text();
        for component in INSTALL_ORDER {
            assert!(text.contains(component), "{text}");
        }
    }

    #[test]
    fn a_re_run_over_an_installed_ecosystem_reports_already_installed() {
        let fixture = fixture();
        let plan = planned(&fixture);
        let core_fs = MemoryActivationFs::default();
        core_fs.put(&staged(&plan, 0), GRAPHD);
        core_fs.put(&staged(&plan, 1), MCP);
        let skills_fs = MemorySkillsFs::default();
        let first = apply_ecosystem(
            &plan,
            &plan.plan_digest,
            &request(&plan),
            &core_fs,
            &skills_source(&fixture),
            &skills_fs,
        )
        .expect("the first run installs");
        assert_eq!(first.status, STATUS_INSTALLED);
        let mutations = core_fs.mutations();
        let second = apply_ecosystem(
            &plan,
            &plan.plan_digest,
            &request(&plan),
            &core_fs,
            &skills_source(&fixture),
            &skills_fs,
        )
        .expect("the re-run reports the existing installation");
        assert_eq!(second.status, STATUS_ALREADY_INSTALLED);
        for row in &second.components {
            assert_eq!(row.status, STATUS_ALREADY_INSTALLED, "{}", row.component);
            assert!(is_digest(&row.sha256), "{}", row.component);
        }
        assert_eq!(
            second.components[0].destination,
            first.components[0].destination
        );
        assert_eq!(second.components[0].sha256, first.components[0].sha256);
        // Nothing was rewritten: no payload re-moved, no pointer re-written.
        assert_eq!(core_fs.mutations(), mutations);
    }

    #[test]
    fn a_run_that_cannot_stage_every_payload_writes_nothing() {
        let fixture = fixture();
        let plan = planned(&fixture);
        let core_fs = MemoryActivationFs::default();
        core_fs.put(&staged(&plan, 0), GRAPHD);
        let skills_fs = MemorySkillsFs::default();
        let error = apply_ecosystem(
            &plan,
            &plan.plan_digest,
            &request(&plan),
            &core_fs,
            &skills_source(&fixture),
            &skills_fs,
        )
        .expect_err("the missing payload refuses before any move");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(error.exit_code().as_i32(), ExitCode::Conflict.as_i32());
        assert_eq!(rule_of(&error), Some(RULE_STAGING_INCOMPLETE));
        assert_eq!(
            error.details().get("component").map(String::as_str),
            Some("axiom-mcp")
        );
        assert_eq!(core_fs.mutations(), 0);
        assert!(!core_fs.holds(&destination(&plan, 0)));
        assert!(!core_fs.holds(&destination(&plan, 1)));
        assert!(core_fs.holds(&staged(&plan, 0)));
        assert!(skills_fs
            .get(&format!("{SKILLS_BUNDLES_DIR}/{ACTIVE_POINTER}"))
            .is_none());
    }

    #[test]
    fn an_interrupted_installation_resumes_without_re_moving_a_placed_component() {
        let fixture = fixture();
        let plan = planned(&fixture);
        let core_fs = MemoryActivationFs::default();
        // A run that was interrupted after moving the first component: the
        // destination holds the planned bytes and its staging tree is gone.
        core_fs.put(&destination(&plan, 0), GRAPHD);
        core_fs.put(&staged(&plan, 1), MCP);
        let skills_fs = MemorySkillsFs::default();
        let applied = apply_ecosystem(
            &plan,
            &plan.plan_digest,
            &request(&plan),
            &core_fs,
            &skills_source(&fixture),
            &skills_fs,
        )
        .expect("the re-run resumes the remaining components");
        assert_eq!(applied.status, STATUS_INSTALLED);
        assert_eq!(applied.components[0].status, STATUS_ALREADY_INSTALLED);
        assert_eq!(applied.components[1].status, STATUS_INSTALLED);
        assert_eq!(applied.components[2].status, STATUS_INSTALLED);
        assert!(core_fs.holds(&destination(&plan, 0)));
        assert!(!core_fs.holds(&staged(&plan, 0)));
        assert_eq!(
            core_fs.read(&destination(&plan, 0)).expect("graphd bytes"),
            GRAPHD.to_vec()
        );
        assert_eq!(
            core_fs.read(&destination(&plan, 1)).expect("mcp bytes"),
            MCP.to_vec()
        );
        // Only the resumed component wrote a journal entry.
        let skipped = format!(
            "{}/{}-{}.json",
            plan.rollback.journal_directory, TRANSACTION, "axiom-graphd"
        );
        let resumed = format!(
            "{}/{}-{}.json",
            plan.rollback.journal_directory, TRANSACTION, "axiom-mcp"
        );
        assert!(!core_fs.holds(&skipped), "{skipped}");
        assert!(core_fs.holds(&resumed), "{resumed}");
    }

    #[test]
    fn a_foreign_approved_digest_refuses_and_writes_nothing() {
        let fixture = fixture();
        let plan = planned(&fixture);
        let core_fs = MemoryActivationFs::default();
        core_fs.put(&staged(&plan, 0), GRAPHD);
        core_fs.put(&staged(&plan, 1), MCP);
        let skills_fs = MemorySkillsFs::default();
        let error = apply_ecosystem(
            &plan,
            &"0".repeat(64),
            &request(&plan),
            &core_fs,
            &skills_source(&fixture),
            &skills_fs,
        )
        .expect_err("an unapproved plan refuses");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(error.exit_code().as_i32(), ExitCode::Authorization.as_i32());
        assert_eq!(rule_of(&error), Some(RULE_APPROVAL));
        assert_eq!(core_fs.mutations(), 0);
        assert!(!core_fs.holds(&destination(&plan, 0)));
        assert!(!core_fs.holds(&destination(&plan, 1)));
        assert!(!core_fs.holds(&plan.rollback.current_pointer));
    }

    #[test]
    fn a_staged_payload_with_foreign_bytes_is_refused_before_any_write() {
        let fixture = fixture();
        let plan = planned(&fixture);
        let core_fs = MemoryActivationFs::default();
        // The same byte count as the declared payload, different bytes: this is
        // the digest branch of the staging check, not the length branch.
        let mut tampered = GRAPHD.to_vec();
        tampered[0] = b'T';
        core_fs.put(&staged(&plan, 0), &tampered);
        core_fs.put(&staged(&plan, 1), MCP);
        let skills_fs = MemorySkillsFs::default();
        let error = apply_ecosystem(
            &plan,
            &plan.plan_digest,
            &request(&plan),
            &core_fs,
            &skills_source(&fixture),
            &skills_fs,
        )
        .expect_err("a substituted payload refuses");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(rule_of(&error), Some(RULE_STAGING_INCOMPLETE));
        assert_eq!(
            error.details().get("component").map(String::as_str),
            Some("axiom-graphd")
        );
        assert_eq!(
            error.details().get("expected").map(String::as_str),
            Some(child(&plan, 0).components[0].source.sha256.as_str())
        );
        assert_ne!(
            error.details().get("observed").map(String::as_str),
            Some(child(&plan, 0).components[0].source.sha256.as_str())
        );
        assert_eq!(core_fs.mutations(), 0);
        assert!(!core_fs.holds(&destination(&plan, 1)));
    }

    #[test]
    fn the_published_activation_digest_is_an_approval_of_the_child_plan() {
        let fixture = fixture();
        let plan = planned(&fixture);
        let core_fs = MemoryActivationFs::default();
        core_fs.put(&staged(&plan, 0), GRAPHD);
        let entry = &plan.component_plans[0];
        let child_plan = child(&plan, 0);
        let request = ApplyRequest::new("t-1", entry.activation_digest.clone(), CREATED_AT);
        let applied =
            apply_install(&child_plan, &request, &core_fs).expect("the published digest activates");
        assert_eq!(applied.plan_digest, entry.activation_digest);
        assert!(core_fs.holds(&destination(&plan, 0)));
        // The ecosystem digest is not an approval of the embedded component
        // plan, so one approval can never be replayed onto the other document.
        let error = apply_install(
            &child_plan,
            &ApplyRequest::new("t-2", plan.plan_digest.clone(), CREATED_AT),
            &core_fs,
        )
        .expect_err("the ecosystem digest is refused by the child plan");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule_of(&error), Some(RULE_APPROVAL));
    }

    #[test]
    fn a_skills_payload_the_reviewed_manifest_does_not_describe_is_refused() {
        let fixture = fixture();
        let plan = planned(&fixture);
        let core_fs = MemoryActivationFs::default();
        core_fs.put(&staged(&plan, 0), GRAPHD);
        core_fs.put(&staged(&plan, 1), MCP);
        let skills_fs = MemorySkillsFs::default();
        let tampered = MemoryPayload::with(SKILL_PATH, b"# a substituted skill payload\n");
        let error = apply_ecosystem(
            &plan,
            &plan.plan_digest,
            &request(&plan),
            &core_fs,
            &tampered,
            &skills_fs,
        )
        .expect_err("a substituted skills payload refuses");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(rule_of(&error), Some(RULE_STAGING_INCOMPLETE));
        assert_eq!(
            error.details().get("component").map(String::as_str),
            Some(SKILLS_COMPONENT)
        );
        assert_eq!(core_fs.mutations(), 0);
        assert!(!core_fs.holds(&destination(&plan, 0)));
        assert!(skills_fs
            .get(&format!("{SKILLS_BUNDLES_DIR}/{ACTIVE_POINTER}"))
            .is_none());
        // The same plan applies from any payload source that carries the bytes
        // the reviewed manifest declares.
        let declared = MemoryPayload::with(SKILL_PATH, SKILL);
        let applied = apply_ecosystem(
            &plan,
            &plan.plan_digest,
            &request(&plan),
            &core_fs,
            &declared,
            &skills_fs,
        )
        .expect("the declared payload applies");
        assert_eq!(applied.status, STATUS_INSTALLED);
        assert_eq!(applied.components[2].status, STATUS_INSTALLED);
    }

    /// A host probe over a fixed search path and fixed program output.
    #[derive(Debug, Default)]
    struct MemoryHostProbe {
        programs: BTreeMap<String, String>,
        versions: BTreeMap<String, String>,
    }

    impl MemoryHostProbe {
        fn found(mut self, stem: &str, path: &str, version: &str) -> Self {
            self.programs.insert(stem.to_string(), path.to_string());
            self.versions.insert(stem.to_string(), version.to_string());
            self
        }
    }

    impl HostProbe for MemoryHostProbe {
        fn locate(&self, stem: &str) -> Option<String> {
            self.programs.get(stem).cloned()
        }

        fn run(
            &self,
            program: &str,
            _argv: &[String],
        ) -> Result<crate::hosts::detect::ProcessOutput, AxiomError> {
            let stem = self
                .programs
                .iter()
                .find(|(_, path)| path.as_str() == program)
                .map(|(stem, _)| stem.clone())
                .ok_or_else(|| {
                    AxiomError::new(ErrorCode::NotFound, "the fixture does not run this program")
                        .with_detail("observed", program)
                })?;
            Ok(crate::hosts::detect::ProcessOutput {
                code: 0,
                stdout: self.versions.get(&stem).cloned().unwrap_or_default(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn the_native_probe_reads_the_declared_pins_from_the_probe_search_path() {
        let dir = TempDir::new().expect("tempdir");
        let root = host_path(dir.path());
        let host = MemoryHostProbe::default()
            .found(
                "rustc",
                "C:/rust/bin/rustc.exe",
                "rustc 1.85.0 (4d91de4e4 2025-02-17)\n",
            )
            .found("python3", "C:/python/python3.exe", "Python 3.13.14\n");
        let probe = NativeProbe::new(&host, &root);
        let rust = probe
            .observe(declaration("axiom-graphd", PrerequisiteClass::Toolchain).expect("declared"));
        assert_eq!(rust.status, PrerequisiteStatus::Satisfied);
        assert!(rust.observed.contains(RUST_PIN), "{}", rust.observed);
        let python = probe
            .observe(declaration("axiom-mcp", PrerequisiteClass::Interpreter).expect("declared"));
        assert_eq!(python.status, PrerequisiteStatus::Satisfied);
        assert!(python.observed.contains("3.13.14"), "{}", python.observed);
        // The entrypoint is this running process, an absolute host path.
        let executable = probe.observe(
            declaration("axiom-graphd", PrerequisiteClass::HostExecutable).expect("declared"),
        );
        assert_eq!(executable.status, PrerequisiteStatus::Satisfied);
        let permission = probe
            .observe(declaration("axiom-graphd", PrerequisiteClass::Permission).expect("declared"));
        assert_eq!(permission.status, PrerequisiteStatus::Satisfied);
        // Approval is unknown until a digest is bound to the run.
        let approval = probe
            .observe(declaration("axiom-skills", PrerequisiteClass::Approval).expect("declared"));
        assert_eq!(approval.status, PrerequisiteStatus::Unknown);
        let approved = NativeProbe::new(&host, &root).with_approval(true);
        assert_eq!(
            approved
                .observe(
                    declaration("axiom-skills", PrerequisiteClass::Approval).expect("declared")
                )
                .status,
            PrerequisiteStatus::Satisfied
        );
    }

    #[test]
    fn the_native_probe_is_never_satisfied_without_an_in_range_interpreter() {
        let dir = TempDir::new().expect("tempdir");
        let root = host_path(dir.path());
        let old =
            MemoryHostProbe::default().found("python", "C:/python/python.exe", "Python 3.12.9\n");
        let probe = NativeProbe::new(&old, &root);
        let observed = probe
            .observe(declaration("axiom-mcp", PrerequisiteClass::Interpreter).expect("declared"));
        assert_eq!(observed.status, PrerequisiteStatus::Unsatisfied);
        assert!(
            observed.observed.contains("3.12.9"),
            "{}",
            observed.observed
        );
        let no_host = MemoryHostProbe::default();
        let probe = NativeProbe::new(&no_host, &root);
        let observed = probe
            .observe(declaration("axiom-mcp", PrerequisiteClass::Interpreter).expect("declared"));
        assert_eq!(observed.status, PrerequisiteStatus::Unsatisfied);
        assert!(
            observed.observed.contains("not found"),
            "{}",
            observed.observed
        );
    }

    #[test]
    fn the_native_probe_declines_a_row_this_build_does_not_declare() {
        let dir = TempDir::new().expect("tempdir");
        let host = MemoryHostProbe::default();
        assert!(declaration("axiom-platform", PrerequisiteClass::Interpreter).is_none());
        let probe = NativeProbe::new(&host, &host_path(dir.path()));
        for class in [
            PrerequisiteClass::Interpreter,
            PrerequisiteClass::Toolchain,
            PrerequisiteClass::Runtime,
            PrerequisiteClass::NativeDependency,
            PrerequisiteClass::Approval,
            PrerequisiteClass::HostExecutable,
            PrerequisiteClass::Permission,
        ] {
            let row = PrerequisiteDeclaration {
                component: "axiom-platform",
                class,
                status: DeclarationStatus::Declared,
                requirement: "a component this ecosystem does not own",
                version_source: None,
                pin: "declared",
                required: true,
                expected: None,
            };
            let observed = probe.observe(&row);
            assert_ne!(
                observed.status,
                PrerequisiteStatus::Satisfied,
                "{}",
                class.as_str()
            );
            assert_eq!(observed.status, PrerequisiteStatus::Unknown);
        }
        assert!(declarations()
            .iter()
            .all(|row| row.component != "axiom-platform"));
    }

    #[test]
    fn the_version_parsers_read_the_declared_pins() {
        assert_eq!(
            parse_tool_version(
                "rustc 1.85.0 (4d91de4e4 2025-02-17)\nhost: x86_64\n",
                "rustc"
            )
            .as_deref(),
            Some("1.85.0")
        );
        assert_eq!(parse_tool_version("cargo 1.85.0\n", "rustc"), None);
        assert_eq!(parse_tool_version("rustc\n", "rustc"), None);
        assert_eq!(parse_tool_version("rustc ", "rustc"), None);
        assert_eq!(parse_python_version("Python 3.13.14"), Some((3, 13, 14)));
        assert_eq!(parse_python_version("Python 3.13"), Some((3, 13, 0)));
        assert_eq!(parse_python_version("no version here"), None);
        assert!(python_in_range((3, 13, 0)));
        assert!(python_in_range((3, 13, 99)));
        assert!(!python_in_range((3, 12, 9)));
        assert!(!python_in_range((3, 14, 0)));
        assert_eq!(PYTHON_MIN, (3, 13, 0));
        assert_eq!(PYTHON_MAX_EXCLUSIVE, (3, 14, 0));
        assert_eq!(
            FORBIDDEN_MECHANISMS,
            [
                "wsl",
                "docker",
                "bash",
                "elevation",
                "node",
                "systemd_foreground"
            ]
        );
    }

    #[test]
    fn the_plan_never_requires_a_forbidden_mechanism() {
        let fixture = fixture();
        let plan = planned(&fixture);
        // Per-user, never elevated: the two mechanisms AC1 rules out.
        assert_eq!(plan.target.scope, InstallScope::PerUser);
        for (index, entry) in plan.component_plans[..CORE_COMPONENTS.len()]
            .iter()
            .enumerate()
        {
            let child_plan = child(&plan, index);
            assert!(
                child_plan
                    .permissions
                    .iter()
                    .all(|permission| !permission.requires_elevation),
                "{}",
                entry.component
            );
        }
    }

    #[test]
    fn the_native_probe_reports_the_real_host_before_any_write() {
        let dir = TempDir::new().expect("tempdir");
        let root = host_path(dir.path());
        let host = crate::hosts::detect::LocalHostProbe::for_current_process();
        let probe = NativeProbe::new(&host, &root);
        let reports = probe_all(&probe);
        assert_eq!(reports.len(), declarations().len());
        for row in &reports {
            println!(
                "{} {} status={} required={} blocking={} expected={} observed={}",
                row.component,
                row.class,
                row.status,
                row.required,
                row.blocking,
                row.expected.as_deref().unwrap_or("<none>"),
                row.observed
            );
        }
        // The entrypoint performing the install is observable on every host.
        let executable = reports
            .iter()
            .find(|row| row.component == "axiom-graphd" && row.class == "host_executable")
            .expect("the host executable row is declared");
        assert_eq!(executable.status, "satisfied", "{}", executable.observed);
        assert!(!executable.blocking);
        // A blocking row is never satisfied and an undeclared row is never a
        // blocker, whatever this host happens to carry.
        for row in &reports {
            assert!(!(row.blocking && row.status == "satisfied"));
            if row.pin == "undeclared" {
                assert!(!row.blocking);
            }
        }
    }

    #[test]
    fn the_real_probe_either_plans_or_refuses_with_exit_four() {
        let fixture = fixture();
        let dir = TempDir::new().expect("tempdir");
        let install_root = host_path(dir.path());
        let host = crate::hosts::detect::LocalHostProbe::for_current_process();
        let probe = NativeProbe::new(&host, &install_root);
        let outcome = plan_ecosystem(&probe, &fixture.bundle_root, &context(&install_root));
        match outcome {
            Ok(plan) => {
                println!("{}", plan.text());
                println!("verification_gaps={:?}", plan.verification_gaps);
                assert!(plan.prerequisites.iter().all(|row| !row.blocking));
                assert_eq!(plan.component_plans.len(), INSTALL_ORDER.len());
                plan.verify(&plan.plan_digest)
                    .expect("the real-host plan verifies at its own digest");
            }
            Err(error) => {
                println!(
                    "refused: code={:?} exit={} component={:?} observed={:?}",
                    error.code(),
                    error.exit_code().as_i32(),
                    error.details().get("component"),
                    error.details().get("observed")
                );
                assert_eq!(error.code(), ErrorCode::NotReady);
                assert_eq!(error.exit_code().as_i32(), i32::from(EXIT_NOT_READY));
                assert_eq!(rule_of(&error), Some(RULE_PREREQUISITE));
            }
        }
    }

    #[test]
    fn the_real_probe_refuses_a_host_with_no_required_interpreter() {
        // An empty search path carries no interpreter, so the one required row
        // this build cannot discharge itself is unmet.
        let no_host = MemoryHostProbe::default();
        let probe = NativeProbe::new(&no_host, "C:/axiom-ecosystem-verify");
        // The bundle root does not exist: the refusal must happen before the
        // bundle is opened, so the run cannot depend on it.
        let error = plan_ecosystem(
            &probe,
            "C:/no-such-bundle-root",
            &context("C:/axiom-ecosystem-verify"),
        )
        .expect_err("a host with no interpreter refuses");
        println!(
            "refused: code={:?} exit={} rule={:?} component={:?} expected={:?} observed={:?}",
            error.code(),
            error.exit_code().as_i32(),
            rule_of(&error),
            error.details().get("component"),
            error.details().get("required_version"),
            error.details().get("observed")
        );
        assert_eq!(error.code(), ErrorCode::NotReady);
        assert_eq!(error.exit_code().as_i32(), i32::from(EXIT_NOT_READY));
        assert_eq!(rule_of(&error), Some(RULE_PREREQUISITE));
        assert!(error.message().contains("axiom-mcp/interpreter"));
    }

    #[test]
    fn the_production_filesystem_boundary_installs_and_reports_already_installed() {
        let fixture = fixture();
        let plan = planned(&fixture);
        let source = skills_source(&fixture);
        let skills_fs = LocalInstallFs::new(fixture.install_root.as_str());
        stage_on_disk(&plan, 0, GRAPHD);
        stage_on_disk(&plan, 1, MCP);
        let applied = apply_ecosystem(
            &plan,
            &plan.plan_digest,
            &request(&plan),
            &LocalFs,
            &source,
            &skills_fs,
        )
        .expect("the production boundary installs");
        println!("{}", applied.text());
        assert_eq!(applied.status, STATUS_INSTALLED);
        assert_eq!(
            std::fs::read(destination(&plan, 0)).expect("graphd bytes"),
            GRAPHD.to_vec()
        );
        assert_eq!(
            std::fs::read(destination(&plan, 1)).expect("mcp bytes"),
            MCP.to_vec()
        );
        assert!(!Path::new(&staged(&plan, 0)).exists());
        assert!(!Path::new(&staged(&plan, 1)).exists());
        assert!(Path::new(&plan.rollback.current_pointer).exists());
        for entry in &plan.component_plans[..CORE_COMPONENTS.len()] {
            let journal = format!(
                "{}/{}-{}.json",
                plan.rollback.journal_directory, TRANSACTION, entry.component
            );
            assert!(Path::new(&journal).exists(), "{journal}");
        }
        let install_root = Path::new(&fixture.install_root);
        assert!(install_root.join(&applied.skills_pointer).exists());
        assert!(install_root
            .join(&applied.components[2].destination)
            .join(SKILL_PATH)
            .exists());
        // The real re-run reads the real destinations and rewrites nothing.
        let again = apply_ecosystem(
            &plan,
            &plan.plan_digest,
            &request(&plan),
            &LocalFs,
            &source,
            &skills_fs,
        )
        .expect("the re-run reports the existing installation");
        println!("re-run: {}", again.text());
        assert_eq!(again.status, STATUS_ALREADY_INSTALLED);
        for row in &again.components {
            assert_eq!(row.status, STATUS_ALREADY_INSTALLED, "{}", row.component);
        }
        assert_eq!(
            std::fs::read(destination(&plan, 0)).expect("graphd bytes"),
            GRAPHD.to_vec()
        );
    }

    #[test]
    fn the_production_filesystem_boundary_writes_nothing_when_a_payload_is_missing() {
        let fixture = fixture();
        let plan = planned(&fixture);
        let source = skills_source(&fixture);
        let skills_fs = LocalInstallFs::new(fixture.install_root.as_str());
        stage_on_disk(&plan, 0, GRAPHD);
        let error = apply_ecosystem(
            &plan,
            &plan.plan_digest,
            &request(&plan),
            &LocalFs,
            &source,
            &skills_fs,
        )
        .expect_err("the missing payload refuses");
        println!(
            "refused: code={:?} exit={} rule={:?} component={:?} observed={:?}",
            error.code(),
            error.exit_code().as_i32(),
            rule_of(&error),
            error.details().get("component"),
            error.details().get("observed")
        );
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(rule_of(&error), Some(RULE_STAGING_INCOMPLETE));
        assert_eq!(
            error.details().get("component").map(String::as_str),
            Some("axiom-mcp")
        );
        // Nothing on disk was touched: no destination, no pointer, no journal.
        assert!(!Path::new(&destination(&plan, 0)).exists());
        assert!(!Path::new(&destination(&plan, 1)).exists());
        assert!(!Path::new(&plan.rollback.current_pointer).exists());
        let install_root = Path::new(&fixture.install_root);
        assert!(!install_root
            .join(format!("{SKILLS_BUNDLES_DIR}/{ACTIVE_POINTER}"))
            .exists());
        assert!(!Path::new(&format!(
            "{}/{}-{}.json",
            plan.rollback.journal_directory, TRANSACTION, "axiom-graphd"
        ))
        .exists());
        // The interrupted installation resumes once the payload arrives.
        stage_on_disk(&plan, 1, MCP);
        let applied = apply_ecosystem(
            &plan,
            &plan.plan_digest,
            &request(&plan),
            &LocalFs,
            &source,
            &skills_fs,
        )
        .expect("the resumed run installs");
        println!("resumed: {}", applied.text());
        assert_eq!(applied.status, STATUS_INSTALLED);
        assert_eq!(applied.components[0].status, STATUS_INSTALLED);
        assert_eq!(applied.components[1].status, STATUS_INSTALLED);
        assert_eq!(applied.components[2].status, STATUS_INSTALLED);
        assert_eq!(
            std::fs::read(destination(&plan, 1)).expect("mcp bytes"),
            MCP.to_vec()
        );
    }

    #[test]
    fn the_production_filesystem_boundary_resumes_without_re_moving_a_placed_component() {
        let fixture = fixture();
        let plan = planned(&fixture);
        let source = skills_source(&fixture);
        let skills_fs = LocalInstallFs::new(fixture.install_root.as_str());
        // A run that was interrupted after moving the first component leaves the
        // destination in place and no staging tree behind it.
        let placed = Path::new(&destination(&plan, 0)).to_path_buf();
        std::fs::create_dir_all(placed.parent().expect("destination parent"))
            .expect("destination directory");
        std::fs::write(&placed, GRAPHD).expect("placed graphd");
        stage_on_disk(&plan, 1, MCP);
        let applied = apply_ecosystem(
            &plan,
            &plan.plan_digest,
            &request(&plan),
            &LocalFs,
            &source,
            &skills_fs,
        )
        .expect("the resumed run completes");
        println!("resumed: {}", applied.text());
        assert_eq!(applied.status, STATUS_INSTALLED);
        assert_eq!(applied.components[0].status, STATUS_ALREADY_INSTALLED);
        assert_eq!(applied.components[1].status, STATUS_INSTALLED);
        assert_eq!(
            std::fs::read(&placed).expect("graphd bytes"),
            GRAPHD.to_vec()
        );
        assert!(!Path::new(&staged(&plan, 0)).exists());
        assert!(!Path::new(&staged(&plan, 1)).exists());
    }
}
