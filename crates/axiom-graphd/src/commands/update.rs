//! `update check` and the delegated `update apply` (task B-092).
//!
//! `docs/16-CLI-AND-CONTROL-API.md` section 7 requires approval to bind to the
//! exact canonical plan digest, and `docs/20-VERSION-CHECK-UPDATE-RELEASE.md`
//! requires the trusted `axiom` CLI from the same core release to perform the
//! install. `docs/23-SECURITY-AND-TRUST.md` adds that `axiom-graphd` must not
//! expose install/update as an arbitrary shell.
//!
//! Three rules make that concrete:
//!
//! * **Delegation is argv, never a shell string.** [`Delegation`] carries a
//!   program name and an argument vector; there is no API that concatenates a
//!   command line, a metacharacter in an argument is refused outright
//!   ([`REASON_SHELL_METACHAR`]), and the program is always the sibling `axiom`
//!   executable ([`AXIOM_PROGRAM`]).
//! * **Trust fails closed.** An unconfigured trust root refuses every delegation
//!   ([`REASON_TRUST_NOT_CONFIGURED`]) rather than falling back to an implicit
//!   key or to a prompt.
//! * **Approval binds to the digest.** Supplying `--plan` is not approval; the
//!   caller must supply `--approve-digest` equal to the plan's canonical digest.

use std::collections::BTreeSet;

use graph_core::error::{AxiomError, ErrorCode};
use serde::Serialize;

/// The sibling installation CLI that performs an approved apply.
pub const AXIOM_PROGRAM: &str = "axiom";
/// Reason recorded when no trusted key is configured.
pub const REASON_TRUST_NOT_CONFIGURED: &str = "trust-not-configured";
/// Reason recorded when approval was not supplied.
pub const REASON_APPROVAL_MISSING: &str = "approval-missing";
/// Reason recorded when the approval digest does not match the plan.
pub const REASON_APPROVAL_DIGEST_MISMATCH: &str = "approval-digest-mismatch";
/// Reason recorded when a plan digest is not a SHA-256 hex digest.
pub const REASON_PLAN_DIGEST_INVALID: &str = "plan-digest-invalid";
/// Reason recorded when a component is not in the trusted allowlist.
pub const REASON_COMPONENT_NOT_ALLOWED: &str = "component-not-allowed";
/// Reason recorded when an argument carries a shell metacharacter.
pub const REASON_SHELL_METACHAR: &str = "shell-metachar";
/// Reason recorded when a plan path is empty or not portable.
pub const REASON_PLAN_PATH_INVALID: &str = "plan-path-invalid";

/// Characters that would change meaning if an argument were ever joined into a
/// command line. They are refused so the argv contract cannot silently become a
/// shell contract.
const SHELL_METACHARACTERS: [char; 12] = [
    ';', '|', '&', '>', '<', '`', '$', '\n', '\r', '"', '\'', '\\',
];

/// A configured release trust root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustRoot {
    /// Hex-encoded public key of the pinned release trust root.
    public_key_hex: String,
    /// Components this trust root permits an update to install.
    allowed_components: BTreeSet<String>,
}

impl TrustRoot {
    /// Build a trust root.
    #[must_use]
    pub fn new(
        public_key_hex: impl Into<String>,
        allowed_components: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            public_key_hex: public_key_hex.into(),
            allowed_components: allowed_components.into_iter().collect(),
        }
    }

    /// The pinned public key.
    #[must_use]
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// Components the trust root permits.
    #[must_use]
    pub fn allowed_components(&self) -> &BTreeSet<String> {
        &self.allowed_components
    }

    /// Whether the trust root is usable.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        !self.public_key_hex.is_empty() && !self.allowed_components.is_empty()
    }
}

/// The trust configuration of this installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateTrust {
    /// A pinned trust root.
    Configured(TrustRoot),
    /// No trust root has been configured; every delegation fails closed.
    Unconfigured,
}

impl UpdateTrust {
    /// The trust root, if any.
    #[must_use]
    pub fn root(&self) -> Option<&TrustRoot> {
        match self {
            Self::Configured(root) => Some(root),
            Self::Unconfigured => None,
        }
    }
}

/// An approved update plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpdatePlan {
    /// Repository-relative path of the plan file.
    pub plan_path: String,
    /// The component the plan installs.
    pub component: String,
    /// Target version.
    pub target_version: String,
    /// SHA-256 of the canonical plan document.
    pub canonical_digest: String,
}

impl UpdatePlan {
    /// Build a plan record.
    #[must_use]
    pub fn new(
        plan_path: impl Into<String>,
        component: impl Into<String>,
        target_version: impl Into<String>,
        canonical_digest: impl Into<String>,
    ) -> Self {
        Self {
            plan_path: plan_path.into(),
            component: component.into(),
            target_version: target_version.into(),
            canonical_digest: canonical_digest.into(),
        }
    }
}

/// The `update check` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionCheck {
    /// Installed version.
    pub current_version: String,
    /// Highest version the channel offers.
    pub latest_version: String,
    /// Whether an update is available.
    pub update_available: bool,
    /// The channel that was consulted.
    pub channel: String,
}

/// Compare an installed version with what a channel offers.
#[must_use]
pub fn check(current_version: &str, latest_version: &str, channel: &str) -> VersionCheck {
    VersionCheck {
        current_version: current_version.to_owned(),
        latest_version: latest_version.to_owned(),
        update_available: current_version != latest_version,
        channel: channel.to_owned(),
    }
}

/// A delegation to the sibling `axiom` CLI, expressed as argv.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Delegation {
    /// Always [`AXIOM_PROGRAM`].
    pub program: String,
    /// The argument vector, in order.
    pub args: Vec<String>,
}
impl Delegation {
    /// The program to execute and its argument vector.
    #[must_use]
    pub fn program_and_args(&self) -> (&str, &[String]) {
        (&self.program, &self.args)
    }

    /// Whether any argument would change meaning in a shell.
    ///
    /// This is always false for a delegation this module built; the assertion
    /// exists so a caller cannot assemble one that is not.
    #[must_use]
    pub fn contains_shell_metacharacters(&self) -> bool {
        self.program
            .chars()
            .chain(self.args.iter().flat_map(|arg| arg.chars()))
            .any(|character| SHELL_METACHARACTERS.contains(&character))
    }
}

/// Build the argv delegation for an approved apply.
///
/// # Errors
/// - [`ErrorCode::ConfigInvalid`] with [`REASON_TRUST_NOT_CONFIGURED`] when
///   trust is unconfigured, and when the trust root is not usable.
/// - [`ErrorCode::ValidationError`] with [`REASON_PLAN_PATH_INVALID`],
///   [`REASON_PLAN_DIGEST_INVALID`] or [`REASON_SHELL_METACHAR`].
/// - [`ErrorCode::Forbidden`] with [`REASON_COMPONENT_NOT_ALLOWED`].
/// - [`ErrorCode::ValidationError`] with [`REASON_APPROVAL_MISSING`], and
///   [`ErrorCode::Conflict`] with [`REASON_APPROVAL_DIGEST_MISMATCH`].
pub fn delegate(
    plan: &UpdatePlan,
    trust: &UpdateTrust,
    approve_digest: Option<&str>,
) -> Result<Delegation, AxiomError> {
    let Some(root) = trust.root() else {
        return Err(AxiomError::new(
            ErrorCode::ConfigInvalid,
            "no release trust root is configured; refusing to delegate an update",
        )
        .with_detail("rule", REASON_TRUST_NOT_CONFIGURED));
    };
    if !root.is_usable() {
        return Err(AxiomError::new(
            ErrorCode::ConfigInvalid,
            "the configured release trust root is not usable",
        )
        .with_detail("rule", REASON_TRUST_NOT_CONFIGURED));
    }
    if !root.allowed_components().contains(&plan.component) {
        return Err(AxiomError::new(
            ErrorCode::Forbidden,
            "the trusted root does not allow updating this component",
        )
        .with_detail("rule", REASON_COMPONENT_NOT_ALLOWED)
        .with_detail("component", plan.component.clone()));
    }
    if plan.plan_path.is_empty() {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "an update apply requires a plan path",
        )
        .with_detail("rule", REASON_PLAN_PATH_INVALID));
    }
    if plan
        .plan_path
        .chars()
        .any(|c| SHELL_METACHARACTERS.contains(&c))
    {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "an update argument must not carry a shell metacharacter",
        )
        .with_detail("rule", REASON_SHELL_METACHAR)
        .with_detail("argument", "plan_path"));
    }
    if plan.canonical_digest.len() != 64
        || !plan.canonical_digest.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "the plan canonical digest must be a SHA-256 hex digest",
        )
        .with_detail("rule", REASON_PLAN_DIGEST_INVALID)
        .with_detail("component", plan.component.clone()));
    }
    let Some(approved) = approve_digest else {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "supplying a plan is not approval; an explicit approval digest is required",
        )
        .with_detail("rule", REASON_APPROVAL_MISSING)
        .with_detail("component", plan.component.clone()));
    };
    if approved != plan.canonical_digest {
        return Err(AxiomError::new(
            ErrorCode::Conflict,
            "the approval digest does not match this plan",
        )
        .with_detail("rule", REASON_APPROVAL_DIGEST_MISMATCH)
        .with_detail("component", plan.component.clone()));
    }
    // argv only: the plan path and digest are separate elements and are never
    // joined into a command line.
    let args = vec![
        "update".to_owned(),
        "apply".to_owned(),
        "--plan".to_owned(),
        plan.plan_path.clone(),
        "--approve-digest".to_owned(),
        plan.canonical_digest.clone(),
    ];
    Ok(Delegation {
        program: AXIOM_PROGRAM.to_owned(),
        args,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: &str) -> String {
        graph_export::sha256_hex(seed.as_bytes())
    }

    fn trust() -> UpdateTrust {
        UpdateTrust::Configured(TrustRoot::new(
            "9f2c4a1b",
            ["axiom-graphd".to_owned(), "axiom-mcp".to_owned()],
        ))
    }

    fn plan() -> UpdatePlan {
        UpdatePlan::new(
            "plan.json",
            "axiom-graphd",
            "1.4.0",
            digest("canonical-plan"),
        )
    }

    #[test]
    fn an_approved_plan_delegates_to_axiom_as_argv_without_a_shell_string() {
        let plan = plan();
        let delegation =
            delegate(&plan, &trust(), Some(plan.canonical_digest.as_str())).expect("delegate");
        let (program, args) = delegation.program_and_args();
        assert_eq!(program, AXIOM_PROGRAM);
        assert_eq!(
            args,
            vec![
                "update".to_owned(),
                "apply".to_owned(),
                "--plan".to_owned(),
                "plan.json".to_owned(),
                "--approve-digest".to_owned(),
                plan.canonical_digest.clone(),
            ]
        );
        // The path and digest are separate argv elements, never concatenated.
        assert!(!args.iter().any(|arg| arg.contains("--approve-digest=")));
        assert!(!delegation.contains_shell_metacharacters());
    }

    #[test]
    fn an_unconfigured_trust_root_fails_closed() {
        let plan = plan();
        let error = delegate(
            &plan,
            &UpdateTrust::Unconfigured,
            Some(&plan.canonical_digest),
        )
        .expect_err("unconfigured trust");
        assert_eq!(error.code(), ErrorCode::ConfigInvalid);
        assert_eq!(error.exit_code().as_i32(), 2);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_TRUST_NOT_CONFIGURED)
        );
        // A trust root with no key is equally refusing, not implicitly trusted.
        let empty = UpdateTrust::Configured(TrustRoot::new("", Vec::new()));
        let error = delegate(&plan, &empty, Some(&plan.canonical_digest)).expect_err("empty root");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_TRUST_NOT_CONFIGURED)
        );
    }

    #[test]
    fn approval_must_bind_to_the_exact_plan_digest() {
        let plan = plan();
        let error = delegate(&plan, &trust(), None).expect_err("no approval");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_APPROVAL_MISSING)
        );
        let error = delegate(&plan, &trust(), Some(&digest("a different plan")))
            .expect_err("mismatched approval");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(error.exit_code().as_i32(), 6);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_APPROVAL_DIGEST_MISMATCH)
        );
        // A malformed digest in the plan itself is refused before approval.
        let malformed = UpdatePlan::new("plan.json", "axiom-graphd", "1.4.0", "not-a-digest");
        let error = delegate(&malformed, &trust(), Some("not-a-digest")).expect_err("digest");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_PLAN_DIGEST_INVALID)
        );
    }

    #[test]
    fn an_untrusted_component_or_a_shell_metacharacter_is_refused() {
        let other = UpdatePlan::new("plan.json", "axiom-skills", "1.0.0", digest("plan"));
        let error =
            delegate(&other, &trust(), Some(&other.canonical_digest)).expect_err("component");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_COMPONENT_NOT_ALLOWED)
        );
        // Even though the delegation is argv, an argument that would change
        // meaning in a shell is refused rather than passed through.
        let injected = UpdatePlan::new(
            "plan.json; rm -rf /",
            "axiom-graphd",
            "1.4.0",
            digest("plan"),
        );
        let error = delegate(&injected, &trust(), Some(&injected.canonical_digest))
            .expect_err("metacharacter");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_SHELL_METACHAR)
        );
        let empty = UpdatePlan::new("", "axiom-graphd", "1.4.0", digest("plan"));
        let error = delegate(&empty, &trust(), Some(&empty.canonical_digest)).expect_err("empty");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_PLAN_PATH_INVALID)
        );
    }

    #[test]
    fn check_reports_availability_without_contacting_a_release() {
        let available = check("1.3.0", "1.4.0", "stable");
        assert!(available.update_available);
        assert_eq!(available.current_version, "1.3.0");
        assert_eq!(available.latest_version, "1.4.0");
        let current = check("1.4.0", "1.4.0", "stable");
        assert!(!current.update_available);
        let root = trust();
        assert!(root.root().is_some_and(TrustRoot::is_usable));
        assert!(root.root().expect("root").public_key_hex() == "9f2c4a1b");
        assert_eq!(UpdateTrust::Unconfigured.root(), None);
    }
}
