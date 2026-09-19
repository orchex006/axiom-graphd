//! The update and migration plan (task E-039).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 5 fixes what a plan must
//! contain: old and new versions, downloads, backup requirements, migrations,
//! disk headroom, service interruptions, host reconnect needs, bootstrap
//! changes and rollback limits; and it freezes the approval rule that a plan
//! changed after approval is refused as `approval_stale` rather than applied.
//!
//! The plan shape and the digest are *not* redefined here. `crate::plan` is the
//! one canonical encoder and digest for `contracts/schemas/update-plan.schema.json`
//! -- `axiom-specs/AGENTS.md` section 5 forbids a second copy of a normative
//! contract -- so this module only *assembles* a document and then runs that
//! module's own `structural_reasons` over the result. [`build_plan`] refuses to
//! return a document that fails those rules, which is why every plan this
//! module produces already has an exit code behind it.
//!
//! What this module adds on top of the contract is the AC1 rule: a major change
//! -- a queue schema migration, an irreversible migration, a major version step,
//! a bootstrap change or a host reconnect -- requires an explicit recorded
//! approval. [`require_approval`] names the kinds it found and refuses an
//! unapproved or stale plan with `plan_requires_approval` / `approval_stale`.
//! A plan with no major change needs no approval, so a no-op check stays cheap.
//!
//! Nothing here downloads, drains, migrates or writes outside the caller's
//! `Value`: it is the plan document, not the transaction (E-042..E-045).

use graph_core::error::{AxiomError, ErrorCode};
use serde_json::{json, Value};

use crate::plan;
use crate::update::resolve::ResolvedUpdate;

/// Baseline of an update plan document, from the frozen contract.
pub const UPDATE_PLAN_SCHEMA_VERSION: u64 = 1;

/// Approval state of a freshly built plan.
pub const APPROVAL_UNAPPROVED: &str = "unapproved";

/// Approval state after a human approval was recorded.
pub const APPROVAL_APPROVED: &str = "approved";

/// Every kind of change that requires an explicit approval, in report order.
pub const APPROVAL_REASONS: [&str; 5] = [
    "schema_migration",
    "irreversible_migration",
    "major_version",
    "bootstrap_change",
    "host_reconnect",
];

/// Where an update lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanTarget {
    /// Component being updated.
    pub component: String,
    /// Host the plan was resolved for.
    pub host: String,
    /// Install root the plan writes under.
    pub install_root: String,
}

/// One component row of a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanComponent {
    /// Component name.
    pub component: String,
    /// Installed version, or `None` for a fresh install.
    pub installed_version: Option<String>,
    /// Installed revision, or `None` when nothing is installed.
    pub installed_revision: Option<String>,
    /// Version the plan installs.
    pub target_version: String,
    /// Revision the plan installs.
    pub target_revision: String,
    /// Digest of the artifact the plan installs.
    pub artifact_sha256: String,
    /// One of `install`, `upgrade`, `reinstall`, `noop`.
    pub action: String,
}

impl PlanComponent {
    /// Build the plan row for one resolved update.
    ///
    /// The action and the installed version come from the resolver (E-038), so
    /// the plan can never describe an action the compatibility set did not
    /// choose.
    #[must_use]
    pub fn from_resolved(resolved: &ResolvedUpdate, installed_revision: Option<&str>) -> Self {
        Self {
            component: resolved.component.clone(),
            installed_version: resolved.installed_version.clone(),
            installed_revision: installed_revision.map(str::to_string),
            target_version: resolved.target_version.clone(),
            target_revision: resolved.target_revision.clone(),
            artifact_sha256: resolved.artifact_sha256.clone(),
            action: resolved.action.as_str().to_string(),
        }
    }
}

/// One artifact the plan downloads before it can apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanDownload {
    /// Artifact file name.
    pub artifact: String,
    /// `https://` location of the artifact.
    pub url: String,
    /// Digest the downloaded bytes must match.
    pub sha256: String,
    /// Expected size in bytes.
    pub size_bytes: u64,
}

/// One queue schema migration the plan will run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanMigration {
    /// Migration identifier.
    pub migration_id: String,
    /// Queue schema the migration starts from.
    pub from_queue_schema: u64,
    /// Queue schema the migration ends at.
    pub to_queue_schema: u64,
    /// Whether the migration can be undone in place.
    pub reversible: bool,
    /// Whether the migration requires a verified backup first.
    pub requires_backup: bool,
}

/// The backup requirement of a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanBackup {
    /// Whether an update requires a backup at all.
    pub required: bool,
    /// Relative paths the backup covers.
    pub targets: Vec<String>,
}

/// One service interruption the plan will take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanServiceInterruption {
    /// Service being interrupted.
    pub service: String,
    /// One of `stop`, `restart`, `none`.
    pub action: String,
    /// Bounded interruption, in seconds.
    pub max_seconds: u64,
}

/// Whether the host must reconnect after the update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanHostReconnect {
    /// Whether a reconnect is required.
    pub required: bool,
    /// Why, in the plan's own words.
    pub reason: String,
}

/// One bootstrap change the plan copies into a user repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanBootstrapChange {
    /// Repository the change lands in.
    pub repo_id: String,
    /// Template version being copied.
    pub template_version: String,
    /// Relative destinations inside that repository.
    pub destinations: Vec<String>,
}

/// What a rollback of this plan can and cannot do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanRollback {
    /// Whether rollback is supported at all.
    pub supported: bool,
    /// Whether it restores the previous versions.
    pub restores_previous_versions: bool,
    /// Limits a human must read before approving.
    pub limits: Vec<String>,
}

/// The trust view a plan was built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanTrust {
    /// Verified metadata version.
    pub metadata_version: u64,
    /// Expiry of the verified metadata.
    pub metadata_expiry: String,
    /// Pinned trust root fingerprint, or `None` when none resolved.
    pub trust_root: Option<String>,
    /// Whether the metadata carried a signature.
    pub signature_present: bool,
}

/// Every planner input, so the digest covers exactly what was reviewed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlanInput {
    /// Specification revision the planner used.
    pub spec_version: String,
    /// Plan identifier.
    pub plan_id: String,
    /// When the plan was produced.
    pub created_at: String,
    /// When the plan stops being applyable.
    pub expires_at: String,
    /// Release channel.
    pub channel: String,
    /// Where the update lands.
    pub target: PlanTarget,
    /// Component rows.
    pub components: Vec<PlanComponent>,
    /// Downloads the update needs.
    pub downloads: Vec<PlanDownload>,
    /// Migrations the update runs.
    pub migrations: Vec<PlanMigration>,
    /// Backup requirement.
    pub backup: PlanBackup,
    /// Free disk space the plan requires.
    pub disk_headroom_bytes: u64,
    /// Service interruptions the plan takes.
    pub service_interruptions: Vec<PlanServiceInterruption>,
    /// Host reconnect requirement.
    pub host_reconnect: PlanHostReconnect,
    /// Bootstrap changes the plan makes.
    pub bootstrap_changes: Vec<PlanBootstrapChange>,
    /// Rollback feasibility.
    pub rollback: PlanRollback,
    /// Trust view the plan was built from.
    pub trust: PlanTrust,
}

/// Assemble a plan document, seal its digest, and refuse it if it breaks the
/// frozen contract.
///
/// The returned document is unapproved, so an update that needs approval must
/// still pass through [`approve`] and [`require_approval`].
///
/// # Errors
///
/// Fails closed with `rule=invalid_plan` (and the contract reasons in
/// `observed`) when the assembled document breaks
/// `crate::plan::structural_reasons` -- an unresolved placeholder, a non-https
/// download, an irreversible migration without a backup, an unsigned trust
/// block, and so on. A planner can therefore never emit a plan the downstream
/// contract would reject.
pub fn build_plan(input: &UpdatePlanInput) -> Result<Value, AxiomError> {
    let mut value = json!({
        "schema_version": UPDATE_PLAN_SCHEMA_VERSION,
        "spec_version": input.spec_version,
        "plan_id": input.plan_id,
        "created_at": input.created_at,
        "expires_at": input.expires_at,
        "channel": input.channel,
        "target": {
            "component": input.target.component,
            "host": input.target.host,
            "install_root": input.target.install_root,
        },
        "components": input.components.iter().map(component_value).collect::<Vec<Value>>(),
        "downloads": input.downloads.iter().map(download_value).collect::<Vec<Value>>(),
        "migrations": input.migrations.iter().map(migration_value).collect::<Vec<Value>>(),
        "backup": {
            "required": input.backup.required,
            "targets": input.backup.targets,
        },
        "disk_headroom_bytes": input.disk_headroom_bytes,
        "service_interruptions": input
            .service_interruptions
            .iter()
            .map(interruption_value)
            .collect::<Vec<Value>>(),
        "host_reconnect": {
            "required": input.host_reconnect.required,
            "reason": input.host_reconnect.reason,
        },
        "bootstrap_changes": input
            .bootstrap_changes
            .iter()
            .map(bootstrap_value)
            .collect::<Vec<Value>>(),
        "rollback": {
            "supported": input.rollback.supported,
            "restores_previous_versions": input.rollback.restores_previous_versions,
            "limits": input.rollback.limits,
        },
        "trust": {
            "metadata_version": input.trust.metadata_version,
            "metadata_expiry": input.trust.metadata_expiry,
            "trust_root": input.trust.trust_root,
            "signature_present": input.trust.signature_present,
        },
        "approval": unapproved(),
    });
    plan::seal_digest(&mut value)?;
    let reasons = verification_reasons(&value);
    if !reasons.is_empty() {
        return Err(refuse("invalid_plan", &reasons.join(",")));
    }
    Ok(value)
}

/// Record a human approval of the plan's current body.
///
/// The approval names the digest of the body it was handed, so it can never be
/// attached to a plan it did not review.
///
/// # Errors
///
/// Fails closed with `rule=invalid_plan` when the plan body is unusable, or when
/// the plan is not an object.
pub fn approve(
    plan: &mut Value,
    approved_by: &str,
    approved_at: &str,
) -> Result<String, AxiomError> {
    let digest = plan::record_approval(plan, approved_by, approved_at)?;
    admit(plan)?;
    Ok(digest)
}

/// Kinds of major change this plan carries, in report order.
///
/// An empty list means the plan is a patch-level change with no schema step,
/// no bootstrap copy and no host reconnect, so it needs no explicit approval.
#[must_use]
pub fn approval_requirements(plan: &Value) -> Vec<String> {
    let Some(object) = plan.as_object() else {
        return vec!["plan_not_object".to_string()];
    };
    let mut reasons: Vec<String> = Vec::new();

    if let Some(rows) = object.get("migrations").and_then(Value::as_array) {
        let mut schema_step = false;
        let mut irreversible = false;
        for row in rows {
            let Some(row) = row.as_object() else { continue };
            let from = row.get("from_queue_schema").and_then(Value::as_u64);
            let to = row.get("to_queue_schema").and_then(Value::as_u64);
            if from != to {
                schema_step = true;
            }
            if row.get("reversible") == Some(&Value::Bool(false)) {
                irreversible = true;
            }
        }
        if schema_step {
            reasons.push("schema_migration".to_string());
        }
        if irreversible {
            reasons.push("irreversible_migration".to_string());
        }
    }

    if let Some(rows) = object.get("components").and_then(Value::as_array) {
        let major_step = rows.iter().any(|row| {
            let Some(row) = row.as_object() else {
                return false;
            };
            let installed = row.get("installed_version").and_then(Value::as_str);
            let target = row.get("target_version").and_then(Value::as_str);
            match (installed.and_then(major_of), target.and_then(major_of)) {
                (Some(installed), Some(target)) => target > installed,
                _ => false,
            }
        });
        if major_step {
            reasons.push("major_version".to_string());
        }
    }

    let bootstrap = object
        .get("bootstrap_changes")
        .and_then(Value::as_array)
        .is_some_and(|rows| !rows.is_empty());
    if bootstrap {
        reasons.push("bootstrap_change".to_string());
    }

    let reconnect = object
        .get("host_reconnect")
        .and_then(|value| value.get("required"))
        == Some(&Value::Bool(true));
    if reconnect {
        reasons.push("host_reconnect".to_string());
    }

    reasons
}

/// Refuse a plan that carries a major change without a current approval.
///
/// # Errors
///
/// Fails closed with `rule=plan_requires_approval` when the plan has a major
/// change and is not approved, and `rule=approval_stale` when it is approved but
/// the recorded digest is not the digest of the *current* body.
pub fn require_approval(plan: &Value) -> Result<(), AxiomError> {
    let requirements = approval_requirements(plan);
    if requirements.is_empty() {
        return Ok(());
    }
    let observed = requirements.join(",");
    let approval = plan.get("approval");
    let state = approval
        .and_then(|value| value.get("state"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if state != APPROVAL_APPROVED {
        return Err(refuse("plan_requires_approval", &observed));
    }
    let recorded = approval
        .and_then(|value| value.get("approved_digest"))
        .and_then(Value::as_str);
    let current = plan::plan_digest(plan).ok();
    if recorded.is_none() || recorded != current.as_deref() {
        return Err(refuse("approval_stale", &observed));
    }
    Ok(())
}

/// Every structural reason the frozen contract reports for this plan.
#[must_use]
pub fn verification_reasons(plan: &Value) -> Vec<String> {
    plan::structural_reasons(plan)
}

/// Every staleness reason for an approval recorded outside the plan.
#[must_use]
pub fn staleness_reasons(plan: &Value, approved_digest: &str) -> Vec<String> {
    plan::approval_reasons(plan, approved_digest)
}

/// The one admission check an update transaction runs on a plan document:
/// the body must satisfy the contract, and any major change must be approved.
///
/// # Errors
///
/// Fails closed with `rule=invalid_plan` for a contract violation, and with the
/// [`require_approval`] rules for an unapproved or stale plan.
pub fn admit(plan: &Value) -> Result<(), AxiomError> {
    let reasons = verification_reasons(plan);
    if !reasons.is_empty() {
        return Err(refuse("invalid_plan", &reasons.join(",")));
    }
    require_approval(plan)
}

/// The unapproved approval block a freshly built plan carries.
fn unapproved() -> Value {
    json!({
        "state": APPROVAL_UNAPPROVED,
        "approved_digest": Value::Null,
        "approved_by": Value::Null,
        "approved_at": Value::Null,
    })
}

/// The leading integer of a semantic version, or `None` when it has none.
fn major_of(version: &str) -> Option<u64> {
    version.split('.').next().and_then(|part| part.parse().ok())
}

/// One component row.
fn component_value(component: &PlanComponent) -> Value {
    json!({
        "component": component.component,
        "installed_version": component.installed_version,
        "installed_revision": component.installed_revision,
        "target_version": component.target_version,
        "target_revision": component.target_revision,
        "artifact_sha256": component.artifact_sha256,
        "action": component.action,
    })
}

/// One download row.
fn download_value(download: &PlanDownload) -> Value {
    json!({
        "artifact": download.artifact,
        "url": download.url,
        "sha256": download.sha256,
        "size_bytes": download.size_bytes,
    })
}

/// One migration row.
fn migration_value(migration: &PlanMigration) -> Value {
    json!({
        "migration_id": migration.migration_id,
        "from_queue_schema": migration.from_queue_schema,
        "to_queue_schema": migration.to_queue_schema,
        "reversible": migration.reversible,
        "requires_backup": migration.requires_backup,
    })
}

/// One service interruption row.
fn interruption_value(interruption: &PlanServiceInterruption) -> Value {
    json!({
        "service": interruption.service,
        "action": interruption.action,
        "max_seconds": interruption.max_seconds,
    })
}

/// One bootstrap change row.
fn bootstrap_value(change: &PlanBootstrapChange) -> Value {
    json!({
        "repo_id": change.repo_id,
        "template_version": change.template_version,
        "destinations": change.destinations,
    })
}

/// One plan refusal, with the rule in a stable detail key.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the plan cannot be applied as written",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use graph_core::error::AxiomError;

    use super::{
        approval_requirements, approve, build_plan, require_approval, staleness_reasons,
        verification_reasons, PlanBackup, PlanBootstrapChange, PlanComponent, PlanDownload,
        PlanHostReconnect, PlanMigration, PlanRollback, PlanServiceInterruption, PlanTarget,
        PlanTrust, UpdatePlanInput, APPROVAL_REASONS,
    };
    use crate::update::resolve::{ResolvedAction, ResolvedUpdate};
    use crate::version::SPEC_VERSION;

    fn rule_of(error: &AxiomError) -> String {
        error.details().get("rule").cloned().unwrap_or_default()
    }

    fn observed_of(error: &AxiomError) -> String {
        error.details().get("observed").cloned().unwrap_or_default()
    }

    fn fixture() -> UpdatePlanInput {
        UpdatePlanInput {
            spec_version: SPEC_VERSION.to_string(),
            plan_id: "update-2026-09-19-graphd-0-2-0".to_string(),
            created_at: "2026-09-19T02:00:00Z".to_string(),
            expires_at: "2026-09-20T02:00:00Z".to_string(),
            channel: "stable".to_string(),
            target: PlanTarget {
                component: "axiom-graphd".to_string(),
                host: "windows-x64".to_string(),
                install_root: "/home/demo/.axiom/components/axiom-graphd/0.2.0".to_string(),
            },
            components: vec![PlanComponent {
                component: "axiom-graphd".to_string(),
                installed_version: Some("0.1.0".to_string()),
                installed_revision: Some("1".repeat(40)),
                target_version: "0.2.0".to_string(),
                target_revision: "2".repeat(40),
                artifact_sha256: "3".repeat(64),
                action: "upgrade".to_string(),
            }],
            downloads: vec![PlanDownload {
                artifact: "axiom-graphd-0.2.0-windows-x64.zip".to_string(),
                url: "https://github.com/orchex006/axiom-graphd/releases/download/v0.2.0/axiom-graphd-0.2.0-windows-x64.zip".to_string(),
                sha256: "3".repeat(64),
                size_bytes: 41_943_040,
            }],
            migrations: vec![PlanMigration {
                migration_id: "queue-schema-1-to-2".to_string(),
                from_queue_schema: 1,
                to_queue_schema: 2,
                reversible: false,
                requires_backup: true,
            }],
            backup: PlanBackup {
                required: true,
                targets: vec![".axiom/state/queue.db".to_string()],
            },
            disk_headroom_bytes: 268_435_456,
            service_interruptions: vec![PlanServiceInterruption {
                service: "axiom-graphd".to_string(),
                action: "restart".to_string(),
                max_seconds: 30,
            }],
            host_reconnect: PlanHostReconnect {
                required: true,
                reason: "the shared core version changes".to_string(),
            },
            bootstrap_changes: vec![PlanBootstrapChange {
                repo_id: "auth-api".to_string(),
                template_version: "0.2.0".to_string(),
                destinations: vec!["AGENTS.md".to_string()],
            }],
            rollback: PlanRollback {
                supported: true,
                restores_previous_versions: true,
                limits: vec!["a queue schema migration is not reversible in place".to_string()],
            },
            trust: PlanTrust {
                metadata_version: 7,
                metadata_expiry: "2026-09-25T02:00:00Z".to_string(),
                trust_root: Some("5".repeat(64)),
                signature_present: true,
            },
        }
    }

    fn noop_fixture() -> UpdatePlanInput {
        let mut input = fixture();
        input.components = vec![PlanComponent {
            component: "axiom-graphd".to_string(),
            installed_version: Some("0.2.0".to_string()),
            installed_revision: Some("1".repeat(40)),
            target_version: "0.2.0".to_string(),
            target_revision: "1".repeat(40),
            artifact_sha256: "3".repeat(64),
            action: "noop".to_string(),
        }];
        input.downloads = Vec::new();
        input.migrations = Vec::new();
        input.bootstrap_changes = Vec::new();
        input.backup = PlanBackup {
            required: false,
            targets: Vec::new(),
        };
        input.host_reconnect = PlanHostReconnect {
            required: false,
            reason: "no host config changes".to_string(),
        };
        input.rollback = PlanRollback {
            supported: true,
            restores_previous_versions: false,
            limits: Vec::new(),
        };
        input
    }

    #[test]
    fn a_built_plan_passes_the_frozen_contract_and_is_unapproved() {
        let value = build_plan(&fixture()).expect("builds");
        assert_eq!(verification_reasons(&value), Vec::<String>::new());
        assert_eq!(value["schema_version"], json!(1));
        assert_eq!(value["approval"]["state"], json!("unapproved"));
        assert_eq!(value["approval"]["approved_digest"], Value::Null);
        let digest = value["plan_digest"].as_str().expect("digest");
        assert_eq!(digest.len(), 64);
        // Building twice is the same digest: the encoder is canonical.
        let again = build_plan(&fixture()).expect("builds");
        assert_eq!(again["plan_digest"], value["plan_digest"]);
    }

    #[test]
    fn a_major_change_requires_an_explicit_approval() {
        let value = build_plan(&fixture()).expect("builds");
        assert_eq!(
            approval_requirements(&value),
            vec![
                "schema_migration",
                "irreversible_migration",
                "bootstrap_change",
                "host_reconnect"
            ]
        );
        let error = require_approval(&value).expect_err("unapproved");
        assert_eq!(rule_of(&error), "plan_requires_approval");
        assert!(observed_of(&error).contains("schema_migration"));
        // Every reported kind is part of the frozen vocabulary.
        for reason in approval_requirements(&value) {
            assert!(APPROVAL_REASONS.contains(&reason.as_str()), "{reason}");
        }

        let mut approved = value;
        let digest = approve(
            &mut approved,
            "maintainer@example.invalid",
            "2026-09-19T02:05:00Z",
        )
        .expect("approves");
        assert_eq!(approved["approval"]["state"], json!("approved"));
        assert_eq!(
            approved["approval"]["approved_digest"].as_str(),
            Some(digest.as_str())
        );
        assert_eq!(verification_reasons(&approved), Vec::<String>::new());
        require_approval(&approved).expect("approved");
    }

    #[test]
    fn an_approval_does_not_survive_a_changed_body() {
        let mut value = build_plan(&fixture()).expect("builds");
        let digest = approve(
            &mut value,
            "maintainer@example.invalid",
            "2026-09-19T02:05:00Z",
        )
        .expect("approves");
        // Change one planner input without re-approving.
        value["target"]["install_root"] = json!("/home/demo/.axiom/components/axiom-graphd/0.3.0");
        assert!(verification_reasons(&value).contains(&"plan_digest_mismatch".to_string()));
        assert!(staleness_reasons(&value, &digest).contains(&"approval_stale".to_string()));
        let error = require_approval(&value).expect_err("stale");
        assert_eq!(rule_of(&error), "approval_stale");
    }

    #[test]
    fn a_plan_with_no_major_change_needs_no_approval() {
        let value = build_plan(&noop_fixture()).expect("builds");
        assert_eq!(approval_requirements(&value), Vec::<String>::new());
        require_approval(&value).expect("no approval needed");
        assert_eq!(verification_reasons(&value), Vec::<String>::new());
    }

    #[test]
    fn build_refuses_a_plan_that_breaks_the_contract() {
        let mut plain_http = fixture();
        plain_http.downloads[0].url = "http://example.invalid/artifact.zip".to_string();
        let error = build_plan(&plain_http).expect_err("refused");
        assert_eq!(rule_of(&error), "invalid_plan");
        assert!(observed_of(&error).contains("download_url_not_https"));

        let mut no_backup = fixture();
        no_backup.migrations[0].requires_backup = false;
        no_backup.backup.required = false;
        let error = build_plan(&no_backup).expect_err("refused");
        assert!(observed_of(&error).contains("irreversible_migration_without_backup"));

        let mut placeholder = fixture();
        placeholder.target.install_root = "REPLACE_ME".to_string();
        let error = build_plan(&placeholder).expect_err("refused");
        assert!(observed_of(&error).contains("unresolved_placeholder"));
    }

    #[test]
    fn an_unsigned_or_unrooted_plan_is_refused() {
        let mut unsigned = fixture();
        unsigned.trust.signature_present = false;
        let error = build_plan(&unsigned).expect_err("refused");
        assert!(observed_of(&error).contains("unsigned_plan"));

        let mut unrooted = fixture();
        unrooted.trust.trust_root = None;
        let error = build_plan(&unrooted).expect_err("refused");
        assert!(observed_of(&error).contains("unresolved_trust_root"));
    }

    #[test]
    fn a_resolved_update_becomes_the_component_row() {
        let upgrade = ResolvedUpdate {
            component: "axiom-graphd".to_string(),
            installed_version: Some("0.1.0".to_string()),
            target_version: "0.2.0".to_string(),
            target_revision: "2".repeat(40),
            artifact_sha256: "3".repeat(64),
            action: ResolvedAction::Upgrade,
            compatible_candidates: 1,
            rejected: Vec::new(),
        };
        let revision = "1".repeat(40);
        let row = PlanComponent::from_resolved(&upgrade, Some(revision.as_str()));
        assert_eq!(row.action, "upgrade");
        assert_eq!(row.installed_version.as_deref(), Some("0.1.0"));

        let install = ResolvedUpdate {
            component: "axiom-mcp".to_string(),
            installed_version: None,
            target_version: "0.2.0".to_string(),
            target_revision: "2".repeat(40),
            artifact_sha256: "3".repeat(64),
            action: ResolvedAction::Install,
            compatible_candidates: 1,
            rejected: Vec::new(),
        };
        let row = PlanComponent::from_resolved(&install, None);
        assert_eq!(row.action, "install");
        assert_eq!(row.installed_version, None);
        assert_eq!(row.installed_revision, None);
    }
}
