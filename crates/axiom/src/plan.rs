//! Canonical update-plan bytes and the approval binding (task E-002).
//!
//! `axiom-specs` freezes one plan contract twice, and both halves must agree:
//! `contracts/schemas/update-plan.schema.json` constrains the shape of one plan,
//! and `tools/update_plan_contract.py` evaluates the cross-record rules a schema
//! cannot express. This module is the Rust half of that contract, so the
//! installer's plans and the specification oracle cannot drift apart.
//!
//! One rule makes a plan safe to approve, and it is why this module exists
//! (G-009 AC1): the plan digest is a deterministic function of the plan body
//! **excluding** `plan_digest` and `approval`, so
//!
//! * approval metadata can never invalidate itself, while
//! * a changed component version, artifact hash, migration set, backup plan,
//!   host, channel or expiry changes the digest, and an approval recorded
//!   against the old digest is reported `approval_stale` instead of being
//!   silently reused.
//!
//! The digest covers every planner input because the target (`install_root`,
//! component, host) and the announced operations (`action`, `migrations`,
//! `service_interruptions`, `bootstrap_changes`) all live in the digested body.
//! Editing any one of them moves the digest.
//!
//! Canonical bytes are not redefined here. [`graph_export::canonical`] owns the
//! one canonical form in this workspace - compact JSON, keys sorted by code
//! point, UTF-8 - and this module appends only the trailing newline the plan
//! digest is defined over. A second canonical encoder would be a second digest
//! contract, which `AGENTS.md` section 5 forbids.
//!
//! Nothing here touches the network, Git, the shell or the filesystem except
//! [`evaluate_plan_file`], which only reads one local file. The module is
//! deliberately pure so the same verdict is produced in tests, in the CLI and
//! in the differential harness `crates/axiom/examples/plan_verify.rs`.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use graph_core::error::{AxiomError, ErrorCode};

/// `schema_version` this build accepts, matching the frozen plan schema.
pub const PLAN_SCHEMA_VERSION: u64 = 1;

/// Components a plan may target or interrupt, in schema order.
pub const COMPONENTS: [&str; 4] = ["axiom-graphd", "axiom-mcp", "axiom", "skills"];

/// Host identifiers a plan may declare, in schema order.
pub const HOSTS: [&str; 4] = ["windows-x64", "linux-x64", "macos-arm64", "macos-x64"];

/// Release channels a plan may name, in schema order.
pub const CHANNELS: [&str; 2] = ["stable", "prerelease"];

/// Component actions a plan may announce, in schema order.
pub const ACTIONS: [&str; 4] = ["install", "upgrade", "reinstall", "noop"];

/// Service interruption actions a plan may announce, in schema order.
pub const INTERRUPTION_ACTIONS: [&str; 3] = ["stop", "restart", "none"];

/// Approval states a plan may carry, in schema order.
pub const APPROVAL_STATES: [&str; 2] = ["unapproved", "approved"];

/// Top-level keys the digest excludes, so approval metadata cannot invalidate
/// itself.
pub const DIGEST_EXCLUDED: [&str; 2] = ["plan_digest", "approval"];

/// Every accepted top-level plan key, in the order the contract reports them.
pub const PLAN_REQUIRED: [&str; 19] = [
    "schema_version",
    "spec_version",
    "plan_id",
    "created_at",
    "expires_at",
    "channel",
    "target",
    "components",
    "downloads",
    "migrations",
    "backup",
    "disk_headroom_bytes",
    "service_interruptions",
    "host_reconnect",
    "bootstrap_changes",
    "rollback",
    "trust",
    "approval",
    "plan_digest",
];

/// Every accepted top-level document key, in schema order.
pub const DOCUMENT_KEYS: [&str; 2] = ["plan", "approved_digest"];

/// Canonical digest input: the plan body without `plan_digest` or `approval`.
///
/// Compact JSON, keys sorted by code point, UTF-8, and exactly one trailing
/// newline; this is the byte form
/// `tools/update_plan_contract.py::canonical_plan_bytes` produces.
///
/// # Errors
///
/// Fails closed when `plan` is not a JSON object or the body cannot be encoded,
/// because a digest that is defined only sometimes is not a contract.
pub fn canonical_plan_bytes(plan: &Value) -> Result<Vec<u8>, AxiomError> {
    let body = digested_body(plan)?;
    let text = graph_export::canonical::canonical_value(&Value::Object(body)).map_err(|error| {
        AxiomError::new(
            ErrorCode::Internal,
            "the plan body cannot be encoded canonically",
        )
        .with_detail("observed", error.to_string())
    })?;
    let mut bytes = text.into_bytes();
    bytes.push(b'\n');
    Ok(bytes)
}

/// Lowercase 64-hex digest of [`canonical_plan_bytes`].
///
/// # Errors
///
/// Propagates the [`canonical_plan_bytes`] failure for a non-object plan.
pub fn plan_digest(plan: &Value) -> Result<String, AxiomError> {
    Ok(graph_export::sha256_hex(&canonical_plan_bytes(plan)?))
}

/// The digested body: a copy of `plan` without the self-referential keys.
fn digested_body(plan: &Value) -> Result<Map<String, Value>, AxiomError> {
    let mut body = match plan {
        Value::Object(object) => object.clone(),
        other => {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a plan digest is defined only over a plan object",
            )
            .with_detail("observed", scalar_kind(other)));
        }
    };
    for key in DIGEST_EXCLUDED {
        body.remove(key);
    }
    Ok(body)
}

/// Store the digest of the plan body in `plan_digest`.
///
/// Sealing is idempotent: `plan_digest` is excluded from its own digest, so a
/// planner can seal, attach approval metadata and seal again without the digest
/// moving. The approval state is left untouched.
///
/// # Errors
///
/// Fails when `plan` is not an object.
pub fn seal_digest(plan: &mut Value) -> Result<String, AxiomError> {
    let digest = plan_digest(plan)?;
    let object = plan_object_mut(plan)?;
    object.insert("plan_digest".to_string(), Value::String(digest.clone()));
    Ok(digest)
}

/// Record an approval of the current plan body and return the approved digest.
///
/// The caller owns the decision to approve. This function guarantees only that
/// the recorded approval names the digest of the body it was handed, so an
/// approval can never be attached to a plan it did not review.
///
/// # Errors
///
/// Fails when `plan` is not an object.
pub fn record_approval(
    plan: &mut Value,
    approved_by: &str,
    approved_at: &str,
) -> Result<String, AxiomError> {
    let digest = seal_digest(plan)?;
    let mut approval = Map::new();
    approval.insert("state".to_string(), Value::String("approved".to_string()));
    approval.insert("approved_digest".to_string(), Value::String(digest.clone()));
    approval.insert(
        "approved_by".to_string(),
        Value::String(approved_by.to_string()),
    );
    approval.insert(
        "approved_at".to_string(),
        Value::String(approved_at.to_string()),
    );
    let object = plan_object_mut(plan)?;
    object.insert("approval".to_string(), Value::Object(approval));
    Ok(digest)
}

/// Mutable plan object, or the fail-closed error naming what was observed.
fn plan_object_mut(plan: &mut Value) -> Result<&mut Map<String, Value>, AxiomError> {
    match plan {
        Value::Object(object) => Ok(object),
        other => Err(AxiomError::new(
            ErrorCode::ValidationError,
            "the plan approval binding is defined only over a plan object",
        )
        .with_detail("observed", scalar_kind(other))),
    }
}

/// Named staleness reasons for an approval recorded outside the plan.
///
/// This is the AC1 boundary: an approval names one digest, and the digest covers
/// every planner input, so re-using an old approval for a changed plan is
/// reported as `approval_stale` (and `plan_digest_not_approved` when the plan
/// body no longer carries the approved digest either).
#[must_use]
pub fn approval_reasons(plan: &Value, approved_digest: &str) -> Vec<String> {
    if !plan.is_object() {
        return vec!["plan_not_object".to_string()];
    }
    if !is_digest(approved_digest) {
        return vec!["approved_digest_not_a_digest".to_string()];
    }
    let mut reasons = Vec::new();
    if plan_digest(plan).map_or(true, |digest| digest != approved_digest) {
        reasons.push("approval_stale".to_string());
    }
    if plan.get("plan_digest").and_then(Value::as_str) != Some(approved_digest) {
        reasons.push("plan_digest_not_approved".to_string());
    }
    reasons
}

/// One plan-contract verdict, the shape `update_plan_contract.evaluate` returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verdict {
    /// True when no structural and no approval reason was found.
    pub ok: bool,
    /// Structural reasons followed by approval reasons.
    pub reasons: Vec<String>,
    /// Plan-shape and plan-rule violations.
    pub structural_reasons: Vec<String>,
    /// Approval-binding violations.
    pub approval_reasons: Vec<String>,
    /// Digest of the plan body, when the document carries a plan object.
    pub plan_digest: Option<String>,
}

impl Verdict {
    /// One JSON object, field order matching the specification oracle.
    ///
    /// # Errors
    ///
    /// Fails only if the verdict cannot be serialised, which is an Axiom defect.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        serde_json::to_string(self).map_err(|error| {
            AxiomError::new(ErrorCode::Internal, "the plan verdict is not serialisable")
                .with_detail("observed", error.to_string())
        })
    }

    /// One human-readable summary line.
    #[must_use]
    pub fn text_line(&self) -> String {
        if self.ok {
            format!(
                "accepted plan_digest={}",
                self.plan_digest.as_deref().unwrap_or("none")
            )
        } else {
            format!(
                "rejected {} reason(s): {}",
                self.reasons.len(),
                self.reasons.join(", ")
            )
        }
    }
}

/// Evaluate one document: `{"plan": {...}, "approved_digest": "<hex>" (optional)}`.
#[must_use]
pub fn evaluate(document: &Value) -> Verdict {
    let object = match document {
        Value::Object(object) => object,
        _ => {
            return Verdict {
                ok: false,
                reasons: vec!["document_not_object".to_string()],
                structural_reasons: vec!["document_not_object".to_string()],
                approval_reasons: Vec::new(),
                plan_digest: None,
            };
        }
    };
    let mut leading: Vec<String> = Vec::new();
    for key in object.keys() {
        if !DOCUMENT_KEYS.contains(&key.as_str()) {
            leading.push(format!("undeclared_document_field:{key}"));
        }
    }
    let plan = match object.get("plan") {
        Some(plan) => plan,
        None => {
            let mut reasons = leading;
            reasons.push("missing_required_field:plan".to_string());
            return Verdict {
                ok: false,
                reasons,
                structural_reasons: vec!["missing_required_field:plan".to_string()],
                approval_reasons: Vec::new(),
                plan_digest: None,
            };
        }
    };
    let mut structural = leading;
    structural.extend(structural_reasons(plan));
    let approval = match object.get("approved_digest") {
        Some(value) => approval_reasons(plan, value.as_str().unwrap_or_default()),
        None => Vec::new(),
    };
    let digest = plan.as_object().and_then(|_| plan_digest(plan).ok());
    let mut reasons = structural.clone();
    reasons.extend(approval.iter().cloned());
    Verdict {
        ok: reasons.is_empty(),
        reasons,
        structural_reasons: structural,
        approval_reasons: approval,
        plan_digest: digest,
    }
}

/// Read and evaluate one local plan document.
///
/// # Errors
///
/// Fails with `INTERNAL` when the file cannot be read and `VALIDATION_ERROR`
/// when its contents are not JSON. No network or Git operation is performed.
pub fn evaluate_plan_file(path: &Path) -> Result<Verdict, AxiomError> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        AxiomError::new(ErrorCode::Internal, "the plan document cannot be read")
            .with_detail("observed", format!("{}: {error}", path.display()))
    })?;
    let document: Value = serde_json::from_str(&text).map_err(|error| {
        AxiomError::new(
            ErrorCode::ValidationError,
            "the plan document is not valid JSON",
        )
        .with_detail("observed", format!("{}: {error}", path.display()))
    })?;
    Ok(evaluate(&document))
}
/// Named rejection reasons for one plan body. An empty list means accepted.
///
/// The reason strings, and the order they are reported in, are the contract
/// `tools/update_plan_contract.py::structural_reasons` defines; the fixture
/// corpus under `axiom-specs/tests/fixtures/update-plan-contract/` pins each
/// one, and the differential harness replays all of them.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn structural_reasons(plan: &Value) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    let object = match plan {
        Value::Object(object) => object,
        _ => return vec!["plan_not_object".to_string()],
    };

    for key in object.keys() {
        if !PLAN_REQUIRED.contains(&key.as_str()) {
            reasons.push(format!("undeclared_plan_field:{key}"));
        }
    }
    for key in PLAN_REQUIRED {
        if !object.contains_key(key) {
            reasons.push(format!("missing_required_field:{key}"));
        }
    }
    for path in placeholder_paths(object) {
        reasons.push(format!("unresolved_placeholder:{path}"));
    }
    if reasons.iter().any(|reason| {
        reason.starts_with("missing_required_field") || reason.starts_with("undeclared_plan_field")
    }) {
        // The shape is already unusable; deeper checks would only add noise.
        return reasons;
    }

    let migrations = object.get("migrations");

    if !equals_integer(object.get("schema_version"), PLAN_SCHEMA_VERSION) {
        reasons.push("unsupported_schema_version".to_string());
    }
    let spec_version = object.get("spec_version");
    if !is_text(spec_version) || !spec_version.and_then(Value::as_str).is_some_and(is_semver) {
        reasons.push(format!("invalid_spec_version:{}", scalar(spec_version)));
    }
    if !object
        .get("plan_id")
        .and_then(Value::as_str)
        .is_some_and(is_plan_id)
    {
        reasons.push("invalid_plan_id".to_string());
    }
    for field in ["created_at", "expires_at"] {
        if !object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(is_timestamp)
        {
            reasons.push(format!("invalid_timestamp:{field}"));
        }
    }
    let created = object.get("created_at").and_then(Value::as_str);
    if let (Some(created), Some(expires)) =
        (created, object.get("expires_at").and_then(Value::as_str))
    {
        if is_timestamp(created) && is_timestamp(expires) && expires <= created {
            reasons.push("expiry_not_after_creation".to_string());
        }
    }
    if !object
        .get("channel")
        .and_then(Value::as_str)
        .is_some_and(|channel| CHANNELS.contains(&channel))
    {
        reasons.push(format!(
            "unsupported_channel:{}",
            scalar(object.get("channel"))
        ));
    }

    match object.get("target") {
        Some(Value::Object(target)) => {
            if !target
                .get("component")
                .and_then(Value::as_str)
                .is_some_and(|component| COMPONENTS.contains(&component))
            {
                reasons.push(format!(
                    "unsupported_target_component:{}",
                    scalar(target.get("component"))
                ));
            }
            if !target
                .get("host")
                .and_then(Value::as_str)
                .is_some_and(|host| HOSTS.contains(&host))
            {
                reasons.push(format!("unsupported_host:{}", scalar(target.get("host"))));
            }
            if !is_text(target.get("install_root")) {
                reasons.push("missing_target_install_root".to_string());
            }
        }
        _ => reasons.push("target_not_object".to_string()),
    }

    match object.get("components") {
        Some(Value::Array(rows)) if rows.is_empty() => {
            reasons.push("components_empty".to_string());
        }
        Some(Value::Array(rows)) => {
            let mut seen: Vec<String> = Vec::new();
            for (index, row) in rows.iter().enumerate() {
                let label = format!("components[{index}]");
                let Value::Object(row) = row else {
                    reasons.push("component_not_object".to_string());
                    continue;
                };
                for key in [
                    "component",
                    "installed_version",
                    "installed_revision",
                    "target_version",
                    "target_revision",
                    "artifact_sha256",
                    "action",
                ] {
                    if !row.contains_key(key) {
                        reasons.push(format!("missing_required_field:{label}.{key}"));
                    }
                }
                let component = scalar(row.get("component"));
                if !COMPONENTS.contains(&component.as_str()) {
                    reasons.push(format!("unsupported_component:{component}"));
                }
                if seen.contains(&component) {
                    reasons.push(format!("duplicate_component:{component}"));
                }
                seen.push(component.clone());
                let action = scalar(row.get("action"));
                if !ACTIONS.contains(&action.as_str()) {
                    reasons.push(format!("unsupported_action:{component}:{action}"));
                }
                let target_version = row.get("target_version");
                if !target_version
                    .and_then(Value::as_str)
                    .is_some_and(is_semver)
                {
                    reasons.push(format!("invalid_version:{component}.target_version"));
                }
                if let Some(installed) = row.get("installed_version") {
                    if !installed.is_null() && !installed.as_str().is_some_and(is_semver) {
                        reasons.push(format!("invalid_version:{component}.installed_version"));
                    }
                }
                for field in ["installed_revision", "target_revision"] {
                    let value = row.get(field);
                    if field == "installed_revision" && value.is_none_or(Value::is_null) {
                        continue;
                    }
                    if !value.and_then(Value::as_str).is_some_and(is_revision) {
                        reasons.push(format!("invalid_revision:{component}.{field}"));
                    }
                }
                if !row
                    .get("artifact_sha256")
                    .and_then(Value::as_str)
                    .is_some_and(is_digest)
                {
                    reasons.push(format!("invalid_digest:{component}.artifact_sha256"));
                }
                if ACTIONS.contains(&action.as_str()) {
                    if let Some(target_text) = target_version.and_then(Value::as_str) {
                        if is_semver(target_text) {
                            let installed_value = row.get("installed_version");
                            let installed_present =
                                installed_value.is_some_and(|value| !value.is_null());
                            let installed_text = installed_value.and_then(Value::as_str);
                            let mismatch = match action.as_str() {
                                "install" => installed_present,
                                "upgrade" => {
                                    !installed_present || (installed_text == Some(target_text))
                                }
                                "reinstall" => !installed_present,
                                "noop" => installed_text != Some(target_text),
                                _ => false,
                            };
                            if mismatch {
                                reasons.push(format!("action_version_mismatch:{component}"));
                            }
                        }
                    }
                }
            }
        }
        _ => reasons.push("components_not_list".to_string()),
    }

    match object.get("downloads") {
        Some(Value::Array(rows)) => {
            let mut seen: Vec<String> = Vec::new();
            for row in rows {
                let Value::Object(row) = row else {
                    reasons.push("download_not_object".to_string());
                    continue;
                };
                let artifact = scalar(row.get("artifact"));
                if !is_text(row.get("artifact")) {
                    reasons.push("missing_download_artifact".to_string());
                } else {
                    if seen.contains(&artifact) {
                        reasons.push(format!("duplicate_download:{artifact}"));
                    }
                    seen.push(artifact.clone());
                }
                if !row
                    .get("url")
                    .and_then(Value::as_str)
                    .is_some_and(|url| url.starts_with("https://"))
                {
                    reasons.push(format!("download_url_not_https:{artifact}"));
                }
                if !row
                    .get("sha256")
                    .and_then(Value::as_str)
                    .is_some_and(is_digest)
                {
                    reasons.push(format!("invalid_digest:{artifact}.sha256"));
                }
                if !is_count(row.get("size_bytes"), 1) {
                    reasons.push(format!("invalid_size:{artifact}"));
                }
            }
        }
        _ => reasons.push("downloads_not_list".to_string()),
    }

    match migrations {
        Some(Value::Array(rows)) => {
            let mut seen: Vec<String> = Vec::new();
            for row in rows {
                let Value::Object(row) = row else {
                    reasons.push("migration_not_object".to_string());
                    continue;
                };
                let migration_id = scalar(row.get("migration_id"));
                if !row
                    .get("migration_id")
                    .and_then(Value::as_str)
                    .is_some_and(is_plan_id)
                {
                    reasons.push(format!("invalid_migration_id:{migration_id}"));
                } else {
                    if seen.contains(&migration_id) {
                        reasons.push(format!("duplicate_migration:{migration_id}"));
                    }
                    seen.push(migration_id.clone());
                }
                let source = row.get("from_queue_schema");
                let target_schema = row.get("to_queue_schema");
                if !is_count(source, 0) || !is_count(target_schema, 0) {
                    reasons.push(format!("invalid_queue_schema_step:{migration_id}"));
                } else if count_of(target_schema).unwrap_or(0) <= count_of(source).unwrap_or(0) {
                    reasons.push(format!("migration_not_forward:{migration_id}"));
                }
                if row.get("reversible") == Some(&Value::Bool(false))
                    && row.get("requires_backup") != Some(&Value::Bool(true))
                {
                    reasons.push(format!(
                        "irreversible_migration_without_backup:{migration_id}"
                    ));
                }
            }
        }
        _ => reasons.push("migrations_not_list".to_string()),
    }

    match object.get("backup") {
        Some(Value::Object(backup)) => {
            if !matches!(backup.get("required"), Some(Value::Bool(_))) {
                reasons.push("invalid_backup_required".to_string());
            }
            match backup.get("targets") {
                Some(Value::Array(targets)) => {
                    for target in targets {
                        if !target.as_str().is_some_and(is_relative_path) {
                            reasons.push(format!("invalid_backup_target:{}", scalar(Some(target))));
                        }
                    }
                }
                _ => reasons.push("backup_targets_not_list".to_string()),
            }
            let mut needs_backup: Vec<String> = Vec::new();
            if let Some(Value::Array(rows)) = migrations {
                for row in rows {
                    if let Value::Object(row) = row {
                        if row.get("requires_backup") == Some(&Value::Bool(true)) {
                            needs_backup.push(scalar(row.get("migration_id")));
                        }
                    }
                }
            }
            if !needs_backup.is_empty() && backup.get("required") != Some(&Value::Bool(true)) {
                needs_backup.sort();
                reasons.push(format!(
                    "backup_required_by_migration:{}",
                    needs_backup.join(",")
                ));
            }
        }
        _ => reasons.push("backup_not_object".to_string()),
    }

    if !is_count(object.get("disk_headroom_bytes"), 0) {
        reasons.push("invalid_disk_headroom_bytes".to_string());
    }

    match object.get("service_interruptions") {
        Some(Value::Array(rows)) => {
            for row in rows {
                let Value::Object(row) = row else {
                    reasons.push("service_interruption_not_object".to_string());
                    continue;
                };
                let service = scalar(row.get("service"));
                if !COMPONENTS.contains(&service.as_str()) {
                    reasons.push(format!("unsupported_service:{service}"));
                }
                let action = scalar(row.get("action"));
                if !INTERRUPTION_ACTIONS.contains(&action.as_str()) {
                    reasons.push(format!(
                        "unsupported_interruption_action:{service}:{action}"
                    ));
                }
                if !is_count(row.get("max_seconds"), 0) {
                    reasons.push(format!("invalid_interruption_seconds:{service}"));
                }
            }
        }
        _ => reasons.push("service_interruptions_not_list".to_string()),
    }

    match object.get("host_reconnect") {
        Some(Value::Object(reconnect)) => {
            if !matches!(reconnect.get("required"), Some(Value::Bool(_))) {
                reasons.push("invalid_host_reconnect_required".to_string());
            }
            if !is_text(reconnect.get("reason")) {
                reasons.push("missing_host_reconnect_reason".to_string());
            }
        }
        _ => reasons.push("host_reconnect_not_object".to_string()),
    }

    match object.get("bootstrap_changes") {
        Some(Value::Array(rows)) => {
            for row in rows {
                let Value::Object(row) = row else {
                    reasons.push("bootstrap_change_not_object".to_string());
                    continue;
                };
                let repo_id = scalar(row.get("repo_id"));
                if !row
                    .get("repo_id")
                    .and_then(Value::as_str)
                    .is_some_and(is_plan_id)
                {
                    reasons.push(format!("invalid_bootstrap_repo:{repo_id}"));
                }
                if !row
                    .get("template_version")
                    .and_then(Value::as_str)
                    .is_some_and(is_semver)
                {
                    reasons.push(format!("invalid_bootstrap_template_version:{repo_id}"));
                }
                match row.get("destinations") {
                    Some(Value::Array(destinations)) if !destinations.is_empty() => {
                        for destination in destinations {
                            if !destination.as_str().is_some_and(is_relative_path) {
                                reasons.push(format!(
                                    "invalid_bootstrap_destination:{}",
                                    scalar(Some(destination))
                                ));
                            }
                        }
                    }
                    _ => reasons.push(format!("missing_bootstrap_destinations:{repo_id}")),
                }
            }
        }
        _ => reasons.push("bootstrap_changes_not_list".to_string()),
    }

    match object.get("rollback") {
        Some(Value::Object(rollback)) => {
            if !matches!(rollback.get("supported"), Some(Value::Bool(_))) {
                reasons.push("invalid_rollback_supported".to_string());
            }
            if !matches!(
                rollback.get("restores_previous_versions"),
                Some(Value::Bool(_))
            ) {
                reasons.push("invalid_rollback_restores".to_string());
            }
            match rollback.get("limits") {
                Some(Value::Array(limits)) => {
                    if rollback.get("supported") == Some(&Value::Bool(true))
                        && limits.iter().any(|limit| !is_text(Some(limit)))
                    {
                        reasons.push("invalid_rollback_limit".to_string());
                    }
                }
                _ => reasons.push("rollback_limits_not_list".to_string()),
            }
            if rollback.get("supported") != Some(&Value::Bool(true))
                && migrations.is_some_and(truthy)
            {
                reasons.push("rollback_unsupported_with_migration".to_string());
            }
        }
        _ => reasons.push("rollback_not_object".to_string()),
    }

    match object.get("trust") {
        Some(Value::Object(trust)) => {
            if !is_count(trust.get("metadata_version"), 1) {
                reasons.push("invalid_trust_metadata_version".to_string());
            }
            match trust.get("metadata_expiry").and_then(Value::as_str) {
                Some(expiry) if is_timestamp(expiry) => {
                    if let Some(created) = created {
                        if is_timestamp(created) && expiry <= created {
                            reasons.push("trust_metadata_expired".to_string());
                        }
                    }
                }
                _ => reasons.push("invalid_trust_metadata_expiry".to_string()),
            }
            let unresolved = match trust.get("trust_root") {
                None | Some(Value::Null) => true,
                Some(Value::String(root)) => !is_digest(root),
                Some(_) => true,
            };
            if unresolved {
                reasons.push("unresolved_trust_root".to_string());
            }
            if trust.get("signature_present") != Some(&Value::Bool(true)) {
                reasons.push("unsigned_plan".to_string());
            }
        }
        _ => reasons.push("trust_not_object".to_string()),
    }

    match object.get("approval") {
        Some(Value::Object(approval)) => {
            let state = scalar(approval.get("state"));
            if !APPROVAL_STATES.contains(&state.as_str()) {
                reasons.push(format!("unsupported_approval_state:{state}"));
            } else if state == "approved" {
                if !is_text(approval.get("approved_by")) {
                    reasons.push("approval_incomplete:approved_by".to_string());
                }
                if !approval
                    .get("approved_at")
                    .and_then(Value::as_str)
                    .is_some_and(is_timestamp)
                {
                    reasons.push("approval_incomplete:approved_at".to_string());
                }
                match approval.get("approved_digest").and_then(Value::as_str) {
                    Some(recorded) if is_digest(recorded) => {
                        if object.get("plan_digest").and_then(Value::as_str) != Some(recorded) {
                            reasons.push("approval_digest_mismatch".to_string());
                        }
                    }
                    _ => reasons.push("approval_incomplete:approved_digest".to_string()),
                }
            } else {
                for (key, reason) in [
                    ("approved_digest", "unapproved_plan_carries_digest"),
                    ("approved_by", "unapproved_plan_carries_approver"),
                    ("approved_at", "unapproved_plan_carries_timestamp"),
                ] {
                    if approval.get(key).is_some_and(|value| !value.is_null()) {
                        reasons.push(reason.to_string());
                    }
                }
            }
        }
        _ => reasons.push("approval_not_object".to_string()),
    }

    match object.get("plan_digest").and_then(Value::as_str) {
        Some(recorded) if is_digest(recorded) => match plan_digest(plan) {
            Ok(computed) => {
                if computed != recorded {
                    reasons.push("plan_digest_mismatch".to_string());
                }
            }
            // Reachable only for a value JSON cannot encode, which no parsed
            // document can contain.
            Err(_) => reasons.push("plan_digest_unencodable".to_string()),
        },
        _ => reasons.push("invalid_plan_digest".to_string()),
    }

    reasons
}
/// Render a value the way the contract spells it in diagnostics: strings bare,
/// JSON null and absent keys as `None`, everything else as compact JSON.
fn scalar(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".to_string(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    }
}

/// The JSON kind of a value, for a fail-closed diagnostic.
fn scalar_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Python truthiness of a JSON value, used where the contract tests a raw field.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// The integer value of a JSON number, or `None` when it is not an integer.
fn count_of(value: Option<&Value>) -> Option<i128> {
    match value {
        Some(Value::Number(number)) => number
            .as_u64()
            .map(i128::from)
            .or_else(|| number.as_i64().map(i128::from)),
        _ => None,
    }
}

/// Whether a value is a JSON integer at or above `minimum`.
///
/// A JSON boolean is not an integer, and neither is `1.0`: the contract tests
/// `type(value) is int`.
fn is_count(value: Option<&Value>, minimum: i128) -> bool {
    count_of(value).is_some_and(|count| count >= minimum)
}

/// Numeric equality with a schema `const`, so both `1` and `1.0` match.
fn equals_integer(value: Option<&Value>, expected: u64) -> bool {
    match value {
        Some(Value::Number(number)) => {
            number.as_u64() == Some(expected) || number.as_f64() == Some(expected as f64)
        }
        _ => false,
    }
}

/// Whether a value is a non-blank JSON string.
fn is_text(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|text| !text.trim().is_empty())
}

/// Every JSON path whose string value still carries an unresolved placeholder.
fn placeholder_paths(root: &Map<String, Value>) -> Vec<String> {
    let mut paths = Vec::new();
    for (key, value) in root {
        collect_placeholder_paths(value, &format!("$.{key}"), &mut paths);
    }
    paths
}

/// Depth-first collection in sorted-key, then index, order.
fn collect_placeholder_paths(value: &Value, path: &str, paths: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            if contains_placeholder(text) {
                paths.push(path.to_string());
            }
        }
        Value::Object(map) => {
            for (key, child) in map {
                collect_placeholder_paths(child, &format!("{path}.{key}"), paths);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_placeholder_paths(item, &format!("{path}[{index}]"), paths);
            }
        }
        _ => {}
    }
}

/// Whether a string still carries a `REPLACE` or `FILL_ME` placeholder.
fn contains_placeholder(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.contains("REPLACE") || upper.contains("FILL_ME")
}

/// Whether a string is exactly `length` lowercase hexadecimal characters.
fn is_lowercase_hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether a string is a lowercase 64-hex SHA-256 digest.
fn is_digest(text: &str) -> bool {
    is_lowercase_hex(text, 64)
}

/// Whether a string is a lowercase 40-hex Git revision.
fn is_revision(text: &str) -> bool {
    is_lowercase_hex(text, 40)
}

/// Whether a string is a `plan_id`: lowercase start, then lowercase, digits or
/// hyphens, at most 63 characters.
fn is_plan_id(text: &str) -> bool {
    let mut bytes = text.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    text.len() <= 63
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Whether a string is a `YYYY-MM-DDTHH:MM:SSZ` UTC timestamp.
///
/// The digit positions are read from a shape string, so the pattern and the
/// check can never drift apart.
fn is_timestamp(text: &str) -> bool {
    const SHAPE: &[u8; 20] = b"0000-00-00T00:00:00Z";
    let bytes = text.as_bytes();
    if bytes.len() != SHAPE.len() {
        return false;
    }
    SHAPE
        .iter()
        .zip(bytes)
        .all(|(expected, actual)| match expected {
            b'0' => actual.is_ascii_digit(),
            literal => actual == literal,
        })
}

/// Whether a string is a semantic version accepted by the frozen schema.
///
/// `MAJOR.MINOR.PATCH` with numeric identifiers that carry no leading zero,
/// an optional `-prerelease` and an optional `+build`, each `[0-9A-Za-z.-]+`.
fn is_semver(text: &str) -> bool {
    let Some(split) = text.find(['-', '+']) else {
        return is_three_numeric_parts(text);
    };
    let (core, suffix) = text.split_at(split);
    if !is_three_numeric_parts(core) {
        return false;
    }
    if let Some(body) = suffix.strip_prefix('-') {
        return match body.split_once('+') {
            None => is_semver_suffix(body),
            Some((prerelease, build)) => is_semver_suffix(prerelease) && is_semver_suffix(build),
        };
    }
    suffix.strip_prefix('+').is_some_and(is_semver_suffix)
}

/// Whether a string is `X.Y.Z` with three numeric identifiers.
fn is_three_numeric_parts(core: &str) -> bool {
    let mut parts = core.split('.');
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    is_numeric_identifier(major) && is_numeric_identifier(minor) && is_numeric_identifier(patch)
}

/// `0`, or a digit run that does not start with `0`.
fn is_numeric_identifier(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && !(text.len() > 1 && text.starts_with('0'))
}

/// Whether a string is a non-empty run of `[0-9A-Za-z.-]`.
fn is_semver_suffix(text: &str) -> bool {
    !text.is_empty()
        && text.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '.' || character == '-'
        })
}

/// Whether a string is a portable relative path: not absolute, no backslash, no
/// `..` segment and no drive prefix.
fn is_relative_path(text: &str) -> bool {
    if text.is_empty() || text.starts_with('/') || text.contains('\\') {
        return false;
    }
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return false;
    }
    text != ".." && !text.starts_with("../") && !text.ends_with("/..") && !text.contains("/../")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        approval_reasons, canonical_plan_bytes, evaluate, plan_digest, record_approval,
        seal_digest, structural_reasons, ACTIONS, APPROVAL_STATES, CHANNELS, COMPONENTS,
        DIGEST_EXCLUDED, DOCUMENT_KEYS, HOSTS, INTERRUPTION_ACTIONS, PLAN_REQUIRED,
        PLAN_SCHEMA_VERSION,
    };

    /// The digest `axiom-specs` pins for `examples/update/update-plan.example.json`;
    /// `tests/test_update_plan_contract.py` re-reads that file, so this literal is
    /// the cross-language anchor for the canonical byte form.
    const FROZEN_EXAMPLE_DIGEST: &str =
        "b1938dd0652de5cd76d1a4934fd39d5a7d83012eb3a8e8c0c6139e1bc1d77b00";

    /// The approved plan of the shipped example, rebuilt here so this crate
    /// never carries a second copy of the normative artifact.
    fn frozen_plan() -> serde_json::Value {
        json!({
            "schema_version": 1,
            "spec_version": "2.0.0-draft.1",
            "plan_id": "update-2026-09-18-graphd-0-2-0",
            "created_at": "2026-09-18T02:00:00Z",
            "expires_at": "2026-09-19T02:00:00Z",
            "channel": "stable",
            "target": {
                "component": "axiom-graphd",
                "host": "windows-x64",
                "install_root": "C:/Users/demo/.axiom/components/axiom-graphd/0.2.0"
            },
            "components": [
                {
                    "component": "axiom-graphd",
                    "installed_version": "0.1.0",
                    "installed_revision": "1111111111111111111111111111111111111111",
                    "target_version": "0.2.0",
                    "target_revision": "2222222222222222222222222222222222222222",
                    "artifact_sha256": "3333333333333333333333333333333333333333333333333333333333333333",
                    "action": "upgrade"
                },
                {
                    "component": "axiom",
                    "installed_version": "0.1.0",
                    "installed_revision": "1111111111111111111111111111111111111111",
                    "target_version": "0.2.0",
                    "target_revision": "2222222222222222222222222222222222222222",
                    "artifact_sha256": "4444444444444444444444444444444444444444444444444444444444444444",
                    "action": "upgrade"
                }
            ],
            "downloads": [
                {
                    "artifact": "axiom-graphd-0.2.0-windows-x64.zip",
                    "url": "https://github.com/orchex006/axiom-graphd/releases/download/v0.2.0/axiom-graphd-0.2.0-windows-x64.zip",
                    "sha256": "3333333333333333333333333333333333333333333333333333333333333333",
                    "size_bytes": 41943040
                }
            ],
            "migrations": [
                {
                    "migration_id": "queue-schema-1-to-2",
                    "from_queue_schema": 1,
                    "to_queue_schema": 2,
                    "reversible": false,
                    "requires_backup": true
                }
            ],
            "backup": {
                "required": true,
                "targets": [".axiom/state/queue.db", ".axiom/state/queue.db-wal"]
            },
            "disk_headroom_bytes": 268435456,
            "service_interruptions": [
                {"service": "axiom-graphd", "action": "restart", "max_seconds": 30},
                {"service": "axiom-mcp", "action": "none", "max_seconds": 0}
            ],
            "host_reconnect": {
                "required": true,
                "reason": "the shared core version changes, so host adapters re-read the local control endpoint"
            },
            "bootstrap_changes": [
                {
                    "repo_id": "auth-api",
                    "template_version": "0.2.0",
                    "destinations": ["AGENTS.md", ".axiom/agent/POLICY.md"]
                }
            ],
            "rollback": {
                "supported": true,
                "restores_previous_versions": true,
                "limits": [
                    "a queue schema migration is not reversible in place; rollback restores the pre-upgrade backup and must not run the old binary against schema 2"
                ]
            },
            "trust": {
                "metadata_version": 7,
                "metadata_expiry": "2026-09-25T02:00:00Z",
                "trust_root": "5555555555555555555555555555555555555555555555555555555555555555",
                "signature_present": true
            },
            "approval": {
                "state": "approved",
                "approved_digest": FROZEN_EXAMPLE_DIGEST,
                "approved_by": "maintainer@example.invalid",
                "approved_at": "2026-09-18T02:05:00Z"
            },
            "plan_digest": FROZEN_EXAMPLE_DIGEST
        })
    }

    #[test]
    fn the_frozen_example_digest_is_reproduced() {
        let plan = frozen_plan();
        assert_eq!(structural_reasons(&plan), Vec::<String>::new());
        assert_eq!(plan_digest(&plan).expect("digest"), FROZEN_EXAMPLE_DIGEST);
        let verdict = evaluate(&json!({"plan": plan.clone()}));
        assert!(verdict.ok, "reasons: {:?}", verdict.reasons);
        assert_eq!(verdict.plan_digest.as_deref(), Some(FROZEN_EXAMPLE_DIGEST));
    }

    #[test]
    fn canonical_bytes_match_the_frozen_oracle_form() {
        let plan = json!({"b": 1, "a": {"z": true, "y": "x"}, "plan_digest": "ff", "approval": 7});
        let bytes = canonical_plan_bytes(&plan).expect("canonical");
        assert_eq!(
            String::from_utf8(bytes).expect("utf8"),
            "{\"a\":{\"y\":\"x\",\"z\":true},\"b\":1}\n"
        );
    }

    #[test]
    fn approval_metadata_never_perturbs_the_digest() {
        // Boundary: the digest excludes the two keys that record approval, so a
        // plan cannot invalidate its own approval by being sealed or approved.
        let plan = frozen_plan();
        let before = plan_digest(&plan).expect("digest");
        let mut mutated = plan.clone();
        mutated["approval"]["state"] = json!("unapproved");
        mutated["approval"]["approved_digest"] = json!(null);
        mutated["approval"]["approved_by"] = json!("someone@example.invalid");
        mutated["approval"]["approved_at"] = json!("2030-01-01T00:00:00Z");
        mutated["plan_digest"] = json!("0".repeat(64));
        assert_eq!(plan_digest(&mutated).expect("digest"), before);
    }

    #[test]
    fn editing_any_planned_payload_invalidates_the_approval() {
        // AC1: the digest covers target paths and operations, so every one of
        // these single-field edits makes the recorded approval stale.
        let plan = frozen_plan();
        let approved = plan_digest(&plan).expect("digest");
        let edits: Vec<(&str, serde_json::Value)> = vec![
            (
                "target path",
                json!({"target": {"component": "axiom-graphd", "host": "windows-x64", "install_root": "C:/elsewhere/0.2.0"}}),
            ),
            ("target host", json!({"channel": "prerelease"})),
            (
                "operation",
                json!({"service_interruptions": [{"service": "axiom-graphd", "action": "stop", "max_seconds": 30}]}),
            ),
            (
                "component version",
                json!({"components": [
                    {"component": "axiom-graphd", "installed_version": "0.1.0", "installed_revision": "1111111111111111111111111111111111111111", "target_version": "0.2.1", "target_revision": "2222222222222222222222222222222222222222", "artifact_sha256": "3333333333333333333333333333333333333333333333333333333333333333", "action": "upgrade"},
                    {"component": "axiom", "installed_version": "0.1.0", "installed_revision": "1111111111111111111111111111111111111111", "target_version": "0.2.0", "target_revision": "2222222222222222222222222222222222222222", "artifact_sha256": "4444444444444444444444444444444444444444444444444444444444444444", "action": "upgrade"}
                ]}),
            ),
            (
                "artifact hash",
                json!({"downloads": [{"artifact": "axiom-graphd-0.2.0-windows-x64.zip", "url": "https://github.com/orchex006/axiom-graphd/releases/download/v0.2.0/axiom-graphd-0.2.0-windows-x64.zip", "sha256": "3".repeat(63) + "4", "size_bytes": 41943040}]}),
            ),
            (
                "migration set",
                json!({"migrations": [{"migration_id": "queue-schema-1-to-3", "from_queue_schema": 1, "to_queue_schema": 3, "reversible": false, "requires_backup": true}], "backup": {"required": true, "targets": [".axiom/state/queue.db", ".axiom/state/queue.db-wal"]}}),
            ),
            (
                "backup plan",
                json!({"backup": {"required": true, "targets": [".axiom/state/queue.db"]}}),
            ),
            ("expiry", json!({"expires_at": "2026-09-20T02:00:00Z"})),
        ];
        for (label, patch) in edits {
            let mut edited = plan.clone();
            let patched = patch.as_object().expect("patch object");
            for (key, value) in patched {
                edited[key] = value.clone();
            }
            let moved = plan_digest(&edited).expect("digest");
            assert_ne!(moved, approved, "{label} must move the digest");
            // A payload edited in place still carries the old self-digest, so it
            // fails structurally as well as having a stale approval.
            assert_eq!(
                approval_reasons(&edited, &approved),
                vec!["approval_stale".to_string()],
                "{label} must invalidate the recorded approval"
            );
            assert!(
                structural_reasons(&edited).contains(&"plan_digest_mismatch".to_string()),
                "{label} must leave the plan self-inconsistent: {:?}",
                structural_reasons(&edited)
            );
            // Re-sealing the changed payload makes the body self-consistent but
            // cannot resurrect the old approval: both approval reasons fire, the
            // shape the shipped update.stale.* fixtures pin.
            let mut resealed = edited.clone();
            seal_digest(&mut resealed).expect("reseal");
            assert_eq!(
                approval_reasons(&resealed, &approved),
                vec![
                    "approval_stale".to_string(),
                    "plan_digest_not_approved".to_string()
                ],
                "{label} must stay rejected after re-sealing"
            );
        }
    }

    #[test]
    fn sealing_and_approving_are_idempotent_and_consistent() {
        let mut plan = frozen_plan();
        plan["plan_digest"] = json!("0".repeat(64));
        plan["approval"] = json!({
            "state": "unapproved",
            "approved_digest": null,
            "approved_by": null,
            "approved_at": null
        });
        let sealed = seal_digest(&mut plan).expect("seal");
        assert_eq!(sealed, FROZEN_EXAMPLE_DIGEST);
        assert_eq!(seal_digest(&mut plan).expect("re-seal"), sealed);
        let approved = record_approval(
            &mut plan,
            "maintainer@example.invalid",
            "2026-09-18T02:05:00Z",
        )
        .expect("approve");
        assert_eq!(approved, sealed);
        assert_eq!(plan_digest(&plan).expect("digest"), sealed);
        assert!(evaluate(&json!({"plan": plan})).ok);
    }

    #[test]
    fn a_changed_payload_cannot_reuse_an_old_approval() {
        // Negative: the classic reuse attempt - approve 0.2.0, then ship 0.2.1
        // under the same approval.
        let mut plan = frozen_plan();
        let approved = plan["plan_digest"].clone();
        plan["components"][0]["target_version"] = json!("0.2.1");
        // The shipped stale-approval fixtures re-seal the changed plan, so the
        // refusal has to survive a body that only the old approval disagrees with.
        seal_digest(&mut plan).expect("reseal");
        let verdict = evaluate(&json!({"plan": plan, "approved_digest": approved}));
        assert!(!verdict.ok);
        assert_eq!(
            verdict.approval_reasons,
            vec![
                "approval_stale".to_string(),
                "plan_digest_not_approved".to_string()
            ]
        );
    }

    #[test]
    fn an_unapproved_plan_may_not_carry_approval_metadata() {
        let mut plan = frozen_plan();
        plan["approval"]["state"] = json!("unapproved");
        let reasons = structural_reasons(&plan);
        assert!(reasons.contains(&"unapproved_plan_carries_digest".to_string()));
        assert!(reasons.contains(&"unapproved_plan_carries_approver".to_string()));
        assert!(reasons.contains(&"unapproved_plan_carries_timestamp".to_string()));
    }

    #[test]
    fn a_non_object_plan_cannot_be_digested_or_approved() {
        // Boundary: the digest fails closed rather than hashing something else.
        let mut not_a_plan = json!([1, 2, 3]);
        let error = plan_digest(&not_a_plan).expect_err("must refuse");
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("array")
        );
        assert!(seal_digest(&mut not_a_plan).is_err());
        assert_eq!(
            approval_reasons(&not_a_plan, FROZEN_EXAMPLE_DIGEST),
            vec!["plan_not_object".to_string()]
        );
    }

    #[test]
    fn the_frozen_vocabularies_match_the_schema() {
        assert_eq!(PLAN_SCHEMA_VERSION, 1);
        assert_eq!(COMPONENTS, ["axiom-graphd", "axiom-mcp", "axiom", "skills"]);
        assert_eq!(
            HOSTS,
            ["windows-x64", "linux-x64", "macos-arm64", "macos-x64"]
        );
        assert_eq!(CHANNELS, ["stable", "prerelease"]);
        assert_eq!(ACTIONS, ["install", "upgrade", "reinstall", "noop"]);
        assert_eq!(INTERRUPTION_ACTIONS, ["stop", "restart", "none"]);
        assert_eq!(APPROVAL_STATES, ["unapproved", "approved"]);
        assert_eq!(DIGEST_EXCLUDED, ["plan_digest", "approval"]);
        assert_eq!(DOCUMENT_KEYS, ["plan", "approved_digest"]);
        assert_eq!(PLAN_REQUIRED.len(), 19);
    }

    #[test]
    fn a_plan_that_still_holds_a_placeholder_is_reported_at_its_path() {
        let mut plan = frozen_plan();
        plan["target"]["install_root"] = json!("REPLACE_WITH_INSTALL_ROOT");
        plan["spec_version"] = json!("2.0.0-draft.1");
        let reasons = structural_reasons(&plan);
        assert!(
            reasons.contains(&"unresolved_placeholder:$.target.install_root".to_string()),
            "{reasons:?}"
        );
    }

    #[test]
    fn a_document_without_a_plan_object_is_rejected() {
        let verdict = evaluate(&json!({"approved_digest": FROZEN_EXAMPLE_DIGEST}));
        assert!(!verdict.ok);
        assert_eq!(verdict.plan_digest, None);
        assert_eq!(
            verdict.structural_reasons,
            vec!["missing_required_field:plan".to_string()]
        );
    }
}
