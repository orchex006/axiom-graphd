//! Local, pointer-bound ecosystem update and rollback runtime.
//!
//! This is deliberately separate from the distribution update channel.  It
//! operates on the `current` pointer and versioned payloads installed by the
//! ecosystem installer, serialised by its maintenance lock.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};
use graph_export::sha256_hex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::install::apply::{ApplyRequest, LocalFs};
use crate::install::ecosystem::{
    apply_ecosystem, plan_ecosystem, verify_ecosystem, EcosystemContext, EcosystemPlan,
    EcosystemProbe,
};
use crate::install::ecosystem_uninstall::maintenance_lock;
use crate::install::plan::{is_digest, InstallPlan};
use crate::skills::install::{LocalInstallFs, LocalPayloadSource};

/// Schema written for outer update plans and recovery journals.
pub const SCHEMA_VERSION: u64 = 1;
/// Stable outer document kind.
pub const PLAN_KIND: &str = "ecosystem-update-plan";
/// Stable durable journal kind.
pub const JOURNAL_KIND: &str = "ecosystem-update-journal";
const JOURNAL_PREFIX: &str = "ecosystem-update-";
const JOURNAL_SUFFIX: &str = ".json";

fn refuse(rule: &str, message: &str) -> AxiomError {
    AxiomError::new(ErrorCode::ValidationError, message).with_detail("rule", rule)
}
fn conflict(rule: &str, message: &str) -> AxiomError {
    AxiomError::new(ErrorCode::Conflict, message).with_detail("rule", rule)
}
fn verify_runtime_host(recorded_host: &str) -> Result<(), AxiomError> {
    let runtime_host = crate::install::plan::host_identifier();
    if recorded_host != runtime_host {
        return Err(refuse(
            "host-mismatch",
            "approved update plan targets a different runtime host",
        )
        .with_detail("expected", runtime_host)
        .with_detail("observed", recorded_host));
    }
    Ok(())
}
fn io(rule: &str, error: std::io::Error) -> AxiomError {
    AxiomError::new(
        if error.kind() == std::io::ErrorKind::NotFound {
            ErrorCode::NotFound
        } else {
            ErrorCode::Internal
        },
        "ecosystem update filesystem operation failed",
    )
    .with_detail("rule", rule)
    .with_detail("observed", error.to_string())
}

/// Service work controlled by a caller that owns the host-specific service.
///
/// The runtime never guesses a service label or invokes a host shell.  A no-op
/// implementation is appropriate where no owned service exists.
pub trait ServiceLifecycle {
    /// Whether this installation has an owned service to preserve in its journal.
    fn is_owned(&self, install_root: &Path) -> Result<bool, AxiomError>;
    /// Stop/drain the owned service before its active pointer changes.
    fn drain(&self, install_root: &Path) -> Result<(), AxiomError>;
    /// Reinstall or restart from the pointer currently on disk.
    fn reinstall(&self, install_root: &Path) -> Result<(), AxiomError>;
}

/// No owned service. Useful for foreground-only local installations.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoService;
impl ServiceLifecycle for NoService {
    fn is_owned(&self, _: &Path) -> Result<bool, AxiomError> {
        Ok(false)
    }
    fn drain(&self, _: &Path) -> Result<(), AxiomError> {
        Ok(())
    }
    fn reinstall(&self, _: &Path) -> Result<(), AxiomError> {
        Ok(())
    }
}

/// Reviewable update plan. The outer digest binds both the sealed ecosystem
/// plan and the exact active pointer that the reviewer inspected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcosystemUpdatePlan {
    pub schema_version: u64,
    pub kind: String,
    pub target_version: String,
    pub previous_pointer_sha256: String,
    pub previous_skills_pointer_sha256: Option<String>,
    pub ecosystem: EcosystemPlan,
    pub plan_digest: String,
}

impl EcosystemUpdatePlan {
    /// Compute the canonical approval digest excluding `plan_digest`.
    pub fn digest(&self) -> Result<String, AxiomError> {
        let mut value = serde_json::to_value(self)
            .map_err(|_| refuse("plan-invalid", "update plan is not serialisable"))?;
        value
            .as_object_mut()
            .ok_or_else(|| refuse("plan-invalid", "update plan is not an object"))?
            .remove("plan_digest");
        graph_export::canonical::canonical_document_value(&value)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| refuse("plan-invalid", "update plan is not canonical"))
    }
    pub fn verify(&self, approved_digest: &str) -> Result<(), AxiomError> {
        if self.schema_version != SCHEMA_VERSION || self.kind != PLAN_KIND {
            return Err(refuse("plan-kind", "unsupported ecosystem update plan"));
        }
        verify_runtime_host(&self.ecosystem.target.host)?;
        if self.target_version.is_empty()
            || self
                .ecosystem
                .component_plans
                .first()
                .is_none_or(|component| component.version != self.target_version)
        {
            return Err(refuse(
                "target-version",
                "update target version does not match the graph daemon component",
            ));
        }
        if !is_digest(&self.previous_pointer_sha256)
            || self
                .previous_skills_pointer_sha256
                .as_deref()
                .is_some_and(|value| !is_digest(value))
            || !is_digest(approved_digest)
        {
            return Err(refuse(
                "plan-digest",
                "update plan carries an invalid digest",
            ));
        }
        if self.digest()? != self.plan_digest || approved_digest != self.plan_digest {
            return Err(AxiomError::new(
                ErrorCode::Forbidden,
                "update approval does not bind this exact ecosystem plan",
            )
            .with_detail("rule", "approval"));
        }
        // Verify the inner sealed plan independently before any host mutation.
        verify_ecosystem(&self.ecosystem, &self.ecosystem.plan_digest)
    }
}

/// Build a plan over a verified local bundle and bind it to the current pointer.
pub fn plan(
    probe: &impl EcosystemProbe,
    bundle_root: &Path,
    context: &EcosystemContext,
    target_version: impl Into<String>,
) -> Result<EcosystemUpdatePlan, AxiomError> {
    let root = Path::new(&context.install_root);
    let pointer = read_pointer(root)?;
    let (skills_pointer, _) = skill_snapshot(root)?;
    let ecosystem = plan_ecosystem(probe, &bundle_root.to_string_lossy(), context)?;
    let mut result = EcosystemUpdatePlan {
        schema_version: SCHEMA_VERSION,
        kind: PLAN_KIND.to_string(),
        target_version: target_version.into(),
        previous_pointer_sha256: sha256_hex(&pointer),
        previous_skills_pointer_sha256: skills_pointer.as_deref().map(sha256_hex),
        ecosystem,
        plan_digest: String::new(),
    };
    result.plan_digest = result.digest()?;
    Ok(result)
}

/// Persist one plan atomically for review.
pub fn write_plan(path: &Path, plan: &EcosystemUpdatePlan) -> Result<(), AxiomError> {
    if plan.digest()? != plan.plan_digest {
        return Err(refuse(
            "plan-digest",
            "cannot write an unsealed update plan",
        ));
    }
    write_atomic(
        path,
        &serde_json::to_vec_pretty(plan)
            .map_err(|_| refuse("plan-invalid", "update plan is not serialisable"))?,
    )
}

/// Read a previously reviewed update plan.
pub fn read_plan(path: &Path) -> Result<EcosystemUpdatePlan, AxiomError> {
    serde_json::from_slice(&fs::read(path).map_err(|e| io("plan-read", e))?)
        .map_err(|_| refuse("plan-invalid", "update plan is not valid JSON"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PointerArtifact {
    destination: String,
    sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u64,
    kind: String,
    transaction_id: String,
    plan_digest: String,
    previous_pointer: Vec<u8>,
    previous_pointer_sha256: String,
    activated_pointer_sha256: Option<String>,
    activated_pointer: Option<Vec<u8>>,
    activated_skills_pointer_sha256: Option<String>,
    previous_artifacts: Vec<PointerArtifact>,
    previous_skills_pointer: Option<Vec<u8>>,
    previous_skill_files: Vec<PointerArtifact>,
    service_owned: bool,
    state: String,
}

/// Result of a successful update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EcosystemUpdateOutcome {
    pub transaction_id: String,
    pub plan_digest: String,
    pub journal_path: String,
}
/// Result of a successful rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EcosystemRollbackOutcome {
    pub transaction_id: String,
    pub restored_pointer_sha256: String,
    pub journal_path: String,
}

/// Stage, activate and rebind an ecosystem update under the shared lock.
pub fn apply(
    plan: &EcosystemUpdatePlan,
    approved_digest: &str,
    transaction_id: &str,
    applied_at: &str,
    service: &impl ServiceLifecycle,
) -> Result<EcosystemUpdateOutcome, AxiomError> {
    plan.verify(approved_digest)?;
    portable_transaction(transaction_id)?;
    let root = Path::new(&plan.ecosystem.target.install_root);
    let _lock = maintenance_lock(root)?;
    refuse_incomplete_journal(root)?;
    let previous = read_pointer(root)?;
    if sha256_hex(&previous) != plan.previous_pointer_sha256 {
        return Err(conflict(
            "pointer-changed",
            "current pointer changed after update plan review",
        ));
    }
    require_pointer_path(plan, root)?;
    let journal_path = journal_path(root, transaction_id)?;
    if journal_path.exists() {
        return Err(conflict(
            "journal-exists",
            "update transaction id already has a journal",
        ));
    }
    let service_owned = service.is_owned(root)?;
    let (previous_skills_pointer, previous_skill_files) = skill_snapshot(root)?;
    if previous_skills_pointer.as_deref().map(sha256_hex) != plan.previous_skills_pointer_sha256 {
        return Err(conflict(
            "skills-pointer-changed",
            "skills pointer changed after update plan review",
        ));
    }
    let mut journal = Journal {
        schema_version: SCHEMA_VERSION,
        kind: JOURNAL_KIND.to_string(),
        transaction_id: transaction_id.to_string(),
        plan_digest: plan.plan_digest.clone(),
        previous_pointer_sha256: sha256_hex(&previous),
        previous_artifacts: pointer_artifacts(root, &previous)?,
        previous_skills_pointer,
        previous_skill_files,
        previous_pointer: previous,
        activated_pointer_sha256: None,
        activated_pointer: None,
        activated_skills_pointer_sha256: None,
        service_owned,
        state: "prepared".to_string(),
    };
    write_journal(&journal_path, &journal)?;
    if service_owned {
        if let Err(error) = service.drain(root) {
            return Err(recover_service_failure(
                root,
                &journal_path,
                &mut journal,
                service,
                error,
            ));
        }
    }
    if let Err(error) = stage_core_payloads(root, &plan.ecosystem) {
        return Err(recover_service_failure(
            root,
            &journal_path,
            &mut journal,
            service,
            error,
        ));
    }
    let skills_source =
        LocalPayloadSource::new(Path::new(&plan.ecosystem.bundle.location).join("skills/payload"));
    let skills_fs = LocalInstallFs::new(root);
    let request = ApplyRequest::new(
        transaction_id,
        plan.ecosystem.plan_digest.clone(),
        applied_at,
    );
    if let Err(error) = apply_ecosystem(
        &plan.ecosystem,
        &plan.ecosystem.plan_digest,
        &request,
        &LocalFs,
        &skills_source,
        &skills_fs,
    ) {
        return Err(recover_after_activation(
            root,
            &journal_path,
            &mut journal,
            service,
            error,
        ));
    }
    let active = match read_pointer(root) {
        Ok(value) => value,
        Err(error) => {
            return Err(recover_after_activation(
                root,
                &journal_path,
                &mut journal,
                service,
                error,
            ))
        }
    };
    journal.activated_pointer_sha256 = Some(sha256_hex(&active));
    journal.activated_pointer = Some(active.clone());
    journal.activated_skills_pointer_sha256 = fs::read(checked(root, "skills/current")?)
        .ok()
        .as_deref()
        .map(sha256_hex);
    journal.state = "activated".to_string();
    if let Err(error) = write_journal(&journal_path, &journal) {
        return Err(recover_after_activation(
            root,
            &journal_path,
            &mut journal,
            service,
            error,
        ));
    }
    if service_owned {
        if let Err(error) = service.reinstall(root) {
            return Err(recover_after_activation(
                root,
                &journal_path,
                &mut journal,
                service,
                error,
            ));
        }
    }
    journal.state = "finalized".to_string();
    if let Err(error) = write_journal(&journal_path, &journal) {
        return Err(recover_after_activation(
            root,
            &journal_path,
            &mut journal,
            service,
            error,
        ));
    }
    Ok(EcosystemUpdateOutcome {
        transaction_id: transaction_id.to_string(),
        plan_digest: plan.plan_digest.clone(),
        journal_path: journal_path.to_string_lossy().into_owned(),
    })
}

/// Restore the precise pre-update pointer after verifying retained old payloads.
pub fn rollback(
    install_root: &Path,
    transaction_id: &str,
    service: &impl ServiceLifecycle,
) -> Result<EcosystemRollbackOutcome, AxiomError> {
    portable_transaction(transaction_id)?;
    let _lock = maintenance_lock(install_root)?;
    let journal_path = journal_path(install_root, transaction_id)?;
    let mut journal: Journal =
        serde_json::from_slice(&fs::read(&journal_path).map_err(|e| io("journal-read", e))?)
            .map_err(|_| refuse("journal-invalid", "update journal is malformed"))?;
    if journal.schema_version != SCHEMA_VERSION
        || journal.kind != JOURNAL_KIND
        || journal.transaction_id != transaction_id
    {
        return Err(refuse(
            "journal-invalid",
            "update journal identity is invalid",
        ));
    }
    if sha256_hex(&journal.previous_pointer) != journal.previous_pointer_sha256
        || pointer_artifacts(install_root, &journal.previous_pointer)? != journal.previous_artifacts
    {
        return Err(refuse(
            "journal-invalid",
            "journal previous pointer evidence is inconsistent",
        ));
    }
    if journal.state == "rolled-back" {
        let current = read_pointer(install_root)?;
        if sha256_hex(&current) == journal.previous_pointer_sha256 {
            return Ok(EcosystemRollbackOutcome {
                transaction_id: transaction_id.to_string(),
                restored_pointer_sha256: journal.previous_pointer_sha256,
                journal_path: journal_path.to_string_lossy().into_owned(),
            });
        }
        return Err(conflict(
            "pointer-changed",
            "rolled-back journal no longer matches the active pointer",
        ));
    }
    if matches!(
        journal.state.as_str(),
        "service-recovery-required" | "restored-after-service-failure"
    ) {
        verify_artifacts(install_root, &journal.previous_artifacts)?;
        verify_artifacts(install_root, &journal.previous_skill_files)?;
        let current = read_pointer(install_root)?;
        let current_skills = read_optional_skills_pointer(install_root)?;
        let previous_matches = current == journal.previous_pointer
            && current_skills == journal.previous_skills_pointer;
        let activated_matches = journal.activated_pointer.as_deref() == Some(current.as_slice())
            && journal.activated_skills_pointer_sha256 == current_skills.as_deref().map(sha256_hex);
        if !previous_matches && !activated_matches {
            return Err(conflict(
                "pointer-changed",
                "recovery journal does not match either recorded pointer state",
            ));
        }
        if activated_matches {
            if journal.service_owned {
                service.drain(install_root)?;
            }
            restore_pointer(install_root, &journal.previous_pointer)?;
            restore_skills_pointer(install_root, journal.previous_skills_pointer.as_deref())?;
        }
        if journal.service_owned {
            // A failed drain can leave a service stopped even though no pointer
            // changed; an explicit recovery rollback therefore always resumes it.
            service.reinstall(install_root)?;
        }
        journal.state = "rolled-back".to_string();
        write_journal(&journal_path, &journal)?;
        return Ok(EcosystemRollbackOutcome {
            transaction_id: transaction_id.to_string(),
            restored_pointer_sha256: journal.previous_pointer_sha256,
            journal_path: journal_path.to_string_lossy().into_owned(),
        });
    }
    if !matches!(journal.state.as_str(), "activated" | "finalized") {
        return Err(conflict(
            "journal-not-active",
            "update journal has no active pointer to roll back",
        ));
    }
    let active = read_pointer(install_root)?;
    if journal.activated_pointer_sha256.as_deref() != Some(sha256_hex(&active).as_str()) {
        return Err(conflict(
            "pointer-changed",
            "current pointer no longer belongs to this update transaction",
        ));
    }
    if journal.activated_pointer.as_deref() != Some(active.as_slice()) {
        return Err(refuse(
            "journal-invalid",
            "journal active pointer does not match its recorded digest",
        ));
    }
    let active_skills = read_optional_skills_pointer(install_root)?;
    if journal.activated_skills_pointer_sha256 != active_skills.as_deref().map(sha256_hex) {
        return Err(conflict(
            "skills-pointer-changed",
            "skills pointer no longer belongs to this update transaction",
        ));
    }
    verify_artifacts(install_root, &journal.previous_artifacts)?;
    verify_artifacts(install_root, &journal.previous_skill_files)?;
    if journal.service_owned {
        service.drain(install_root)?;
    }
    restore_pointer(install_root, &journal.previous_pointer)?;
    restore_skills_pointer(install_root, journal.previous_skills_pointer.as_deref())?;
    if journal.service_owned {
        if let Err(error) = service.reinstall(install_root) {
            restore_pointer(install_root, &active)?;
            restore_skills_pointer(install_root, active_skills.as_deref())?;
            return Err(recover_service_failure(
                install_root,
                &journal_path,
                &mut journal,
                service,
                error,
            ));
        }
    }
    journal.state = "rolled-back".to_string();
    write_journal(&journal_path, &journal)?;
    Ok(EcosystemRollbackOutcome {
        transaction_id: transaction_id.to_string(),
        restored_pointer_sha256: journal.previous_pointer_sha256,
        journal_path: journal_path.to_string_lossy().into_owned(),
    })
}

fn require_pointer_path(plan: &EcosystemUpdatePlan, root: &Path) -> Result<(), AxiomError> {
    if Path::new(&plan.ecosystem.rollback.current_pointer) != root.join("current") {
        return Err(refuse(
            "pointer-path",
            "ecosystem update may only mutate its install-root current pointer",
        ));
    }
    Ok(())
}
fn portable_transaction(value: &str) -> Result<(), AxiomError> {
    if graph_core::paths::is_portable_id(value) {
        Ok(())
    } else {
        Err(refuse("transaction-id", "transaction id is not portable"))
    }
}
fn checked(root: &Path, relative: &str) -> Result<PathBuf, AxiomError> {
    crate::install::ecosystem_uninstall::checked_path(root, relative)
}
fn read_pointer(root: &Path) -> Result<Vec<u8>, AxiomError> {
    fs::read(checked(root, "current")?).map_err(|e| io("pointer-read", e))
}
fn read_optional_skills_pointer(root: &Path) -> Result<Option<Vec<u8>>, AxiomError> {
    match fs::read(checked(root, "skills/current")?) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io("skills-pointer-read", error)),
    }
}
fn journal_path(root: &Path, transaction: &str) -> Result<PathBuf, AxiomError> {
    portable_transaction(transaction)?;
    checked(
        root,
        &format!("journal/{JOURNAL_PREFIX}{transaction}{JOURNAL_SUFFIX}"),
    )
}
fn refuse_incomplete_journal(root: &Path) -> Result<(), AxiomError> {
    let directory = checked(root, "journal")?;
    if !directory.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(directory).map_err(|error| io("journal-directory", error))? {
        let entry = entry.map_err(|error| io("journal-directory", error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(JOURNAL_PREFIX) || !name.ends_with(JOURNAL_SUFFIX) {
            continue;
        }
        let path = checked(root, &format!("journal/{name}"))?;
        let journal: Journal =
            serde_json::from_slice(&fs::read(path).map_err(|error| io("journal-read", error))?)
                .map_err(|_| {
                    refuse(
                        "journal-invalid",
                        "existing ecosystem update journal is malformed",
                    )
                })?;
        if !matches!(journal.state.as_str(), "finalized" | "rolled-back") {
            return Err(conflict(
                "recovery-required",
                "an earlier ecosystem update needs recovery before a new transaction",
            ));
        }
    }
    Ok(())
}
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), AxiomError> {
    let parent = path
        .parent()
        .ok_or_else(|| refuse("path", "update file has no parent"))?;
    fs::create_dir_all(parent).map_err(|e| io("mkdir", e))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|e| io("temp", e))?;
    temp.write_all(bytes).map_err(|e| io("write", e))?;
    temp.as_file().sync_all().map_err(|e| io("sync", e))?;
    temp.persist(path).map_err(|e| io("rename", e.error))?;
    Ok(())
}
fn write_journal(path: &Path, journal: &Journal) -> Result<(), AxiomError> {
    write_atomic(
        path,
        &serde_json::to_vec_pretty(journal)
            .map_err(|_| refuse("journal-invalid", "journal is not serialisable"))?,
    )
}
fn restore_pointer(root: &Path, bytes: &[u8]) -> Result<(), AxiomError> {
    write_atomic(&checked(root, "current")?, bytes)
}
fn restore_skills_pointer(root: &Path, bytes: Option<&[u8]>) -> Result<(), AxiomError> {
    let path = checked(root, "skills/current")?;
    match bytes {
        Some(bytes) => write_atomic(&path, bytes),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io("skills-pointer-remove", error)),
        },
    }
}
fn recover_service_failure(
    root: &Path,
    journal_path: &Path,
    journal: &mut Journal,
    service: &impl ServiceLifecycle,
    primary: AxiomError,
) -> AxiomError {
    // Before activation the pointer already names the original generation.  A
    // drain failure still needs a best-effort resume and a durable journal that
    // tells the next operator exactly where recovery stopped.
    journal.state = "service-recovery-required".to_string();
    let persisted = write_journal(journal_path, journal).err();
    if journal.service_owned {
        if let Err(recovery) = service.reinstall(root) {
            return primary
                .with_detail("recovery", recovery.message())
                .with_detail("journal", journal_path.to_string_lossy());
        }
    }
    if let Some(error) = persisted {
        return primary
            .with_detail("recovery", error.message())
            .with_detail("journal", journal_path.to_string_lossy());
    }
    primary.with_detail("journal", journal_path.to_string_lossy())
}
fn recover_after_activation(
    root: &Path,
    journal_path: &Path,
    journal: &mut Journal,
    service: &impl ServiceLifecycle,
    primary: AxiomError,
) -> AxiomError {
    let pointer_restore = restore_pointer(root, &journal.previous_pointer);
    let skills_restore = restore_skills_pointer(root, journal.previous_skills_pointer.as_deref());
    journal.state = "restored-after-service-failure".to_string();
    let persisted = write_journal(journal_path, journal).err();
    let restarted = if journal.service_owned {
        service.reinstall(root).err()
    } else {
        None
    };
    let detail = pointer_restore
        .err()
        .or(skills_restore.err())
        .or(persisted)
        .or(restarted);
    match detail {
        Some(error) => primary
            .with_detail("recovery", error.message())
            .with_detail("journal", journal_path.to_string_lossy()),
        None => primary.with_detail("journal", journal_path.to_string_lossy()),
    }
}
fn skill_snapshot(root: &Path) -> Result<(Option<Vec<u8>>, Vec<PointerArtifact>), AxiomError> {
    let pointer_path = checked(root, "skills/current")?;
    let pointer = match fs::read(&pointer_path) {
        Ok(pointer) => pointer,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((None, Vec::new()))
        }
        Err(error) => return Err(io("skills-pointer-read", error)),
    };
    let value: Value = serde_json::from_slice(&pointer)
        .map_err(|_| refuse("skills-pointer-invalid", "skills pointer is not JSON"))?;
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| refuse("skills-pointer-invalid", "skills pointer has no version"))?;
    if graph_core::paths::validate_portable_relative_path(version).is_err() {
        return Err(refuse(
            "skills-pointer-invalid",
            "skills pointer version is unsafe",
        ));
    }
    let directory = checked(root, &format!("skills/{version}"))?;
    let files = tree_artifacts(root, &directory)?;
    Ok((Some(pointer), files))
}
fn tree_artifacts(root: &Path, directory: &Path) -> Result<Vec<PointerArtifact>, AxiomError> {
    if !directory.starts_with(root.join("skills")) || !directory.is_dir() {
        return Err(refuse(
            "skills-pointer-invalid",
            "skills pointer directory is invalid",
        ));
    }
    let mut pending = vec![directory.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).map_err(|error| io("skills-read-dir", error))? {
            let entry = entry.map_err(|error| io("skills-read-dir", error))?;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|error| io("skills-file-type", error))?;
            if kind.is_symlink() {
                return Err(refuse("skills-symlink", "skills snapshot refuses symlinks"));
            }
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                let bytes = fs::read(&path).map_err(|error| io("skills-read", error))?;
                files.push(PointerArtifact {
                    destination: path.to_string_lossy().into_owned(),
                    sha256: sha256_hex(&bytes),
                });
            }
        }
    }
    files.sort_by(|left, right| left.destination.cmp(&right.destination));
    Ok(files)
}
fn pointer_artifacts(root: &Path, pointer: &[u8]) -> Result<Vec<PointerArtifact>, AxiomError> {
    let value: Value = serde_json::from_slice(pointer)
        .map_err(|_| refuse("pointer-invalid", "current pointer is not JSON"))?;
    let rows = value
        .get("activated")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            refuse(
                "pointer-invalid",
                "current pointer has no activated artifacts",
            )
        })?;
    let mut artifacts = Vec::new();
    for row in rows {
        let destination = row
            .get("destination")
            .and_then(Value::as_str)
            .ok_or_else(|| refuse("pointer-invalid", "pointer artifact has no destination"))?;
        let digest = row
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| refuse("pointer-invalid", "pointer artifact has no digest"))?;
        if !is_digest(digest) || !Path::new(destination).starts_with(root.join("versions")) {
            return Err(refuse(
                "pointer-invalid",
                "pointer artifact escapes versioned install root",
            ));
        }
        artifacts.push(PointerArtifact {
            destination: destination.to_string(),
            sha256: digest.to_string(),
        });
    }
    if artifacts.is_empty() {
        return Err(refuse(
            "pointer-invalid",
            "current pointer has no activated artifacts",
        ));
    }
    verify_artifacts(root, &artifacts)?;
    Ok(artifacts)
}
fn verify_artifacts(root: &Path, artifacts: &[PointerArtifact]) -> Result<(), AxiomError> {
    for artifact in artifacts {
        let path = Path::new(&artifact.destination);
        let relative = path.strip_prefix(root).map_err(|_| {
            refuse(
                "previous-artifact-path",
                "retained artifact escapes the installation root",
            )
        })?;
        let checked =
            crate::install::ecosystem_uninstall::checked_path(root, &relative.to_string_lossy())?;
        if sha256_hex(&fs::read(checked).map_err(|e| io("previous-artifact-read", e))?)
            != artifact.sha256
        {
            return Err(conflict(
                "previous-artifact-changed",
                "retained previous payload does not match its recorded digest",
            ));
        }
    }
    Ok(())
}
fn stage_core_payloads(root: &Path, plan: &EcosystemPlan) -> Result<(), AxiomError> {
    for entry in plan.component_plans.iter().take(2) {
        let mut body = entry.plan.clone();
        let object = body
            .as_object_mut()
            .ok_or_else(|| refuse("core-plan", "core plan is not an object"))?;
        for key in crate::plan::DIGEST_EXCLUDED {
            object.remove(key);
        }
        let child: InstallPlan = serde_json::from_value(body)
            .map_err(|_| refuse("core-plan", "core plan is invalid"))?;
        let component = child
            .components
            .first()
            .ok_or_else(|| refuse("core-plan", "core plan has no component"))?;
        if child.components.len() != 1 {
            return Err(refuse("core-plan", "core plan has multiple components"));
        }
        let bytes = fs::read(&component.source.location).map_err(|e| io("bundle-read", e))?;
        if bytes.len() as u64 != component.source.size_bytes
            || sha256_hex(&bytes) != component.source.sha256
        {
            return Err(conflict(
                "bundle-changed",
                "bundle payload no longer matches approved ecosystem plan",
            ));
        }
        let destination = Path::new(&component.staged_destination);
        let relative = destination
            .strip_prefix(root)
            .map_err(|_| refuse("staging-path", "staging path escapes install root"))?;
        let destination = checked(root, &relative.to_string_lossy())?;
        let parent = destination
            .parent()
            .ok_or_else(|| refuse("staging-path", "staging path has no parent"))?;
        fs::create_dir_all(parent).map_err(|e| io("staging-mkdir", e))?;
        fs::write(destination, bytes).map_err(|e| io("staging-write", e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use tempfile::TempDir;

    use crate::install::ecosystem::SatisfiedProbe;
    use crate::install::plan::{
        ArtifactKind, BundleComponent, BundleManifest, BUNDLE_SCHEMA_VERSION,
    };
    use crate::skills::install::{DeclaredEntry, SkillBundle};

    const GRAPHD: &[u8] = b"new graphd";
    const MCP: &[u8] = b"new mcp";
    const SKILL: &[u8] = b"new skill\n";

    struct Service {
        owned: bool,
        drains: Cell<u8>,
        reinstalls: Cell<u8>,
        fail_drain: Cell<bool>,
        fail_reinstall: Cell<bool>,
    }
    impl Service {
        fn owned() -> Self {
            Self {
                owned: true,
                drains: Cell::new(0),
                reinstalls: Cell::new(0),
                fail_drain: Cell::new(false),
                fail_reinstall: Cell::new(false),
            }
        }
    }
    impl ServiceLifecycle for Service {
        fn is_owned(&self, _: &Path) -> Result<bool, AxiomError> {
            Ok(self.owned)
        }
        fn drain(&self, _: &Path) -> Result<(), AxiomError> {
            self.drains.set(self.drains.get() + 1);
            if self.fail_drain.replace(false) {
                Err(conflict(
                    "service-drain-failed",
                    "test service drain failed",
                ))
            } else {
                Ok(())
            }
        }
        fn reinstall(&self, _: &Path) -> Result<(), AxiomError> {
            self.reinstalls.set(self.reinstalls.get() + 1);
            if self.fail_reinstall.replace(false) {
                Err(conflict("service-failed", "test service failed"))
            } else {
                Ok(())
            }
        }
    }

    fn component(
        name: &str,
        version: &str,
        artifact: &str,
        kind: ArtifactKind,
        payload: &[u8],
    ) -> BundleComponent {
        BundleComponent {
            component: name.to_string(),
            version: version.to_string(),
            host: crate::install::plan::host_identifier(),
            artifact: artifact.to_string(),
            kind,
            sha256: sha256_hex(payload),
            size_bytes: payload.len() as u64,
            permissions: if kind == ArtifactKind::Binary {
                vec!["read".to_string(), "execute".to_string()]
            } else {
                vec!["read".to_string()]
            },
            service: None,
            network_access: vec![],
        }
    }
    fn setup() -> (TempDir, TempDir, EcosystemUpdatePlan) {
        let install = tempfile::tempdir().unwrap();
        let bundle = tempfile::tempdir().unwrap();
        let root = install.path();
        let old = root.join("versions/1.0.0/bin/axiom-graphd");
        fs::create_dir_all(old.parent().unwrap()).unwrap();
        fs::write(&old, b"old graphd").unwrap();
        let pointer = serde_json::json!({"schema_version":1,"activated":[{"destination":old,"sha256":sha256_hex(b"old graphd")} ]});
        fs::write(root.join("current"), serde_json::to_vec(&pointer).unwrap()).unwrap();
        let manifest = BundleManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            bundle_id: "core".to_string(),
            channel: "stable".to_string(),
            created_at: "2026-09-22T00:00:00Z".to_string(),
            components: vec![
                component(
                    "axiom-graphd",
                    "2.0.0",
                    "bin/axiom-graphd",
                    ArtifactKind::Binary,
                    GRAPHD,
                ),
                component(
                    "axiom-mcp",
                    "1.5.0",
                    "python/axiom-mcp.whl",
                    ArtifactKind::Python,
                    MCP,
                ),
            ],
        };
        fs::create_dir_all(bundle.path().join("bin")).unwrap();
        fs::create_dir_all(bundle.path().join("python")).unwrap();
        fs::write(bundle.path().join("bin/axiom-graphd"), GRAPHD).unwrap();
        fs::write(bundle.path().join("python/axiom-mcp.whl"), MCP).unwrap();
        fs::write(
            bundle.path().join("bundle.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let skills = bundle.path().join("skills");
        fs::create_dir_all(skills.join("payload/instructions")).unwrap();
        let entry = DeclaredEntry::new(
            "instructions/skill.md",
            "instruction",
            sha256_hex(SKILL),
            SKILL.len() as u64,
        );
        let declaration = SkillBundle::new("2.0.0", "a".repeat(40), "b".repeat(40), vec![entry]);
        fs::write(
            skills.join("bundle.json"),
            declaration.manifest_bytes().unwrap(),
        )
        .unwrap();
        fs::write(skills.join("payload/instructions/skill.md"), SKILL).unwrap();
        let runtime_host = crate::install::plan::host_identifier();
        let context = EcosystemContext::new(
            "update-plan",
            "2026-09-22T00:00:00Z",
            &runtime_host,
            root.to_string_lossy(),
        );
        let plan = super::plan(&SatisfiedProbe, bundle.path(), &context, "2.0.0").unwrap();
        assert_eq!(plan.ecosystem.component_plans[0].version, "2.0.0");
        assert_eq!(plan.ecosystem.component_plans[1].version, "1.5.0");
        (install, bundle, plan)
    }

    #[test]
    fn apply_and_rollback_restore_the_bound_pointer_with_real_filesystem() {
        let (install, _bundle, plan) = setup();
        let root = install.path();
        let before = fs::read(root.join("current")).unwrap();
        let service = Service::owned();
        let applied = apply(
            &plan,
            &plan.plan_digest,
            "update-20260922-1",
            "2026-09-22T00:01:00Z",
            &service,
        )
        .unwrap();
        let active = fs::read(root.join("current")).unwrap();
        assert_ne!(active, before);
        assert!(root.join("skills/current").is_file());
        assert!(Path::new(&applied.journal_path).is_file());
        assert_eq!(service.drains.get(), 1);
        assert_eq!(service.reinstalls.get(), 1);
        let rollback = super::rollback(root, "update-20260922-1", &service).unwrap();
        assert_eq!(fs::read(root.join("current")).unwrap(), before);
        assert!(!root.join("skills/current").exists());
        assert_eq!(rollback.restored_pointer_sha256, sha256_hex(&before));
        assert_eq!(service.drains.get(), 2);
        assert_eq!(service.reinstalls.get(), 2);
    }

    #[test]
    fn pointer_change_after_plan_is_refused_before_service_or_staging() {
        let (install, _bundle, plan) = setup();
        fs::write(
            install.path().join("current"),
            b"different reviewed pointer",
        )
        .unwrap();
        let service = Service::owned();
        let error = apply(
            &plan,
            &plan.plan_digest,
            "update-20260922-2",
            "2026-09-22T00:01:00Z",
            &service,
        )
        .unwrap_err();
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("pointer-changed")
        );
        assert_eq!(service.drains.get(), 0);
        assert_eq!(service.reinstalls.get(), 0);
    }

    #[test]
    fn failed_reinstall_restores_pointer_and_records_recovery() {
        let (install, _bundle, plan) = setup();
        let root = install.path();
        let before = fs::read(root.join("current")).unwrap();
        let service = Service::owned();
        service.fail_reinstall.set(true);
        assert!(apply(
            &plan,
            &plan.plan_digest,
            "update-20260922-3",
            "2026-09-22T00:01:00Z",
            &service
        )
        .is_err());
        assert_eq!(fs::read(root.join("current")).unwrap(), before);
        let journal =
            fs::read_to_string(root.join("journal/ecosystem-update-update-20260922-3.json"))
                .unwrap();
        assert!(journal.contains("restored-after-service-failure"));
    }

    #[test]
    fn stage_failure_after_drain_preserves_pointer_and_resumes_service() {
        let (install, bundle, plan) = setup();
        let before = fs::read(install.path().join("current")).unwrap();
        fs::write(bundle.path().join("bin/axiom-graphd"), b"tampered").unwrap();
        let service = Service::owned();
        let error = apply(
            &plan,
            &plan.plan_digest,
            "update-20260922-4",
            "2026-09-22T00:01:00Z",
            &service,
        )
        .unwrap_err();
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("bundle-changed")
        );
        assert_eq!(fs::read(install.path().join("current")).unwrap(), before);
        assert_eq!(service.drains.get(), 1);
        assert_eq!(service.reinstalls.get(), 1);
    }

    #[test]
    fn rollback_refuses_tampered_retained_payload_before_service_drain() {
        let (install, _bundle, plan) = setup();
        let root = install.path();
        let service = Service::owned();
        apply(
            &plan,
            &plan.plan_digest,
            "update-20260922-5",
            "2026-09-22T00:01:00Z",
            &service,
        )
        .unwrap();
        fs::write(
            root.join("versions/1.0.0/bin/axiom-graphd"),
            b"tampered old",
        )
        .unwrap();
        let error = rollback(root, "update-20260922-5", &service).unwrap_err();
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("previous-artifact-changed")
        );
        assert_eq!(
            service.drains.get(),
            1,
            "rollback must not drain after retained-byte failure"
        );
    }

    #[test]
    fn drain_failure_keeps_pointer_and_records_a_recovery_journal() {
        let (install, _bundle, plan) = setup();
        let before = fs::read(install.path().join("current")).unwrap();
        let service = Service::owned();
        service.fail_drain.set(true);
        assert!(apply(
            &plan,
            &plan.plan_digest,
            "update-20260922-6",
            "2026-09-22T00:01:00Z",
            &service,
        )
        .is_err());
        assert_eq!(fs::read(install.path().join("current")).unwrap(), before);
        assert_eq!(service.drains.get(), 1);
        assert_eq!(
            service.reinstalls.get(),
            1,
            "failed drain is resumed explicitly"
        );
        let journal = fs::read_to_string(
            install
                .path()
                .join("journal/ecosystem-update-update-20260922-6.json"),
        )
        .unwrap();
        assert!(journal.contains("service-recovery-required"));
    }

    #[test]
    fn incomplete_recovery_journal_blocks_a_second_transaction_before_drain() {
        let (install, _bundle, plan) = setup();
        let service = Service::owned();
        service.fail_drain.set(true);
        assert!(apply(
            &plan,
            &plan.plan_digest,
            "update-20260922-6",
            "2026-09-22T00:01:00Z",
            &service
        )
        .is_err());
        let error = apply(
            &plan,
            &plan.plan_digest,
            "update-20260922-7",
            "2026-09-22T00:01:00Z",
            &service,
        )
        .unwrap_err();
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("recovery-required")
        );
        assert_eq!(service.drains.get(), 1);
        rollback(install.path(), "update-20260922-6", &service).unwrap();
        apply(
            &plan,
            &plan.plan_digest,
            "update-20260922-7",
            "2026-09-22T00:01:00Z",
            &service,
        )
        .unwrap();
    }

    #[test]
    fn recovery_rollback_refuses_when_the_original_pointer_changed() {
        let (install, _bundle, plan) = setup();
        let service = Service::owned();
        service.fail_drain.set(true);
        assert!(apply(
            &plan,
            &plan.plan_digest,
            "update-20260922-9",
            "2026-09-22T00:01:00Z",
            &service,
        )
        .is_err());
        fs::write(install.path().join("current"), b"foreign pointer").unwrap();
        let error = rollback(install.path(), "update-20260922-9", &service).unwrap_err();
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("pointer-changed")
        );
    }

    #[test]
    fn foreign_runtime_host_is_refused() {
        let actual = crate::install::plan::host_identifier();
        let foreign = if actual == "macos-x64" {
            "linux-x64"
        } else {
            "macos-x64"
        };
        let error = verify_runtime_host(foreign).unwrap_err();
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("host-mismatch")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_current_is_refused_without_touching_the_external_target() {
        use std::os::unix::fs::symlink;
        let (install, _bundle, plan) = setup();
        let external = tempfile::NamedTempFile::new().unwrap();
        fs::write(external.path(), b"external pointer bytes").unwrap();
        fs::remove_file(install.path().join("current")).unwrap();
        symlink(external.path(), install.path().join("current")).unwrap();
        let service = Service::owned();
        assert!(apply(
            &plan,
            &plan.plan_digest,
            "update-20260922-8",
            "2026-09-22T00:01:00Z",
            &service
        )
        .is_err());
        assert_eq!(
            fs::read(external.path()).unwrap(),
            b"external pointer bytes"
        );
        assert_eq!(service.drains.get(), 0);
    }
}
