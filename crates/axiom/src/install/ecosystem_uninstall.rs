//! Approval-bound removal of recorded ecosystem runtime files (ADR-0014).
//!
//! Activation journals are the ownership source. Plans never authorize arbitrary
//! paths, and edited files survive removal. Recovery records remain after uninstall.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::locks::{LockMode, SolutionGuard};
use graph_export::sha256_hex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::apply::AppliedInstall;

const RECOVERY: &str = "uninstall-recovery-v1.json";
const REPORT: &str = "uninstall-report.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRecord {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema_version: u32,
    kind: String,
    install_root: String,
    host: String,
    pointer_sha256: String,
    skills_pointer_sha256: Option<String>,
    ownership: Vec<FileRecord>,
    runtime: Vec<FileRecord>,
    service_sha256: Option<String>,
    preserve: Vec<String>,
    plan_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recovery {
    schema_version: u32,
    plan: Plan,
    service_removed: bool,
    removed: Vec<String>,
    preserved: Vec<String>,
    complete: bool,
}

fn refuse(rule: &str) -> AxiomError {
    AxiomError::new(ErrorCode::Conflict, "ecosystem uninstall refused").with_detail("rule", rule)
}

fn io(error: std::io::Error) -> AxiomError {
    AxiomError::new(
        if error.kind() == std::io::ErrorKind::NotFound {
            ErrorCode::NotFound
        } else {
            ErrorCode::Internal
        },
        "ecosystem uninstall filesystem operation failed",
    )
    .with_detail("observed", error.to_string())
}

fn digest(plan: &Plan) -> Result<String, AxiomError> {
    let mut value = serde_json::to_value(plan).map_err(|_| refuse("plan-invalid"))?;
    value
        .as_object_mut()
        .ok_or_else(|| refuse("plan-invalid"))?
        .remove("plan_digest");
    graph_export::canonical::canonical_document_value(&value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| refuse("plan-invalid"))
}

/// Resolve a recorded relative path without traversing a symlink or parent segment.
///
/// # Errors
/// Refuses absolute, traversing, symlinked or non-directory ancestor paths.
pub fn checked_path(root: &Path, relative: &str) -> Result<PathBuf, AxiomError> {
    if !root.is_absolute() || !fs::symlink_metadata(root).map_err(io)?.file_type().is_dir() {
        return Err(refuse("unsafe-install-root"));
    }
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(refuse("ownership-path-escape"));
    }
    let mut path = root.to_path_buf();
    for part in relative.components() {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(refuse("ownership-symlink")),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io(error)),
        }
    }
    Ok(path)
}

fn read(root: &Path, relative: &str) -> Result<Vec<u8>, AxiomError> {
    let path = checked_path(root, relative)?;
    let metadata = fs::metadata(&path).map_err(io)?;
    if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 {
        return Err(refuse("ownership-record-invalid"));
    }
    fs::read(path).map_err(io)
}

fn write_json(root: &Path, relative: &str, value: &impl Serialize) -> Result<(), AxiomError> {
    let path = checked_path(root, relative)?;
    let parent = path
        .parent()
        .ok_or_else(|| refuse("ownership-path-escape"))?;
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| refuse("report-invalid"))?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(io)?;
    file.write_all(&bytes).map_err(io)?;
    file.as_file().sync_all().map_err(io)?;
    file.persist(path).map_err(|error| io(error.error))?;
    Ok(())
}

/// Serialize installation/removal mutations using the same native lock file.
///
/// # Errors
/// Refuses unsafe roots or another active maintenance transaction.
pub fn maintenance_lock(root: &Path) -> Result<SolutionGuard, AxiomError> {
    let path = checked_path(root, "maintenance.lock")?;
    SolutionGuard::acquire(&path, LockMode::Exclusive).map_err(|_| refuse("maintenance-busy"))
}

/// Refuse installation over incomplete removal; retain completed removal evidence.
/// Call only while holding the maintenance lock.
///
/// # Errors
/// Refuses malformed or incomplete removal state and archive collisions.
pub fn prepare_install(root: &Path) -> Result<(), AxiomError> {
    let path = checked_path(root, RECOVERY)?;
    if !path.exists() {
        return Ok(());
    }
    let bytes = read(root, RECOVERY)?;
    let recovery: Recovery =
        serde_json::from_slice(&bytes).map_err(|_| refuse("recovery-invalid"))?;
    if recovery.schema_version != 1 || digest(&recovery.plan)? != recovery.plan.plan_digest {
        return Err(refuse("recovery-invalid"));
    }
    if !recovery.complete {
        return Err(refuse("uninstall-incomplete"));
    }
    let archive = checked_path(
        root,
        &format!("uninstall-completed-{}.json", recovery.plan.plan_digest),
    )?;
    if archive.exists() {
        if fs::read(&archive).map_err(io)? != bytes {
            return Err(refuse("recovery-archive-conflict"));
        }
        fs::remove_file(path).map_err(io)?;
    } else {
        fs::rename(path, archive).map_err(io)?;
    }
    Ok(())
}

fn normalize_artifact(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("already_present");
    }
    value
}

fn build(root: &Path) -> Result<Plan, AxiomError> {
    let pointer = read(root, "current")?;
    let current: Value = serde_json::from_slice(&pointer).map_err(|_| refuse("pointer-invalid"))?;
    let transaction = current
        .get("transaction_id")
        .and_then(Value::as_str)
        .ok_or_else(|| refuse("pointer-invalid"))?;
    if !graph_core::paths::is_portable_id(transaction) {
        return Err(refuse("pointer-invalid"));
    }
    let journal = checked_path(root, "journal")?;
    let mut ownership = Vec::new();
    let mut runtime = BTreeMap::new();
    let activated = current
        .get("activated")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| refuse("pointer-invalid"))?;
    let mut records = Vec::new();
    let mut transitions = Vec::new();
    for entry in fs::read_dir(journal).map_err(io)? {
        let entry = entry.map_err(io)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".json") || name.ends_with(".rollback.json") {
            continue;
        }
        let relative = format!("journal/{name}");
        let bytes = read(root, &relative)?;
        if let Ok(record) = serde_json::from_slice::<AppliedInstall>(&bytes) {
            if name != format!("{}.json", record.transaction_id)
                || Path::new(&record.pointer_path) != root.join("current")
                || record.schema_version != 1
            {
                return Err(refuse("ownership-record-invalid"));
            }
            records.push((relative, bytes, record));
        } else if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
            if value["kind"] == "ecosystem-update-journal" {
                let id = value["transaction_id"]
                    .as_str()
                    .ok_or_else(|| refuse("ownership-record-invalid"))?;
                if name != format!("ecosystem-update-{id}.json") {
                    return Err(refuse("ownership-record-invalid"));
                }
                let previous: Vec<u8> = serde_json::from_value(value["previous_pointer"].clone())
                    .map_err(|_| refuse("ownership-record-invalid"))?;
                if value["previous_pointer_sha256"] != sha256_hex(&previous) {
                    return Err(refuse("ownership-record-invalid"));
                }
                if !value["activated_pointer"].is_null() {
                    let active: Vec<u8> =
                        serde_json::from_value(value["activated_pointer"].clone())
                            .map_err(|_| refuse("ownership-record-invalid"))?;
                    if value["activated_pointer_sha256"] != sha256_hex(&active) {
                        return Err(refuse("ownership-record-invalid"));
                    }
                    transitions.push((relative, bytes, previous, active));
                }
            }
        }
    }
    // Only pointer-reachable activation history grants ownership. A stray
    // parseable journal cannot add an unrelated file to the deletion set.
    let mut pending = vec![pointer.clone()];
    let mut seen = std::collections::BTreeSet::new();
    let mut selected = std::collections::BTreeSet::new();
    let mut journal_artifacts = Vec::new();
    while let Some(bytes) = pending.pop() {
        let hash = sha256_hex(&bytes);
        if !seen.insert(hash) {
            continue;
        }
        if seen.len() > 10_000 {
            return Err(refuse("ownership-history-limit"));
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| refuse("pointer-invalid"))?;
        let members = value["activated"]
            .as_array()
            .ok_or_else(|| refuse("pointer-invalid"))?;
        let txn = value["transaction_id"]
            .as_str()
            .ok_or_else(|| refuse("pointer-invalid"))?;
        for (relative, record_bytes, record) in &records {
            let rows = record
                .activated
                .iter()
                .map(|artifact| {
                    serde_json::to_value(artifact)
                        .map(normalize_artifact)
                        .map_err(|_| refuse("ownership-record-invalid"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if rows.is_empty()
                || rows.iter().any(|row| {
                    !members
                        .iter()
                        .cloned()
                        .map(normalize_artifact)
                        .any(|member| member == *row)
                })
            {
                continue;
            }
            let connected = record.transaction_id == txn
                || record.activated.iter().all(|artifact| {
                    record.transaction_id == format!("{txn}-{}", artifact.component)
                });
            if connected {
                if let Some(previous) = &record.previous_pointer {
                    pending.push(previous.as_bytes().to_vec());
                }
            }
            if !selected.insert(relative.clone()) {
                continue;
            }
            ownership.push(FileRecord {
                path: relative.clone(),
                sha256: sha256_hex(record_bytes),
            });
            journal_artifacts.extend(rows);
            for artifact in &record.activated {
                let path = Path::new(&artifact.destination)
                    .strip_prefix(root)
                    .map_err(|_| refuse("ownership-path-escape"))?
                    .to_string_lossy()
                    .into_owned();
                if !path.starts_with("versions/") {
                    return Err(refuse("ownership-outside-runtime"));
                }
                checked_path(root, &path)?;
                if let Some(previous) = runtime.insert(path, artifact.sha256.clone()) {
                    if previous != artifact.sha256 {
                        return Err(refuse("ownership-hash-conflict"));
                    }
                }
            }
        }
        for (relative, record_bytes, previous, active) in &transitions {
            if bytes == *previous || bytes == *active {
                pending.push(previous.clone());
                pending.push(active.clone());
                if selected.insert(relative.clone()) {
                    ownership.push(FileRecord {
                        path: relative.clone(),
                        sha256: sha256_hex(record_bytes),
                    });
                }
            }
        }
    }
    if runtime.is_empty()
        || activated
            .iter()
            .cloned()
            .map(normalize_artifact)
            .any(|item| !journal_artifacts.contains(&item))
    {
        return Err(refuse("ownership-record-missing"));
    }
    let skills_pointer_sha256 = collect_skills(root, &mut ownership, &mut runtime)?;
    ownership.sort_by(|a, b| a.path.cmp(&b.path));
    let service_path = checked_path(root, "state/service-v1.json")?;
    let service_sha256 = if service_path.exists() {
        Some(sha256_hex(&read(root, "state/service-v1.json")?))
    } else {
        None
    };
    let mut plan = Plan {
        schema_version: 1,
        kind: "ecosystem-uninstall".into(),
        install_root: root.to_string_lossy().into_owned(),
        host: super::plan::host_identifier(),
        pointer_sha256: sha256_hex(&pointer),
        skills_pointer_sha256,
        ownership,
        runtime: runtime
            .into_iter()
            .map(|(path, sha256)| FileRecord { path, sha256 })
            .collect(),
        service_sha256,
        preserve: [
            "source",
            "annotations",
            "checkpoints",
            "instructions",
            "credentials",
            "unowned-or-edited-files",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        plan_digest: String::new(),
    };
    plan.plan_digest = digest(&plan)?;
    if read(root, "current")? != pointer {
        return Err(refuse("installed-state-changed"));
    }
    Ok(plan)
}

// Skill manifests authorize only their declared files, never recursive removal.
// Manifests remain as recovery evidence; edits and undeclared siblings survive.
fn collect_skills(
    root: &Path,
    ownership: &mut Vec<FileRecord>,
    runtime: &mut BTreeMap<String, String>,
) -> Result<Option<String>, AxiomError> {
    let pointer_path = checked_path(root, "skills/current")?;
    if !pointer_path.exists() {
        return Ok(None);
    }
    let bytes = read(root, "skills/current")?;
    let pointer: Value =
        serde_json::from_slice(&bytes).map_err(|_| refuse("skills-pointer-invalid"))?;
    let mut active_found = false;
    for entry in fs::read_dir(checked_path(root, "skills")?).map_err(io)? {
        let entry = entry.map_err(io)?;
        if !entry.file_type().map_err(io)?.is_dir() {
            continue;
        }
        let version = entry.file_name().to_string_lossy().into_owned();
        let manifest_path = format!("skills/{version}/bundle.json");
        if !checked_path(root, &manifest_path)?.exists() {
            continue;
        }
        let manifest = read(root, &manifest_path)?;
        let bundle: crate::skills::install::SkillBundle =
            serde_json::from_slice(&manifest).map_err(|_| refuse("skills-manifest-invalid"))?;
        bundle.validate()?;
        if bundle.version != version {
            return Err(refuse("skills-manifest-invalid"));
        }
        let directory = format!("skills/{version}");
        if pointer["directory"] == directory {
            if pointer["schema_version"] != 1
                || pointer["component"] != "skills"
                || pointer["version"] != bundle.version
                || pointer["manifest_sha256"] != sha256_hex(&manifest)
            {
                return Err(refuse("skills-pointer-invalid"));
            }
            active_found = true;
        }
        ownership.push(FileRecord {
            path: manifest_path,
            sha256: sha256_hex(&manifest),
        });
        for entry in bundle.entries {
            let path = format!("{directory}/{}", entry.path);
            checked_path(root, &path)?;
            runtime.insert(path, entry.sha256);
        }
    }
    if !active_found {
        return Err(refuse("skills-ownership-missing"));
    }
    Ok(Some(sha256_hex(&bytes)))
}

fn remove_pointers(root: &Path, plan: &Plan) -> Result<(), AxiomError> {
    for (path, expected) in [
        ("current", Some(&plan.pointer_sha256)),
        ("skills/current", plan.skills_pointer_sha256.as_ref()),
    ] {
        if let Some(expected) = expected {
            let target = checked_path(root, path)?;
            if target.exists() {
                if sha256_hex(&read(root, path)?) != *expected {
                    return Err(refuse("installed-state-changed"));
                }
                fs::remove_file(target).map_err(io)?;
            }
        }
    }
    Ok(())
}

/// Build a read-only removal plan from installed activation records.
///
/// # Errors
/// Refuses missing, inconsistent or unsafe ownership evidence.
pub fn plan(root: &Path) -> Result<Value, AxiomError> {
    serde_json::to_value(build(root)?).map_err(|_| refuse("plan-invalid"))
}

/// Apply an exact approved plan, preserving edits and recording recoverable progress.
/// The callback removes the verified owned service before any runtime file.
///
/// # Errors
/// Refuses changed approval/ownership or failed service removal before runtime deletion.
pub fn apply(
    root: &Path,
    document: Value,
    approval: &str,
    remove_service: impl FnOnce() -> Result<(), AxiomError>,
) -> Result<Value, AxiomError> {
    let plan: Plan = serde_json::from_value(document).map_err(|_| refuse("plan-invalid"))?;
    if plan.schema_version != 1
        || plan.kind != "ecosystem-uninstall"
        || digest(&plan)? != plan.plan_digest
    {
        return Err(refuse("plan_digest_mismatch"));
    }
    if approval != plan.plan_digest {
        return Err(refuse("approval_stale"));
    }
    if Path::new(&plan.install_root) != root || plan.host != super::plan::host_identifier() {
        return Err(refuse("host-or-root-mismatch"));
    }
    let recovery_path = checked_path(root, RECOVERY)?;
    let previous = if recovery_path.exists() {
        let recovery: Recovery = serde_json::from_slice(&read(root, RECOVERY)?)
            .map_err(|_| refuse("recovery-invalid"))?;
        if recovery.schema_version != 1 || recovery.plan != plan {
            return Err(refuse("other-uninstall-transaction"));
        }
        Some(recovery)
    } else {
        if build(root)? != plan {
            return Err(refuse("installed-state-changed"));
        }
        None
    };
    let _lock = maintenance_lock(root)?;
    let mut recovery = previous.unwrap_or(Recovery {
        schema_version: 1,
        plan: plan.clone(),
        service_removed: false,
        removed: Vec::new(),
        preserved: Vec::new(),
        complete: false,
    });
    if recovery.complete {
        remove_pointers(root, &plan)?;
        return Ok(json!({"status":"removed", "removed":recovery.removed,
            "preserved":recovery.preserved, "preserve":plan.preserve, "report":REPORT}));
    }
    // A recovery document is not a second source of deletion authority. Rebuild
    // the runtime set from the still-retained activation records on every retry.
    let observed = build(root)?;
    if observed.runtime != plan.runtime
        || observed.ownership != plan.ownership
        || observed.pointer_sha256 != plan.pointer_sha256
        || observed.skills_pointer_sha256 != plan.skills_pointer_sha256
    {
        return Err(refuse("installed-state-changed"));
    }
    // Ownership records remain immutable throughout recovery; retry cannot acquire new paths.
    for record in &plan.ownership {
        if sha256_hex(&read(root, &record.path)?) != record.sha256 {
            return Err(refuse("ownership-record-changed"));
        }
    }
    if sha256_hex(&read(root, "current")?) != plan.pointer_sha256 {
        return Err(refuse("installed-state-changed"));
    }
    write_json(root, RECOVERY, &recovery)?;
    write_json(root, REPORT, &recovery)?;
    if !recovery.service_removed {
        if let Some(expected) = &plan.service_sha256 {
            let state = checked_path(root, "state/service-v1.json")?;
            if state.exists() && sha256_hex(&read(root, "state/service-v1.json")?) != *expected {
                return Err(refuse("service-state-changed"));
            }
            remove_service()?;
        }
        recovery.service_removed = true;
        write_json(root, RECOVERY, &recovery)?;
    }
    if sha256_hex(&read(root, "current")?) != plan.pointer_sha256 {
        return Err(refuse("installed-state-changed"));
    }
    for record in &plan.runtime {
        if recovery.removed.contains(&record.path) || recovery.preserved.contains(&record.path) {
            continue;
        }
        let path = checked_path(root, &record.path)?;
        if path.exists() && sha256_hex(&fs::read(&path).map_err(io)?) != record.sha256 {
            recovery.preserved.push(record.path.clone());
        } else {
            if path.exists() {
                fs::remove_file(path).map_err(io)?;
            }
            recovery.removed.push(record.path.clone());
        }
        write_json(root, RECOVERY, &recovery)?;
    }
    recovery.complete = true;
    // Keep the ownership pointer with the report until durable completion is recorded.
    write_json(root, REPORT, &recovery)?;
    write_json(root, RECOVERY, &recovery)?;
    remove_pointers(root, &plan)?;
    Ok(json!({"status":"removed", "removed":recovery.removed,
        "preserved":recovery.preserved, "preserve":plan.preserve, "report":REPORT}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::apply::ActivatedArtifact;

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("temp");
        let root = dir.path().join("ecosystem");
        fs::create_dir_all(root.join("versions/core/0.1.0")).expect("versions");
        fs::create_dir(root.join("journal")).expect("journal");
        let executable = root.join("versions/core/0.1.0/axiom-graphd");
        fs::write(&executable, b"owned-binary").expect("binary");
        let artifact = ActivatedArtifact {
            component: "axiom-graphd".into(),
            version: "0.1.0".into(),
            artifact: "axiom-graphd".into(),
            sha256: sha256_hex(b"owned-binary"),
            destination: executable.to_string_lossy().into_owned(),
            already_present: false,
        };
        let applied = AppliedInstall {
            schema_version: 1,
            transaction_id: "txn-one".into(),
            plan_id: "plan-one".into(),
            plan_digest: "a".repeat(64),
            applied_at: "2026-09-22T00:00:00Z".into(),
            activated: vec![artifact],
            pointer_path: root.join("current").to_string_lossy().into_owned(),
            journal_path: root
                .join("journal/txn-one.json")
                .to_string_lossy()
                .into_owned(),
            rollback_path: root
                .join("journal/txn-one.json.rollback.json")
                .to_string_lossy()
                .into_owned(),
            previous_pointer: None,
            keeps_previous_versions: 1,
        };
        fs::write(
            root.join("journal/txn-one.json"),
            serde_json::to_vec(&applied).expect("record"),
        )
        .expect("journal");
        fs::write(
            root.join("current"),
            super::super::apply::pointer_document(
                &applied.plan_id,
                &applied.plan_digest,
                &applied.transaction_id,
                &applied.applied_at,
                &applied.activated,
            )
            .expect("pointer"),
        )
        .expect("write");
        fs::write(root.join("human.txt"), b"human-data").expect("human");
        fs::write(root.join("versions/human-note.txt"), b"not-owned").expect("unowned");
        (dir, root)
    }

    fn approved(document: &Value) -> String {
        document["plan_digest"].as_str().expect("digest").to_owned()
    }

    #[test]
    fn exact_approved_removal_preserves_unowned_data_and_is_retryable() {
        let (_temp, root) = fixture();
        let document = plan(&root).expect("plan");
        let digest = approved(&document);
        let first =
            apply(&root, document.clone(), &digest, || panic!("no service")).expect("apply");
        assert!(!root.join("versions/core/0.1.0/axiom-graphd").exists());
        assert!(!root.join("current").exists());
        assert_eq!(
            fs::read(root.join("human.txt")).expect("human"),
            b"human-data"
        );
        assert_eq!(
            fs::read(root.join("versions/human-note.txt")).expect("unowned"),
            b"not-owned"
        );
        assert!(root.join(REPORT).exists());
        assert_eq!(
            apply(&root, document, &digest, || panic!("retry service")).expect("retry"),
            first
        );
    }

    #[test]
    fn aggregate_pointer_matches_component_journals_without_parent_journal() {
        let (_temp, root) = fixture();
        let mut pointer: Value =
            serde_json::from_slice(&fs::read(root.join("current")).unwrap()).unwrap();
        pointer["transaction_id"] = json!("aggregate-parent");
        fs::write(root.join("current"), serde_json::to_vec(&pointer).unwrap()).unwrap();
        let document = plan(&root).expect("aggregate ownership");
        apply(&root, document.clone(), &approved(&document), || Ok(())).unwrap();
        assert!(!root.join("current").exists());
    }

    #[test]
    fn unrecorded_active_pointer_member_refuses_removal() {
        let (_temp, root) = fixture();
        let mut pointer: Value =
            serde_json::from_slice(&fs::read(root.join("current")).unwrap()).unwrap();
        pointer["activated"][0]["sha256"] = json!("b".repeat(64));
        fs::write(root.join("current"), serde_json::to_vec(&pointer).unwrap()).unwrap();
        assert!(plan(&root).is_err());
        assert!(root.join("versions/core/0.1.0/axiom-graphd").exists());
    }

    #[test]
    fn skills_removal_preserves_edited_and_undeclared_files() {
        use crate::skills::install::{DeclaredEntry, SkillBundle};
        let (_temp, root) = fixture();
        let skills = root.join("skills/0.1.0");
        fs::create_dir_all(skills.join("demo")).unwrap();
        let bundle = SkillBundle::new(
            "0.1.0",
            "a".repeat(40),
            "b".repeat(40),
            vec![
                DeclaredEntry::new("demo/one.md", "reference", sha256_hex(b"one"), 3),
                DeclaredEntry::new("demo/two.md", "reference", sha256_hex(b"two"), 3),
            ],
        );
        let manifest = bundle.manifest_bytes().expect("manifest");
        fs::write(skills.join("bundle.json"), &manifest).unwrap();
        fs::write(skills.join("demo/one.md"), b"one").unwrap();
        fs::write(skills.join("demo/two.md"), b"two").unwrap();
        fs::write(skills.join("human.md"), b"human").unwrap();
        fs::write(
            root.join("skills/current"),
            serde_json::to_vec(&json!({
                "schema_version":1,"component":"skills","version":"0.1.0",
                "directory":"skills/0.1.0","manifest_sha256":sha256_hex(&manifest)
            }))
            .unwrap(),
        )
        .unwrap();
        let document = plan(&root).unwrap();
        fs::write(skills.join("demo/two.md"), b"human edit").unwrap();
        apply(&root, document.clone(), &approved(&document), || Ok(())).unwrap();
        assert!(!skills.join("demo/one.md").exists());
        assert_eq!(fs::read(skills.join("demo/two.md")).unwrap(), b"human edit");
        assert!(skills.join("human.md").exists());
        assert!(skills.join("bundle.json").exists());
        assert!(!root.join("skills/current").exists());
        apply(&root, document.clone(), &approved(&document), || Ok(())).unwrap();
    }

    #[test]
    fn reinstall_archives_completed_removal_but_refuses_incomplete_removal() {
        let (_temp, root) = fixture();
        let document = plan(&root).unwrap();
        let parsed: Plan = serde_json::from_value(document.clone()).unwrap();
        let recovery = Recovery {
            schema_version: 1,
            plan: parsed,
            service_removed: false,
            removed: vec![],
            preserved: vec![],
            complete: false,
        };
        write_json(&root, RECOVERY, &recovery).unwrap();
        assert!(prepare_install(&root).is_err());
        apply(&root, document.clone(), &approved(&document), || Ok(())).unwrap();
        prepare_install(&root).unwrap();
        assert!(!root.join(RECOVERY).exists());
        assert!(root
            .join(format!("uninstall-completed-{}.json", approved(&document)))
            .exists());
        assert!(root.join(REPORT).exists());
    }

    #[test]
    fn injected_unreachable_journal_cannot_authorize_a_user_file() {
        let (_temp, root) = fixture();
        let mut record: AppliedInstall =
            serde_json::from_slice(&fs::read(root.join("journal/txn-one.json")).unwrap()).unwrap();
        record.transaction_id = "unrelated".into();
        record.activated[0].destination = root
            .join("versions/human-note.txt")
            .to_string_lossy()
            .into_owned();
        record.activated[0].sha256 = sha256_hex(b"not-owned");
        fs::write(
            root.join("journal/unrelated.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let document = plan(&root).unwrap();
        apply(&root, document.clone(), &approved(&document), || Ok(())).unwrap();
        assert_eq!(
            fs::read(root.join("versions/human-note.txt")).unwrap(),
            b"not-owned"
        );
    }

    #[test]
    fn altered_approval_and_body_refuse_before_any_recovery_write() {
        let (_temp, root) = fixture();
        let mut document = plan(&root).expect("plan");
        let digest = approved(&document);
        assert!(apply(&root, document.clone(), &"0".repeat(64), || Ok(())).is_err());
        document["runtime"][0]["path"] = json!("human.txt");
        assert!(apply(&root, document, &digest, || Ok(())).is_err());
        assert!(!root.join(RECOVERY).exists());
        assert!(root.join("versions/core/0.1.0/axiom-graphd").exists());
    }

    #[test]
    fn human_edit_after_plan_is_preserved_and_reported() {
        let (_temp, root) = fixture();
        let document = plan(&root).expect("plan");
        let digest = approved(&document);
        let path = root.join("versions/core/0.1.0/axiom-graphd");
        fs::write(&path, b"human-edited").expect("edit");
        let report = apply(&root, document, &digest, || Ok(())).expect("apply");
        assert_eq!(fs::read(path).expect("preserved"), b"human-edited");
        assert_eq!(
            report["preserved"],
            json!(["versions/core/0.1.0/axiom-graphd"])
        );
    }

    #[test]
    fn failed_service_removal_keeps_payloads_and_retry_finishes() {
        let (_temp, root) = fixture();
        fs::create_dir(root.join("state")).expect("state");
        fs::write(root.join("state/service-v1.json"), b"owned-service").expect("service");
        let document = plan(&root).expect("plan");
        let digest = approved(&document);
        assert!(apply(&root, document.clone(), &digest, || Err(refuse(
            "backend-failed"
        )))
        .is_err());
        assert!(root.join("versions/core/0.1.0/axiom-graphd").exists());
        assert!(root.join(REPORT).exists());
        apply(&root, document, &digest, || Ok(())).expect("retry");
        assert!(!root.join("versions/core/0.1.0/axiom-graphd").exists());
    }

    #[test]
    fn replaced_ownership_is_refused_before_removal() {
        let (_temp, root) = fixture();
        let document = plan(&root).expect("plan");
        let digest = approved(&document);
        fs::write(root.join("journal/txn-one.json"), b"changed").expect("change");
        assert!(apply(&root, document, &digest, || Ok(())).is_err());
        assert!(root.join("versions/core/0.1.0/axiom-graphd").exists());
    }

    #[test]
    #[cfg(unix)]
    fn linked_owned_payload_does_not_authorize_deleting_target() {
        let (_temp, root) = fixture();
        let document = plan(&root).expect("plan");
        let digest = approved(&document);
        let path = root.join("versions/core/0.1.0/axiom-graphd");
        fs::remove_file(&path).expect("replace");
        std::os::unix::fs::symlink(root.join("human.txt"), path).expect("link");
        assert!(apply(&root, document, &digest, || Ok(())).is_err());
        assert_eq!(
            fs::read(root.join("human.txt")).expect("human"),
            b"human-data"
        );
    }
}
