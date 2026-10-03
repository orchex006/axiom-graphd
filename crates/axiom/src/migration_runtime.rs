//! K-310: native adapter for the existing pure migration engine.
//!
//! Plans inventory immutable, validated graph generations in the current
//! repository. They never copy a live database, rewrite human instructions or
//! remove legacy files. Unsupported/unowned input is a conflict, never READY.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use axiom_migration as engine;
use graph_core::error::{AxiomError, ErrorCode};
use graph_core::locks::{LockMode, SolutionGuard};
use graph_core::paths::{AxiomHome, PathEnvironment};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const ROOTS: [&str; 3] = [
    engine::LEGACY_GRAPH_DIR,
    engine::LEGACY_MISSPELLED_GRAPH_DIR,
    engine::AXIOM_GRAPH_DIR,
];
const MAX_FILES: usize = 16_384;
const MAX_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    path: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    status: String,
    migration_scope: String,
    target_layout: u32,
    changes: Vec<Value>,
    required_free_bytes: u64,
    target_core: crate::version::VersionReport,
    solution_id: String,
    root: String,
    created_epoch_seconds: i64,
    ttl_seconds: i64,
    sources: Vec<Source>,
    selected_source: Option<String>,
    migration_needed: bool,
    engine_digest: String,
    plan_digest: String,
    transaction: String,
}

fn error(code: ErrorCode, rule: &str, detail: impl ToString) -> AxiomError {
    AxiomError::new(code, format!("migration {rule}: {}", detail.to_string()))
        .with_detail("rule", rule)
}

fn io_error(e: impl ToString) -> AxiomError {
    error(ErrorCode::Internal, "filesystem", e)
}

fn conflict(e: impl ToString) -> AxiomError {
    error(ErrorCode::Conflict, "MIGRATION_CONFLICT", e)
}

fn now() -> Result<i64, AxiomError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io_error)?
            .as_secs(),
    )
    .map_err(io_error)
}

fn spelling(path: &Path) -> Result<String, AxiomError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| conflict("non UTF-8 path"))
}

fn linked(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn safe_path(root: &Path, relative: &str) -> Result<PathBuf, AxiomError> {
    graph_core::paths::validate_portable_relative_path(relative)?;
    let mut path = root.to_path_buf();
    for part in relative.split('/') {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(meta) if linked(&meta) => return Err(conflict("link/junction in migration path")),
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(io_error(e)),
        }
    }
    Ok(path)
}

fn walk(
    root: &Path,
    rel: &str,
    files: &mut BTreeMap<String, Vec<u8>>,
    total: &mut u64,
    nodes: &mut usize,
) -> Result<(), AxiomError> {
    *nodes += 1;
    if *nodes > MAX_FILES * 2 || rel.split('/').count() > 128 {
        return Err(conflict("directory inventory budget"));
    }
    let path = safe_path(root, rel)?;
    let meta = fs::symlink_metadata(&path).map_err(io_error)?;
    if meta.is_dir() {
        for entry in fs::read_dir(&path).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| conflict("non UTF-8 name"))?;
            if name == "solution.lock" {
                continue;
            }
            walk(root, &format!("{rel}/{name}"), files, total, nodes)?;
        }
    } else if meta.is_file() {
        *total = total
            .checked_add(meta.len())
            .ok_or_else(|| conflict("input size overflow"))?;
        if files.len() >= MAX_FILES || *total > MAX_BYTES {
            return Err(conflict("inventory budget"));
        }
        files.insert(rel.to_owned(), fs::read(path).map_err(io_error)?);
    } else {
        return Err(conflict("non regular input"));
    }
    Ok(())
}

fn inventory(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, AxiomError> {
    let mut files = BTreeMap::new();
    let mut total = 0;
    let mut nodes = 0;
    for rel in ROOTS {
        let p = safe_path(root, rel)?;
        if p.exists() {
            walk(root, rel, &mut files, &mut total, &mut nodes)?;
        }
    }
    let mut aliases = BTreeSet::new();
    for path in files.keys() {
        let key = axiom_platform::PathKey::new(path).map_err(|e| e.to_axiom_error())?;
        if !aliases.insert(key.collision_key()) {
            return Err(conflict("case-colliding inputs"));
        }
    }
    Ok(files)
}

fn validate_snapshots(
    root: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    solution: &str,
) -> Result<(), AxiomError> {
    let mut owned = BTreeSet::new();
    for (path, bytes) in files {
        if !path.ends_with("/manifest.json") {
            continue;
        }
        let parent = path
            .strip_suffix("/manifest.json")
            .ok_or_else(|| conflict("manifest path"))?;
        let id = parent.rsplit('/').next().unwrap_or_default();
        if id != graph_export::sha256_hex(bytes) {
            return Err(conflict("generation digest"));
        }
        let value: Value = serde_json::from_slice(bytes).map_err(|e| conflict(e.to_string()))?;
        if value.get("solution_id").and_then(Value::as_str) != Some(solution) {
            return Err(conflict("solution identity differs"));
        }
        if value.get("projects").is_some() {
            let canonical = graph_export::canonical::canonical_document_value(&value)
                .map_err(|e| conflict(e.to_string()))?;
            let keys = [
                "analysis_profile",
                "coverage",
                "projects",
                "schema_version",
                "solution_id",
            ];
            if canonical != *bytes
                || value["schema_version"] != 1
                || value
                    .as_object()
                    .is_none_or(|o| o.len() != 5 || o.keys().any(|k| !keys.contains(&k.as_str())))
                || value["analysis_profile"].as_str().is_none_or(str::is_empty)
                || value["coverage"]
                    .as_str()
                    .is_none_or(|v| !graph_export::manifest::COVERAGE_STATUSES.contains(&v))
            {
                return Err(conflict("catalog schema/canonical bytes"));
            }
            let lane_root = Path::new(parent)
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| conflict("catalog path"))?;
            let lane = lane_root
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| conflict("catalog lane"))?;
            let solution_root = lane_root
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| conflict("catalog solution root"))?;
            let projects = value["projects"]
                .as_array()
                .ok_or_else(|| conflict("catalog projects"))?;
            if projects.is_empty() {
                return Err(conflict("empty catalog"));
            }
            let mut ids = BTreeSet::new();
            for member in projects {
                if member.as_object().is_none_or(|m| {
                    m.len() != 3
                        || m.keys().any(|k| {
                            !["project_id", "generation_id", "source_fingerprint"]
                                .contains(&k.as_str())
                        })
                }) {
                    return Err(conflict("closed catalog member schema"));
                }
                let project = member["project_id"]
                    .as_str()
                    .ok_or_else(|| conflict("project id"))?;
                let generation = member["generation_id"]
                    .as_str()
                    .ok_or_else(|| conflict("member generation"))?;
                if !graph_core::paths::is_portable_id(project) || !ids.insert(project) {
                    return Err(conflict("duplicate/unsafe catalog project"));
                }
                let mp = format!(
                    "{}/{project}/{lane}/generations/{generation}/manifest.json",
                    spelling(solution_root)?
                );
                let mb = files
                    .get(&mp)
                    .ok_or_else(|| conflict("catalog member missing"))?;
                if graph_export::sha256_hex(mb) != generation {
                    return Err(conflict("catalog member digest"));
                }
                let mv: Value = serde_json::from_slice(mb).map_err(|e| conflict(e.to_string()))?;
                if mv["project_id"] != project
                    || mv["source_fingerprint"] != member["source_fingerprint"]
                {
                    return Err(conflict("catalog member identity/fingerprint"));
                }
            }
        } else {
            let generation_dir = safe_path(root, parent)?;
            let manifest = graph_export::validate::read_manifest(&generation_dir)
                .map_err(|e| conflict(e.to_string()))?;
            for entry in &manifest.files {
                owned.insert(format!("{parent}/{}", entry.path));
            }
            graph_export::validate::validate_generation(&generation_dir)
                .map_err(|e| conflict(e.to_string()))?;
        }
        owned.insert(path.clone());
    }
    for (path, bytes) in files {
        if !path.ends_with("/current.json") {
            continue;
        }
        let parent = path
            .strip_suffix("/current.json")
            .ok_or_else(|| conflict("pointer path"))?;
        let pointer = graph_export::pointer::read(&safe_path(root, parent)?)
            .map_err(|e| conflict(e.to_string()))?
            .ok_or_else(|| conflict("pointer missing"))?;
        if graph_export::pointer::canonical_bytes(&pointer).map_err(|e| conflict(e.to_string()))?
            != *bytes
            || !files.contains_key(&format!(
                "{parent}/generations/{}/manifest.json",
                pointer.generation_id
            ))
        {
            return Err(conflict("pointer generation missing/corrupt"));
        }
        owned.insert(path.clone());
    }
    if files.keys().any(|p| !owned.contains(p)) {
        return Err(conflict("unowned/unvalidated graph files"));
    }
    Ok(())
}

fn make_engine(doc: &Document) -> Result<engine::MigrationPlan, AxiomError> {
    let decision = match doc.selected_source.as_deref() {
        Some(p) if p == ROOTS[0] => engine::DiscoveryDecision::Import {
            source: engine::LayoutId::LegacyGraph,
        },
        Some(p) if p == ROOTS[1] => engine::DiscoveryDecision::Import {
            source: engine::LayoutId::LegacyMisspelledGraph,
        },
        None => engine::DiscoveryDecision::Fresh,
        _ => return Err(conflict("unrecognised source root")),
    };
    let mut repo = engine::RepoPlan::new("root", decision).map_err(|e| e.to_axiom_error())?;
    for source in &doc.sources {
        repo.add_source(
            engine::SourceArtifact::new(&source.path, &source.sha256, source.size_bytes)
                .map_err(|e| e.to_axiom_error())?,
        )
        .map_err(|e| e.to_axiom_error())?;
        if doc.migration_needed {
            if let Some(selected) = &doc.selected_source {
                if let Some(suffix) = source.path.strip_prefix(&format!("{selected}/")) {
                    let destination = format!("{}/{suffix}", ROOTS[2]);
                    repo.add_change(
                        engine::DestinationChange::new(
                            &destination,
                            engine::ChangeAction::Create,
                            Some(&source.path),
                            engine::DestinationOwnership::Managed {
                                previous_sha256: None,
                            },
                        )
                        .map_err(|e| e.to_axiom_error())?,
                    )
                    .map_err(|e| e.to_axiom_error())?;
                }
            }
        }
    }
    engine::build_plan(
        &doc.solution_id,
        doc.created_epoch_seconds,
        doc.ttl_seconds,
        vec![repo],
    )
    .map_err(|e| e.to_axiom_error())
}

fn digest(doc: &Document) -> Result<String, AxiomError> {
    let mut body = serde_json::to_value(doc).map_err(io_error)?;
    if let Some(object) = body.as_object_mut() {
        object.remove("plan_digest");
        object.remove("transaction");
    }
    Ok(graph_export::sha256_hex(
        &graph_export::canonical::canonical_document_value(&body).map_err(io_error)?,
    ))
}

/// Create a read-only plan for this repository; writes only an explicitly named plan file.
pub fn plan(
    solution: &str,
    from: Option<&str>,
    layout: Option<&str>,
    out: Option<&str>,
) -> Result<Value, AxiomError> {
    if !graph_core::paths::is_portable_id(solution)
        || !matches!(from, None | Some("auto" | "legacy-v1"))
        || !matches!(layout, None | Some("2"))
    {
        return Err(error(
            ErrorCode::ValidationError,
            "arguments",
            "supported source auto/legacy-v1 and layout 2",
        ));
    }
    let root = fs::canonicalize(std::env::current_dir().map_err(io_error)?).map_err(io_error)?;
    let files = inventory(&root)?;
    validate_snapshots(&root, &files, solution)?;
    if root.join("AGENTS.md").is_file() {
        let instructions = fs::read(root.join("AGENTS.md")).map_err(io_error)?;
        if String::from_utf8_lossy(&instructions).contains("<!-- agrimap-graph:") {
            return Err(conflict(
                "legacy instruction ownership requires an explicit separate plan",
            ));
        }
    }
    let normalized = |prefix: &str| -> BTreeMap<String, String> {
        files
            .iter()
            .filter_map(|(p, b)| {
                p.strip_prefix(&format!("{prefix}/"))
                    .map(|suffix| (suffix.to_owned(), graph_export::sha256_hex(b)))
            })
            .collect()
    };
    let a = normalized(ROOTS[0]);
    let b = normalized(ROOTS[1]);
    let target = normalized(ROOTS[2]);
    if !a.is_empty() && !b.is_empty() && a != b {
        return Err(conflict("legacy graph/grahp differ"));
    }
    let selected = if !a.is_empty() {
        Some(ROOTS[0])
    } else if !b.is_empty() {
        Some(ROOTS[1])
    } else {
        None
    };
    let source = if !a.is_empty() { &a } else { &b };
    if !target.is_empty() && !source.is_empty() && target != *source {
        return Err(conflict("conflicting .axiom target"));
    }
    let mut doc = Document {
        schema_version: 1,
        status: "ready".to_owned(),
        migration_scope: "immutable_graph_import".to_owned(),
        target_layout: 2,
        changes: Vec::new(),
        required_free_bytes: 0,
        target_core: crate::version::VersionReport::cli(),
        solution_id: solution.to_owned(),
        root: spelling(&root)?,
        created_epoch_seconds: now()?,
        ttl_seconds: 3600,
        sources: files
            .into_iter()
            .map(|(path, bytes)| Source {
                path,
                sha256: graph_export::sha256_hex(&bytes),
                size_bytes: bytes.len() as u64,
            })
            .collect(),
        selected_source: selected.map(str::to_owned),
        migration_needed: selected.is_some() && target.is_empty(),
        engine_digest: String::new(),
        plan_digest: String::new(),
        transaction: String::new(),
    };
    let planned = make_engine(&doc)?;
    doc.engine_digest = planned.digest().as_str().to_owned();
    doc.changes = describe_changes(&doc, &planned)?;
    doc.required_free_bytes = required_bytes(&doc)?;
    doc.plan_digest = digest(&doc)?;
    doc.transaction = format!("migration-{}", &doc.plan_digest[..32]);
    let value = serde_json::to_value(&doc).map_err(io_error)?;
    if let Some(path) = out {
        // A read-only inventory never overwrites an existing human plan/file.
        atomic_write(
            Path::new(path),
            &serde_json::to_vec_pretty(&doc).map_err(io_error)?,
            false,
        )?;
    }
    Ok(value)
}

fn atomic_write(path: &Path, bytes: &[u8], replace: bool) -> Result<(), AxiomError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(io_error)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(io_error)?;
    temp.write_all(bytes).map_err(io_error)?;
    temp.as_file().sync_all().map_err(io_error)?;
    if replace {
        temp.persist(path).map_err(|e| io_error(e.error))?;
    } else {
        temp.persist_noclobber(path)
            .map_err(|e| io_error(e.error))?;
    }
    #[cfg(unix)]
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)?;
    Ok(())
}

fn describe_changes(
    doc: &Document,
    plan: &engine::MigrationPlan,
) -> Result<Vec<Value>, AxiomError> {
    plan.planned_writes()
        .iter()
        .map(|write| {
            let source = doc
                .sources
                .iter()
                .find(|s| Some(s.path.as_str()) == write.source())
                .ok_or_else(|| conflict("planned source missing"))?;
            Ok(json!({"destination": write.path(), "source": source.path,
                  "action": "create", "before_sha256": null, "after_sha256": source.sha256}))
        })
        .collect()
}

fn required_bytes(doc: &Document) -> Result<u64, AxiomError> {
    let mut bytes = 0u64;
    for source in &doc.sources {
        if doc.migration_needed
            && doc
                .selected_source
                .as_deref()
                .is_some_and(|p| source.path.starts_with(&format!("{p}/")))
        {
            bytes = bytes
                .checked_add(source.size_bytes)
                .ok_or_else(|| conflict("size overflow"))?;
        }
    }
    bytes
        .checked_mul(2)
        .ok_or_else(|| conflict("stage/cutover size overflow"))
}

struct NativeIo {
    root: PathBuf,
}
impl engine::ApplyIo for NativeIo {
    fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
        fs::read(safe_path(&self.root, path)?).map_err(io_error)
    }
    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError> {
        let destination = safe_path(&self.root, path)?;
        if destination.exists() {
            if fs::read(&destination).map_err(io_error)? == bytes {
                return Ok(());
            }
            return Err(conflict("existing owned/staging bytes differ"));
        }
        atomic_write(&destination, bytes, false)
    }
    fn remove(&self, path: &str) -> Result<(), AxiomError> {
        fs::remove_file(safe_path(&self.root, path)?).map_err(io_error)
    }
    fn exists(&self, path: &str) -> bool {
        safe_path(&self.root, path)
            .map(|p| p.exists())
            .unwrap_or(true)
    }
}

struct Store {
    path: PathBuf,
}
impl engine::JournalStore for Store {
    fn load(&self) -> Result<Option<engine::ApplyJournal>, AxiomError> {
        match fs::read_to_string(&self.path) {
            Ok(text) => engine::ApplyJournal::parse(&text)
                .map(Some)
                .map_err(|e| e.to_axiom_error()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(e)),
        }
    }
    fn save(&self, journal: &engine::ApplyJournal) -> Result<(), AxiomError> {
        atomic_write(&self.path, journal.encode().as_bytes(), true)
    }
}

struct Fenced;
impl engine::WriterFence for Fenced {
    fn establish(&self, _namespace: &str) -> Result<engine::FenceOutcome, AxiomError> {
        Ok(engine::FenceOutcome::quiescent())
    }
}

fn load_document(path: &Path) -> Result<Document, AxiomError> {
    let bytes = fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            error(
                ErrorCode::NotFound,
                "plan",
                "no recorded migration plan at this path",
            )
        } else {
            io_error(e)
        }
    })?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(conflict("plan budget"));
    }
    let doc: Document = serde_json::from_slice(&bytes)
        .map_err(|e| error(ErrorCode::ValidationError, "plan-shape", e))?;
    if doc.schema_version != 1
        || doc.status != "ready"
        || doc.migration_scope != "immutable_graph_import"
        || doc.target_layout != 2
        || doc.target_core != crate::version::VersionReport::cli()
        || doc.plan_digest != digest(&doc)?
        || doc.plan_digest.len() != 64
        || doc.transaction != format!("migration-{}", &doc.plan_digest[..32])
        || doc.engine_digest != make_engine(&doc)?.digest().as_str()
    {
        return Err(conflict("plan hash or identity"));
    }
    if doc.changes != describe_changes(&doc, &make_engine(&doc)?)?
        || doc.required_free_bytes != required_bytes(&doc)?
    {
        return Err(conflict(
            "reviewed destination/space inventory differs from the engine plan",
        ));
    }
    let hashes = |prefix: &str| -> BTreeMap<String, String> {
        doc.sources
            .iter()
            .filter_map(|s| {
                s.path
                    .strip_prefix(&format!("{prefix}/"))
                    .map(|suffix| (suffix.to_owned(), s.sha256.clone()))
            })
            .collect()
    };
    let a = hashes(ROOTS[0]);
    let b = hashes(ROOTS[1]);
    let target = hashes(ROOTS[2]);
    let selected = if !a.is_empty() {
        Some(ROOTS[0])
    } else if !b.is_empty() {
        Some(ROOTS[1])
    } else {
        None
    };
    let source = if !a.is_empty() { &a } else { &b };
    if (!a.is_empty() && !b.is_empty() && a != b)
        || (!target.is_empty() && !source.is_empty() && target != *source)
        || doc.selected_source.as_deref() != selected
        || doc.migration_needed != (selected.is_some() && target.is_empty())
    {
        return Err(conflict(
            "plan discovery decision does not follow its immutable inputs",
        ));
    }
    Ok(doc)
}

/// Apply, inspect or roll back an exact approved native transaction.
pub fn operate(
    action: &str,
    plan_path: Option<&str>,
    transaction: Option<&str>,
    approval: Option<&str>,
) -> Result<Value, AxiomError> {
    let environment = PathEnvironment::for_current_process();
    let home = AxiomHome::resolve(&environment)?;
    let doc = if let Some(path) = plan_path {
        load_document(Path::new(path))?
    } else {
        let id = transaction.ok_or_else(|| conflict("transaction missing"))?;
        if !graph_core::paths::is_portable_id(id) {
            return Err(conflict("unsafe transaction id"));
        }
        load_document(&safe_path(
            home.root(),
            &format!("update-journal/migrations/{id}/plan.json"),
        )?)?
    };
    let root = fs::canonicalize(std::env::current_dir().map_err(io_error)?).map_err(io_error)?;
    if spelling(&root)? != doc.root {
        return Err(conflict("plan belongs to another repository"));
    }
    let tx = safe_path(
        home.root(),
        &format!("update-journal/migrations/{}", doc.transaction),
    )?;
    let store = Store {
        path: tx.join("journal.txt"),
    };
    if action == "status" {
        use engine::JournalStore;
        let journal = store
            .load()?
            .ok_or_else(|| error(ErrorCode::NotFound, "transaction", "not applied"))?;
        return Ok(
            json!({"status": journal.phase().as_str(), "transaction": doc.transaction,
                         "plan_digest": doc.plan_digest, "files": journal.files().len()}),
        );
    }
    if approval != Some(doc.plan_digest.as_str()) {
        return Err(error(
            ErrorCode::Forbidden,
            "approval",
            "explicit exact plan digest required",
        ));
    }
    let resolved = axiom_platform::state_root::ensure_state_root(
        &environment,
        &axiom_platform::state_root::NativeStateRootProbe,
    )?;
    // Windows canonicalization uses the kernel's extended path prefix. Keep
    // the already validated lexical home for public path policy, after proving
    // that it resolves to the same owner-private directory the probe checked.
    if fs::canonicalize(home.root()).map_err(io_error)? != resolved.root() {
        return Err(conflict(
            "state home identity changed during ownership verification",
        ));
    }
    // Reuse the daemon's actual OS claim, not an assertion that the writer is stopped.
    let _daemon = axiom_graphd::instance_lock::DaemonLock::acquire(&home, "migration")?;
    fs::create_dir_all(&tx).map_err(io_error)?;
    let _transaction = SolutionGuard::acquire(&tx.join("transaction.lock"), LockMode::Exclusive)
        .map_err(|e| conflict(e.to_string()))?;
    let engine = make_engine(&doc)?;
    let mut current = engine::CurrentSources::new();
    let actual = inventory(&root)?;
    let sources: BTreeMap<_, _> = actual
        .iter()
        .filter(|(path, _)| !doc.migration_needed || !path.starts_with(&format!("{}/", ROOTS[2])))
        .map(|(path, bytes)| (path.clone(), bytes.clone()))
        .collect();
    validate_snapshots(&root, &sources, &doc.solution_id)?;
    let mut guards = Vec::new();
    let mut pointer_paths: BTreeSet<String> = sources
        .keys()
        .filter(|p| p.ends_with("/current.json"))
        .cloned()
        .collect();
    pointer_paths.extend(
        engine
            .planned_writes()
            .iter()
            .filter(|p| p.path().ends_with("/current.json"))
            .map(|p| p.path().to_owned()),
    );
    for path in &pointer_paths {
        let lane = Path::new(path)
            .parent()
            .ok_or_else(|| conflict("lane guard path"))?;
        let lock = safe_path(&root, &format!("{}/solution.lock", spelling(lane)?))?;
        if let Some(parent) = lock.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        guards.push(
            SolutionGuard::acquire(&lock, LockMode::Exclusive)
                .map_err(|e| conflict(e.to_string()))?,
        );
    }
    if doc.migration_needed && action == "apply" {
        use engine::JournalStore;
        let journal = store.load()?;
        let allowed: BTreeMap<_, _> = engine
            .planned_writes()
            .iter()
            .map(|write| {
                let hash = doc
                    .sources
                    .iter()
                    .find(|s| Some(s.path.as_str()) == write.source())
                    .map(|s| s.sha256.clone())
                    .unwrap_or_default();
                (write.path().to_owned(), hash)
            })
            .collect();
        for (path, bytes) in actual
            .iter()
            .filter(|(p, _)| p.starts_with(&format!("{}/", ROOTS[2])))
        {
            if journal.is_none() || allowed.get(path) != Some(&graph_export::sha256_hex(bytes)) {
                return Err(conflict(
                    "target appeared or changed outside the owned journal",
                ));
            }
        }
    }
    // V2 output created by this transaction is not a new legacy input on resume.
    for (path, bytes) in actual {
        if doc.migration_needed && path.starts_with(&format!("{}/", ROOTS[2])) {
            continue;
        }
        current
            .observe("root", &path, &graph_export::sha256_hex(&bytes))
            .map_err(|e| e.to_axiom_error())?;
    }
    let backup = format!(".axiom/tmp/{}/backup", doc.transaction);
    let staging = format!(".axiom/tmp/{}/stage", doc.transaction);
    let request = engine::ApplyRequest {
        plan: &engine,
        reviewed_digest: &doc.engine_digest,
        current: &current,
        now_seconds: now()?,
        namespace: &doc.solution_id,
        backup_root: &backup,
        staging_root: &staging,
    };
    let io = NativeIo { root };
    if action == "apply" {
        engine
            .apply(&doc.engine_digest, &current, request.now_seconds)
            .map_err(|e| e.to_axiom_error())?;
        let saved = tx.join("plan.json");
        if saved.exists() {
            if load_document(&saved)?.plan_digest != doc.plan_digest {
                return Err(conflict("foreign transaction"));
            }
        } else {
            atomic_write(&saved, &serde_json::to_vec(&doc).map_err(io_error)?, false)?;
        }
        let result = engine::apply_journaled(&request, &Fenced, &io, &store)
            .map_err(|e| e.to_axiom_error())?;
        validate_snapshots(&io.root, &inventory(&io.root)?, &doc.solution_id)?;
        Ok(
            json!({"status": result.status().as_str(), "readiness": "ready", "transaction": doc.transaction,
                  "files": result.files(), "plan_digest": doc.plan_digest}),
        )
    } else if action == "rollback" {
        let result =
            engine::rollback_journaled(&request, &io, &store).map_err(|e| e.to_axiom_error())?;
        Ok(
            json!({"status": result.status().as_str(), "transaction": doc.transaction,
                  "removed": result.removed(), "restored": result.restored()}),
        )
    } else {
        Err(error(
            ErrorCode::ValidationError,
            "action",
            "unknown migration action",
        ))
    }
}
