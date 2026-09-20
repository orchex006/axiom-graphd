//! The foreground daemon: inventory, analyse, publish (task H-002).
//!
//! Before this task `serve` took the single-owner instance lock, logged a line
//! and answered `NOT_READY`: the command modules and the library crates existed,
//! but nothing bound the store, the registry, the watcher policy and the export
//! lane into a running worker. This module is that binding. It drives the
//! bounded pipeline the contract requires:
//!
//! 1. **inventory** - resolve every registered project through the binding
//!    table, plan the inventory with the ignore and input policies, and apply it
//!    through the generation-aware file writer (`graph_store::files`);
//! 2. **analyse** - read each dirty file, run the pinned per-language
//!    declaration analyzer and replace that file's facts
//!    (`graph_store::graph_rows`);
//! 3. **stage** - render the project's records as one canonical document and
//!    stage it under `<lane>/.staging/<id>`, which is never reader-visible;
//! 4. **publish** - seal the staging directory, write its manifest, then take
//!    the exclusive solution guard for the whole publication barrier: install
//!    the generation under `<lane>/generations/<generation-id>/` and move
//!    `current.json` last, so a reader sees either the previous generation or
//!    the complete new one, never a half-written one.
//!
//! The lifecycle is bounded by [`ShutdownToken`]. Every unit of work claims the
//! token first, so a cooperative shutdown stops the loop at a file boundary
//! rather than mid-write, and a claimed unit is drained before the process
//! returns. The four documented lifecycle steps are: claim, drain, report, exit.
//!
//! A verb that cannot finish still answers a truthful `NOT_READY`; nothing in
//! this module reports success while having published nothing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use graph_analyze::adapter::Language;
use graph_core::bindings::{resolve_binding, resolve_project_root, CatalogRepoReference};
use graph_core::config::ServiceConfig;
use graph_core::error::{AxiomError, ErrorCode};
use graph_core::locks::{default_lock_path, LockMode, SolutionGuard};
use graph_core::paths::AxiomHome;
use graph_export::manifest::ManifestHeader;
use graph_export::staging::StagingLayout;
use graph_export::{pointer, reader, recovery};
use graph_store::files::{ack_generation, apply_inventory, ObservedFile};
use graph_store::graph_rows::{EdgeFact, EdgeTarget, GraphFactSet, NodeFact};
use graph_store::outbox::{self, AnalysisCommit, Operation, OutboxState, PublishIntent};
use graph_watch::ignore::IgnorePolicy;
use graph_watch::input_policy::InputPolicy;
use graph_watch::inventory::{plan_inventory, KnownInventory, StdDirentSource};
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

use crate::instance_lock::DaemonLock;
use crate::lifecycle::ShutdownToken;
use crate::payload::{self, Payload};
use crate::runtime;
use crate::telemetry::{LogLevel, Telemetry};

/// What one project's pass changed and published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectOutcome {
    /// Solution the project belongs to.
    pub solution_id: String,
    /// Project id.
    pub project_id: String,
    /// Absolute root the project was resolved to.
    pub project_root: String,
    /// Live lane root the generation is published under.
    ///
    /// One publication writes the same generation into the live lane and the
    /// checkpoint lane, so this is the lane a query resolves.
    pub lane_root: String,
    /// Inventory generation this pass advanced the project to.
    pub inventory_generation: i64,
    /// Paths observed for the first time.
    pub inventory_added: usize,
    /// Paths whose content digest changed.
    pub inventory_changed: usize,
    /// Paths newly tombstoned because the inventory no longer lists them.
    pub inventory_deleted: usize,
    /// Files whose facts were replaced in this pass.
    pub analyzed_files: usize,
    /// Nodes written for the project.
    pub nodes: usize,
    /// Edges written for the project.
    pub edges: usize,
    /// Whether a generation was published by this pass.
    pub published: bool,
    /// The generation published, when one was.
    pub generation_id: Option<String>,
    /// SHA-256 of the published manifest, when one was.
    pub manifest_hash: Option<String>,
    /// The generation `current.json` points at after this pass.
    pub current_generation: Option<String>,
}

/// The report one bounded foreground pass produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServeReport {
    /// Instance id the lock was taken for.
    pub instance_id: String,
    /// Registered solutions considered.
    pub solutions: usize,
    /// Projects reconciled.
    pub projects: usize,
    /// Dirty files before the pass.
    pub dirty_before: i64,
    /// Dirty files after the pass.
    pub dirty_after: i64,
    /// Generations published by this pass.
    pub published_generations: usize,
    /// Recovery actions taken before publishing, one per project that needed one.
    pub recoveries: Vec<String>,
    /// Per-project outcomes, in solution then project id order.
    pub outcomes: Vec<ProjectOutcome>,
    /// The documented lifecycle step the loop ended in.
    pub shutdown: String,
}

/// Which registered work one bounded pass covers.
#[derive(Debug, Clone, Default)]
struct Selection {
    solution: Option<String>,
    project: Option<String>,
}

/// Run one bounded reconcile pass over every registered solution.
///
/// # Errors
///
/// * [`ErrorCode::WriterAlreadyRunning`] when a foreground daemon already holds
///   the instance lock, which is the documented refusal for a second `serve`;
/// * [`ErrorCode::ConfigInvalid`] naming the missing bindings document when a
///   registered project cannot be resolved;
/// * the store, inventory, analysis and publication errors of the pipeline.
pub fn serve(config: &ServiceConfig, telemetry: &mut Telemetry) -> Result<ServeReport, AxiomError> {
    let home = AxiomHome::resolve(&graph_core::paths::PathEnvironment::for_current_process())?;
    home.verify_destination()?;
    let lock = DaemonLock::acquire(&home, config.daemon().instance_id())?;
    let _ = telemetry.record(
        LogLevel::Info,
        "daemon",
        "instance lock acquired; running one bounded reconcile pass",
    );
    let token = ShutdownToken::generate(Duration::from_millis(
        config.runtime().shutdown_deadline_ms(),
    ));
    let report = run_bounded(config, &home, &token, &Selection::default())?;
    drop(lock);
    Ok(report)
}

/// Run one bounded reconcile pass for a single solution.
///
/// `reconcile` is the one-shot form of the same worker: when no foreground
/// daemon holds the instance lock it performs the pass itself, which is what
/// makes the documented bounded barrier observable without a daemon.
///
/// # Errors
///
/// The same errors as [`serve`].
pub fn reconcile(
    config: &ServiceConfig,
    solution_id: &str,
    project: Option<&str>,
    telemetry: &mut Telemetry,
) -> Result<ServeReport, AxiomError> {
    let home = AxiomHome::resolve(&graph_core::paths::PathEnvironment::for_current_process())?;
    home.verify_destination()?;
    let lock = DaemonLock::acquire(&home, config.daemon().instance_id())?;
    let _ = telemetry.record(
        LogLevel::Info,
        "daemon",
        "instance lock acquired; running one bounded reconcile request",
    );
    let token = ShutdownToken::generate(Duration::from_millis(
        config.runtime().shutdown_deadline_ms(),
    ));
    let selection = Selection {
        solution: Some(solution_id.to_owned()),
        project: project.map(str::to_owned),
    };
    let report = run_bounded(config, &home, &token, &selection)?;
    drop(lock);
    Ok(report)
}

fn run_bounded(
    config: &ServiceConfig,
    home: &AxiomHome,
    token: &ShutdownToken,
    selection: &Selection,
) -> Result<ServeReport, AxiomError> {
    let mut store = runtime::open_store(config, home)?;
    graph_store::migrations::apply(store.connection_mut())?;

    let solutions = match selection.solution.as_deref() {
        Some(id) => vec![runtime::solution(store.connection(), id)?],
        None => runtime::solutions(store.connection())?,
    };
    let dirty_before = runtime::dirty_count(store.connection())?;

    let bindings = if solutions.is_empty() {
        Vec::new()
    } else {
        runtime::load_bindings(home)?
    };

    let mut recoveries = Vec::new();
    let mut outcomes = Vec::new();
    let mut published_generations = 0usize;

    for solution in &solutions {
        let projects = runtime::projects(store.connection(), &solution.id)?;
        let catalog: Vec<CatalogRepoReference> = projects
            .iter()
            .map(|project| CatalogRepoReference::new(project.repo_id.clone()))
            .collect();
        let mut scanned_every_project = true;
        for project in &projects {
            if let Some(only) = selection.project.as_deref() {
                if only != project.id {
                    scanned_every_project = false;
                    continue;
                }
            }
            let _claim = token.claim()?;
            let outcome = reconcile_project(
                config,
                store.connection_mut(),
                solution,
                project,
                ResolutionInputs {
                    bindings: &bindings,
                    catalog: &catalog,
                },
                token,
                &mut recoveries,
            )?;
            if outcome.published {
                published_generations += 1;
            }
            outcomes.push(outcome);
        }
        if scanned_every_project {
            runtime::clear_full_scan(store.connection(), &solution.id)?;
        }
        mark_solution_jobs_succeeded(store.connection_mut(), &solution.id)?;
    }

    let dirty_after = runtime::dirty_count(store.connection())?;
    let drain = token.drain_state(std::time::Instant::now());
    Ok(ServeReport {
        instance_id: config.daemon().instance_id().to_owned(),
        solutions: solutions.len(),
        projects: outcomes.len(),
        dirty_before,
        dirty_after,
        published_generations,
        recoveries,
        outcomes,
        shutdown: format!("{drain:?}"),
    })
}

/// Mark the durable queue rows a completed pass satisfied.
fn mark_solution_jobs_succeeded(
    connection: &mut Connection,
    solution_id: &str,
) -> Result<(), AxiomError> {
    connection
        .execute(
            "UPDATE jobs SET state = 'SUCCEEDED' WHERE solution_id = ?1 \
             AND state IN('PENDING','RETRY_WAIT') \
             AND kind IN('reconcile-dirty','reconcile-project','analyze-full')",
            [solution_id],
        )
        .map_err(|error| runtime::storage_error("job completion", &error))?;
    Ok(())
}

/// The binding and catalog inputs one project root is resolved from.
///
/// A `serve` pass builds the catalog from the same project rows it resolves
/// bindings for, so the two are carried together rather than as separate
/// positional arguments.
struct ResolutionInputs<'a> {
    bindings: &'a [graph_core::bindings::LocalBinding],
    catalog: &'a [CatalogRepoReference],
}

fn reconcile_project(
    config: &ServiceConfig,
    connection: &mut Connection,
    solution: &runtime::SolutionRow,
    project: &runtime::ProjectRow,
    resolution: ResolutionInputs<'_>,
    token: &ShutdownToken,
    recoveries: &mut Vec<String>,
) -> Result<ProjectOutcome, AxiomError> {
    let probe = runtime::symlink_probe();
    let resolved = resolve_binding(
        resolution.bindings,
        resolution.catalog,
        &project.repo_id,
        &probe,
    )?;
    let project_root = resolve_project_root(&resolved, &project.relative_path, &probe)?;
    let live_lane = runtime::live_root(&project_root, &solution.id, &project.id);
    let checkpoint_lane = runtime::checkpoint_root(&project_root, &solution.id, &project.id);
    let lane_display = live_lane.to_string_lossy().to_string();

    // Recovery runs before anything else writes, so a crashed publication is
    // completed or discarded rather than mistaken for a clean lane. Every lane
    // this pass publishes is recovered, so neither can be left half-published.
    for lane in [&live_lane, &checkpoint_lane] {
        let action = recovery::resume(lane, None).map_err(runtime::export_error)?;
        if !matches!(action, recovery::RecoveryAction::Nothing) {
            recoveries.push(format!("{}: {}", project.id, action.describe()));
        }
    }

    // Inventory is planned with the watcher's own ignore and input policies, so
    // the daemon and the watcher agree on what counts as source.
    let known = known_inventory(connection, &project.id)?;
    let plan = plan_inventory(
        &StdDirentSource,
        Path::new(&project_root),
        &known,
        &IgnorePolicy::new(".axiom"),
        &InputPolicy::new(project_root.clone()),
    )?;
    let observed: Vec<ObservedFile> = plan
        .observed_files(&known)
        .into_iter()
        .map(|(path, hash)| ObservedFile::new(path, hash))
        .collect();
    let highest: i64 = connection
        .query_row(
            "SELECT COALESCE(MAX(desired_generation), 0) FROM files WHERE project_id = ?1",
            [project.id.as_str()],
            |row| row.get(0),
        )
        .map_err(|error| runtime::storage_error("inventory generation", &error))?;
    let generation = highest + 1;
    let inventory = apply_inventory(connection, &project.id, generation, &observed)?;

    // Analysis: every file the inventory advanced, path order, so the pass is
    // deterministic and reproducible.
    let dirty = dirty_files(connection, &project.id)?;
    let mut analyzed = 0usize;
    for file in &dirty {
        let _claim = token.claim()?;
        if let Some(hash) = file.observed_hash.as_deref() {
            let absolute = Path::new(&project_root)
                .join(file.path.replace('/', std::path::MAIN_SEPARATOR_STR));
            let bytes = std::fs::read(&absolute).map_err(|error| {
                runtime::storage_error(
                    "analysis input",
                    &format!("{}: {error}", absolute.display()),
                )
            })?;
            let source = String::from_utf8_lossy(&bytes);
            let facts = analyze_file(&file.path, &source, &project.id);
            graph_store::graph_rows::replace_file_facts(connection, &project.id, file.id, &facts)?;
            analyzed += 1;
            ack_generation(connection, file.id, file.desired_generation, Some(hash))?;
        } else {
            // A tombstone: the file is gone, so its facts must go too.
            graph_store::graph_rows::replace_file_facts(
                connection,
                &project.id,
                file.id,
                &GraphFactSet::new(Vec::new(), Vec::new()),
            )?;
            ack_generation(connection, file.id, file.desired_generation, None)?;
        }
    }

    // The published payload is rendered from the same store rows the analyzers
    // wrote, in the frozen contract's own document shape.
    let payload = payload::render(connection, &project.id)?;
    let nodes = payload.nodes.len();
    let edges = payload.edges.len();

    let mut outcome = ProjectOutcome {
        solution_id: solution.id.clone(),
        project_id: project.id.clone(),
        project_root: project_root.clone(),
        lane_root: lane_display,
        inventory_generation: inventory.generation,
        inventory_added: inventory.added,
        inventory_changed: inventory.changed,
        inventory_deleted: inventory.deleted,
        analyzed_files: analyzed,
        nodes,
        edges,
        published: false,
        generation_id: None,
        manifest_hash: None,
        current_generation: None,
    };

    if payload.is_empty() {
        outcome.current_generation = current_generation(&live_lane)?;
        return Ok(outcome);
    }

    // Publish when there is new work, or when a previous pass analysed but did
    // not finish publishing (a lane has no pointer yet).
    let live_before = pointer::read(&live_lane).map_err(runtime::export_error)?;
    let checkpoint_before = pointer::read(&checkpoint_lane).map_err(runtime::export_error)?;
    let has_new_work = inventory.queued > 0 || analyzed > 0;
    if !has_new_work && live_before.is_some() && checkpoint_before.is_some() {
        outcome.current_generation = live_before.map(|pointer| pointer.generation_id);
        return Ok(outcome);
    }

    let published = publish(
        config,
        connection,
        solution,
        project,
        &live_lane,
        &checkpoint_lane,
        &payload,
    )?;
    outcome.published = true;
    outcome.generation_id = Some(published.generation_id);
    outcome.manifest_hash = Some(published.manifest_hash);
    outcome.current_generation = current_generation(&live_lane)?;
    Ok(outcome)
}

/// The identity of one published generation.
#[derive(Debug)]
struct PublishedGeneration {
    generation_id: String,
    manifest_hash: String,
}

/// Stage, seal and publish one generation under the exclusive guard.
fn publish(
    config: &ServiceConfig,
    connection: &mut Connection,
    solution: &runtime::SolutionRow,
    project: &runtime::ProjectRow,
    live_lane: &Path,
    checkpoint_lane: &Path,
    payload: &Payload,
) -> Result<PublishedGeneration, AxiomError> {
    let header = manifest_header(config, solution, project, payload)?;
    let live_layout = StagingLayout::new(live_lane.to_path_buf());
    let staging_id = format!("pending-{}-{}", solution.event_seq, project.id);
    let (generation_id, manifest_hash, content_dir) =
        stage_generation(&live_layout, &staging_id, payload, &header)?;

    // The revision and its durable publish intent are recorded before the
    // pointer could move, so a crash leaves a replayable row rather than a
    // generation nothing knows about.
    let intent_id = format!("ob-{}-{}", project.id, solution.event_seq);
    let intent_key = format!("{}-{}-{}", solution.id, project.id, solution.event_seq);
    outbox::commit_analysis_and_intent(
        connection,
        &AnalysisCommit {
            solution_id: solution.id.clone(),
            event_seq: solution.event_seq,
            profile: solution.profile.clone(),
            source_fingerprint: header.source_fingerprint.clone(),
            created_at: graph_store::migrations::utc_timestamp(),
        },
        &PublishIntent {
            id: intent_id.clone(),
            project_id: Some(project.id.clone()),
            operation: Operation::Project,
            idempotency_key: intent_key,
            generation_id: Some(generation_id.clone()),
        },
    )?;
    runtime::bump_event_seq(connection, &solution.id)?;

    // Both lanes carry the same content-addressed generation, so a reader of
    // either lane sees one generation and the two can never disagree. Both
    // generations are sealed before either pointer moves, so a failure while
    // sealing leaves every lane exactly as it was.
    let checkpoint_layout = StagingLayout::new(checkpoint_lane.to_path_buf());
    let (checkpoint_id, checkpoint_hash, checkpoint_dir) =
        stage_generation(&checkpoint_layout, &staging_id, payload, &header)?;
    if checkpoint_id != generation_id || checkpoint_hash != manifest_hash {
        return Err(runtime::storage_error(
            "lane publication",
            &format!(
                "the live lane sealed {generation_id} but the checkpoint lane sealed \
                 {checkpoint_id}; publishing divergent lanes is refused"
            ),
        ));
    }

    // Publication barrier: install the complete generation, then move the
    // pointer. Both happen under the exclusive solution guard, and the guard is
    // released before the outcome is recorded, so a slower reader never waits
    // behind a database write.
    // The live lane is what a query answers from; the checkpoint lane is the
    // tracked artifact the operator verbs read.
    publish_lane(live_lane, &live_layout, &generation_id, &content_dir)?;
    publish_lane(
        checkpoint_lane,
        &checkpoint_layout,
        &checkpoint_id,
        &checkpoint_dir,
    )?;

    outbox::mark(connection, &intent_id, OutboxState::Published, None)?;
    // Each lane is recorded with the generation and manifest digest it was
    // actually sealed from, so a reader of either lane resolves its own row.
    for (lane, lane_generation, lane_hash) in [
        (
            runtime::LIVE_LANE,
            generation_id.as_str(),
            manifest_hash.as_str(),
        ),
        (
            runtime::LANE,
            checkpoint_id.as_str(),
            checkpoint_hash.as_str(),
        ),
    ] {
        connection
            .execute(
                "INSERT OR IGNORE INTO published_generations(project_id, generation_id, \
                 revision_id, lane, manifest_hash, published_at) \
                 SELECT ?1, ?2, revision_id, ?3, ?4, ?5 FROM publish_outbox WHERE id = ?6",
                rusqlite::params![
                    project.id,
                    lane_generation,
                    lane,
                    lane_hash,
                    graph_store::migrations::utc_timestamp(),
                    intent_id
                ],
            )
            .map_err(|error| runtime::storage_error("published generation record", &error))?;
    }

    Ok(PublishedGeneration {
        generation_id,
        manifest_hash,
    })
}

/// Install one lane's sealed generation, then move that lane's pointer, both
/// under the exclusive solution guard.
///
/// The order is the whole point: a reader either sees the previous complete
/// pointer or the new one, and never a pointer that names a generation which is
/// not already readable.
fn publish_lane(
    lane: &Path,
    layout: &StagingLayout,
    generation_id: &str,
    content_dir: &Path,
) -> Result<(), AxiomError> {
    let guard = SolutionGuard::acquire(&default_lock_path(lane), LockMode::Exclusive)
        .map_err(runtime::guard_error)?;
    install_generation(layout, generation_id, content_dir)?;
    pointer::replace(
        lane,
        &pointer::CurrentPointer::new(generation_id.to_owned()),
        pointer::PointerStrategy::AtomicReplace,
    )
    .map_err(runtime::export_error)?;
    guard.release().map_err(runtime::guard_error)
}

/// Stage and seal one generation, then name its directory after the content id.
///
/// Every frozen reader -- `pointer::read`, `reader::load` and
/// `recovery::resume` -- addresses a generation by the id the manifest computes
/// for itself, and the pointer accepts only a lowercase sha256 of that length.
/// `seal()` computes the id but leaves the directory under the caller's staging
/// name, and it deliberately does not write `manifest.json`, so this function
/// finishes both steps while the directory is still unreadable.
///
/// The returned path is the sealed staging directory the caller must install.
fn stage_generation(
    layout: &StagingLayout,
    staging_id: &str,
    payload: &Payload,
    header: &ManifestHeader,
) -> Result<(String, String, PathBuf), AxiomError> {
    let mut staged = layout.begin(staging_id).map_err(runtime::export_error)?;
    // Only non-empty roles are published, and every shard is one canonical JSON
    // document at the fixed path the contract assigns to its role.
    if !payload.nodes.is_empty() {
        staged
            .write_records(NODES_SHARD, NODES_ROLE, &payload.nodes)
            .map_err(runtime::export_error)?;
    }
    if !payload.edges.is_empty() {
        staged
            .write_records(EDGES_SHARD, EDGES_ROLE, &payload.edges)
            .map_err(runtime::export_error)?;
    }
    let coverage = serde_json::to_value(&payload.coverage)
        .map_err(|error| runtime::storage_error("coverage document", &error))?;
    staged
        .write_document(COVERAGE_SHARD, COVERAGE_ROLE, &coverage)
        .map_err(runtime::export_error)?;
    let sealed = staged.seal(header.clone()).map_err(runtime::export_error)?;
    let generation_id = sealed.generation_id().to_owned();
    let manifest_bytes = sealed.manifest_bytes().map_err(runtime::export_error)?;
    let manifest_hash = graph_export::sha256_hex(&manifest_bytes);
    let staged_dir = layout.staging_dir(staging_id);
    std::fs::write(staged_dir.join(MANIFEST_NAME), &manifest_bytes)
        .map_err(|error| runtime::storage_error("manifest write", &error))?;
    let content_dir = layout.staging_dir(&generation_id);
    if content_dir != staged_dir {
        if content_dir.exists() {
            // The identical content-addressed generation is already staged from an
            // interrupted pass. Dropping the duplicate keeps recovery from
            // installing the same generation twice.
            let _ = std::fs::remove_dir_all(&staged_dir);
        } else {
            std::fs::rename(&staged_dir, &content_dir)
                .map_err(|error| runtime::storage_error("staging rename", &error))?;
        }
    }
    Ok((generation_id, manifest_hash, content_dir))
}

/// Move the sealed staging directory into its readable generation directory.
///
/// This is the first half of the publication barrier: the pointer must never
/// name a generation that is not completely readable. A generation directory is
/// never rewritten, because its name is the digest of its own content, so an
/// already-installed generation is left exactly as it is.
fn install_generation(
    layout: &StagingLayout,
    generation_id: &str,
    content_dir: &Path,
) -> Result<(), AxiomError> {
    let installed = layout.generation_dir(generation_id);
    if installed.exists() {
        let _ = std::fs::remove_dir_all(content_dir);
        return Ok(());
    }
    if let Some(parent) = installed.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| runtime::storage_error("generation directory", &error))?;
    }
    std::fs::rename(content_dir, &installed)
        .map_err(|error| runtime::storage_error("generation install", &error))
}

/// One dirty file row the worker must analyse.
struct DirtyFile {
    id: i64,
    path: String,
    observed_hash: Option<String>,
    desired_generation: i64,
}

fn dirty_files(connection: &Connection, project_id: &str) -> Result<Vec<DirtyFile>, AxiomError> {
    let mut statement = connection
        .prepare(
            "SELECT id, path, observed_hash, desired_generation FROM files \
             WHERE project_id = ?1 AND desired_generation > indexed_generation ORDER BY path",
        )
        .map_err(|error| runtime::storage_error("dirty file query", &error))?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok(DirtyFile {
                id: row.get(0)?,
                path: row.get(1)?,
                observed_hash: row.get(2)?,
                desired_generation: row.get(3)?,
            })
        })
        .map_err(|error| runtime::storage_error("dirty file query", &error))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|error| runtime::storage_error("dirty file row", &error))?);
    }
    Ok(out)
}

fn known_inventory(
    connection: &Connection,
    project_id: &str,
) -> Result<KnownInventory, AxiomError> {
    let mut statement = connection
        .prepare(
            "SELECT path, observed_hash FROM files \
             WHERE project_id = ?1 AND observed_hash IS NOT NULL",
        )
        .map_err(|error| runtime::storage_error("known inventory query", &error))?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|error| runtime::storage_error("known inventory query", &error))?;
    let mut pairs = Vec::new();
    for row in rows {
        pairs.push(row.map_err(|error| runtime::storage_error("known inventory row", &error))?);
    }
    Ok(KnownInventory::from_pairs(pairs))
}

/// The fixed shard path one project's nodes are staged under.
const NODES_SHARD: &str = "nodes/000000.json";
/// The role that path plays in the manifest.
const NODES_ROLE: &str = "nodes";
/// The fixed shard path one project's edges are staged under.
const EDGES_SHARD: &str = "edges/000000.json";
/// The role that path plays in the manifest.
const EDGES_ROLE: &str = "edges";
/// The single coverage document, at the generation root.
const COVERAGE_SHARD: &str = "coverage.json";
/// The role that path plays in the manifest.
const COVERAGE_ROLE: &str = "coverage";
/// The manifest file the frozen reader loads from a generation directory.
const MANIFEST_NAME: &str = "manifest.json";

/// Build the frozen manifest header for one project's payload.
fn manifest_header(
    config: &ServiceConfig,
    solution: &runtime::SolutionRow,
    project: &runtime::ProjectRow,
    payload: &Payload,
) -> Result<ManifestHeader, AxiomError> {
    let analyzer_set_hash = analyzer_set_hash()?;
    let dependency_fingerprint = dependency_lock_hash()?;
    let config_fingerprint = graph_export::sha256_hex(config.canonical_json().as_bytes());
    let source_fingerprint = source_fingerprint(
        payload,
        &solution.profile,
        &analyzer_set_hash,
        &config_fingerprint,
        &dependency_fingerprint,
    )?;
    Ok(ManifestHeader {
        solution_id: solution.id.clone(),
        project_id: project.id.clone(),
        analysis_profile: solution.profile.clone(),
        generator_version: env!("CARGO_PKG_VERSION").to_owned(),
        analyzer_set_hash,
        source_fingerprint,
        config_fingerprint,
        dependency_fingerprint,
        coverage: payload.coverage.clone(),
    })
}

/// The pinned grammar lock this build is bound to, in a stable order.
fn pinned_grammars() -> Result<Vec<serde_json::Value>, AxiomError> {
    let grammars = graph_analyze::grammar::GrammarSet::load_documented_default()
        .map_err(|error| runtime::storage_error("pinned grammar set", &error))?;
    let mut rows: Vec<serde_json::Value> = grammars
        .grammars()
        .iter()
        .map(|grammar| {
            serde_json::json!({
                "abi": grammar.abi(),
                "fingerprint": grammar.fingerprint(),
                "grammar_id": grammar.id(),
                "language": grammar.language().as_str(),
                "version": grammar.version(),
            })
        })
        .collect();
    rows.sort_by(|left, right| left["language"].as_str().cmp(&right["language"].as_str()));
    Ok(rows)
}

/// A lowercase `sha256` over a value's compact JSON encoding.
fn canonical_digest(value: &serde_json::Value) -> Result<String, AxiomError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| runtime::storage_error("fingerprint", &error))?;
    Ok(graph_export::sha256_hex(&bytes))
}

/// Digest of the pinned analyzer set: the declaration analyzers and the grammar lock.
fn analyzer_set_hash() -> Result<String, AxiomError> {
    canonical_digest(&serde_json::json!({
        "analyzers": [payload::CSHARP_ANALYZER_ID, payload::TYPESCRIPT_ANALYZER_ID],
        "grammars": pinned_grammars()?,
    }))
}

/// Digest of the pinned dependency lock: the exact grammars this build binds.
fn dependency_lock_hash() -> Result<String, AxiomError> {
    canonical_digest(&serde_json::json!({ "grammar_lock": pinned_grammars()? }))
}

/// Digest of the analysed source: sorted inputs, the profile and every lock.
fn source_fingerprint(
    payload: &Payload,
    profile: &str,
    analyzer_set_hash: &str,
    config_fingerprint: &str,
    dependency_fingerprint: &str,
) -> Result<String, AxiomError> {
    let inputs: Vec<serde_json::Value> = payload
        .input_paths
        .iter()
        .map(|(path, hash)| serde_json::json!([path, hash]))
        .collect();
    canonical_digest(&serde_json::json!({
        "analyzer_set_hash": analyzer_set_hash,
        "config_fingerprint": config_fingerprint,
        "dependency_fingerprint": dependency_fingerprint,
        "inputs": inputs,
        "profile": profile,
    }))
}

fn current_generation(lane: &Path) -> Result<Option<String>, AxiomError> {
    Ok(pointer::read(lane)
        .map_err(runtime::export_error)?
        .map(|pointer| pointer.generation_id))
}
/// One declaration, lifted out of the language-specific analyzer types.
struct Declaration {
    kind: &'static str,
    name: String,
    semantic_path: Vec<String>,
    key: String,
    start_line: usize,
    end_line: usize,
}

/// The one-based lines an analyzer byte span covers.
///
/// `Span::line` reports the line of a span *start*, so the end line is read from a
/// zero-length span at the end offset. The result is clamped inside the source and
/// to `end >= start`, so a published source location is always a valid one.
fn span_lines(start: usize, end: usize, source: &str) -> (usize, usize) {
    let start_line = graph_analyze::Span { start, end }.line(source);
    let end_offset = end.min(source.len());
    let end_line = graph_analyze::Span {
        start: end_offset,
        end: end_offset,
    }
    .line(source);
    (start_line, end_line.max(start_line))
}

/// One path as the graph data contract spells a source location: relative, `/`.
fn portable_path(path: &str) -> String {
    path.replace('\\', "/")
}

/// The last component of a qualified name, for a declaration the analyzer left unnamed.
fn leaf_name(qualified_name: &str) -> &str {
    qualified_name
        .rsplit(['.', '/', ':'])
        .next()
        .unwrap_or(qualified_name)
}

/// Analyse one source file into the facts that replace its previous ones.
///
/// Only the pinned C# and TypeScript declaration analyzers run here. A path in a
/// language this build does not pin yields no facts and no false claim: the file
/// is acknowledged as observed, with nothing asserted about its contents.
fn analyze_file(path: &str, source: &str, project_id: &str) -> GraphFactSet {
    match Language::from_path(path) {
        Some(Language::CSharp) => {
            let analysis = graph_analyze::csharp::declarations::analyze(path, source);
            let declarations: Vec<Declaration> = analysis
                .declarations
                .iter()
                .map(|declaration| {
                    let (start_line, end_line) =
                        span_lines(declaration.span.start, declaration.span.end, source);
                    Declaration {
                        kind: declaration.kind.as_str(),
                        name: declaration.name.clone(),
                        semantic_path: declaration.semantic_path.clone(),
                        key: declaration.key.clone(),
                        start_line,
                        end_line,
                    }
                })
                .collect();
            facts_from_declarations(
                project_id,
                Language::CSharp.as_str(),
                payload::CSHARP_ANALYZER_ID,
                path,
                declarations,
            )
        }
        Some(Language::TypeScript) => {
            let analysis = graph_analyze::typescript::declarations::analyze(path, source);
            let declarations: Vec<Declaration> = analysis
                .declarations
                .iter()
                .map(|declaration| {
                    let (start_line, end_line) =
                        span_lines(declaration.span.start, declaration.span.end, source);
                    Declaration {
                        kind: declaration.kind.as_str(),
                        name: declaration
                            .name
                            .clone()
                            .unwrap_or_else(|| declaration.key.clone()),
                        semantic_path: declaration.semantic_path.clone(),
                        key: declaration.key.clone(),
                        start_line,
                        end_line,
                    }
                })
                .collect();
            facts_from_declarations(
                project_id,
                Language::TypeScript.as_str(),
                payload::TYPESCRIPT_ANALYZER_ID,
                path,
                declarations,
            )
        }
        None => GraphFactSet::new(Vec::new(), Vec::new()),
    }
}

/// Turn one file's declarations into the node and containment-edge facts the store holds.
///
/// The stored `record_json` is the only place the published payload reads the file,
/// the language, the source lines and the analyzer's evidence from, so they are
/// written here - by the one component that holds both the analysed path and the
/// analyzer's spans - instead of being guessed by the renderer later.
fn facts_from_declarations(
    project_id: &str,
    language: &str,
    analyzer_id: &str,
    path: &str,
    declarations: Vec<Declaration>,
) -> GraphFactSet {
    let file = portable_path(path);
    let mut nodes = Vec::with_capacity(declarations.len());
    let mut scope_of: BTreeMap<String, String> = BTreeMap::new();
    for declaration in &declarations {
        scope_of.insert(
            scope_key(&declaration.semantic_path, &declaration.name),
            declaration.key.clone(),
        );
    }

    let mut edges = Vec::new();
    for declaration in &declarations {
        let qualified_name = qualify(&declaration.semantic_path, &declaration.name);
        let name = if declaration.name.is_empty() {
            leaf_name(&qualified_name).to_owned()
        } else {
            declaration.name.clone()
        };
        // The contract's node document, written where both halves are known. The
        // published id is not this one: `payload` derives it from the canonical
        // identity tuple, because the store key is an analyzer-internal digest.
        let body = serde_json::json!({
            "id": declaration.key,
            "kind": declaration.kind,
            "name": name,
            "qualified_name": qualified_name,
            "language": language,
            "file": file,
            "start_line": declaration.start_line,
            "end_line": declaration.end_line,
            "attributes": {},
        });
        nodes.push(NodeFact::new(
            declaration.key.clone(),
            declaration.kind,
            qualified_name,
            body.to_string(),
        ));

        // Containment: a declaration whose semantic path names an enclosing
        // declaration in the same file is reached from it. Resolution stays
        // exact because the source and target are both in this batch.
        if let Some((parent_name, parent_path)) = declaration
            .semantic_path
            .split_last()
            .map(|(name, parents)| (name, parents.to_vec()))
        {
            if let Some(parent_key) = scope_of.get(&scope_key(&parent_path, parent_name)) {
                let edge_id = format!("{parent_key}->contains->{}", declaration.key);
                // The evidence key is part of the published edge identity, so the
                // location and rule are stored with the fact rather than re-derived.
                let edge_body = serde_json::json!({
                    "evidence": [{
                        "source": {
                            "file": file,
                            "start_line": declaration.start_line,
                            "end_line": declaration.end_line,
                        },
                        "rule_id": payload::CONTAINS_RULE_ID,
                    }],
                    "analyzer_id": analyzer_id,
                });
                edges.push(EdgeFact::new(
                    edge_id,
                    parent_key.clone(),
                    EdgeTarget::Resolved(declaration.key.clone()),
                    project_id,
                    "contains",
                    edge_body.to_string(),
                ));
            }
        }
    }
    GraphFactSet::new(nodes, edges)
}

fn scope_key(path: &[String], name: &str) -> String {
    format!("{}|{name}", path.join("/"))
}

fn qualify(path: &[String], name: &str) -> String {
    if path.is_empty() {
        name.to_owned()
    } else {
        format!("{}.{}", path.join("."), name)
    }
}

/// Read one published generation through the frozen, guarded reader.
///
/// # Errors
///
/// [`ErrorCode::NotFound`] with `publication-missing` when the lane has no
/// readable generation yet, plus the reader's own errors.
pub fn load_snapshot(
    solution_id: &str,
    project: &runtime::ProjectRow,
    project_root: &str,
) -> Result<reader::Snapshot, AxiomError> {
    let lane = runtime::checkpoint_root(project_root, solution_id, &project.id);
    if pointer::read(&lane)
        .map_err(runtime::export_error)?
        .is_none()
    {
        return Err(AxiomError::new(
            ErrorCode::NotFound,
            "this project has no published generation yet",
        )
        .with_detail("rule", "publication-missing")
        .with_detail("lane", lane.to_string_lossy()));
    }
    let guard = SolutionGuard::acquire(&default_lock_path(&lane), LockMode::Shared)
        .map_err(runtime::guard_error)?;
    let snapshot = reader::load(&lane, &guard).map_err(runtime::export_error)?;
    guard.release().map_err(runtime::guard_error)?;
    Ok(snapshot)
}

/// Resolve every registered project of one solution to its absolute root.
///
/// # Errors
///
/// [`ErrorCode::ConfigInvalid`] when the bindings document is missing, plus the
/// binding resolution errors.
pub fn resolve_projects(
    home: &AxiomHome,
    projects: &[runtime::ProjectRow],
) -> Result<Vec<(String, String)>, AxiomError> {
    let bindings = runtime::load_bindings(home)?;
    let probe = runtime::symlink_probe();
    let catalog: Vec<CatalogRepoReference> = projects
        .iter()
        .map(|project| CatalogRepoReference::new(project.repo_id.clone()))
        .collect();
    let mut out = Vec::with_capacity(projects.len());
    for project in projects {
        let resolved = resolve_binding(&bindings, &catalog, &project.repo_id, &probe)?;
        let root = resolve_project_root(&resolved, &project.relative_path, &probe)?;
        out.push((project.id.clone(), root));
    }
    out.sort();
    Ok(out)
}

/// Resolve one registered project to its absolute root.
///
/// # Errors
///
/// [`ErrorCode::ConfigInvalid`] when the bindings document is missing, plus the
/// binding resolution errors.
pub fn resolve_one_project(
    home: &AxiomHome,
    project: &runtime::ProjectRow,
) -> Result<String, AxiomError> {
    let bindings = runtime::load_bindings(home)?;
    let probe = runtime::symlink_probe();
    let catalog = vec![CatalogRepoReference::new(project.repo_id.clone())];
    let resolved = resolve_binding(&bindings, &catalog, &project.repo_id, &probe)?;
    resolve_project_root(&resolved, &project.relative_path, &probe)
}

/// Whether a solution has a registration row, used before queue operations.
///
/// # Errors
///
/// [`ErrorCode::Internal`] for a storage failure.
pub fn solution_exists(connection: &Connection, solution_id: &str) -> Result<bool, AxiomError> {
    connection
        .query_row(
            "SELECT 1 FROM solutions WHERE id = ?1",
            [solution_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(|error| runtime::storage_error("solution lookup", &error))
}
#[cfg(test)]
mod tests {
    use super::*;

    use graph_export::manifest::Coverage;

    /// A payload holding exactly the documents a serve fixture publishes.
    fn payload_of(nodes: Vec<serde_json::Value>, edges: Vec<serde_json::Value>) -> Payload {
        let inputs = nodes.len() + edges.len();
        Payload {
            nodes,
            edges,
            coverage: Coverage::complete_for_profile(inputs, inputs, 0),
            input_paths: Vec::new(),
        }
    }

    /// A manifest header every serve fixture is sealed with.
    fn fixture_header() -> ManifestHeader {
        ManifestHeader {
            solution_id: "demo".to_owned(),
            project_id: "demo-project".to_owned(),
            analysis_profile: "default".to_owned(),
            generator_version: "w10-fixture".to_owned(),
            analyzer_set_hash: "0".repeat(64),
            source_fingerprint: "1".repeat(64),
            config_fingerprint: "2".repeat(64),
            dependency_fingerprint: "3".repeat(64),
            coverage: Coverage::complete_for_profile(1, 1, 0),
        }
    }

    #[test]
    fn csharp_declarations_become_nodes_and_containment_edges() {
        let source = "\
namespace Demo
{
    public sealed class Service
    {
        public void Run() { }
    }
}
";
        let facts = analyze_file("src/Service.cs", source, "demo-project");
        assert_eq!(
            facts.nodes.len(),
            3,
            "expected namespace, class and method nodes, got {:?}",
            facts
                .nodes
                .iter()
                .map(NodeFact::qualified_name)
                .collect::<Vec<_>>()
        );
        assert!(
            !facts.edges.is_empty(),
            "a nested declaration must be reached from its enclosing declaration"
        );
        for node in &facts.nodes {
            assert!(!node.qualified_name().is_empty());
            let body: serde_json::Value =
                serde_json::from_str(node.record_json()).expect("node body is JSON");
            assert!(
                body.get("qualified_name").is_some(),
                "the published identity is read from the documented field"
            );
            assert!(
                payload::contract_node_kind(node.kind()).is_some(),
                "every node the publisher writes maps onto a contract node kind"
            );
        }
        for edge in &facts.edges {
            let body: serde_json::Value =
                serde_json::from_str(edge.record_json()).expect("edge body is JSON");
            assert!(
                body.get("evidence").is_some(),
                "an edge publishes the evidence locations the contract requires"
            );
            assert!(body.get("analyzer_id").is_some());
            assert!(
                facts.nodes.iter().any(|node| node.id() == edge.source_id()),
                "every edge source must be a node in the same batch"
            );
        }
    }

    #[test]
    fn an_unsupported_language_asserts_nothing() {
        let facts = analyze_file("data/table.json", "{}", "demo-project");
        assert!(facts.nodes.is_empty());
        assert!(facts.edges.is_empty());
    }

    #[test]
    fn sealed_manifest_makes_the_generation_readable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lane = dir.path();
        let layout = StagingLayout::new(lane);
        let payload = payload_of(
            vec![serde_json::json!({
                "id": "node-1",
                "kind": "Class",
                "qualified_name": "Demo.Service",
                "name": "Service",
            })],
            Vec::new(),
        );
        let (generation_id, manifest_hash, content_dir) =
            stage_generation(&layout, "pending-0-demo", &payload, &fixture_header())
                .expect("stage");
        assert_eq!(
            generation_id.len(),
            64,
            "the pointer accepts a sha256 id only"
        );
        assert!(
            generation_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "the pointer accepts a lowercase sha256 id only, got {generation_id}"
        );
        assert_eq!(manifest_hash.len(), 64);
        // Staging is not readable: the pointer is still absent and no generation
        // directory exists until the barrier completes.
        assert!(pointer::read(lane).expect("read").is_none());
        assert!(!layout.generation_dir(&generation_id).exists());

        let guard =
            SolutionGuard::acquire(&default_lock_path(lane), LockMode::Exclusive).expect("guard");
        install_generation(&layout, &generation_id, &content_dir).expect("install");
        pointer::replace(
            lane,
            &pointer::CurrentPointer::new(generation_id.clone()),
            pointer::PointerStrategy::AtomicReplace,
        )
        .expect("pointer");
        guard.release().expect("release");
        assert!(layout
            .generation_dir(&generation_id)
            .join(MANIFEST_NAME)
            .is_file());

        let guard =
            SolutionGuard::acquire(&default_lock_path(lane), LockMode::Shared).expect("guard");
        let snapshot = reader::load(lane, &guard).expect("the frozen reader loads it");
        assert_eq!(snapshot.generation_id(), generation_id);
        let parsed = snapshot.parse_shard(NODES_SHARD).expect("shard parses");
        assert_eq!(parsed.len(), 1);
        guard.release().expect("release");
    }

    #[test]
    fn a_type_declaration_without_a_modifier_is_not_yet_analysed() {
        // The pinned C# analyzer (`graph_analyze::csharp::declarations`) rejects a
        // type keyword at byte 0 of a trimmed line, so `class Service` without a
        // modifier asserts nothing while `public class Service` does. The worker
        // publishes exactly what the pinned analyzer asserts; this test records the
        // limitation instead of hiding it.
        let source = "namespace Demo\n{\n    class Service\n    {\n    }\n}\n";
        let facts = analyze_file("src/Bare.cs", source, "demo-project");
        assert_eq!(facts.nodes.len(), 1, "only the namespace is asserted");
        assert_eq!(facts.nodes[0].kind(), "namespace");
    }

    #[test]
    fn an_unsealed_staging_directory_never_advances_the_pointer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lane = dir.path();
        let layout = StagingLayout::new(lane);
        let mut staged = layout.begin("pending-0-demo").expect("begin");
        staged
            .write_records(
                NODES_SHARD,
                NODES_ROLE,
                &[serde_json::json!({
                    "id": "n",
                    "kind": "Class",
                    "qualified_name": "Demo.N",
                })],
            )
            .expect("write");
        // No install, no pointer replace: the lane must stay unreadable.
        assert!(pointer::read(lane).expect("read").is_none());
        assert!(!layout.generation_dir("pending-0-demo").exists());
    }

    /// A migrated in-memory store with one registered solution and project.
    ///
    /// `publish` writes through the real schema, so the fixture applies the real
    /// `schema-v1.sql` (including its `lane IN('live','checkpoint')` check)
    /// instead of a laxer hand-written table.
    fn publishable_store() -> Connection {
        let mut connection = Connection::open_in_memory().expect("open in-memory sqlite");
        graph_store::migrations::apply(&mut connection).expect("schema v1 applies");
        connection
            .execute(
                "INSERT INTO solutions(id, workspace_instance_id, profile, config_hash) \
                 VALUES('demo', 'inst-1', 'default', 'config-hash')",
                [],
            )
            .expect("seed solution");
        connection
            .execute(
                "INSERT INTO projects(id, solution_id, repo_id, relative_path) \
                 VALUES('demo-project', 'demo', 'demo', '.')",
                [],
            )
            .expect("seed project");
        connection
    }

    fn demo_solution() -> runtime::SolutionRow {
        runtime::SolutionRow {
            id: "demo".to_owned(),
            profile: "default".to_owned(),
            event_seq: 1,
            full_scan_required: false,
        }
    }

    fn demo_project() -> runtime::ProjectRow {
        runtime::ProjectRow {
            id: "demo-project".to_owned(),
            repo_id: "demo".to_owned(),
            relative_path: ".".to_owned(),
        }
    }

    #[test]
    fn one_publication_publishes_both_lanes_with_the_same_generation() {
        // docs/12-SNAPSHOT-READ-WRITE-PROTOCOL.md section 2: each of
        // `<project>/live` and `<project>/checkpoint` carries `current.json` and
        // `generations/<hash>/`. A publication that wrote only the checkpoint
        // lane left the query lane empty, so this pins both halves.
        let dir = tempfile::tempdir().expect("tempdir");
        let live = dir.path().join("live");
        let checkpoint = dir.path().join("checkpoint");
        let mut connection = publishable_store();
        let payload = payload_of(
            vec![serde_json::json!({
                "id": "node-1",
                "kind": "Class",
                "qualified_name": "Demo.Service",
            })],
            Vec::new(),
        );

        let published = publish(
            &ServiceConfig::default(),
            &mut connection,
            &demo_solution(),
            &demo_project(),
            &live,
            &checkpoint,
            &payload,
        )
        .expect("publish");
        assert_eq!(published.generation_id.len(), 64);

        let mut lane_generations = Vec::new();
        for lane in [&live, &checkpoint] {
            let pointer = pointer::read(lane)
                .expect("read pointer")
                .expect("the lane has a pointer");
            assert_eq!(
                pointer.schema_version,
                pointer::POINTER_SCHEMA_VERSION,
                "{} must carry the schema version the shared reader requires",
                lane.display()
            );
            assert_eq!(pointer.generation_id, published.generation_id);
            // The bytes on disk are the exact canonical document, which is what
            // makes the lane readable by the shipped `axiom-mcp` data plane.
            let written = std::fs::read(lane.join(pointer::POINTER_FILE)).expect("read bytes");
            assert_eq!(
                written,
                pointer::canonical_bytes(&pointer).expect("canonical"),
                "{} must hold the canonical pointer document",
                lane.display()
            );
            let layout = StagingLayout::new(lane.to_path_buf());
            assert!(layout
                .generation_dir(&published.generation_id)
                .join(MANIFEST_NAME)
                .is_file());

            let guard =
                SolutionGuard::acquire(&default_lock_path(lane), LockMode::Shared).expect("guard");
            let snapshot = reader::load(lane, &guard).expect("the frozen reader loads the lane");
            assert_eq!(snapshot.generation_id(), published.generation_id);
            guard.release().expect("release");
            lane_generations.push(pointer.generation_id);
        }
        assert_eq!(
            lane_generations[0], lane_generations[1],
            "the two lanes must not name different generations"
        );

        // The recorded publication names both lanes, which is what
        // `doctor` reports and what a catalog vector reads.
        let recorded: Vec<String> = {
            let mut statement = connection
                .prepare(
                    "SELECT lane FROM published_generations WHERE project_id = 'demo-project' \
                     ORDER BY lane",
                )
                .expect("prepare");
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .expect("query")
                .map(|row| row.expect("row"))
                .collect()
        };
        assert_eq!(recorded, vec!["checkpoint".to_owned(), "live".to_owned()]);
    }

    #[test]
    fn a_lane_that_cannot_be_sealed_leaves_every_pointer_unmoved() {
        // Both generations are sealed before either pointer moves, so a failure
        // while sealing the second lane leaves the first lane exactly as it was:
        // no pointer names a generation that is not complete.
        let dir = tempfile::tempdir().expect("tempdir");
        let live = dir.path().join("live");
        let blocked = dir.path().join("blocked-checkpoint");
        std::fs::write(&blocked, b"a file where a lane directory must be").expect("write blocker");
        let mut connection = publishable_store();
        let payload = payload_of(
            vec![serde_json::json!({
                "id": "node-1",
                "kind": "Class",
                "qualified_name": "Demo.Service",
            })],
            Vec::new(),
        );

        let error = publish(
            &ServiceConfig::default(),
            &mut connection,
            &demo_solution(),
            &demo_project(),
            &live,
            &blocked,
            &payload,
        )
        .expect_err("a lane that cannot be staged must refuse the publication");
        assert_eq!(error.code(), ErrorCode::Internal);

        assert!(
            pointer::read(&live).expect("read").is_none(),
            "the live lane must not gain a pointer when the checkpoint lane could not be sealed"
        );
        assert!(!live.join("generations").exists());
        let recorded: i64 = connection
            .query_row("SELECT COUNT(*) FROM published_generations", [], |row| {
                row.get(0)
            })
            .expect("count");
        assert_eq!(recorded, 0, "nothing may be recorded as published");
        // The durable intent survives, so the failed publication is replayable
        // rather than a generation nothing knows about.
        let pending: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM publish_outbox WHERE state = 'PENDING'",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(pending, 1);
    }
}
