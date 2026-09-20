//! Shared runtime bindings for the operator commands and the foreground daemon.
//!
//! Task H-002 makes `serve` run a real reconcile worker loop. The loop needs the
//! store, the solution registry, the machine-local binding table and the export
//! lane in one place, and the one-shot operator verbs need exactly the same
//! state. This module owns that shared opening, so a command cannot invent a
//! second database path, a second bindings document, a second lane root or a
//! second lock path.

use std::path::{Path, PathBuf};

use graph_core::bindings::{LocalBinding, NoSymlinkProbe};
use graph_core::config::ServiceConfig;
use graph_core::error::{AxiomError, ErrorCode};
use graph_core::locks::{GuardError, ERR_LOCKED};
use graph_core::paths::AxiomHome;
use graph_store::open::{LexicalVolumeProbe, OpenOptions, Store};
use rusqlite::{Connection, OptionalExtension};

/// The machine-local bindings document, relative to the Axiom home.
///
/// `serve` has no `--bindings` flag and the parser is frozen, so project roots
/// are resolved from this documented, deterministic location. `solution
/// register --bindings <path>` remains the operator action that writes it.
pub const BINDINGS_DOCUMENT: &str = "config/bindings.json";

/// Absolute path of the machine-local bindings document.
#[must_use]
pub fn bindings_document_path(home: &AxiomHome) -> PathBuf {
    home.root().join("config").join("bindings.json")
}

/// Read and validate the machine-local binding table.
///
/// # Errors
///
/// [`ErrorCode::ConfigInvalid`] naming the exact missing path when the document
/// is absent, and the same errors [`crate::commands::changed::BindingsDocument`]
/// reports for a malformed document.
pub fn load_bindings(home: &AxiomHome) -> Result<Vec<LocalBinding>, AxiomError> {
    let path = bindings_document_path(home);
    let document = std::fs::read_to_string(&path).map_err(|error| {
        AxiomError::new(
            ErrorCode::ConfigInvalid,
            "project roots cannot be resolved: the machine-local bindings document is required",
        )
        .with_detail("rule", "bindings-document-missing")
        .with_detail("path", path.to_string_lossy())
        .with_detail("io", error.to_string())
    })?;
    crate::commands::changed::BindingsDocument::parse(&document)
}

/// Open the instance store, creating its parent directory when needed.
///
/// # Errors
///
/// The same errors [`graph_store::open`] and [`AxiomHome::instance_db`] report.
pub fn open_store(config: &ServiceConfig, home: &AxiomHome) -> Result<Store, AxiomError> {
    let database = match config.storage().database_path() {
        Some(path) => PathBuf::from(path),
        None => home.instance_db(config.daemon().instance_id())?,
    };
    // The configured storage policy reaches the open call, so the runtime
    // baseline, the journal mode, the bounded busy timeout and the local-storage
    // requirement are the operator's declared ones and never silent defaults.
    let storage = config.storage();
    graph_store::open(
        &OpenOptions::file(database)
            .with_create_parent(true)
            .with_journal_mode(storage.journal_mode())
            .with_busy_timeout_ms(storage.busy_timeout_ms())
            .with_synchronous(storage.synchronous())
            .with_require_local_storage(storage.require_local_storage()),
        &LexicalVolumeProbe,
    )
}

/// The lexical symlink probe used to resolve a project root inside a binding.
#[must_use]
pub fn symlink_probe() -> NoSymlinkProbe {
    NoSymlinkProbe
}

/// Map a solution-guard failure onto the shared error envelope.
#[must_use]
pub fn guard_error(error: GuardError) -> AxiomError {
    let code = if error.code() == ERR_LOCKED {
        ErrorCode::WriterAlreadyRunning
    } else {
        ErrorCode::Internal
    };
    let mut mapped = AxiomError::new(code, format!("solution guard: {error}"));
    if let Some(path) = error.path() {
        mapped = mapped.with_detail("path", path);
    }
    mapped
}

/// Map a publication failure onto the shared error envelope.
#[must_use]
pub fn export_error(error: graph_export::ExportError) -> AxiomError {
    let code = match error.code {
        graph_export::ERR_LOCKED => ErrorCode::WriterAlreadyRunning,
        graph_export::ERR_BUDGET => ErrorCode::RateLimited,
        graph_export::ERR_MISSING => ErrorCode::NotFound,
        _ => ErrorCode::Internal,
    };
    AxiomError::new(code, format!("publication failed: {error}")).with_detail("rule", error.code)
}

/// Map a storage failure onto the shared error envelope.
#[must_use]
pub fn storage_error(context: &str, error: &dyn std::fmt::Display) -> AxiomError {
    AxiomError::new(ErrorCode::Internal, format!("{context}: {error}"))
}

/// The per-project graph output root:
/// `<project>/.axiom/graph/<solution>/<project>`.
#[must_use]
pub fn project_graph_root(project_root: &str, solution_id: &str, project_id: &str) -> PathBuf {
    Path::new(project_root)
        .join(".axiom")
        .join("graph")
        .join(solution_id)
        .join(project_id)
}

/// The checkpoint lane root a generation is published under.
#[must_use]
pub fn checkpoint_root(project_root: &str, solution_id: &str, project_id: &str) -> PathBuf {
    project_graph_root(project_root, solution_id, project_id).join(LANE)
}

/// The live lane root a generation is published under.
#[must_use]
pub fn live_root(project_root: &str, solution_id: &str, project_id: &str) -> PathBuf {
    project_graph_root(project_root, solution_id, project_id).join(LIVE_LANE)
}

/// The tracked checkpoint lane: an artifact a human chose to publish.
pub const LANE: &str = "checkpoint";

/// The Git-ignored live lane, rewritten on every publication.
///
/// `docs/12-SNAPSHOT-READ-WRITE-PROTOCOL.md` section 2 requires both lanes
/// under a project, and the shipped `axiom-mcp` data plane resolves its query
/// lane to `live`. A publication that wrote only the checkpoint lane therefore
/// left every query with nothing to read.
pub const LIVE_LANE: &str = "live";

/// A registered solution, as the worker loop reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolutionRow {
    /// Solution id.
    pub id: String,
    /// Analysis profile the solution was registered with.
    pub profile: String,
    /// Last used event sequence.
    pub event_seq: i64,
    /// Whether the next pass must reconcile the whole solution.
    pub full_scan_required: bool,
}

/// One registered project of a solution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRow {
    /// Project id.
    pub id: String,
    /// Declared repository id, resolved through the binding table.
    pub repo_id: String,
    /// Repository-relative membership root.
    pub relative_path: String,
}

/// Every registered solution, in id order.
///
/// # Errors
///
/// [`ErrorCode::Internal`] for a storage failure.
pub fn solutions(connection: &Connection) -> Result<Vec<SolutionRow>, AxiomError> {
    let mut statement = connection
        .prepare("SELECT id, profile, event_seq, full_scan_required FROM solutions ORDER BY id")
        .map_err(|error| storage_error("solution query", &error))?;
    let rows = statement
        .query_map([], |row| {
            Ok(SolutionRow {
                id: row.get(0)?,
                profile: row.get(1)?,
                event_seq: row.get(2)?,
                full_scan_required: row.get::<_, i64>(3)? != 0,
            })
        })
        .map_err(|error| storage_error("solution query", &error))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|error| storage_error("solution row", &error))?);
    }
    Ok(out)
}

/// One registered solution by id.
///
/// # Errors
///
/// [`ErrorCode::NotFound`] when the solution has no registration row.
pub fn solution(connection: &Connection, solution_id: &str) -> Result<SolutionRow, AxiomError> {
    connection
        .query_row(
            "SELECT id, profile, event_seq, full_scan_required FROM solutions WHERE id = ?1",
            [solution_id],
            |row| {
                Ok(SolutionRow {
                    id: row.get(0)?,
                    profile: row.get(1)?,
                    event_seq: row.get(2)?,
                    full_scan_required: row.get::<_, i64>(3)? != 0,
                })
            },
        )
        .optional()
        .map_err(|error| storage_error("solution lookup", &error))?
        .ok_or_else(|| {
            AxiomError::new(ErrorCode::NotFound, "this solution id is not registered")
                .with_detail("rule", crate::commands::solution::REASON_SOLUTION_NOT_FOUND)
                .with_detail("solution_id", solution_id)
        })
}

/// Every project of a solution, in id order.
///
/// # Errors
///
/// [`ErrorCode::Internal`] for a storage failure.
pub fn projects(connection: &Connection, solution_id: &str) -> Result<Vec<ProjectRow>, AxiomError> {
    let mut statement = connection
        .prepare(
            "SELECT id, repo_id, relative_path FROM projects WHERE solution_id = ?1 ORDER BY id",
        )
        .map_err(|error| storage_error("project query", &error))?;
    let rows = statement
        .query_map([solution_id], |row| {
            Ok(ProjectRow {
                id: row.get(0)?,
                repo_id: row.get(1)?,
                relative_path: row.get(2)?,
            })
        })
        .map_err(|error| storage_error("project query", &error))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|error| storage_error("project row", &error))?);
    }
    Ok(out)
}

/// Number of files whose desired generation is ahead of their indexed one.
///
/// # Errors
///
/// [`ErrorCode::Internal`] for a storage failure.
pub fn dirty_count(connection: &Connection) -> Result<i64, AxiomError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM files WHERE desired_generation > indexed_generation",
            [],
            |row| row.get(0),
        )
        .map_err(|error| storage_error("dirty count", &error))
}

/// Advance a solution's event sequence so the next publication is a new revision.
///
/// # Errors
///
/// [`ErrorCode::Internal`] for a storage failure.
pub fn bump_event_seq(connection: &Connection, solution_id: &str) -> Result<(), AxiomError> {
    connection
        .execute(
            "UPDATE solutions SET event_seq = event_seq + 1 WHERE id = ?1",
            [solution_id],
        )
        .map_err(|error| storage_error("solution event sequence", &error))?;
    Ok(())
}

/// Clear the full-scan requirement once a full inventory has been reconciled.
///
/// # Errors
///
/// [`ErrorCode::Internal`] for a storage failure.
pub fn clear_full_scan(connection: &Connection, solution_id: &str) -> Result<(), AxiomError> {
    connection
        .execute(
            "UPDATE solutions SET full_scan_required = 0 WHERE id = ?1",
            [solution_id],
        )
        .map_err(|error| storage_error("solution full-scan flag", &error))?;
    Ok(())
}

/// Enqueue one reconcile job, tolerating a duplicate pending job.
///
/// # Errors
///
/// [`ErrorCode::Internal`] for a storage failure.
pub fn enqueue_job(
    connection: &Connection,
    job_id: &str,
    solution_id: &str,
    kind: &str,
    scope_key: &str,
    target_event_seq: i64,
) -> Result<bool, AxiomError> {
    let now = graph_store::migrations::utc_timestamp();
    let changed = connection
        .execute(
            "INSERT OR IGNORE INTO jobs(id, solution_id, kind, scope_key, state, \
             target_event_seq, ready_at, created_at) VALUES(?1, ?2, ?3, ?4, 'PENDING', ?5, ?6, ?6)",
            rusqlite::params![job_id, solution_id, kind, scope_key, target_event_seq, now],
        )
        .map_err(|error| storage_error("job insert", &error))?;
    Ok(changed == 1)
}

/// The most recently published generation of one project, when any exists.
///
/// # Errors
///
/// [`ErrorCode::Internal`] for a storage failure.
pub fn latest_published(
    connection: &Connection,
    project_id: &str,
) -> Result<Option<(String, String)>, AxiomError> {
    connection
        .query_row(
            "SELECT generation_id, manifest_hash FROM published_generations \
             WHERE project_id = ?1 AND lane = ?2 ORDER BY published_at DESC, generation_id DESC LIMIT 1",
            rusqlite::params![project_id, LANE],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|error| storage_error("published generation lookup", &error))
}
