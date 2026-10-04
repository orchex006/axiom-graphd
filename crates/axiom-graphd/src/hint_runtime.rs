//! Durable change-hint inbox: producers never open a second SQLite writer.

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use graph_core::config::ServiceConfig;
use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{AxiomHome, PathEnvironment};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::cli::ChangedCommand;
use crate::commands::changed::{self, ChangeHintRequest, SourceReader, SourceState};
use crate::runtime;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
const LIMIT: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    solution: String,
    project: String,
    reason: String,
    paths: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema_version: u32,
    job_id: String,
    requests: Vec<Request>,
}

struct Reader;
impl SourceReader for Reader {
    fn read(&self, path: &Path) -> SourceState {
        if axiom_platform::atomic_file::reject_links(path).is_err() {
            return SourceState::Unreadable;
        }
        match std::fs::read(path) {
            Ok(bytes) => SourceState::Bytes(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => SourceState::Missing,
            Err(_) => SourceState::Unreadable,
        }
    }
}
fn error(code: ErrorCode, rule: &str) -> AxiomError {
    AxiomError::new(code, rule).with_detail("rule", rule)
}

fn check(
    request: &Request,
    connection: &Connection,
    home: &AxiomHome,
) -> Result<Value, AxiomError> {
    let probe = runtime::symlink_probe();
    let registry = changed::StoreRegistry::new(connection, runtime::load_bindings(home)?, &probe)?;
    let report = ChangeHintRequest::new(
        &request.solution,
        &request.project,
        Some(&request.reason),
        request.paths.clone(),
    )
    .accept(&registry, &Reader)?;
    serde_json::to_value(report).map_err(|_| error(ErrorCode::Internal, "hint-report"))
}

/// Validate actual registered source bytes, then persist a bounded pending intent.
pub fn submit(command: &ChangedCommand) -> Result<Value, AxiomError> {
    let home = AxiomHome::resolve(&PathEnvironment::for_current_process())?;
    home.verify_destination()?;
    let config = ServiceConfig::load(None)?;
    let database = match config.storage().database_path() {
        Some(p) => p.into(),
        None => home.instance_db(config.daemon().instance_id())?,
    };
    let connection =
        Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| error(ErrorCode::NotFound, "registered-store-unavailable"))?;
    let requests = match command {
        ChangedCommand::Hint {
            solution,
            project,
            path,
            reason,
        } => vec![Request {
            solution: solution.clone(),
            project: project.clone(),
            paths: vec![path.clone()],
            reason: reason.clone(),
        }],
        ChangedCommand::Batch {
            solution,
            from_json,
        } => {
            axiom_platform::atomic_file::reject_links(from_json)
                .map_err(|_| error(ErrorCode::Forbidden, "unsafe-hint-document"))?;
            let raw = std::fs::read(from_json)
                .map_err(|_| error(ErrorCode::NotFound, "hint-document-missing"))?;
            if raw.len() > changed::MAX_HINT_DOCUMENT_BYTES {
                return Err(error(ErrorCode::ValidationError, "hint-document-too-large"));
            }
            let document = String::from_utf8(raw)
                .map_err(|_| error(ErrorCode::ValidationError, "hint-document-encoding"))?;
            let parsed = ChangeHintRequest::from_json(&document, solution, None, None)?;
            vec![Request {
                solution: solution.clone(),
                project: parsed.project_id().to_owned(),
                reason: parsed.reason().to_owned(),
                paths: parsed.paths().to_vec(),
            }]
        }
    };
    let reports = requests
        .iter()
        .map(|r| check(r, &connection, &home))
        .collect::<Result<Vec<_>, _>>()?;
    let directory = home.root().join("incoming-changes");
    axiom_platform::atomic_file::reject_links(&directory)
        .map_err(|_| error(ErrorCode::Forbidden, "unsafe-hint-inbox"))?;
    std::fs::create_dir_all(&directory)
        .map_err(|_| error(ErrorCode::Forbidden, "hint-inbox-create"))?;
    if std::fs::read_dir(&directory)
        .map_err(|_| error(ErrorCode::Forbidden, "hint-inbox-read"))?
        .take(LIMIT + 1)
        .count()
        >= LIMIT
    {
        return Err(error(ErrorCode::RateLimited, "hint-inbox-full"));
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| error(ErrorCode::Internal, "clock"))?
        .as_nanos();
    let id = format!(
        "hint-{}-{}-{}",
        std::process::id(),
        nanos,
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let temporary = directory.join(format!("{id}.next"));
    let target = directory.join(format!("{id}.json"));
    let bytes = serde_json::to_vec(&Intent {
        schema_version: 1,
        job_id: id.clone(),
        requests,
    })
    .map_err(|_| error(ErrorCode::Internal, "hint-encoding"))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|_| error(ErrorCode::Conflict, "hint-stage-collision"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| error(ErrorCode::Internal, "hint-stage-write"))?;
    drop(file);
    axiom_platform::atomic_file::replace(&temporary, &target)
        .map_err(|_| error(ErrorCode::Internal, "hint-publish"))?;
    Ok(
        json!({"job_id":id,"accepted":true,"pending":true,"freshness":"pending","source_verification":reports}),
    )
}

/// Consume intents only while the caller owns the daemon's native writer claim.
pub fn ingest(connection: &Connection, home: &AxiomHome) -> Result<usize, AxiomError> {
    let directory = home.root().join("incoming-changes");
    if !directory.exists() {
        return Ok(0);
    }
    axiom_platform::atomic_file::reject_links(&directory)
        .map_err(|_| error(ErrorCode::Forbidden, "unsafe-hint-inbox"))?;
    let mut files = std::fs::read_dir(&directory)
        .map_err(|_| error(ErrorCode::Forbidden, "hint-inbox-read"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| error(ErrorCode::Forbidden, "hint-inbox-read"))?;
    files.sort_by_key(|e| e.file_name());
    if files.len() > LIMIT {
        return Err(error(ErrorCode::RateLimited, "hint-inbox-full"));
    }
    let mut consumed = 0;
    for file in files {
        let path = file.path();
        if path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }
        axiom_platform::atomic_file::reject_links(&path)
            .map_err(|_| error(ErrorCode::Forbidden, "unsafe-hint-file"))?;
        let bytes =
            std::fs::read(&path).map_err(|_| error(ErrorCode::NotFound, "hint-file-read"))?;
        if bytes.len() > changed::MAX_HINT_DOCUMENT_BYTES {
            return Err(error(ErrorCode::ValidationError, "hint-document-too-large"));
        }
        let intent: Intent = serde_json::from_slice(&bytes)
            .map_err(|_| error(ErrorCode::ValidationError, "hint-intent-malformed"))?;
        if intent.schema_version != 1
            || !graph_core::paths::is_portable_id(&intent.job_id)
            || path.file_stem().and_then(|v| v.to_str()) != Some(intent.job_id.as_str())
            || intent.requests.is_empty()
            || intent.requests.len() > LIMIT
        {
            return Err(error(ErrorCode::ValidationError, "hint-intent-scope"));
        }
        for request in &intent.requests {
            check(request, connection, home)?;
        }
        connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| runtime::storage_error("hint transaction", &e))?;
        let result = (|| {
            for request in &intent.requests {
                let existing: bool = connection
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM jobs WHERE id=?1)",
                        [&intent.job_id],
                        |r| r.get(0),
                    )
                    .map_err(|e| runtime::storage_error("hint idempotency", &e))?;
                if existing {
                    continue;
                }
                runtime::bump_event_seq(connection, &request.solution)?;
                let sequence = runtime::solution(connection, &request.solution)?.event_seq;
                runtime::enqueue_job(
                    connection,
                    &intent.job_id,
                    &request.solution,
                    "RECONCILE",
                    &request.project,
                    sequence,
                )?;
            }
            Ok::<(), AxiomError>(())
        })();
        match result {
            Ok(()) => connection
                .execute_batch("COMMIT")
                .map_err(|e| runtime::storage_error("hint commit", &e))?,
            Err(e) => {
                let _ = connection.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
        std::fs::remove_file(path)
            .map_err(|_| error(ErrorCode::Internal, "hint-receipt-remove"))?;
        consumed += 1;
    }
    Ok(consumed)
}
