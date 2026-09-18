//! `status` and `doctor` reports (task B-085).
//!
//! `docs/16-CLI-AND-CONTROL-API.md` section 2 requires `doctor` to report roots,
//! locks, DB health, watcher, publish and coverage and requires that it performs
//! **no automatic repair**, and `docs/22-OPERATIONS-AND-TROUBLESHOOTING.md`
//! treats a degraded component as an operator action item. The single invariant
//! this module enforces is therefore: **the overall state is the worst component
//! state, and a degraded or unavailable component is never rendered as
//! healthy.** The overall label is derived from the four probes, never passed in,
//! so a caller cannot report a healthy daemon over a broken database.

use graph_core::error::{AxiomError, ErrorCode};
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

/// Reason recorded when the queue probe found failed jobs.
pub const REASON_QUEUE_FAILED: &str = "queue-failed-jobs";
/// Reason recorded when the queue probe found work waiting to be retried.
pub const REASON_QUEUE_RETRY_WAIT: &str = "queue-retry-wait";
/// Reason recorded when the watcher is not running natively.
pub const REASON_WATCHER_DEGRADED: &str = "watcher-degraded";
/// Reason recorded when the database probe failed.
pub const REASON_DATABASE_UNHEALTHY: &str = "database-unhealthy";
/// Reason recorded when no catalog generation is reachable.
pub const REASON_CATALOG_MISSING: &str = "catalog-missing";
/// Reason recorded when the solution has no registration row.
pub const REASON_SOLUTION_NOT_REGISTERED: &str = "solution-not-registered";

/// The worst-of state of one component, or of the whole report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthState {
    /// Everything this component needs is present and current.
    Healthy,
    /// The component answers but is stale, degraded or has failed work.
    Degraded,
    /// The component cannot answer.
    Unavailable,
}

impl HealthState {
    /// Stable wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        }
    }

    /// Whether this state means the component is fully usable.
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(self, Self::Healthy)
    }

    /// The worse of two states.
    #[must_use]
    pub fn worst(self, other: Self) -> Self {
        if self >= other {
            self
        } else {
            other
        }
    }
}

/// How the file watcher is currently running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WatcherMode {
    /// Native recursive filesystem notifications.
    Native,
    /// The declared polling fallback.
    Polling,
    /// No watcher is running; only explicit hints are honored.
    Disabled,
}

impl WatcherMode {
    /// Stable wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Polling => "polling",
            Self::Disabled => "disabled",
        }
    }

    /// Parse a wire spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "native" => Some(Self::Native),
            "polling" => Some(Self::Polling),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// Watcher health: the mode plus whether that mode is currently working.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WatcherHealth {
    /// Reported watcher mode.
    pub mode: WatcherMode,
    /// Whether the reported mode is functioning.
    pub healthy: bool,
    /// Operator-readable detail.
    pub detail: String,
}

impl WatcherHealth {
    /// A native watcher that is running.
    #[must_use]
    pub fn native() -> Self {
        Self {
            mode: WatcherMode::Native,
            healthy: true,
            detail: "native recursive notifications are active".to_owned(),
        }
    }

    /// A watcher that is not fully healthy.
    #[must_use]
    pub fn degraded(mode: WatcherMode, detail: impl Into<String>) -> Self {
        Self {
            mode,
            healthy: false,
            detail: detail.into(),
        }
    }

    fn state(&self) -> HealthState {
        if self.healthy {
            HealthState::Healthy
        } else {
            HealthState::Degraded
        }
    }
}

/// Queue health derived from the durable `jobs` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueueHealth {
    /// Jobs waiting to be claimed.
    pub pending: i64,
    /// Jobs a worker currently holds.
    pub leased: i64,
    /// Jobs waiting for a bounded retry.
    pub retry_wait: i64,
    /// Jobs that reached `FAILED`.
    pub failed: i64,
    /// Whether the queue is in a usable state.
    pub healthy: bool,
    /// Operator-readable detail.
    pub detail: String,
}

impl QueueHealth {
    fn state(&self) -> HealthState {
        if !self.healthy {
            HealthState::Unavailable
        } else if self.failed > 0 || self.retry_wait > 0 {
            HealthState::Degraded
        } else {
            HealthState::Healthy
        }
    }
}

/// Database health.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DatabaseHealth {
    /// Whether the database answered its probe.
    pub healthy: bool,
    /// Schema version the connection reports.
    pub schema_version: i64,
    /// Operator-readable detail.
    pub detail: String,
}

impl DatabaseHealth {
    fn state(&self) -> HealthState {
        if self.healthy {
            HealthState::Healthy
        } else {
            HealthState::Unavailable
        }
    }
}

/// Catalog health for one solution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogHealth {
    /// Whether a reachable catalog generation exists.
    pub healthy: bool,
    /// Reachable catalog generation id, when there is one.
    pub generation_id: Option<String>,
    /// Number of catalog references.
    pub refs: i64,
    /// Operator-readable detail.
    pub detail: String,
}

impl CatalogHealth {
    fn state(&self) -> HealthState {
        if self.healthy {
            HealthState::Healthy
        } else {
            HealthState::Degraded
        }
    }
}
/// The complete doctor report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    /// Solution the report is scoped to.
    pub solution_id: String,
    /// Watcher section.
    pub watcher: WatcherHealth,
    /// Queue section.
    pub queue: QueueHealth,
    /// Database section.
    pub database: DatabaseHealth,
    /// Catalog section.
    pub catalog: CatalogHealth,
    /// Derived worst-of overall state.
    pub overall: HealthState,
    /// Stable reasons for anything that is not healthy.
    pub diagnostics: Vec<String>,
    /// This command never repairs anything.
    pub automatic_repair: bool,
}

impl DoctorReport {
    /// Whether every component is healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.overall.is_healthy()
    }

    /// Stable overall label.
    #[must_use]
    pub fn overall_label(&self) -> &'static str {
        self.overall.wire()
    }

    /// Render the report as the text an operator sees.
    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("solution: {}\n", self.solution_id));
        out.push_str(&format!("overall: {}\n", self.overall.wire()));
        out.push_str(&format!(
            "watcher: {} ({})\n",
            self.watcher.mode.wire(),
            self.watcher.state().wire()
        ));
        out.push_str(&format!("queue: {}\n", self.queue.state().wire()));
        out.push_str(&format!("database: {}\n", self.database.state().wire()));
        out.push_str(&format!("catalog: {}\n", self.catalog.state().wire()));
        for diagnostic in &self.diagnostics {
            out.push_str(&format!("diagnostic: {diagnostic}\n"));
        }
        out
    }
}

/// Read queue health for a solution.
///
/// # Errors
/// [`ErrorCode::NotFound`] with [`REASON_SOLUTION_NOT_REGISTERED`] when the
/// solution has no registration row, and the storage error otherwise.
pub fn read_queue_health(
    connection: &Connection,
    solution_id: &str,
) -> Result<QueueHealth, AxiomError> {
    require_solution(connection, solution_id)?;
    let count = |state: &str| -> Result<i64, AxiomError> {
        connection
            .query_row(
                "SELECT COUNT(*) FROM jobs WHERE solution_id = ?1 AND state = ?2",
                rusqlite::params![solution_id, state],
                |row| row.get(0),
            )
            .map_err(|error| crate::commands::storage_error("queue census", &error))
    };
    let pending = count("PENDING")?;
    let leased = count("LEASED")? + count("RUNNING")?;
    let retry_wait = count("RETRY_WAIT")?;
    let failed = count("FAILED")?;
    Ok(QueueHealth {
        pending,
        leased,
        retry_wait,
        failed,
        healthy: true,
        detail: format!("pending={pending} leased={leased} failed={failed}"),
    })
}

/// Read database health from the live connection.
///
/// # Errors
/// The storage error when the probe itself fails.
pub fn read_database_health(connection: &Connection) -> Result<DatabaseHealth, AxiomError> {
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|error| crate::commands::storage_error("database probe", &error))?;
    let schema_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|error| crate::commands::storage_error("schema probe", &error))?;
    let healthy = integrity == "ok";
    Ok(DatabaseHealth {
        healthy,
        schema_version,
        detail: format!("integrity={integrity} schema_version={schema_version}"),
    })
}

/// Read catalog health for a solution.
///
/// # Errors
/// [`ErrorCode::NotFound`] with [`REASON_SOLUTION_NOT_REGISTERED`] when the
/// solution has no row, and the storage error otherwise.
pub fn read_catalog_health(
    connection: &Connection,
    solution_id: &str,
) -> Result<CatalogHealth, AxiomError> {
    require_solution(connection, solution_id)?;
    let refs: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM catalog_refs \
             WHERE project_id IN (SELECT id FROM projects WHERE solution_id = ?1)",
            [solution_id],
            |row| row.get(0),
        )
        .map_err(|error| crate::commands::storage_error("catalog census", &error))?;
    let generation: Option<String> = connection
        .query_row(
            "SELECT c.catalog_generation_id FROM catalog_refs c \
             WHERE c.project_id IN (SELECT id FROM projects WHERE solution_id = ?1) \
             ORDER BY c.catalog_generation_id DESC LIMIT 1",
            [solution_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| crate::commands::storage_error("catalog lookup", &error))?;
    Ok(CatalogHealth {
        healthy: refs > 0,
        generation_id: generation,
        refs,
        detail: format!("refs={refs}"),
    })
}

fn require_solution(connection: &Connection, solution_id: &str) -> Result<(), AxiomError> {
    let found: Option<String> = connection
        .query_row(
            "SELECT id FROM solutions WHERE id = ?1",
            [solution_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| crate::commands::storage_error("solution lookup", &error))?;
    if found.is_some() {
        return Ok(());
    }
    Err(
        AxiomError::new(ErrorCode::NotFound, "this solution id is not registered")
            .with_detail("rule", REASON_SOLUTION_NOT_REGISTERED)
            .with_detail("solution_id", solution_id),
    )
}

/// Build a doctor report from the three live probes plus a watcher observation.
///
/// The overall state is the worst of the four component states, so a degraded
/// component can never be reported as a healthy daemon.
///
/// # Errors
/// Any probe error, which propagates rather than being swallowed into a
/// misleadingly healthy report.
pub fn report(
    connection: &Connection,
    solution_id: &str,
    watcher: WatcherHealth,
) -> Result<DoctorReport, AxiomError> {
    let queue = read_queue_health(connection, solution_id)?;
    let database = read_database_health(connection)?;
    let catalog = read_catalog_health(connection, solution_id)?;
    let overall = watcher
        .state()
        .worst(queue.state())
        .worst(database.state())
        .worst(catalog.state());
    let mut diagnostics = Vec::new();
    if !watcher.healthy {
        diagnostics.push(REASON_WATCHER_DEGRADED.to_owned());
    }
    if queue.failed > 0 {
        diagnostics.push(REASON_QUEUE_FAILED.to_owned());
    }
    if queue.retry_wait > 0 {
        diagnostics.push(REASON_QUEUE_RETRY_WAIT.to_owned());
    }
    if !database.healthy {
        diagnostics.push(REASON_DATABASE_UNHEALTHY.to_owned());
    }
    if !catalog.healthy {
        diagnostics.push(REASON_CATALOG_MISSING.to_owned());
    }
    Ok(DoctorReport {
        solution_id: solution_id.to_owned(),
        watcher,
        queue,
        database,
        catalog,
        overall,
        diagnostics,
        automatic_repair: false,
    })
}

/// The `status` report: freshness, queue depth, generations and versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusReport {
    /// Solution the report is scoped to.
    pub solution_id: String,
    /// Whether a full scan is still required.
    pub full_scan_required: bool,
    /// Highest observed solution event sequence.
    pub event_seq: i64,
    /// Number of files that are dirty.
    pub dirty_files: i64,
    /// Queue depth by state.
    pub queue: QueueHealth,
    /// Reachable published generations.
    pub generations: i64,
    /// Reachable checkpoint generations.
    pub checkpoint_generations: i64,
}

/// Read the `status` report for a solution.
///
/// # Errors
/// [`ErrorCode::NotFound`] with [`REASON_SOLUTION_NOT_REGISTERED`] when the
/// solution has no row, and the storage error otherwise.
pub fn status(connection: &Connection, solution_id: &str) -> Result<StatusReport, AxiomError> {
    let row: Option<(i64, i64)> = connection
        .query_row(
            "SELECT event_seq, full_scan_required FROM solutions WHERE id = ?1",
            [solution_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| crate::commands::storage_error("solution lookup", &error))?;
    let Some((event_seq, full_scan_required)) = row else {
        return Err(
            AxiomError::new(ErrorCode::NotFound, "this solution id is not registered")
                .with_detail("rule", REASON_SOLUTION_NOT_REGISTERED)
                .with_detail("solution_id", solution_id),
        );
    };
    let queue = read_queue_health(connection, solution_id)?;
    let dirty_files: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM dirty_files d \
             JOIN files f ON f.id = d.file_id \
             WHERE f.project_id IN (SELECT id FROM projects WHERE solution_id = ?1)",
            [solution_id],
            |row| row.get(0),
        )
        .map_err(|error| crate::commands::storage_error("dirty census", &error))?;
    let generations: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM published_generations WHERE lane = 'live' \
             AND project_id IN (SELECT id FROM projects WHERE solution_id = ?1)",
            [solution_id],
            |row| row.get(0),
        )
        .map_err(|error| crate::commands::storage_error("generation census", &error))?;
    let checkpoint_generations: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM published_generations WHERE lane = 'checkpoint' \
             AND project_id IN (SELECT id FROM projects WHERE solution_id = ?1)",
            [solution_id],
            |row| row.get(0),
        )
        .map_err(|error| crate::commands::storage_error("generation census", &error))?;
    Ok(StatusReport {
        solution_id: solution_id.to_owned(),
        full_scan_required: full_scan_required != 0,
        event_seq,
        dirty_files,
        queue,
        generations,
        checkpoint_generations,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    fn open_connection() -> Connection {
        let connection = Connection::open_in_memory().expect("in-memory sqlite");
        connection
            .execute_batch(graph_store::migrations::SCHEMA_V1_SQL)
            .expect("shipped schema");
        connection
    }

    fn seed_solution(connection: &Connection, id: &str) {
        connection
            .execute(
                "INSERT INTO solutions (id, workspace_instance_id, profile, config_hash) \
                 VALUES (?1, ?2, 'default', 'hash')",
                rusqlite::params![id, format!("wi-{id}")],
            )
            .expect("solution");
        connection
            .execute(
                "INSERT INTO projects (id, solution_id, repo_id, relative_path) \
                 VALUES (?1, ?2, 'repo-main', 'src')",
                rusqlite::params![format!("{id}-project"), id],
            )
            .expect("project");
    }

    #[test]
    fn a_healthy_solution_reports_healthy() {
        let connection = open_connection();
        seed_solution(&connection, "demo-solution");
        // A healthy solution has a published catalog reference as well as a
        // registered solution and a clean queue.
        connection
            .execute(
                "INSERT INTO catalog_refs (catalog_generation_id, project_id, generation_id, lane) \
                 VALUES ('cat-1','demo-solution-project','gen-1','live')",
                [],
            )
            .expect("catalog ref");
        let report = report(&connection, "demo-solution", WatcherHealth::native()).expect("report");
        assert!(report.is_healthy());
        assert_eq!(report.overall_label(), "healthy");
        assert!(!report.automatic_repair);
        let text = report.render_text();
        assert!(text.contains("overall: healthy"), "{text}");
    }

    #[test]
    fn a_degraded_component_is_never_rendered_as_a_healthy_daemon() {
        let connection = open_connection();
        seed_solution(&connection, "demo-solution");
        // A failed job degrades the queue.
        connection
            .execute(
                "INSERT INTO jobs (id, solution_id, kind, scope_key, state, target_event_seq, ready_at, created_at) \
                 VALUES ('job-1','demo-solution','reconcile','dirty','FAILED',0,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
                [],
            )
            .expect("job");
        let report = report(&connection, "demo-solution", WatcherHealth::native()).expect("report");
        assert!(!report.is_healthy());
        assert_eq!(report.overall_label(), "degraded");
        assert_eq!(report.queue.state(), HealthState::Degraded);
        let text = report.render_text();
        assert!(text.contains("overall: degraded"), "{text}");
        assert!(!text.contains("overall: healthy"), "{text}");
        assert!(report.diagnostics.iter().any(|d| d == REASON_QUEUE_FAILED));

        // A polling or disabled watcher degrades the report even with a clean queue.
        let clean = open_connection();
        seed_solution(&clean, "demo-solution");
        let degraded = super::report(
            &clean,
            "demo-solution",
            WatcherHealth::degraded(WatcherMode::Polling, "native watcher unavailable"),
        )
        .expect("report");
        assert_eq!(degraded.overall_label(), "degraded");
        assert!(degraded
            .diagnostics
            .iter()
            .any(|d| d == REASON_WATCHER_DEGRADED));
        assert_eq!(WatcherMode::parse("polling"), Some(WatcherMode::Polling));
        assert_eq!(WatcherMode::parse("nope"), None);
    }

    #[test]
    fn a_missing_catalog_generation_is_reported_as_degraded() {
        let connection = open_connection();
        seed_solution(&connection, "demo-solution");
        let report = report(&connection, "demo-solution", WatcherHealth::native()).expect("report");
        assert!(!report.catalog.healthy);
        assert_eq!(report.catalog.state(), HealthState::Degraded);
        assert_eq!(report.overall_label(), "degraded");
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d == REASON_CATALOG_MISSING));
        // Publishing a catalog reference makes it healthy again.
        connection
            .execute(
                "INSERT INTO catalog_refs (catalog_generation_id, project_id, generation_id, lane) \
                 VALUES ('cat-1','demo-solution-project','gen-1','live')",
                [],
            )
            .expect("catalog ref");
        let healed =
            super::report(&connection, "demo-solution", WatcherHealth::native()).expect("report");
        assert!(healed.catalog.healthy);
        assert_eq!(healed.catalog.generation_id.as_deref(), Some("cat-1"));
        assert!(healed.is_healthy());
    }

    #[test]
    fn status_reports_freshness_and_generations() {
        let connection = open_connection();
        seed_solution(&connection, "demo-solution");
        connection
            .execute(
                "UPDATE solutions SET event_seq = 7 WHERE id = 'demo-solution'",
                [],
            )
            .expect("seq");
        connection
            .execute(
                "INSERT INTO files (id, project_id, path, desired_generation, indexed_generation) \
                 VALUES (1,'demo-solution-project','src/a.rs',1,0)",
                [],
            )
            .expect("file");
        connection
            .execute(
                "INSERT INTO dirty_files (file_id, target_generation, first_seen, last_seen, reason) \
                 VALUES (1,1,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','edit')",
                [],
            )
            .expect("dirty");
        let status = status(&connection, "demo-solution").expect("status");
        assert_eq!(status.event_seq, 7);
        assert!(status.full_scan_required);
        assert_eq!(status.dirty_files, 1);
        assert_eq!(status.generations, 0);
        assert_eq!(status.checkpoint_generations, 0);
    }

    #[test]
    fn an_unregistered_solution_is_a_not_found_with_a_stable_reason() {
        let connection = open_connection();
        let error = report(&connection, "missing", WatcherHealth::native()).expect_err("missing");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_SOLUTION_NOT_REGISTERED)
        );
        let error = status(&connection, "missing").expect_err("missing");
        assert_eq!(error.code(), ErrorCode::NotFound);
    }
}
