//! Quarantine-and-rebuild repair planning (task B-019).
//!
//! `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` sections 5, 9 and 10 give the
//! daemon a `Repair` job kind, require a real inventory after downtime and
//! require an upgrade backup rather than a live-file copy. Repair therefore has
//! exactly two safe moves: move the damaged Axiom state aside into a quarantine
//! directory (never delete it), and schedule a rebuild that re-derives the index
//! from the user's source. User source is never an input to the plan and never a
//! target of an operation, and this is enforced structurally: a plan whose
//! operations leave the Axiom state root is refused before anything is applied.

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::is_portable_id;
use rusqlite::params;
use sha2::{Digest, Sha256};

use crate::storage_error;

/// Directory created under the Axiom state root for quarantined state.
pub const DEFAULT_QUARANTINE_DIR: &str = "quarantine";
/// Job kind scheduled by a repair, per section 5.
pub const REPAIR_JOB_KIND: &str = "Repair";

/// What kind of damage was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptionKind {
    /// `PRAGMA integrity_check` reported damage.
    CorruptDatabase,
    /// A migration checksum did not match the recorded one.
    ChecksumMismatch,
    /// The database schema is newer than this binary understands.
    SchemaNewerThanBinary,
}

impl CorruptionKind {
    /// Frozen spelling recorded in the repair job scope.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CorruptDatabase => "corrupt-database",
            Self::ChecksumMismatch => "checksum-mismatch",
            Self::SchemaNewerThanBinary => "schema-newer-than-binary",
        }
    }
}

/// A damage report handed to the repair planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorruptionFinding {
    kind: CorruptionKind,
    state_path: String,
    detail: String,
}

impl CorruptionFinding {
    /// Report `kind` for the Axiom state file `state_path`.
    #[must_use]
    pub fn new(
        kind: CorruptionKind,
        state_path: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            state_path: state_path.into(),
            detail: detail.into(),
        }
    }

    /// Damage kind.
    #[must_use]
    pub const fn kind(&self) -> CorruptionKind {
        self.kind
    }

    /// Axiom state file that is damaged.
    #[must_use]
    pub fn state_path(&self) -> &str {
        &self.state_path
    }

    /// Human-readable detail for evidence.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Where quarantine lives and whether a rebuild is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPolicy {
    state_root: String,
    quarantine_dir: String,
    rebuild: bool,
}

impl RepairPolicy {
    /// Quarantine under `state_root` and rebuild.
    #[must_use]
    pub fn new(state_root: impl Into<String>) -> Self {
        Self {
            state_root: state_root.into(),
            quarantine_dir: DEFAULT_QUARANTINE_DIR.to_string(),
            rebuild: true,
        }
    }

    /// Override the quarantine directory name.
    #[must_use]
    pub fn with_quarantine_dir(mut self, dir: impl Into<String>) -> Self {
        self.quarantine_dir = dir.into();
        self
    }

    /// Choose whether the plan schedules a rebuild.
    #[must_use]
    pub const fn with_rebuild(mut self, rebuild: bool) -> Self {
        self.rebuild = rebuild;
        self
    }

    /// Axiom state root.
    #[must_use]
    pub fn state_root(&self) -> &str {
        &self.state_root
    }
}

/// One step of a repair plan. There is deliberately no delete variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairAction {
    /// Move damaged state into the quarantine directory.
    Quarantine,
    /// Create an empty state file for the rebuild to fill.
    RecreateEmpty,
    /// Queue the rebuild job.
    ScheduleRebuild,
}

impl RepairAction {
    /// Frozen spelling for evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Quarantine => "quarantine",
            Self::RecreateEmpty => "recreate-empty",
            Self::ScheduleRebuild => "schedule-rebuild",
        }
    }
}

/// One planned operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairOperation {
    /// What the operation does.
    pub action: RepairAction,
    /// Axiom state path the operation touches.
    pub path: String,
}

/// A reviewed, non-destructive repair plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPlan {
    /// Axiom state root every operation must stay inside.
    pub state_root: String,
    /// Quarantine destination for the damaged state.
    pub quarantine_path: String,
    /// Planned operations, in order.
    pub operations: Vec<RepairOperation>,
    /// Whether a rebuild job must be scheduled.
    pub rebuild_required: bool,
    /// Damage kind that produced the plan.
    pub kind: CorruptionKind,
}

/// What applying a repair changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairOutcome {
    /// Quarantine destination recorded in the plan.
    pub quarantine_path: String,
    /// Rebuild job id, present when a rebuild was scheduled.
    pub rebuild_job_id: Option<String>,
    /// Whether the solution was marked for a full inventory scan.
    pub full_scan_required: bool,
}

/// Build a quarantine-and-rebuild plan for `finding`.
///
/// `stamp` names the quarantine copy; it must be a portable identifier fragment
/// so the quarantine file name stays portable.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] for a state path outside `policy.state_root`,
///   a non-portable stamp, or an empty quarantine directory name.
pub fn plan_repair(
    finding: &CorruptionFinding,
    policy: &RepairPolicy,
    stamp: &str,
) -> Result<RepairPlan, AxiomError> {
    let state_root = normalise(policy.state_root());
    if state_root.is_empty() {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "repair requires a non-empty Axiom state root",
        )
        .with_detail("rule", "empty-state-root"));
    }
    if policy.quarantine_dir.trim().is_empty() {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "repair requires a non-empty quarantine directory name",
        )
        .with_detail("rule", "empty-quarantine-dir"));
    }
    if !is_portable_id(stamp) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "repair stamp must be a portable Axiom identifier",
        )
        .with_detail("rule", "non-portable-stamp"));
    }
    let state_path = normalise(finding.state_path());
    if !is_within(&state_root, &state_path) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "repair only operates on Axiom state, never on user source",
        )
        .with_detail("rule", "state-path-outside-state-root")
        .with_detail("portable_path", state_path));
    }

    let file_name = state_path.rsplit('/').next().unwrap_or("state").to_string();
    let quarantine_path = format!(
        "{state_root}/{}/{stamp}-{file_name}",
        policy.quarantine_dir.trim_matches('/')
    );

    let mut operations = vec![RepairOperation {
        action: RepairAction::Quarantine,
        path: quarantine_path.clone(),
    }];
    if policy.rebuild {
        operations.push(RepairOperation {
            action: RepairAction::RecreateEmpty,
            path: state_path,
        });
        operations.push(RepairOperation {
            action: RepairAction::ScheduleRebuild,
            path: quarantine_path.clone(),
        });
    }

    let plan = RepairPlan {
        state_root,
        quarantine_path,
        operations,
        rebuild_required: policy.rebuild,
        kind: finding.kind(),
    };
    verify_plan_within_state(&plan)?;
    Ok(plan)
}

/// Refuse a plan that leaves the Axiom state root.
///
/// # Errors
/// Returns [`ErrorCode::ValidationError`] for an operation or quarantine path
/// outside `plan.state_root`.
pub fn verify_plan_within_state(plan: &RepairPlan) -> Result<(), AxiomError> {
    if !is_within(&plan.state_root, &plan.quarantine_path) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "quarantine path escapes the Axiom state root",
        )
        .with_detail("rule", "quarantine-outside-state-root")
        .with_detail("portable_path", plan.quarantine_path.clone()));
    }
    for operation in &plan.operations {
        if operation.action == RepairAction::ScheduleRebuild {
            continue;
        }
        if !is_within(&plan.state_root, &operation.path) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "repair operation escapes the Axiom state root",
            )
            .with_detail("rule", "operation-outside-state-root")
            .with_detail("portable_path", operation.path.clone()));
        }
    }
    Ok(())
}

/// Record a repair: mark the solution for a full scan and schedule the rebuild.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] for a non-portable solution id or a plan
///   that escapes the state root.
/// - [`ErrorCode::NotFound`] when the solution is not registered.
/// - [`ErrorCode::Internal`] for a storage failure.
pub fn apply_repair(
    connection: &mut rusqlite::Connection,
    solution_id: &str,
    plan: &RepairPlan,
    now: &str,
) -> Result<RepairOutcome, AxiomError> {
    if !is_portable_id(solution_id) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "solution id must be a portable Axiom identifier",
        )
        .with_detail("solution_id", solution_id));
    }
    verify_plan_within_state(plan)?;

    let transaction = connection
        .transaction()
        .map_err(|error| storage_error("repair transaction", &error))?;
    let event_seq: Option<i64> = transaction
        .query_row(
            "SELECT event_seq FROM solutions WHERE id = ?1",
            [solution_id],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .map_err(|error| storage_error("repair solution lookup", &error))?;
    let Some(event_seq) = event_seq else {
        return Err(
            AxiomError::new(ErrorCode::NotFound, "solution is not registered")
                .with_detail("solution_id", solution_id),
        );
    };

    transaction
        .execute(
            "UPDATE solutions SET full_scan_required = 1 WHERE id = ?1",
            [solution_id],
        )
        .map_err(|error| storage_error("repair full-scan flag", &error))?;

    let rebuild_job_id =
        if plan.rebuild_required {
            let scope_key = format!("{}:{}", plan.kind.as_str(), quarantine_digest(plan));
            let existing: Option<String> = transaction
                .query_row(
                    "SELECT id FROM jobs WHERE solution_id = ?1 AND kind = ?2 AND scope_key = ?3 \
                 AND state IN ('PENDING','RETRY_WAIT')",
                    params![solution_id, REPAIR_JOB_KIND, scope_key],
                    |row| row.get(0),
                )
                .map(Some)
                .or_else(|error| match error {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })
                .map_err(|error| storage_error("repair job lookup", &error))?;
            let job_id =
                match existing {
                    Some(id) => id,
                    None => {
                        let id = format!("repair-{}", quarantine_digest(plan));
                        transaction
                    .execute(
                        "INSERT INTO jobs(id, solution_id, kind, scope_key, state, priority, \
                         target_event_seq, attempt, fence, ready_at, created_at) \
                         VALUES(?1, ?2, ?3, ?4, 'PENDING', 0, ?5, 0, 0, ?6, ?6)",
                        params![id, solution_id, REPAIR_JOB_KIND, scope_key, event_seq + 1, now],
                    )
                    .map_err(|error| storage_error("repair job insert", &error))?;
                        id
                    }
                };
            Some(job_id)
        } else {
            None
        };

    transaction
        .commit()
        .map_err(|error| storage_error("repair commit", &error))?;
    Ok(RepairOutcome {
        quarantine_path: plan.quarantine_path.clone(),
        rebuild_job_id,
        full_scan_required: true,
    })
}

fn quarantine_digest(plan: &RepairPlan) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plan.quarantine_path.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Separator-normalised, `..`-free path.
fn normalise(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    let mut joined = segments.join("/");
    if path.starts_with('/') || path.starts_with('\\') {
        joined.insert(0, '/');
    }
    joined
}

/// Whether `path` is `root` or a descendant of it, by whole path segment.
fn is_within(root: &str, path: &str) -> bool {
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return false;
    }
    if path == root {
        return true;
    }
    path.strip_prefix(root)
        .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{memory_store, seed_solution};

    const STAMP: &str = "stamp-20260918t101500";
    const STATE_FILE: &str = "/srv/axiom/state/instances/inst-one/index.sqlite";

    fn corrupt_finding() -> CorruptionFinding {
        CorruptionFinding::new(
            CorruptionKind::CorruptDatabase,
            STATE_FILE,
            "PRAGMA integrity_check reported a malformed page",
        )
    }

    #[test]
    fn corruption_is_quarantined_and_a_rebuild_is_scheduled() {
        let mut connection = memory_store();
        seed_solution(&connection, "sol-one", "inst-one");

        let plan = plan_repair(
            &corrupt_finding(),
            &RepairPolicy::new("/srv/axiom/state"),
            STAMP,
        )
        .expect("repair plan");
        assert_eq!(
            plan.quarantine_path,
            "/srv/axiom/state/quarantine/stamp-20260918t101500-index.sqlite"
        );
        assert!(plan.rebuild_required);
        assert_eq!(plan.operations.len(), 3);
        assert_eq!(plan.operations[0].action, RepairAction::Quarantine);
        assert!(plan.operations[0].path.ends_with("index.sqlite"));
        verify_plan_within_state(&plan).expect("plan stays inside the state root");

        let outcome = apply_repair(&mut connection, "sol-one", &plan, "2026-09-18T10:15:00Z")
            .expect("apply repair");
        assert!(outcome.full_scan_required);
        let job_id = outcome.rebuild_job_id.expect("rebuild job");
        let (kind, state): (String, String) = connection
            .query_row(
                "SELECT kind, state FROM jobs WHERE id = ?1",
                [&job_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("rebuild job row");
        assert_eq!(kind, REPAIR_JOB_KIND);
        assert_eq!(state, "PENDING");
        let full_scan: i64 = connection
            .query_row(
                "SELECT full_scan_required FROM solutions WHERE id = 'sol-one'",
                [],
                |row| row.get(0),
            )
            .expect("full-scan flag");
        assert_eq!(full_scan, 1);

        // Re-planning the same damage reuses the pending rebuild instead of
        // stacking duplicate work.
        let again = apply_repair(&mut connection, "sol-one", &plan, "2026-09-18T10:16:00Z")
            .expect("apply repair again");
        assert_eq!(again.rebuild_job_id.as_deref(), Some(job_id.as_str()));
        let jobs: i64 = connection
            .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))
            .expect("job count");
        assert_eq!(jobs, 1);
    }

    #[test]
    fn a_plan_that_would_touch_user_source_is_refused() {
        let policy = RepairPolicy::new("/srv/axiom/state");
        let finding = CorruptionFinding::new(
            CorruptionKind::CorruptDatabase,
            "/home/user/project/src/App.cs",
            "PRAGMA integrity_check reported a malformed page",
        );
        assert_eq!(
            plan_repair(&finding, &policy, STAMP)
                .expect_err("user source is never repair input")
                .code(),
            ErrorCode::ValidationError
        );

        // A hand-built plan cannot smuggle an operation out of the state root.
        let escaping = RepairPlan {
            state_root: "/srv/axiom/state".to_string(),
            quarantine_path: format!("/srv/axiom/state/quarantine/{STAMP}-index.sqlite"),
            operations: vec![RepairOperation {
                action: RepairAction::RecreateEmpty,
                path: "/home/user/project/src/App.cs".to_string(),
            }],
            rebuild_required: true,
            kind: CorruptionKind::CorruptDatabase,
        };
        assert_eq!(
            verify_plan_within_state(&escaping)
                .expect_err("operation escapes the state root")
                .code(),
            ErrorCode::ValidationError
        );

        // Nor can it name an unregistered solution.
        let mut connection = memory_store();
        let plan = plan_repair(&corrupt_finding(), &policy, STAMP).expect("repair plan");
        assert_eq!(
            apply_repair(
                &mut connection,
                "sol-missing",
                &plan,
                "2026-09-18T10:15:00Z"
            )
            .expect_err("unknown solution")
            .code(),
            ErrorCode::NotFound
        );
    }
}
