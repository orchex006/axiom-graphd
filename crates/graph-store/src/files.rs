//! Generation-aware file inventory and tombstone reconciliation (task B-015).
//!
//! `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` sections 3 and 9 require the
//! daemon to compare a real inventory against the database instead of trusting a
//! watcher hint or a stale `content_hash` column. Every observation advances the
//! file's `desired_generation`; an analysis result is acknowledged only against
//! the exact generation it analyzed, so a file that changed while a worker was
//! parsing stays dirty. A file that vanished from the inventory becomes a
//! tombstone (`deleted = 1`) with a dirty generation, never a silently clean row.

use std::collections::BTreeMap;

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::is_portable_id;
use rusqlite::{params, Connection};

use crate::migrations::utc_timestamp;
use crate::storage_error;

/// Upper bound on files in one inventory batch.
///
/// The parser batch default is 64 files / 16 MiB (section 6); the inventory
/// batch is bounded larger but still bounded, so a hostile directory cannot make
/// one reconciliation unbounded.
pub const MAX_INVENTORY_BATCH: usize = 4096;

/// Dirty reason recorded for a path that appeared for the first time.
pub const REASON_NEW_FILE: &str = "new-file";
/// Dirty reason recorded when an observed content digest differs from the stored one.
pub const REASON_CONTENT_CHANGE: &str = "content-change";
/// Dirty reason recorded when a previously deleted path reappears.
pub const REASON_REAPPEARED: &str = "reappeared";
/// Dirty reason recorded for a path missing from the inventory.
pub const REASON_DELETED: &str = "deleted";

/// One file observed on disk during an inventory scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedFile {
    path: String,
    content_hash: String,
}

impl ObservedFile {
    /// Record `path` with its observed content digest.
    #[must_use]
    pub fn new(path: impl Into<String>, content_hash: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            content_hash: content_hash.into(),
        }
    }

    /// Repository-relative, project-relative path as it will be stored.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Observed content digest.
    #[must_use]
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }
}

/// What one inventory reconciliation changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InventoryReport {
    /// Generation the whole batch advanced the project to.
    pub generation: i64,
    /// Paths seen for the first time.
    pub added: usize,
    /// Paths whose content digest changed or that reappeared after deletion.
    pub changed: usize,
    /// Paths whose digest matched the stored observation.
    pub unchanged: usize,
    /// Paths newly tombstoned because they were absent from the inventory.
    pub deleted: usize,
    /// Dirty rows written or advanced by this reconciliation.
    pub queued: usize,
}

/// Outcome of acknowledging an analyzed generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcome {
    /// The analyzed generation was still current; the result was applied.
    Applied,
    /// A newer generation arrived first, so the result was discarded and the
    /// file remains dirty.
    Superseded {
        /// Generation the file currently requires.
        desired_generation: i64,
        /// Generation the discarded result analyzed.
        target_generation: i64,
    },
}

impl AckOutcome {
    /// Whether the result was applied.
    #[must_use]
    pub const fn is_applied(self) -> bool {
        matches!(self, Self::Applied)
    }
}

struct FileRow {
    id: i64,
    observed_hash: Option<String>,
    desired_generation: i64,
    deleted: bool,
}

/// Reconcile a project's inventory against the stored file rows.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] for a non-portable project id, a batch over
///   [`MAX_INVENTORY_BATCH`], a duplicated observed path, a non-positive
///   generation, or a generation that does not advance the project.
/// - [`ErrorCode::UnsafePortablePath`] for an observed path that violates the
///   portable path policy.
/// - [`ErrorCode::NotFound`] when `project_id` has no row.
/// - [`ErrorCode::Internal`] for a storage failure.
pub fn apply_inventory(
    connection: &mut Connection,
    project_id: &str,
    generation: i64,
    observed: &[ObservedFile],
) -> Result<InventoryReport, AxiomError> {
    if !is_portable_id(project_id) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "project id must be a portable Axiom identifier",
        )
        .with_detail("project_id", project_id));
    }
    if generation < 1 {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "inventory generation must be positive",
        )
        .with_detail("generation", generation.to_string()));
    }
    if observed.len() > MAX_INVENTORY_BATCH {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "inventory batch exceeds the bounded size",
        )
        .with_detail("limit", MAX_INVENTORY_BATCH.to_string())
        .with_detail("observed", observed.len().to_string()));
    }
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    for file in observed {
        graph_core::paths::validate_portable_relative_path(file.path())?;
        if seen.insert(file.path(), file.content_hash()).is_some() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "inventory observed the same path twice",
            )
            .with_detail("rule", "duplicate-inventory-path")
            .with_detail("portable_path", file.path()));
        }
    }

    let now = utc_timestamp();
    let transaction = connection
        .transaction()
        .map_err(|error| storage_error("inventory transaction", &error))?;

    let project_exists: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM projects WHERE id = ?1",
            [project_id],
            |row| row.get(0),
        )
        .map_err(|error| storage_error("inventory project lookup", &error))?;
    if project_exists == 0 {
        return Err(AxiomError::new(
            ErrorCode::NotFound,
            "project is not registered in this solution",
        )
        .with_detail("project_id", project_id));
    }

    let mut rows: BTreeMap<String, FileRow> = BTreeMap::new();
    let mut highest: i64 = 0;
    {
        let mut statement = transaction
            .prepare(
                "SELECT id, path, observed_hash, desired_generation, deleted FROM files \
                 WHERE project_id = ?1",
            )
            .map_err(|error| storage_error("inventory file query", &error))?;
        let mut cursor = statement
            .query_map([project_id], |row| {
                Ok((
                    row.get::<_, String>(1)?,
                    FileRow {
                        id: row.get(0)?,
                        observed_hash: row.get(2)?,
                        desired_generation: row.get(3)?,
                        deleted: row.get::<_, i64>(4)? != 0,
                    },
                ))
            })
            .map_err(|error| storage_error("inventory file query", &error))?;
        for row in cursor.by_ref() {
            let (path, file) = row.map_err(|error| storage_error("inventory file row", &error))?;
            highest = highest.max(file.desired_generation);
            rows.insert(path, file);
        }
    }
    if generation <= highest {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "inventory generation must advance the project",
        )
        .with_detail("observed", generation.to_string())
        .with_detail("expected", (highest + 1).to_string()));
    }

    let mut report = InventoryReport {
        generation,
        ..InventoryReport::default()
    };

    for file in observed {
        let previous = rows.remove(file.path());
        match previous {
            None => {
                transaction
                    .execute(
                        "INSERT INTO files(project_id, path, observed_hash, indexed_hash, \
                         desired_generation, indexed_generation, deleted) \
                         VALUES(?1, ?2, ?3, NULL, ?4, 0, 0)",
                        params![project_id, file.path(), file.content_hash(), generation],
                    )
                    .map_err(|error| storage_error("inventory insert", &error))?;
                report.added += 1;
                queue_dirty(
                    &transaction,
                    file.path(),
                    project_id,
                    generation,
                    REASON_NEW_FILE,
                    &now,
                )?;
                report.queued += 1;
            }
            Some(row) => {
                let digest_changed = row.observed_hash.as_deref() != Some(file.content_hash());
                let reappeared = row.deleted;
                if digest_changed || reappeared {
                    transaction
                        .execute(
                            "UPDATE files SET observed_hash = ?1, desired_generation = ?2, \
                             deleted = 0 WHERE id = ?3",
                            params![file.content_hash(), generation, row.id],
                        )
                        .map_err(|error| storage_error("inventory update", &error))?;
                    let reason = if reappeared {
                        REASON_REAPPEARED
                    } else {
                        REASON_CONTENT_CHANGE
                    };
                    queue_dirty_id(&transaction, row.id, generation, reason, &now)?;
                    report.changed += 1;
                    report.queued += 1;
                } else {
                    if row.deleted {
                        transaction
                            .execute("UPDATE files SET deleted = 0 WHERE id = ?1", [row.id])
                            .map_err(|error| storage_error("inventory update", &error))?;
                    }
                    report.unchanged += 1;
                }
            }
        }
    }

    for (_path, row) in rows {
        if row.deleted {
            continue;
        }
        transaction
            .execute(
                "UPDATE files SET deleted = 1, observed_hash = NULL, desired_generation = ?1 \
                 WHERE id = ?2",
                params![generation, row.id],
            )
            .map_err(|error| storage_error("inventory tombstone", &error))?;
        queue_dirty_id(&transaction, row.id, generation, REASON_DELETED, &now)?;
        report.deleted += 1;
        report.queued += 1;
    }

    transaction
        .commit()
        .map_err(|error| storage_error("inventory commit", &error))?;
    Ok(report)
}

/// Acknowledge the result of analyzing `file_id` at `target_generation`.
///
/// The acknowledgement is conditional on the analyzed generation: a newer
/// generation that arrived while the worker was parsing wins, the result is
/// discarded as [`AckOutcome::Superseded`], and the file stays dirty.
///
/// # Errors
/// - [`ErrorCode::NotFound`] when `file_id` has no row.
/// - [`ErrorCode::Internal`] for a storage failure.
pub fn ack_generation(
    connection: &mut Connection,
    file_id: i64,
    target_generation: i64,
    indexed_hash: Option<&str>,
) -> Result<AckOutcome, AxiomError> {
    let transaction = connection
        .transaction()
        .map_err(|error| storage_error("ack transaction", &error))?;
    let desired: Option<i64> = transaction
        .query_row(
            "SELECT desired_generation FROM files WHERE id = ?1",
            [file_id],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .map_err(|error| storage_error("ack file lookup", &error))?;
    let Some(desired) = desired else {
        return Err(AxiomError::new(
            ErrorCode::NotFound,
            "file is not registered in this project",
        ));
    };
    if desired != target_generation {
        return Ok(AckOutcome::Superseded {
            desired_generation: desired,
            target_generation,
        });
    }
    transaction
        .execute(
            "UPDATE files SET indexed_generation = ?1, indexed_hash = ?2 WHERE id = ?3",
            params![target_generation, indexed_hash, file_id],
        )
        .map_err(|error| storage_error("ack update", &error))?;
    transaction
        .execute(
            "DELETE FROM dirty_files WHERE file_id = ?1 AND target_generation = ?2",
            params![file_id, target_generation],
        )
        .map_err(|error| storage_error("ack dirty delete", &error))?;
    transaction
        .commit()
        .map_err(|error| storage_error("ack commit", &error))?;
    Ok(AckOutcome::Applied)
}

/// Paths of a project that are currently dirty, ordered by path.
///
/// # Errors
/// Returns [`ErrorCode::Internal`] for a storage failure.
pub fn dirty_paths(connection: &Connection, project_id: &str) -> Result<Vec<String>, AxiomError> {
    let mut statement = connection
        .prepare(
            "SELECT f.path FROM files f JOIN dirty_files d ON d.file_id = f.id \
             WHERE f.project_id = ?1 ORDER BY f.path",
        )
        .map_err(|error| storage_error("dirty query", &error))?;
    let rows = statement
        .query_map([project_id], |row| row.get::<_, String>(0))
        .map_err(|error| storage_error("dirty query", &error))?;
    let mut paths = Vec::new();
    for row in rows {
        paths.push(row.map_err(|error| storage_error("dirty row", &error))?);
    }
    Ok(paths)
}

fn queue_dirty(
    transaction: &rusqlite::Transaction<'_>,
    path: &str,
    project_id: &str,
    generation: i64,
    reason: &str,
    now: &str,
) -> Result<(), AxiomError> {
    let file_id: i64 = transaction
        .query_row(
            "SELECT id FROM files WHERE project_id = ?1 AND path = ?2",
            params![project_id, path],
            |row| row.get(0),
        )
        .map_err(|error| storage_error("dirty file lookup", &error))?;
    queue_dirty_id(transaction, file_id, generation, reason, now)
}

fn queue_dirty_id(
    transaction: &rusqlite::Transaction<'_>,
    file_id: i64,
    generation: i64,
    reason: &str,
    now: &str,
) -> Result<(), AxiomError> {
    transaction
        .execute(
            "INSERT INTO dirty_files(file_id, target_generation, first_seen, last_seen, reason) \
             VALUES(?1, ?2, ?3, ?3, ?4) \
             ON CONFLICT(file_id) DO UPDATE SET target_generation = excluded.target_generation, \
             last_seen = excluded.last_seen, reason = excluded.reason",
            params![file_id, generation, now, reason],
        )
        .map_err(|error| storage_error("dirty upsert", &error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{memory_store, seed_project, seed_solution};

    fn store() -> Connection {
        let connection = memory_store();
        seed_solution(&connection, "sol-one", "inst-one");
        seed_project(&connection, "proj-app", "sol-one");
        connection
    }

    fn file_id(connection: &Connection, path: &str) -> i64 {
        connection
            .query_row("SELECT id FROM files WHERE path = ?1", [path], |row| {
                row.get(0)
            })
            .expect("file id")
    }

    #[test]
    fn inventory_tracks_new_changed_and_deleted_generations() {
        let mut connection = store();
        let first = apply_inventory(
            &mut connection,
            "proj-app",
            1,
            &[
                ObservedFile::new("src/App.cs", "h1"),
                ObservedFile::new("src/Keep.cs", "h2"),
            ],
        )
        .expect("first inventory");
        assert_eq!((first.added, first.changed, first.deleted), (2, 0, 0));
        assert_eq!(first.queued, 2);
        assert_eq!(
            dirty_paths(&connection, "proj-app").expect("dirty"),
            vec!["src/App.cs".to_string(), "src/Keep.cs".to_string()]
        );

        // An unchanged digest queues nothing new.
        let second = apply_inventory(
            &mut connection,
            "proj-app",
            2,
            &[
                ObservedFile::new("src/App.cs", "h1"),
                ObservedFile::new("src/Keep.cs", "h3"),
            ],
        )
        .expect("second inventory");
        assert_eq!((second.added, second.changed, second.unchanged), (0, 1, 1));

        // A path missing from the inventory becomes a tombstone, not a clean row.
        let third = apply_inventory(
            &mut connection,
            "proj-app",
            3,
            &[ObservedFile::new("src/App.cs", "h1")],
        )
        .expect("third inventory");
        assert_eq!((third.deleted, third.changed), (1, 0));
        let (deleted, observed_hash, desired): (i64, Option<String>, i64) = connection
            .query_row(
                "SELECT deleted, observed_hash, desired_generation FROM files WHERE path = 'src/Keep.cs'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("tombstone row");
        assert_eq!(deleted, 1);
        assert_eq!(observed_hash, None);
        assert_eq!(desired, 3);
        assert!(dirty_paths(&connection, "proj-app")
            .expect("dirty")
            .contains(&"src/Keep.cs".to_string()));
    }

    #[test]
    fn stale_acknowledgement_keeps_the_newer_generation_dirty() {
        let mut connection = store();
        apply_inventory(
            &mut connection,
            "proj-app",
            1,
            &[ObservedFile::new("src/App.cs", "h1")],
        )
        .expect("inventory 1");
        let id = file_id(&connection, "src/App.cs");

        assert_eq!(
            ack_generation(&mut connection, id, 1, Some("h1")).expect("ack 1"),
            AckOutcome::Applied
        );
        assert!(dirty_paths(&connection, "proj-app")
            .expect("dirty")
            .is_empty());

        // Generation 2 arrives, is analyzed and acknowledged.
        apply_inventory(
            &mut connection,
            "proj-app",
            2,
            &[ObservedFile::new("src/App.cs", "h2")],
        )
        .expect("inventory 2");
        assert!(ack_generation(&mut connection, id, 2, Some("h2"))
            .expect("ack 2")
            .is_applied());

        // Generation 3 arrives while a slow worker still holds generation 2.
        apply_inventory(
            &mut connection,
            "proj-app",
            3,
            &[ObservedFile::new("src/App.cs", "h3")],
        )
        .expect("inventory 3");
        assert_eq!(
            ack_generation(&mut connection, id, 2, Some("h2")).expect("stale ack"),
            AckOutcome::Superseded {
                desired_generation: 3,
                target_generation: 2,
            }
        );
        let indexed: i64 = connection
            .query_row(
                "SELECT indexed_generation FROM files WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .expect("indexed generation");
        assert_eq!(indexed, 2);
        assert_eq!(
            dirty_paths(&connection, "proj-app").expect("dirty"),
            vec!["src/App.cs".to_string()]
        );
    }

    #[test]
    fn stale_generations_and_duplicate_paths_are_refused() {
        let mut connection = store();
        apply_inventory(
            &mut connection,
            "proj-app",
            4,
            &[ObservedFile::new("src/App.cs", "h1")],
        )
        .expect("inventory");
        assert_eq!(
            apply_inventory(
                &mut connection,
                "proj-app",
                4,
                &[ObservedFile::new("src/App.cs", "h1")]
            )
            .expect_err("non-advancing generation")
            .code(),
            ErrorCode::ValidationError
        );
        assert_eq!(
            apply_inventory(
                &mut connection,
                "proj-app",
                5,
                &[
                    ObservedFile::new("src/App.cs", "h1"),
                    ObservedFile::new("src/App.cs", "h2"),
                ]
            )
            .expect_err("duplicate path")
            .code(),
            ErrorCode::ValidationError
        );
        assert_eq!(
            apply_inventory(&mut connection, "proj-missing", 6, &[])
                .expect_err("unknown project")
                .code(),
            ErrorCode::NotFound
        );
    }
}
