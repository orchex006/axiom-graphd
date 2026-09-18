//! Shared in-memory fixtures for graph-store unit tests.
//!
//! Every fixture builds on the real `schema-v1.sql` through [`migrations::apply`],
//! including `PRAGMA foreign_keys = ON`, so a test that deletes rows in the wrong
//! order fails instead of passing on a laxer schema.

use rusqlite::{params, Connection};

use crate::migrations;

/// An in-memory database carrying the current schema.
pub(crate) fn memory_store() -> Connection {
    let mut connection = Connection::open_in_memory().expect("open in-memory sqlite");
    migrations::apply(&mut connection).expect("schema v1 applies");
    connection
}

/// Register a solution row.
pub(crate) fn seed_solution(connection: &Connection, id: &str, instance_key: &str) {
    connection
        .execute(
            "INSERT INTO solutions(id, workspace_instance_id, profile, config_hash) \
             VALUES(?1, ?2, 'default', 'config-hash')",
            params![id, instance_key],
        )
        .expect("seed solution");
}

/// Register a project row bound to its own repository.
///
/// The project id doubles as the repository id so one solution can hold several
/// projects without violating `UNIQUE(solution_id, repo_id, relative_path)`.
pub(crate) fn seed_project(connection: &Connection, id: &str, solution_id: &str) {
    connection
        .execute(
            "INSERT INTO projects(id, solution_id, repo_id, relative_path) \
             VALUES(?1, ?2, ?1, '.')",
            params![id, solution_id],
        )
        .expect("seed project");
}

/// Register an indexed file row and return its id.
pub(crate) fn seed_file(connection: &Connection, project_id: &str, path: &str) -> i64 {
    connection
        .execute(
            "INSERT INTO files(project_id, path, observed_hash, indexed_hash, \
             desired_generation, indexed_generation) VALUES(?1, ?2, 'seed', 'seed', 1, 1)",
            params![project_id, path],
        )
        .expect("seed file");
    connection.last_insert_rowid()
}

/// Register a node owned by a file.
pub(crate) fn seed_node(
    connection: &Connection,
    id: &str,
    project_id: &str,
    file_id: i64,
    qualified_name: &str,
) {
    connection
        .execute(
            "INSERT INTO nodes(id, project_id, owner_file_id, kind, qualified_name, record_json) \
             VALUES(?1, ?2, ?3, 'method', ?4, '{}')",
            params![id, project_id, file_id, qualified_name],
        )
        .expect("seed node");
}

/// Register a job in the given state.
pub(crate) fn seed_job(connection: &Connection, id: &str, solution_id: &str, state: &str) {
    connection
        .execute(
            "INSERT INTO jobs(id, solution_id, kind, scope_key, state, priority, \
             target_event_seq, attempt, fence, ready_at, created_at) \
             VALUES(?1, ?2, 'ParseBatch', ?1, ?3, 0, 1, 0, 0, '2026-09-18T00:00:00Z', \
             '2026-09-18T00:00:00Z')",
            params![id, solution_id, state],
        )
        .expect("seed job");
}

/// Register a runtime checkpoint.
pub(crate) fn seed_checkpoint(connection: &Connection, id: &str, solution_id: &str) {
    connection
        .execute(
            "INSERT INTO runtime_checkpoints(id, solution_id, source_mode, source_revision, \
             catalog_generation_id, verified_at) \
             VALUES(?1, ?2, 'worktree', NULL, 'gen-1', '2026-09-18T00:00:00Z')",
            params![id, solution_id],
        )
        .expect("seed checkpoint");
}
