//! Incoming-reference queries that never pretend to be complete (task B-017).
//!
//! `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 7 uses incoming edges to
//! find the affected set, and section 8 refuses to report a fresh answer when the
//! required scope is not indexed. A caller asking "who calls this" must therefore
//! get one of two honest answers: the references the local index knows, or an
//! explicit "this scope is not indexed". An empty result is only ever reported
//! for a scope that is fully indexed, so a partial index can never be mistaken
//! for "nobody calls it". The query crosses project boundaries inside the
//! solution, because a cross-project edge is exactly what a caller is asking
//! about.

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::is_portable_id;
use rusqlite::{params, Connection};

use crate::storage_error;

/// One reference pointing at a node, from any project of the solution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingReference {
    /// Edge id.
    pub edge_id: String,
    /// Node id the edge starts at.
    pub source_id: String,
    /// Project that owns the referencing node.
    pub source_project_id: String,
    /// Edge kind.
    pub kind: String,
    /// Frozen resolution spelling stored on the edge.
    pub resolution: String,
    /// Resolved target node id, when the edge still resolves.
    pub target_id: Option<String>,
    /// Unresolved target name, when the edge does not resolve.
    pub unresolved_target: Option<String>,
}

/// How much of a project's file set the local index has actually covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexCoverage {
    /// Files the project owns, excluding tombstones.
    pub total_files: usize,
    /// Files still waiting for an analysis result.
    pub pending_files: usize,
}

impl IndexCoverage {
    /// Whether the index covers every file of the project.
    ///
    /// A project with no files at all is *not* covered: an empty index is an
    /// absence of evidence, and this query exists precisely to avoid reading that
    /// absence as proof.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.total_files > 0 && self.pending_files == 0
    }
}

/// The answer to an incoming-reference query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceAnswer {
    /// The target's project is fully indexed; the list is complete.
    Known(Vec<IncomingReference>),
    /// The target's project has pending or absent coverage, so the query cannot
    /// answer yet. The caller must reconcile rather than conclude "no callers".
    NotIndexed(IndexCoverage),
}

impl ReferenceAnswer {
    /// The references, when the answer is [`ReferenceAnswer::Known`].
    #[must_use]
    pub fn references(&self) -> Option<&[IncomingReference]> {
        match self {
            Self::Known(references) => Some(references),
            Self::NotIndexed(_) => None,
        }
    }
}

/// Find every reference to `node_id` inside `solution_id`.
///
/// `kind` optionally narrows the edge kind.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] for a non-portable solution id.
/// - [`ErrorCode::NotFound`] when the node is not part of the solution.
/// - [`ErrorCode::Internal`] for a storage failure.
pub fn incoming_references(
    connection: &Connection,
    solution_id: &str,
    node_id: &str,
    kind: Option<&str>,
) -> Result<ReferenceAnswer, AxiomError> {
    if !is_portable_id(solution_id) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "solution id must be a portable Axiom identifier",
        )
        .with_detail("solution_id", solution_id));
    }

    let target: Option<(String, String)> = connection
        .query_row(
            "SELECT n.project_id, n.qualified_name FROM nodes n \
             JOIN projects p ON p.id = n.project_id \
             WHERE n.id = ?1 AND p.solution_id = ?2",
            params![node_id, solution_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .map_err(|error| storage_error("reverse index node lookup", &error))?;
    let Some((project_id, qualified_name)) = target else {
        return Err(
            AxiomError::new(ErrorCode::NotFound, "node is not part of this solution")
                .with_detail("solution_id", solution_id),
        );
    };

    let coverage = project_coverage(connection, &project_id)?;
    if !coverage.is_complete() {
        return Ok(ReferenceAnswer::NotIndexed(coverage));
    }

    let mut statement = connection
        .prepare(
            "SELECT e.id, e.source_id, n.project_id, e.kind, e.resolution, e.target_id, \
             e.unresolved_target \
             FROM edges e \
             JOIN nodes n ON n.id = e.source_id \
             JOIN projects p ON p.id = n.project_id \
             WHERE p.solution_id = ?1 AND e.target_project_id = ?2 \
             AND (e.target_id = ?3 OR e.unresolved_target = ?4) \
             AND (?5 IS NULL OR e.kind = ?5) \
             ORDER BY e.source_id, e.id",
        )
        .map_err(|error| storage_error("reverse index query", &error))?;
    let rows = statement
        .query_map(
            params![solution_id, project_id, node_id, qualified_name, kind],
            |row| {
                Ok(IncomingReference {
                    edge_id: row.get(0)?,
                    source_id: row.get(1)?,
                    source_project_id: row.get(2)?,
                    kind: row.get(3)?,
                    resolution: row.get(4)?,
                    target_id: row.get(5)?,
                    unresolved_target: row.get(6)?,
                })
            },
        )
        .map_err(|error| storage_error("reverse index query", &error))?;
    let mut references = Vec::new();
    for row in rows {
        references.push(row.map_err(|error| storage_error("reverse index row", &error))?);
    }
    Ok(ReferenceAnswer::Known(references))
}

/// Coverage of one project, computed from the dirty-file generation state.
///
/// # Errors
/// Returns [`ErrorCode::Internal`] for a storage failure.
pub fn project_coverage(
    connection: &Connection,
    project_id: &str,
) -> Result<IndexCoverage, AxiomError> {
    let row: (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN d.file_id IS NOT NULL THEN 1 ELSE 0 END), 0) \
             FROM files f LEFT JOIN dirty_files d ON d.file_id = f.id \
             WHERE f.project_id = ?1 AND f.deleted = 0",
            [project_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| storage_error("coverage query", &error))?;
    Ok(IndexCoverage {
        total_files: usize::try_from(row.0).unwrap_or(usize::MAX),
        pending_files: usize::try_from(row.1).unwrap_or(usize::MAX),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::{apply_inventory, ObservedFile};
    use crate::graph_rows::{replace_file_facts, EdgeFact, EdgeTarget, GraphFactSet, NodeFact};
    use crate::test_support::{memory_store, seed_file, seed_project, seed_solution};

    #[test]
    fn incoming_references_cross_project_boundaries() {
        let mut connection = memory_store();
        seed_solution(&connection, "sol-one", "inst-one");
        seed_project(&connection, "proj-app", "sol-one");
        seed_project(&connection, "proj-lib", "sol-one");
        let app = seed_file(&connection, "proj-app", "src/App.cs");
        let lib = seed_file(&connection, "proj-lib", "src/Lib.cs");
        replace_file_facts(
            &mut connection,
            "proj-app",
            app,
            &GraphFactSet::new(
                vec![NodeFact::new("node-app", "method", "App.Run", "{}")],
                vec![EdgeFact::new(
                    "edge-cross",
                    "node-app",
                    EdgeTarget::Resolved("node-lib".to_string()),
                    "proj-lib",
                    "calls",
                    "{}",
                )],
            ),
        )
        .expect("app facts");
        replace_file_facts(
            &mut connection,
            "proj-lib",
            lib,
            &GraphFactSet::new(
                vec![NodeFact::new("node-lib", "method", "Lib.Helper", "{}")],
                vec![],
            ),
        )
        .expect("lib facts");

        let answer = incoming_references(&connection, "sol-one", "node-lib", None).expect("query");
        let references = answer.references().expect("indexed project answers");
        assert_eq!(references.len(), 1);
        assert_eq!(references[0].source_project_id, "proj-app");
        assert_eq!(references[0].edge_id, "edge-cross");

        // A kind filter that does not match returns a complete, empty answer.
        let filtered = incoming_references(&connection, "sol-one", "node-lib", Some("imports"))
            .expect("query");
        assert_eq!(filtered.references().expect("indexed").len(), 0);
    }

    #[test]
    fn unindexed_scope_is_not_reported_as_no_callers() {
        let mut connection = memory_store();
        seed_solution(&connection, "sol-one", "inst-one");
        seed_project(&connection, "proj-lib", "sol-one");
        let lib = seed_file(&connection, "proj-lib", "src/Lib.cs");
        replace_file_facts(
            &mut connection,
            "proj-lib",
            lib,
            &GraphFactSet::new(
                vec![NodeFact::new("node-lib", "method", "Lib.Helper", "{}")],
                vec![],
            ),
        )
        .expect("lib facts");

        // A pending generation means the scope is not covered.
        apply_inventory(
            &mut connection,
            "proj-lib",
            2,
            &[ObservedFile::new("src/Lib.cs", "h1")],
        )
        .expect("inventory");
        match incoming_references(&connection, "sol-one", "node-lib", None).expect("query") {
            ReferenceAnswer::NotIndexed(coverage) => {
                assert_eq!(coverage.total_files, 1);
                assert_eq!(coverage.pending_files, 1);
                assert!(!coverage.is_complete());
            }
            ReferenceAnswer::Known(references) => {
                panic!("unindexed scope must not answer 'no callers': {references:?}")
            }
        }

        // A project with no files at all is an absence of evidence too.
        assert!(!IndexCoverage {
            total_files: 0,
            pending_files: 0,
        }
        .is_complete());

        assert_eq!(
            incoming_references(&connection, "sol-one", "node-missing", None)
                .expect_err("unknown node")
                .code(),
            ErrorCode::NotFound
        );
    }
}
