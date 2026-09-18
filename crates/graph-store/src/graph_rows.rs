//! Replacing one file's graph facts without collateral damage (task B-016).
//!
//! `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 7 scopes a body-only
//! change to "reparse the changed file and replace the edges of its owner". A
//! replace therefore deletes rows by `owner_file_id` and never by project, so
//! nodes and edges owned by other files survive untouched. A node that
//! disappears takes incoming references with it: instead of leaving a dangling
//! `target_id` or silently dropping the reference, those edges become explicitly
//! unresolved, which is what makes a stale answer impossible to mistake for a
//! correct one.

use std::collections::{BTreeMap, BTreeSet};

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::is_portable_id;
use rusqlite::{params, Connection};

use crate::storage_error;

/// Upper bound on nodes contributed by a single file.
pub const MAX_NODES_PER_FILE: usize = 20_000;
/// Upper bound on edges contributed by a single file.
pub const MAX_EDGES_PER_FILE: usize = 100_000;

/// How an edge target was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Exactly one static target was proven.
    ExactStatic,
    /// A static target was inferred from context.
    InferredStatic,
    /// The target came from an annotation.
    Annotated,
    /// The target is known to be missing or ambiguous.
    Unresolved,
}

impl Resolution {
    /// Frozen wire spelling used by the `edges.resolution` column.
    #[must_use]
    pub const fn as_sql(self) -> &'static str {
        match self {
            Self::ExactStatic => "exact_static",
            Self::InferredStatic => "inferred_static",
            Self::Annotated => "annotated",
            Self::Unresolved => "unresolved",
        }
    }

    /// Whether this resolution is the explicit unresolved state.
    #[must_use]
    pub const fn is_unresolved(self) -> bool {
        matches!(self, Self::Unresolved)
    }
}

/// The target of an edge: a resolved node id or an explicitly unresolved name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeTarget {
    /// Node id proven by the analyzer.
    Resolved(String),
    /// Symbol name the analyzer could not resolve.
    Unresolved(String),
}

impl EdgeTarget {
    /// Resolved node id, when the target resolved.
    #[must_use]
    pub fn resolved_id(&self) -> Option<&str> {
        match self {
            Self::Resolved(id) => Some(id),
            Self::Unresolved(_) => None,
        }
    }

    /// Unresolved symbol name, when the target did not resolve.
    #[must_use]
    pub fn unresolved_name(&self) -> Option<&str> {
        match self {
            Self::Resolved(_) => None,
            Self::Unresolved(name) => Some(name),
        }
    }
}

/// One node owned by the file being replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeFact {
    id: String,
    kind: String,
    qualified_name: String,
    record_json: String,
}

impl NodeFact {
    /// Describe node `id`.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        kind: impl Into<String>,
        qualified_name: impl Into<String>,
        record_json: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            kind: kind.into(),
            qualified_name: qualified_name.into(),
            record_json: record_json.into(),
        }
    }

    /// Node id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Node kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Fully qualified name.
    #[must_use]
    pub fn qualified_name(&self) -> &str {
        &self.qualified_name
    }

    /// Serialized record payload.
    #[must_use]
    pub fn record_json(&self) -> &str {
        &self.record_json
    }
}

/// One edge owned by the file being replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeFact {
    id: String,
    source_id: String,
    target: EdgeTarget,
    target_project_id: String,
    kind: String,
    resolution: Resolution,
    record_json: String,
}

impl EdgeFact {
    /// Describe edge `id`; the resolution follows the target shape.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        source_id: impl Into<String>,
        target: EdgeTarget,
        target_project_id: impl Into<String>,
        kind: impl Into<String>,
        record_json: impl Into<String>,
    ) -> Self {
        let resolution = if target.resolved_id().is_some() {
            Resolution::ExactStatic
        } else {
            Resolution::Unresolved
        };
        Self {
            id: id.into(),
            source_id: source_id.into(),
            target,
            target_project_id: target_project_id.into(),
            kind: kind.into(),
            resolution,
            record_json: record_json.into(),
        }
    }

    /// Override the resolution for inferred or annotated edges.
    #[must_use]
    pub fn with_resolution(mut self, resolution: Resolution) -> Self {
        self.resolution = resolution;
        self
    }

    /// Edge id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Owning source node id.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Edge target.
    #[must_use]
    pub fn target(&self) -> &EdgeTarget {
        &self.target
    }

    /// Project the target belongs to.
    #[must_use]
    pub fn target_project_id(&self) -> &str {
        &self.target_project_id
    }

    /// Edge kind.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Declared resolution.
    #[must_use]
    pub const fn resolution(&self) -> Resolution {
        self.resolution
    }

    /// Serialized record payload.
    #[must_use]
    pub fn record_json(&self) -> &str {
        &self.record_json
    }
}

/// The complete fact set one file now owns.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GraphFactSet {
    /// Nodes owned by the file.
    pub nodes: Vec<NodeFact>,
    /// Edges owned by the file.
    pub edges: Vec<EdgeFact>,
}

impl GraphFactSet {
    /// Build a fact set.
    #[must_use]
    pub fn new(nodes: Vec<NodeFact>, edges: Vec<EdgeFact>) -> Self {
        Self { nodes, edges }
    }
}

/// What one file-fact replacement changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReplaceReport {
    /// Nodes the file used to own.
    pub nodes_removed: usize,
    /// Nodes the file now owns.
    pub nodes_inserted: usize,
    /// Edges the file used to own.
    pub edges_removed: usize,
    /// Edges the file now owns.
    pub edges_inserted: usize,
    /// Incoming edges from other owners rewritten to unresolved.
    pub edges_invalidated: usize,
}

/// Replace every fact owned by `file_id` with `facts`.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] for a non-portable id, a batch over the
///   per-file bounds, a duplicated node or edge id, an edge whose source is not
///   in the batch, or a resolution that contradicts its target shape.
/// - [`ErrorCode::NotFound`] when `file_id` is not a file of `project_id`.
/// - [`ErrorCode::Internal`] for a storage failure.
pub fn replace_file_facts(
    connection: &mut Connection,
    project_id: &str,
    file_id: i64,
    facts: &GraphFactSet,
) -> Result<ReplaceReport, AxiomError> {
    if !is_portable_id(project_id) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "project id must be a portable Axiom identifier",
        )
        .with_detail("project_id", project_id));
    }
    validate_facts(facts)?;

    let transaction = connection
        .transaction()
        .map_err(|error| storage_error("graph replace transaction", &error))?;

    let owner: Option<String> = transaction
        .query_row(
            "SELECT project_id FROM files WHERE id = ?1",
            [file_id],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .map_err(|error| storage_error("graph replace file lookup", &error))?;
    match owner.as_deref() {
        Some(owner) if owner == project_id => {}
        Some(_) => {
            return Err(AxiomError::new(
                ErrorCode::NotFound,
                "file does not belong to the given project",
            )
            .with_detail("project_id", project_id));
        }
        None => {
            return Err(AxiomError::new(
                ErrorCode::NotFound,
                "file is not registered in this project",
            )
            .with_detail("project_id", project_id));
        }
    }

    let mut removed_nodes: BTreeMap<String, String> = BTreeMap::new();
    {
        let mut statement = transaction
            .prepare("SELECT id, qualified_name FROM nodes WHERE owner_file_id = ?1")
            .map_err(|error| storage_error("graph node query", &error))?;
        let mut cursor = statement
            .query_map([file_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| storage_error("graph node query", &error))?;
        for row in cursor.by_ref() {
            let (id, name) = row.map_err(|error| storage_error("graph node row", &error))?;
            removed_nodes.insert(id, name);
        }
    }
    let edges_removed: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM edges WHERE owner_file_id = ?1",
            [file_id],
            |row| row.get(0),
        )
        .map_err(|error| storage_error("graph edge count", &error))?;

    let mut invalidated = 0usize;
    for (node_id, qualified_name) in &removed_nodes {
        let changed = transaction
            .execute(
                "UPDATE edges SET target_id = NULL, unresolved_target = ?1, \
                 resolution = 'unresolved' \
                 WHERE target_id = ?2 AND owner_file_id IS NOT ?3",
                params![qualified_name, node_id, file_id],
            )
            .map_err(|error| storage_error("graph edge invalidation", &error))?;
        invalidated += changed;
    }

    transaction
        .execute("DELETE FROM edges WHERE owner_file_id = ?1", [file_id])
        .map_err(|error| storage_error("graph edge delete", &error))?;
    transaction
        .execute("DELETE FROM nodes WHERE owner_file_id = ?1", [file_id])
        .map_err(|error| storage_error("graph node delete", &error))?;

    for node in &facts.nodes {
        transaction
            .execute(
                "INSERT INTO nodes(id, project_id, owner_file_id, kind, qualified_name, \
                 record_json) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    node.id(),
                    project_id,
                    file_id,
                    node.kind(),
                    node.qualified_name(),
                    node.record_json()
                ],
            )
            .map_err(|error| storage_error("graph node insert", &error))?;
    }
    for edge in &facts.edges {
        transaction
            .execute(
                "INSERT INTO edges(id, owner_file_id, source_id, target_id, unresolved_target, \
                 target_project_id, kind, resolution, record_json) \
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    edge.id(),
                    file_id,
                    edge.source_id(),
                    edge.target().resolved_id(),
                    edge.target().unresolved_name(),
                    edge.target_project_id(),
                    edge.kind(),
                    edge.resolution().as_sql(),
                    edge.record_json()
                ],
            )
            .map_err(|error| storage_error("graph edge insert", &error))?;
    }

    transaction
        .commit()
        .map_err(|error| storage_error("graph replace commit", &error))?;
    Ok(ReplaceReport {
        nodes_removed: removed_nodes.len(),
        nodes_inserted: facts.nodes.len(),
        edges_removed: usize::try_from(edges_removed).unwrap_or(usize::MAX),
        edges_inserted: facts.edges.len(),
        edges_invalidated: invalidated,
    })
}

fn validate_facts(facts: &GraphFactSet) -> Result<(), AxiomError> {
    if facts.nodes.len() > MAX_NODES_PER_FILE {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "file contributes more nodes than the bounded maximum",
        )
        .with_detail("limit", MAX_NODES_PER_FILE.to_string())
        .with_detail("observed", facts.nodes.len().to_string()));
    }
    if facts.edges.len() > MAX_EDGES_PER_FILE {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "file contributes more edges than the bounded maximum",
        )
        .with_detail("limit", MAX_EDGES_PER_FILE.to_string())
        .with_detail("observed", facts.edges.len().to_string()));
    }

    let mut node_ids: BTreeSet<&str> = BTreeSet::new();
    for node in &facts.nodes {
        if node.id().is_empty() || node.kind().is_empty() || node.qualified_name().is_empty() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "node facts require an id, kind and qualified name",
            )
            .with_detail("rule", "incomplete-node"));
        }
        if !node_ids.insert(node.id()) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "node id is duplicated in this file's fact set",
            )
            .with_detail("rule", "duplicate-node"));
        }
    }

    let mut edge_ids: BTreeSet<&str> = BTreeSet::new();
    for edge in &facts.edges {
        if edge.id().is_empty() || edge.kind().is_empty() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "edge facts require an id and kind",
            )
            .with_detail("rule", "incomplete-edge"));
        }
        if !edge_ids.insert(edge.id()) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "edge id is duplicated in this file's fact set",
            )
            .with_detail("rule", "duplicate-edge"));
        }
        if !node_ids.contains(edge.source_id()) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "edge source is not owned by this file",
            )
            .with_detail("rule", "orphan-edge-source"));
        }
        let unresolved_shape = edge.target().unresolved_name().is_some();
        if unresolved_shape != edge.resolution().is_unresolved() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "edge resolution contradicts its target shape",
            )
            .with_detail("rule", "resolution-target-mismatch"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{memory_store, seed_file, seed_project, seed_solution};

    #[test]
    fn replacing_one_file_preserves_other_owners_and_invalidates_removed_targets() {
        let mut connection = memory_store();
        seed_solution(&connection, "sol-one", "inst-one");
        seed_project(&connection, "proj-app", "sol-one");
        let app = seed_file(&connection, "proj-app", "src/App.cs");
        let other = seed_file(&connection, "proj-app", "src/Other.cs");

        replace_file_facts(
            &mut connection,
            "proj-app",
            other,
            &GraphFactSet::new(
                vec![NodeFact::new("node-other", "method", "Other.Run", "{}")],
                vec![EdgeFact::new(
                    "edge-other",
                    "node-other",
                    EdgeTarget::Resolved("node-app".to_string()),
                    "proj-app",
                    "calls",
                    "{}",
                )],
            ),
        )
        .expect("seed other file");
        replace_file_facts(
            &mut connection,
            "proj-app",
            app,
            &GraphFactSet::new(
                vec![NodeFact::new("node-app", "method", "App.Run", "{}")],
                vec![],
            ),
        )
        .expect("seed app file");

        let report = replace_file_facts(
            &mut connection,
            "proj-app",
            app,
            &GraphFactSet::new(
                vec![NodeFact::new("node-app-2", "method", "App.RunAgain", "{}")],
                vec![],
            ),
        )
        .expect("replace app file");
        assert_eq!(report.nodes_removed, 1);
        assert_eq!(report.nodes_inserted, 1);
        assert_eq!(report.edges_invalidated, 1);

        let (target, unresolved, resolution, owner): (Option<String>, Option<String>, String, i64) =
            connection
                .query_row(
                    "SELECT target_id, unresolved_target, resolution, owner_file_id FROM edges \
                 WHERE id = 'edge-other'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .expect("preserved edge");
        assert_eq!(target, None);
        assert_eq!(unresolved.as_deref(), Some("App.Run"));
        assert_eq!(resolution, "unresolved");
        assert_eq!(owner, other);

        let other_nodes: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM nodes WHERE owner_file_id = ?1",
                [other],
                |row| row.get(0),
            )
            .expect("other nodes");
        assert_eq!(other_nodes, 1);
    }

    #[test]
    fn edges_that_leave_the_file_fact_set_are_refused() {
        let mut connection = memory_store();
        seed_solution(&connection, "sol-one", "inst-one");
        seed_project(&connection, "proj-app", "sol-one");
        let app = seed_file(&connection, "proj-app", "src/App.cs");

        let orphan = GraphFactSet::new(
            vec![NodeFact::new("node-app", "method", "App.Run", "{}")],
            vec![EdgeFact::new(
                "edge-orphan",
                "node-elsewhere",
                EdgeTarget::Resolved("node-app".to_string()),
                "proj-app",
                "calls",
                "{}",
            )],
        );
        assert_eq!(
            replace_file_facts(&mut connection, "proj-app", app, &orphan)
                .expect_err("orphan edge source")
                .code(),
            ErrorCode::ValidationError
        );

        let contradictory = GraphFactSet::new(
            vec![NodeFact::new("node-app", "method", "App.Run", "{}")],
            vec![EdgeFact::new(
                "edge-mismatch",
                "node-app",
                EdgeTarget::Unresolved("Missing.Target".to_string()),
                "proj-app",
                "calls",
                "{}",
            )
            .with_resolution(Resolution::ExactStatic)],
        );
        assert_eq!(
            replace_file_facts(&mut connection, "proj-app", app, &contradictory)
                .expect_err("resolution contradicts target")
                .code(),
            ErrorCode::ValidationError
        );

        // A file from another project is never replaced under the wrong owner.
        seed_project(&connection, "proj-other", "sol-one");
        let foreign = seed_file(&connection, "proj-other", "src/Foreign.cs");
        assert_eq!(
            replace_file_facts(
                &mut connection,
                "proj-app",
                foreign,
                &GraphFactSet::default()
            )
            .expect_err("foreign file")
            .code(),
            ErrorCode::NotFound
        );
        let nodes: i64 = connection
            .query_row("SELECT COUNT(*) FROM nodes", [], |row| row.get(0))
            .expect("nodes");
        assert_eq!(nodes, 0);
    }
}
