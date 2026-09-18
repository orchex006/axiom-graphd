//! Shard locators for edges (task B-069).
//!
//! An edge is only useful if a reader can find it, so the index stores the shard
//! locator that [`crate::shard`] planned for it. The index is built from the
//! plan, never from a second guess at the bucket function, so a locator can
//! never point at a shard the bytes were not written to.
//!
//! The second rule is about honesty of coverage. This build reads some
//! projects, not all of them. An incoming edge to a symbol therefore may exist
//! in a project that was not analysed, so [`EdgeIndex::incoming`] returns
//! [`IncomingLookup::complete`] `false` unless the index was told that every
//! project which could reference the symbol was indexed. A local index is never
//! presented as complete external knowledge.

use std::collections::BTreeMap;

use crate::shard::ShardPlan;
use crate::{ExportError, Result, ERR_MISSING};

/// Reason recorded when a symbol may also be referenced by an unindexed project.
pub const REASON_CROSS_PROJECT_UNKNOWN: &str = "unresolved-cross-project-unknown";

/// One edge fact, before indexing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeFact {
    /// Stable record key of the edge.
    pub key: String,
    /// Source end.
    pub from: String,
    /// Target end.
    pub to: String,
    /// Relation kind.
    pub relation: String,
}

impl EdgeFact {
    /// Build an edge fact.
    #[must_use]
    pub fn new(
        key: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
        relation: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            from: from.into(),
            to: to.into(),
            relation: relation.into(),
        }
    }
}

/// Where one edge lives in the published generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeLocator {
    /// The edge's stable record key.
    pub key: String,
    /// Source end.
    pub from: String,
    /// Target end.
    pub to: String,
    /// Relation kind.
    pub relation: String,
    /// The bucket the edge was sharded into.
    pub bucket: usize,
    /// The stable shard name, for example `bucket-005/part-000`.
    pub shard: String,
}

/// The answer to an incoming-edge question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingLookup {
    /// Locators found inside the indexed projects, in key order.
    pub locators: Vec<EdgeLocator>,
    /// Whether the index covers every project that could reference the symbol.
    pub complete: bool,
    /// The reason the answer may be incomplete.
    pub reason: Option<&'static str>,
}

impl IncomingLookup {
    /// Whether the answer covers every project that could reference the symbol.
    #[must_use]
    pub const fn is_complete_local_knowledge(&self) -> bool {
        self.complete
    }
}

/// Index of one project's edges by symbol.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EdgeIndex {
    /// The project these edges belong to.
    pub project: String,
    /// Every locator, in plan order.
    pub locators: Vec<EdgeLocator>,
    /// Locator indices by source symbol.
    pub outgoing: BTreeMap<String, Vec<usize>>,
    /// Locator indices by target symbol.
    pub incoming: BTreeMap<String, Vec<usize>>,
    /// Whether every project that could reference these symbols was indexed.
    pub all_projects_indexed: bool,
}

impl EdgeIndex {
    /// Locators leaving `symbol`, in key order.
    #[must_use]
    pub fn outgoing(&self, symbol: &str) -> Vec<EdgeLocator> {
        let mut out: Vec<EdgeLocator> = self
            .outgoing
            .get(symbol)
            .map(|indices| {
                indices
                    .iter()
                    .filter_map(|index| self.locators.get(*index).cloned())
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by(|left, right| left.key.cmp(&right.key));
        out
    }

    /// Locators entering `symbol`, with an explicit completeness answer.
    #[must_use]
    pub fn incoming(&self, symbol: &str) -> IncomingLookup {
        let mut locators: Vec<EdgeLocator> = self
            .incoming
            .get(symbol)
            .map(|indices| {
                indices
                    .iter()
                    .filter_map(|index| self.locators.get(*index).cloned())
                    .collect()
            })
            .unwrap_or_default();
        locators.sort_by(|left, right| left.key.cmp(&right.key));
        IncomingLookup {
            locators,
            complete: self.all_projects_indexed,
            reason: if self.all_projects_indexed {
                None
            } else {
                Some(REASON_CROSS_PROJECT_UNKNOWN)
            },
        }
    }

    /// The locator for an edge key.
    #[must_use]
    pub fn resolve(&self, key: &str) -> Option<&EdgeLocator> {
        self.locators.iter().find(|locator| locator.key == key)
    }
}

/// Build an edge index from the edges and the shard plan that published them.
///
/// # Errors
///
/// Returns [`ERR_MISSING`] when an edge key has no shard in the plan, because a
/// locator without a shard would be a dead pointer.
pub fn build(
    project: &str,
    edges: &[EdgeFact],
    plan: &ShardPlan,
    all_projects_indexed: bool,
) -> Result<EdgeIndex> {
    let mut shard_of: BTreeMap<&str, (usize, &str)> = BTreeMap::new();
    for shard in &plan.shards {
        for key in &shard.record_keys {
            shard_of.insert(key.as_str(), (shard.bucket, shard.name.as_str()));
        }
    }
    let mut index = EdgeIndex {
        project: project.to_string(),
        all_projects_indexed,
        ..EdgeIndex::default()
    };
    for edge in edges {
        let Some((bucket, shard)) = shard_of.get(edge.key.as_str()) else {
            return Err(ExportError::new(
                ERR_MISSING,
                format!("edge {} has no shard in the plan", edge.key),
            ));
        };
        let position = index.locators.len();
        index.locators.push(EdgeLocator {
            key: edge.key.clone(),
            from: edge.from.clone(),
            to: edge.to.clone(),
            relation: edge.relation.clone(),
            bucket: *bucket,
            shard: (*shard).to_string(),
        });
        index
            .outgoing
            .entry(edge.from.clone())
            .or_default()
            .push(position);
        index
            .incoming
            .entry(edge.to.clone())
            .or_default()
            .push(position);
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{build, EdgeFact, REASON_CROSS_PROJECT_UNKNOWN};
    use crate::shard::{plan, ShardPolicy};
    use crate::GraphRecord;

    fn plan_for(edges: &[EdgeFact]) -> crate::shard::ShardPlan {
        let records: Vec<GraphRecord> = edges
            .iter()
            .map(|edge| {
                GraphRecord::new(
                    edge.key.clone(),
                    "edge",
                    json!({"from": edge.from, "to": edge.to, "relation": edge.relation}),
                )
            })
            .collect();
        plan(
            &records,
            &ShardPolicy {
                bucket_count: 8,
                max_bytes: 4096,
            },
        )
        .expect("plan")
    }

    #[test]
    fn an_edge_resolves_through_its_shard_locator() {
        let edges = vec![
            EdgeFact::new("e1", "Orders.Api", "Orders.Repo", "calls"),
            EdgeFact::new("e2", "Orders.Repo", "Orders.Db", "reads"),
        ];
        let shard_plan = plan_for(&edges);
        let index = build("Orders", &edges, &shard_plan, true).expect("index");
        let locator = index.resolve("e1").expect("locator");
        let owner = shard_plan
            .shards
            .iter()
            .find(|shard| shard.record_keys.contains(&"e1".to_string()))
            .expect("shard");
        assert_eq!(locator.shard, owner.name);
        assert_eq!(locator.bucket, owner.bucket);
        assert_eq!(index.outgoing("Orders.Api").len(), 1);
        assert_eq!(index.outgoing("Orders.Api")[0].relation, "calls");
    }

    #[test]
    fn a_local_index_never_claims_complete_cross_project_knowledge() {
        let edges = vec![EdgeFact::new("e1", "Web.Api", "Orders.Repo", "calls")];
        let shard_plan = plan_for(&edges);
        let partial = build("Web", &edges, &shard_plan, false).expect("index");
        let lookup = partial.incoming("Orders.Repo");
        assert_eq!(lookup.locators.len(), 1);
        assert!(!lookup.is_complete_local_knowledge());
        assert_eq!(lookup.reason, Some(REASON_CROSS_PROJECT_UNKNOWN));

        let complete = build("Web", &edges, &shard_plan, true).expect("index");
        assert!(complete
            .incoming("Orders.Repo")
            .is_complete_local_knowledge());
        assert!(complete.incoming("Orders.Repo").reason.is_none());
    }

    #[test]
    fn an_edge_without_a_shard_is_a_missing_locator_error() {
        let edges = vec![EdgeFact::new("e1", "a", "b", "calls")];
        let shard_plan = plan_for(&edges);
        let stray = vec![EdgeFact::new("e2", "a", "b", "calls")];
        let error = build("P", &stray, &shard_plan, true).expect_err("must refuse");
        assert_eq!(error.code, crate::ERR_MISSING);
    }

    #[test]
    fn a_symbol_with_no_incoming_edges_still_reports_completeness() {
        let edges = vec![EdgeFact::new("e1", "a", "b", "calls")];
        let shard_plan = plan_for(&edges);
        let index = build("P", &edges, &shard_plan, false).expect("index");
        let lookup = index.incoming("never-referenced");
        assert!(lookup.locators.is_empty());
        assert!(!lookup.is_complete_local_knowledge());
    }
}
