//! Bounded `query context` and `query impact` (task B-087).
//!
//! `docs/16-CLI-AND-CONTROL-API.md` section 2 requires `query context` to return
//! the same projection and result contract the MCP surface returns, reading the
//! pinned JSON snapshot, and requires `query impact` to be a bounded reverse
//! projection that is explicitly **not** a guarantee of runtime impact.
//!
//! Two properties keep the answer bounded and honest:
//!
//! * **A limit always applies.** [`QueryLimits::default`] is bounded, and a
//!   request outside the accepted range is refused with
//!   [`REASON_LIMIT_UNBOUNDED`] instead of being clamped upward. There is
//!   therefore no invocation that returns the whole solution by default.
//! * **Truncation is reported, never silent.** When a byte, node or depth limit
//!   stops the walk, the projection carries the reason so a caller can narrow
//!   the query rather than assume it saw everything.

use std::collections::{BTreeSet, VecDeque};

use graph_core::error::{AxiomError, ErrorCode};
use graph_export::reader::Snapshot;
use serde::Serialize;

/// Default byte budget of one projection.
pub const DEFAULT_MAX_BYTES: usize = 8192;
/// Largest accepted byte budget.
pub const MAX_MAX_BYTES: usize = 1_048_576;
/// Smallest accepted byte budget, so the answer envelope always fits.
pub const MIN_MAX_BYTES: usize = 2048;
/// Bytes reserved for the projection envelope, so max_bytes bounds the
/// serialized answer and not only the record payload.
pub const ENVELOPE_RESERVE_BYTES: usize = 1024;
/// Default record budget of one projection.
pub const DEFAULT_MAX_NODES: usize = 64;
/// Largest accepted record budget.
pub const MAX_MAX_NODES: usize = 4096;
/// Default traversal depth.
pub const DEFAULT_DEPTH: u32 = 1;
/// Largest accepted traversal depth.
pub const MAX_DEPTH: u32 = 6;
/// Reason recorded when the byte budget stopped the walk.
pub const REASON_BYTE_LIMIT: &str = "byte-limit";
/// Reason recorded when the record budget stopped the walk.
pub const REASON_NODE_LIMIT: &str = "node-limit";
/// Reason recorded when the depth budget stopped the walk.
pub const REASON_DEPTH_LIMIT: &str = "depth-limit";
/// Reason recorded when a limit is outside the accepted range.
pub const REASON_LIMIT_UNBOUNDED: &str = "limit-unbounded";
/// Reason recorded when the requested symbol is not in the snapshot.
pub const REASON_SYMBOL_NOT_FOUND: &str = "symbol-not-found";
/// Reason recorded when the snapshot cannot be read.
pub const REASON_SNAPSHOT_UNREADABLE: &str = "snapshot-unreadable";

/// The bounded projection budget of one query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct QueryLimits {
    /// Byte budget for the returned records.
    pub max_bytes: usize,
    /// Record budget for the returned records.
    pub max_nodes: usize,
    /// Traversal depth budget.
    pub depth: u32,
}

impl Default for QueryLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_nodes: DEFAULT_MAX_NODES,
            depth: DEFAULT_DEPTH,
        }
    }
}

impl QueryLimits {
    /// Build explicit limits.
    #[must_use]
    pub fn new(max_bytes: usize, max_nodes: usize, depth: u32) -> Self {
        Self {
            max_bytes,
            max_nodes,
            depth,
        }
    }

    /// Refuse an unbounded or nonsensical limit rather than clamping it.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with [`REASON_LIMIT_UNBOUNDED`].
    pub fn validate(&self) -> Result<(), AxiomError> {
        if self.max_bytes < MIN_MAX_BYTES || self.max_bytes > MAX_MAX_BYTES {
            return Err(unbounded("max_bytes", self.max_bytes.to_string()));
        }
        if self.max_nodes == 0 || self.max_nodes > MAX_MAX_NODES {
            return Err(unbounded("max_nodes", self.max_nodes.to_string()));
        }
        if self.depth == 0 || self.depth > MAX_DEPTH {
            return Err(unbounded("depth", self.depth.to_string()));
        }
        Ok(())
    }
}

fn unbounded(limit: &str, observed: String) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "a query limit is outside the accepted bounded range",
    )
    .with_detail("rule", REASON_LIMIT_UNBOUNDED)
    .with_detail("limit", limit)
    .with_detail("observed", observed)
}

/// Which bounded projection was requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QueryKind {
    /// Forward context for a symbol.
    Context,
    /// Bounded reverse impact for a node id.
    Impact,
}

/// The pinned snapshot a query reads.
///
/// The production implementation reads a loaded [`Snapshot`]; tests use an
/// in-memory provider, so the projection rules stay testable without a
/// filesystem layout.
pub trait PinnedSnapshot {
    /// Generation id the answer is pinned to.
    fn generation_id(&self) -> &str;
    /// Shard names, in deterministic order.
    fn shard_names(&self) -> Vec<String>;
    /// The records of one shard.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`] with [`REASON_SNAPSHOT_UNREADABLE`].
    fn shard_records(&self, shard: &str) -> Result<Vec<serde_json::Value>, AxiomError>;
}

impl PinnedSnapshot for Snapshot {
    fn generation_id(&self) -> &str {
        Snapshot::generation_id(self)
    }

    fn shard_names(&self) -> Vec<String> {
        self.shards()
            .iter()
            .map(|shard| shard.relative_path.clone())
            .collect()
    }

    fn shard_records(&self, shard: &str) -> Result<Vec<serde_json::Value>, AxiomError> {
        self.parse_shard(shard).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                format!("the pinned snapshot shard could not be read: {error}"),
            )
            .with_detail("rule", REASON_SNAPSHOT_UNREADABLE)
            .with_detail("shard", shard)
        })
    }
}
/// One record in a bounded projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SelectedRecord {
    /// Stable record key.
    pub key: String,
    /// Record kind.
    pub kind: String,
    /// Record body.
    pub body: serde_json::Value,
}

impl SelectedRecord {
    fn from_value(value: &serde_json::Value) -> Option<Self> {
        let key = value.get("key")?.as_str()?.to_owned();
        let kind = value
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let body = value
            .get("body")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        Some(Self { key, kind, body })
    }
}

/// The bounded answer to one query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Projection {
    /// Solution the projection is scoped to.
    pub solution_id: String,
    /// Generation the answer is pinned to.
    pub generation_id: String,
    /// Which query produced it.
    pub kind: QueryKind,
    /// The requested symbol or node id.
    pub target: String,
    /// The limits that were applied.
    pub limits: QueryLimits,
    /// Selected records, in deterministic source order.
    pub records: Vec<SelectedRecord>,
    /// Records that matched but were left out by a limit.
    pub omitted: usize,
    /// Whether a limit stopped the walk.
    pub truncated: bool,
    /// Stable reasons for a truncated answer.
    pub reasons: Vec<&'static str>,
    /// Canonical size of the returned records.
    pub bytes: usize,
}

impl Projection {
    /// Whether the projection returned everything that matched.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.truncated
    }

    /// Whether the answer is within the limits it declares.
    #[must_use]
    pub fn fits_budget(&self) -> bool {
        self.bytes <= self.limits.max_bytes && self.records.len() <= self.limits.max_nodes
    }

    /// Serialize the projection, refusing to emit a body over its own budget.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`] when the serialized body exceeds `max_bytes`,
    /// which would mean the accounting above was wrong.
    pub fn render_json(&self) -> Result<String, AxiomError> {
        let text = serde_json::to_string(self)
            .map_err(|error| crate::commands::storage_error("projection serialization", &error))?;
        if text.len() > self.limits.max_bytes {
            return Err(AxiomError::new(
                ErrorCode::Internal,
                "the projection exceeded the byte budget it reported",
            )
            .with_detail("rule", REASON_BYTE_LIMIT)
            .with_detail("budget", self.limits.max_bytes.to_string())
            .with_detail("observed", text.len().to_string()));
        }
        Ok(text)
    }
}

fn load_all(snapshot: &dyn PinnedSnapshot) -> Result<Vec<serde_json::Value>, AxiomError> {
    let mut all = Vec::new();
    for shard in snapshot.shard_names() {
        all.extend(snapshot.shard_records(&shard)?);
    }
    Ok(all)
}

fn field<'a>(value: &'a serde_json::Value, names: &[&str]) -> Option<&'a str> {
    let body = value.get("body")?;
    for name in names {
        if let Some(text) = body.get(*name).and_then(serde_json::Value::as_str) {
            return Some(text);
        }
    }
    None
}

fn is_edge(value: &serde_json::Value) -> bool {
    value
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|kind| kind == "edge")
}

fn edge_from(value: &serde_json::Value) -> Option<&str> {
    field(value, &["source_id", "from", "source"])
}

fn edge_to(value: &serde_json::Value) -> Option<&str> {
    field(value, &["target_id", "to", "target"])
}
/// Assemble a bounded projection from an ordered candidate list.
fn assemble(
    solution_id: &str,
    snapshot: &dyn PinnedSnapshot,
    kind: QueryKind,
    target: &str,
    limits: QueryLimits,
    candidates: Vec<&serde_json::Value>,
    depth_truncated: bool,
) -> Result<Projection, AxiomError> {
    let mut records = Vec::new();
    let mut bytes = 0usize;
    let mut reasons: Vec<&'static str> = Vec::new();
    let mut omitted = 0usize;
    let mut byte_stopped = false;
    for candidate in &candidates {
        if records.len() >= limits.max_nodes {
            reasons.push(REASON_NODE_LIMIT);
            byte_stopped = true;
            break;
        }
        let Some(record) = SelectedRecord::from_value(candidate) else {
            continue;
        };
        let encoded = serde_json::to_string(&record)
            .map_err(|error| crate::commands::storage_error("record serialization", &error))?;
        if bytes + encoded.len() + ENVELOPE_RESERVE_BYTES > limits.max_bytes {
            reasons.push(REASON_BYTE_LIMIT);
            byte_stopped = true;
            break;
        }
        bytes += encoded.len();
        records.push(record);
    }
    if byte_stopped {
        omitted = candidates.len().saturating_sub(records.len());
    }
    if depth_truncated {
        reasons.push(REASON_DEPTH_LIMIT);
    }
    reasons.sort_unstable();
    reasons.dedup();
    let truncated = omitted > 0 || depth_truncated || byte_stopped;
    Ok(Projection {
        solution_id: solution_id.to_owned(),
        generation_id: snapshot.generation_id().to_owned(),
        kind,
        target: target.to_owned(),
        limits,
        records,
        omitted,
        truncated,
        reasons,
        bytes,
    })
}

/// Build a bounded forward-context projection for `symbol`.
///
/// # Errors
/// [`ErrorCode::ValidationError`] for an out-of-range limit, and
/// [`ErrorCode::NotFound`] with [`REASON_SYMBOL_NOT_FOUND`] when the symbol is
/// not present in the pinned snapshot.
pub fn context(
    solution_id: &str,
    snapshot: &dyn PinnedSnapshot,
    symbol: &str,
    limits: QueryLimits,
) -> Result<Projection, AxiomError> {
    limits.validate()?;
    let all = load_all(snapshot)?;
    let mut seeds: BTreeSet<String> = BTreeSet::new();
    let mut ordered: Vec<&serde_json::Value> = Vec::new();
    for value in &all {
        let key = value
            .get("key")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let named = field(value, &["qualified_name", "name", "id"]);
        let matches =
            key == symbol || named == Some(symbol) || key.split(':').any(|part| part == symbol);
        if matches {
            if let Some(identity) = named.or(Some(key)) {
                seeds.insert(identity.to_owned());
            }
            ordered.push(value);
        }
    }
    if ordered.is_empty() {
        return Err(AxiomError::new(
            ErrorCode::NotFound,
            "the requested symbol is not present in the pinned snapshot",
        )
        .with_detail("rule", REASON_SYMBOL_NOT_FOUND)
        .with_detail("symbol", symbol)
        .with_detail("generation", snapshot.generation_id()));
    }
    // One hop of directly incident edges, in source order.
    let depth_truncated = limits.depth < 1;
    if limits.depth >= 1 {
        for value in &all {
            if !is_edge(value) {
                continue;
            }
            let touches = edge_from(value).is_some_and(|from| seeds.contains(from))
                || edge_to(value).is_some_and(|to| seeds.contains(to));
            if touches && !ordered.iter().any(|seen| **seen == *value) {
                ordered.push(value);
            }
        }
    }
    assemble(
        solution_id,
        snapshot,
        QueryKind::Context,
        symbol,
        limits,
        ordered,
        depth_truncated,
    )
}

/// Build a bounded reverse-impact projection for `node_id`.
///
/// # Errors
/// [`ErrorCode::ValidationError`] for an out-of-range limit, and
/// [`ErrorCode::NotFound`] with [`REASON_SYMBOL_NOT_FOUND`] when the node is not
/// present in the pinned snapshot.
pub fn impact(
    solution_id: &str,
    snapshot: &dyn PinnedSnapshot,
    node_id: &str,
    limits: QueryLimits,
) -> Result<Projection, AxiomError> {
    limits.validate()?;
    let all = load_all(snapshot)?;
    let edges: Vec<&serde_json::Value> = all.iter().filter(|value| is_edge(value)).collect();
    let known = all.iter().any(|value| {
        value.get("key").and_then(serde_json::Value::as_str) == Some(node_id)
            || field(value, &["qualified_name", "name", "id"]) == Some(node_id)
    });
    if !known {
        return Err(AxiomError::new(
            ErrorCode::NotFound,
            "the requested node is not present in the pinned snapshot",
        )
        .with_detail("rule", REASON_SYMBOL_NOT_FOUND)
        .with_detail("symbol", node_id)
        .with_detail("generation", snapshot.generation_id()));
    }
    let mut frontier: VecDeque<(String, u32)> = VecDeque::new();
    frontier.push_back((node_id.to_owned(), 0));
    let mut seen: BTreeSet<String> = BTreeSet::new();
    seen.insert(node_id.to_owned());
    let mut depth_truncated = false;
    let mut reachable: Vec<String> = Vec::new();
    while let Some((current, depth)) = frontier.pop_front() {
        for edge in &edges {
            if edge_to(edge) != Some(current.as_str()) {
                continue;
            }
            let Some(source) = edge_from(edge) else {
                continue;
            };
            let source = source.to_owned();
            if !seen.insert(source.clone()) {
                continue;
            }
            reachable.push(source.clone());
            match (depth + 1).cmp(&limits.depth) {
                std::cmp::Ordering::Less => frontier.push_back((source, depth + 1)),
                std::cmp::Ordering::Equal => {
                    // A deeper level exists beyond the budget.
                    depth_truncated = edges
                        .iter()
                        .any(|candidate| edge_to(candidate) == Some(source.as_str()));
                }
                std::cmp::Ordering::Greater => {}
            }
        }
    }
    let mut ordered: Vec<&serde_json::Value> = Vec::new();
    for value in &all {
        if is_edge(value) {
            if let Some(source) = edge_from(value) {
                if reachable.iter().any(|id| id == source) {
                    ordered.push(value);
                }
            }
        }
    }
    for identity in &reachable {
        for value in &all {
            let matches = value.get("key").and_then(serde_json::Value::as_str)
                == Some(identity.as_str())
                || field(value, &["qualified_name", "name", "id"]) == Some(identity.as_str());
            if matches && !ordered.iter().any(|seen| **seen == *value) {
                ordered.push(value);
            }
        }
    }
    assemble(
        solution_id,
        snapshot,
        QueryKind::Impact,
        node_id,
        limits,
        ordered,
        depth_truncated,
    )
}
#[cfg(test)]
mod tests {
    use super::*;

    /// A pinned snapshot held in memory so the projection rules are testable
    /// without a filesystem generation.
    struct FakeSnapshot {
        generation_id: String,
        shards: Vec<(String, Vec<serde_json::Value>)>,
    }

    impl FakeSnapshot {
        fn new(records: Vec<serde_json::Value>) -> Self {
            Self {
                generation_id: "gen-0001".to_owned(),
                shards: vec![("bucket-000".to_owned(), records)],
            }
        }
    }

    impl PinnedSnapshot for FakeSnapshot {
        fn generation_id(&self) -> &str {
            &self.generation_id
        }
        fn shard_names(&self) -> Vec<String> {
            self.shards.iter().map(|(name, _)| name.clone()).collect()
        }
        fn shard_records(&self, shard: &str) -> Result<Vec<serde_json::Value>, AxiomError> {
            Ok(self
                .shards
                .iter()
                .find(|(name, _)| name == shard)
                .map(|(_, records)| records.clone())
                .unwrap_or_default())
        }
    }

    fn symbol(qualified_name: &str) -> serde_json::Value {
        serde_json::json!({
            "key": format!("sym:{qualified_name}"),
            "kind": "symbol",
            "body": {"qualified_name": qualified_name, "name": qualified_name},
        })
    }

    fn edge(key: &str, from: &str, to: &str) -> serde_json::Value {
        serde_json::json!({
            "key": key,
            "kind": "edge",
            "body": {"source_id": from, "target_id": to, "kind": "calls"},
        })
    }

    fn graph() -> FakeSnapshot {
        FakeSnapshot::new(vec![
            symbol("Billing"),
            symbol("AuthService"),
            symbol("AuthController"),
            edge("edge:controller->auth", "AuthController", "AuthService"),
        ])
    }

    #[test]
    fn context_returns_the_symbol_and_its_incident_edges_within_budget() {
        let snapshot = graph();
        let projection = context(
            "demo-solution",
            &snapshot,
            "AuthService",
            QueryLimits::default(),
        )
        .expect("context");
        assert_eq!(projection.generation_id, "gen-0001");
        assert_eq!(projection.kind, QueryKind::Context);
        assert!(!projection.truncated);
        assert!(projection.is_complete());
        assert!(projection.fits_budget());
        assert!(projection
            .records
            .iter()
            .any(|record| record.kind == "edge" && record.key == "edge:controller->auth"));
        let text = projection.render_json().expect("render");
        assert!(
            text.len() <= QueryLimits::default().max_bytes,
            "{}",
            text.len()
        );
    }

    #[test]
    fn a_default_query_never_returns_the_whole_solution() {
        let mut records = Vec::new();
        for index in 0..400 {
            records.push(symbol(&format!("Symbol{index:03}")));
            records.push(edge(
                &format!("edge:{index:03}"),
                &format!("Symbol{index:03}"),
                "Symbol000",
            ));
        }
        records.push(symbol("Target"));
        records.push(edge("edge:target", "Target", "Symbol000"));
        let snapshot = FakeSnapshot::new(records);
        let limits = QueryLimits::default();
        // The most connected symbol in the fixture; a symbol-focused query on
        // it still exceeds the default node budget of the whole answer.
        let projection = context("demo-solution", &snapshot, "Symbol000", limits).expect("context");
        assert!(projection.truncated);
        assert!(!projection.is_complete());
        assert!(projection.records.len() < 802);
        assert!(projection.omitted > 0);
        assert!(projection.fits_budget());
        assert!(
            projection.reasons.contains(&REASON_NODE_LIMIT)
                || projection.reasons.contains(&REASON_BYTE_LIMIT),
            "{:?}",
            projection.reasons
        );
        // Both the payload and the serialized answer stay inside the budget.
        assert!(projection.bytes <= limits.max_bytes);
        let text = projection.render_json().expect("render");
        assert!(text.len() <= limits.max_bytes, "{}", text.len());
        // Raising the record budget above the accepted cap is refused.
        let unbounded = QueryLimits::new(MAX_MAX_BYTES + 1, MAX_MAX_NODES, DEFAULT_DEPTH);
        let error =
            context("demo-solution", &snapshot, "Target", unbounded).expect_err("unbounded");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_LIMIT_UNBOUNDED)
        );
    }

    #[test]
    fn impact_is_a_bounded_reverse_walk_that_reports_a_depth_cut() {
        let snapshot = FakeSnapshot::new(vec![
            symbol("Leaf"),
            symbol("Middle"),
            symbol("Root"),
            symbol("Caller"),
            edge("edge:middle->leaf", "Middle", "Leaf"),
            edge("edge:root->middle", "Root", "Middle"),
            edge("edge:caller->root", "Caller", "Root"),
        ]);
        // Depth 1 sees only the direct caller.
        let shallow = impact(
            "demo-solution",
            &snapshot,
            "Leaf",
            QueryLimits::new(DEFAULT_MAX_BYTES, DEFAULT_MAX_NODES, 1),
        )
        .expect("shallow impact");
        assert!(shallow
            .records
            .iter()
            .any(|record| record.key == "edge:middle->leaf"));
        assert!(!shallow
            .records
            .iter()
            .any(|record| record.key == "edge:root->middle"));
        assert!(shallow.truncated);
        assert!(shallow.reasons.contains(&REASON_DEPTH_LIMIT));
        // Depth 3 walks the whole chain and is complete.
        let deep = impact(
            "demo-solution",
            &snapshot,
            "Leaf",
            QueryLimits::new(DEFAULT_MAX_BYTES, DEFAULT_MAX_NODES, 3),
        )
        .expect("deep impact");
        assert!(deep
            .records
            .iter()
            .any(|record| record.key == "edge:caller->root"));
        assert!(!deep.truncated);
        assert!(deep.is_complete());
        assert_eq!(deep.kind, QueryKind::Impact);
    }

    #[test]
    fn an_out_of_range_limit_is_refused_rather_than_clamped() {
        let snapshot = graph();
        for limits in [
            QueryLimits::new(MIN_MAX_BYTES - 1, DEFAULT_MAX_NODES, DEFAULT_DEPTH),
            QueryLimits::new(DEFAULT_MAX_BYTES, 0, DEFAULT_DEPTH),
            QueryLimits::new(DEFAULT_MAX_BYTES, MAX_MAX_NODES + 1, DEFAULT_DEPTH),
            QueryLimits::new(DEFAULT_MAX_BYTES, DEFAULT_MAX_NODES, 0),
            QueryLimits::new(DEFAULT_MAX_BYTES, DEFAULT_MAX_NODES, MAX_DEPTH + 1),
        ] {
            assert_eq!(
                limits.validate().expect_err("unbounded").code(),
                ErrorCode::ValidationError
            );
        }
        let error = context(
            "demo-solution",
            &snapshot,
            "AuthService",
            QueryLimits::new(MIN_MAX_BYTES - 1, DEFAULT_MAX_NODES, DEFAULT_DEPTH),
        )
        .expect_err("unbounded");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_LIMIT_UNBOUNDED)
        );
    }

    #[test]
    fn an_unknown_symbol_is_not_found_in_the_pinned_snapshot() {
        let snapshot = graph();
        for error in [
            context(
                "demo-solution",
                &snapshot,
                "NoSuchSymbol",
                QueryLimits::default(),
            )
            .expect_err("context"),
            impact(
                "demo-solution",
                &snapshot,
                "sym:Missing",
                QueryLimits::default(),
            )
            .expect_err("impact"),
        ] {
            assert_eq!(error.code(), ErrorCode::NotFound);
            assert_eq!(
                error.details().get("rule").map(String::as_str),
                Some(REASON_SYMBOL_NOT_FOUND)
            );
            assert_eq!(
                error.details().get("generation").map(String::as_str),
                Some("gen-0001")
            );
        }
    }
}
