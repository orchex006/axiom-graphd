//! Deterministic diagram projection of one published generation (task H-005).
//!
//! `query` answers a bounded question about a pinned generation; nothing in this
//! workspace draws one. This module adds exactly one projection: read a
//! published generation through the frozen reader ([`graph_export::reader`]) and
//! emit a self-contained diagram document ([`RESULT_HTML`]) plus a
//! machine-readable summary ([`SUMMARY_JSON`]) so a reviewer can see the shape of
//! a solution and tell a resolved cross-service edge from an unresolved
//! placeholder.
//!
//! Four properties are deliberate and unit tested:
//!
//! * **Every shard is concatenated, never only the first.** [`build_diagram`]
//!   walks `Snapshot::shards()` - the manifest entries, in manifest order - and a
//!   shard it cannot parse is an error, never a silent omission. Shards that are
//!   not node/edge record shards (the coverage document, the index and
//!   architecture documents) are accounted explicitly as skipped records and
//!   `read + skipped == manifest.record_count` is enforced, so a diagram that
//!   dropped a shard cannot be reported as a success.
//! * **The banner is always present.** Coverage is read from the generation's
//!   coverage document, freshness from the caller's store comparison and the
//!   inventory from the manifest. A generation that publishes no coverage
//!   document renders `unknown` and never `complete`, so a partially analysed
//!   graph is never presented as complete.
//! * **An unresolved target is a placeholder.** It is drawn as its own
//!   `UnresolvedTarget` node with `placeholder = true`, listed next to the
//!   banner, and never merged into a resolved node.
//! * **The rendering is deterministic and path free.** Two renders of the same
//!   generation produce byte-identical artifacts, there is no timestamp, and
//!   neither artifact carries a machine-local absolute path
//!   ([`assert_no_absolute_path`] re-checks the emitted bytes rather than trusting
//!   the producer).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::is_absolute_host_path;
use graph_export::reader::Snapshot;
use serde::{Deserialize, Serialize};

/// Version of the summary document this module emits.
pub const SCHEMA_VERSION: u32 = 1;
/// File name of the rendered diagram document.
pub const RESULT_HTML: &str = "result.html";
/// File name of the machine-readable summary.
pub const SUMMARY_JSON: &str = "summary.json";
/// Shard name that carries the generation's coverage document.
pub const COVERAGE_DOCUMENT: &str = "coverage.json";
/// Shard prefix of the symbol and edge indexes, which hold no graph records.
pub const INDEX_PREFIX: &str = "indexes/";
/// Shard prefix of the architecture summary, which holds no graph records.
pub const ARCHITECTURE_PREFIX: &str = "architecture/";
/// The frozen node kind an unresolved or absent target is drawn as.
pub const KIND_UNRESOLVED_TARGET: &str = "UnresolvedTarget";
/// Bucket used when a record carries no usable kind.
pub const KIND_UNKNOWN: &str = "unknown";
/// Bucket used when an edge carries no usable resolution.
pub const RESOLUTION_UNKNOWN: &str = "unknown";
/// Coverage status meaning the profile analysed every input it saw.
pub const COVERAGE_COMPLETE: &str = "complete_for_profile";
/// Coverage status of a graph that is known to be incomplete.
pub const COVERAGE_PARTIAL: &str = "partial";
/// Coverage status of a graph whose inputs are not supported.
pub const COVERAGE_UNSUPPORTED: &str = "unsupported";
/// Coverage status when the generation publishes no coverage document.
pub const COVERAGE_UNKNOWN: &str = "unknown";
/// The record kind an incident edge carries.
pub const EDGE_KIND_RECORD: &str = "edge";
/// Vocabulary label for a kind the frozen schema enum names.
pub const VOCABULARY_FROZEN: &str = "frozen";
/// Vocabulary label for a kind the frozen schema enum does not name.
pub const VOCABULARY_EXTENSION: &str = "extension";
/// Freshness: the rendered generation matches the analysed state.
pub const FRESHNESS_FRESH: &str = "fresh";
/// Freshness: the working tree holds changes the generation does not contain.
pub const FRESHNESS_STALE: &str = "stale";
/// Freshness: a publication is in flight.
pub const FRESHNESS_UPDATING: &str = "updating";
/// Freshness: no comparison against the store was possible.
pub const FRESHNESS_UNKNOWN: &str = "unknown";
/// Verification mode: the store's latest published generation was compared.
pub const VERIFICATION_INVENTORY_HASH: &str = "inventory_hash";
/// Verification mode: nothing was compared, so freshness is never claimed.
pub const VERIFICATION_NONE: &str = "none";
/// Placeholder reason: the analyzer named a target it could not resolve.
pub const PLACEHOLDER_UNRESOLVED: &str = "unresolved-target";
/// Placeholder reason: the edge names a resolved id no rendered node carries.
pub const PLACEHOLDER_ABSENT: &str = "target-node-absent";
/// Reason recorded on a placeholder drawn for an edge source no node carries.
pub const PLACEHOLDER_SOURCE_ABSENT: &str = "source-node-absent";
/// Rule recorded when the parsed record count disagrees with the manifest.
pub const REASON_MANIFEST_DISAGREES: &str = "rendered-manifest-disagrees";
/// Rule recorded when a rendered artifact carries an absolute host path.
pub const REASON_ABSOLUTE_PATH: &str = "rendered-absolute-path";
/// Rule recorded when a manifest-named shard cannot be parsed.
pub const REASON_SHARD_UNREADABLE: &str = "rendered-shard-unreadable";
/// Rule recorded when a named coverage document is not a valid document.
pub const REASON_DOCUMENT_INVALID: &str = "rendered-document-invalid";
/// Rule recorded when a render is asked for with no project.
pub const REASON_NO_PROJECT: &str = "rendered-no-project";
/// Rule recorded when an artifact cannot be written.
pub const REASON_WRITE_FAILED: &str = "rendered-write-failed";

/// The frozen node kind vocabulary of `contracts/schemas/node.schema.json`.
pub const NODE_KINDS: [&str; 17] = [
    "Solution",
    "Project",
    "File",
    "Namespace",
    "Class",
    "Interface",
    "Function",
    "Method",
    "Property",
    "ApiEndpoint",
    "DataStore",
    "Table",
    "StoredProcedure",
    "QueueTopic",
    "ExternalService",
    "TestCase",
    "UnresolvedTarget",
];
/// The frozen edge kind vocabulary of `contracts/schemas/edge.schema.json`.
pub const EDGE_KINDS: [&str; 15] = [
    "CONTAINS",
    "IMPORTS",
    "REFERENCES",
    "CALLS",
    "INHERITS",
    "IMPLEMENTS",
    "EXPOSES",
    "CALLS_ENDPOINT",
    "READS",
    "WRITES",
    "EXECUTES_PROCEDURE",
    "DEPENDS_ON",
    "PUBLISHES",
    "SUBSCRIBES",
    "TESTS",
];
/// The frozen resolution vocabulary of the edge schema.
pub const RESOLUTIONS: [&str; 4] = ["exact_static", "inferred_static", "annotated", "unresolved"];
/// Dash pattern drawn for `exact_static`: a solid line.
pub const DASH_EXACT_STATIC: &str = "";
/// Dash pattern drawn for `inferred_static`.
pub const DASH_INFERRED_STATIC: &str = "6 3";
/// Dash pattern drawn for `annotated`.
pub const DASH_ANNOTATED: &str = "2 2";
/// Dash pattern drawn for `unresolved`.
pub const DASH_UNRESOLVED: &str = "8 3 2 3";
/// Dash pattern drawn for a resolution outside the frozen vocabulary.
pub const DASH_UNKNOWN: &str = "1 3";

/// Fixed, integer-only fills so two renders can never disagree on a colour.
///
/// The palette is indexed by a SHA-256 of the kind name, and [`palette`] retries
/// with a suffixed seed when two kinds land on the same bucket, so every kind in
/// a diagram is drawn distinctly for as many kinds as the table holds.
const PALETTE: [&str; 24] = [
    "#e6194b", "#3cb44b", "#ffe119", "#4363d8", "#f58231", "#911eb4", "#46f0f0", "#f032e6",
    "#bcf60c", "#fabebe", "#008080", "#e6beff", "#9a6324", "#fffac8", "#800000", "#aaffc3",
    "#808000", "#ffd8b1", "#000075", "#a9a9a9", "#7fbf7f", "#bf7fbf", "#7f7fbf", "#bfbf7f",
];

/// Map each distinct kind onto a distinct palette entry, deterministically.
fn palette(kinds: &BTreeSet<String>) -> BTreeMap<String, String> {
    let mut used: BTreeSet<&'static str> = BTreeSet::new();
    let mut assigned: BTreeMap<String, String> = BTreeMap::new();
    for kind in kinds {
        let mut attempt = 0_u32;
        let mut chosen: Option<&'static str> = None;
        while chosen.is_none() && (attempt as usize) < PALETTE.len() * 2 {
            let seed = if attempt == 0 {
                kind.clone()
            } else {
                format!("{kind}#{attempt}")
            };
            let digest = graph_export::sha256_hex(seed.as_bytes());
            let index = usize::from_str_radix(&digest[..4], 16).unwrap_or(0) % PALETTE.len();
            let candidate = PALETTE[index];
            if used.insert(candidate) {
                chosen = Some(candidate);
            }
            attempt += 1;
        }
        // Exhausting the table is deterministic too: reuse the first entry the
        // retry sequence found rather than failing a render over a colour.
        let colour = chosen.unwrap_or(PALETTE[0]);
        assigned.insert(kind.clone(), colour.to_owned());
    }
    assigned
}
/// One published project generation a diagram is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectGraph {
    /// The registered project id.
    pub project_id: String,
    /// The published generation, already read through the frozen reader.
    pub snapshot: Snapshot,
}

impl ProjectGraph {
    /// Pair a project id with its loaded generation.
    #[must_use]
    pub fn new(project_id: impl Into<String>, snapshot: Snapshot) -> Self {
        Self {
            project_id: project_id.into(),
            snapshot,
        }
    }

    /// The generation id this project is pinned to.
    #[must_use]
    pub fn generation_id(&self) -> &str {
        self.snapshot.generation_id()
    }
}

/// How strongly the caller could compare the generation with the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMode {
    /// The store's latest published generation was actually compared.
    InventoryHash,
    /// Nothing was compared, so freshness must not be claimed.
    None,
}

impl VerificationMode {
    /// Frozen spelling used in the summary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InventoryHash => VERIFICATION_INVENTORY_HASH,
            Self::None => VERIFICATION_NONE,
        }
    }
}

/// The freshness facts the caller could actually observe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshnessInput {
    /// Files whose analysed generation is behind their observed generation.
    pub dirty_files: usize,
    /// The generations the store knows as published, sorted and unique.
    pub latest_published_generations: Vec<String>,
    /// Whether the store comparison actually happened.
    pub verification_mode: VerificationMode,
}

impl FreshnessInput {
    /// Build the freshness facts.
    #[must_use]
    pub fn new(
        dirty_files: usize,
        latest_published_generations: Vec<String>,
        verification_mode: VerificationMode,
    ) -> Self {
        let mut latest = latest_published_generations;
        latest.sort();
        latest.dedup();
        Self {
            dirty_files,
            latest_published_generations: latest,
            verification_mode,
        }
    }

    /// The freshness state this input justifies.
    ///
    /// A render never claims `fresh` without a comparison: when the caller
    /// could not compare the generation against the store the answer is
    /// `unknown`, and a pending dirty file makes the rendered generation `stale`
    /// because it does not contain that edit.
    #[must_use]
    pub fn status(&self) -> &'static str {
        match self.verification_mode {
            VerificationMode::None => FRESHNESS_UNKNOWN,
            VerificationMode::InventoryHash => {
                if self.dirty_files == 0 {
                    FRESHNESS_FRESH
                } else {
                    FRESHNESS_STALE
                }
            }
        }
    }
}

/// The generation's coverage document (`coverage.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageDocument {
    /// Frozen coverage status.
    pub status: String,
    /// Input files the profile considered.
    #[serde(default)]
    pub input_files: usize,
    /// Input files the profile processed.
    #[serde(default)]
    pub processed_files: usize,
    /// References the analysis could not resolve.
    #[serde(default)]
    pub unresolved_references: usize,
    /// Patterns the profile explicitly does not support.
    #[serde(default)]
    pub unsupported_patterns: Vec<String>,
}

/// The always-present coverage banner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageBanner {
    /// Frozen status, or [`COVERAGE_UNKNOWN`] when no document was published.
    pub status: String,
    /// Whether every rendered generation published a coverage document.
    pub present: bool,
    /// True only for [`COVERAGE_COMPLETE`].
    pub complete: bool,
    /// Summed input files, when every generation published a document.
    pub input_files: Option<usize>,
    /// Summed processed files, when every generation published a document.
    pub processed_files: Option<usize>,
    /// Summed unresolved references, when every generation published one.
    pub unresolved_references: Option<usize>,
    /// Union of the unsupported patterns, sorted.
    pub unsupported_patterns: Vec<String>,
}

/// The always-present freshness banner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FreshnessBanner {
    /// [`FRESHNESS_FRESH`], [`FRESHNESS_STALE`], [`FRESHNESS_UPDATING`] or
    /// [`FRESHNESS_UNKNOWN`].
    pub status: String,
    /// Dirty files the caller observed.
    pub dirty_files: usize,
    /// [`VERIFICATION_INVENTORY_HASH`] or [`VERIFICATION_NONE`].
    pub verification: String,
    /// Generations the store knows as published.
    pub latest_published_generations: Vec<String>,
}

/// The always-present manifest inventory banner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestBanner {
    /// The generation ids the diagram was built from, sorted and unique.
    pub generation_ids: Vec<String>,
    /// Manifest entries read, across every rendered generation.
    pub shards: usize,
    /// Records the manifests declare, across every rendered generation.
    pub records: usize,
    /// Bytes the manifests declare.
    pub total_bytes: usize,
    /// Records parsed into nodes and edges.
    pub graph_records: usize,
    /// Records deliberately not treated as graph records (coverage, indexes,
    /// architecture), counted rather than dropped.
    pub skipped_records: usize,
}

/// The banner every diagram document and summary carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Banner {
    /// Coverage, always present.
    pub coverage: CoverageBanner,
    /// Freshness, always present.
    pub freshness: FreshnessBanner,
    /// Manifest inventory, always present.
    pub manifest: ManifestBanner,
    /// The honest one-line reading of the coverage state.
    pub notice: String,
}

/// One rendered node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagramNode {
    /// Node id: the record key, or the derived placeholder id.
    pub id: String,
    /// Canonical kind: a frozen spelling, an extension spelling, or
    /// [`KIND_UNKNOWN`].
    pub kind: String,
    /// [`VOCABULARY_FROZEN`] or [`VOCABULARY_EXTENSION`].
    pub vocabulary: String,
    /// The fill drawn for this kind.
    pub color: String,
    /// Whether this node stands in for a target that did not resolve.
    pub placeholder: bool,
    /// Why the placeholder exists, when it does.
    pub placeholder_reason: Option<String>,
    /// Short name, when the record carries one.
    pub name: Option<String>,
    /// Qualified name, when the record carries one.
    pub qualified_name: Option<String>,
    /// Projects that carry this node, sorted.
    pub project_ids: Vec<String>,
}

/// One rendered edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagramEdge {
    /// Edge id: the record key.
    pub id: String,
    /// The project whose generation carries this edge.
    pub project_id: String,
    /// Source node id.
    pub source_id: String,
    /// The node the edge is drawn to: a resolved node, or a placeholder node.
    pub target: String,
    /// `resolved` or `placeholder`.
    pub target_kind: String,
    /// The unresolved spelling the analyzer recorded, when there is one.
    pub unresolved_target: Option<String>,
    /// The project the edge asserted as its target project, when recorded.
    pub target_project_id: Option<String>,
    /// Canonical edge kind.
    pub kind: String,
    /// [`VOCABULARY_FROZEN`] or [`VOCABULARY_EXTENSION`].
    pub vocabulary: String,
    /// The fill drawn for this kind.
    pub color: String,
    /// Frozen resolution spelling, or [`RESOLUTION_UNKNOWN`].
    pub resolution: String,
    /// The dash pattern drawn for this resolution; distinct per resolution.
    pub dash_pattern: String,
}

/// One node-kind legend row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeLegendEntry {
    /// Canonical kind.
    pub kind: String,
    /// Vocabulary label.
    pub vocabulary: String,
    /// The fill drawn for this kind.
    pub color: String,
    /// Whether the kind is drawn as a placeholder shape.
    pub placeholder: bool,
}

/// One edge-kind legend row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EdgeLegendEntry {
    /// Canonical kind.
    pub kind: String,
    /// Vocabulary label.
    pub vocabulary: String,
    /// The stroke drawn for this kind.
    pub color: String,
}

/// One resolution legend row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolutionLegendEntry {
    /// Frozen resolution spelling, or [`RESOLUTION_UNKNOWN`].
    pub resolution: String,
    /// The dash pattern drawn for this resolution.
    pub dash_pattern: String,
}

/// Inventory counts a reviewer can check at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Counts {
    /// Nodes drawn, including placeholders.
    pub nodes: usize,
    /// Edges drawn.
    pub edges: usize,
    /// Placeholder nodes drawn.
    pub placeholders: usize,
    /// Edges drawn to a placeholder.
    pub placeholder_edges: usize,
    /// Edges that name a resolved id no rendered node carries, as a source
    /// or as a target.
    pub absent_targets: usize,
    /// Manifest entries read.
    pub shards: usize,
    /// Records parsed into nodes and edges.
    pub graph_records: usize,
    /// Records accounted as non-graph documents.
    pub skipped_records: usize,
    /// Distinct node kinds drawn.
    pub node_kinds: usize,
    /// Distinct edge kinds drawn.
    pub edge_kinds: usize,
    /// Distinct resolutions drawn.
    pub resolutions: usize,
}

/// The machine-readable inventory of one diagram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagramSummary {
    /// Version of this document.
    pub schema_version: u32,
    /// Solution the diagram belongs to.
    pub solution_id: String,
    /// The always-present banner.
    pub banner: Banner,
    /// Nodes, sorted by id.
    pub nodes: Vec<DiagramNode>,
    /// Edges, sorted by id.
    pub edges: Vec<DiagramEdge>,
    /// Node-kind legend, in frozen order then extension order.
    pub node_legend: Vec<NodeLegendEntry>,
    /// Edge-kind legend, in frozen order then extension order.
    pub edge_legend: Vec<EdgeLegendEntry>,
    /// Resolution legend, in frozen order then unknown.
    pub resolution_legend: Vec<ResolutionLegendEntry>,
    /// Inventory counts.
    pub counts: Counts,
    /// The placeholder ids, in the order they are listed under the banner.
    pub unresolved_targets: Vec<String>,
}

/// One rendered diagram: the summary and its document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagram {
    /// The machine-readable inventory.
    pub summary: DiagramSummary,
    /// The self-contained diagram document.
    pub result_html: String,
}

/// One emitted artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Artifact {
    /// Path relative to the output directory, never an absolute path.
    pub name: String,
    /// SHA-256 of the emitted bytes.
    pub sha256: String,
    /// Byte length of the emitted bytes.
    pub bytes: usize,
}

/// What one render wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderReport {
    /// Version of this report.
    pub schema_version: u32,
    /// Solution the diagram belongs to.
    pub solution_id: String,
    /// The banner, so a caller that only prints the report still sees coverage.
    pub banner: Banner,
    /// Inventory counts.
    pub counts: Counts,
    /// The emitted artifacts, in a fixed order.
    pub artifacts: Vec<Artifact>,
}
/// Which target spelling an edge record carried.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RawTarget {
    /// A node id the analyzer proved.
    Resolved(String),
    /// A name the analyzer could not resolve.
    Unresolved(String),
}

/// One edge record before its target is resolved against the node inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RawEdge {
    project_id: String,
    id: String,
    source_id: String,
    target: RawTarget,
    target_project_id: Option<String>,
    kind: String,
    resolution: String,
}

/// One node before its colour and project list are final.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeBuild {
    kind: String,
    vocabulary: String,
    name: Option<String>,
    qualified_name: Option<String>,
    placeholder: bool,
    placeholder_reason: Option<String>,
    projects: BTreeSet<String>,
}

fn document_invalid(detail: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::Internal,
        "the generation's coverage document is not a valid coverage document",
    )
    .with_detail("rule", REASON_DOCUMENT_INVALID)
    .with_detail("observed", detail)
}

fn parse_coverage(
    snapshot: &Snapshot,
    relative_path: &str,
) -> Result<CoverageDocument, AxiomError> {
    if let Ok(records) = snapshot.parse_shard(relative_path) {
        if let Some(value) = records.into_iter().next() {
            if let Ok(document) = serde_json::from_value::<CoverageDocument>(value) {
                return Ok(document);
            }
        }
    }
    // The graph data contract spells these documents as plain JSON, not JSONL,
    // so a pretty-printed document is read from its bytes rather than refused.
    let bytes = snapshot
        .shard(relative_path)
        .ok_or_else(|| document_invalid("the coverage document is not in the manifest"))?;
    serde_json::from_slice::<CoverageDocument>(bytes)
        .map_err(|error| document_invalid(&error.to_string()))
}

fn body_str(record: &serde_json::Value, names: &[&str]) -> Option<String> {
    let body = record.get("body")?;
    names
        .iter()
        .find_map(|name| body.get(*name).and_then(serde_json::Value::as_str))
        .map(ToOwned::to_owned)
}

fn record_kind(record: &serde_json::Value) -> String {
    record
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Map an observed spelling onto the frozen vocabulary, case-insensitively.
fn canonical_kind(observed: &str, vocabulary: &[&str]) -> (String, &'static str) {
    if observed.is_empty() {
        return (KIND_UNKNOWN.to_owned(), VOCABULARY_EXTENSION);
    }
    match vocabulary
        .iter()
        .find(|kind| kind.eq_ignore_ascii_case(observed))
    {
        Some(frozen) => ((*frozen).to_owned(), VOCABULARY_FROZEN),
        None => (observed.to_owned(), VOCABULARY_EXTENSION),
    }
}

/// Map an observed resolution onto the frozen vocabulary.
fn canonical_resolution(observed: &str) -> String {
    match RESOLUTIONS
        .iter()
        .find(|value| value.eq_ignore_ascii_case(observed))
    {
        Some(frozen) => (*frozen).to_owned(),
        None => RESOLUTION_UNKNOWN.to_owned(),
    }
}

/// The distinct dash pattern drawn for one resolution.
fn dash_pattern(resolution: &str) -> &'static str {
    match resolution {
        "exact_static" => DASH_EXACT_STATIC,
        "inferred_static" => DASH_INFERRED_STATIC,
        "annotated" => DASH_ANNOTATED,
        "unresolved" => DASH_UNRESOLVED,
        _ => DASH_UNKNOWN,
    }
}

/// The derived id of one placeholder node.
fn placeholder_id(name: &str) -> String {
    let digest = graph_export::sha256_hex(name.as_bytes());
    format!("unresolved:{}", &digest[..16])
}

fn node_from_record(project_id: &str, record: &serde_json::Value) -> (String, NodeBuild) {
    let id = body_str(record, &["id"]).unwrap_or_else(|| {
        record
            .get("key")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned()
    });
    let observed = body_str(record, &["kind"]).unwrap_or_else(|| record_kind(record));
    let (kind, vocabulary) = canonical_kind(&observed, &NODE_KINDS);
    let mut projects = BTreeSet::new();
    projects.insert(project_id.to_owned());
    (
        id,
        NodeBuild {
            kind,
            vocabulary: vocabulary.to_owned(),
            name: body_str(record, &["name"]),
            qualified_name: body_str(record, &["qualified_name"]),
            placeholder: false,
            placeholder_reason: None,
            projects,
        },
    )
}

fn edge_from_record(project_id: &str, record: &serde_json::Value) -> RawEdge {
    let id = record
        .get("key")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let source_id = body_str(record, &["source_id", "from", "source"]).unwrap_or_default();
    let resolution = canonical_resolution(
        body_str(record, &["resolution"])
            .unwrap_or_default()
            .as_str(),
    );
    let target_id = body_str(record, &["target_id", "to", "target"]);
    let unresolved = body_str(record, &["unresolved_target", "unresolved"]);
    let target = match (resolution == "unresolved", target_id) {
        (false, Some(resolved)) => RawTarget::Resolved(resolved),
        _ => RawTarget::Unresolved(unresolved.unwrap_or_default()),
    };
    let observed_kind = body_str(record, &["kind"]).unwrap_or_else(|| record_kind(record));
    let (kind, _) = canonical_kind(&observed_kind, &EDGE_KINDS);
    RawEdge {
        project_id: project_id.to_owned(),
        id,
        source_id,
        target,
        target_project_id: body_str(record, &["target_project_id"]),
        kind,
        resolution,
    }
}
/// `target_kind` of an edge drawn to a real node.
pub const TARGET_RESOLVED: &str = "resolved";
/// `target_kind` of an edge drawn to a placeholder node.
pub const TARGET_PLACEHOLDER: &str = "placeholder";

fn merge_node(nodes: &mut BTreeMap<String, NodeBuild>, id: &str, build: NodeBuild) {
    match nodes.get_mut(id) {
        Some(existing) => {
            existing.projects.extend(build.projects);
        }
        None => {
            nodes.insert(id.to_owned(), build);
        }
    }
}

fn insert_placeholder(
    nodes: &mut BTreeMap<String, NodeBuild>,
    placeholder: &str,
    name: &str,
    project_id: &str,
    reason: &str,
) {
    let mut projects = BTreeSet::new();
    projects.insert(project_id.to_owned());
    merge_node(
        nodes,
        placeholder,
        NodeBuild {
            kind: KIND_UNRESOLVED_TARGET.to_owned(),
            vocabulary: VOCABULARY_FROZEN.to_owned(),
            name: Some(name.to_owned()),
            qualified_name: None,
            placeholder: true,
            placeholder_reason: Some(reason.to_owned()),
            projects,
        },
    );
}

fn vocabulary_of(kind: &str, frozen: &[&str]) -> &'static str {
    if frozen.iter().any(|value| value.eq_ignore_ascii_case(kind)) {
        VOCABULARY_FROZEN
    } else {
        VOCABULARY_EXTENSION
    }
}

/// Frozen values first, in frozen order, then the extensions sorted by name.
fn ordered_values(present: &BTreeSet<String>, frozen: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = frozen
        .iter()
        .filter(|value| present.contains(**value))
        .map(|value| (*value).to_owned())
        .collect();
    for value in present {
        if !frozen
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(value))
        {
            out.push(value.clone());
        }
    }
    out
}

fn aggregate_coverage(
    coverages: &[CoverageDocument],
    every_generation_published: bool,
) -> CoverageBanner {
    if !every_generation_published || coverages.is_empty() {
        return CoverageBanner {
            status: COVERAGE_UNKNOWN.to_owned(),
            present: false,
            complete: false,
            input_files: None,
            processed_files: None,
            unresolved_references: None,
            unsupported_patterns: Vec::new(),
        };
    }
    let status = if coverages
        .iter()
        .any(|document| document.status == COVERAGE_UNSUPPORTED)
    {
        COVERAGE_UNSUPPORTED
    } else if coverages
        .iter()
        .any(|document| document.status == COVERAGE_PARTIAL)
    {
        COVERAGE_PARTIAL
    } else if coverages
        .iter()
        .all(|document| document.status == COVERAGE_COMPLETE)
    {
        COVERAGE_COMPLETE
    } else {
        COVERAGE_UNKNOWN
    };
    let mut unsupported: BTreeSet<String> = BTreeSet::new();
    for document in coverages {
        unsupported.extend(document.unsupported_patterns.iter().cloned());
    }
    CoverageBanner {
        status: status.to_owned(),
        present: true,
        complete: status == COVERAGE_COMPLETE,
        input_files: Some(coverages.iter().map(|document| document.input_files).sum()),
        processed_files: Some(
            coverages
                .iter()
                .map(|document| document.processed_files)
                .sum(),
        ),
        unresolved_references: Some(
            coverages
                .iter()
                .map(|document| document.unresolved_references)
                .sum(),
        ),
        unsupported_patterns: unsupported.into_iter().collect(),
    }
}

fn banner_notice(coverage: &CoverageBanner, freshness: &FreshnessBanner) -> String {
    let status = coverage.status.as_str();
    let coverage_line = if coverage.complete {
        format!(
            "coverage is {status}: the analysed profile reported no partial or unsupported input"
        )
    } else {
        format!("coverage is {status}: this diagram is not evidence that the solution is fully analysed")
    };
    let dirty = freshness.dirty_files;
    let freshness_line = match freshness.status.as_str() {
        FRESHNESS_FRESH => {
            "freshness is fresh: the rendered generations match the analysed state".to_owned()
        }
        FRESHNESS_STALE => format!(
            "freshness is stale: {dirty} file(s) changed after the rendered generations were published"
        ),
        FRESHNESS_UPDATING => "freshness is updating: a publication is in flight".to_owned(),
        _ => "freshness is unknown: no store comparison backed this render".to_owned(),
    };
    format!("{coverage_line}. {freshness_line}.")
}

/// Build the deterministic diagram of one solution from its published projects.
///
/// # Errors
///
/// [`ErrorCode::NotFound`] with [`REASON_NO_PROJECT`] when no project is given;
/// [`ErrorCode::Internal`] with [`REASON_SHARD_UNREADABLE`],
/// [`REASON_DOCUMENT_INVALID`] or [`REASON_MANIFEST_DISAGREES`] when a
/// manifest-named shard cannot be parsed or the rendered record count disagrees
/// with the manifest. A diagram that silently omitted a shard is a failure here,
/// not a partial success.
pub fn build_diagram(
    solution_id: &str,
    projects: &[ProjectGraph],
    freshness: &FreshnessInput,
) -> Result<Diagram, AxiomError> {
    if projects.is_empty() {
        return Err(AxiomError::new(
            ErrorCode::NotFound,
            "a diagram needs at least one published project generation",
        )
        .with_detail("rule", REASON_NO_PROJECT)
        .with_detail("solution_id", solution_id));
    }

    let mut nodes: BTreeMap<String, NodeBuild> = BTreeMap::new();
    let mut raw_edges: Vec<RawEdge> = Vec::new();
    let mut coverages: Vec<CoverageDocument> = Vec::new();
    let mut every_generation_published = true;
    let mut generation_ids: BTreeSet<String> = BTreeSet::new();
    let mut shards = 0usize;
    let mut records = 0usize;
    let mut total_bytes = 0usize;
    let mut skipped_records = 0usize;
    let mut graph_records = 0usize;

    for project in projects {
        let snapshot = &project.snapshot;
        let manifest = snapshot.manifest();
        generation_ids.insert(snapshot.generation_id().to_owned());
        let mut project_coverage: Option<CoverageDocument> = None;
        let mut skipped = 0usize;
        let mut counted = 0usize;
        for entry in &manifest.entries {
            let path = entry.relative_path.replace('\\', "/");
            if path == COVERAGE_DOCUMENT {
                project_coverage = Some(parse_coverage(snapshot, &entry.relative_path)?);
                skipped += entry.record_count;
                continue;
            }
            if path.starts_with(INDEX_PREFIX) || path.starts_with(ARCHITECTURE_PREFIX) {
                skipped += entry.record_count;
                continue;
            }
            let parsed = snapshot
                .parse_shard(&entry.relative_path)
                .map_err(|error| {
                    AxiomError::new(
                        ErrorCode::Internal,
                        format!("a published shard could not be read: {error}"),
                    )
                    .with_detail("rule", REASON_SHARD_UNREADABLE)
                    .with_detail("observed", path.clone())
                    .with_detail("generation", snapshot.generation_id())
                })?;
            if parsed.len() != entry.record_count {
                return Err(AxiomError::new(
                    ErrorCode::Internal,
                    format!(
                        "a rendered shard disagrees with the manifest of generation {}",
                        snapshot.generation_id()
                    ),
                )
                .with_detail("rule", REASON_MANIFEST_DISAGREES)
                .with_detail("observed", path.clone())
                .with_detail("expected", entry.record_count.to_string())
                .with_detail("actual", parsed.len().to_string()));
            }
            for record in &parsed {
                counted += 1;
                if record_kind(record) == EDGE_KIND_RECORD {
                    raw_edges.push(edge_from_record(&project.project_id, record));
                } else {
                    let (id, build) = node_from_record(&project.project_id, record);
                    merge_node(&mut nodes, &id, build);
                }
            }
        }
        if counted + skipped != manifest.record_count {
            return Err(AxiomError::new(
                ErrorCode::Internal,
                format!(
                    "the rendered shards disagree with the manifest of generation {}",
                    snapshot.generation_id()
                ),
            )
            .with_detail("rule", REASON_MANIFEST_DISAGREES)
            .with_detail("expected", manifest.record_count.to_string())
            .with_detail("actual", counted.to_string())
            .with_detail("observed", format!("skipped_records={skipped}")));
        }
        shards += manifest.entries.len();
        records += manifest.record_count;
        total_bytes += manifest.total_bytes;
        skipped_records += skipped;
        graph_records += counted;
        match project_coverage {
            Some(document) => coverages.push(document),
            None => every_generation_published = false,
        }
    }

    // Resolve every edge target against the whole inventory, so an edge in a
    // later shard resolves exactly like one in the first shard.
    let mut absent_targets = 0usize;
    let mut edges: Vec<DiagramEdge> = Vec::with_capacity(raw_edges.len());
    for raw in &raw_edges {
        // An edge whose source names no rendered node would be dropped by the
        // canvas, which is exactly the silent omission this projection must not
        // make, so the source gets the same placeholder treatment as a target.
        let source_id = if raw.source_id.is_empty() || nodes.contains_key(&raw.source_id) {
            raw.source_id.clone()
        } else {
            absent_targets += 1;
            let placeholder = placeholder_id(&raw.source_id);
            insert_placeholder(
                &mut nodes,
                &placeholder,
                &raw.source_id,
                &raw.project_id,
                PLACEHOLDER_SOURCE_ABSENT,
            );
            placeholder
        };
        let (target, target_kind, unresolved_target) = match &raw.target {
            RawTarget::Resolved(id) => {
                if nodes.contains_key(id) {
                    (id.clone(), TARGET_RESOLVED, None)
                } else {
                    absent_targets += 1;
                    let placeholder = placeholder_id(id);
                    insert_placeholder(
                        &mut nodes,
                        &placeholder,
                        id,
                        &raw.project_id,
                        PLACEHOLDER_ABSENT,
                    );
                    (placeholder, TARGET_PLACEHOLDER, None)
                }
            }
            RawTarget::Unresolved(name) => {
                let placeholder = placeholder_id(name);
                insert_placeholder(
                    &mut nodes,
                    &placeholder,
                    name,
                    &raw.project_id,
                    PLACEHOLDER_UNRESOLVED,
                );
                (placeholder, TARGET_PLACEHOLDER, Some(name.clone()))
            }
        };
        edges.push(DiagramEdge {
            id: raw.id.clone(),
            project_id: raw.project_id.clone(),
            source_id,
            target,
            target_kind: target_kind.to_owned(),
            unresolved_target,
            target_project_id: raw.target_project_id.clone(),
            kind: raw.kind.clone(),
            vocabulary: vocabulary_of(&raw.kind, &EDGE_KINDS).to_owned(),
            color: String::new(),
            resolution: raw.resolution.clone(),
            dash_pattern: dash_pattern(&raw.resolution).to_owned(),
        });
    }
    edges.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.project_id.cmp(&right.project_id))
    });
    edges.dedup();

    // One distinct fill per distinct kind, then the fills are attached.
    let node_kind_set: BTreeSet<String> = nodes.values().map(|node| node.kind.clone()).collect();
    let edge_kind_set: BTreeSet<String> = edges.iter().map(|edge| edge.kind.clone()).collect();
    let node_colors = palette(&node_kind_set);
    let edge_colors = palette(&edge_kind_set);
    for edge in &mut edges {
        edge.color = edge_colors.get(&edge.kind).cloned().unwrap_or_default();
    }

    let mut drawn: Vec<DiagramNode> = nodes
        .into_iter()
        .map(|(id, build)| DiagramNode {
            id,
            color: node_colors.get(&build.kind).cloned().unwrap_or_default(),
            kind: build.kind,
            vocabulary: build.vocabulary,
            placeholder: build.placeholder,
            placeholder_reason: build.placeholder_reason,
            name: build.name,
            qualified_name: build.qualified_name,
            project_ids: build.projects.into_iter().collect(),
        })
        .collect();
    drawn.sort_by(|left, right| left.id.cmp(&right.id));

    let resolution_set: BTreeSet<String> =
        edges.iter().map(|edge| edge.resolution.clone()).collect();
    let node_legend: Vec<NodeLegendEntry> = ordered_values(&node_kind_set, &NODE_KINDS)
        .into_iter()
        .map(|kind| NodeLegendEntry {
            vocabulary: vocabulary_of(&kind, &NODE_KINDS).to_owned(),
            color: node_colors.get(&kind).cloned().unwrap_or_default(),
            placeholder: kind == KIND_UNRESOLVED_TARGET,
            kind,
        })
        .collect();
    let edge_legend: Vec<EdgeLegendEntry> = ordered_values(&edge_kind_set, &EDGE_KINDS)
        .into_iter()
        .map(|kind| EdgeLegendEntry {
            vocabulary: vocabulary_of(&kind, &EDGE_KINDS).to_owned(),
            color: edge_colors.get(&kind).cloned().unwrap_or_default(),
            kind,
        })
        .collect();
    let resolution_legend: Vec<ResolutionLegendEntry> =
        ordered_values(&resolution_set, &RESOLUTIONS)
            .into_iter()
            .map(|resolution| ResolutionLegendEntry {
                dash_pattern: dash_pattern(&resolution).to_owned(),
                resolution,
            })
            .collect();

    let placeholders = drawn.iter().filter(|node| node.placeholder).count();
    let placeholder_edges = edges
        .iter()
        .filter(|edge| edge.target_kind == TARGET_PLACEHOLDER)
        .count();
    let counts = Counts {
        nodes: drawn.len(),
        edges: edges.len(),
        placeholders,
        placeholder_edges,
        absent_targets,
        shards,
        graph_records,
        skipped_records,
        node_kinds: node_kind_set.len(),
        edge_kinds: edge_kind_set.len(),
        resolutions: resolution_set.len(),
    };
    let unresolved_targets: Vec<String> = drawn
        .iter()
        .filter(|node| node.placeholder)
        .map(|node| node.id.clone())
        .collect();

    let coverage = aggregate_coverage(&coverages, every_generation_published);
    let freshness_banner = FreshnessBanner {
        status: freshness.status().to_owned(),
        dirty_files: freshness.dirty_files,
        verification: freshness.verification_mode.as_str().to_owned(),
        latest_published_generations: freshness.latest_published_generations.clone(),
    };
    let banner = Banner {
        notice: banner_notice(&coverage, &freshness_banner),
        coverage,
        freshness: freshness_banner,
        manifest: ManifestBanner {
            generation_ids: generation_ids.into_iter().collect(),
            shards,
            records,
            total_bytes,
            graph_records,
            skipped_records,
        },
    };

    let summary = DiagramSummary {
        schema_version: SCHEMA_VERSION,
        solution_id: solution_id.to_owned(),
        banner,
        nodes: drawn,
        edges,
        node_legend,
        edge_legend,
        resolution_legend,
        counts,
        unresolved_targets,
    };
    let result_html = render_html(&summary);
    Ok(Diagram {
        summary,
        result_html,
    })
}

/// Serialize the summary as one deterministic JSON document.
///
/// # Errors
///
/// [`ErrorCode::Internal`] when the summary cannot be serialised.
pub fn summary_json_bytes(summary: &DiagramSummary) -> Result<Vec<u8>, AxiomError> {
    let mut bytes = serde_json::to_vec_pretty(summary).map_err(|error| {
        AxiomError::new(
            ErrorCode::Internal,
            "the diagram summary is not serialisable",
        )
        .with_detail("observed", error.to_string())
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_failed(error: &std::io::Error) -> AxiomError {
    AxiomError::new(
        ErrorCode::Internal,
        "a diagram artifact could not be written",
    )
    .with_detail("rule", REASON_WRITE_FAILED)
    .with_detail("observed", error.to_string())
}

fn artifact(name: &str, bytes: &[u8]) -> Artifact {
    Artifact {
        name: name.to_owned(),
        sha256: graph_export::sha256_hex(bytes),
        bytes: bytes.len(),
    }
}

/// Write `result.html` and `summary.json` into `out_dir` and report their hashes.
///
/// # Errors
///
/// [`ErrorCode::Internal`] with [`REASON_ABSOLUTE_PATH`] when an artifact carries
/// a machine-local absolute path, or with [`REASON_WRITE_FAILED`] when the
/// output cannot be written. The failure never names a host path, so a caller
/// that prints the error envelope does not leak one either.
pub fn write_diagram(diagram: &Diagram, out_dir: &Path) -> Result<RenderReport, AxiomError> {
    let summary_bytes = summary_json_bytes(&diagram.summary)?;
    let html_bytes = diagram.result_html.as_bytes().to_vec();
    let summary_text = String::from_utf8_lossy(&summary_bytes).into_owned();
    assert_no_absolute_path(SUMMARY_JSON, &summary_text)?;
    assert_no_absolute_path(RESULT_HTML, &diagram.result_html)?;
    std::fs::create_dir_all(out_dir).map_err(|error| write_failed(&error))?;
    std::fs::write(out_dir.join(RESULT_HTML), &html_bytes).map_err(|error| write_failed(&error))?;
    std::fs::write(out_dir.join(SUMMARY_JSON), &summary_bytes)
        .map_err(|error| write_failed(&error))?;
    Ok(RenderReport {
        schema_version: SCHEMA_VERSION,
        solution_id: diagram.summary.solution_id.clone(),
        banner: diagram.summary.banner.clone(),
        counts: diagram.summary.counts,
        artifacts: vec![
            artifact(RESULT_HTML, &html_bytes),
            artifact(SUMMARY_JSON, &summary_bytes),
        ],
    })
}

/// Refuse to emit an artifact that carries a machine-local absolute path.
///
/// The check is syntactic, deterministic and independent of the producer:
/// [`strip_markup`] removes tag names first, then the remaining text is split on
/// the delimiters that can separate a path from its surrounding markup -
/// whitespace, quoting, the `=` of an attribute, the `,` and `;` of a list, the
/// parentheses of a `url(...)`, and the `<`, `>`, `&` and `|` of markup - and
/// every token is tested with `graph_core::paths::is_absolute_host_path`. A
/// leaked project root is a hard error instead of something a reviewer has to
/// notice, and the error records the token length rather than the token, so the
/// refusal itself never carries the path.
///
/// Tag *names* are removed because `is_absolute_host_path` treats any leading
/// `/` as absolute, so a closing tag such as `</span>` would otherwise be
/// mistaken for a POSIX path. Attribute values are kept, so a path hidden in
/// an attribute value is still refused.
fn assert_no_absolute_path(label: &str, text: &str) -> Result<(), AxiomError> {
    for token in strip_markup(text).split([
        ' ', '\t', '\n', '\r', '"', '\'', '=', ',', ';', '(', ')', '<', '>', '&', '|',
    ]) {
        if token.is_empty() {
            continue;
        }
        if is_absolute_host_path(token) {
            return Err(AxiomError::new(
                ErrorCode::Internal,
                "a rendered artifact carries a machine-local absolute path",
            )
            .with_detail("rule", REASON_ABSOLUTE_PATH)
            .with_detail("observed", format!("{label} token_bytes={}", token.len())));
        }
    }
    Ok(())
}

/// Remove tag names from `text`, keeping tag attribute values and all text.
///
/// A host path wrapped in markup becomes a bare token the scanner can see, while
/// a closing tag such as `</span>` becomes a single space so no fragment ever
/// starts with a bare `/`.
fn strip_markup(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '<' {
            out.push(character);
            continue;
        }
        out.push(' ');
        if chars.peek() == Some(&'/') {
            chars.next();
        }
        while let Some(&next) = chars.peek() {
            if next.is_ascii_alphanumeric() || matches!(next, '-' | '_' | ':') {
                chars.next();
            } else {
                break;
            }
        }
        for inner in chars.by_ref() {
            if inner == '>' {
                break;
            }
            out.push(inner);
        }
        out.push(' ');
    }
    out
}
/// Escape a value for HTML text and for a quoted attribute value.
fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

/// Shorten a canvas label without splitting a character.
fn short(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_owned();
    }
    let kept: String = value.chars().take(limit.saturating_sub(1)).collect();
    format!("{kept}\u{2026}")
}

/// Drawn node width, in diagram units.
const NODE_WIDTH: i64 = 200;
/// Drawn node height, in diagram units.
const NODE_HEIGHT: i64 = 56;
/// Nodes per row on the canvas.
const COLUMNS: usize = 4;
/// Horizontal distance between column origins.
const COLUMN_PITCH: i64 = 300;
/// Vertical distance between row origins.
const ROW_PITCH: i64 = 140;
/// Canvas margin around the node grid.
const MARGIN: i64 = 40;

/// The centre of the node at `index`, in diagram units.
fn node_centre(index: usize) -> (i64, i64) {
    let column = (index % COLUMNS) as i64;
    let row = (index / COLUMNS) as i64;
    (
        MARGIN + column * COLUMN_PITCH + NODE_WIDTH / 2,
        MARGIN + row * ROW_PITCH + NODE_HEIGHT / 2,
    )
}

/// The canvas size that holds `nodes` node boxes.
fn canvas_size(nodes: usize) -> (i64, i64) {
    let rows = nodes.div_ceil(COLUMNS).max(1) as i64;
    (
        MARGIN * 2 + COLUMNS as i64 * COLUMN_PITCH,
        MARGIN * 2 + rows * ROW_PITCH,
    )
}

/// The offset from the centre of a node box to its border along a direction.
///
/// Integer arithmetic only: the horizontal border is hit first exactly when
/// `half_width * |dy| <= half_height * |dx|`, so two renders can never disagree
/// about where a line starts.
fn border_offset(dx: i64, dy: i64) -> (i64, i64) {
    let (ax, ay) = (dx.abs(), dy.abs());
    if ax == 0 && ay == 0 {
        return (0, 0);
    }
    let half_width = NODE_WIDTH / 2;
    let half_height = NODE_HEIGHT / 2;
    if ay == 0 {
        return (half_width * dx.signum(), 0);
    }
    if ax == 0 {
        return (0, half_height * dy.signum());
    }
    if half_width * ay <= half_height * ax {
        (half_width * dx.signum(), (half_width * dy) / ax)
    } else {
        ((half_height * dx) / ay, half_height * dy.signum())
    }
}

/// The trimmed endpoints of the line drawn between two node boxes.
fn edge_endpoints(source: (i64, i64), target: (i64, i64)) -> ((i64, i64), (i64, i64)) {
    let (dx, dy) = (target.0 - source.0, target.1 - source.1);
    let start_offset = border_offset(dx, dy);
    let end_offset = border_offset(-dx, -dy);
    (
        (source.0 + start_offset.0, source.1 + start_offset.1),
        (target.0 + end_offset.0, target.1 + end_offset.1),
    )
}

/// The `stroke-dasharray` attribute for a resolution, or nothing when solid.
fn dash_attribute(pattern: &str) -> String {
    if pattern.is_empty() {
        String::new()
    } else {
        format!(" stroke-dasharray=\"{}\"", escape_html(pattern))
    }
}
/// One `field | value` row of the banner table.
fn banner_row(html: &mut String, name: &str, value: &str) {
    html.push_str(&format!(
        "<tr><td>{}</td><td>{}</td></tr>\n",
        escape_html(name),
        escape_html(value)
    ));
}

/// The always-present coverage, freshness and inventory banner, with the
/// unresolved placeholder list directly beneath it.
fn render_banner(summary: &DiagramSummary) -> String {
    let banner = &summary.banner;
    let coverage = &banner.coverage;
    let freshness = &banner.freshness;
    let manifest = &banner.manifest;
    let yes_no = |value: bool| if value { "yes" } else { "no" };
    let joined = |values: &[String]| {
        if values.is_empty() {
            "none".to_owned()
        } else {
            values.join(", ")
        }
    };
    let counted = |value: Option<usize>| match value {
        Some(number) => number.to_string(),
        None => "unknown (no coverage document published)".to_owned(),
    };

    let mut html = String::new();
    html.push_str("<section id=\"axiom-banner\">\n");
    html.push_str("<h2>coverage and freshness</h2>\n");
    html.push_str(&format!(
        "<p id=\"axiom-banner-notice\">{}</p>\n",
        escape_html(&banner.notice)
    ));
    html.push_str("<table id=\"axiom-banner-table\">\n");
    html.push_str("<thead><tr><th>field</th><th>value</th></tr></thead>\n<tbody>\n");
    banner_row(&mut html, "coverage status", &coverage.status);
    banner_row(
        &mut html,
        "coverage document present",
        yes_no(coverage.present),
    );
    banner_row(
        &mut html,
        "coverage complete for profile",
        yes_no(coverage.complete),
    );
    banner_row(
        &mut html,
        "coverage input files",
        &counted(coverage.input_files),
    );
    banner_row(
        &mut html,
        "coverage processed files",
        &counted(coverage.processed_files),
    );
    banner_row(
        &mut html,
        "coverage unresolved references",
        &counted(coverage.unresolved_references),
    );
    banner_row(
        &mut html,
        "coverage unsupported patterns",
        &joined(&coverage.unsupported_patterns),
    );
    banner_row(&mut html, "freshness status", &freshness.status);
    banner_row(
        &mut html,
        "freshness dirty files",
        &freshness.dirty_files.to_string(),
    );
    banner_row(&mut html, "freshness verification", &freshness.verification);
    banner_row(
        &mut html,
        "store published generations",
        &joined(&freshness.latest_published_generations),
    );
    banner_row(
        &mut html,
        "rendered generation ids",
        &joined(&manifest.generation_ids),
    );
    banner_row(&mut html, "manifest shards", &manifest.shards.to_string());
    banner_row(&mut html, "manifest records", &manifest.records.to_string());
    banner_row(
        &mut html,
        "manifest total bytes",
        &manifest.total_bytes.to_string(),
    );
    banner_row(
        &mut html,
        "manifest graph records",
        &manifest.graph_records.to_string(),
    );
    banner_row(
        &mut html,
        "manifest skipped records",
        &manifest.skipped_records.to_string(),
    );
    html.push_str("</tbody>\n</table>\n");

    html.push_str("<h3>unresolved and absent targets</h3>\n");
    html.push_str("<ul id=\"axiom-unresolved\">\n");
    let placeholders: Vec<&DiagramNode> = summary
        .nodes
        .iter()
        .filter(|node| node.placeholder)
        .collect();
    if placeholders.is_empty() {
        html.push_str("<li>none: every drawn edge target resolved to a rendered node</li>\n");
    } else {
        for node in placeholders {
            let reason = node.placeholder_reason.as_deref().unwrap_or("unrecorded");
            let label = node.name.clone().unwrap_or_else(|| node.id.clone());
            html.push_str(&format!(
                "<li><span class=\"hex\">{}</span> {} [{} {}]</li>\n",
                escape_html(&node.id),
                escape_html(&short(&label, 60)),
                escape_html(reason),
                escape_html(&node.kind)
            ));
        }
    }
    html.push_str("</ul>\n</section>\n");
    html
}

/// The placeholder outline dash pattern, distinct from every resolution dash.
const PLACEHOLDER_DASH: &str = "4 3";

/// The deterministic node and edge canvas.
fn render_canvas(summary: &DiagramSummary) -> String {
    let nodes = &summary.nodes;
    let (width, height) = canvas_size(nodes.len());
    let centres: BTreeMap<&str, (i64, i64)> = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.id.as_str(), node_centre(index)))
        .collect();
    let marker_for: BTreeMap<&str, usize> = summary
        .edge_legend
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.kind.as_str(), index))
        .collect();

    let mut html = String::new();
    html.push_str(&format!(
        "<svg class=\"chart\" xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {width} {height}\" width=\"{width}\" height=\"{height}\" role=\"img\">\n"
    ));
    html.push_str(&format!(
        "<title>{} node(s) and {} edge(s) of {}</title>\n",
        nodes.len(),
        summary.edges.len(),
        escape_html(&summary.solution_id)
    ));
    html.push_str("<defs>\n");
    for (index, entry) in summary.edge_legend.iter().enumerate() {
        html.push_str(&format!(
            "<marker id=\"axiom-arrow-{index}\" markerWidth=\"10\" markerHeight=\"8\" refX=\"9\" refY=\"4\" orient=\"auto\" markerUnits=\"userSpaceOnUse\"><polygon points=\"0,0 10,4 0,8\" fill=\"{}\"></polygon></marker>\n",
            escape_html(&entry.color)
        ));
    }
    html.push_str("</defs>\n");

    html.push_str("<g id=\"axiom-edges\">\n");
    for edge in &summary.edges {
        let (Some(source), Some(target)) = (
            centres.get(edge.source_id.as_str()),
            centres.get(edge.target.as_str()),
        ) else {
            continue;
        };
        let ((x1, y1), (x2, y2)) = edge_endpoints(*source, *target);
        let marker = match marker_for.get(edge.kind.as_str()) {
            Some(index) => format!(" marker-end=\"url(#axiom-arrow-{index})\""),
            None => String::new(),
        };
        let hover = format!(
            "{} --{} ({})--> {}",
            edge.source_id, edge.kind, edge.resolution, edge.target
        );
        html.push_str(&format!(
            "<g><title>{}</title><line x1=\"{x1}\" y1=\"{y1}\" x2=\"{x2}\" y2=\"{y2}\" stroke=\"{}\" stroke-width=\"2\"{}{}></line></g>\n",
            escape_html(&hover),
            escape_html(&edge.color),
            dash_attribute(&edge.dash_pattern),
            marker
        ));
    }
    html.push_str("</g>\n");

    if nodes.is_empty() {
        html.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" text-anchor=\"middle\" font-size=\"14\" fill=\"#1b1b1b\">no graph records in the rendered generation(s)</text>\n",
            MARGIN,
            MARGIN + 18
        ));
    }
    html.push_str("<g id=\"axiom-nodes\">\n");
    for (index, node) in nodes.iter().enumerate() {
        let (cx, cy) = node_centre(index);
        let (x, y) = (cx - NODE_WIDTH / 2, cy - NODE_HEIGHT / 2);
        let label = node.name.clone().unwrap_or_else(|| node.id.clone());
        let outline = if node.placeholder {
            dash_attribute(PLACEHOLDER_DASH)
        } else {
            String::new()
        };
        let (label_y, kind_y) = (cy - 2, cy + 16);
        let hover = format!("{} {} {}", node.id, node.kind, node.vocabulary);
        html.push_str(&format!(
            "<g><title>{}</title><rect x=\"{x}\" y=\"{y}\" width=\"{NODE_WIDTH}\" height=\"{NODE_HEIGHT}\" rx=\"6\" fill=\"{}\" stroke=\"#1b1b1b\" stroke-width=\"2\"{outline}></rect><text x=\"{cx}\" y=\"{label_y}\" text-anchor=\"middle\" font-size=\"13\" fill=\"#1b1b1b\">{}</text><text x=\"{cx}\" y=\"{kind_y}\" text-anchor=\"middle\" font-size=\"11\" fill=\"#1b1b1b\">{}</text>",
            escape_html(&hover),
            escape_html(&node.color),
            escape_html(&short(&label, 24)),
            escape_html(&short(&node.kind, 24))
        ));
        if node.placeholder {
            let mark_x = cx + NODE_WIDTH / 2 - 12;
            let mark_y = y + 16;
            html.push_str(&format!(
                "<text x=\"{mark_x}\" y=\"{mark_y}\" text-anchor=\"middle\" font-size=\"16\" fill=\"#1b1b1b\">?</text>"
            ));
        }
        html.push_str("</g>\n");
    }
    html.push_str("</g>\n</svg>\n");
    html
}
/// The node-kind, edge-kind and resolution legends.
fn render_legends(summary: &DiagramSummary) -> String {
    let empty = |values: usize| values == 0;
    let mut html = String::new();
    html.push_str("<div class=\"legend\">\n");

    html.push_str("<h3>node kinds</h3>\n<ul id=\"axiom-legend-nodes\">\n");
    if empty(summary.node_legend.len()) {
        html.push_str("<li>none drawn</li>\n");
    }
    for entry in &summary.node_legend {
        let suffix = if entry.placeholder {
            " (drawn as a dashed placeholder)"
        } else {
            ""
        };
        html.push_str(&format!(
            "<li><span class=\"swatch\" style=\"background:{}\"></span> {} <span class=\"hex\">({})</span>{}</li>\n",
            escape_html(&entry.color),
            escape_html(&entry.kind),
            escape_html(&entry.vocabulary),
            suffix
        ));
    }
    html.push_str("</ul>\n");

    html.push_str("<h3>edge kinds</h3>\n<ul id=\"axiom-legend-edges\">\n");
    if empty(summary.edge_legend.len()) {
        html.push_str("<li>none drawn</li>\n");
    }
    for entry in &summary.edge_legend {
        html.push_str(&format!(
            "<li><span class=\"swatch\" style=\"background:{}\"></span> {} <span class=\"hex\">({})</span></li>\n",
            escape_html(&entry.color),
            escape_html(&entry.kind),
            escape_html(&entry.vocabulary)
        ));
    }
    html.push_str("</ul>\n");

    html.push_str("<h3>resolutions</h3>\n<ul id=\"axiom-legend-resolutions\">\n");
    if empty(summary.resolution_legend.len()) {
        html.push_str("<li>none drawn</li>\n");
    }
    for entry in &summary.resolution_legend {
        let solid = if entry.dash_pattern.is_empty() {
            " (solid)"
        } else {
            ""
        };
        html.push_str(&format!(
            "<li><svg width=\"64\" height=\"12\" role=\"img\"><line x1=\"0\" y1=\"6\" x2=\"64\" y2=\"6\" stroke=\"#1b1b1b\" stroke-width=\"2\"{}></line></svg> <span class=\"hex\">{}</span>{}</li>\n",
            dash_attribute(&entry.dash_pattern),
            escape_html(&entry.resolution),
            solid
        ));
    }
    html.push_str("</ul>\n</div>\n");
    html
}

/// The machine-checkable inventory counts.
fn render_counts(counts: &Counts) -> String {
    let mut html = String::new();
    html.push_str("<table id=\"axiom-counts\">\n");
    html.push_str("<thead><tr><th>field</th><th>value</th></tr></thead>\n<tbody>\n");
    banner_row(&mut html, "nodes", &counts.nodes.to_string());
    banner_row(&mut html, "edges", &counts.edges.to_string());
    banner_row(&mut html, "placeholders", &counts.placeholders.to_string());
    banner_row(
        &mut html,
        "placeholder edges",
        &counts.placeholder_edges.to_string(),
    );
    banner_row(
        &mut html,
        "absent targets",
        &counts.absent_targets.to_string(),
    );
    banner_row(&mut html, "shards", &counts.shards.to_string());
    banner_row(
        &mut html,
        "graph records",
        &counts.graph_records.to_string(),
    );
    banner_row(
        &mut html,
        "skipped records",
        &counts.skipped_records.to_string(),
    );
    banner_row(&mut html, "node kinds", &counts.node_kinds.to_string());
    banner_row(&mut html, "edge kinds", &counts.edge_kinds.to_string());
    banner_row(&mut html, "resolutions", &counts.resolutions.to_string());
    html.push_str("</tbody>\n</table>\n");
    html
}

/// The whole document style sheet. No comments, so nothing in it can read as a
/// path, and no timestamps, so two renders cannot differ.
const STYLE: &str = r#"body{background:#ffffff;color:#1b1b1b;font-family:system-ui,sans-serif;margin:0;padding:24px;}
h1{font-size:20px;margin:0 0 12px 0;}
h2{font-size:16px;margin:24px 0 8px 0;}
h3{font-size:14px;margin:16px 0 6px 0;}
#axiom-banner{border:3px solid #1b1b1b;border-radius:6px;padding:12px 16px;background:#fffbe6;margin-bottom:16px;}
#axiom-banner-notice{font-weight:700;margin:0 0 8px 0;}
table{border-collapse:collapse;font-size:13px;margin:0 0 8px 0;}
th,td{border:1px solid #cccccc;padding:3px 8px;text-align:left;vertical-align:top;}
th{background:#eeeeee;}
ul{margin:4px 0 0 0;padding-left:20px;font-size:13px;}
.swatch{display:inline-block;width:14px;height:14px;border:1px solid #1b1b1b;vertical-align:middle;}
.hex{font-family:monospace;}
.legend{font-size:13px;}
svg.chart{border:1px solid #cccccc;background:#fcfcfc;width:100%;height:auto;}
"#;

/// Render the deterministic, self-contained diagram document.
///
/// The document carries the always-present banner (and the unresolved
/// placeholder list directly beneath it), the node and edge canvas drawn from
/// the frozen kinds and resolutions, the legends that explain the fills, the
/// dashes and the placeholder shape, and the inventory counts. Nothing in it
/// depends on the host, on a clock or on map iteration order, so rendering the
/// same summary twice is byte identical.
fn render_html(summary: &DiagramSummary) -> String {
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    html.push_str("<title>axiom relationship diagram</title>\n<style>\n");
    html.push_str(STYLE);
    html.push_str("</style>\n</head>\n<body>\n");
    html.push_str(&format!(
        "<h1>axiom relationship diagram: {}</h1>\n",
        escape_html(&summary.solution_id)
    ));
    html.push_str(&render_banner(summary));
    html.push_str("<h2>relationship graph</h2>\n");
    html.push_str(&render_canvas(summary));
    html.push_str("<h2>legend</h2>\n");
    html.push_str(&render_legends(summary));
    html.push_str("<h2>inventory</h2>\n");
    html.push_str(&render_counts(&summary.counts));
    html.push_str("</body>\n</html>\n");
    html
}
#[cfg(test)]
mod tests {
    use super::*;
    use graph_core::locks::{default_lock_path, LockMode, SolutionGuard};
    use graph_export::manifest::{self, ManifestEntry};
    use graph_export::pointer::{self, CurrentPointer, PointerStrategy};
    use graph_export::{canonical, reader, GraphRecord};
    use serde_json::{json, Value};
    use std::path::{Path, PathBuf};

    /// One shard a fixture publishes: its path, its bytes, and the record count
    /// the manifest will claim for it. `None` means "count the real records".
    type FixtureShard = (String, Vec<u8>, Option<usize>);

    /// A shard of canonical records, counted the way the publisher counts them.
    fn canonical_shard(relative_path: &str, records: &[GraphRecord]) -> FixtureShard {
        (
            relative_path.to_owned(),
            canonical::canonical_document(records).expect("canonical bytes"),
            None,
        )
    }

    /// A shard whose bytes are not records, plus an explicit record count.
    fn declared_shard(relative_path: &str, bytes: Vec<u8>, record_count: usize) -> FixtureShard {
        (relative_path.to_owned(), bytes, Some(record_count))
    }

    /// A shard whose bytes are not records, counted from its own lines.
    fn raw_shard(relative_path: &str, bytes: Vec<u8>) -> FixtureShard {
        (relative_path.to_owned(), bytes, None)
    }

    fn node(id: &str, kind: &str, name: &str) -> GraphRecord {
        GraphRecord::new(
            id,
            kind,
            json!({
                "id": id,
                "kind": kind,
                "name": name,
                "qualified_name": format!("Demo.{name}"),
            }),
        )
    }

    fn edge(key: &str, kind: &str, source: &str, target: &str, resolution: &str) -> GraphRecord {
        GraphRecord::new(
            key,
            "edge",
            json!({
                "kind": kind,
                "source_id": source,
                "target_id": target,
                "resolution": resolution,
            }),
        )
    }

    fn unresolved_edge(key: &str, source: &str, name: &str) -> GraphRecord {
        GraphRecord::new(
            key,
            "edge",
            json!({
                "kind": "calls",
                "source_id": source,
                "resolution": "unresolved",
                "unresolved_target": name,
            }),
        )
    }

    /// A coverage document, as compact canonical JSON or as a pretty document,
    /// so both branches of `parse_coverage` are exercised.
    fn coverage_bytes(status: &str, pretty: bool) -> Vec<u8> {
        let value = json!({
            "status": status,
            "input_files": 12,
            "processed_files": 9,
            "unresolved_references": 3,
            "unsupported_patterns": ["dynamic", "generics"],
        });
        if pretty {
            let mut bytes = serde_json::to_vec_pretty(&value).expect("coverage json");
            bytes.push(b'\n');
            bytes
        } else {
            canonical::canonical_value(&value)
                .expect("canonical coverage")
                .into_bytes()
        }
    }

    /// Publish a real generation exactly the way the production publisher does:
    /// a content-addressed directory, its `manifest.json`, then the atomic
    /// pointer. The snapshot is then read back through the frozen reader, so no
    /// test ever hand-builds a `Snapshot`.
    fn publish(root: &Path, shards: &[FixtureShard]) -> Snapshot {
        let mut entries = Vec::new();
        for (relative_path, bytes, declared) in shards {
            let count = match declared {
                Some(count) => *count,
                // The publisher counts records as non-empty lines, so the
                // fixture counts them the same way.
                None => String::from_utf8_lossy(bytes)
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .count(),
            };
            entries.push(ManifestEntry::from_bytes(
                relative_path.clone(),
                bytes,
                count,
            ));
        }
        let manifest = manifest::build(entries).expect("manifest");
        let layout = graph_export::staging::StagingLayout::new(root.to_path_buf());
        let generation_dir = layout.generation_dir(&manifest.generation_id);
        std::fs::create_dir_all(&generation_dir).expect("generation directory");
        for (relative_path, bytes, _) in shards {
            let target = generation_dir.join(relative_path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).expect("shard directory");
            }
            std::fs::write(target, bytes).expect("shard bytes");
        }
        std::fs::write(
            generation_dir.join("manifest.json"),
            serde_json::to_vec(&manifest).expect("manifest json"),
        )
        .expect("manifest file");
        pointer::replace(
            root,
            &CurrentPointer::new(manifest.generation_id.clone()),
            PointerStrategy::AtomicReplace,
        )
        .expect("current pointer");
        let guard = SolutionGuard::acquire(&default_lock_path(root), LockMode::Shared)
            .expect("shared reader guard");
        let snapshot = reader::load(root, &guard).expect("frozen reader load");
        guard.release().expect("release guard");
        snapshot
    }

    fn graph(project_id: &str, snapshot: Snapshot) -> ProjectGraph {
        ProjectGraph::new(project_id, snapshot)
    }

    fn fresh(dirty_files: usize, latest: &[&str]) -> FreshnessInput {
        FreshnessInput::new(
            dirty_files,
            latest.iter().map(|value| (*value).to_owned()).collect(),
            VerificationMode::InventoryHash,
        )
    }

    fn render(solution_id: &str, projects: &[ProjectGraph], freshness: &FreshnessInput) -> Diagram {
        build_diagram(solution_id, projects, freshness).expect("diagram")
    }

    fn fixture_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    /// Write a diagram into its own temporary output directory.
    fn write_out(diagram: &Diagram) -> (tempfile::TempDir, PathBuf, RenderReport) {
        let dir = fixture_dir();
        let out = dir.path().join("diagram");
        let report = write_diagram(diagram, &out).expect("write diagram");
        (dir, out, report)
    }
    /// When `AXIOM_H005_EVIDENCE_DIR` is set, write the very artifacts this test
    /// just asserted on into `<dir>/<leg>/`, so a reviewer can open the real
    /// document and hash it instead of taking the assertion on trust. The suite
    /// stays hermetic when the variable is unset, which is the default.
    fn dump_evidence(leg: &str, diagram: &Diagram) {
        let Ok(root) = std::env::var("AXIOM_H005_EVIDENCE_DIR") else {
            return;
        };
        let out = PathBuf::from(root).join(leg);
        let report = write_diagram(diagram, &out).expect("evidence diagram");
        println!("evidence [{leg}] {}", out.display());
        for artifact in &report.artifacts {
            println!(
                "  {} {} bytes sha256={}",
                artifact.name, artifact.bytes, artifact.sha256
            );
        }
    }
    /// Every drawn node and every drawn edge really appears in the document, so
    /// the canvas can never quietly drop one.
    fn canvas_covers(summary: &DiagramSummary, html: &str) -> bool {
        summary.nodes.iter().all(|node| {
            html.contains(&escape_html(&format!(
                "{} {} {}",
                node.id, node.kind, node.vocabulary
            )))
        }) && summary.edges.iter().all(|edge| {
            html.contains(&escape_html(&format!(
                "{} --{} ({})--> {}",
                edge.source_id, edge.kind, edge.resolution, edge.target
            )))
        })
    }

    fn basic_fixture() -> (tempfile::TempDir, Snapshot) {
        let dir = fixture_dir();
        let snapshot = publish(
            dir.path(),
            &[
                canonical_shard(
                    "bucket-000",
                    &[node("n-a", "class", "Alpha"), node("n-b", "Class", "Beta")],
                ),
                canonical_shard("bucket-001", &[node("n-c", "interface", "Gamma")]),
                canonical_shard(
                    "bucket-002",
                    &[edge("e-1", "implements", "n-b", "n-c", "exact_static")],
                ),
                raw_shard(
                    "coverage.json",
                    coverage_bytes("complete_for_profile", false),
                ),
            ],
        );
        (dir, snapshot)
    }

    #[test]
    fn every_named_shard_is_concatenated_and_a_later_shard_edge_resolves() {
        let (_dir, snapshot) = basic_fixture();
        let diagram = render(
            "fixture-solution",
            &[graph("auth-api", snapshot)],
            &fresh(0, &[]),
        );
        let summary = &diagram.summary;
        assert_eq!(summary.counts.shards, 4, "every manifest entry is read");
        assert_eq!(summary.counts.nodes, 3);
        assert_eq!(summary.counts.edges, 1);
        assert_eq!(summary.counts.graph_records, 4);
        assert_eq!(
            summary.counts.skipped_records, 1,
            "coverage.json is accounted, not ignored"
        );
        // The edge lives in a later shard and must still resolve to the node a
        // first shard published, by its canonical frozen kind.
        let drawn = &summary.edges[0];
        assert_eq!(drawn.target, "n-c");
        assert_eq!(drawn.target_kind, TARGET_RESOLVED);
        assert_eq!(drawn.kind, "IMPLEMENTS");
        assert_eq!(drawn.vocabulary, VOCABULARY_FROZEN);
        assert_eq!(drawn.resolution, "exact_static");
        assert_eq!(drawn.dash_pattern, DASH_EXACT_STATIC);
        assert!(canvas_covers(summary, &diagram.result_html));
        assert!(diagram.result_html.contains("<g id=\"axiom-edges\">"));
        assert!(diagram.result_html.contains("<g id=\"axiom-nodes\">"));
        dump_evidence("a-later-shard-edge", &diagram);
    }

    #[test]
    fn a_cross_project_edge_only_in_a_later_shard_is_drawn_to_its_real_node() {
        let (_dir_a, first) = basic_fixture();
        let dir_b = fixture_dir();
        // The second project publishes its nodes first and the cross-project
        // edge last, in a shard of its own.
        let second = publish(
            dir_b.path(),
            &[
                canonical_shard("bucket-000", &[node("n-z", "class", "Zeta")]),
                canonical_shard(
                    "bucket-001",
                    &[edge("e-cross", "calls", "n-z", "n-b", "inferred_static")],
                ),
            ],
        );
        let diagram = render(
            "fixture-solution",
            &[graph("auth-api", first), graph("billing-api", second)],
            &fresh(0, &[]),
        );
        let summary = &diagram.summary;
        assert_eq!(summary.counts.shards, 6);
        assert_eq!(summary.counts.nodes, 4);
        // One in-file edge from the first project, plus the cross-project edge.
        assert_eq!(summary.counts.edges, 2);
        let cross = summary
            .edges
            .iter()
            .find(|item| item.id == "e-cross")
            .expect("the cross-project edge is drawn");
        assert_eq!(cross.target, "n-b");
        assert_eq!(cross.target_kind, TARGET_RESOLVED);
        assert_eq!(cross.project_id, "billing-api");
        assert_eq!(cross.dash_pattern, DASH_INFERRED_STATIC);
        assert!(canvas_covers(summary, &diagram.result_html));
        dump_evidence("a-cross-project-later-shard-edge", &diagram);
    }

    #[test]
    fn an_unresolved_edge_is_a_placeholder_next_to_its_banner() {
        let dir = fixture_dir();
        let snapshot = publish(
            dir.path(),
            &[
                canonical_shard("bucket-000", &[node("n-a", "class", "Alpha")]),
                canonical_shard(
                    "bucket-001",
                    &[unresolved_edge("e-u", "n-a", "Demo.Missing.Target")],
                ),
            ],
        );
        let diagram = render(
            "fixture-solution",
            &[graph("auth-api", snapshot)],
            &fresh(0, &[]),
        );
        let summary = &diagram.summary;
        assert_eq!(summary.counts.nodes, 2, "the placeholder is its own node");
        assert_eq!(summary.counts.placeholders, 1);
        assert_eq!(summary.counts.placeholder_edges, 1);
        assert_eq!(summary.unresolved_targets.len(), 1);
        let placeholder = summary.unresolved_targets[0].clone();
        assert!(placeholder.starts_with("unresolved:"));
        let drawn = summary
            .nodes
            .iter()
            .find(|item| item.id == placeholder)
            .expect("the placeholder node");
        assert_eq!(drawn.kind, KIND_UNRESOLVED_TARGET);
        assert!(drawn.placeholder);
        assert_eq!(
            drawn.placeholder_reason.as_deref(),
            Some(PLACEHOLDER_UNRESOLVED)
        );
        assert_eq!(drawn.name.as_deref(), Some("Demo.Missing.Target"));
        // The unresolved name is never drawn as a resolved node.
        assert!(!summary
            .nodes
            .iter()
            .any(|item| item.name.as_deref() == Some("Demo.Missing.Target") && !item.placeholder));
        assert_eq!(summary.edges[0].target, placeholder);
        assert_eq!(summary.edges[0].target_kind, TARGET_PLACEHOLDER);
        assert_eq!(
            summary.edges[0].unresolved_target.as_deref(),
            Some("Demo.Missing.Target")
        );
        assert_eq!(summary.edges[0].dash_pattern, DASH_UNRESOLVED);
        assert!(canvas_covers(summary, &diagram.result_html));
        assert!(diagram.result_html.contains("<ul id=\"axiom-unresolved\">"));
        assert!(diagram.result_html.contains("Demo.Missing.Target"));
        assert!(diagram.result_html.contains("unresolved-target"));
        dump_evidence("b-unresolved-placeholder", &diagram);
    }

    #[test]
    fn an_edge_to_an_absent_id_is_a_placeholder_rather_than_a_missing_line() {
        let dir = fixture_dir();
        let snapshot = publish(
            dir.path(),
            &[canonical_shard(
                "bucket-000",
                &[
                    node("n-a", "class", "Alpha"),
                    edge("e-1", "references", "n-a", "n-ghost", "exact_static"),
                ],
            )],
        );
        let diagram = render(
            "fixture-solution",
            &[graph("auth-api", snapshot)],
            &fresh(0, &[]),
        );
        let summary = &diagram.summary;
        assert_eq!(summary.counts.absent_targets, 1);
        assert_eq!(summary.counts.placeholders, 1);
        assert_eq!(summary.edges[0].target_kind, TARGET_PLACEHOLDER);
        let drawn = summary
            .nodes
            .iter()
            .find(|item| item.id == summary.edges[0].target)
            .expect("the absent target is drawn");
        assert_eq!(
            drawn.placeholder_reason.as_deref(),
            Some(PLACEHOLDER_ABSENT)
        );
        assert_eq!(drawn.name.as_deref(), Some("n-ghost"));
        assert!(canvas_covers(summary, &diagram.result_html));
    }

    #[test]
    fn an_edge_from_an_absent_source_is_still_drawn() {
        let dir = fixture_dir();
        let snapshot = publish(
            dir.path(),
            &[canonical_shard(
                "bucket-000",
                &[
                    node("n-a", "class", "Alpha"),
                    edge("e-1", "calls", "n-ghost", "n-a", "exact_static"),
                ],
            )],
        );
        let diagram = render(
            "fixture-solution",
            &[graph("auth-api", snapshot)],
            &fresh(0, &[]),
        );
        let summary = &diagram.summary;
        assert_eq!(summary.counts.edges, 1, "the edge is never dropped");
        assert_eq!(summary.counts.absent_targets, 1);
        assert!(summary.edges[0].source_id.starts_with("unresolved:"));
        let drawn = summary
            .nodes
            .iter()
            .find(|item| item.id == summary.edges[0].source_id)
            .expect("the absent source is drawn");
        assert_eq!(
            drawn.placeholder_reason.as_deref(),
            Some(PLACEHOLDER_SOURCE_ABSENT)
        );
        assert!(canvas_covers(summary, &diagram.result_html));
    }

    #[test]
    fn two_renders_of_the_same_generation_are_byte_identical() {
        let (_dir, snapshot) = basic_fixture();
        let projects = [graph("auth-api", snapshot)];
        let freshness = fresh(1, &[]);
        let first = render("fixture-solution", &projects, &freshness);
        let second = render("fixture-solution", &projects, &freshness);
        assert_eq!(first.summary, second.summary);
        assert_eq!(first.result_html, second.result_html);
        assert_eq!(
            summary_json_bytes(&first.summary).expect("summary"),
            summary_json_bytes(&second.summary).expect("summary")
        );

        let (_dir_a, out_a, report_a) = write_out(&first);
        let (_dir_b, out_b, report_b) = write_out(&second);
        assert_eq!(report_a, report_b);
        assert_eq!(report_a.artifacts.len(), 2);
        assert_eq!(report_a.artifacts[0].name, RESULT_HTML);
        assert_eq!(report_a.artifacts[1].name, SUMMARY_JSON);
        assert_ne!(report_a.artifacts[0].sha256, report_a.artifacts[1].sha256);
        for name in [RESULT_HTML, SUMMARY_JSON] {
            assert_eq!(
                std::fs::read(out_a.join(name)).expect("first bytes"),
                std::fs::read(out_b.join(name)).expect("second bytes"),
                "{name} differs between two renders of one generation"
            );
        }
    }

    #[test]
    fn the_emitted_artifacts_carry_no_machine_local_absolute_path() {
        let (dir, snapshot) = basic_fixture();
        let diagram = render(
            "fixture-solution",
            &[graph("auth-api", snapshot)],
            &fresh(0, &[]),
        );
        let (_out_dir, out, _report) = write_out(&diagram);
        let html = std::fs::read_to_string(out.join(RESULT_HTML)).expect("html");
        let summary = std::fs::read_to_string(out.join(SUMMARY_JSON)).expect("summary");
        let host = dir.path().to_string_lossy().into_owned();
        assert!(!html.contains(&host), "the document leaked a host path");
        assert!(!summary.contains(&host), "the summary leaked a host path");
        assert_no_absolute_path(RESULT_HTML, &html).expect("document is path free");
        assert_no_absolute_path(SUMMARY_JSON, &summary).expect("summary is path free");

        let secret = dir.path().join("secret.rs").display().to_string();
        // Markup-wrapped, so the path is not separated from its markup by a
        // space: the check has to split on the markup itself to catch it.
        let error = assert_no_absolute_path(RESULT_HTML, &format!("<p>{secret}</p>"))
            .expect_err("a host path wrapped in markup must be refused");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_ABSOLUTE_PATH)
        );
        assert!(!error.message().contains("secret.rs"));
        assert!(error
            .details()
            .values()
            .all(|value| !value.contains("secret.rs")));
        assert_eq!(error.dropped_details(), 0, "the context must survive");
        assert!(error
            .details()
            .get("observed")
            .is_some_and(|value| value.starts_with("result.html token_bytes=")));
    }
    #[test]
    fn a_canonical_coverage_document_keeps_the_banner_honest() {
        let (_dir, snapshot) = basic_fixture();
        let diagram = render(
            "fixture-solution",
            &[graph("auth-api", snapshot)],
            &fresh(0, &[]),
        );
        let banner = &diagram.summary.banner;
        assert_eq!(banner.coverage.status, COVERAGE_COMPLETE);
        assert!(banner.coverage.present);
        assert!(banner.coverage.complete);
        assert_eq!(banner.coverage.input_files, Some(12));
        assert_eq!(banner.coverage.processed_files, Some(9));
        assert_eq!(banner.coverage.unresolved_references, Some(3));
        assert_eq!(
            banner.coverage.unsupported_patterns,
            vec!["dynamic".to_owned(), "generics".to_owned()]
        );
        assert_eq!(banner.freshness.status, FRESHNESS_FRESH);
        assert_eq!(banner.freshness.verification, VERIFICATION_INVENTORY_HASH);
        assert_eq!(banner.manifest.shards, 4);
        assert!(banner.notice.contains("coverage is complete_for_profile"));
        let html = &diagram.result_html;
        assert!(html.contains("id=\"axiom-banner\""));
        assert!(html.contains("id=\"axiom-banner-notice\""));
        assert!(html.contains("id=\"axiom-banner-table\""));
        assert!(html.contains("coverage complete for profile"));
        assert!(html.contains("freshness status"));
    }

    #[test]
    fn a_pretty_printed_coverage_document_is_read_from_its_bytes() {
        let dir = fixture_dir();
        let snapshot = publish(
            dir.path(),
            &[
                canonical_shard("bucket-000", &[node("n-a", "class", "Alpha")]),
                raw_shard("coverage.json", coverage_bytes("partial", true)),
            ],
        );
        let diagram = render(
            "fixture-solution",
            &[graph("auth-api", snapshot)],
            &fresh(0, &[]),
        );
        let banner = &diagram.summary.banner;
        assert_eq!(banner.coverage.status, COVERAGE_PARTIAL);
        assert!(banner.coverage.present);
        assert!(!banner.coverage.complete);
        assert!(banner
            .notice
            .contains("not evidence that the solution is fully analysed"));
        assert!(diagram.result_html.contains("partial"));
    }

    #[test]
    fn a_generation_without_a_coverage_document_is_unknown_and_never_complete() {
        let dir = fixture_dir();
        let snapshot = publish(
            dir.path(),
            &[canonical_shard(
                "bucket-000",
                &[node("n-a", "class", "Alpha")],
            )],
        );
        let diagram = render(
            "fixture-solution",
            &[graph("auth-api", snapshot)],
            &FreshnessInput::new(0, Vec::new(), VerificationMode::None),
        );
        let banner = &diagram.summary.banner;
        assert_eq!(banner.coverage.status, COVERAGE_UNKNOWN);
        assert!(!banner.coverage.present);
        assert!(!banner.coverage.complete);
        assert_eq!(banner.coverage.input_files, None);
        assert_eq!(banner.coverage.processed_files, None);
        assert_eq!(banner.coverage.unresolved_references, None);
        assert_eq!(banner.freshness.status, FRESHNESS_UNKNOWN);
        assert_eq!(banner.freshness.verification, VERIFICATION_NONE);
        assert!(banner.notice.contains("coverage is unknown"));
        assert!(banner.notice.contains("freshness is unknown"));
        assert!(diagram
            .result_html
            .contains("unknown (no coverage document published)"));
    }

    #[test]
    fn a_stale_generation_is_reported_stale_rather_than_fresh() {
        let (_dir, snapshot) = basic_fixture();
        let diagram = render(
            "fixture-solution",
            &[graph("auth-api", snapshot)],
            &fresh(
                2,
                &["588e49d71bfaf39403268c3f3a3cf8dd97e428eab0d8401d165de86d2d21ee53"],
            ),
        );
        let banner = &diagram.summary.banner;
        assert_eq!(banner.freshness.status, FRESHNESS_STALE);
        assert_eq!(banner.freshness.dirty_files, 2);
        assert_eq!(banner.freshness.latest_published_generations.len(), 1);
        assert!(banner.notice.contains("freshness is stale"));
    }

    #[test]
    fn a_manifest_that_disagrees_with_a_shard_is_a_failure() {
        let dir = fixture_dir();
        // The shard really holds one record; the manifest claims five.
        let bytes = canonical::canonical_document(&[node("n-a", "class", "Alpha")]).expect("bytes");
        let snapshot = publish(dir.path(), &[declared_shard("bucket-000", bytes, 5)]);
        let error = build_diagram(
            "fixture-solution",
            &[graph("auth-api", snapshot)],
            &fresh(0, &[]),
        )
        .expect_err("a shard that disagrees with the manifest must fail the render");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_MANIFEST_DISAGREES)
        );
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(
            error.details().get("expected").map(String::as_str),
            Some("5")
        );
        assert_eq!(error.details().get("actual").map(String::as_str), Some("1"));
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("bucket-000")
        );
        assert_eq!(error.dropped_details(), 0, "the context must survive");
    }

    #[test]
    fn a_generation_with_no_records_still_carries_its_banner() {
        let dir = fixture_dir();
        let snapshot = publish(dir.path(), &[]);
        let diagram = render(
            "fixture-solution",
            &[graph("auth-api", snapshot)],
            &fresh(0, &[]),
        );
        assert_eq!(diagram.summary.counts.nodes, 0);
        assert_eq!(diagram.summary.counts.edges, 0);
        assert_eq!(diagram.summary.counts.shards, 0);
        assert_eq!(diagram.summary.banner.manifest.records, 0);
        assert!(diagram.result_html.contains("id=\"axiom-banner\""));
        assert!(diagram
            .result_html
            .contains("no graph records in the rendered generation(s)"));
        assert!(diagram.result_html.contains("<li>none drawn</li>"));
    }

    #[test]
    fn the_frozen_kinds_are_drawn_distinctly_and_an_unknown_kind_is_an_extension() {
        let (_dir, snapshot) = basic_fixture();
        let dir = fixture_dir();
        let extended = publish(
            dir.path(),
            &[
                canonical_shard("bucket-000", &[node("n-a", "class", "Alpha")]),
                canonical_shard("bucket-001", &[node("n-x", "wibble", "Weird")]),
                canonical_shard(
                    "bucket-002",
                    &[
                        edge("e-1", "calls", "n-a", "n-x", "exact_static"),
                        edge("e-2", "depends_on", "n-x", "n-a", "annotated"),
                    ],
                ),
            ],
        );
        let diagram = render(
            "fixture-solution",
            &[graph("auth-api", snapshot), graph("billing-api", extended)],
            &fresh(0, &[]),
        );
        let summary = &diagram.summary;
        let colour = |kind: &str| {
            summary
                .node_legend
                .iter()
                .find(|entry| entry.kind == kind)
                .map(|entry| entry.color.clone())
                .expect("legend entry")
        };
        assert_eq!(summary.counts.node_kinds, 3);
        assert_ne!(colour("Class"), colour("Interface"));
        assert_ne!(colour("Class"), colour("wibble"));
        let wibble = summary
            .node_legend
            .iter()
            .find(|entry| entry.kind == "wibble")
            .expect("extension entry");
        assert_eq!(wibble.vocabulary, VOCABULARY_EXTENSION);
        let class = summary
            .node_legend
            .iter()
            .find(|entry| entry.kind == "Class")
            .expect("frozen entry");
        assert_eq!(class.vocabulary, VOCABULARY_FROZEN);
        assert!(!class.placeholder);
        let edge_colour = |kind: &str| {
            summary
                .edge_legend
                .iter()
                .find(|entry| entry.kind == kind)
                .map(|entry| entry.color.clone())
                .expect("edge legend entry")
        };
        assert_eq!(summary.counts.edge_kinds, 3);
        let edge_colours = [
            edge_colour("CALLS"),
            edge_colour("DEPENDS_ON"),
            edge_colour("IMPLEMENTS"),
        ];
        assert!(edge_colours.iter().all(|colour| !colour.is_empty()));
        for (index, left) in edge_colours.iter().enumerate() {
            for right in edge_colours.iter().skip(index + 1) {
                assert_ne!(left, right, "two edge kinds share a fill");
            }
        }
        // One arrow marker per distinct edge kind, so the kinds read apart.
        assert!(diagram.result_html.contains("id=\"axiom-arrow-0\""));
        assert!(diagram.result_html.contains("id=\"axiom-arrow-1\""));
        assert!(diagram.result_html.contains("id=\"axiom-arrow-2\""));
        assert!(canvas_covers(summary, &diagram.result_html));
    }

    #[test]
    fn every_resolution_is_visually_distinguishable() {
        let dir = fixture_dir();
        let snapshot = publish(
            dir.path(),
            &[
                canonical_shard(
                    "bucket-000",
                    &[node("n-a", "class", "Alpha"), node("n-b", "class", "Beta")],
                ),
                canonical_shard(
                    "bucket-001",
                    &[
                        edge("e-exact", "calls", "n-a", "n-b", "exact_static"),
                        edge("e-inferred", "calls", "n-a", "n-b", "inferred_static"),
                        edge("e-annotated", "calls", "n-a", "n-b", "annotated"),
                        unresolved_edge("e-unresolved", "n-a", "Demo.Missing"),
                    ],
                ),
            ],
        );
        let diagram = render(
            "fixture-solution",
            &[graph("auth-api", snapshot)],
            &fresh(0, &[]),
        );
        let summary = &diagram.summary;
        assert_eq!(summary.counts.edges, 4);
        assert_eq!(summary.counts.resolutions, 4);
        assert_eq!(summary.resolution_legend.len(), 4);
        let patterns: Vec<&str> = summary
            .resolution_legend
            .iter()
            .map(|entry| entry.dash_pattern.as_str())
            .collect();
        assert_eq!(patterns, vec!["", "6 3", "2 2", "8 3 2 3"]);
        for (index, left) in patterns.iter().enumerate() {
            for right in patterns.iter().skip(index + 1) {
                assert_ne!(left, right, "two resolutions share a dash pattern");
            }
        }
        assert!(diagram
            .result_html
            .contains("id=\"axiom-legend-resolutions\""));
        assert!(diagram.result_html.contains("(solid)"));
        assert!(canvas_covers(summary, &diagram.result_html));
        dump_evidence("c-determinism", &diagram);
    }

    #[test]
    fn a_resolution_outside_the_frozen_vocabulary_is_drawn_as_unknown() {
        let dir = fixture_dir();
        let snapshot = publish(
            dir.path(),
            &[canonical_shard(
                "bucket-000",
                &[
                    node("n-a", "class", "Alpha"),
                    edge("e-1", "calls", "n-a", "n-a2", "guessed"),
                ],
            )],
        );
        let diagram = render(
            "fixture-solution",
            &[graph("auth-api", snapshot)],
            &fresh(0, &[]),
        );
        let summary = &diagram.summary;
        assert_eq!(summary.edges[0].resolution, RESOLUTION_UNKNOWN);
        assert_eq!(summary.edges[0].dash_pattern, DASH_UNKNOWN);
        assert_eq!(summary.resolution_legend.len(), 1);
        assert_eq!(summary.resolution_legend[0].resolution, RESOLUTION_UNKNOWN);
    }

    #[test]
    fn the_summary_is_json_and_mirrors_the_document_inventory() {
        let (_dir, snapshot) = basic_fixture();
        let diagram = render(
            "fixture-solution",
            &[graph("auth-api", snapshot)],
            &fresh(1, &[]),
        );
        let bytes = summary_json_bytes(&diagram.summary).expect("summary bytes");
        assert_eq!(bytes.last(), Some(&b'\n'));
        let value: Value = serde_json::from_slice(&bytes).expect("the summary is JSON");
        assert_eq!(
            value["schema_version"].as_u64(),
            Some(u64::from(SCHEMA_VERSION))
        );
        assert_eq!(value["solution_id"], json!("fixture-solution"));
        assert_eq!(
            value["counts"]["nodes"].as_u64(),
            Some(diagram.summary.counts.nodes as u64)
        );
        assert_eq!(
            value["counts"]["edges"].as_u64(),
            Some(diagram.summary.counts.edges as u64)
        );
        assert_eq!(
            value["nodes"].as_array().map(Vec::len),
            Some(diagram.summary.nodes.len())
        );
        assert_eq!(
            value["edges"].as_array().map(Vec::len),
            Some(diagram.summary.edges.len())
        );
        assert_eq!(value["edges"][0]["id"], json!(diagram.summary.edges[0].id));
        assert_eq!(
            value["banner"]["coverage"]["status"],
            json!(COVERAGE_COMPLETE)
        );
        assert_eq!(
            value["banner"]["freshness"]["status"],
            json!(FRESHNESS_STALE)
        );
        assert_eq!(value["banner"]["manifest"]["shards"].as_u64(), Some(4));
        assert_eq!(
            value["banner"]["manifest"]["generation_ids"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn a_diagram_needs_at_least_one_published_project() {
        let error = build_diagram("fixture-solution", &[], &fresh(0, &[]))
            .expect_err("an empty project list is not a diagram");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_NO_PROJECT)
        );
    }

    #[test]
    fn the_derived_ids_and_the_frozen_vocabularies_are_stable() {
        assert_eq!(
            placeholder_id("Demo.Missing.Target"),
            placeholder_id("Demo.Missing.Target")
        );
        assert_ne!(placeholder_id("a"), placeholder_id("b"));
        assert_eq!(placeholder_id("a").len(), "unresolved:".len() + 16);
        assert_eq!(canonical_kind("class", &NODE_KINDS).0, "Class");
        assert_eq!(canonical_kind("class", &NODE_KINDS).1, VOCABULARY_FROZEN);
        assert_eq!(canonical_kind("wibble", &NODE_KINDS).0, "wibble");
        assert_eq!(
            canonical_kind("wibble", &NODE_KINDS).1,
            VOCABULARY_EXTENSION
        );
        assert_eq!(canonical_kind("", &NODE_KINDS).0, KIND_UNKNOWN);
        assert_eq!(canonical_resolution("EXACT_STATIC"), "exact_static");
        assert_eq!(canonical_resolution("guessed"), RESOLUTION_UNKNOWN);
        assert_eq!(dash_pattern("exact_static"), DASH_EXACT_STATIC);
        assert_eq!(dash_pattern("guessed"), DASH_UNKNOWN);
        assert_eq!(short("abcd", 4), "abcd");
        assert_eq!(short("abcdefghij", 4), "abc\u{2026}");
        assert_eq!(escape_html("<a & \"b\">"), "&lt;a &amp; &quot;b&quot;&gt;");
        assert_eq!(escape_html("it's"), "it&#39;s");
    }
}
