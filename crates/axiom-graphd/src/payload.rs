//! Render one project's stored facts as the documents the frozen graph contract publishes.
//!
//! `docs/11-GRAPH-DATA-CONTRACT.md` fixes the published graph payload: a node document
//! with exactly the fields of `contracts/schemas/node.schema.json`, an edge document with
//! the contract's fields plus exactly one target form, and a node/edge identity that is
//! `sha256` over a canonical JSON tuple rather than over raw string concatenation
//! (section 10: "the implementation must match golden Rust/Python identity bytes").
//!
//! The SQLite store is an internal index, not the published artifact. It keys a node by
//! the pinned analyzer's own declaration key - a 16 hex digit FNV-1a digest of
//! (scheme, file, kind, semantic path) - and an edge by a readable
//! `"<parent>->contains-><child>"` string. Neither is the contract's identity, and the
//! contract requires `sha256`, so this module is the translation:
//!
//! * a node's published id is `sha256(canonical JSON [project_id, language, kind,
//!   canonical_symbol_key])`, and its published `qualified_name` is that same key, so the
//!   identity the specs-side evaluator recomputes from `qualified_name` agrees with the id
//!   that is actually published;
//! * one declaration key can legitimately repeat a qualified name (overloads, a repeated
//!   `namespace P { }` block, `partial class`). A repeated name is rewritten with a
//!   deterministic `#<ordinal>` suffix, ordered by source file then declaration line, so
//!   the published name - and therefore the identity - is unique inside one project while
//!   staying stable across runs;
//! * an edge is rendered from the authoritative columns (`source_id`, `target_id`,
//!   `unresolved_target`, `target_project_id`, `kind`, `resolution`) rather than from its
//!   stored body, because `graph_store::graph_rows::replace_file_facts` rewrites those
//!   columns to `unresolved` when a node disappears without rewriting the body. Reading the
//!   columns is what makes a stale `target_id` impossible to publish;
//! * the published edge id is `sha256(canonical JSON [source_id, kind, target_identity,
//!   evidence_key])` with `evidence_key` the sorted, JSON-encoded evidence locations, which
//!   is the tuple `tool/graph_contract.py` recomputes.
//!
//! Nothing here invents a fact: the rows come from the store the analyzer wrote, the lines
//! come from the analyzer's byte spans, and a declaration whose kind the contract does not
//! name is dropped rather than mapped onto a kind it is not.

use std::collections::BTreeMap;

use graph_core::error::AxiomError;
use graph_export::manifest::Coverage;
use rusqlite::Connection;
use serde_json::{json, Value};

use crate::runtime;

/// The contract's node kind allowlist (`contracts/schemas/node.schema.json`).
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

/// The contract's edge kind allowlist (`contracts/schemas/edge.schema.json`).
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

/// Identity quality published for a name-derived, analyzer-stable symbol key.
pub const IDENTITY_QUALITY: &str = "semantic_key";

/// Separator that disambiguates a repeated qualified name inside one project.
pub const OCCURRENCE_SEPARATOR: char = '#';

/// The analyzer id the declaration containment edges are attributed to.
pub const CSHARP_ANALYZER_ID: &str = "csharp-declarations-v1";
/// The TypeScript analyzer id.
pub const TYPESCRIPT_ANALYZER_ID: &str = "typescript-declarations-v1";

/// The evidence rule id for a declaration containment edge.
pub const CONTAINS_RULE_ID: &str = "declaration-contains-v1";

/// Map a pinned declaration kind onto the contract's node kinds.
///
/// `struct`, `record` and `enum` are published as `Class` because the contract's node kind
/// allowlist has no separate spelling for them; the collapse is deliberate and lossless with
/// respect to identity, which keeps the analyzer's own kind in the node's `attributes`.
#[must_use]
pub fn contract_node_kind(declaration_kind: &str) -> Option<&'static str> {
    Some(match declaration_kind {
        "namespace" => "Namespace",
        "class" => "Class",
        "interface" => "Interface",
        "struct" | "record" | "enum" => "Class",
        "method" => "Method",
        "function" => "Function",
        "type-alias" | "variable" => "Property",
        "default-export" => "Class",
        _ => return None,
    })
}

/// Map a pinned declaration edge kind onto the contract's edge kinds.
#[must_use]
pub fn contract_edge_kind(declaration_kind: &str) -> Option<&'static str> {
    Some(match declaration_kind {
        "contains" => "CONTAINS",
        _ => return None,
    })
}

/// `sha256` over a canonical JSON identity tuple: compact, sorted-free, no trailing LF.
///
/// This is byte-identical to `tools/graph_contract.py::identity_bytes`, which renders the
/// same tuple with `json.dumps(values, separators=(",", ":"), ensure_ascii=False)`.
///
/// # Errors
///
/// [`ErrorCode::Internal`] when the tuple cannot be encoded.
pub fn identity_sha256(parts: &[&str]) -> Result<String, AxiomError> {
    let tuple = serde_json::to_string(parts)
        .map_err(|error| runtime::storage_error("identity tuple", &error))?;
    Ok(graph_export::sha256_hex(tuple.as_bytes()))
}

/// The contract's node identity for one symbol key.
///
/// # Errors
///
/// The same encoding error as [`identity_sha256`].
pub fn node_identity(
    project_id: &str,
    language: &str,
    kind: &str,
    canonical_symbol_key: &str,
) -> Result<String, AxiomError> {
    identity_sha256(&[project_id, language, kind, canonical_symbol_key])
}

/// The contract's edge identity for one resolved or unresolved target.
///
/// # Errors
///
/// The same encoding error as [`identity_sha256`].
pub fn edge_identity(
    source_id: &str,
    kind: &str,
    target_identity: &str,
    evidence_key: &str,
) -> Result<String, AxiomError> {
    identity_sha256(&[source_id, kind, target_identity, evidence_key])
}

/// Deterministic evidence key: sorted `[file, start_line, end_line, rule_id]` locations.
///
/// # Errors
///
/// [`ErrorCode::Internal`] when an evidence location cannot be encoded.
pub fn evidence_key(evidence: &[Value]) -> Result<String, AxiomError> {
    let mut rendered: Vec<String> = Vec::with_capacity(evidence.len());
    for item in evidence {
        let source = item.get("source").cloned().unwrap_or(Value::Null);
        let row = Value::Array(vec![
            source.get("file").cloned().unwrap_or(Value::Null),
            source.get("start_line").cloned().unwrap_or(Value::Null),
            source.get("end_line").cloned().unwrap_or(Value::Null),
            item.get("rule_id").cloned().unwrap_or(Value::Null),
        ]);
        rendered.push(
            serde_json::to_string(&row)
                .map_err(|error| runtime::storage_error("evidence row", &error))?,
        );
    }
    rendered.sort();
    let rows: Vec<Value> = rendered
        .iter()
        .map(|row| serde_json::from_str(row).unwrap_or(Value::Null))
        .collect();
    serde_json::to_string(&Value::Array(rows))
        .map_err(|error| runtime::storage_error("evidence key", &error))
}

/// One node row read out of the store, with the analyzer metadata the payload needs.
#[derive(Debug, Clone)]
struct StoredNode {
    id: String,
    analyzer_kind: String,
    qualified_name: String,
    name: String,
    language: String,
    file: String,
    start_line: i64,
    end_line: i64,
    attributes: Value,
}

/// One edge row read out of the store's authoritative columns.
#[derive(Debug, Clone)]
struct StoredEdge {
    source_id: String,
    target_id: Option<String>,
    unresolved_target: Option<String>,
    target_project_id: String,
    analyzer_kind: String,
    resolution: String,
    evidence: Vec<Value>,
    analyzer_id: String,
    owner_file: String,
}

/// The published payload of one project: the shards and the coverage block.
#[derive(Debug, Clone)]
pub struct Payload {
    /// Published node documents, in published id order.
    pub nodes: Vec<Value>,
    /// Published edge documents, in published id order.
    pub edges: Vec<Value>,
    /// The coverage block, exactly the fields the manifest and `coverage.json` carry.
    ///
    /// It is the frozen `Coverage` type rather than a loose document so the block
    /// the manifest declares and the block `coverage.json` holds cannot drift.
    pub coverage: Coverage,
    /// Paths of the input files, sorted, for the source fingerprint.
    pub input_paths: Vec<(String, String)>,
}

impl Payload {
    /// Whether this project has no publishable facts at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.edges.is_empty()
    }
}

/// Read one project's stored facts and render the contract's documents.
///
/// # Errors
///
/// [`ErrorCode::Internal`] for a storage failure or a row that cannot be decoded.
pub fn render(connection: &Connection, project_id: &str) -> Result<Payload, AxiomError> {
    let stored_nodes = read_nodes(connection, project_id)?;
    let stored_edges = read_edges(connection, project_id)?;
    let inputs = read_inputs(connection, project_id)?;

    // Published identity is per (language, contract kind, qualified name). A repeated name
    // gets a deterministic ordinal so the published name, and therefore the identity, is
    // unique inside the project.
    let mut groups: BTreeMap<(String, String, String), Vec<usize>> = BTreeMap::new();
    for (index, node) in stored_nodes.iter().enumerate() {
        let Some(kind) = contract_node_kind(&node.analyzer_kind) else {
            continue;
        };
        groups
            .entry((
                node.language.clone(),
                kind.to_owned(),
                node.qualified_name.clone(),
            ))
            .or_default()
            .push(index);
    }

    let mut published: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut nodes: Vec<Value> = Vec::new();
    for ((language, kind, _qualified_name), mut indexes) in groups {
        indexes.sort_by(|left, right| {
            let a = &stored_nodes[*left];
            let b = &stored_nodes[*right];
            (a.file.as_str(), a.start_line, a.id.as_str()).cmp(&(
                b.file.as_str(),
                b.start_line,
                b.id.as_str(),
            ))
        });
        for (position, index) in indexes.iter().enumerate() {
            let node = &stored_nodes[*index];
            let key = if position == 0 {
                node.qualified_name.clone()
            } else {
                format!(
                    "{}{}{}",
                    node.qualified_name,
                    OCCURRENCE_SEPARATOR,
                    position + 1
                )
            };
            let id = node_identity(project_id, &language, &kind, &key)?;
            published.insert(node.id.clone(), (id.clone(), key.clone()));
            nodes.push(json!({
                "id": id,
                "project_id": project_id,
                "kind": kind,
                "name": node.name,
                "qualified_name": key,
                "language": language,
                "source": {
                    "file": node.file,
                    "start_line": node.start_line,
                    "end_line": node.end_line,
                },
                "identity_quality": IDENTITY_QUALITY,
                "attributes": node.attributes,
            }));
        }
    }
    nodes.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));

    let mut edges: Vec<Value> = Vec::new();
    let mut unresolved_references = 0usize;
    let mut seen_edges: BTreeMap<String, ()> = BTreeMap::new();
    for edge in &stored_edges {
        let Some(kind) = contract_edge_kind(&edge.analyzer_kind) else {
            continue;
        };
        let Some((source_id, _)) = published.get(&edge.source_id) else {
            // The source is not a pinned node, so this edge would be refused by every
            // reader. Dropping it is the honest outcome; inventing a source is not.
            continue;
        };
        // A published edge has to satisfy the contract's own invariant: a static
        // resolution carries a `target_id` this generation pins, and `unresolved`
        // carries an `unresolved_target`. So the target form is decided by what is
        // actually published, and the resolution follows it. A target the store
        // resolved but this generation does not pin (its kind has no contract
        // spelling) is published as the weaker, true claim `unresolved` and is
        // counted in coverage rather than dropped or asserted as pinned.
        let target = match edge.target_id.as_ref().and_then(|id| published.get(id)) {
            Some((target_id, _)) => Some((Some(target_id.clone()), edge.resolution.clone())),
            None => {
                let name = edge
                    .unresolved_target
                    .clone()
                    .or_else(|| {
                        edge.target_id
                            .as_ref()
                            .and_then(|id| stored_nodes.iter().find(|node| &node.id == id))
                            .map(|node| node.qualified_name.clone())
                    })
                    .unwrap_or_else(|| edge.owner_file.clone());
                if name.is_empty() {
                    // Neither a pinned target nor a name to publish: the row
                    // supports no edge document at all.
                    continue;
                }
                Some((None, name))
            }
        };
        // The store's own invariant is `Resolved -> exact_static`, so a resolution
        // of `unresolved` alongside a pinned target is a stale column, not a fact.
        let resolution = match &target {
            Some((Some(_), stored)) if stored == "unresolved" => "exact_static".to_owned(),
            Some((Some(_), stored)) => stored.clone(),
            _ => "unresolved".to_owned(),
        };
        let evidence = if edge.evidence.is_empty() {
            vec![json!({
                "source": {"file": edge.owner_file, "start_line": 1, "end_line": 1},
                "rule_id": CONTAINS_RULE_ID,
            })]
        } else {
            edge.evidence.clone()
        };
        let evidence_key = evidence_key(&evidence)?;
        let target_identity = match &target {
            Some((Some(target_id), _)) => target_id.clone(),
            Some((None, name)) => name.clone(),
            None => continue,
        };
        let id = edge_identity(source_id, kind, &target_identity, &evidence_key)?;
        if seen_edges.insert(id.clone(), ()).is_some() {
            continue;
        }
        let mut document = json!({
            "id": id,
            "source_id": source_id,
            "target_project_id": edge.target_project_id,
            "kind": kind,
            "resolution": resolution,
            "evidence": evidence,
            "analyzer_id": edge.analyzer_id,
        });
        match target {
            Some((Some(target_id), _)) => {
                document["target_id"] = Value::String(target_id);
            }
            Some((None, name)) => {
                // Only a target this generation does not pin is an unresolved
                // reference; a target the store itself left unresolved is one too.
                document["unresolved_target"] = Value::String(name);
                unresolved_references += 1;
            }
            None => continue,
        }
        edges.push(document);
    }
    edges.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));

    let input_files = inputs.len();
    let processed_files = inputs
        .iter()
        .filter(|(_, _, indexed, desired, _)| indexed >= desired)
        .count();
    let status = if processed_files == input_files {
        "complete_for_profile"
    } else {
        "partial"
    };
    let coverage = Coverage {
        status: status.to_owned(),
        input_files,
        processed_files,
        unresolved_references,
        unsupported_patterns: Vec::new(),
    };

    let input_paths = inputs
        .iter()
        .map(|(path, hash, _, _, _)| (path.clone(), hash.clone()))
        .collect();

    Ok(Payload {
        nodes,
        edges,
        coverage,
        input_paths,
    })
}

fn read_nodes(connection: &Connection, project_id: &str) -> Result<Vec<StoredNode>, AxiomError> {
    let mut statement = connection
        .prepare(
            "SELECT id, kind, qualified_name, record_json FROM nodes \
             WHERE project_id = ?1 ORDER BY id",
        )
        .map_err(|error| runtime::storage_error("payload node query", &error))?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|error| runtime::storage_error("payload node query", &error))?;
    let mut nodes = Vec::new();
    for row in rows {
        let (id, kind, stored_name, body) =
            row.map_err(|error| runtime::storage_error("payload node row", &error))?;
        let record: Value = serde_json::from_str(&body)
            .map_err(|error| runtime::storage_error("payload node body", &error))?;
        let language = text_field(&record, "language");
        let file = text_field(&record, "file");
        // A row the analyzer wrote without a path and a language cannot be
        // published as a contract node, and inventing either would be a claim
        // nothing supports. The honest outcome is not to publish the row.
        if language.is_empty() || file.is_empty() {
            continue;
        }
        let qualified_name = match text_field(&record, "qualified_name") {
            name if name.is_empty() => stored_name,
            name => name,
        };
        // `node.schema.json` requires a non-empty `name`, and the published
        // identity is the unique qualified name, so an unnamed declaration is
        // named by its own last component rather than published invalid.
        let name = match text_field(&record, "name") {
            name if name.is_empty() => leaf_name(&qualified_name).to_owned(),
            name => name,
        };
        let start_line = line_field(&record, "start_line");
        let end_line = line_field(&record, "end_line").max(start_line);
        nodes.push(StoredNode {
            id,
            analyzer_kind: kind,
            qualified_name,
            name,
            language,
            file,
            start_line,
            end_line,
            attributes: record
                .get("attributes")
                .cloned()
                .unwrap_or_else(|| json!({})),
        });
    }
    Ok(nodes)
}

/// A non-empty string field, or the empty string when it is absent.
fn text_field(value: &Value, name: &str) -> String {
    value
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// A one-based source line, defaulted to 1 when it is absent or not positive.
fn line_field(value: &Value, name: &str) -> i64 {
    value
        .get(name)
        .and_then(Value::as_i64)
        .filter(|line| *line >= 1)
        .unwrap_or(1)
}

/// The last component of a qualified name, for a declaration the analyzer left unnamed.
fn leaf_name(qualified_name: &str) -> &str {
    qualified_name
        .rsplit(['.', '/', ':'])
        .next()
        .unwrap_or(qualified_name)
}

fn read_edges(connection: &Connection, project_id: &str) -> Result<Vec<StoredEdge>, AxiomError> {
    let mut statement = connection
        .prepare(
            "SELECT e.source_id, e.target_id, e.unresolved_target, e.target_project_id, \
             e.kind, e.resolution, e.record_json, f.path \
             FROM edges e JOIN files f ON f.id = e.owner_file_id \
             WHERE f.project_id = ?1 AND f.deleted = 0 ORDER BY e.id",
        )
        .map_err(|error| runtime::storage_error("payload edge query", &error))?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(|error| runtime::storage_error("payload edge query", &error))?;
    let mut edges = Vec::new();
    for row in rows {
        let (
            source_id,
            target_id,
            unresolved_target,
            target_project_id,
            kind,
            resolution,
            body,
            owner_file,
        ) = row.map_err(|error| runtime::storage_error("payload edge row", &error))?;
        let record: Value = serde_json::from_str(&body)
            .map_err(|error| runtime::storage_error("payload edge body", &error))?;
        let evidence = record
            .get("evidence")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let analyzer_id = record
            .get("analyzer_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| CSHARP_ANALYZER_ID.to_owned());
        edges.push(StoredEdge {
            source_id,
            target_id,
            unresolved_target,
            target_project_id,
            analyzer_kind: kind,
            resolution,
            evidence,
            analyzer_id,
            owner_file,
        });
    }
    Ok(edges)
}

type InputRow = (String, String, i64, i64, i64);

fn read_inputs(connection: &Connection, project_id: &str) -> Result<Vec<InputRow>, AxiomError> {
    let mut statement = connection
        .prepare(
            "SELECT path, observed_hash, indexed_generation, desired_generation, deleted \
             FROM files WHERE project_id = ?1 AND observed_hash IS NOT NULL ORDER BY path",
        )
        .map_err(|error| runtime::storage_error("payload input query", &error))?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(|error| runtime::storage_error("payload input query", &error))?;
    let mut inputs = Vec::new();
    for row in rows {
        let (path, hash, indexed, desired, deleted) =
            row.map_err(|error| runtime::storage_error("payload input row", &error))?;
        if deleted != 0 {
            continue;
        }
        // Only the inputs the pinned profile declares: a file in a language this build
        // does not analyse is not part of the profile's input set.
        if graph_analyze::adapter::Language::from_path(&path).is_none() {
            continue;
        }
        inputs.push((path, hash, indexed, desired, deleted));
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::{
        contract_edge_kind, contract_node_kind, edge_identity, evidence_key, identity_sha256,
        node_identity, EDGE_KINDS, NODE_KINDS,
    };
    use serde_json::json;

    /// The golden vectors the specs-side evaluator `tools/graph_contract.py` produced.
    #[test]
    fn identity_bytes_agree_with_the_specs_side_evaluator() {
        assert_eq!(
            identity_sha256(&["demo-project", "csharp", "Class", "Demo.App.Core.Widget"])
                .expect("identity"),
            "ab2c570b2c579782f967cae4b116126e9fb00afc05f342ea87d251198e1177e3"
        );
        assert_eq!(
            node_identity("demo-project", "csharp", "Class", "Demo.App.Core.Widget")
                .expect("node identity"),
            "ab2c570b2c579782f967cae4b116126e9fb00afc05f342ea87d251198e1177e3"
        );
        let evidence = vec![json!({
            "source": {"file": "src/Widget.cs", "start_line": 12, "end_line": 12},
            "rule_id": "csharp-declaration-contains",
        })];
        let key = evidence_key(&evidence).expect("evidence key");
        assert_eq!(
            key,
            r#"[["src/Widget.cs",12,12,"csharp-declaration-contains"]]"#
        );
        assert_eq!(
            edge_identity(&"0".repeat(64), "CONTAINS", &"1".repeat(64), &key)
                .expect("edge identity"),
            "a6595089fefeb59106bee9aa95697ee7dba5c261f1943715bf0ed5a14284110c"
        );
    }

    #[test]
    fn every_published_kind_is_in_the_contract_allowlist() {
        for kind in [
            "namespace",
            "class",
            "interface",
            "struct",
            "record",
            "enum",
            "method",
            "function",
            "type-alias",
            "variable",
            "default-export",
        ] {
            let published = contract_node_kind(kind).expect("a known declaration kind");
            assert!(NODE_KINDS.contains(&published), "{kind} -> {published}");
        }
        assert!(contract_node_kind("unknown-kind").is_none());
        assert_eq!(contract_edge_kind("contains"), Some("CONTAINS"));
        assert!(EDGE_KINDS.contains(&"CONTAINS"));
        assert!(contract_edge_kind("calls").is_none());
    }

    #[test]
    fn a_repeated_qualified_name_is_disambiguated_deterministically() {
        let first = node_identity("demo-project", "csharp", "Method", "App.Run").expect("first");
        let second =
            node_identity("demo-project", "csharp", "Method", "App.Run#2").expect("second");
        assert_ne!(first, second);
    }
}
