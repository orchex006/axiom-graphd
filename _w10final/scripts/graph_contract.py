#!/usr/bin/env python3
"""Offline semantic contract for graph node/edge payloads (Axiom V2, spec 2.0.0-draft.1).

JSON Schema (``contracts/schemas/node.schema.json``, ``contracts/schemas/edge.schema.json``)
can require fields and constrain single values, but it cannot express identity, duplication or
cross-record rules. ``contracts/README.md`` requires exactly those additional semantic checks.
This module is the reference evaluator for the declared graph identity rules in
``docs/11-GRAPH-DATA-CONTRACT.md``:

* ``node_id = sha256(canonical JSON tuple [project_id, language, kind, canonical_symbol_key])``
* ``edge_id = sha256(canonical JSON tuple [source_id, kind, target_identity, evidence_key])``
* an edge carries exactly one target form and that form must agree with ``resolution``
* duplicate node IDs, duplicate edge IDs, ambiguous duplicate target forms and name-only
  cross-project targets are rejected instead of silently merged
* ``source.start_line <= source.end_line``

Identity tuples are canonical compact JSON arrays, not raw string concatenation, so ``a + bc``
and ``ab + c`` cannot collide. The function is pure and stdlib-only: no network, Git, shell,
install or update operation is performed.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

NODE_KINDS = frozenset({
    "Solution", "Project", "File", "Namespace", "Class", "Interface", "Function", "Method",
    "Property", "ApiEndpoint", "DataStore", "Table", "StoredProcedure", "QueueTopic",
    "ExternalService", "TestCase", "UnresolvedTarget",
})
EDGE_KINDS = frozenset({
    "CONTAINS", "IMPORTS", "REFERENCES", "CALLS", "INHERITS", "IMPLEMENTS", "EXPOSES",
    "CALLS_ENDPOINT", "READS", "WRITES", "EXECUTES_PROCEDURE", "DEPENDS_ON", "PUBLISHES",
    "SUBSCRIBES", "TESTS",
})
RESOLUTIONS = frozenset({"exact_static", "inferred_static", "annotated", "unresolved"})
IDENTITY_QUALITIES = frozenset({"semantic_key", "syntax_key", "annotation_key"})
NODE_REQUIRED = ("id", "project_id", "kind", "name", "qualified_name", "language", "source",
                 "identity_quality", "attributes")
EDGE_REQUIRED = ("id", "source_id", "target_project_id", "kind", "resolution", "evidence",
                 "analyzer_id")


def identity_bytes(values):
    """Canonical identity tuple bytes: compact UTF-8 JSON array, never raw concatenation."""
    return json.dumps(list(values), separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def identity_sha256(values):
    return hashlib.sha256(identity_bytes(values)).hexdigest()


def node_identity(project_id, language, kind, canonical_symbol_key):
    return identity_sha256([project_id, language, kind, canonical_symbol_key])


def edge_identity(source_id, kind, target_identity, evidence_key):
    return identity_sha256([source_id, kind, target_identity, evidence_key])


def evidence_key(evidence):
    """Deterministic evidence key: sorted (file, start_line, end_line, rule_id) locations."""
    locations = []
    for item in evidence or []:
        if not isinstance(item, dict):
            locations.append(("<invalid>",))
            continue
        source = item.get("source") if isinstance(item.get("source"), dict) else {}
        locations.append((str(source.get("file")), source.get("start_line"),
                          source.get("end_line"), str(item.get("rule_id"))))
    return json.dumps(sorted(locations, key=lambda row: json.dumps(row, default=str)),
                      separators=(",", ":"), ensure_ascii=False)


def _source_range_reason(owner_id, source):
    if not isinstance(source, dict):
        return "source is not an object: " + str(owner_id)
    start, end = source.get("start_line"), source.get("end_line")
    if isinstance(start, int) and isinstance(end, int) and start > end:
        return "source range inverted (start_line > end_line): " + str(owner_id)
    return None


def _node_reasons(node, seen_ids):
    reasons = []
    if not isinstance(node, dict):
        return ["node is not an object"], None
    for field in NODE_REQUIRED:
        if field not in node:
            reasons.append("node missing required field: " + field)
    node_id = node.get("id")
    if not isinstance(node_id, str) or not node_id:
        reasons.append("node id is not a non-empty string")
        return reasons, None
    if node_id in seen_ids:
        reasons.append("duplicate node ID: " + node_id)
    seen_ids.add(node_id)
    kind = node.get("kind")
    if isinstance(kind, str) and kind not in NODE_KINDS:
        reasons.append("unsupported node kind: " + kind)
    quality = node.get("identity_quality")
    if isinstance(quality, str) and quality not in IDENTITY_QUALITIES:
        reasons.append("unsupported identity_quality: " + quality)
    reason = _source_range_reason(node_id, node.get("source"))
    if reason:
        reasons.append(reason)
    key = node.get("canonical_symbol_key", node.get("qualified_name"))
    if isinstance(key, str) and key and isinstance(node.get("language"), str) \
            and isinstance(node.get("project_id"), str) and isinstance(kind, str):
        expected = node_identity(node["project_id"], node["language"], kind, key)
        if expected != node_id:
            reasons.append("node ID does not match its canonical identity tuple: " + node_id)
    return reasons, node_id


def _edge_reasons(edge, seen_ids):
    reasons = []
    if not isinstance(edge, dict):
        return ["edge is not an object"]
    for field in EDGE_REQUIRED:
        if field not in edge:
            reasons.append("edge missing required field: " + field)
    edge_id = edge.get("id")
    if not isinstance(edge_id, str) or not edge_id:
        reasons.append("edge id is not a non-empty string")
        return reasons
    if edge_id in seen_ids:
        reasons.append("duplicate edge ID: " + edge_id)
    seen_ids.add(edge_id)
    has_target = isinstance(edge.get("target_id"), str) and bool(edge.get("target_id"))
    has_unresolved = isinstance(edge.get("unresolved_target"), str) and bool(edge.get("unresolved_target"))
    if has_target and has_unresolved:
        reasons.append("ambiguous target form: edge has both target_id and unresolved_target: " + edge_id)
    if not has_target and not has_unresolved:
        reasons.append("missing target: edge has neither target_id nor unresolved_target: " + edge_id)
    resolution = edge.get("resolution")
    if isinstance(resolution, str) and resolution not in RESOLUTIONS:
        reasons.append("unsupported resolution: " + resolution)
    if resolution == "unresolved" and not has_unresolved:
        reasons.append("resolution unresolved requires unresolved_target: " + edge_id)
    if isinstance(resolution, str) and resolution != "unresolved" and not has_target:
        reasons.append("resolution " + resolution + " requires target_id: " + edge_id)
    target_project = edge.get("target_project_id")
    if not isinstance(target_project, str) or not target_project:
        reasons.append("name-only edge target is prohibited: target_project_id is required: " + edge_id)
    kind = edge.get("kind")
    if isinstance(kind, str) and kind not in EDGE_KINDS:
        reasons.append("unsupported edge kind: " + kind)
    for item in edge.get("evidence") or []:
        if isinstance(item, dict):
            reason = _source_range_reason(edge_id, item.get("source"))
            if reason:
                reasons.append("evidence " + reason)
    target_identity = edge.get("target_id") if has_target else edge.get("unresolved_target")
    if has_target and has_unresolved:
        target_identity = None
    if isinstance(target_identity, str) and isinstance(kind, str) and isinstance(edge.get("source_id"), str):
        expected = edge_identity(edge["source_id"], kind, target_identity, evidence_key(edge.get("evidence")))
        if expected != edge_id:
            reasons.append("edge ID does not match its canonical identity tuple: " + edge_id)
    return reasons


def graph_reasons(payload):
    """Reference evaluator for one graph payload. Empty list means accept."""
    if not isinstance(payload, dict):
        return ["graph payload is not a JSON object"]
    reasons = []
    nodes, edges = payload.get("nodes"), payload.get("edges")
    if not isinstance(nodes, list):
        reasons.append("graph payload nodes is not a list")
    if not isinstance(edges, list):
        reasons.append("graph payload edges is not a list")
    if reasons:
        return reasons
    seen_node_ids = set()
    for node in nodes:
        reasons.extend(_node_reasons(node, seen_node_ids)[0])
    seen_edge_ids = set()
    for edge in edges:
        reasons.extend(_edge_reasons(edge, seen_edge_ids))
    return reasons


def check_path(path, root=None):
    raw = Path(path).read_text(encoding="utf-8")
    payload = json.loads(raw)
    return {"ok": not graph_reasons(payload), "path": str(path), "reasons": graph_reasons(payload)}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    usage = "usage: python tools/graph_contract.py [--json] <graph-payload.json>"
    if any(a in ("-h", "--help") for a in argv):
        print(usage)
        return 0
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    if len(argv) != 1:
        print(usage)
        return 1
    try:
        result = check_path(argv[0])
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("usage/IO error: " + str(exc), file=sys.stderr)
        return 1
    if as_json:
        print(json.dumps(result, indent=2))
    elif result["ok"]:
        print("accepted: " + result["path"])
    else:
        for reason in result["reasons"]:
            print("rejected: " + reason)
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
