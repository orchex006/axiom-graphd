#!/usr/bin/env python3
"""Assemble one combined {nodes,edges} payload from a published generation and evaluate it
with the SPECS-SIDE reference evaluator (tools/graph_contract.py, copied verbatim).

Read-only over the generation. Writes only the combined payload into our own evidence dir.
"""
import argparse, importlib.util, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

def load_evaluator():
    spec = importlib.util.spec_from_file_location("graph_contract", HERE / "graph_contract.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--generation", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    gen = Path(a.generation).resolve()
    nodes, edges = [], []
    files = []
    for role, bag in (("nodes", nodes), ("edges", edges)):
        shards = sorted((gen / role).glob("*.json"))
        for sh in shards:
            payload = json.loads(sh.read_text(encoding="utf-8"))
            recs = payload if isinstance(payload, list) else payload.get("records", [])
            bag.extend(recs)
            files.append({"path": f"{role}/{sh.name}", "bytes": sh.stat().st_size, "records": len(recs)})

    combined = {"nodes": nodes, "edges": edges}
    out = Path(a.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(combined, separators=(",", ":")), encoding="utf-8")

    gc = load_evaluator()
    reasons = gc.graph_reasons(combined)
    result = {
        "ok": not reasons,
        "generation_dir": str(gen),
        "nodes_total": len(nodes),
        "edges_total": len(edges),
        "shards": files,
        "reasons": reasons,
        "evaluator": {"module": str(HERE / "graph_contract.py"),
                      "spec_version_note": "Axiom V2 spec 2.0.0-draft.1"},
        "combined_payload": str(out),
    }
    print(json.dumps(result, indent=2))
    return 0 if not reasons else 2

if __name__ == "__main__":
    raise SystemExit(main())
