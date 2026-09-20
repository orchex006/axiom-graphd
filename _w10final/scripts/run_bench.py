"""Before/after cost of N relationship questions, both legs measured honestly.

WITHOUT graphd: every source file is read from disk for each question, and the
declaring file is read again to list members. Nothing is cached between
questions, because "no stored graph" means exactly that.

WITH graphd: ONE `serve` built the graph; each question is then a real
`tools/call` for `graph_query` inside a single real MCP stdio session, driven by
mcp_stdio_client.py. The graph-build cost is reported separately and is NOT
hidden inside the per-question number.

Both legs answer the same kind of bounded question (a symbol and its incident
relationships), so the comparison is like-for-like.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser(prog="w10-bench")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--generation-dir", required=True)
    parser.add_argument("--home", required=True)
    parser.add_argument("--mcp-src", required=True)
    parser.add_argument("--host-script", required=True)
    parser.add_argument("--client-script", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--questions", type=int, default=20)
    parser.add_argument("--solution", default="agmws-license")
    parser.add_argument("--project", default="agmws-web-service")
    parser.add_argument("--graph-build-ms", type=float, required=True)
    args = parser.parse_args()

    repo = pathlib.Path(args.repo)
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    nodes = json.loads(
        (pathlib.Path(args.generation_dir) / "nodes/000000.json").read_text(encoding="utf-8")
    )
    symbols = [
        node["qualified_name"]
        for node in nodes
        if node.get("kind") in ("Class", "Interface", "ApiEndpoint")
    ][: args.questions]
    if len(symbols) != args.questions:
        raise SystemExit(f"expected {args.questions} symbols, found {len(symbols)}")

    # --- without graphd ---------------------------------------------------
    def answer_without_graph(qualified_name: str) -> int:
        leaf = qualified_name.rsplit(".", 1)[-1]
        declaring: list[pathlib.Path] = []
        for path in repo.rglob("*.cs"):
            if ".axiom" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                if re.search(rf"\b(class|interface|struct|enum|record)\s+{re.escape(leaf)}\b", line):
                    declaring.append(path)
                    break
        members = 0
        for path in declaring:
            text = path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                stripped = line.strip()
                if re.match(r"(public|internal|protected|private)\s", stripped) and "(" in stripped:
                    members += 1
        return members

    scan_started = time.perf_counter()
    scan_members = [answer_without_graph(symbol) for symbol in symbols]
    scan_ms = round((time.perf_counter() - scan_started) * 1000, 1)

    # --- with graphd, through real MCP ------------------------------------
    calls = {
        "label": "bench-with-graphd",
        "calls": [
            {
                "label": f"bench-{index}",
                "tool": "graph_query",
                "arguments": {
                    "solution_id": args.solution,
                    "operation": "context",
                    "project_id": args.project,
                    "target": symbol,
                },
            }
            for index, symbol in enumerate(symbols)
        ],
    }
    calls_path = out_dir / "bench-calls.json"
    calls_path.write_text(json.dumps(calls, indent=2), encoding="utf-8")

    client_started = time.perf_counter()
    completed = subprocess.run(
        [
            sys.executable,
            args.client_script,
            "--host-script",
            args.host_script,
            "--mcp-src",
            args.mcp_src,
            "--home",
            args.home,
            "--calls",
            str(calls_path),
            "--transcript",
            str(out_dir / "bench-mcp-transcript.txt"),
            "--results",
            str(out_dir / "bench-mcp-results.json"),
            "--pretty-results",
            str(out_dir / "bench-mcp-pretty.txt"),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    session_ms = round((time.perf_counter() - client_started) * 1000, 1)
    (out_dir / "bench-client.stdout").write_text(completed.stdout or "", encoding="utf-8")
    (out_dir / "bench-client.stderr").write_text(completed.stderr or "", encoding="utf-8")
    if completed.returncode != 0:
        raise SystemExit(f"mcp client failed rc={completed.returncode}: {completed.stderr}")

    results = json.loads((out_dir / "bench-mcp-results.json").read_text(encoding="utf-8"))
    per_query = []
    for entry in results["calls"]:
        envelope = entry["response"].get("result", {})
        structured = envelope.get("structuredContent")
        if structured is None and envelope.get("content"):
            try:
                structured = json.loads(envelope["content"][0]["text"])
            except (KeyError, ValueError, TypeError):
                structured = None
        structured = structured or {}
        per_query.append(
            {
                "target": entry["arguments"]["target"],
                "mcp_elapsed_ms": entry["elapsed_ms"],
                "is_error": bool(entry["response"].get("error")),
                "nodes": len(structured.get("nodes", []) or []),
                "edges": len(structured.get("edges", []) or []),
                "catalog_generation_id": structured.get("catalog_generation_id"),
            }
        )

    graphd_ms = round(sum(item["mcp_elapsed_ms"] for item in per_query), 1)

    report = {
        "questions": args.questions,
        "symbols": symbols,
        "without_graphd": {
            "mode": "text-scan-per-question (no stored graph, no caching)",
            "files_per_question": len(list(p for p in repo.rglob('*.cs') if '.axiom' not in p.parts)),
            "total_ms": scan_ms,
            "per_question_ms": round(scan_ms / args.questions, 1),
            "members_found": sum(scan_members),
            "note": (
                "untyped text hits only: no node ids, kinds, edges, resolutions or evidence, and "
                "no answer to 'what depends on this' without scanning the whole tree again"
            ),
        },
        "with_graphd": {
            "mode": "one real MCP stdio session, N tools/call graph_query (warm), shipped data plane",
            "total_ms_of_calls": graphd_ms,
            "per_question_ms": round(graphd_ms / args.questions, 1),
            "whole_session_ms_including_handshake": session_ms,
            "all_ok": all(not item["is_error"] for item in per_query),
            "per_query": per_query,
        },
        "graph_build_cost_ms": args.graph_build_ms,
        "saving": {
            "per_question_ms": round(scan_ms / args.questions - graphd_ms / args.questions, 1),
            "total_ms_over_questions": round(scan_ms - graphd_ms, 1),
            "note": (
                "with_graphd excludes the one-off `serve` (graph_build_cost_ms) that built the "
                "graph; that cost is paid once and amortises over every question after it"
            ),
        },
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
