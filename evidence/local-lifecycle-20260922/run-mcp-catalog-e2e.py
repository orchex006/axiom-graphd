#!/usr/bin/env python3
"""Real macOS local lifecycle: analyzer -> catalog -> MCP -> edit -> drain."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MCP_ROOT = ROOT.parent / "axiom-mcp"
sys.path.insert(0, str(MCP_ROOT / "src"))

from axiom_mcp.registry import load_registry  # noqa: E402
from axiom_mcp.tools.context import GuardedSnapshotSource, ToolContext, ToolPrincipal  # noqa: E402
from axiom_mcp.tools.query import graph_query  # noqa: E402


def catalog_id(path: Path) -> str:
    return json.loads(path.read_text(encoding="utf-8"))["generation_id"]


def wait_for(predicate, process: subprocess.Popen[str], *, seconds: float, what: str):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"serve exited before {what}: {process.returncode}")
        value = predicate()
        if value:
            return value
        time.sleep(0.2)
    raise TimeoutError(f"timed out waiting for {what}")


def query(home: Path, repo: Path, needle: str) -> dict:
    # Keep the MCP reader registry separate from graphd's service config file.
    # Its `axiom_home` still points at the exact guard/bindings state the daemon uses.
    registry_path = home.parent / "mcp-registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "axiom_home": str(home),
                "instances": [{"instance_id": "local-instance"}],
                "solutions": [
                    {
                        "solution_id": "demo-solution",
                        "instance_id": "local-instance",
                        "catalog_host_repo": "demo-repo",
                        "repositories": [
                            {
                                "repo_id": "demo-repo",
                                "repo_root": str(repo),
                                "projects": [{"project_id": "demo-project"}],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    registry = load_registry(registry_path, env={"AXIOM_HOME": str(home)}, platform="darwin")
    context = ToolContext(
        registry=registry,
        principal=ToolPrincipal("local-e2e", frozenset({"read"}), frozenset({"demo-solution"})),
        source=GuardedSnapshotSource(home / "instances" / "local-instance" / "solution.guard"),
    )
    return graph_query(
        {"solution_id": "demo-solution", "operation": "search", "query": needle}, context
    )


def main() -> int:
    binary = ROOT / "target" / "debug" / "axiom-graphd"
    source_fixture = ROOT / "evidence" / "engine-readiness-20260922" / "sqlite-default-wal-e2e-Demo.cs"
    with tempfile.TemporaryDirectory(prefix="axiom-mcp-e2e-") as temporary:
        root = Path(temporary)
        repo, home = root / "repo", root / "home"
        (repo / "src").mkdir(parents=True)
        (home / "config").mkdir(parents=True)
        source = repo / "src" / "Demo.cs"
        shutil.copyfile(source_fixture, source)
        solution = root / "solution.json"
        bindings = home / "config" / "bindings.json"
        solution.write_text(json.dumps({"id":"demo-solution","profile":"default","catalog_host_repo":"demo-repo","projects":[{"id":"demo-project","repo_id":"demo-repo","path":"src"}]}), encoding="utf-8")
        bindings.write_text(json.dumps({"bindings":{"demo-repo":str(repo)}}), encoding="utf-8")
        environment = {**os.environ, "AXIOM_HOME": str(home)}
        registered = subprocess.run([str(binary), "solution", "register", "--config", str(solution), "--apply", "--json"], env=environment, text=True, capture_output=True, check=True)
        serve = subprocess.Popen([str(binary), "serve", "--json"], env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pointer = repo / ".axiom" / "graph" / "demo-solution" / "_catalog" / "live" / "current.json"
        try:
            first = wait_for(lambda: catalog_id(pointer) if pointer.is_file() else None, serve, seconds=15, what="initial catalog")
            before = query(home, repo, "Demo")
            assert any(node["source"]["file"] == "Demo.cs" for node in before["nodes"]), before
            source.write_text(source.read_text(encoding="utf-8") + "\npublic sealed class WatcherAdded { }\n", encoding="utf-8")
            def changed_catalog() -> str | None:
                value = catalog_id(pointer)
                return value if value != first else None

            second = wait_for(changed_catalog, serve, seconds=15, what="catalog after source edit")
            after = query(home, repo, "WatcherAdded")
            assert any(node["source"]["file"] == "Demo.cs" for node in after["nodes"]), after
            serve.send_signal(signal.SIGTERM)
            serve.wait(timeout=10)
            reconciled = subprocess.run([str(binary), "reconcile", "--solution", "demo-solution", "--scope", "dirty", "--json"], env=environment, text=True, capture_output=True)
            if reconciled.returncode:
                raise RuntimeError(f"bounded reconcile failed: {reconciled.stdout} {reconciled.stderr}")
        finally:
            if serve.poll() is None:
                serve.kill()
                serve.wait(timeout=5)
        print(json.dumps({"register_exit": registered.returncode, "catalog_before": first, "catalog_after": second, "query_before_catalog": before["catalog_generation_id"], "query_after_catalog": after["catalog_generation_id"], "query_before_nodes": len(before["nodes"]), "query_after_nodes": len(after["nodes"]), "serve_exit": serve.returncode, "reconcile_exit": reconciled.returncode}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
