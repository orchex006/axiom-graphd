#!/usr/bin/env python3
"""Exercise a packaged core against an isolated, real C# source project."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def call(argv: list[str], env: dict[str, str], expected: int = 0) -> dict:
    result = subprocess.run(argv, env=env, capture_output=True, text=True)
    if result.returncode != expected:
        raise AssertionError(f"{Path(argv[0]).name} returned {result.returncode}, expected {expected}: {result.stdout[-300:]} {result.stderr[-300:]}")
    return json.loads(result.stdout)


def generation(pointer: Path) -> str | None:
    if not pointer.is_file():
        return None
    return json.loads(pointer.read_text())["generation_id"]


def wait_generation(pointer: Path, previous: str | None, timeout: float = 20) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = generation(pointer)
        if current and current != previous:
            return current
        time.sleep(0.2)
    raise AssertionError("catalog generation did not advance")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        raise SystemExit("output already exists")
    candidate = args.candidate_dir.resolve()
    manifest = json.loads((candidate / "candidate-manifest.json").read_text())
    if manifest["signing"] != "unsigned" or manifest["publication"] != "not_published":
        raise SystemExit("candidate claims release authority")
    with tempfile.TemporaryDirectory(prefix="axiom-k102-source-") as temporary:
        root = Path(temporary)
        binary_dir = root / "core"
        binary_dir.mkdir()
        with tarfile.open(candidate / manifest["archive"]["name"], "r:gz") as archive:
            members = archive.getmembers()
            if {row.name for row in members} != {"axiom", "axiom-graphd", "release-info.json"} or any(not row.isfile() for row in members):
                raise AssertionError("candidate archive membership changed")
            archive.extractall(binary_dir)
        daemon = binary_dir / "axiom-graphd"
        daemon.chmod(0o755)
        if sha(daemon) != next(row["sha256"] for row in manifest["binaries"] if row["name"] == "axiom-graphd"):
            raise AssertionError("candidate daemon digest changed")
        home = root / "home"
        repo = root / "repo"
        source = repo / "src" / "TokenSource.cs"
        source.parent.mkdir(parents=True)
        source.write_text("namespace Demo;\npublic class TokenSource { public string Issue() => \"ok\"; }\n")
        (repo / "Demo.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>\n')
        (home / "config").mkdir(parents=True)
        solution = root / "solution.json"
        solution.write_text(json.dumps({"id": "demo-solution", "profile": "default", "catalog_host_repo": "demo-repo", "projects": [{"id": "demo-project", "repo_id": "demo-repo", "path": "src"}]}))
        (home / "config" / "bindings.json").write_text(json.dumps({"bindings": {"demo-repo": str(repo)}}))
        env = {**os.environ, "AXIOM_HOME": str(home)}
        registration = call([str(daemon), "solution", "register", "--config", str(solution), "--apply", "--json"], env)
        pointer = repo / ".axiom/graph/demo-solution/_catalog/live/current.json"
        project_pointer = repo / ".axiom/graph/demo-solution/demo-project/live/current.json"
        process = subprocess.Popen([str(daemon), "serve", "--json"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            first = wait_generation(pointer, None)
            first_project = wait_generation(project_pointer, None)
            source.write_text(source.read_text() + "public sealed class WatcherAdded { }\n")
            second = wait_generation(pointer, first)
            wait_generation(project_pointer, first_project)
        finally:
            process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=20)
        if process.returncode != 0:
            raise AssertionError(f"daemon exited {process.returncode}: {stderr[-300:]}")
        context = call([str(daemon), "query", "context", "--solution", "demo-solution",
                        "--symbol", "TokenSource", "--json"], env)
        project_generation = generation(project_pointer)
        if not project_generation:
            raise AssertionError("project generation missing")
        project_live = project_pointer.parent / "generations" / project_generation
        graph_bytes = b"".join(path.read_bytes() for path in project_live.rglob("*.json"))
        if b"TokenSource" not in graph_bytes or b"WatcherAdded" not in graph_bytes:
            raise AssertionError("published graph omitted expected source symbols")
        if "TokenSource" not in json.dumps(context):
            raise AssertionError("checkpoint query omitted expected source symbol")
        out.mkdir(parents=True)
        shutil.copytree(repo / ".axiom/graph/demo-solution", out / "graph")
        shutil.copytree(repo / "src", out / "source")
        checkpoint_pointer = repo / ".axiom/graph/demo-solution/demo-project/checkpoint/current.json"
        original_pointer = checkpoint_pointer.read_bytes()
        incompatible = json.loads(original_pointer)
        incompatible["schema_version"] = 99
        checkpoint_pointer.write_text(json.dumps(incompatible) + "\n")
        try:
            incompatible_query = subprocess.run(
                [str(daemon), "query", "context", "--solution", "demo-solution",
                 "--symbol", "TokenSource", "--json"], env=env, capture_output=True, text=True,
            )
        finally:
            checkpoint_pointer.write_bytes(original_pointer)
        if incompatible_query.returncode == 0:
            raise AssertionError("incompatible fixture schema was accepted")
        report = {"source_revision": manifest["source_revision"], "candidate_manifest_sha256": sha(candidate / "candidate-manifest.json"),
                  "daemon_sha256": sha(daemon), "source_sha256": sha(source),
                  "first_catalog_generation": first, "updated_catalog_generation": second,
                  "project_generation": project_generation, "registered": registration,
                  "graph_contains_TokenSource": True, "graph_contains_WatcherAdded": True,
                  "checkpoint_query_contains_TokenSource": True,
                  "incompatible_fixture_exit_code": incompatible_query.returncode,
                  "incompatible_fixture_response": json.loads(incompatible_query.stdout),
                  "daemon_exit_code": process.returncode,
                  "watcher_advanced": first != second, "candidate": True,
                  "graph_pointer_sha256": sha(pointer), "project_pointer_sha256": sha(project_pointer)}
        (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        (out / "daemon-stdout.txt").write_text(stdout)
        (out / "daemon-stderr.txt").write_text(stderr)
        print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
