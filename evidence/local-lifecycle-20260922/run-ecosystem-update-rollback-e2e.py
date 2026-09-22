#!/usr/bin/env python3
"""Native local ecosystem install -> update -> rollback proof.

Uses the compiled `axiom` installation CLI, real temporary files, and local
unsigned development payload bytes.  It deliberately does not register a host
service or claim release-channel certification.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ENGINE = REPO / "target/debug/axiom"
RESULT = Path(__file__).with_name("ecosystem-update-rollback-e2e.json")
HOST = "macos-x64"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def command(env: dict[str, str], *args: str, expect: int = 0) -> dict:
    completed = subprocess.run([str(ENGINE), *args, "--json"], env=env, text=True, capture_output=True)
    if completed.returncode != expect:
        raise RuntimeError(f"argv={args!r} exit={completed.returncode} stdout={completed.stdout!r} stderr={completed.stderr!r}")
    if not completed.stdout.strip():
        return {"exit": completed.returncode}
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"non-JSON stdout for {args!r}: {completed.stdout!r}") from error
    value["exit"] = completed.returncode
    return value


def payload(bundle: Path, relative: str, data: bytes) -> dict:
    path = bundle / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"sha256": digest(data), "size_bytes": len(data)}


def bundle(root: Path, graphd_version: str, mcp_version: str, skills_version: str, marker: str) -> None:
    graphd = f"graphd-{marker}".encode()
    mcp = f"mcp-{marker}".encode()
    skill = f"# skill {marker}\n".encode()
    graphd_info = payload(root, "bin/axiom-graphd", graphd)
    mcp_info = payload(root, "python/axiom-mcp.whl", mcp)
    manifest = {
        "schema_version": 1,
        "bundle_id": f"local-{marker}",
        "channel": "stable",
        "created_at": "2026-09-22T00:00:00Z",
        "components": [
            {"component": "axiom-graphd", "version": graphd_version, "host": HOST,
             "artifact": "bin/axiom-graphd", "kind": "binary", **graphd_info,
             "permissions": ["read", "execute"], "service": None, "network_access": []},
            {"component": "axiom-mcp", "version": mcp_version, "host": HOST,
             "artifact": "python/axiom-mcp.whl", "kind": "python", **mcp_info,
             "permissions": ["read"], "service": None, "network_access": []},
        ],
    }
    (root / "bundle.json").write_text(json.dumps(manifest, sort_keys=True))
    skill_info = payload(root, "skills/payload/instructions/local.md", skill)
    skills = {
        "schema_version": 1, "component": "skills", "version": skills_version,
        "revision": "a" * 40, "spec_revision": "b" * 40,
        "entries": [{"path": "instructions/local.md", "kind": "instruction", **skill_info,
                     "capabilities": []}],
    }
    (root / "skills/bundle.json").write_text(json.dumps(skills, sort_keys=True) + "\n")


def read_snapshot(install: Path) -> dict:
    core = (install / "current").read_bytes()
    skills = (install / "skills/current").read_bytes()
    core_value = json.loads(core)
    skills_value = json.loads(skills)
    payloads: dict[str, str] = {}
    for item in core_value["activated"]:
        location = Path(item["destination"])
        payloads[location.name] = digest(location.read_bytes())
        assert payloads[location.name] == item["sha256"]
    version = skills_value["version"]
    skill_file = install / "skills" / version / "instructions/local.md"
    return {
        "core_pointer": core, "skills_pointer": skills,
        "core_pointer_sha256": digest(core), "skills_pointer_sha256": digest(skills),
        "payloads": payloads, "skills_version": version, "skill_sha256": digest(skill_file.read_bytes()),
    }


def main() -> int:
    if not ENGINE.is_file():
        raise SystemExit(f"missing compiled engine: {ENGINE}; run cargo build -p axiom")
    with tempfile.TemporaryDirectory(prefix="axiom-update-e2e-") as temporary:
        temporary_root = Path(temporary)
        home, initial, update = temporary_root / "home", temporary_root / "initial", temporary_root / "update"
        bundle(initial, "1.0.0", "1.0.0", "1.0.0", "initial")
        bundle(update, "2.0.0", "1.5.0", "2.0.0", "update")
        python_dir = Path(os.environ.get(
            "AXIOM_E2E_PYTHON_DIR",
            Path.home() / ".local/share/uv/python/cpython-3.13.15-macos-x86_64-none/bin",
        ))
        env = os.environ | {"AXIOM_HOME": str(home), "PATH": f"{python_dir}:{os.environ['PATH']}"}
        initial_plan = temporary_root / "initial-plan.json"
        initial_plan_result = command(env, "install", "plan", "--bundle", str(initial), "--out", str(initial_plan))
        command(env, "install", "apply", "--plan", str(initial_plan), "--approve-digest", initial_plan_result["plan_digest"])
        install = home / "installs/ecosystem"
        before = read_snapshot(install)

        update_plan = temporary_root / "update-plan.json"
        planned = command(env, "update", "plan", "--to", "2.0.0", "--bundle", str(update), "--out", str(update_plan))
        wrong = command(env, "update", "apply", "--plan", str(update_plan), "--approve-digest", "0" * 64, expect=5)
        assert wrong["exit"] == 5
        assert read_snapshot(install)["core_pointer_sha256"] == before["core_pointer_sha256"]
        applied = command(env, "update", "apply", "--plan", str(update_plan), "--approve-digest", planned["plan_digest"])
        during = read_snapshot(install)
        assert during["core_pointer_sha256"] != before["core_pointer_sha256"]
        assert during["skills_pointer_sha256"] != before["skills_pointer_sha256"]
        assert during["skills_version"] == "2.0.0"
        assert set(during["payloads"].values()) != set(before["payloads"].values())

        transaction = applied["transaction_id"]
        rolled_back = command(env, "update", "rollback", "--transaction", transaction)
        after = read_snapshot(install)
        assert after["core_pointer"] == before["core_pointer"]
        assert after["skills_pointer"] == before["skills_pointer"]
        assert after["payloads"] == before["payloads"]
        assert after["skill_sha256"] == before["skill_sha256"]
        repeated = command(env, "update", "rollback", "--transaction", transaction)
        assert repeated["exit"] == 0
        result = {
            "schema_version": 1, "host": HOST, "engine": "target/debug/axiom",
            "synthetic_development_payloads": True,
            "initial_install_exit": 0, "update_plan_exit": planned["exit"],
            "wrong_approval_exit": wrong["exit"], "update_apply_exit": applied["exit"],
            "rollback_exit": rolled_back["exit"], "repeat_rollback_exit": repeated["exit"],
            "before_core_pointer_sha256": before["core_pointer_sha256"],
            "during_core_pointer_sha256": during["core_pointer_sha256"],
            "after_core_pointer_sha256": after["core_pointer_sha256"],
            "before_skills_pointer_sha256": before["skills_pointer_sha256"],
            "during_skills_pointer_sha256": during["skills_pointer_sha256"],
            "after_skills_pointer_sha256": after["skills_pointer_sha256"],
            "transaction_id": transaction,
        }
        RESULT.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        print(json.dumps(result, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
