"""Exercise public native executables on isolated registered inputs; no user installs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FORMS = ["bootstrap plan", "bootstrap apply", "bootstrap verify", "bootstrap update plan", "bootstrap update apply",
         "host detect", "host configure", "host verify", "skills version", "skills check", "skills update plan", "skills update apply",
         "specs version", "specs check", "specs update plan", "specs update apply", "doctor", "support-bundle", "changed", "daemon update"]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--skills", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    cli, daemon, skills = [p.resolve() for p in (args.cli, args.daemon, args.skills)]
    cases = []
    with tempfile.TemporaryDirectory(prefix="axiom public ") as temporary:
        scratch = Path(temporary).resolve()
        project = scratch / "project"
        project.mkdir()
        (project / "src").mkdir()
        (project / "src/App.cs").write_text("public class App {}\n", encoding="utf-8")
        human = b"# Human instructions\nKeep my source and governance.\n"
        (project / "AGENTS.md").write_bytes(human)
        env = dict(os.environ, AXIOM_HOME=str(scratch / "home"), AXIOM_SKILLS_BUNDLE=str(skills))
        fixture = scratch / ("mcp-fixture.exe" if os.name == "nt" else "mcp-fixture")
        subprocess.run(["rustc", str(ROOT / "tests/native/mcp_fixture.rs"), "-o", str(fixture)], check=True)
        env.update(AXIOM_MCP_COMMAND=str(fixture), AXIOM_MCP_ARGS="[]")

        def call(case, program, words, expected=0):
            result = subprocess.run([str(program), *map(str, words), "--json"], env=env, cwd=project,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
            cases.append({"id": case, "exit_code": result.returncode, "expected_exit_code": expected,
                          "stdout_sha256": digest(result.stdout), "stderr_sha256": digest(result.stderr)})
            if result.returncode != expected:
                raise AssertionError(f"{case}: expected {expected}, got {result.returncode}: {result.stdout.decode(errors='replace')} {result.stderr.decode(errors='replace')}")
            value = json.loads(result.stdout)
            assert isinstance(value, dict), case
            return value

        version = call("core version", cli, ["version"])
        if args.source_revision != "unknown":
            assert version["build_revision"] == args.source_revision, "binary source differs from claimed source"

        config = scratch / "solution.json"
        bindings = scratch / "bindings.json"
        config.write_text(json.dumps({"id": "ready-solution", "profile": "default", "projects": [{"id": "app", "repo_id": "repo-main", "path": "src"}]}))
        bindings.write_text(json.dumps({"bindings": {"repo-main": str(project)}}))
        call("register", daemon, ["solution", "register", "--config", config, "--bindings", bindings, "--apply"])
        call("host detect", cli, ["host", "detect"])
        before = (project / "AGENTS.md").read_bytes()
        bootstrap = scratch / "bootstrap.json"
        plan = call("bootstrap plan", cli, ["bootstrap", "plan", "--solution", "ready-solution", "--out", bootstrap])
        assert (project / "AGENTS.md").read_bytes() == before
        call("bootstrap wrong approval", cli, ["bootstrap", "apply", "--plan", bootstrap, "--approve-digest", "0" * 64], 5)
        call("bootstrap apply", cli, ["bootstrap", "apply", "--plan", bootstrap, "--approve-digest", plan["plan_digest"]])
        assert (project / "AGENTS.md").read_bytes().startswith(human)
        call("bootstrap apply replay", cli, ["bootstrap", "apply", "--plan", bootstrap, "--approve-digest", plan["plan_digest"]])
        call("bootstrap verify", cli, ["bootstrap", "verify", "--solution", "ready-solution"])
        managed = project / ".axiom/agent/POLICY.md"
        approved_policy = managed.read_bytes()
        managed.write_bytes(approved_policy + b"human edit\n")
        call("bootstrap human edit refusal", cli, ["bootstrap", "verify", "--solution", "ready-solution"], 6)
        assert managed.read_bytes().endswith(b"human edit\n")
        managed.write_bytes(approved_policy)
        update = scratch / "bootstrap-update.json"
        plan = call("bootstrap update plan", cli, ["bootstrap", "update", "plan", "--solution", "ready-solution", "--to", "2.0.0-draft.1", "--out", update])
        call("bootstrap update apply", cli, ["bootstrap", "update", "apply", "--plan", update, "--approve-digest", plan["plan_digest"]])
        host_plan = scratch / "host.json"
        hp = call("host configure", cli, ["host", "configure", "--host", "codex", "--dry-run", "--out", host_plan])
        assert not (project / ".codex/config.toml").exists()
        call("host apply", cli, ["host", "configure", "--host", "codex", "--plan", host_plan, "--approve-digest", hp["plan_digest"]])
        call("host apply replay", cli, ["host", "configure", "--host", "codex", "--plan", host_plan, "--approve-digest", hp["plan_digest"]])
        call("host dry-run cannot apply", cli, ["host", "configure", "--host", "codex", "--plan", host_plan, "--approve-digest", hp["plan_digest"], "--dry-run"], 2)
        verified = call("host verify", cli, ["host", "verify", "--host", "codex"])
        assert verified["host_runtime_verified"] is False
        env["AXIOM_MCP_ARGS"] = '["--empty"]'
        call("host peer mismatch", cli, ["host", "verify", "--host", "codex"], 6)
        env["AXIOM_MCP_ARGS"] = "[]"

        for component in ["skills", "specs"]:
            bundle = scratch / (component + "-input")
            bundle.mkdir()
            payload = bundle / "payload"
            payload.mkdir()
            body = b"# Native verified content\n"
            (payload / "content").mkdir()
            (payload / "content/README.md").write_bytes(body)
            manifest = {"schema_version": 1, "component": component, "version": "0.1.2", "revision": "b" * 40,
                        "spec_revision": "c" * 40, "entries": [{"path": "content/README.md", "kind": "reference", "sha256": digest(body), "size_bytes": len(body), "capabilities": []}]}
            (bundle / "bundle.json").write_text(json.dumps(manifest))
            call(component + " version", cli, [component, "version"])
            call(component + " check", cli, [component, "check", "--updates", "--bundle", bundle])
            out = scratch / (component + "-plan.json")
            plan = call(component + " update plan", cli, [component, "update", "plan", "--to", "0.1.2", "--bundle", bundle, "--out", out])
            call(component + " wrong approval", cli, [component, "update", "apply", "--plan", out, "--approve-digest", "0" * 64], 5)
            call(component + " update apply", cli, [component, "update", "apply", "--plan", out, "--approve-digest", plan["plan_digest"]])
            call(component + " apply replay", cli, [component, "update", "apply", "--plan", out, "--approve-digest", plan["plan_digest"]])
            installed = scratch / f"home/installs/ecosystem/{component}/0.1.2/content/README.md"
            assert installed.read_bytes() == body
            installed.write_bytes(body + b"human edit\n")
            call(component + " human edit refusal", cli, [component, "version"], 2)
            assert installed.read_bytes().endswith(b"human edit\n")
            installed.write_bytes(body)
        doctor = call("doctor", cli, ["doctor", "--all"], 3)
        assert doctor["code"] == "NOT_FOUND" and "observed" in doctor["details"], doctor
        archive = scratch / "diagnostics.zip"
        call("support-bundle", cli, ["support-bundle", "--redact", "--out", archive])
        import zipfile
        with zipfile.ZipFile(archive) as bundle:
            assert bundle.testzip() is None
            assert "doctor.json" in bundle.namelist()
        call("support existing output", cli, ["support-bundle", "--out", archive], 6)
        changed = call("changed", daemon, ["changed", "--solution", "ready-solution", "--project", "app", "--path", "src/App.cs", "--reason", "manual"])
        assert changed["pending"] is True
        call("reconcile pending hint", daemon, ["reconcile", "--solution", "ready-solution", "--scope", "dirty"])
        assert not list((scratch / "home/incoming-changes").glob("*.json"))
        root = scratch / "home/installs/ecosystem"
        root.mkdir(parents=True, exist_ok=True)
        (root / "current").write_text(json.dumps({"version": "0.1.1", "source": args.source_revision}))
        delegated = call("daemon update", daemon, ["update", "check"])
        assert delegated["update_source"] == "explicit-local-bundle"
        assert (project / "src/App.cs").read_text() == "public class App {}\n"
    args.out.mkdir(parents=True, exist_ok=True)
    report = {"platform": {"Windows": "windows-x64", "Linux": "linux-x64", "Darwin": "macos-x64"}[platform.system()],
              "execution": "native", "source_revision": args.source_revision, "public_forms": FORMS,
              "cli_sha256": digest(cli.read_bytes()), "daemon_sha256": digest(daemon.read_bytes()), "arch": platform.machine(),
              "cases": cases, "negative_cases_verified": True, "host_runtime_claim": "fixture-gateway-only",
              "development_candidate": args.source_revision == "unknown"}
    (args.out / "public-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"OK {len(cases)} real native executable cases; all public forms exercised")


if __name__ == "__main__":
    main()
