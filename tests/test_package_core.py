#!/usr/bin/env python3
"""Native K-006 candidate reproducibility, consumption and refusal checks."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "release/package_core.py"
VERIFY = ROOT / "release/verify_core_candidate.py"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    cases = []
    with tempfile.TemporaryDirectory(prefix="axiom-k006-core-") as name:
        temporary = Path(name)

        def call(case: str, script: Path, options: list[str], expected: int, reason: str | None = None) -> dict:
            result = subprocess.run([sys.executable, str(script), *options], text=True, capture_output=True, check=False)
            if result.returncode != expected:
                raise AssertionError(f"{case} exited {result.returncode}: {result.stdout[-250:]} {result.stderr[-250:]}")
            value = json.loads(result.stdout) if result.stdout.strip().startswith("{") else {}
            if reason and reason not in result.stdout + result.stderr:
                raise AssertionError(f"{case} did not refuse {reason}")
            cases.append({"case": case, "exit_code": result.returncode, **({"reason": reason} if reason else {})})
            return value

        def build(output: Path) -> dict:
            return call("build_candidate", BUILD, ["--daemon", str(args.daemon), "--cli", str(args.cli),
                                                  "--source-revision", args.source_revision, "--out-dir", str(output)], 0)

        first, second = temporary / "first", temporary / "second"
        built = build(first)
        build(second)
        assert sha(first / "candidate-manifest.json") == sha(second / "candidate-manifest.json")
        assert sha(first / f"axiom-0.1.0-macos-x64.tar.gz") == sha(second / f"axiom-0.1.0-macos-x64.tar.gz")
        assert sha(first / f"axiom-0.1.0-macos-x64.sbom.json") == sha(second / f"axiom-0.1.0-macos-x64.sbom.json")
        checked = call("verify_candidate", VERIFY, ["--candidate-dir", str(first)], 0)
        assert checked["source_revision"] == args.source_revision and checked["native_executable_checks"] == 2
        call("wrong_source_revision", BUILD, ["--daemon", str(args.daemon), "--cli", str(args.cli),
                                               "--source-revision", "0" * 40, "--out-dir", str(temporary / "wrong")], 9,
             "source revision differs")

        corrupt = temporary / "corrupt"
        shutil.copytree(first, corrupt)
        archive = corrupt / "axiom-0.1.0-macos-x64.tar.gz"
        data = bytearray(archive.read_bytes())
        data[-1] ^= 1
        archive.write_bytes(data)
        call("corrupt_archive", VERIFY, ["--candidate-dir", str(corrupt)], 9, "digest/size mismatch")

        shutil.copyfile(first / archive.name, archive)
        manifest = corrupt / "candidate-manifest.json"
        document = json.loads(manifest.read_text())
        document["version"] = "9.9.9"
        manifest.write_text(json.dumps(document) + "\n")
        call("incompatible_manifest_version", VERIFY, ["--candidate-dir", str(corrupt)], 9,
             "archive release identity mismatch")
    print(json.dumps({"ok": True, "source_revision": args.source_revision,
                      "candidate_manifest_sha256": built["candidate_manifest_sha256"],
                      "archive_sha256": checked["archive_sha256"], "sbom_sha256": checked["sbom_sha256"],
                      "package_count": checked["package_count"], "cases": cases}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
