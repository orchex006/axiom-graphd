#!/usr/bin/env python3
"""Build an unsigned, deterministic Intel Mac core candidate from pinned binaries.

The two executable inputs must report the same version, schema set and exact
40-character source commit. This tool neither signs nor publishes a release.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
REVISION = re.compile(r"[0-9a-f]{40}\Z")
MACHO_X64 = bytes.fromhex("cffaedfe07000001")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def command(argv: list[str], *, cwd: Path = ROOT) -> str:
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode:
        raise ValueError(f"{Path(argv[0]).name} exited {result.returncode}: {result.stderr[-300:]}")
    return result.stdout.strip()


def source_revision(expected: str) -> str:
    if not REVISION.fullmatch(expected):
        raise ValueError("source revision must be full lowercase 40-hex")
    actual = command(["git", "rev-parse", "HEAD"])
    if expected != actual:
        raise ValueError("source revision differs from checked-out commit")
    if command(["git", "status", "--porcelain", "--untracked-files=normal"]):
        raise ValueError("source checkout is dirty; commit reviewed inputs before packaging")
    return actual


def binary(path: Path, component: str, revision: str, version: str, compatibility: dict) -> dict:
    if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError(f"{component} input is not a regular executable")
    data = path.read_bytes()
    if data[:8] != MACHO_X64:
        raise ValueError(f"{component} input is not Intel Mac Mach-O")
    report = json.loads(command([str(path.resolve()), "version", "--json"]))
    if report.get("component") != component or report.get("version") != version:
        raise ValueError(f"{component} version report disagrees with the core manifest")
    if report.get("build_revision") != revision:
        raise ValueError(f"{component} binary was not built from the pinned source revision")
    for key, expected in (("spec_version", compatibility["spec_version"]),
                          ("graph_schema", compatibility["graph_schema_version"]),
                          ("control_api", compatibility["control_api_version"]),
                          ("queue_schema", compatibility["queue_schema_version"])):
        if report.get(key) != expected:
            raise ValueError(f"{component} {key} is incompatible with the core manifest")
    return {"name": component, "sha256": sha(data), "size_bytes": len(data), "mode": "0755", "version_report": report}


def archive(path: Path, files: dict[str, bytes]) -> None:
    with path.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                for name, data in sorted(files.items()):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o755 if name in ("axiom", "axiom-graphd") else 0o644
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ""
                    tar.addfile(info, io.BytesIO(data))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    if (platform.system(), platform.machine()) != ("Darwin", "x86_64"):
        raise ValueError("native Intel Mac packaging host required")
    revision = source_revision(args.source_revision)
    manifest = read_json(ROOT / "release/core-manifest.json")
    release = manifest["release"]
    version = release["version"]
    if version != release["components"][0]["version"] or version != release["components"][1]["version"]:
        raise ValueError("core component versions disagree with the release version")
    target = next((row for row in release["targets"] if row["platform"] == "macos-x64"), None)
    if target is None or target["rust_target"] != "x86_64-apple-darwin":
        raise ValueError("Intel Mac target is absent from the checked-in core manifest")
    if release["publication"]["state"] != "not_published" or release["signature"]["state"] != "required":
        raise ValueError("candidate packager refuses a claimed published/signed release")
    compatibility = release["compatibility"]
    binaries = [binary(args.daemon, "axiom-graphd", revision, version, compatibility),
                binary(args.cli, "axiom", revision, version, compatibility)]
    output = args.out_dir.resolve()
    if output == ROOT or ROOT in output.parents:
        raise ValueError("candidate output must be outside the source checkout")
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)

    metadata = json.loads(command(["cargo", "metadata", "--locked", "--format-version", "1"]))
    packages = sorted(({"name": p["name"], "version": p["version"], "source": p.get("source"),
                        "license": p.get("license")} for p in metadata["packages"]),
                      key=lambda p: (p["name"], p["version"], p["source"] or ""))
    lock_bytes = (ROOT / "Cargo.lock").read_bytes()
    sbom = {"schema_version": 1, "kind": "cargo-workspace-package-inventory", "source_revision": revision,
            "cargo_lock_sha256": sha(lock_bytes), "packages": packages}
    sbom_name = f"axiom-{version}-macos-x64.sbom.json"
    sbom_bytes = (json.dumps(sbom, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (output / sbom_name).write_bytes(sbom_bytes)

    release_info = {"schema_version": 1, "candidate": True, "platform": "macos-x64",
                    "version": version, "source_revision": revision,
                    "binaries": [{k: row[k] for k in ("name", "sha256", "size_bytes", "mode")} for row in binaries],
                    "sbom_sha256": sha(sbom_bytes)}
    info_bytes = (json.dumps(release_info, sort_keys=True, separators=(",", ":")) + "\n").encode()
    archive_name = f"axiom-{version}-macos-x64.tar.gz"
    archive(output / archive_name, {"axiom": args.cli.read_bytes(),
                                    "axiom-graphd": args.daemon.read_bytes(),
                                    "release-info.json": info_bytes})
    candidate = {
        "schema_version": 1, "kind": "unsigned-core-candidate", "platform": "macos-x64",
        "version": version, "source_revision": revision, "spec_revision": read_json(ROOT / "spec.lock.json")["spec_revision"],
        "core_manifest_sha256": sha((ROOT / "release/core-manifest.json").read_bytes()),
        "source_lock_sha256": sha(lock_bytes), "archive": {"name": archive_name,
            "sha256": sha((output / archive_name).read_bytes()), "size_bytes": (output / archive_name).stat().st_size},
        "sbom": {"name": sbom_name, "sha256": sha(sbom_bytes), "size_bytes": len(sbom_bytes),
                 "package_count": len(packages)},
        "binaries": binaries,
        "host": {"system": platform.system(), "machine": platform.machine(), "macos": platform.mac_ver()[0]},
        "toolchain": {"rustc": command(["rustc", "--version", "--verbose"]),
                      "cargo": command(["cargo", "--version"]), "python": platform.python_version()},
        "signing": "unsigned", "notarization": "not_notarized", "publication": "not_published",
    }
    candidate_path = output / "candidate-manifest.json"
    candidate_path.write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"candidate_manifest_sha256": sha(candidate_path.read_bytes()),
                      "archive_sha256": candidate["archive"]["sha256"],
                      "sbom_sha256": candidate["sbom"]["sha256"], "source_revision": revision}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, AssertionError, StopIteration, json.JSONDecodeError) as error:
        print(f"core candidate refused: {error}", file=sys.stderr)
        sys.exit(9)
