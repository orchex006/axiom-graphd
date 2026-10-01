#!/usr/bin/env python3
"""Verify and execute an unsigned native x64 core candidate without source files."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile

MACHO_X64 = bytes.fromhex("cffaedfe07000001")
ELF_X64_PREFIX = bytes.fromhex("7f454c460201")
TARGETS = {("Darwin", "x86_64"): "macos-x64", ("Linux", "x86_64"): "linux-x64",
           ("Windows", "AMD64"): "windows-x64", ("Windows", "x86_64"): "windows-x64"}


def native_binary(data: bytes, target: str) -> bool:
    if target == "windows-x64":
        if len(data) < 0x40 or data[:2] != b"MZ":
            return False
        offset = int.from_bytes(data[0x3c:0x40], "little")
        return (offset >= 0x40 and offset + 26 <= len(data)
                and data[offset:offset + 4] == b"PE\0\0"
                and data[offset + 4:offset + 6] == bytes.fromhex("6486")
                and data[offset + 24:offset + 26] == bytes.fromhex("0b02"))
    if target == "macos-x64":
        return data[:8] == MACHO_X64
    return data[:6] == ELF_X64_PREFIX and data[18:20] == bytes.fromhex("3e00")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_file(root: Path, row: dict) -> bytes:
    name = row.get("name")
    if not isinstance(name, str) or Path(name).name != name:
        raise ValueError("candidate artifact path is invalid")
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"candidate artifact {name} is missing or symlinked")
    data = path.read_bytes()
    if len(data) != row.get("size_bytes") or sha(data) != row.get("sha256"):
        raise ValueError(f"candidate artifact {name} digest/size mismatch")
    return data


def verify(root: Path) -> dict:
    target = TARGETS.get((platform.system(), platform.machine()))
    if target is None:
        raise ValueError("native x64 macOS, Linux or Windows verifier host required")
    path = root / "candidate-manifest.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("candidate manifest missing")
    manifest = json.loads(path.read_text())
    if manifest.get("schema_version") != 1 or manifest.get("kind") != "unsigned-core-candidate" or manifest.get("platform") != target:
        raise ValueError("candidate manifest kind/platform invalid")
    if manifest.get("signing") != "unsigned" or manifest.get("notarization") != "not_notarized" or manifest.get("publication") != "not_published":
        raise ValueError("candidate falsely claims release authority")
    revision = manifest.get("source_revision")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("candidate source revision is not immutable")
    archive = checked_file(root, manifest["archive"])
    sbom = json.loads(checked_file(root, manifest["sbom"]))
    if sbom.get("source_revision") != revision or sbom.get("cargo_lock_sha256") != manifest.get("source_lock_sha256"):
        raise ValueError("candidate SBOM provenance mismatch")
    if not isinstance(sbom.get("packages"), list) or len(sbom["packages"]) != manifest["sbom"].get("package_count") or not sbom["packages"]:
        raise ValueError("candidate SBOM package inventory incomplete")
    expected = {row["name"]: row for row in manifest["binaries"]}
    names = {"axiom.exe", "axiom-graphd.exe"} if target == "windows-x64" else {"axiom", "axiom-graphd"}
    if set(expected) != names:
        raise ValueError("candidate does not carry both core executables")
    with tempfile.TemporaryDirectory(prefix="axiom-core-verify-") as temporary:
        directory = Path(temporary)
        archive_path = root / manifest["archive"]["name"]
        if target == "windows-x64":
            with zipfile.ZipFile(archive_path) as zipped:
                members = zipped.infolist()
                if len(members) != len(names) + 1 or {item.filename for item in members} != names | {"release-info.json"}:
                    raise ValueError("candidate archive membership mismatch")
                for item in members:
                    if item.is_dir() or item.flag_bits & 1 or item.file_size > archive_path.stat().st_size * 50:
                        raise ValueError("candidate archive type/size invalid")
                    (directory / item.filename).write_bytes(zipped.read(item))
        else:
            with tarfile.open(archive_path, "r:gz") as tar:
                members = tar.getmembers()
                if {item.name for item in members} != names | {"release-info.json"}:
                    raise ValueError("candidate archive membership mismatch")
                for item in members:
                    if not item.isfile() or item.uid or item.gid or item.mtime or item.mode != (0o644 if item.name == "release-info.json" else 0o755):
                        raise ValueError("candidate archive type/ownership/mode mismatch")
                    data = tar.extractfile(item).read()
                    (directory / item.name).write_bytes(data)
                    if item.name != "release-info.json":
                        (directory / item.name).chmod(0o755)
        info = json.loads((directory / "release-info.json").read_text())
        if info.get("platform") != target or info.get("version") != manifest["version"] or info.get("source_revision") != revision or info.get("sbom_sha256") != manifest["sbom"]["sha256"]:
            raise ValueError("candidate archive release identity mismatch")
        if info.get("binaries") != [{k: row[k] for k in ("name", "sha256", "size_bytes", "mode")} for row in manifest["binaries"]]:
            raise ValueError("candidate archive binary inventory mismatch")
        for name, row in expected.items():
            file = directory / name
            data = file.read_bytes()
            if not native_binary(data, target) or sha(data) != row["sha256"] or len(data) != row["size_bytes"]:
                raise ValueError(f"candidate {name} bytes or architecture mismatch")
            result = subprocess.run([str(file), "version", "--json"], capture_output=True, text=True, check=False)
            if result.returncode:
                raise ValueError(f"candidate {name} executable failed with {result.returncode}")
            report = json.loads(result.stdout)
            component = name.removesuffix(".exe") if target == "windows-x64" else name
            if report != row["version_report"] or report.get("component") != component or report.get("build_revision") != revision or report.get("version") != manifest["version"]:
                raise ValueError(f"candidate {name} version report mismatch")
    return {"ok": True, "source_revision": revision, "archive_sha256": sha(archive),
            "sbom_sha256": manifest["sbom"]["sha256"], "binary_sha256": {name: row["sha256"] for name, row in expected.items()},
            "package_count": len(sbom["packages"]), "native_executable_checks": 2}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.candidate_dir), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile, json.JSONDecodeError) as error:
        print(json.dumps({"ok": False, "reason": str(error)}))
        sys.exit(9)
