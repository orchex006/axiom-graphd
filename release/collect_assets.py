"""Bind checked archives to native source proof before preparing Release assets."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path

LANES = {"windows-x64", "linux-x64", "macos-x64"}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect(root, revision, output):
    if output.exists():
        raise ValueError("output must be a new directory")
    selected = []
    seen = set()
    for directory in root.iterdir():
        candidate = directory / "candidate-manifest.json"
        report = directory / "native-report.json"
        if not candidate.is_file() or not report.is_file():
            continue
        manifest = json.loads(candidate.read_text(encoding="utf-8"))
        proof = json.loads(report.read_text(encoding="utf-8"))
        lane = manifest["platform"]
        if lane not in LANES or lane in seen:
            raise ValueError("unsupported or duplicate native lane")
        seen.add(lane)
        if manifest["source_revision"] != revision or proof["source_revision"] != revision:
            raise ValueError("source drift")
        if proof["platform"] != lane or proof["execution"] != "native" or proof.get("migration_verified") is not True:
            raise ValueError("native proof incomplete")
        for kind in ("archive", "sbom"):
            entry = manifest[kind]
            name = entry["name"]
            if Path(name).name != name or "/" in name or "\\" in name:
                raise ValueError("unsafe asset name")
            path = directory / name
            if sha(path) != entry["sha256"]:
                raise ValueError("asset hash changed")
            selected.append((path, name))
        selected.extend([(candidate, lane + "-manifest.json"), (report, lane + "-native-report.json")])
    if seen != LANES:
        raise ValueError("three native lanes are required")
    output.mkdir(parents=True)
    for path, name in selected:
        shutil.copyfile(path, output / name)
    (output / "SOURCE-REVISION.txt").write_text(revision + "\n", encoding="utf-8", newline="\n")
    (output / "RELEASE-NOTES.md").write_text(
        "# Axiom core\n\nNative Windows x64, Linux x64 and Mac Intel assets verified by GitHub Actions. "
        "Mac ARM is deferred. No certification, signing or attestation prerequisite. "
        "Daemon and axiom share one core source/version. Host runtime claims remain separate; "
        "MCP native adapter tests use a hermetic fixture peer. Existing update approvals and integrity checks remain.\n",
        encoding="utf-8", newline="\n")
    (output / "SHA256SUMS").write_text("".join(sha(path) + "  " + path.name + "\n" for path in sorted(output.iterdir())), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    collect(args.input, args.source_revision, args.out)
    print("OK source-bound checked Release assets and SHA256SUMS")
