"""Combine actual public and migration proof bytes from one native CI job."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--migration", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    public = json.loads(args.public.read_text(encoding="utf-8"))
    migration = json.loads(args.migration.read_text(encoding="utf-8"))
    assert public["execution"] == "native" and public["source_revision"] != "unknown"
    assert len(public["source_revision"]) == 40
    assert all(row["exit_code"] == row["expected_exit_code"] for row in public["cases"])
    assert migration.get("status") == "ready" and migration.get("native_runtime") is True
    assert migration["cli_sha256"] == public["cli_sha256"], "migration used another executable"
    assert migration["environment"]["execution"] == "native", "migration is not native CI evidence"
    assert len(migration.get("cases", [])) >= 10, "missing actual migration cases"
    assert migration["environment"]["os"] == {"windows-x64": "Windows", "linux-x64": "Linux", "macos-x64": "Darwin"}[public["platform"]]
    public["migration_verified"] = True
    public["migration_report_sha256"] = hashlib.sha256(args.migration.read_bytes()).hexdigest()
    public["public_report_sha256"] = hashlib.sha256(args.public.read_bytes()).hexdigest()
    args.out.write_text(json.dumps(public, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("OK native public/migration proof bound by exact report digests")


if __name__ == "__main__":
    main()
