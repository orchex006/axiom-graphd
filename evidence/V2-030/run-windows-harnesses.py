#!/usr/bin/env python3
"""Run the repository's Python harnesses natively on this Windows host (V2-030).

This is the Windows side of the native platform matrix. It runs each harness in
`tests/` as a real child process of the host Python, captures stdout and stderr
as raw bytes, and writes the byte-exact log plus the observed exit code. It is
the counterpart of `run-wsl-linux.sh`, which does the same inside WSL2 Linux.

It never fabricates a result: the exit code it records is the status the child
process really returned, and the log it writes is the bytes the child really
wrote. The harnesses themselves are read-only over the repository.

Usage:
    python evidence/V2-030/run-windows-harnesses.py
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

HARNESSES = (
    "watch_save_burst.py",
    "watch_overflow.py",
    "queue_crash.py",
    "queue_concurrent_edit.py",
    "publish_crash.py",
    "storage_failure.py",
    "git_checkpoint.py",
    "sqlite_migration.py",
    "core_manifest.py",
    "bootstrap_e2e.py",
    "update_e2e.py",
)

EVIDENCE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(EVIDENCE))
LOG_DIR = os.path.join(EVIDENCE, "py-win")


def sha256_file(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    rows = []
    for name in HARNESSES:
        harness = os.path.join(ROOT, "tests", name)
        completed = subprocess.run(
            [sys.executable, harness],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        log_path = os.path.join(LOG_DIR, name + ".log")
        # Normalize CRLF to LF before writing. `.gitattributes` uses
        # `* text=auto`, so the committed blob stores LF; writing LF here
        # keeps the recorded `log_sha256` equal to the committed bytes.
        stdout = completed.stdout.replace(b"\r\n", b"\n")
        stderr = completed.stderr.replace(b"\r\n", b"\n")
        with open(log_path, "wb") as handle:
            handle.write(stdout)
            handle.write(stderr)
        rows.append(
            {
                "name": name,
                "exit": completed.returncode,
                "log_sha256": sha256_file(log_path),
                "harness_sha256": sha256_file(harness),
            }
        )
        size = os.path.getsize(log_path)
        print("%-28s exit=%-3s log_bytes=%s" % (name, completed.returncode, size))

    with open(os.path.join(LOG_DIR, "_exit-codes.tsv"), "w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write("%s\t%s\n" % (row["name"], row["exit"]))

    manifest = {
        "manifest_kind": "axiom-native-matrix-run",
        "target": "windows-x64",
        "scope": "python-side harnesses executed on the native Windows host",
        "python": sys.version.split()[0],
        "executable": sys.executable,
        "harnesses": rows,
        "non_zero_exits": sum(1 for row in rows if row["exit"] != 0),
        "note": (
            "Real native Windows execution of the repository Python harnesses. The Rust artifact of "
            "this target is target/debug/axiom-graphd.exe, hashed in v2030-windows-artifacts.txt; "
            "this manifest is the Python-side record of the same host."
        ),
    }
    manifest_path = os.path.join(EVIDENCE, "py-win-manifest.json")
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print("")
    print("non_zero_exits=%d" % manifest["non_zero_exits"])
    print("manifest=evidence/V2-030/py-win-manifest.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
