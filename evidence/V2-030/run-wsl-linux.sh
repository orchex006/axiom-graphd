#!/usr/bin/env bash
set -u
TREE=/mnt/d/SP-Billy/axiom-worktrees/axiom-graphd-w10-v2030
cd "$TREE" || exit 99
mkdir -p evidence/V2-030/py-wsl

echo "tree=$TREE"
echo "pwd=$(pwd)"
echo "uname_srm=$(uname -srm)"
echo "os_release=$(grep -E '^PRETTY_NAME=' /etc/os-release)"
echo "libc=$(ldd --version | head -1)"
echo "python=$(python3 --version 2>&1)"
echo "sqlite3_module=$(python3 -c 'import sqlite3;print(sqlite3.sqlite_version)')"
echo "cargo=$(command -v cargo || echo NOT-PRESENT)"
echo "git=$(git version)"
echo ""
codes=evidence/V2-030/py-wsl/_exit-codes.tsv
: > "$codes"
fail=0
for f in watch_save_burst.py watch_overflow.py queue_crash.py queue_concurrent_edit.py publish_crash.py storage_failure.py git_checkpoint.py sqlite_migration.py core_manifest.py bootstrap_e2e.py update_e2e.py; do
  start=$(date +%s.%N)
  python3 "tests/$f" > "evidence/V2-030/py-wsl/$f.log" 2>&1
  code=$?
  end=$(date +%s.%N)
  printf "%-28s exit=%-3s s=%s\n" "$f" "$code" "$(awk -v a="$start" -v b="$end" "BEGIN{printf \"%.1f\", b-a}")"
  printf "%s\t%s\n" "$f" "$code" >> "$codes"
  if [ "$code" -ne 0 ]; then fail=$((fail+1)); fi
done
echo ""
echo "non_zero_exits=$fail"

python3 - "$codes" <<'PY'
import hashlib, json, os, subprocess, sys

codes_path = sys.argv[1]
root = os.getcwd()
rows = []
with open(codes_path, "r", encoding="utf-8") as fh:
    for line in fh:
        line = line.rstrip("\n")
        if not line:
            continue
        name, code = line.split("\t")
        log_path = os.path.join("evidence", "V2-030", "py-wsl", name + ".log")
        with open(log_path, "rb") as lf:
            log_bytes = lf.read()
        with open(os.path.join("tests", name), "rb") as hf:
            harness_bytes = hf.read()
        rows.append({
            "name": name,
            "exit": int(code),
            "log_sha256": hashlib.sha256(log_bytes).hexdigest(),
            "harness_sha256": hashlib.sha256(harness_bytes).hexdigest(),
        })

def cmd(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True, check=False).stdout.strip()
    except Exception as exc:  # pragma: no cover - diagnostic only
        return "unavailable: %s" % exc

manifest = {
    "manifest_kind": "axiom-native-matrix-run",
    "target": "linux-x64",
    "scope": "python-side harnesses executed on WSL2 Linux (no Rust toolchain present)",
    "kernel": cmd("uname", "-srm"),
    "distribution": cmd("grep", "-E", "^PRETTY_NAME=", "/etc/os-release"),
    "libc": cmd("ldd", "--version").splitlines()[0] if cmd("ldd", "--version") else "unknown",
    "interpreter": cmd("python3", "--version"),
    "sqlite3_module": cmd("python3", "-c", "import sqlite3;print(sqlite3.sqlite_version)"),
    "cargo": "NOT-PRESENT",
    "rust_binary_built": False,
    "rust_binary_sha256": None,
    "harnesses": rows,
    "non_zero_exits": sum(1 for r in rows if r["exit"] != 0),
    "host_python_tests_dir": "tests",
    "note": ("Real Linux (WSL2) execution of the repository Python harnesses. No cargo is installed, "
             "so no x86_64-unknown-linux-gnu artifact was built; this manifest is the artifact of this leg."),
}
with open("evidence/V2-030/wsl-linux-manifest.json", "w", encoding="utf-8", newline="\n") as out:
    json.dump(manifest, out, indent=2, sort_keys=True)
    out.write("\n")
print("manifest=evidence/V2-030/wsl-linux-manifest.json")
PY
exit 0