#!/bin/sh
# Run the native default-WAL lifecycle from portable source/config templates.
# Invoke from the primary workspace root. The scoped root is removed on exit.
set -u

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary="${AXIOM_GRAPHD_BINARY:-target/local-macos/axiom-graphd}"
root=$(mktemp -d "${TMPDIR:-/tmp}/axiom-sqlite-wal-e2e.XXXXXX")
export AXIOM_SQLITE_E2E_ROOT="$root"
trap 'rm -rf "$AXIOM_SQLITE_E2E_ROOT"' EXIT HUP INT TERM

mkdir -p "$root/repo/src" "$root/home/config"
cp "$script_dir/sqlite-default-wal-e2e-Demo.cs" "$root/repo/src/Demo.cs"
cp "$script_dir/sqlite-default-wal-e2e-solution.json" "$root/solution.json"
python3 - "$root/home/config/bindings.json" "$root/repo" <<'PY'
import json, sys
with open(sys.argv[1], 'w', encoding='utf-8') as output:
    json.dump({'bindings': {'demo-repo': sys.argv[2]}}, output)
PY

run() {
  name=$1
  shift
  output=$(AXIOM_HOME="$root/home" "$binary" "$@" 2>&1)
  code=$?
  printf 'command=%s\n' "$name"
  printf 'argv=AXIOM_HOME=<scoped-home> <primary-native-axiom-graphd> %s\n' "$*" | python3 -c 'import os, sys; print(sys.stdin.read().replace(os.environ["AXIOM_SQLITE_E2E_ROOT"], "<scoped-temp-root>"), end="")'
  printf 'exit_code=%s\n' "$code"
  printf '%s\n' "$output" | python3 -c 'import os, sys; print(sys.stdin.read().replace(os.environ["AXIOM_SQLITE_E2E_ROOT"], "<scoped-temp-root>"), end="")'
  return "$code"
}

result=0
run version version --json || result=1
run register solution register --config "$root/solution.json" --apply --json || result=1
run reconcile reconcile --solution demo-solution --scope dirty --json || result=1
run query query context --solution demo-solution --symbol Demo.TokenSource --json || result=1
exit "$result"
