#!/bin/sh
# Re-run the successful scoped-home SQLite default-WAL lifecycle.
# Usage: AXIOM_SQLITE_E2E_ROOT=/absolute/scoped/root ./run-sqlite-default-wal-e2e.sh
# The fixture must already contain home/config/bindings.json, solution.json,
# and repo/src/Demo.cs. This script does not create or modify the fixture.
set -u

: "${AXIOM_SQLITE_E2E_ROOT:?set the existing scoped fixture root}"
binary="${AXIOM_GRAPHD_BINARY:-target/local-macos/axiom-graphd}"

run() {
  name=$1
  shift
  output=$(AXIOM_HOME="$AXIOM_SQLITE_E2E_ROOT/home" "$binary" "$@" 2>&1)
  code=$?
  printf 'command=%s\n' "$name"
  printf 'argv=AXIOM_HOME=<scoped-home> <primary-native-axiom-graphd> %s\n' "$*" | python3 -c 'import os, sys; print(sys.stdin.read().replace(os.environ["AXIOM_SQLITE_E2E_ROOT"], "<scoped-temp-root>"), end="")'
  printf 'exit_code=%s\n' "$code"
  printf '%s\n' "$output" | python3 -c 'import os, sys; print(sys.stdin.read().replace(os.environ["AXIOM_SQLITE_E2E_ROOT"], "<scoped-temp-root>"), end="")'
  return "$code"
}

result=0
run version version --json || result=1
run register solution register --config "$AXIOM_SQLITE_E2E_ROOT/solution.json" --apply --json || result=1
run serve serve --json || result=1
run query query context --solution demo-solution --symbol Demo.TokenSource --json || result=1
exit "$result"
