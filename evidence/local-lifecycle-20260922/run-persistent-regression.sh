#!/bin/sh
set -eu

binary=${AXIOM_GRAPHD_BINARY:-target/debug/axiom-graphd}
root=$(mktemp -d "${TMPDIR:-/tmp}/axiom-persistent.XXXXXX")
cleanup() { rm -rf "$root"; }
trap cleanup EXIT HUP INT TERM

mkdir -p "$root/repo/src" "$root/home/config"
cp evidence/engine-readiness-20260922/sqlite-default-wal-e2e-Demo.cs "$root/repo/src/Demo.cs"
python3 - "$root/solution.json" "$root/home/config/bindings.json" "$root/repo" <<'PY'
import json, sys
json.dump({"id":"demo-solution","profile":"default","catalog_host_repo":"demo-repo","projects":[{"id":"demo-project","repo_id":"demo-repo","path":"src"}]}, open(sys.argv[1], "w"))
json.dump({"bindings":{"demo-repo":sys.argv[3]}}, open(sys.argv[2], "w"))
PY

AXIOM_HOME="$root/home" "$binary" solution register --config "$root/solution.json" --apply --json >/dev/null
AXIOM_HOME="$root/home" "$binary" serve --json >"$root/serve.json" 2>"$root/serve.err" &
daemon=$!

for attempt in 1 2 3 4 5 6 7 8 9 10; do
  test -f "$root/repo/.axiom/graph/demo-solution/_catalog/live/current.json" && break
  sleep 1
done
first=$(python3 - "$root/repo/.axiom/graph/demo-solution/_catalog/live/current.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["generation_id"])
PY
)
printf '\n// watcher regression\npublic sealed class WatcherAdded { }\n' >> "$root/repo/src/Demo.cs"
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  second=$(python3 - "$root/repo/.axiom/graph/demo-solution/_catalog/live/current.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["generation_id"])
PY
)
  test "$first" != "$second" && break
  sleep 1
done
test "$first" != "$second"
kill -INT "$daemon"
wait "$daemon"
AXIOM_HOME="$root/home" "$binary" reconcile --solution demo-solution --scope dirty --json >/dev/null
printf 'persistent_generation=%s\nupdated_generation=%s\nlock_reacquired=true\n' "$first" "$second"
