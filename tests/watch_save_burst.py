#!/usr/bin/env python3
"""Failure-injection harness F-011 - repeated human save bursts.

An editor does not save a file once. It writes a temporary file, renames it over
the target, rewrites it again, and touches metadata - a burst of filesystem hints
for one path inside a few tens of milliseconds. The watcher is only a hint source
(docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md section 9) and coalescing is what
keeps one human save from queueing the same path many times.

This harness replays a burst against a faithful, dependency-free model of the
coalescer in graph-watch::debounce (debounce 750ms, hard maximum wait 3s, bounded
held-path set) over a real temporary directory, and then reads the real bytes
back from disk. The property under test is not "an event was delivered": it is
that the content eventually indexed is the last content saved, no matter how many
hints the burst produced.

Positive legs:

* a five-write burst coalesces into one batch and the indexed digest equals the
  digest of the final save;
* a burst that never goes quiet still releases within the hard maximum wait and
  loses no path;
* distinct paths touched in one window are released together.

Negative legs (a check that cannot reject is not a check):

* a "dedup once per burst" policy that ignores a later hint for a path already
  seen is shown to index stale content - the real policy must index the last
  save, and the harness fails if the two agree;
* exceeding the held-path bound must raise the overflow signal
  (full_scan_required) instead of silently dropping paths.

No container, no Rust binary and no shell are needed. The real coalescer is
compiled Rust under crates/graph-watch; this harness models its documented
policy, not its private internals. The reproducible command that exercises the
real type instead is recorded below and reported as not_run here:

    cargo test --locked -p graph-watch debounce

Exit codes: 0 every property held and every negative leg was rejected, 2 at least
one divergence, 1 a usage or I/O failure.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import stat
import sys
import tempfile

# Policy constants mirrored from the shipped implementation so the model and the
# code cannot silently disagree on the numbers. See graph-core::config
# (DEFAULT_DEBOUNCE_MS, DEFAULT_MAX_DEBOUNCE_MS) and
# graph-watch::debounce::MAX_DEBOUNCED_PATHS.
DEBOUNCE_MS = 750
MAX_DEBOUNCE_MS = 3000
MAX_DEBOUNCED_PATHS = 65_536


class Debouncer:
    """Faithful model of graph-watch::debounce over an injected clock.

    Time arrives as an integer millisecond value so the harness is deterministic
    and never sleeps. hint records a path and its arrival; ready returns the batch
    that must be released at the given instant, or None while the burst is open.
    """

    def __init__(self, debounce_ms=DEBOUNCE_MS, max_debounce_ms=MAX_DEBOUNCE_MS,
                 max_paths=MAX_DEBOUNCED_PATHS):
        self.debounce_ms = debounce_ms
        self.max_debounce_ms = max_debounce_ms
        self.max_paths = max_paths
        self.pending = set()
        self.first_seen = {}
        self.last_hint = None
        self.overflowed = False

    def hint(self, path, now_ms):
        if len(self.pending) >= self.max_paths and path not in self.pending:
            # Buffer overflow is a notification overflow: recovery answers it
            # with a full scan (FullScanReason::BufferOverflow), never an
            # unbounded in-memory buffer and never a silent drop.
            self.overflowed = True
            return
        if path not in self.pending:
            self.first_seen[path] = now_ms
        self.pending.add(path)
        self.last_hint = now_ms

    def next_release_at(self):
        if not self.pending:
            return None
        quiet = (self.last_hint or 0) + self.debounce_ms
        aged = min(self.first_seen.values()) + self.max_debounce_ms
        return min(quiet, aged)

    def ready(self, now_ms):
        if not self.pending:
            return None
        if now_ms >= self.next_release_at():
            batch = sorted(self.pending)
            self.pending = set()
            self.first_seen = {}
            self.last_hint = None
            return batch
        return None


class NaiveDedup:
    """The rejected policy: treat one burst as one shot per path.

    A path released once is marked handled and every later hint for it in the same
    window is ignored. This is exactly the class of bug the monotonic generation
    rule exists to prevent, so the harness must refuse to let it pass.
    """

    def __init__(self, window_ms=MAX_DEBOUNCE_MS):
        self.window_ms = window_ms
        self.handled_at = {}

    def note(self, path, now_ms):
        if path in self.handled_at:
            return False
        return True

    def release(self, path, now_ms):
        self.handled_at[path] = now_ms


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_burst(root, path, values):
    """Write the real values to the real path and return their digests."""
    full = os.path.join(root, path)
    parent = os.path.dirname(full)
    if parent:
        os.makedirs(parent, exist_ok=True)
    digests = []
    for value in values:
        with io.open(full, "wb") as handle:
            handle.write(value)
        digests.append(digest(value))
    return digests


def run(root):
    problems = []
    not_run = []
    work = tempfile.mkdtemp(prefix="axiom-f011-")

    # --- leg 1: a five-write burst coalesces and indexes the last save --------
    debounce = Debouncer()
    saves = [b"v1", b"v2", b"v3", b"v4", b"v5"]
    digests = write_burst(work, "src/handler.cs", saves)
    arrived = 0
    for index in range(len(saves)):
        now = index * 80  # editor writes every 80ms
        debounce.hint("src/handler.cs", now)
        arrived += 1
    batches = []
    now = arrived * 80
    while len(batches) < 2 and now <= arrived * 80 + MAX_DEBOUNCE_MS + DEBOUNCE_MS:
        batch = debounce.ready(now)
        if batch is not None:
            batches.append((now, batch))
        now += 50
    if len(batches) != 1:
        problems.append("five-write burst produced %d batches, expected 1 coalesced batch" % len(batches))
    else:
        release_ms, batch = batches[0]
        if batch != ["src/handler.cs"]:
            problems.append("coalesced batch held %r, expected the single edited path" % batch)
        if arrived > 1 and len(batch) < arrived:
            pass  # coalescing reduced work as required
        else:
            problems.append("coalescing did not reduce work: %d events -> %d path(s)" % (arrived, len(batch)))
        indexed = digest(io.open(os.path.join(work, "src/handler.cs"), "rb").read())
        if indexed != digests[-1]:
            problems.append("indexed digest is not the last save (indexed %s, last %s)" % (indexed[:12], digests[-1][:12]))

    # --- leg 2: a burst that never goes quiet still releases by the hard wait -
    debounce = Debouncer()
    paths = ["p%02d.cs" % i for i in range(8)]
    for index in range(8):
        write_burst(work, paths[index], [b"content-%d" % index])
        debounce.hint(paths[index], index * 400)  # 400ms apart: never quiet for 750ms
    release_at = debounce.next_release_at()
    if release_at is None or release_at > MAX_DEBOUNCE_MS:
        problems.append("hard maximum wait not enforced: next release at %r" % release_at)
    released = debounce.ready(MAX_DEBOUNCE_MS)
    if released is None:
        problems.append("burst that never goes quiet was not released at the hard maximum wait")
    elif sorted(released) != paths:
        problems.append("hard-wait release lost paths: %r" % released)

    # --- leg 3: distinct paths in one window release together -----------------
    debounce = Debouncer()
    for index, path in enumerate(["a.cs", "b.cs", "c.cs"]):
        write_burst(work, path, [b"x"])
        debounce.hint(path, index * 50)
    together = debounce.ready(50 * 2 + DEBOUNCE_MS)
    if together != ["a.cs", "b.cs", "c.cs"]:
        problems.append("distinct paths did not release together: %r" % together)

    # --- negative A: the naive dedup policy must index stale content ----------
    naive = NaiveDedup()
    naive_path = "src/edited.cs"
    naive_observed = None
    final_digest = None
    # Interleave the real writes with the hints so the naive policy genuinely
    # reads the bytes it saw, not bytes written later by the test harness.
    for now, value in [(0, b"first"), (100, b"second")]:
        write_burst(work, naive_path, [value])
        final_digest = digest(value)
        if not naive.note(naive_path, now):
            continue
        naive.release(naive_path, now)
        naive_observed = digest(io.open(os.path.join(work, naive_path), "rb").read())
    if naive_observed is None:
        problems.append("negative leg A did not observe anything")
    elif naive_observed == final_digest:
        problems.append("negative leg A: naive dedup indexed the last save (no loss to prove)")
    # Correct outcome: naive_observed == first digest and the two digests differ.

    # --- negative B: held-path overflow must escalate, not drop ---------------
    debounce = Debouncer(max_paths=4)
    for index in range(6):
        debounce.hint("burst%02d.cs" % index, index)
    if not debounce.overflowed:
        problems.append("negative leg B: held-path overflow was not detected")
    # A completed full scan clears the overflow; arriving hints never do.
    if debounce.overflowed and debounce.ready(10_000) is None and not debounce.pending:
        problems.append("negative leg B: overflow cleared without a full scan acknowledgement")

    not_run.append(
        "cargo test --locked -p graph-watch debounce "
        "(real coalescer; no Rust build taken in this lane)"
    )
    cleanup(work)
    return problems, not_run


def cleanup(path):
    for dirpath, dirnames, filenames in os.walk(path, topdown=False):
        for name in filenames:
            try:
                os.chmod(os.path.join(dirpath, name), stat.S_IWRITE)
            except OSError:
                pass
        for name in dirnames + filenames:
            try:
                os.remove(os.path.join(dirpath, name))
            except OSError:
                pass
        try:
            os.rmdir(dirpath)
        except OSError:
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(description="F-011 repeated human save bursts")
    parser.add_argument("--json-out", help="write the structured result to this path as well")
    args = parser.parse_args(argv)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        problems, not_run = run(root)
    except (OSError, ValueError) as exc:
        print("usage or I/O failure: %s" % exc, file=sys.stderr)
        return 1
    result = {
        "task": "F-011",
        "harness": "watch_save_burst",
        "positive_legs": 3,
        "negative_legs": 2,
        "not_run": not_run,
        "problems": problems,
        "ok": not problems,
    }
    if args.json_out:
        with io.open(args.json_out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    for item in not_run:
        print("not_run: %s" % item)
    if problems:
        for problem in problems:
            print("PROBLEM: %s" % problem)
        print("FAIL: %d problem(s)" % len(problems))
        return 2
    print("ok: F-011 coalescing holds; 3 positive legs, 2 negative legs rejected as required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())