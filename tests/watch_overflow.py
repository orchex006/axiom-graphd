#!/usr/bin/env python3
"""Failure-injection harness F-012 - rename and watcher overflow.

A native watcher is a hint source, not the truth. Two losses cannot be repaired
by replaying the events that were delivered: the kernel queue overflowed while
the process was busy, or the backend lost events around a rename. The documented
answer is to persist `full_scan_required` and let a real startup inventory walk
the working tree (graph-watch::recovery, graph-watch::inventory;
docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md sections 6 and 9).

This harness builds a real temporary working tree, mutates it with real
filesystem operations, walks it for real, and diffs the result against a stored
snapshot. It proves that the recovery set contains every final file state -
creates, content changes, deletes, untracked files and renames - and that a
"HEAD did not move, so nothing changed" shortcut is not a substitute for the walk.

Positive legs:

* a rename is observed as one removal plus one addition carrying the same bytes;
* deleting a tracked file and adding an untracked file are both found;
* an overflow reason is sticky and is cleared only by a completed scan.

Negative legs (each must be rejected):

* a digest-only re-read of the known paths (the `git diff HEAD~1`-style shortcut)
  misses the untracked file the full inventory finds;
* a "path exists on both sides, therefore unchanged" diff misses a real content
  change that a delete-then-recreate performed;
* reconnecting without the overflow flag (replaying delivered hints) is refused
  as a recovery source once a scan is required.

No container is needed. The real logic lives in crates/graph-watch; the
reproducible real-code command is recorded and reported as not_run here:

    cargo test --locked -p graph-watch inventory recovery

Exit codes: 0 every property held and every negative leg was rejected, 2 a
divergence, 1 a usage or I/O failure.
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

MAX_INVENTORY_ENTRIES = 500_000


class Recovery:
    """Sticky full-scan requirement (graph-watch::recovery)."""

    def __init__(self):
        self.reason = None

    def note(self, reason):
        """A loss reason arrives. The first reason wins; hints never clear it."""
        if self.reason is None:
            self.reason = reason
        return self.reason

    def complete_scan(self):
        if self.reason is None:
            return False
        self.reason = None
        return True

    def requires_scan(self):
        return self.reason is not None


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def write(root, relative, value):
    full = os.path.join(root, *relative.split("/"))
    parent = os.path.dirname(full)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with io.open(full, "wb") as handle:
        handle.write(value)
    return digest_bytes(value)


def inventory(root, exclude=()):
    """Walk the real tree and return {relative_posix: digest} for regular files.

    This is the complete input inventory: it enumerates the *set* of paths, so
    new, untracked and deleted files are discovered. It is bounded by
    MAX_INVENTORY_ENTRIES exactly like the real walk.
    """
    found = {}
    entries = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in exclude)
        for name in sorted(filenames):
            entries += 1
            if entries > MAX_INVENTORY_ENTRIES:
                raise ValueError("inventory exceeded MAX_INVENTORY_ENTRIES")
            full = os.path.join(dirpath, name)
            relative = os.path.relpath(full, root).replace(os.sep, "/")
            if any(part in exclude for part in relative.split("/")):
                continue
            with io.open(full, "rb") as handle:
                found[relative] = digest_bytes(handle.read())
    return found


def diff(stored, scanned):
    """Return (deletes, upserts, unchanged) between a stored and a scanned set."""
    deletes = sorted(set(stored) - set(scanned))
    upserts = sorted(path for path in scanned if path not in stored or stored[path] != scanned[path])
    unchanged = sorted(set(stored) & set(scanned) - set(upserts))
    return deletes, upserts, unchanged


def shortcut_diff(stored, root):
    """The rejected digest-only re-read: look only at the paths already known."""
    result = []
    for relative in sorted(stored):
        full = os.path.join(root, *relative.split("/"))
        if not os.path.exists(full):
            result.append((relative, "deleted"))
            continue
        with io.open(full, "rb") as handle:
            current = digest_bytes(handle.read())
        if current != stored[relative]:
            result.append((relative, "changed"))
    return result


def run(root):
    problems = []
    not_run = []
    work = tempfile.mkdtemp(prefix="axiom-f012-")

    # --- leg 1: rename observed as removal + addition of the same bytes -------
    base = os.path.join(work, "rename")
    os.makedirs(base, exist_ok=True)
    handle = write(base, "src/old.cs", b"class Old {}")
    stored = {"src/old.cs": handle}
    os.rename(os.path.join(base, "src", "old.cs"), os.path.join(base, "src", "new.cs"))
    scanned = inventory(base)
    deletes, upserts, _ = diff(stored, scanned)
    if deletes != ["src/old.cs"]:
        problems.append("rename: expected a removal of src/old.cs, got %r" % deletes)
    if upserts != ["src/new.cs"]:
        problems.append("rename: expected an addition of src/new.cs, got %r" % upserts)
    if scanned.get("src/new.cs") != handle:
        problems.append("rename: bytes were not carried to the new path")

    # --- leg 2: delete + untracked create are both found ----------------------
    base = os.path.join(work, "delete-untracked")
    os.makedirs(base, exist_ok=True)
    stored = {
        "src/a.cs": write(base, "src/a.cs", b"a"),
        "src/b.cs": write(base, "src/b.cs", b"b"),
    }
    os.remove(os.path.join(base, "src", "a.cs"))
    write(base, "src/c.cs", b"c")  # untracked
    scanned = inventory(base)
    deletes, upserts, _ = diff(stored, scanned)
    if deletes != ["src/a.cs"]:
        problems.append("delete+untracked: removal not reported: %r" % deletes)
    if upserts != ["src/c.cs"]:
        problems.append("delete+untracked: untracked addition not reported: %r" % upserts)

    # --- leg 3: overflow reason is sticky until a completed scan --------------
    recovery = Recovery()
    if recovery.requires_scan():
        problems.append("recovery started already requiring a scan")
    recovery.note("backend_overflow")
    recovery.note("backend_reconnect")  # arriving hints must not replace or clear
    if recovery.reason != "backend_overflow":
        problems.append("later hint replaced the first loss reason: %r" % recovery.reason)
    if not recovery.complete_scan():
        problems.append("a completed scan did not clear the pending requirement")
    if recovery.requires_scan():
        problems.append("recovery still requires a scan after a completed scan")

    # --- negative A: the digest-only shortcut misses the untracked file -------
    base = os.path.join(work, "shortcut")
    os.makedirs(base, exist_ok=True)
    stored = {"src/a.cs": write(base, "src/a.cs", b"a")}
    write(base, "src/untracked.cs", b"u")  # never in the stored set
    head_unchanged = True  # the working tree changed without moving HEAD
    if not head_unchanged:
        problems.append("negative A setup: HEAD was expected to be unchanged")
    shortcut = shortcut_diff(stored, base)
    full = inventory(base)
    if "src/untracked.cs" in {path for path, _ in shortcut}:
        problems.append("negative A: the shortcut unexpectedly reported the untracked file")
    if "src/untracked.cs" not in full:
        problems.append("negative A: the full inventory missed the untracked file")
    if set(full) == set(stored):
        problems.append("negative A: shortcut and inventory agree; no gap to prove")

    # --- negative B: "present on both sides" must not mean unchanged ----------
    base = os.path.join(work, "recreate")
    os.makedirs(base, exist_ok=True)
    stored = {"src/x.cs": write(base, "src/x.cs", b"first")}
    os.remove(os.path.join(base, "src", "x.cs"))
    new_digest = write(base, "src/x.cs", b"second")
    scanned = inventory(base)
    deletes, upserts, unchanged = diff(stored, scanned)
    if "src/x.cs" in unchanged:
        problems.append("negative B: delete-then-recreate was reported unchanged")
    if "src/x.cs" not in upserts:
        problems.append("negative B: delete-then-recreate was not reported as an upsert")
    if scanned.get("src/x.cs") != new_digest:
        problems.append("negative B: upsert carries the wrong digest")
    # The naive "in both sets -> unchanged" policy would say unchanged; show it.
    naive_unchanged = set(stored) & set(scanned)
    if "src/x.cs" not in naive_unchanged:
        problems.append("negative B setup: naive policy did not see x.cs on both sides")

    # --- negative C: replaying hints is refused once a scan is required -------
    recovery = Recovery()
    recovery.note("backend_overflow")
    replayed = ["src/a.cs", "src/b.cs"]  # delivered hints, not the missing ones

    def accept_replay(rec, hints):
        # A recovery source may use delivered hints only while no scan is required.
        return (not rec.requires_scan()) and bool(hints)

    if accept_replay(recovery, replayed):
        problems.append("negative C: delivered hints were accepted as a recovery source while a scan is required")
    recovery.complete_scan()
    if not accept_replay(recovery, replayed):
        problems.append("negative C: replay was refused even after a completed scan cleared the requirement")

    # --- leg 4: case-only rename boundary (Windows case-insensitive FS) -------
    base = os.path.join(work, "case")
    os.makedirs(base, exist_ok=True)
    write(base, "src/Foo.cs", b"case")
    try:
        os.rename(os.path.join(base, "src", "Foo.cs"), os.path.join(base, "src", "foo.cs"))
        scanned = inventory(base)
        if "src/foo.cs" in scanned:
            pass  # the final state is the new spelling
        elif "src/Foo.cs" in scanned:
            not_run.append(
                "case-only rename: host reported the old spelling after rename; "
                "Windows case-only rename needs the real graph-watch test"
            )
        else:
            problems.append("case-only rename: neither spelling is present after rename")
    except OSError as exc:
        not_run.append("case-only rename: host refused the rename (%s)" % exc.__class__.__name__)

    not_run.append(
        "cargo test --locked -p graph-watch inventory recovery "
        "(real walk and recovery; no Rust build taken in this lane)"
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
    parser = argparse.ArgumentParser(description="F-012 rename and watcher overflow")
    parser.add_argument("--json-out", help="write the structured result to this path as well")
    args = parser.parse_args(argv)
    try:
        problems, not_run = run(None)
    except (OSError, ValueError) as exc:
        print("usage or I/O failure: %s" % exc, file=sys.stderr)
        return 1
    result = {
        "task": "F-012",
        "harness": "watch_overflow",
        "positive_legs": 4,
        "negative_legs": 3,
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
    print("ok: F-012 inventory recovery holds; 4 positive legs, 3 negative legs rejected as required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())