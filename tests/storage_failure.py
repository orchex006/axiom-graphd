#!/usr/bin/env python3
"""Failure-injection harness F-018 - disk-full and permissions errors.

Storage fails in two ways that must not be confused: the volume is full (ENOSPC)
and the process is not allowed to write (EACCES). graph-store::storage_error maps
both to a bounded, retryable classification, and the publication rule
(docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md section 1, section 8;
graph-export::staging) is that a failed write never advances the pointer and never
destroys the current snapshot. The failure must stay visible in the queue/outbox
and in the user-facing error so recovery information survives.

This harness performs a real permission-denied write on this host (a read-only
file), injects a disk-full write, and checks the outcome against the database
model. A real full filesystem cannot be produced portably without administrator
privileges or a loopback mount, so the disk-full leg is an honest injected fault
and its real-filesystem counterpart is reported as not_run with the reason:

    real ENOSPC injection: needs a loopback/quota mount or an admin tool; not
    available on this unprivileged Windows host.

Positive legs:

* a real permission-denied write is surfaced and leaves the pointer untouched;
* an injected disk-full write leaves the current snapshot intact and records a
  retryable failure with recovery information;
* a short write is refused by the byte-count guard.

Negative legs (each must be rejected):

* a writer that swallows the failure and reports success must not be allowed to
  advance the pointer (the guard refuses);
* an inventory that silently drops a permission-denied entry is refused: the
  denial must be recorded and the scan reported incomplete.

The real logic is crates/graph-store and crates/graph-export; the reproducible
command is recorded and reported as not_run here:

    cargo test --locked -p graph-store storage_error
    cargo test --locked -p graph-export staging

Exit codes: 0 every property held and every negative leg was rejected, 2 a
divergence, 1 a usage or I/O failure.
"""
from __future__ import annotations

import argparse
import errno
import io
import json
import os
import stat
import sys
import tempfile

RETRYABLE = {"disk-full", "permission-denied", "io-transient"}


class StorageFault(Exception):
    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def classify(exc):
    if isinstance(exc, PermissionError):
        return "permission-denied", str(exc)
    if isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
        return "disk-full", str(exc)
    return "io-transient", str(exc)


class Outbox:
    """Minimal durable model: one intent row plus the published pointer."""

    def __init__(self):
        self.row = None
        self.pointer = None

    def record_failure(self, code, detail):
        self.row = {"state": "FAILED", "last_error_code": code, "last_error": detail}

    def record_success(self, generation):
        self.row = {"state": "PUBLISHED", "last_error_code": None, "last_error": None}
        self.pointer = generation


class Writer:
    """A writer that writes real bytes, or injects a fault on request."""

    def __init__(self, mode="ok", fail_after=None, path=None):
        self.mode = mode
        self.fail_after = fail_after
        self.path = path

    def write(self, path, data):
        if self.mode == "enospc":
            raise OSError(errno.ENOSPC, "No space left on device (injected)")
        if self.mode == "short":
            with io.open(path, "wb") as handle:
                handle.write(data[: max(1, len(data) // 2)])
            raise OSError(errno.ENOSPC, "No space left on device mid-write (injected)")
        if self.mode == "swallow":
            # The rejected writer: it fails, swallows the error and claims success.
            with io.open(path, "wb") as handle:
                handle.write(data[: max(1, len(data) // 2)])
            return  # no exception
        if self.mode == "readonly":
            # Real permission denied: open a read-only file for writing.
            with io.open(path, "wb") as handle:
                handle.write(data)
            return
        with io.open(path, "wb") as handle:
            handle.write(data)


def publish(outbox, project, generation, staging, writer, payload, verify_bytes=True):
    """Write the generation, verify it, then swap the pointer. Returns ok bool."""
    target = os.path.join(staging, "%s.shard" % generation)
    try:
        writer.write(target, payload)
    except (OSError, PermissionError) as exc:
        code, detail = classify(exc)
        outbox.record_failure(code, detail)
        return False
    if verify_bytes:
        actual = os.path.getsize(target) if os.path.exists(target) else 0
        if actual != len(payload):
            outbox.record_failure("disk-full", "short write: %d of %d bytes" % (actual, len(payload)))
            return False
    outbox.record_success(generation)
    return True


class InventoryWalk:
    """Walk a directory, recording a denial instead of silently skipping it."""

    def __init__(self, denied=()):
        self.denied = tuple(denied)
        self.entries = []

    def scan(self, root):
        complete = True
        denied = []
        for dirpath, dirnames, filenames in os.walk(root):
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                if full in self.denied:
                    complete = False
                    denied.append({"path": full, "reason": "permission_denied"})
                    continue
                self.entries.append(full)
        return {"entries": self.entries, "denied": denied, "complete": complete}


def silent_inventory(root, denied):
    """The rejected inventory: it skips denied entries and still claims complete."""
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if full in denied:
                continue
            entries.append(full)
    return {"entries": entries, "denied": [], "complete": True}


def run():
    problems = []
    not_run = []
    work = tempfile.mkdtemp(prefix="axiom-f018-")
    staging = os.path.join(work, "staging")
    os.makedirs(staging, exist_ok=True)
    payload = b"x" * 4096
    project = "proj-1"

    # --- leg 1: a real permission-denied write --------------------------------
    outbox = Outbox()
    outbox.pointer = "gen-previous"
    target = os.path.join(staging, "gen-denied.shard")
    with io.open(target, "wb") as handle:
        handle.write(payload)
    os.chmod(target, stat.S_IREAD)
    real_writer = Writer(mode="readonly")
    try:
        with io.open(target, "wb") as handle:
            handle.write(payload)
        problems.append("leg 1: the read-only write unexpectedly succeeded")
    except PermissionError as exc:
        code, detail = classify(exc)
        outbox.record_failure(code, detail)
        if code != "permission-denied":
            problems.append("leg 1: classification was %r, expected permission-denied" % code)
    finally:
        os.chmod(target, stat.S_IWRITE)
    if outbox.pointer != "gen-previous":
        problems.append("leg 1: a denied write moved the pointer to %r" % outbox.pointer)
    if outbox.row is None or outbox.row["state"] != "FAILED":
        problems.append("leg 1: the failure was not recorded in the outbox")
    if outbox.row and outbox.row["last_error_code"] not in RETRYABLE:
        problems.append("leg 1: the failure is not classified retryable")

    # --- leg 2: an injected disk-full write -----------------------------------
    outbox = Outbox()
    outbox.pointer = "gen-previous"
    ok = publish(outbox, project, "gen-full", staging, Writer(mode="enospc"), payload)
    if ok:
        problems.append("leg 2: an injected disk-full write reported success")
    if outbox.pointer != "gen-previous":
        problems.append("leg 2: a disk-full write moved the pointer to %r" % outbox.pointer)
    if outbox.row is None or outbox.row["last_error_code"] != "disk-full":
        problems.append("leg 2: the disk-full failure was not recorded: %r" % outbox.row)
    if outbox.row and outbox.row["last_error_code"] not in RETRYABLE:
        problems.append("leg 2: the disk-full failure is not retryable")

    # --- leg 3: a short write is refused by the byte-count guard --------------
    outbox = Outbox()
    outbox.pointer = "gen-previous"
    ok = publish(outbox, project, "gen-short", staging, Writer(mode="short"), payload)
    if ok:
        problems.append("leg 3: a short write was accepted")
    if outbox.pointer != "gen-previous":
        problems.append("leg 3: a short write moved the pointer to %r" % outbox.pointer)

    # --- negative A: a swallowing writer must not advance the pointer ---------
    outbox = Outbox()
    outbox.pointer = "gen-previous"
    ok = publish(outbox, project, "gen-swallow", staging, Writer(mode="swallow"), payload)
    if ok:
        problems.append("negative A: the guard accepted a swallowed failure")
    if outbox.pointer != "gen-previous":
        problems.append("negative A: a swallowed failure moved the pointer to %r" % outbox.pointer)
    # Show the naive policy (no byte verification) would have accepted it.
    naive = Outbox()
    naive.pointer = "gen-previous"
    naive_ok = publish(naive, project, "gen-swallow", staging, Writer(mode="swallow"), payload, verify_bytes=False)
    if not naive_ok or naive.pointer != "gen-swallow":
        problems.append("negative A: the naive policy did not accept it; no teeth")

    # --- negative B: an inventory that silently drops a denial is refused -----
    denied_file = os.path.join(work, "locked.cs")
    with io.open(denied_file, "w", encoding="utf-8") as handle:
        handle.write("class Locked {}\n")
    honest = InventoryWalk(denied=[denied_file]).scan(work)
    if honest["complete"]:
        problems.append("negative B: the honest inventory claimed complete with a denial present")
    if not honest["denied"] or honest["denied"][0]["reason"] != "permission_denied":
        problems.append("negative B: the denial was not recorded")
    silent = silent_inventory(work, [denied_file])
    if silent["denied"] or not silent["complete"]:
        problems.append("negative B: the silent policy is actually honest; no teeth")
    if denied_file in honest["entries"]:
        problems.append("negative B: a denied file was also listed as indexed")

    not_run.append(
        "real ENOSPC injection: needs a loopback/quota mount or an admin tool; not available "
        "on this unprivileged Windows host (the disk-full leg above is an injected fault)"
    )
    not_run.append(
        "cargo test --locked -p graph-store storage_error; cargo test --locked -p graph-export staging "
        "(real storage classification; no Rust build taken in this lane)"
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
    parser = argparse.ArgumentParser(description="F-018 disk-full and permissions errors")
    parser.add_argument("--json-out", help="write the structured result to this path as well")
    args = parser.parse_args(argv)
    try:
        problems, not_run = run()
    except (OSError, ValueError) as exc:
        print("usage or I/O failure: %s" % exc, file=sys.stderr)
        return 1
    result = {
        "task": "F-018",
        "harness": "storage_failure",
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
    print("ok: F-018 storage failures stay visible and reversible; 3 positive legs, 2 negative legs rejected as required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())