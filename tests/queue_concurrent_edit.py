#!/usr/bin/env python3
"""Failure-injection harness F-014 - edit a file while a worker parses it.

A file can be saved again while its previous bytes are still being analysed. If
the analyzer then cleared a boolean dirty flag, the second edit would be lost.
The contract prevents this with monotonic generations
(graph-watch::dirty, graph-queue::ack, docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md
section 3):

* every file carries a desired_generation that only increases;
* a result names the generation the worker actually read and is committed
  against that generation, even if a newer edit has arrived meanwhile;
* because desired_generation is then still ahead, the file remains dirty and the
  next batch analyses the newer generation.

So the interesting property is not "the older result was rejected". It is that
the older result commits without ever being mistaken for the latest content.

This harness models one file row with real content digests and replays an edit
that lands mid-parse. The reproducible real-code command is recorded and
reported as not_run here:

    cargo test --locked -p graph-watch dirty
    cargo test --locked -p graph-queue ack

Positive legs:

* an edit that lands mid-parse leaves desired_generation ahead after the older
  result commits, so the file stays dirty;
* the next batch analyses the latest generation and the indexed hash then equals
  the digest of the latest saved content;
* an edit that lands exactly at the commit instant is still not lost.

Negative legs (each must be rejected):

* the naive "delete the dirty marker without checking the generation" policy is
  shown to call a file clean while it still has unindexed content;
* a result claiming a generation the worker never read is refused;
* committing a generation that is not newer than the indexed one is refused;
* a content-hash-only dirty check is shown to call a reverted file clean even
  though a newer generation is outstanding.

Exit codes: 0 every property held and every negative leg was rejected, 2 a
divergence, 1 a usage or I/O failure.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys

MAX_GENERATION = 2 ** 63 - 1


def sha(data):
    return hashlib.sha256(data).hexdigest()


class FileRow:
    """One durable file row: the in-memory mirror of graph-watch::dirty."""

    def __init__(self, path, indexed_generation=0, indexed_hash=None, desired_generation=None):
        self.path = path
        self.indexed_generation = indexed_generation
        self.indexed_hash = indexed_hash
        self.content_hash = indexed_hash
        # Seed the outstanding generation so a scenario can start mid-life.
        self.desired_generation = indexed_generation if desired_generation is None else desired_generation

    def bump(self, data):
        """A change hint requiring inspection: desired generation advances."""
        if self.desired_generation >= MAX_GENERATION:
            raise ValueError("generation budget exhausted for %s" % self.path)
        self.desired_generation += 1
        self.content_hash = sha(data)
        return self.desired_generation

    def read(self):
        """A worker snapshots the generation and bytes it will analyse."""
        return self.desired_generation, self.content_hash

    def is_dirty(self):
        """The generation rule: dirty when a newer generation is outstanding."""
        return self.desired_generation > self.indexed_generation


def commit(row, read_generation, target_generation, analysed_hash):
    """Model graph-queue::ack plus the durable file-row write.

    Returns (accepted, reason). The result is committed against the generation
    the worker read; the row stays dirty when desired_generation is still ahead.
    """
    if target_generation != read_generation:
        return False, "generation-not-read(read=%d,target=%d)" % (read_generation, target_generation)
    if target_generation <= row.indexed_generation:
        return False, "not-newer(indexed=%d,target=%d)" % (row.indexed_generation, target_generation)
    row.indexed_generation = target_generation
    row.indexed_hash = analysed_hash
    return True, "indexed=%d dirty=%s" % (target_generation, row.desired_generation > target_generation)


class NaiveTracker:
    """The rejected policy: a boolean dirty flag with an unconditional delete."""

    def __init__(self):
        self.dirty = set()

    def bump(self, path):
        self.dirty.add(path)

    def ack(self, path):
        # DELETE dirty_files WHERE path = ? - with no generation check.
        self.dirty.discard(path)

    def is_clean(self, path):
        return path not in self.dirty


def run():
    problems = []
    not_run = []

    # --- leg 1: edit mid-parse; the older result commits and stays dirty ------
    row = FileRow("src/handler.cs", indexed_generation=40, indexed_hash=sha(b"v40"))
    first = b"v41"
    row.bump(first)
    if row.desired_generation != 41:
        problems.append("bump did not advance to generation 41")
    read_generation, analysed_hash = row.read()
    if (read_generation, analysed_hash) != (41, sha(first)):
        problems.append("worker snapshot was %r, expected (41, digest(v41))" % ((read_generation, analysed_hash),))
    second = b"v42"
    row.bump(second)  # the human saves again while the worker parses 41
    accepted, reason = commit(row, read_generation, read_generation, analysed_hash)
    if not accepted:
        problems.append("leg 1: the generation-41 result was refused: %s" % reason)
    if row.indexed_generation != 41:
        problems.append("leg 1: indexed generation was %d, expected 41" % row.indexed_generation)
    if not row.is_dirty():
        problems.append("leg 1: file was declared clean after committing the older generation")
    if row.desired_generation != 42:
        problems.append("leg 1: desired generation was %d, expected 42" % row.desired_generation)
    if row.indexed_hash == sha(second):
        problems.append("leg 1: indexed hash equals the unanalysed latest content")

    # --- leg 2: the next batch indexes the latest content ---------------------
    read_generation, analysed_hash = row.read()
    if (read_generation, analysed_hash) != (42, sha(second)):
        problems.append("leg 2: next batch snapshot was %r, expected (42, digest(v42))" % ((read_generation, analysed_hash),))
    accepted, reason = commit(row, read_generation, read_generation, analysed_hash)
    if not accepted:
        problems.append("leg 2: the generation-42 result was refused: %s" % reason)
    if row.is_dirty():
        problems.append("leg 2: file is still dirty after indexing the latest generation")
    if row.indexed_hash != sha(second):
        problems.append("leg 2: indexed hash is not the latest saved content")

    # --- leg 3: an edit exactly at the commit instant is not lost -------------
    row = FileRow("src/exact.cs", indexed_generation=10, indexed_hash=sha(b"e10"))
    row.bump(b"e11")
    read_generation, analysed_hash = row.read()
    # The write and the commit interleave at the same generation boundary: the
    # newer generation is observed before the result is applied.
    row.bump(b"e12")
    accepted, _ = commit(row, read_generation, read_generation, analysed_hash)
    if not accepted:
        problems.append("leg 3: the generation-11 result was refused")
    if not row.is_dirty():
        problems.append("leg 3: an edit at the commit instant was lost")
    if row.indexed_hash != sha(b"e11"):
        problems.append("leg 3: the committed hash is not the generation that was read")

    # --- negative A: the naive boolean flag declares a dirty file clean -------
    row = FileRow("src/naive.cs", indexed_generation=5, indexed_hash=sha(b"n5"))
    naive = NaiveTracker()
    row.bump(b"n6")
    naive.bump(row.path)
    read_generation, analysed_hash = row.read()
    row.bump(b"n7")   # a second edit lands while the worker parses n6
    naive.bump(row.path)
    commit(row, read_generation, read_generation, analysed_hash)  # ack generation 6
    naive.ack(row.path)  # the naive ack deletes the whole dirty marker
    if not row.is_dirty():
        problems.append("negative A setup: the real rule said clean")
    if not naive.is_clean(row.path):
        problems.append("negative A: the naive policy did not claim the file clean (no teeth)")
    if row.indexed_hash == row.content_hash:
        problems.append("negative A: the unindexed content was somehow indexed")

    # --- negative B: a generation the worker never read is refused ------------
    row = FileRow("src/unread.cs", indexed_generation=1, indexed_hash=sha(b"u1"))
    row.bump(b"u2")  # desired = 2
    accepted, reason = commit(row, read_generation=2, target_generation=3, analysed_hash=sha(b"u3"))
    if accepted:
        problems.append("negative B: a generation the worker never read was committed")
    if "generation-not-read" not in reason:
        problems.append("negative B: refusal reason was %r" % reason)
    if row.indexed_generation != 1:
        problems.append("negative B: a refused commit advanced indexed_generation")

    # --- negative C: a non-newer generation is refused ------------------------
    row = FileRow("src/regress.cs", indexed_generation=7, indexed_hash=sha(b"r7"), desired_generation=8)
    accepted, reason = commit(row, read_generation=7, target_generation=7, analysed_hash=sha(b"r7"))
    if accepted:
        problems.append("negative C: a non-newer generation was committed")
    if "not-newer" not in reason:
        problems.append("negative C: refusal reason was %r" % reason)

    # --- negative D: a content-hash-only check calls a reverted file clean ----
    row = FileRow("src/revert.cs", indexed_generation=41, indexed_hash=sha(b"same"))
    row.bump(b"same")  # desired = 42, content hash unchanged
    row.bump(b"same")  # desired = 43, content hash unchanged again
    hash_only_clean = (row.indexed_hash == row.content_hash)
    if not hash_only_clean:
        problems.append("negative D setup: hash-only check did not report clean")
    if not row.is_dirty():
        problems.append("negative D: the generation rule also said clean")
    if row.desired_generation <= row.indexed_generation:
        problems.append("negative D: no outstanding generation to prove")

    not_run.append(
        "cargo test --locked -p graph-watch dirty; cargo test --locked -p graph-queue ack "
        "(real generations and ack; no Rust build taken in this lane)"
    )
    return problems, not_run


def main(argv=None):
    parser = argparse.ArgumentParser(description="F-014 edit files while a worker parses")
    parser.add_argument("--json-out", help="write the structured result to this path as well")
    args = parser.parse_args(argv)
    try:
        problems, not_run = run()
    except (OSError, ValueError) as exc:
        print("usage or I/O failure: %s" % exc, file=sys.stderr)
        return 1
    result = {
        "task": "F-014",
        "harness": "queue_concurrent_edit",
        "positive_legs": 3,
        "negative_legs": 4,
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
    print("ok: F-014 dirty generations hold; 3 positive legs, 4 negative legs rejected as required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())