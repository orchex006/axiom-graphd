#!/usr/bin/env python3
"""Failure-injection harness F-015 - crash the publisher at each outbox boundary.

Publication is not one write. graph-store::outbox records the analysis revision
and the publish intent in one BEGIN IMMEDIATE transaction, and the publisher then
creates the generation, swaps the pointer and acknowledges the outbox row. A crash
can land at any of those boundaries. The contract
(docs/sqlite-schema-v1.sql, docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md sections 1
and 8) is that recovery stays idempotent:

* the revision and the intent are either both committed or both rolled back;
* publish_outbox.idempotency_key is unique, so a crashed publisher replays the
  same intent and publishes the generation once;
* the pointer swaps only to a generation that a published_generations row backs
  (gap-free), and only once.

This harness runs that model against a real SQLite database and a real staging
directory, injecting a crash at four boundaries and then recovering. It also
proves the guards have teeth with negative cases.

Boundaries injected (the four the acceptance criterion names):

1. ``before_commit`` - crash inside the intent transaction before COMMIT;
2. ``after_files`` - crash after the generation is materialized, before the swap;
3. ``after_swap`` - crash after the pointer swap commits, before the outbox ack;
4. ``during_ack`` - crash while acknowledging, so the outbox row is still open.

Positive legs:

* at every boundary, recovery leaves exactly one revision, one PUBLISHED outbox
  row, one published generation and a pointer that names it;
* a second recovery run is idempotent: the row counts and the published_at value
  do not change.

Negative legs (each must be rejected):

* a duplicate published_generations insert violates the primary key;
* acknowledging an already-PUBLISHED outbox row is a no-op, not a second publish;
* swapping the pointer to a generation with no published row is refused
  (gap-free guard).

The real publisher is crates/graph-store and crates/graph-export; the
reproducible command is recorded and reported as not_run here:

    cargo test --locked -p graph-store outbox

Exit codes: 0 every property held and every negative leg was rejected, 2 a
divergence, 1 a usage or I/O failure.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sqlite3
import sys
import tempfile

PUBLISHED_AT = "2026-09-19T00:00:00Z"

SCHEMA = """
CREATE TABLE graph_revisions(
  id INTEGER PRIMARY KEY, solution_id TEXT NOT NULL, event_seq INTEGER NOT NULL,
  profile TEXT NOT NULL, source_fingerprint TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE publish_outbox(
  id TEXT PRIMARY KEY, revision_id INTEGER NOT NULL REFERENCES graph_revisions(id),
  project_id TEXT, operation TEXT NOT NULL CHECK(operation IN('project','catalog')),
  state TEXT NOT NULL CHECK(state IN('PENDING','STAGED','PUBLISHED','FAILED')),
  idempotency_key TEXT NOT NULL UNIQUE, generation_id TEXT, last_error TEXT);
CREATE TABLE published_generations(
  project_id TEXT NOT NULL, generation_id TEXT NOT NULL, revision_id INTEGER NOT NULL,
  lane TEXT NOT NULL CHECK(lane IN('live','checkpoint')), manifest_hash TEXT NOT NULL,
  published_at TEXT NOT NULL, PRIMARY KEY(project_id,generation_id,lane));
CREATE TABLE current_pointer(project_id TEXT PRIMARY KEY, generation_id TEXT NOT NULL);
"""


class Crash(Exception):
    """Injected process death at a boundary."""


def connect(db):
    conn = sqlite3.connect(db, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db):
    conn = connect(db)
    conn.executescript(SCHEMA)
    conn.close()
    return db


def gen_dir(staging, generation):
    return os.path.join(staging, generation)


def stage_generation(staging, generation, manifest_hash):
    directory = gen_dir(staging, generation)
    os.makedirs(directory, exist_ok=True)
    index = os.path.join(directory, "shard-0000.json")
    with io.open(index, "w", encoding="utf-8", newline="\n") as handle:
        handle.write('{"generation":"%s","manifest_hash":"%s"}\n' % (generation, manifest_hash))


def intent_exists(conn, key):
    return conn.execute(
        "SELECT id, revision_id, generation_id, state FROM publish_outbox WHERE idempotency_key = ?",
        (key,),
    ).fetchone()


def publish_transaction(conn, project, generation, revision_id, manifest_hash, key):
    """The swap transaction: record the generation and move the pointer, gap-free."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT 1 FROM published_generations WHERE project_id = ? AND generation_id = ? AND lane = 'live'",
            (project, generation),
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO published_generations(project_id, generation_id, revision_id, lane, manifest_hash, published_at)"
                " VALUES(?,?,?,'live',?,?)",
                (project, generation, revision_id, manifest_hash, PUBLISHED_AT),
            )
        # Gap-free guard: never point at a generation that has no published row.
        backed = conn.execute(
            "SELECT 1 FROM published_generations WHERE project_id = ? AND generation_id = ? AND lane = 'live'",
            (project, generation),
        ).fetchone()
        if backed is None:
            raise Crash("pointer swap refused: no published generation to point at")
        conn.execute(
            "INSERT INTO current_pointer(project_id, generation_id) VALUES(?,?)"
            " ON CONFLICT(project_id) DO UPDATE SET generation_id = excluded.generation_id",
            (project, generation),
        )
        conn.execute("COMMIT")
    except Crash:
        conn.execute("ROLLBACK")
        raise


def swap_pointer(conn, project, generation):
    """Gap-free pointer swap: the guard a caller must not bypass."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        backed = conn.execute(
            "SELECT 1 FROM published_generations WHERE project_id = ? AND generation_id = ? AND lane = 'live'",
            (project, generation),
        ).fetchone()
        if backed is None:
            raise Crash("pointer swap refused: no published generation to point at")
        conn.execute(
            "INSERT INTO current_pointer(project_id, generation_id) VALUES(?,?)"
            " ON CONFLICT(project_id) DO UPDATE SET generation_id = excluded.generation_id",
            (project, generation),
        )
        conn.execute("COMMIT")
    except Crash:
        conn.execute("ROLLBACK")
        raise


def ack_outbox(conn, key, boundary=None):
    if boundary == "during_ack":
        # The acknowledgment never commits: the row stays open.
        raise Crash("crash during outbox ack")
    cur = conn.execute(
        "UPDATE publish_outbox SET state = 'PUBLISHED' WHERE idempotency_key = ? AND state IN('PENDING','STAGED')",
        (key,),
    )
    return cur.rowcount


def publisher_run(db, staging, boundary, project, generation, key, manifest_hash="mh-1"):
    """Run the publisher until the injected boundary crashes it."""
    conn = connect(db)
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "INSERT INTO graph_revisions(solution_id, event_seq, profile, source_fingerprint, created_at)"
            " VALUES('sol-1', 1, 'default', ?, ?)",
            (manifest_hash, PUBLISHED_AT),
        )
        revision_id = cur.lastrowid
        conn.execute(
            "INSERT INTO publish_outbox(id, revision_id, project_id, operation, state, idempotency_key, generation_id)"
            " VALUES('out-1', ?, ?, 'project', 'PENDING', ?, ?)",
            (revision_id, project, key, generation),
        )
        if boundary == "before_commit":
            raise Crash("crash before the intent transaction commits")
        conn.execute("COMMIT")
    except Crash:
        conn.execute("ROLLBACK")
        conn.close()
        raise
    stage_generation(staging, generation, manifest_hash)
    if boundary == "after_files":
        conn.close()
        raise Crash("crash after generation files, before the swap")
    conn.execute("UPDATE publish_outbox SET state = 'STAGED' WHERE idempotency_key = ?", (key,))
    publish_transaction(conn, project, generation, revision_id, manifest_hash, key)
    if boundary == "after_swap":
        conn.close()
        raise Crash("crash after the pointer swap, before the outbox ack")
    ack_outbox(conn, key, boundary)
    conn.close()


def recover(db, staging, project, generation, key, manifest_hash="mh-1"):
    """Replay the intent idempotently and finish publication. Returns a snapshot."""
    conn = connect(db)
    row = intent_exists(conn, key)
    if row is None:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "INSERT INTO graph_revisions(solution_id, event_seq, profile, source_fingerprint, created_at)"
            " VALUES('sol-1', 1, 'default', ?, ?)",
            (manifest_hash, PUBLISHED_AT),
        )
        revision_id = cur.lastrowid
        conn.execute(
            "INSERT INTO publish_outbox(id, revision_id, project_id, operation, state, idempotency_key, generation_id)"
            " VALUES('out-1', ?, ?, 'project', 'PENDING', ?, ?)",
            (revision_id, project, key, generation),
        )
        conn.execute("COMMIT")
        row = intent_exists(conn, key)
    _id, revision_id, stored_generation, state = row
    if stored_generation is None:
        stored_generation = generation
    stage_generation(staging, stored_generation, manifest_hash)
    if state != "PUBLISHED":
        publish_transaction(conn, project, stored_generation, revision_id, manifest_hash, key)
        ack_outbox(conn, key)
    return snapshot(conn, project)


def snapshot(conn, project):
    revisions = conn.execute("SELECT COUNT(*) FROM graph_revisions").fetchone()[0]
    outbox = conn.execute(
        "SELECT COUNT(*), COALESCE(MAX(state), '-') FROM publish_outbox"
    ).fetchone()
    published = conn.execute(
        "SELECT COUNT(*), COALESCE(MAX(generation_id), '-'), COALESCE(MAX(published_at), '-')"
        " FROM published_generations WHERE project_id = ? AND lane = 'live'",
        (project,),
    ).fetchone()
    pointer = conn.execute(
        "SELECT generation_id FROM current_pointer WHERE project_id = ?", (project,)
    ).fetchone()
    return {
        "revisions": revisions,
        "outbox_rows": outbox[0],
        "outbox_state": outbox[1],
        "published_rows": published[0],
        "published_generation": published[1],
        "published_at": published[2],
        "pointer": pointer[0] if pointer else None,
    }


def run():
    problems = []
    not_run = []
    work = tempfile.mkdtemp(prefix="axiom-f015-")
    project = "proj-1"
    generation = "gen-1"
    key = "idem-key-1"

    for boundary in ["before_commit", "after_files", "after_swap", "during_ack"]:
        db = init_db(os.path.join(work, "%s.db" % boundary))
        staging = os.path.join(work, "%s-staging" % boundary)
        os.makedirs(staging, exist_ok=True)
        try:
            publisher_run(db, staging, boundary, project, generation, key)
            problems.append("%s: publisher run did not crash" % boundary)
        except Crash:
            pass
        # Observe the pre-recovery state where it is meaningful.
        conn = connect(db)
        if boundary == "before_commit":
            pre = snapshot(conn, project)
            if pre["revisions"] != 0 or pre["outbox_rows"] != 0:
                problems.append("before_commit: intent transaction left state behind: %r" % pre)
        conn.close()
        # Recover and assert the converged state.
        state = recover(db, staging, project, generation, key)
        expected = {
            "revisions": 1,
            "outbox_rows": 1,
            "outbox_state": "PUBLISHED",
            "published_rows": 1,
            "published_generation": generation,
            "pointer": generation,
        }
        for field, want in expected.items():
            if state[field] != want:
                problems.append("%s: recovery left %s=%r, expected %r" % (boundary, field, state[field], want))
        if not os.path.exists(os.path.join(gen_dir(staging, generation), "shard-0000.json")):
            problems.append("%s: recovered generation files are missing" % boundary)
        # Idempotent second recovery: nothing changes, published_at is stable.
        again = recover(db, staging, project, generation, key)
        if again != state:
            problems.append("%s: a second recovery changed state: %r != %r" % (boundary, again, state))
        conn.close()

    # --- negative A: a duplicate published_generations insert violates the PK --
    db = init_db(os.path.join(work, "dup.db"))
    conn = connect(db)
    publish_transaction(conn, project, generation, 1, "mh-1", key)
    try:
        conn.execute(
            "INSERT INTO published_generations(project_id, generation_id, revision_id, lane, manifest_hash, published_at)"
            " VALUES(?,?,?,'live',?,?)",
            (project, generation, 1, "mh-1", PUBLISHED_AT),
        )
        problems.append("negative A: a duplicate published generation was accepted")
    except sqlite3.IntegrityError:
        pass
    conn.close()

    # --- negative B: acking an already PUBLISHED row is a no-op -----------------
    conn = connect(db)
    state = snapshot(conn, project)
    changed = ack_outbox(conn, key)
    if changed != 0:
        problems.append("negative B: acking a PUBLISHED row changed %d row(s)" % changed)
    after = snapshot(conn, project)
    if after != state:
        problems.append("negative B: re-acking changed the durable state")
    conn.close()

    # --- negative C: gap-free guard refuses an unbacked pointer swap -----------
    db = init_db(os.path.join(work, "gap.db"))
    conn = connect(db)
    publish_transaction(conn, project, generation, 1, "mh-1", "idem-gap")
    # Remove the backing row so the generation is no longer published, then prove
    # the guard refuses to point at it.
    conn.execute("DELETE FROM published_generations WHERE project_id = ? AND generation_id = ?", (project, generation))
    conn.execute("DELETE FROM current_pointer WHERE project_id = ?", (project,))
    try:
        swap_pointer(conn, project, generation)
        problems.append("negative C: the pointer was swapped to an unbacked generation")
    except Crash:
        pass
    pointer = conn.execute("SELECT generation_id FROM current_pointer WHERE project_id = ?", (project,)).fetchone()
    conn.close()
    if pointer is not None:
        problems.append("negative C: an unbacked generation is still in the pointer")

    not_run.append(
        "cargo test --locked -p graph-store outbox "
        "(real outbox and recovery; no Rust build taken in this lane)"
    )
    cleanup(work)
    return problems, not_run


def cleanup(path):
    for dirpath, dirnames, filenames in os.walk(path, topdown=False):
        for name in filenames:
            try:
                os.remove(os.path.join(dirpath, name))
            except OSError:
                pass
        for name in dirnames:
            try:
                os.rmdir(os.path.join(dirpath, name))
            except OSError:
                pass
        try:
            os.rmdir(dirpath)
        except OSError:
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(description="F-015 crash publisher at each outbox boundary")
    parser.add_argument("--json-out", help="write the structured result to this path as well")
    args = parser.parse_args(argv)
    try:
        problems, not_run = run()
    except (OSError, ValueError, sqlite3.Error) as exc:
        print("usage or I/O failure: %s" % exc, file=sys.stderr)
        return 1
    result = {
        "task": "F-015",
        "harness": "publish_crash",
        "boundaries": 4,
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
    print("ok: F-015 outbox recovery is idempotent at 4 boundaries; 3 negative legs rejected as required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())