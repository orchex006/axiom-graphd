#!/usr/bin/env python3
"""Failure-injection harness F-022 - SQLite upgrade and restore.

The durable state lives in one SQLite database, so the upgrade path is part of
the failure surface (docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md section 10,
graph-store::migrations, graph-store::backup):

* migrations are ordered and checksum-verified; a migration runs in its own
  transaction, so a failure rolls back and leaves the previous database usable;
* a database newer than the binary is refused, never downgraded;
* the pre-upgrade backup uses the SQLite backup API or a consistent equivalent
  (VACUUM INTO) and never copies only the .db file while WAL is active.

This harness runs the real SQLite engine through Python's sqlite3 module against
the real shipped DDL (docs/sqlite-schema-v1.sql) with WAL active. It performs a
real consistent backup, a real raw-file copy, and a real restore, so the
difference between them is measured, not asserted.

Positive legs:

* the shipped DDL applies cleanly and yields PRAGMA user_version = 1;
* a consistent backup taken with WAL frames outstanding includes every committed
  row, and restoring it preserves the schema version and integrity;
* a failing migration rolls back and leaves the database usable at its old
  version.

Negative legs (each must be rejected):

* a raw copy of only the .db file while WAL is active loses committed rows;
* a database newer than the binary (user_version 99) is refused;
* an applied migration whose checksum does not match the shipped SQL is refused.

Runtime baseline. The documented baseline needs a SQLite runtime with the
WAL-reset fix (>= 3.51.3). This host reports a different version; the harness
prints it and marks the version-baseline certification as not_run rather than
pretending it passed. The real Rust commands are recorded and reported as
not_run here:

    cargo test --locked -p graph-store migrations
    cargo test --locked -p graph-store backup

Exit codes: 0 every property held and every negative leg was rejected, 2 a
divergence, 1 a usage or I/O failure.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile

CURRENT_SCHEMA_VERSION = 1
REQUIRED_RUNTIME = (3, 51, 3)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def integrity(conn):
    return conn.execute("PRAGMA integrity_check").fetchone()[0]


def user_version(conn):
    return conn.execute("PRAGMA user_version").fetchone()[0]


class Refused(Exception):
    pass


def reconcile(conn, shipped):
    """Read-only check that the database matches the shipped migrations."""
    version = user_version(conn)
    if version > CURRENT_SCHEMA_VERSION:
        raise Refused("database schema %d is newer than this binary (%d)" % (version, CURRENT_SCHEMA_VERSION))
    applied = conn.execute(
        "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
    ).fetchall()
    versions = [row[0] for row in applied]
    if versions != list(range(1, len(applied) + 1)):
        raise Refused("applied migrations are not an ordered prefix: %r" % versions)
    for version_number, name, checksum in applied:
        if version_number > len(shipped):
            raise Refused("applied migration %d has no shipped definition" % version_number)
        expected = sha(shipped[version_number - 1]["sql"].encode("utf-8"))
        if checksum != expected:
            raise Refused("migration %d checksum mismatch" % version_number)
    if version != (max(versions) if versions else 0):
        raise Refused("user_version %d does not equal the highest applied migration" % version)
    return version


def open_db(path):
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def apply_shipped_ddl(conn, ddl):
    conn.executescript(ddl)
    conn.execute(
        "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES(1, ?, ?, ?)",
        ("v1", sha(ddl.encode("utf-8")), "2026-09-19T00:00:00Z"),
    )


def consistent_backup(source, destination):
    """VACUUM INTO: one self-contained file that includes committed WAL frames."""
    source.execute("VACUUM INTO ?", (destination,))


def restore_into(backup_path, target_path):
    """Stream a backup through the SQLite backup API into a fresh database."""
    src = open_db(backup_path)
    dst = open_db(target_path)
    src.backup(dst)
    dst.close()
    src.close()


def migration_failure_rolls_back(conn):
    """Apply a migration that fails partway; the transaction must roll back."""
    conn.execute("BEGIN")
    try:
        conn.execute("CREATE TABLE migration_v2_marker(x INTEGER)")
        conn.execute("INSERT INTO does_not_exist VALUES(1)")  # forces a failure
    except sqlite3.Error:
        conn.execute("ROLLBACK")
        return True
    conn.execute("COMMIT")
    return False


def run():
    problems = []
    not_run = []
    work = tempfile.mkdtemp(prefix="axiom-f022-")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ddl_path = os.path.join(root, "docs", "sqlite-schema-v1.sql")
    if not os.path.exists(ddl_path):
        raise IOError("shipped DDL is missing: %s" % ddl_path)
    with io.open(ddl_path, encoding="utf-8") as handle:
        ddl = handle.read()
    shipped = [{"version": 1, "name": "v1", "sql": ddl}]

    # --- leg 1: the shipped DDL applies and reports version 1 -----------------
    db = os.path.join(work, "main.db")
    conn = open_db(db)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = FULL")
    apply_shipped_ddl(conn, ddl)
    if user_version(conn) != CURRENT_SCHEMA_VERSION:
        problems.append("leg 1: user_version was %d, expected %d" % (user_version(conn), CURRENT_SCHEMA_VERSION))
    if integrity(conn) != "ok":
        problems.append("leg 1: integrity check was %r" % integrity(conn))
    try:
        reconcile(conn, shipped)
    except Refused as exc:
        problems.append("leg 1: reconcile refused a fresh database: %s" % exc)

    # --- leg 2: consistent backup with WAL frames outstanding, then restore ----
    conn.execute(
        "INSERT INTO solutions(id, workspace_instance_id, profile, config_hash, event_seq, full_scan_required)"
        " VALUES('sol-1','ws-1','default','h',1,0)"
    )
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # fold the schema into the main db
    conn.execute(
        "INSERT INTO audit_events(event_type, solution_id, actor, redacted_json, created_at)"
        " VALUES('checkpoint','sol-1','tester','{}','2026-09-19T00:00:00Z')"
    )
    wal_path = db + "-wal"
    if not os.path.exists(wal_path) or os.path.getsize(wal_path) == 0:
        problems.append("leg 2: no WAL frames were outstanding; the WAL case was not exercised")
    backup_path = os.path.join(work, "backup.db")
    consistent_backup(conn, backup_path)
    backup = open_db(backup_path)
    backup_rows = backup.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    if backup_rows != 1:
        problems.append("leg 2: consistent backup lost the WAL-committed row (%d rows)" % backup_rows)
    if integrity(backup) != "ok":
        problems.append("leg 2: backup integrity was %r" % integrity(backup))
    if user_version(backup) != CURRENT_SCHEMA_VERSION:
        problems.append("leg 2: backup schema version was %d" % user_version(backup))
    backup.close()
    restored_path = os.path.join(work, "restored.db")
    restore_into(backup_path, restored_path)
    restored = open_db(restored_path)
    if integrity(restored) != "ok":
        problems.append("leg 2: restored integrity was %r" % integrity(restored))
    restored_rows = restored.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    if restored_rows != 1:
        problems.append("leg 2: restore lost the row (%d rows)" % restored_rows)
    restored.close()

    # --- leg 3: a failing migration rolls back --------------------------------
    pre_version = user_version(conn)
    rolled_back = migration_failure_rolls_back(conn)
    if not rolled_back:
        problems.append("leg 3: the failing migration did not report a failure")
    if user_version(conn) != pre_version:
        problems.append("leg 3: user_version changed after a failed migration")
    present = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='migration_v2_marker'"
    ).fetchone()
    if present is not None:
        problems.append("leg 3: the failed migration left its table behind")

    # --- negative A: a raw .db copy with WAL active loses committed rows -------
    raw_path = os.path.join(work, "raw-copy.db")
    shutil.copyfile(db, raw_path)  # main file only; -wal is not copied
    raw = open_db(raw_path)
    raw_rows = raw.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    raw.close()
    if raw_rows == 1:
        problems.append("negative A: the raw copy kept the WAL row; the shortcut looked safe")
    if backup_rows != 1:
        problems.append("negative A: the consistent backup also lost the row")

    # --- negative B: a database newer than the binary is refused --------------
    newer = os.path.join(work, "newer.db")
    newer_conn = open_db(newer)
    apply_shipped_ddl(newer_conn, ddl)
    newer_conn.execute("PRAGMA user_version = 99")
    newer_conn.close()
    newer_conn = open_db(newer)
    try:
        reconcile(newer_conn, shipped)
        problems.append("negative B: a newer database was not refused")
    except Refused as exc:
        if "newer" not in str(exc):
            problems.append("negative B: refusal reason was %r" % str(exc))
    finally:
        newer_conn.close()

    # --- negative C: a checksum mismatch is refused --------------------------
    tampered = os.path.join(work, "tampered.db")
    tampered_conn = open_db(tampered)
    apply_shipped_ddl(tampered_conn, ddl)
    tampered_conn.execute("UPDATE schema_migrations SET checksum = 'deadbeef' WHERE version = 1")
    try:
        reconcile(tampered_conn, shipped)
        problems.append("negative C: a checksum mismatch was not refused")
    except Refused as exc:
        if "checksum" not in str(exc):
            problems.append("negative C: refusal reason was %r" % str(exc))
    finally:
        tampered_conn.close()

    conn.close()

    # --- runtime version baseline ---------------------------------------------
    runtime = tuple(int(part) for part in sqlite3.sqlite_version.split("."))
    print("runtime: sqlite3.sqlite_version = %s" % sqlite3.sqlite_version)
    if runtime < REQUIRED_RUNTIME:
        not_run.append(
            "runtime WAL-reset baseline: host sqlite %s < documented baseline %s; "
            "the patched-runtime leg cannot be certified on this host"
            % (sqlite3.sqlite_version, ".".join(str(part) for part in REQUIRED_RUNTIME))
        )
    not_run.append(
        "cargo test --locked -p graph-store migrations backup "
        "(real migration and backup code; no Rust build taken in this lane)"
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
    parser = argparse.ArgumentParser(description="F-022 SQLite upgrade and restore")
    parser.add_argument("--json-out", help="write the structured result to this path as well")
    args = parser.parse_args(argv)
    try:
        problems, not_run = run()
    except (OSError, ValueError, sqlite3.Error) as exc:
        print("usage or I/O failure: %s" % exc, file=sys.stderr)
        return 1
    result = {
        "task": "F-022",
        "harness": "sqlite_migration",
        "positive_legs": 3,
        "negative_legs": 3,
        "runtime_sqlite": sqlite3.sqlite_version,
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
    print("ok: F-022 migration and restore hold; 3 positive legs, 3 negative legs rejected as required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())