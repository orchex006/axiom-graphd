# Cross-component failure-injection harnesses (F-011 - F-022)

Owner: `axiom-graphd`. These are component-local failure-injection harnesses, not
shared contract fixtures and not replacements for the Rust test suite in
`crates/*/tests/`. Each one is a standalone Python 3 program with no third-party
dependencies, no network access and no shell interpolation.

They inject the failure boundaries the F work package names, model the documented
contract honestly, and exit non-zero when a property does not hold. Where a leg
needs a real Rust binary or an unprivileged host cannot produce the condition,
the leg is reported as `not_run` with the reason printed and the reproducible
`cargo test` command kept in the file. No harness claims to have run something it
did not.

## Harnesses

| Task | File | Boundary injected |
| --- | --- | --- |
| F-011 | `tests/watch_save_burst.py` | repeated human save bursts and coalescing |
| F-012 | `tests/watch_overflow.py` | rename and watcher/notification overflow |
| F-013 | `tests/queue_crash.py` | worker crash before and after acknowledgment |
| F-014 | `tests/queue_concurrent_edit.py` | an edit that lands while a worker parses |
| F-015 | `tests/publish_crash.py` | publisher crash at each outbox boundary |
| F-018 | `tests/storage_failure.py` | disk-full and permission errors |
| F-021 | `tests/git_checkpoint.py` | staged and merged checkpoint accuracy |
| F-022 | `tests/sqlite_migration.py` | SQLite upgrade, backup and restore |

## Running

```bash
python tests/watch_save_burst.py
python tests/watch_overflow.py
python tests/queue_crash.py
python tests/queue_concurrent_edit.py
python tests/publish_crash.py
python tests/storage_failure.py
python tests/git_checkpoint.py
python tests/sqlite_migration.py
```

Each accepts `--json-out PATH` to also write a machine-readable result. Exit
codes are consistent across the set:

* `0` every property held and every negative leg was rejected;
* `2` at least one divergence (the failing message is printed as `PROBLEM:`);
* `1` a usage or I/O failure.

## What is real and what is modelled

* **Real filesystem, real SQLite, real Git.** F-011, F-012, F-018 use a real
  temporary tree and real bytes; F-015 and F-022 run the real SQLite engine
  (WAL, `VACUUM INTO`, the backup API); F-021 launches the real `git` program as
  program plus argv, exactly like `fixtures/git/driver.py`.
* **Modelled state machines.** F-013 and F-014 model the documented queue and
  generation policies from `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` and the
  `graph-watch` / `graph-queue` module contracts. They do not link the Rust
  crates; the equivalent real-code command is recorded in each file and reported
  under `not_run`.
* **Honest limitations.** The disk-full leg of F-018 is an injected fault because
  a real full filesystem needs a loopback/quota mount or an admin tool. F-022
  reports the host SQLite runtime and marks the WAL-reset baseline `not_run` when
  the host is below the documented minimum. The case-only rename leg of F-012 and
  the case-only workspace behaviour depend on the host filesystem.

## Scope

These harnesses do not modify the repository, do not take a Docker container and
do not push anything. They are read-only checks over temporary state.