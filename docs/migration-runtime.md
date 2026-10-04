# Public migration runtime — K-310

The public `axiom migrate` entrypoint now composes the existing migration engine.
`plan` returns `status: ready` for a valid supported input, rather than the old
unimplemented `NOT_READY` response. Run it from the repository being migrated.

```text
axiom migrate plan --solution demo-solution --from auto --to-layout 2 --out migration-plan.json --json
axiom migrate apply --plan migration-plan.json --approve-digest <plan_digest> --json
axiom migrate status --transaction <transaction> --json
axiom migrate rollback --transaction <transaction> --approve-digest <plan_digest> --json
```

The supported operation is `immutable_graph_import`: verified graph generation,
catalog and pointer bytes from either legacy `graph` or `grahp` spelling are
copied into `.axiom/graph`. The plan shows the absolute repository binding,
unchanged solution ID, exact source and destination hashes, target layout/core,
space estimate, expiry, transaction and approval digest. A fresh repository has
`migration_needed: false`; applying that plan records a no-op transaction.

Legacy files and unrelated human content stay intact. This operation does not
copy a runtime database, regenerate an unsupported legacy format, replace host
settings or rewrite instructions. Legacy managed instructions need a separate
ownership-reviewed plan and currently produce a conflict. Conflicting targets,
different graph/grahp content, unknown graph files, corrupt/missing generations,
incompatible schemas, links/junctions, path aliases, stale plans and different
repositories/builds are refused rather than adopted.

Apply holds the daemon's actual native ownership claim plus graph/transaction
guards. It stages all bytes and publishes current pointers after their immutable
generations. Journals live in the owner-private `AXIOM_HOME` migration transaction
directory. Resume and idempotency use the recorded hashes; rollback reports a
partial/refused recovery if later human edits prevent restoring/removing an
owned file. Legacy cleanup is a separate operation and is never automatic.

## Native reproduction

`tests/native/capture_migration_k310.py` launches the actual executable against
the hash-pinned, engine-produced K-302 source graph fixture. It checks fresh
plan/apply/status/rollback, both spellings, equal/conflicting inputs, stale
approval/source/target, native staging failure/resume, human-edited rollback,
unsafe links/junctions and actual native writer contention. No product command
runs as guest root; Linux evidence records the WSL2 environment, not a container.

For Mac Intel, checkout the exact source revision recorded by K-310's handoff,
build the CLI with the recorded Rust toolchain and run:

```text
python3 tests/native/capture_migration_k310.py --cli /absolute/path/to/axiom --fixture /absolute/path/to/real-source-fixture.tar --fixture-sha256 095d36a3db66f81b3db8df8d96e4f312c6ea5e91e80ccb6bc635d6538522fade --out /absolute/new/evidence-directory --scratch /absolute/task-owned/scratch
```

Mac execution remains `not_run` until this native run exists. These are unsigned
development builds. Existing immutable release artifacts and installed user
versions are not overwritten by the test harness.

## K-607 native CI completion

Current public readiness requires the K-310 executable harness on actual Windows x64, Linux x64 and Mac Intel GitHub runners at the chosen source revision. Mac ARM remains deferred. This augments the immutable K-310 historical handoff without relabeling its unrun Mac record. Fresh native reports are emitted as CI artifacts; certification is not required.
