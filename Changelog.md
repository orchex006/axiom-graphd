# Changelog — axiom-graphd

## Unreleased

V2 seed adopts `2.0.0-draft.1`, `.axiom` workspace layout and component-owned docs/tests. Runtime implementation and platform certification are pending.

### store-and-registration (B-011 - B-020)

- **B-011** - single writer actor: `graph-store::writer` serializes worker mutations through one bounded queue, applies each in its own short `BEGIN IMMEDIATE` transaction, rolls a failed mutation back alone, and reports `Backpressure { depth, capacity }` instead of growing without limit.
- **B-012** - solution instance registration: `graph-store::solutions` derives a stable `inst-` key from the normalized worktree root and profile, so two worktrees or profiles never share a mutable database, and records `solutions` rows with `full_scan_required` on first use.
- **B-013** - project membership validation: `graph-core::solution` refuses duplicate project ids and overlapping source or generated-output claims by whole path segment, while allowing two projects in one repository.
- **B-014** - trusted repository bindings: `graph-core::bindings` resolves a catalog `repo_id` only through an operator-provided absolute binding, refusing relative roots, `..` traversal and symlink escape out of the bound root.
- **B-015** - inventory and tombstones: `graph-store::files` advances `desired_generation` for new, changed and deleted paths, writes a tombstone instead of a clean row for a vanished file, and acknowledges a result only against the generation it analyzed.
- **B-016** - graph rows: `graph-store::graph_rows` replaces facts by `owner_file_id`, so another file's nodes and edges survive, and rewrites incoming references to a removed node as explicit `unresolved` edges.
- **B-017** - reverse index: `graph-store::reverse_index` answers incoming-reference queries across project boundaries inside a solution and returns `NotIndexed` with coverage instead of an empty "no callers" when the scope is not covered.
- **B-018** - consistent backup: `graph-store::backup` takes backups with `VACUUM INTO` and restores through the SQLite backup API, so WAL frames are included and a live `.db` copy is never the algorithm.
- **B-019** - repair decision: `graph-store::repair` plans a quarantine move plus a `Repair` rebuild job and refuses any plan whose operations leave the Axiom state root.
- **B-020** - trusted unregister: `graph-store::unregister` refuses a busy instance unless the caller chooses a cancellation policy, cancels queued work, and removes only the one solution's rows so other checkpoints and all user source survive.

### rust-runtime-foundation (B-001 - B-010)

- **B-001** - Rust workspace foundation: `Cargo.toml`, pinned `rust-toolchain.toml` (1.85.0), committed `Cargo.lock`, `.cargo/config.toml` lint/verify/fmt-check aliases, `deny.toml` dependency-audit policy, `rustfmt.toml`, `.editorconfig`, `.gitattributes`, `.gitignore`, `VERSION`, the unapproved `spec.lock.json` draft pin with `spec.lock.example.json`, and the component `README.md`.
- **B-002** - `graph-core` typed errors and exit codes: stable `ErrorCode` wire spellings, redacted `AxiomError`/`ErrorEnvelope`, the frozen `ExitCode` table (`0,2,3,4,5,6,7,8,9,10,20`; `1` unassigned) and `docs/CLI-EXIT-CODES.md` pinned to that table by a compile-time test.
- **B-003** - AXIOM_HOME and path policy: `AxiomHome`, lexical `StorageClass` classification, `is_portable_id`, `Platform` and `PathEnvironment`, so resolution stays testable without touching the real user profile.
- **B-004** - single-daemon ownership: `DaemonLock` with exclusive-open semantics, `LockRecord`, stale-claim recovery and `inspect`; a concurrent writer reports `WRITER_ALREADY_RUNNING` (exit 10).
- **B-005** - immutable runtime configuration: validated `ServiceConfig` (JSON load, canonical form, validate), an environment that can only narrow source roots, and the daemon/sync/journal/log enums with their frozen spellings.
- **B-006** - shutdown and cancellation: `lifecycle` tokens that stop work without discarding dirty output or truncating a publish.
- **B-007** - redacted structured diagnostics: stderr `telemetry` with level filtering (rank 0 = most severe), bounded fields and secret scrubbing.
- **B-008** - `version` reports the frozen `VersionReport` properties plus runtime properties (SQLite, WAL baseline/support, analyzers); the documented property gap is recorded in the task evidence.
- **B-009** - patched-SQLite gate and pragmas: `open()` with `MIN_SQLITE_VERSION` 3.51.3, a volume probe, `PragmaReport`, and honest refusal (`SQLITE_UNSUPPORTED_VERSION`, exit 9) when the linked runtime is below the floor.
- **B-010** - ordered migrations: `SCHEMA_V1_SQL` byte-identical to the canonical `axiom-specs` schema, checksum/order verification, and a migration plan that refuses to move a newer database downward.

### governance-alignment (branch/merge/release policy)

- Align `Development.md` with the canonical `axiom-specs` §3 policy: `main` is the integration branch, `feature/<task-id>-<slug>` is the mandatory task branch, and `release/vX.Y.Z` is the release branch.
- Record the merge gate: an agent MAY merge a verified, fully-verified task branch into `main` on its own authority once every gate condition holds; release branches, tags and publishes still require explicit release authorization.
- Record the worktree rule: work finished in a worktree MUST be integrated into `main` and reflected in the owner's primary checkout, or explicitly reported as not yet delivered to that checkout.
