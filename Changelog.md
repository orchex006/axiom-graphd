# Changelog — axiom-graphd

## Unreleased

V2 seed adopts `2.0.0-draft.1`, `.axiom` workspace layout and component-owned docs/tests. Runtime implementation and platform certification are pending.

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
