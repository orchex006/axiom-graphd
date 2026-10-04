# axiom-graphd

Rust daemon, durable queue, SQLite index, static analyzers, immutable
publication engine and the `axiom` installation/operations CLI for the Axiom
Graph Ecosystem. Specification baseline: `2.0.0-draft.1`.

**Owner scope:** watching, reconciliation, durable queue, SQLite, analyzers,
immutable publication, CLI, bootstrap engine, installation, native lifecycle and
safe updates. Bootstrap/CLI/daemon modules share one core release.

## Workspace layout

```text
Cargo.toml              workspace, shared dependency and lint policy
rust-toolchain.toml     pinned toolchain (provisional - see the file header)
deny.toml               dependency audit policy for `cargo deny check`
crates/graph-core/      pure domain logic: errors/exit codes, path resolution, config,
                        solution membership, trusted repository bindings
crates/graph-store/     SQLite: patched-runtime gate, pragmas, ordered migrations,
                        single writer actor, solution registration, inventory,
                        graph rows, reverse index, backup, repair, unregister
crates/graph-watch/     hint source: notify adapter, polling fallback, normalization,
                        ignore/secret policy, debounce, dirty generations, inventory,
                        recovery, config invalidation, read-only Git observation
crates/graph-queue/     durable job queue: enqueue, claim, heartbeat, ack, scheduling,
                        budget, retry, cancel, recovery, pressure, freshness barrier
crates/graph-analyze/   static analysis: parser adapter and grammar registry, project
                        manifests, C#/TypeScript declarations, stable symbol ids
crates/axiom-graphd/    daemon/CLI: instance lock, lifecycle, diagnostics, version,
                        changed-file hints and queue inspection commands
docs/                   engine, CLI, installation and operations documentation
```

`graph-core` is platform- and I/O-independent so it can be unit tested anywhere;
native adapters (`UserDirs`, `CrossProcessGuard`, `AtomicPublisher`,
`WatchBackend`, `PathIdentity`, `ExecutableLocator`) stay behind narrow
interfaces inside these crates (CP-02).

## Public command readiness

All documented `axiom` forms dispatch to actual native adapters: bootstrap plan/apply/verify/update, host discovery/configuration/gateway verification, skills/specs version/check/approved update, diagnostics and redacted ZIP support artifacts. The existing installation, service, ecosystem update/rollback and immutable graph migration engines remain.

Daemon `changed` validates registered source bytes and persists a durable pending intent; the native writer consumes it on its next bounded pass. Daemon `update` delegates to the same-release sibling executable with program/argv, identity and plan approval checks. A missing real installation/input/host, stale approval or unavailable peer still refuses with its actual reason; no current form has an unbuilt fallback.

Native READY requires actual Windows x64, Linux x64 and Mac Intel executable and current migration proofs from GitHub Actions. Mac ARM is deferred. GitHub Releases distributes the checked core pair and SHA-256 values; no certification, signing or attestation prerequisite applies. Publication is a separate factual state and is not performed by adding CI.

Host round-trip tests use a hermetic native MCP fixture peer and do not claim an installed licensed AI host was exercised. The adapter retains that distinction in its reports.

## Build and verify

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo deny check
```

The product compiler remains Rust 1.85.0. Dependency audit uses pinned cargo-deny 0.20.2 (a separate Rust 1.88 audit-tool build), so current CVSS advisories can be parsed. Record the actual audit-tool version; never silently skip an advisory parser failure.

`Cargo.lock` is committed for binary crates. Generate it once with the pinned
toolchain (`cargo generate-lockfile`) and commit it; every other command uses
`--locked`.

## Specification pin

`spec.lock.json` binds an exact owner-approved immutable specification revision and contract digest rollup. Current public composition and release policy follow ADR-0030. Public CI verifies owner implementation and native artifact bytes; private specification-byte validation is recorded by the authorized local handoff.

## Native scope

Windows x64, Linux x64 and Mac Intel are the required READY lanes. Mac ARM is deferred. Existing older native/candidate evidence remains historical; fresh GitHub source-bound reports govern current READY.
