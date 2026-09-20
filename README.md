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

## Command surface

Every operator slice below is wired into `parse` (task H-001) and is listed by
`axiom-graphd help`. Wiring is not implementation: each verb parses its full
documented argument surface, rejects an unknown flag or a malformed argument
(`VALIDATION_ERROR`, exit 2), and then answers `NOT_READY` (exit 4) with the
reason that names the binding it still needs, so an unimplemented slice is never
an empty success.

| Verb | Forms | Answers today |
| --- | --- | --- |
| `version` | `version [--json]` | the version report (implemented) |
| `serve` | `serve [--registry <path>] [--json]` | `NOT_READY` - the instance lock is taken, no reconcile loop is bound yet |
| `doctor` | `doctor [--solution <id>] [--json]` | `NOT_READY` - no status sources in this build |
| `status` | `status --solution <id> [--json]` | `NOT_READY` - no open store in this build |
| `solution` | `solution register\|list\|remove ...` | `NOT_READY` - no registry write path in this build |
| `changed` | `changed --solution <id> --project <p> --path <p> --reason <r>` / `--from-json <f>` | `NOT_READY` - no store binding in this build |
| `reconcile` | `reconcile --solution <id> --scope dirty\|project\|full ...` | `NOT_READY` - no queue writer in this build |
| `queue` | `queue list\|retry\|cancel ...` | `NOT_READY` - no open store in this build |
| `query` | `query context\|impact --solution <id> (--symbol <s>\|--node-id <id>) ...` | `NOT_READY` - no pinned snapshot source in this build |
| `update` | `update check` / `update apply --plan <file> [--approve-digest <sha>]` | `NOT_READY` - no trusted `axiom` CLI path in this build |
| `help` | `help`, `--help`, `-h` | the usage text, every wired verb form and the frozen exit table |

`checkpoint` and `snapshot` are documented in the CLI contract but have no owning
module in this revision, so they are still rejected as unrecognised commands.

## Build and verify

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo deny check
```

`cargo deny` must be built for the pinned toolchain (`cargo-deny 0.18.3` is the
last release that supports `rustc 1.85.0`); newer releases require a newer
compiler and are not a substitute result.

`Cargo.lock` is committed for binary crates. Generate it once with the pinned
toolchain (`cargo generate-lockfile`) and commit it; every other command uses
`--locked`.

## Specification pin

`spec.lock.json` pins the immutable `axiom-specs` revision this workspace was
implemented against, plus a SHA256 digest for each contract this runtime is
built against. It is currently an **unapproved draft pin**: no released
specification revision exists, so the pin is not owner approval and does not
carry release coverage. Re-record it against an owner-approved revision before
any release or compatibility claim. `spec.lock.example.json` is a shape example
only and is never a valid pin.

Validate the pin offline against a checkout of the pinned content:

```bash
python tools/spec-lock-check.py --lock spec.lock.json --spec-root <axiom-specs-checkout>
```

Default mode must accept (`immutable revision and pinned digests verified`).
`--release` deliberately still rejects with
`release-coverage-missing:conformance/fixture-index.json`, because release
coverage is only meaningful against a released revision.

## Platform support status

Windows x64, Linux x64, macOS arm64 and macOS x64 are required native targets.
No target is certified: there are no released binaries and no native
install/run/uninstall evidence in this repository yet. Support is never inferred
from compilation alone (CP-01).
