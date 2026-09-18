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
crates/axiom-graphd/    daemon/CLI: instance lock, lifecycle, diagnostics, version
docs/                   engine, CLI, installation and operations documentation
```

`graph-core` is platform- and I/O-independent so it can be unit tested anywhere;
native adapters (`UserDirs`, `CrossProcessGuard`, `AtomicPublisher`,
`WatchBackend`, `PathIdentity`, `ExecutableLocator`) stay behind narrow
interfaces inside these crates (CP-02).

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
