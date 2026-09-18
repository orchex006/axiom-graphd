# Watcher, durable queue, static analysis and the command slices (B-021 - B-050)

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`, pinned by
`spec.lock.json` at `1bf754298ba1bb266a77f13cded4bfe69484906f`. This is local
implementation documentation; it is not a second copy of any `axiom-specs`
contract.

## Crates added by this work package

| Crate | Owns | Contracts it implements |
| --- | --- | --- |
| `graph-watch` | B-021 - B-031 | `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` §7 and §9; `contracts/queue-state-machine.md` (dirty-generation side) |
| `graph-queue` | B-033 - B-044 | `contracts/queue-state-machine.md`; `docs/13` §5 and §8 |
| `graph-analyze` | B-045 - B-050 | `docs/15-STATIC-ANALYSIS-COVERAGE.md`; `contracts/schemas/coverage.schema.json` |
| `axiom-graphd::commands` | B-032, B-043 | `docs/16-CLI-AND-CONTROL-API.md` §2, §8 |

## Module map

- `graph-watch::native` / `poll` - the `notify`-backed adapter and the declared
  polling fallback; the watcher is a hint source and never the truth.
- `graph-watch::normalize`, `ignore`, `input_policy` - create/write/rename/delete
  normalization, generated-output and build exclusions, secret and symlink
  policy.
- `graph-watch::debounce`, `dirty` - coalescing with a hard maximum wait and
  monotonic desired/indexed generations.
- `graph-watch::inventory`, `recovery` - the complete startup inventory and the
  full rescan used after overflow or reconnect.
- `graph-watch::config_invalidation`, `git_observer` - configuration and
  dependency fingerprints, and read-only Git worktree observation.
- `graph-queue` - `enqueue`, `claim`, `heartbeat`, `ack`, `schedule`, `budget`,
  `retry`, `cancel`, `recover`, `pressure` and the bounded `barrier`, all keyed
  to the nine contract states and the frozen transition table.
- `graph-analyze` - `adapter` (parser adapter trait and registry), `grammar`
  (pinned grammar registry), `project_manifests`, `csharp`, `typescript`,
  `identity` (unambiguous stable ids).
- `axiom-graphd::commands::changed` - explicit changed-file hints; the caller may
  supply a reason and paths, never a digest.
- `axiom-graphd::commands::queue` - scoped list/retry/cancel over the durable
  queue.

## Justified deviations, recorded before implementation

1. **No native `tree-sitter` dependency (B-046).** The acceptance criterion
   requires pinned grammars, deterministic builds and a build/startup failure on
   ABI mismatch. `graph-analyze::grammar` satisfies all three with a
   dependency-free pinned registry (`GRAMMAR_ABI_VERSION = 14`, pinned
   `tree-sitter-c-sharp` 0.23.1 and `tree-sitter-typescript` 0.23.2);
   `GrammarSet::load` returns `INCOMPATIBLE_INPUT` with
   `rule = grammar_abi_mismatch`. Byte-level integrity of the pinned sources is
   delegated to `Cargo.lock` and `cargo deny check`. Adding a C toolchain
   requirement to a crate that must stay unit testable without a compiler was
   rejected as a larger risk than the deviation.
2. **`CC0-1.0` added to the `deny.toml` licence allowlist (B-021).** The native
   watcher backend `notify` 8.2.0 is CC0-1.0, a permissive public-domain
   dedication with no attribution or copyleft term. The allowance is scoped to
   that reason in the file itself.
3. **`changed` and `queue` are delivered as compiled command modules, not as new
   argv surface.** `docs/16` §2 lists them as commands; the argv surface, the
   single-JSON-object stdout contract and the exit-code mapping belong to the
   CLI/control work package (B-083 - B-087), which owns `crates/axiom-graphd/src/cli.rs`.
   Wiring them early would have widened this task into that package.
4. **`axiom-graphd` consumes `graph-watch::inventory::content_digest`.** The
   hint path must record the same digest the inventory uses; a second local
   implementation of the digest was rejected because the two would drift.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo deny check bans licenses sources
```

All four are green on `x86_64-pc-windows-msvc` with `rustc 1.85.0` and
`cargo-deny 0.18.3`. Platform certification is still absent: no target in this
repository has native install/run/uninstall evidence, and compilation alone is
never certification (CP-01).