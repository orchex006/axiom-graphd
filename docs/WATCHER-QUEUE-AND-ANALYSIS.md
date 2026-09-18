# Watcher, durable queue, static analysis and the command slices (B-021 - B-093)

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
| `axiom-graphd::commands` | B-032, B-043, B-084 - B-087, B-092 | `docs/16-CLI-AND-CONTROL-API.md` §2, §8 |
| `graph-export` | B-067 - B-072, B-075, B-077 - B-082 | `docs/12-SNAPSHOT-READ-WRITE-PROTOCOL.md`; `contracts/schemas/project-manifest.schema.json`, `catalog.schema.json`, `pointer.schema.json` |
| `graph-core::locks` | B-073, B-074 | `contracts/native-reader-writer-guards.md`; `docs/19-GIT-SNAPSHOTS-AND-MERGES.md` §2 |
| `axiom-graphd::control` | B-083 | `contracts/control-api-v1.md`; `docs/16-CLI-AND-CONTROL-API.md` §5 (audience, scope, loopback) |
| `axiom-graphd::checkpoint` | B-088 - B-091 | `docs/19-GIT-SNAPSHOTS-AND-MERGES.md` §2, §3, §6 |
| `axiom-graphd::release` | B-093 | `docs/20-VERSION-CHECK-UPDATE-RELEASE.md`; `docs/23-SECURITY-AND-TRUST.md`; `release/build-matrix.md` |

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
- `graph-analyze::imports`, `calls`, `types` - project-scoped resolution of
  literal imports, conservative call-site evidence and explicit
  inheritance/interface facts, each keeping an unresolved target unresolved
  (tasks B-051 - B-053).
- `graph-analyze::incremental`, `invalidation`, `coverage` - one-file
  replacement by `owner_file_id`, exported-signature invalidation of
  dependents, and honest parse-failure/coverage reporting (tasks B-054 -
  B-056).
- `graph-analyze::l3::*` - the versioned L3 pattern registry: ASP.NET routes,
  minimal API mappings, Angular literal requests, the solution-scoped HTTP
  join, literal SQL access, explicit EF table annotations, messaging topics,
  deployment/dependency manifests, human annotations and the per-rule
  coverage report (tasks B-057 - B-066).
- `graph-export` - canonical JSON, deterministic sparse shards, local
  symbol/adjacency indexes, project manifests, same-volume staging, flush and
  validation, gap-free pointer replacement, catalog publication, bounded
  snapshot reads, garbage collection, disk budgets and read-only archive mode
  (tasks B-067 - B-072, B-075, B-077 - B-082).
- `graph-core::locks` (`locks_posix`, `locks_windows`) - the shared/exclusive
  `SolutionGuard` beside the existing single-daemon `DaemonLock` (tasks B-073,
  B-074).
- `graph-store::outbox` - the publication outbox row persisted in the same
  transaction as the generation it publishes (task B-076).
- `axiom-graphd::control::auth` - loopback control authentication: audiences,
  scopes, constant-time digest comparison and a secret-free `Debug`
  (task B-083).
- `axiom-graphd::commands::solution`, `doctor`, `reconcile`, `query`, `update`
  - solution registry administration, worst-state-wins health reporting, the
  bounded reconcile wait, bounded context/impact queries over a pinned
  snapshot, and approval-bound update delegation (tasks B-084 - B-087,
  B-092).
- `axiom-graphd::checkpoint::staged`, `worktree`, `export`, `verify` -
  index-only staged materialization, stable-worktree verification with
  `WORKTREE_BUSY`, explicit-command Git checkpoint export and merged-source
  verification with `NOT_READY` (tasks B-088 - B-091).
- `axiom-graphd::release` - the release artifact publication gate: pinned-
  commit attribution and refusal of unsigned or placeholder metadata
  (task B-093).

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
4. **The L3 adapters stay dependency-free bounded literal parsing (B-057 -
   B-066).** `docs/15` section 2 requires a versioned pattern registry with
   positive/negative fixtures per pattern and forbids a whole-file regex scan
   that claims semantic accuracy. `graph-analyze::l3` implements exactly that:
   each pattern is matched after the AST is parsed, and a non-literal value is
   reported as unresolved with a coverage reason rather than guessed.
5. **Checkpoint and export modules are compiled library slices, not new argv
   surface (B-088 - B-093).** As with `changed` and `queue`, `docs/16` and
   `docs/19` describe these as commands; the argv surface and the exit-code
   mapping stay in `crates/axiom-graphd/src/cli.rs`. The modules are unit
   tested through the library, and `release/build-matrix.md` records the
   publication gate without claiming a published artifact.
6. **`axiom-graphd` consumes `graph-watch::inventory::content_digest`.** The
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
`cargo-deny 0.18.3` at the batch `B-051 - B-093` revision. Platform
certification is still absent: no target in this repository has native
install/run/uninstall evidence, and compilation alone is never certification
(CP-01). Only the Windows x64 release artifact is built on this host; the
Linux and macOS rows in `release/build-matrix.md` have no build evidence.
`cargo deny check advisories` is not evaluated in this environment because
the advisory database record uses CVSS 4.0, which the pinned `cargo-deny`
0.18.3 cannot parse; `bans`, `licenses` and `sources` are green.