# Changelog — axiom-graphd

## Unreleased

V2 seed adopts `2.0.0-draft.1`, `.axiom` workspace layout and component-owned docs/tests. Runtime implementation and platform certification are pending.

### watcher-queue-and-analysis (B-021 - B-050)

- **B-021** - notify native watcher adapter: `graph-watch::native` wraps the `notify` crate behind a declared backend, debounces raw events into normalized hints, and reports an explicit failure when the root is missing instead of silently watching nothing.
- **B-022** - polling fallback: `graph-watch::poll` finds changes without any native event, switches backends only by the declared policy, and never lets a snapshot exceed the hint bound or escape the root.
- **B-023** - normalize create/write/rename/delete: `graph-watch::normalize` maps create, write and delete to one action each, covers both paths of a rename, and keeps the correct tombstone plus new state for a case-only rename.
- **B-024** - ignore policy: `graph-watch::ignore` excludes generated graph output so writing it never requeues itself, and drops `bin`, `obj` and `node_modules` bursts at any depth.
- **B-025** - input policy: `graph-watch::input_policy` never parses secret files or escaping and unresolved symlinks while keeping safe configured sources visible, and root containment is exact rather than a sibling-prefix match.
- **B-026** - debounce: `graph-watch::debounce` coalesces repeated saves into one batch while a maximum wait means continuous writes cannot postpone reconciliation forever.
- **B-027** - dirty generations: `graph-watch::dirty` raises `desired_generation` on a second edit during processing and never lets acknowledging an older generation clear newer work.
- **B-028** - startup inventory: `graph-watch::inventory` discovers offline additions, changes and deletions even when HEAD did not move, and a truncated walk never claims a complete inventory.
- **B-029** - recovery: `graph-watch::recovery` persists `full_scan_required` for missed-notification conditions instead of replaying lost events, and never silently downgrades an overflow reason.
- **B-030** - config invalidation: `graph-watch::config_invalidation` invalidates only the necessary project or solution scope for csproj, tsconfig, lock and annotation changes, while ignored build outputs invalidate nothing.
- **B-031** - Git observer: `graph-watch::git_observer` distinguishes staged, unstaged and branch-change inputs and refuses destructive or configuration-overriding requests; no reset, stash or checkout is performed.
- **B-032** - changed-file hints: `axiom-graphd::commands::changed` accepts explicit path hints under a registered project for the manual, git, tool and reconcile reasons and still re-checks inventory and hashes before reporting anything observed.
- **B-033** - enqueue: `graph-queue::enqueue` coalesces equivalent pending scopes into one row without lowering the covered event sequence and never mutates a running job's target.
- **B-034** - claim with leases: `graph-queue::claim` assigns one owner and the next fence atomically, so concurrent claimers cannot share a fence and a requested lease is clamped to the maximum.
- **B-035** - heartbeat: `graph-queue::heartbeat` renews only for the current owner within bounds and refuses an expired, stale or mismatched owner.
- **B-036** - stale result rejection: `graph-queue::ack` rejects a stale or out-of-order commit after reclaim and keeps the scope dirty when `desired_generation` is newer than the analyzed input.
- **B-037** - priority with aging: `graph-queue::schedule` runs explicit verification ahead of inventory while a bounded wait bonus prevents starving inventory or garbage collection, and ordering is total and deterministic.
- **B-038** - resource budget: `graph-queue::budget` hard-caps worker count, input bytes and in-flight batches, leaves one CPU free, and returns an explicit result for a single oversized input.
- **B-039** - retry classification: `graph-queue::retry` gives transient IO a bounded deterministic jittered exponential backoff, gives up immediately on a permanent failure, and never retries unsupported syntax without new input.
- **B-040** - cancellation: `graph-queue::cancel` cancels pending and retry-waiting jobs immediately, gives running work a cooperative cancel token, and preserves unprocessed dirty state.
- **B-041** - lease recovery: `graph-queue::recover` makes a lease from a dead process eligible with a new fence, keeps a live lease, and does not repeat a completed publication.
- **B-042** - high-water pressure: `graph-queue::pressure` subsumes a burst of hints beyond the documented mark into one persisted full-scan intent while bounding memory, and drops no dirty state silently.
- **B-043** - queue inspection and retry commands: `axiom-graphd::commands::queue` lists, retries and cancels with stable ids and a deterministic order, rejects an unauthorized solution, and refuses a limit outside the bounded range.
- **B-044** - freshness barrier: `graph-queue::barrier` captures the target event sequence and publication requirement, bounds the wait with a thirty-second default, and returns pending job ids on timeout instead of claiming false freshness.
- **B-045** - parser adapter and registry: `graph-analyze::adapter` enumerates supported languages and parser versions, routes paths to a language, rejects a duplicate language before any analysis, and reports an unknown language as unsupported rather than empty complete.
- **B-046** - pinned grammar registry: `graph-analyze::grammar` pins one grammar per supported language, fails the whole set on an incompatible grammar ABI before any analysis, and keeps the build deterministic.
- **B-047** - project manifests: `graph-analyze::project_manifests` extracts dependency and property facts from csproj and package.json, marks values needing code evaluation or a version as unresolved with a reason, and never reports a malformed manifest as an empty success.
- **B-048** - C# declarations: `graph-analyze::csharp::declarations` records namespaces, types, interfaces and methods with source spans, keeps keys stable across runs, and reports malformed syntax as diagnostics instead of a silent empty result.
- **B-049** - TypeScript declarations: `graph-analyze::typescript::declarations` gives classes, functions and exported members explicit stable keys and marks anonymous, computed or destructured names with an explicit syntax identity quality.
- **B-050** - unambiguous stable ids: `graph-analyze::identity` builds canonical length-delimited tuples so concatenation cannot collide, and an unchanged symbol keeps its id across repeated runs.

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
