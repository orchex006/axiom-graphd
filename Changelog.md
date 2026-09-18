# Changelog — axiom-graphd

## Unreleased

V2 seed adopts `2.0.0-draft.1`, `.axiom` workspace layout and component-owned docs/tests. Runtime implementation and platform certification are pending.

### portable-contract-fixtures (F-006, F-008)

- **F-006** - L3 fixture vectors: `fixtures/l3/` holds static positive and negative conformance vectors
  for the Level-3 HTTP, SQL and messaging adapters (ASP.NET attribute routes, minimal API mappings,
  Angular `HttpClient`, literal SQL, messaging topics and the configured-alias HTTP join). Each rule
  carries a provenance note naming the implementing source file, the function and the invariant it
  serves, and the corpus README records the `PATTERN_*` constants that never reach an output.
  `crates/graph-analyze/tests/l3_fixtures.rs` loads every vector from disk and asserts both the
  positive fact set and the exact refusal pattern and reason, including the boundary cases. No vector
  contains a runtime log, captured traffic or executed user source.

### analysis-checkpoints (B-051 - B-093)

- **B-051** - literal imports: `graph-analyze::imports` resolves relative and explicitly aliased imports through the configured rules, keeps an ambiguous or missing target unresolved instead of guessing, and is deterministic in source order.
- **B-052** - conservative call sites: `graph-analyze::calls` records only high-confidence literal or explicit call evidence against resolved symbols, keeps an unresolved receiver as an explicit unresolved edge, and never synthesizes a caller relation from name similarity alone.
- **B-053** - inheritance and interface facts: `graph-analyze::types` extracts explicit declaration, inheritance and interface-implementation facts, preserves multiple members in a stable order, and reports an ambiguous base name as unresolved rather than picking one.
- **B-054** - incremental file replacement: `graph-analyze::incremental` replaces exactly one file's facts by `owner_file_id`, leaves every other file intact, and refuses to apply a replacement whose acknowledged generation is not the analyzed generation.
- **B-055** - signature invalidation: `graph-analyze::invalidation` propagates an exported-signature change to the transitive dependents of that file while leaving unrelated files untouched, and expands to a full invalidation when a boundary cannot be proven.
- **B-056** - parse failures and coverage: `graph-analyze::coverage` reports an unparsed or partially parsed file as reduced coverage with its rule and reason instead of silently claiming the file was analyzed, and keeps the per-rule totals consistent with the artifacts.
- **B-057** - ASP.NET literal route attributes: `graph-analyze::l3::dotnet_routes` extracts literal route attributes and their HTTP verbs from .NET controllers, leaves a route assembled from a non-literal constant for the coverage report, and preserves controller, action and verb in the evidence.
- **B-058** - minimal API mappings: `graph-analyze::l3::minimal_api` extracts explicit minimal API route mappings and their handler symbols, rejects a mapping whose pattern is not a literal, and emits one relation per verb and pattern.
- **B-059** - Angular literal requests: `graph-analyze::l3::angular_http` extracts literal `HttpClient` request URLs and methods, keeps a computed URL unresolved with a coverage reason, and orders the findings deterministically.
- **B-060** - HTTP relation join: `graph-analyze::l3::http_join` joins client requests to server routes only through a declared solution mapping, leaves an unmatched request unresolved rather than matching on a similar path, and records both sides of a successful join.
- **B-061** - literal SQL access: `graph-analyze::l3::sql_literals` extracts literal SQL access operations and the objects they name, keeps a dynamically built statement unresolved with its rule, and never infers a table that the literal does not name.
- **B-062** - EF table annotations: `graph-analyze::l3::ef_mapping` maps explicit EF table and column annotations to their entity properties, keeps a convention-only mapping for the coverage report, and preserves schema, table and member.
- **B-063** - messaging topics: `graph-analyze::l3::messaging` extracts explicit publish and subscribe topic patterns, leaves a topic built from a non-literal value unresolved, and records the direction of each relation.
- **B-064** - deployment and dependency hints: `graph-analyze::l3::manifests` extracts deployment and external-dependency hints from declared manifests, keeps an unreadable or unsupported manifest in the coverage report, and records the manifest path with each hint.
- **B-065** - human annotations: `graph-analyze::l3::annotations` merges human architectural annotations only where the file declares them, refuses a conflicting annotation instead of overwriting a derived fact, and keeps the annotation source visible.
- **B-066** - per-rule coverage report: `graph-analyze::l3::report` produces a per-rule coverage report with analyzed, skipped and unresolved counts, keeps the totals equal to the sum of the rule rows, and reports an unmeasured rule as explicitly unmeasured.
- **B-067** - canonical JSON serializer: `graph-export::canonical` serializes a value to canonical UTF-8 JSON with sorted keys, stable number and string escaping, and a trailing-newline contract so two runs of the same value produce byte-identical output.
- **B-068** - deterministic sparse shards: `graph-export::shard` splits a generation into deterministic sparse shards with a stable boundary rule, keeps a shard empty rather than padded when nothing belongs to it, and reproduces identical shard digests for identical input.
- **B-069** - local symbol and adjacency indexes: `graph-export::indexes` builds local symbol and adjacency indexes from the shard set, refuses an index entry that points at a missing shard, and orders every index deterministically.
- **B-070** - project manifest digests: `graph-export::manifest` records a project manifest with a digest per file, keeps the manifest digest content-addressed over the recorded digests, and refuses to emit a manifest for a shard that failed validation.
- **B-071** - same-volume staging generations: `graph-export::staging` writes a new generation into a same-volume staging directory so a rename cannot cross a device boundary, refuses a staging root outside the configured state root, and leaves the published generation untouched on failure.
- **B-072** - flush and validate a generation: `graph-export::validate` flushes and validates an immutable generation against its manifest, refuses to accept a generation with a missing or mismatched digest, and reports the failing path with its rule.
- **B-073** - POSIX solution guard: `graph-core::locks_posix` implements the shared and exclusive `SolutionGuard` over POSIX advisory locks, refuses a downgrade that would invalidate a shared holder, and releases the lock on drop without leaving a stale artifact.
- **B-074** - Windows solution guard: `graph-core::locks_windows` implements shared and exclusive `SolutionGuard` locking with the Windows byte-range API, proves mutual exclusion with a cross-process child probe, and reports a held lock rather than waiting forever.
- **B-075** - pointer replacement without a gap: `graph-export::pointer` replaces the current pointer without an observable delete gap, refuses a pointer swap whose target generation is not validated, and keeps the previous pointer recoverable if the swap fails.
- **B-076** - publication outbox: `graph-store::outbox` persists a publication outbox row inside the same database transaction as the generation, refuses to enqueue a duplicate publication for the same generation, and lets a replay skip an already-applied row.
- **B-077** - interrupted publication recovery: `graph-export::recovery` recovers an interrupted multi-project publication by completing or rolling back the pending outbox rows, refuses to resurrect a generation that was never validated, and never publishes a partial catalog.
- **B-078** - pinned multi-project catalog: `graph-export::catalog` publishes a multi-project catalog pinned to one generation per project, refuses a catalog that references an unpublished generation, and keeps the catalog digest stable over the pinned set.
- **B-079** - bounded snapshot reads: `graph-export::reader` reads a published snapshot into bounded memory, refuses a read beyond the declared limits instead of growing unbounded, and resolves a symbol through the index without loading the whole generation.
- **B-080** - garbage collection: `graph-export::gc` collects only generations that no pointer, catalog or archive references, keeps a referenced generation even when it is old, and reports each collected generation with its reason.
- **B-081** - publication disk budgets: `graph-export::disk_budget` enforces a configured publication disk budget, refuses a publication that would exceed the budget instead of partially writing it, and reports the observed and expected sizes.
- **B-082** - archived checkpoint read-only mode: `graph-export::archive` serves an archived checkpoint in read-only mode, refuses any mutation against an archive, and keeps the archive digest verifiable after extraction.
- **B-083** - loopback control authentication: `axiom-graphd::control::auth` authenticates loopback control clients against declared audiences and scopes, checks the audience before the scope so a wrong-audience token is rejected first, and compares digests in constant time while keeping the secret out of `Debug`.
- **B-084** - solution CLI commands: `axiom-graphd::commands::solution` plans and applies solution registration and removal, refuses to remove a busy solution without a cancellation policy, and cascades removal through the solution-owned rows only.
- **B-085** - status and doctor commands: `axiom-graphd::commands::doctor` reports watcher, queue, database and catalog health with worst-state-wins severity, renders a stable text report, and reports an unknown state instead of assuming healthy.
- **B-086** - reconcile CLI and API: `axiom-graphd::commands::reconcile` validates a reconcile request and enforces a bounded wait budget, refuses an out-of-scope request, and returns an explicit incomplete result when the budget expires.
- **B-087** - bounded graph query CLI: `axiom-graphd::commands::query` assembles and serves bounded context and impact queries against a pinned snapshot, refuses a query beyond the byte, node or depth limits, and reports the pinned generation with the result.
- **B-088** - staged source checkpoint: `axiom-graphd::checkpoint::staged` materializes a staged source checkpoint with index-only writes, keeps `index_writes` at zero so the source is not mutated, and refuses to overwrite a non-checkpoint path.
- **B-089** - stable worktree checkpoint: `axiom-graphd::checkpoint::worktree` verifies that a checkpoint source is stable before and after materialization, retries a bounded number of times, and reports `WORKTREE_BUSY` (exit 6) rather than taking a moving tree.
- **B-090** - deterministic Git checkpoint: `axiom-graphd::checkpoint::export` exports a deterministic Git checkpoint only for an explicit command, refuses an implicit export, and derives the checkpoint identity from the committed revision.
- **B-091** - merged-source checkpoint verification: `axiom-graphd::checkpoint::verify` verifies a merged-source checkpoint against merge evidence, reports `NOT_READY` (exit 4) when the merge cannot be proven, and never certifies an unverified merge.
- **B-092** - safe update delegation: `axiom-graphd::commands::update` plans an update against a declared trust root and delegates through an explicit argv list, failing closed on unconfigured trust, a missing approval, a digest mismatch or a shell metacharacter.
- **B-093** - versioned release artifacts: `axiom-graphd::release` and `release/build-matrix.md` describe the Windows, Linux and macOS release artifacts with pinned-commit attribution, refuse to publish unsigned or placeholder metadata, and state explicitly that only the Windows artifact is built on this host.
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
