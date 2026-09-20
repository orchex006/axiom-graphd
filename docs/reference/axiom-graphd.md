# axiom-graphd command reference

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Implementation/release evidence is not implied.

This reference documents the `axiom-graphd` foreground command line as it is
implemented in this revision, and labels every command and flag that belongs to a
later work package as **proposed / not implemented**. The generating source is
`crates/axiom-graphd/src/cli.rs` (`parse`, `usage`, `exit_code_table`) and
`crates/axiom-graphd/src/version.rs`.

The frozen process exit table and the error-code-to-exit-code table are **single
sourced** in [CLI-EXIT-CODES](../CLI-EXIT-CODES.md) and are not copied here, so
the two documents cannot drift. Every exit code quoted in this reference is one
of those frozen values.

## 1. Command availability

A command or argument is `available` only when this revision parses and executes
it. `proposed` means it is documented for a later work package and this binary
rejects or cannot complete it.

<!-- BEGIN COMMAND STATUS -->
| Command | State | Evidence |
| ------- | ----- | -------- |
| help | available | Accepted positional; also `--help` and `-h`. |
| version | available | Accepted positional; also `--version` and `-V`. |
| doctor | available | `doctor [--solution <id>]` executes against the open store and prints a diagnostic report. |
| serve | available | Takes the instance lock and runs one bounded reconcile pass over every registered solution, publishing a generation. |
| status | available | `status --solution <id>` executes against the open store and prints queue, freshness and coverage state. |
| solution | available | `solution register\|list\|remove` executes against the registry in the open store. |
| changed | available | Wired in task H-001: accepts the explicit-hint and `--from-json` forms and answers `NOT_READY`. |
| queue | available | `queue list\|retry\|cancel` executes against the operational queue in the open store. |
| reconcile | available | Runs the same bounded pass as `serve` for one solution (or one project) and returns its report. |
| query | available | `query context\|impact` executes against a pinned published generation. |
| render | available | `render --solution <id> [--project <id>]... --out <dir>` writes a deterministic `result.html` and `summary.json` for a published generation (task H-005). |
| update | available | Wired in task H-001: accepts `update check\|apply` and answers `NOT_READY`. |
| install | proposed | Not accepted by `parse`; belongs to the installation work package. |
| service | proposed | Not accepted by `parse`; belongs to the native lifecycle work package. |
| bootstrap | proposed | Not accepted by `parse`; belongs to the bootstrap work package. |
| host | proposed | Not accepted by `parse`; belongs to the host-configuration work package. |
<!-- END COMMAND STATUS -->

`available` means `parse` accepts the command and the verb has a production
binding; it does not mean every verb is complete. Task H-002 bound `serve`,
`solution`, `status`, `doctor`, `reconcile`, `queue` and `query` to the store,
registry, queue and pinned-generation pipeline, and task H-005 bound `render` to
that same pinned-generation reader. Two verbs remain wired but not implemented:
`changed` and `update` accept their full documented argument surface and then
answer `NOT_READY` (exit 4) with one stable reason that names the binding they
still need. Sections 8 and 13 describe those two; the remaining sections describe
the implemented verbs, their accepted forms and their behaviour.

Global arguments:

| Argument | State | Applies to | Behaviour |
| -------- | ----- | ---------- | --------- |
| `--json` | available | every command | Machine-readable mode. Writes exactly one JSON object to stdout; diagnostics stay on stderr. |
| `--registry <path>` | available | `serve` only | Explicit registry config path, passed as argv. Supplying it for any other command is rejected. |
| `--help`, `-h` | available | - | Same as the `help` command. |
| `--version`, `-V` | available | - | Same as the `version` command. |
| `--solution <id>` | available | `doctor`, `status`, `changed`, `reconcile`, `queue`, `query`, `render` | Named solution scope. Rejected for a verb that does not accept it. |
| `--project <id>`, `--out <dir>` | available | `render` | Repeatable project scope (empty means every registered project) and the output directory; an empty `--out` is rejected. |
| `--dry-run` / `--apply` | available | `solution register`, `solution remove` | Exactly one of the two is required; supplying neither is a rejection. |
| `--limit <n>` | available | `queue list` | Bounded 1..`queue::MAX_LIST_LIMIT`. |
| `--wait`, `--timeout <ms\|Ns>` | available | `reconcile --scope dirty` | Bounded wait, bounded by `reconcile::MIN/MAX_TIMEOUT_MS`. |
| `--symbol`, `--node-id`, `--max-bytes`, `--max-nodes`, `--depth` | available | `query context`, `query impact` | Query subject and bounds; each has its own validated range. |
| `--plan <path>`, `--approve-digest <sha256>` | available | `update apply` | Reviewed plan plus its 64-lowercase-hex digest. |
| `--all` | proposed | `version` | Not accepted by this revision's `parse`. |

Parsing notes that are contract:

- Parsing an unrecognised option (`--nope`), an unrecognised command
  (`frobnicate`), a second positional (`version extra`), or `--registry` without
  a value is a rejection, never a silent ignore.
- `--registry` counts as "only valid for `serve`": `version --registry x` is
  rejected.
- Paths arrive as argv. Axiom never interpolates a path into an interpolated
  shell string, and no command in this revision requires Bash.

## 2. `help`

```text
axiom-graphd help
axiom-graphd --help
axiom-graphd -h
```

- Arguments: none. No positional command is the same as `help`.
- Example response: the shipped usage text, followed by the exit-code table
  generated from `ExitCode::all()`. The usage block is fixed source text:

```text
axiom-graphd - Axiom graph engine daemon

Usage: axiom-graphd <command> [options]

Commands:
  serve [--registry <path>] [--json]   run the foreground daemon
  version [--json]                     print component, build and runtime versions
  doctor [--solution <id>] [--json]    print diagnostics (never repairs automatically)
  status --solution <id> [--json]      print queue, freshness and coverage state
  solution register|list|remove ...    administer the solution registry
  changed ...                          accept explicit changed-file hints
  reconcile ...                        request a bounded reconcile
  queue list|retry|cancel ...          inspect and steer the operational queue
  query context|impact ...             bounded context and impact over a pinned snapshot
  update check|apply ...               delegate to the trusted axiom CLI
  help, --help                         print this help

Options:
  --json    write exactly one JSON object to stdout; diagnostics go to stderr

Exit codes:
```

  The operator-slice block follows the command list, one entry per wired verb,
  each with the exact forms that verb accepts (task H-001). The exit-code table
  then lists every frozen code and its meaning. Code `1` stays unassigned and is
  deliberately absent.
- Exit codes: `0`. `help` has no failing path.
- Failure recovery: not applicable. If `help` prints a table that disagrees with
  [CLI-EXIT-CODES](../CLI-EXIT-CODES.md), treat it as an internal defect
  (`INTERNAL`, exit `8`) and report it: both are generated from one value and
  cannot legitimately disagree.

## 3. `version`

```text
axiom-graphd version
axiom-graphd version --json
axiom-graphd --version
axiom-graphd -V
```

- Arguments: none.
- Output: exactly one JSON object on stdout. In this revision the payload is the
  JSON object in text mode as well; `--json` controls the failure envelope and
  the diagnostic level, not the payload.
- Example response (shape from the frozen report plus the runtime facts the code
  adds; **not a captured run** - no binary was built in this revision):

```json
{"component":"axiom-graphd","version":"0.0.0-dev","spec_version":"2.0.0-draft.1","graph_schema":1,"control_api":1,"queue_schema":1,"build_revision":"unknown","update_status":"unconfigured","sqlite_version":"3.51.3","sqlite_wal_baseline":"3.51.3","sqlite_wal_supported":true,"analyzers":[]}
```

| Property | Meaning |
| -------- | ------- |
| `component` | Reporting component. Only the seven frozen component names are accepted. |
| `version` | Workspace core version; currently `0.0.0-dev`, never a placeholder. |
| `spec_version` | Specification baseline this build implements. |
| `graph_schema`, `control_api`, `queue_schema` | Independent contract versions. |
| `build_revision` | Injected 40-character build commit, or `unknown` when not injected. |
| `update_status` | `not_checked`, `current`, `available`, `offline`, `unconfigured` or `blocked`. This build has no trusted update source and can only report `unconfigured`; claiming any other status is refused as a defect. |
| `sqlite_version` | Actual runtime SQLite version, or `unavailable` if the probe fails. |
| `sqlite_wal_baseline` | Minimum WAL-capable baseline this build requires. |
| `sqlite_wal_supported` | Whether the linked runtime meets that baseline. |
| `analyzers` | Analyzer identifiers compiled into this build, in stable order. Empty in this revision. |

- Exit codes: `0` on success; `8` (`INTERNAL`) if the report would violate the
  frozen version-report schema or cannot be serialised. Any such failure is a
  build defect, not a user error.
- Failure recovery: re-install a verified archive of the same version and re-run
  `version --json`. Do not edit the report or the schema to make it validate.

## 4. `doctor`

```text
axiom-graphd doctor
axiom-graphd doctor --solution <id>
axiom-graphd doctor --json
```

- Arguments: optional `--solution <id>` (wired in task H-001); `--all` is
  proposed. With no `--solution`, `doctor` prints one report per registered
  solution.
- Behaviour: opens the instance store and, for the named solution or each
  registered solution, prints the watcher, queue, database and catalog health
  plus an `overall` verdict. `doctor` never repairs automatically:
  `automatic_repair` is always `false`.
- Example response (captured run, Windows 11 x64, task H-002):

```json
{"solution_id":"demo-solution","watcher":{"mode":"polling","healthy":false,"detail":"no continuous filesystem watcher is bound in this build; each pass plans a stat-based inventory"},"queue":{"pending":0,"leased":0,"retry_wait":0,"failed":0,"healthy":true,"detail":"pending=0 leased=0 failed=0"},"database":{"healthy":true,"schema_version":1,"detail":"integrity=ok schema_version=1"},"catalog":{"healthy":false,"generation_id":null,"refs":0,"detail":"refs=0"},"overall":"degraded","diagnostics":["watcher-degraded","catalog-missing"],"automatic_repair":false}
```

- Exit codes: `0` when the report is produced, whether `overall` is `healthy` or
  `degraded` - a degraded verdict is a report, not an error. An unknown solution
  is `NOT_FOUND` (exit `3`); an unparsable or unsafe configuration is
  `CONFIG_INVALID` (exit `2`).
- Failure recovery: a `degraded` verdict names its own diagnostics. In this
  revision they are `watcher-degraded` (no continuous filesystem watcher is
  bound; every pass plans a stat-based inventory) and `catalog-missing` (no
  catalog generation is bound). Neither blocks a published generation. `doctor`
  never repairs automatically, so read the diagnostic and use the platform
  runbooks ([install-windows](../guides/install-windows.md),
  [install-linux](../guides/install-linux.md),
  [install-macos](../guides/install-macos.md)) rather than expecting a repair.

## 5. `serve`

```text
axiom-graphd serve
axiom-graphd serve --registry <path>
axiom-graphd serve --json --registry <path>
```

- Arguments: optional `--registry <path>`. A path may contain spaces, Thai
  characters, apostrophes, ampersands or parentheses; it is passed as an argv
  element and is never concatenated into a shell command.
- Behaviour: resolves `AXIOM_HOME`, verifies the destination, loads the service
  config, takes the single-owner instance lock at `AXIOM_HOME/run/daemon.lock`,
  then runs **one bounded reconcile pass** over every registered solution: it
  resumes both publication lanes, plans a stat-based inventory delta, analyses
  the changed files and publishes the closed generation through the publication
  barrier (staging seal, analysis commit, event-sequence bump, exclusive
  solution guard, content-addressed install, atomic pointer replace in both
  lanes, outbox acknowledgement). One publication writes the *same*
  content-addressed generation into the project's `live/` lane (the Git-ignored
  working set a query answers from) and its `checkpoint/` lane (the tracked
  artifact the operator verbs read); both lanes are sealed before either pointer
  moves, so a failure while sealing leaves every lane exactly as it was and the
  two lanes can never name different generations. Each lane's `current.json`
  carries the schema document `contracts/schemas/pointer.schema.json` fixes -
  `schema_version`, `generation_id` and `manifest_sha256` - as compact,
  key-sorted bytes with one trailing LF, which is the exact form the shipped
  `axiom-mcp` pointer reader accepts. The JSON report names, per project, the
  inventory delta, the analysed files, the node and edge counts, whether a
  generation was published and the published `generation_id`/`manifest_hash`;
  `lane_root` names the live lane, because that is the lane a query resolves.
  One pass is not a daemon loop: `serve` installs no `SIGINT`/`SIGTERM` handler
  and exits after the pass, so the `lifecycle.rs` drain stays a design target.
- Example response (captured run, Windows 11 x64, task H-002):

```json
{"instance_id":"default","solutions":1,"projects":1,"dirty_before":0,"dirty_after":0,"published_generations":1,"recoveries":[],"outcomes":[{"solution_id":"demo-solution","project_id":"auth-api","inventory_generation":1,"inventory_added":1,"inventory_changed":0,"inventory_deleted":0,"analyzed_files":1,"nodes":5,"edges":4,"published":true,"generation_id":"3e1996028b0ee400673115f6fadb8881c8daa024a74fc2d4a38a1617be618f34","manifest_hash":"531ad8de70848a3d6c7bb22072c63193a380b088292983283df37694102b99d7","current_generation":"3e1996028b0ee400673115f6fadb8881c8daa024a74fc2d4a38a1617be618f34"}],"shutdown":"Running"}
```

- Exit codes and recovery:

| Condition | Exit code | Recovery |
| --------- | --------- | -------- |
| Bounded pass completed (with or without a published generation) | `0` | The report names what was published; nothing to recover. |
| `AXIOM_HOME` relative, remote, cloud-synchronised or a device path | `2` (`UNSAFE_HOME_PATH`) | Set an absolute `AXIOM_HOME` on a supported local filesystem. |
| Registry/config rejected or malformed, or a registered project has no binding | `2` (`CONFIG_INVALID`) | Fix the named field, or add the binding to `AXIOM_HOME/config/bindings.json`, then re-run. Never delete the database to silence a config error. |
| Another owner holds the instance lock | `10` (`WRITER_ALREADY_RUNNING`) | Identify the owning process and coordinate. Never delete `run/daemon.lock` by guess. |
| Lock held but unusable | Retryable; bounded retry | Retry with a bounded wait, then report. |
| `--registry` supplied for another command | `2` (`VALIDATION_ERROR`) | Remove the flag; it applies only to `serve`. |

- Known limitation (W10 lane publication): a `serve` publication is now readable
  at the *pointer* and *lane* level by `axiom-mcp`, but the published generation
  **payload** is still `axiom-graphd`'s native form, which the shipped
  `axiom-mcp` data plane does not yet accept. `serve` writes a single canonical
  JSONL shard (`bucket-000`) holding `{key, kind, body}` records and a
  `manifest.json` of
  `{generation_id, entries[], record_count, total_bytes}`, while
  `docs/11-GRAPH-DATA-CONTRACT.md` section 6 and
  `contracts/schemas/project-manifest.schema.json` require role-sharded JSON
  (`nodes/`, `edges/`, `indexes/{symbols,outgoing,incoming}/`,
  `architecture/summary.json`, `coverage.json`) described by a manifest of
  `{schema_version, solution_id, project_id, analysis_profile, generator_version,
  analyzer_set_hash, source_fingerprint, config_fingerprint,
  dependency_fingerprint, coverage, files[]}` that must not carry its own hash.
  The reader therefore stops with `ManifestInvalid: manifest <id> schema_version
  is not an integer` before any shard is read. Closing that gap changes the
  published payload layout and the generation-identity rule, which is a
  `graph_payload_schema`/layout decision that `AGENTS.md` and `Development.md`
  route through `axiom-specs` coordination; it is not a local implementation
  change and is recorded here as a blocker rather than worked around.

- `SIGINT`/`SIGTERM` are not handled in this revision: a pass runs to its
  bounded end and exits. The `lifecycle.rs` design target is a bounded graceful
  drain, not queue deletion.
- Only one writer per bound output namespace and one daemon per OS user is
  allowed; the instance lock is how that is enforced.

## 6. `status`

```text
axiom-graphd status --solution <id>
axiom-graphd status --solution <id> --json
```

- Arguments: required `--solution <id>`; optional `--json`. Omitting `--solution`
  is a rejection, not a defaulted scope.
- Behaviour: opens the instance store and prints the named solution's queue,
  freshness and coverage state: the event sequence, the dirty-file count, the
  queue depth by state and the generation counts on disk. It reports only what
  it can verify and never invents a solution state.
- Example response (captured run, Windows 11 x64, task H-002):

```json
{"solution_id":"demo-solution","full_scan_required":false,"event_seq":1,"dirty_files":0,"queue":{"pending":0,"leased":0,"retry_wait":0,"failed":0,"healthy":true,"detail":"pending=0 leased=0 failed=0"},"generations":0,"checkpoint_generations":1}
```

- Exit codes: `0` when the report is produced. An unknown solution is
  `NOT_FOUND` (exit `3`); an unparsable or unsafe configuration is
  `CONFIG_INVALID` (exit `2`).
- Failure recovery: a dirty-file count above zero means the next `serve` or
  `reconcile` pass will analyse it; a failed job names its own retry. Never
  delete a store to silence a count.

## 7. `solution`

```text
axiom-graphd solution register --config <solution.yaml> [--bindings <bindings.json>] (--dry-run|--apply)
axiom-graphd solution list [--solution <id>]
axiom-graphd solution remove --solution <id> (--dry-run|--apply)
```

- Arguments: `register` takes `--config <solution.yaml>` and optional
  `--bindings <bindings.json>`; `list` takes optional `--solution <id>`;
  `remove` takes required `--solution <id>`. `register` and `remove` require
  exactly one of `--dry-run` or `--apply`; supplying neither, or both, is a
  rejection.
- Behaviour: `register` parses the solution configuration, resolves each
  project's binding (from `--bindings` or `AXIOM_HOME/config/bindings.json`) and,
  with `--apply`, writes the solution and project rows into the registry in the
  open store; `--dry-run` prints the same plan without writing. `list` reads the
  registered solutions; `remove --apply` deletes one. A `--apply` really mutates
  the user-owned registry, so `--dry-run` is the review step.
- Example response (captured run, Windows 11 x64, task H-002):

```json
{"id":"demo-solution","profile":"default","config_hash":"c0abdbf018993355b2d95af93c237cbe1262918391f552e93420ce7261ccdb4d","projects":1}
```

- Exit codes: `0` when the plan or record is produced. A malformed config,
  an unresolved binding or a missing `--dry-run`/`--apply` is `2`
  (`VALIDATION_ERROR` or `CONFIG_INVALID`); an unknown solution on `remove` is
  `NOT_FOUND` (exit `3`).
- Failure recovery: a rejected config names the field to fix. Never hand-edit a
  registry row to work around a rejected plan; re-run `register --apply` after
  fixing the named field. `--dry-run` first when the change is not obvious.

## 8. `changed`

```text
axiom-graphd changed --solution <id> --project <project> --path <repo-relative> --reason <manual|git|tool|reconcile>
axiom-graphd changed --solution <id> --from-json <changes.json>
```

- Arguments: required `--solution <id>`; either the explicit hint
  `--project <project> --path <repo-relative> --reason <manual|git|tool|reconcile>`
  or `--from-json <changes.json>`. Omitting both forms is a rejection, as is an
  unknown `--reason` value or a path that is not a repository-relative path
  (`--path a\b.cs` is rejected).
- Behaviour: accepts both documented forms, then answers `NOT_READY`. The verb
  validates the hint without recording it, because the verified change-hint path
  has no open store binding in this build. It is a wired slice (task H-001), not
  an implemented one.
- Exit codes: `4` (`NOT_READY`) with the reason that the verified change-hint
  path has no open store binding. A malformed hint is `2` (`VALIDATION_ERROR`).
  With `--json`, stdout is exactly the error envelope; in text mode stdout stays
  empty and the reason goes to stderr.
- Failure recovery: the change-hint binding is owned by a later work package.
  Until it lands, treat a file change as a full reconcile scope rather than a
  targeted hint. Never re-send a rejected hint unchanged; fix the named flag.

## 9. `reconcile`

```text
axiom-graphd reconcile --solution <id> --scope dirty [--wait] [--timeout <ms|Ns>]
axiom-graphd reconcile --solution <id> --scope project --project <project>
axiom-graphd reconcile --solution <id> --scope full
```

- Arguments: required `--solution <id>` and `--scope <dirty|project|full>`.
  `--project` is required for `--scope project` and rejected otherwise;
  `--wait` and `--timeout <ms|Ns>` apply only to `--scope dirty`, and the timeout
  is bounded. `--timeout` without `--wait` or an out-of-range timeout is a
  rejection.
- Behaviour: records the reconcile plan row in the durable queue, then runs the
  same bounded pass `serve` runs, for the requested solution (and project, for
  `--scope project`), under the same instance lock. The report is the same shape
  `serve` returns, so a `--scope full` request with nothing changed reports
  `published_generations:0` and leaves the current generation in place.
- Exit codes: `0` when the pass completes. A malformed scope or timeout is `2`
  (`VALIDATION_ERROR`); an unknown solution is `NOT_FOUND` (exit `3`); another
  owner holding the instance lock is `WRITER_ALREADY_RUNNING` (exit `10`).
- Failure recovery: if another daemon holds the lock, coordinate with it rather
  than deleting `run/daemon.lock`; the next `serve` pass will do the work. Never
  raise the timeout past its bound to force progress.

## 10. `queue`

```text
axiom-graphd queue list --solution <id> [--limit <n>]
axiom-graphd queue retry --job <id>
axiom-graphd queue cancel --job <id>
```

- Arguments: `list` takes required `--solution <id>` and optional `--limit <n>`,
  bounded from `1` to the queue maximum (`--limit 0` is rejected); `retry` and
  `cancel` take required `--job <id>`.
- Behaviour: `list` reads the durable queue in the open store - the job id,
  kind, scope key, state and attempt count - for the named solution; `retry`
  re-arms a failed job; `cancel` cancels a job. The queue is the same queue the
  `serve`/`reconcile` pass feeds, so a job enqueued by one is visible here.
- Example response (captured run, Windows 11 x64, task H-002):

```json
{"solution_id":"demo-solution","limit":50,"total":0,"jobs":[]}
```

- Exit codes: `0` when the page or mutation is produced. A missing `--job` or an
  out-of-range `--limit` is `2` (`VALIDATION_ERROR`); an unknown job is
  `NOT_FOUND` (exit `3`).
- Failure recovery: `retry` is the sanctioned way to re-arm a failed job;
  `cancel` the only sanctioned way to stop one. Never delete queue rows to clear
  a stuck job.

## 11. `query`

```text
axiom-graphd query context --solution <id> (--symbol <name>|--node-id <id>) [--max-bytes <n>] [--max-nodes <n>] [--depth <n>]
axiom-graphd query impact --solution <id> (--symbol <name>|--node-id <id>) [--max-bytes <n>] [--max-nodes <n>] [--depth <n>]
```

- Arguments: required `--solution <id>` and exactly one of `--symbol <name>` or
  `--node-id <id>`; optional `--max-bytes <n>`, `--max-nodes <n>` and
  `--depth <n>`, each bounded by its own range (`--max-nodes 0` and `--depth 99`
  are rejected). Supplying both subject forms, or neither, is a rejection.
- Behaviour: loads the project's published generation (the pinned snapshot) and
  answers `context` (the node and its in-file containment neighbours) or
  `impact` (the edges that reach the node) from it. Every answer names the
  `generation_id` it was pinned to, so a later publish cannot silently change a
  past answer.
- Example response (captured run, Windows 11 x64, task H-002):

```json
{"solution_id":"demo-solution","generation_id":"3e1996028b0ee400673115f6fadb8881c8daa024a74fc2d4a38a1617be618f34","kind":"context","target":"Demo.Auth.TokenSource","limits":{"max_bytes":8192,"max_nodes":64,"depth":1},"records":[{"key":"0b60c4cc994c7478","kind":"class","body":{"id":"0b60c4cc994c7478","kind":"class","name":"TokenSource","qualified_name":"Demo.Auth.TokenSource","span":{"end":142,"start":131}}}],"omitted":0,"truncated":false,"reasons":[],"bytes":182}
```

- Exit codes: `0` when the projection is produced. A subject not present in the
  pinned snapshot is `NOT_FOUND` (exit `3`); a malformed subject or out-of-range
  bound is `2` (`VALIDATION_ERROR`); a solution with no published generation is
  reported honestly rather than answered from an empty graph.
- Failure recovery: a `NOT_FOUND` means the subject is not in the pinned
  generation - run `serve` or `reconcile` to publish the current tree, or widen
  the selector to a qualified name. Never widen `--max-nodes` or `--depth` past
  their bounds to force an answer; the bounds are contract.

## 12. `render`

```text
axiom-graphd render --solution <id> [--project <id>]... --out <dir>
```

- Arguments: required `--solution <id>`; repeatable `--project <id>`, where an
  empty list means every registered project; required `--out <dir>`, which must
  be a non-empty directory path (`--out ""` is rejected).
- Behaviour: reads every selected project's published generation through the
  frozen reader and concatenates **every** node shard and **every** edge shard the
  generation's manifest names - never only the first - then writes two artifacts
  into `--out`: a self-contained `result.html` that draws the relationship graph,
  and a machine-readable `summary.json` that carries the same inventory.
  `result.html` draws each node and edge with its frozen `kind`, draws the four
  resolution classes (`exact_static`, `inferred_static`, `annotated`,
  `unresolved`) distinctly, and draws an edge whose target is unresolved or absent
  as a placeholder rather than as a resolved node. Both artifacts carry an
  always-present coverage-and-freshness banner taken from the generation's
  coverage document and manifest, so a partially analysed graph is never
  presented as complete. Two renders of the same generation are byte-identical,
  and neither artifact carries a machine-local absolute path.
- Exit codes: `0` when both artifacts are written. A solution or project that is
  not registered is `NOT_FOUND` (exit `3`), and so is a solution that has no
  registered project; a missing or malformed argument is `2`
  (`VALIDATION_ERROR`). A manifest that disagrees with the shards it names, or a
  shard that cannot be read, is an `Internal` error rather than a silently short
  diagram.
- Failure recovery: a `NOT_FOUND` means nothing has been published for that
  project yet - run `serve` or `reconcile` to publish the current tree, then
  render again. A manifest disagreement means the generation is damaged: publish
  a fresh generation instead of editing the checkpoint by hand. Never drop a
  shard from the manifest to make a render succeed; a diagram that silently omits
  a shard is a failure, not a partial success.

## 13. `update`

```text
axiom-graphd update check
axiom-graphd update apply --plan <plan.json> [--approve-digest <sha256>]
```

- Arguments: `check` takes no arguments; `apply` takes required `--plan <path>`
  and optional `--approve-digest <sha256>`, which must be 64 lowercase hex
  characters (`--approve-digest abc` is rejected).
- Behaviour: accepts both documented forms, then answers `NOT_READY`. The verb
  never applies an update it cannot verify: delegated update apply has no trusted
  `axiom` CLI path in this build. It is a wired slice (task H-001), not an
  implemented one.
- Exit codes: `4` (`NOT_READY`) with the reason that delegated update apply has
  no trusted `axiom` CLI path. A malformed digest or missing plan is `2`
  (`VALIDATION_ERROR`). With `--json`, stdout is exactly the error envelope; in
  text mode stdout stays empty and the reason goes to stderr.
- Failure recovery: the trusted `axiom` CLI path is owned by a later work
  package. Until it lands, follow the platform installation runbooks
  ([install-windows](../guides/install-windows.md), [install-linux](../guides/install-linux.md),
  [install-macos](../guides/install-macos.md)) for a manual update. Never
  fabricate an approval digest.

`--json` is the only global option and applies to every verb above. In text mode
stdout stays empty and the reason goes to stderr; with `--json` stdout is exactly
the envelope `{code,message,retryable,details,request_id}` and nothing else.

Wiring is not permission to guess. An unknown flag, an unparsable value, an
out-of-range number or a malformed path is a rejection (`VALIDATION_ERROR`, exit
2) in both modes, never a silent ignore: `--limit 0`, `--reason bogus`,
`--path a\b.cs`, `--approve-digest abc`, `--max-nodes 0` and `--depth 99` are all
rejected, and a JSON rejection still writes the error envelope to stdout.

## 14. Proposed commands (not implemented)

The following shapes appear in the installation contract and are **not**
implemented in this revision. They are listed so an operator is not surprised by
a rejection, and so a future implementation has a documented target.

| Proposed command | Target contract | Current behaviour |
| ---------------- | --------------- | ----------------- |
| `axiom install plan` / `axiom install apply` | [../21-INSTALLATION.md](../21-INSTALLATION.md) | Binary `axiom` does not exist in this repository; `install` is not an accepted `axiom-graphd` command. |
| `axiom service install`, then `axiom service start` / `status` / `uninstall --user` | [../21-INSTALLATION-QUICKSTART.md](../21-INSTALLATION-QUICKSTART.md) | Not accepted as a command. |
| `axiom host detect`, and `axiom bootstrap plan` / `apply` / `verify` | [../18-BOOTSTRAP-AND-MANAGED-INSTRUCTIONS](../18-BOOTSTRAP-AND-MANAGED-INSTRUCTIONS.md) | Not accepted as commands. |
| `axiom-graphd checkpoint create\|verify`, `axiom-graphd snapshot read\|export\|gc` | CLI contract `docs/16-CLI-AND-CONTROL-API.md` in `axiom-specs` | Documented in the contract, but no module owns them in this revision, so `parse` rejects them as an unrecognised command (`VALIDATION_ERROR`, exit 2). |
| `axiom-mcp serve --host 127.0.0.1 --port 8766` | Owned by `axiom-mcp`, not this repository. | Out of scope for this reference; loopback-only binding is contract. |

Do not treat a module existing in `crates/` as a command: availability is decided
by `parse` in `crates/axiom-graphd/src/cli.rs`, and the tables in sections 1 and
4 to 13 mirror exactly that.

## 15. Exit-code and envelope rules

- Every invocation returns exactly one frozen exit code. Code `1` is unassigned
  on purpose so a generic shell or runtime failure is never mistaken for an Axiom
  outcome.
- Text mode writes diagnostics to stderr and leaves stdout empty on failure.
- `--json` writes exactly one JSON object to stdout. On failure that object is
  the envelope `{code,message,retryable,details,request_id}` whose `code` is a
  stable `ErrorCode` spelling. Diagnostic prose never joins the JSON object, and
  no source path leaks into it.
- See [CLI-EXIT-CODES](../CLI-EXIT-CODES.md) for the complete frozen tables.

## 16. Related documents

- [CLI-EXIT-CODES](../CLI-EXIT-CODES.md) - frozen exit-code and error-code
  tables.
- [../README.md](../README.md) - the command surface at a glance and how to
  build and verify this workspace.
- [../21-INSTALLATION](../21-INSTALLATION.md) and
  [../21-INSTALLATION-QUICKSTART](../21-INSTALLATION-QUICKSTART.md) - install
  contract.
- [../22-OPERATIONS-AND-TROUBLESHOOTING](../22-OPERATIONS-AND-TROUBLESHOOTING.md)
  - operator diagnostics.
- [../docs/README](../README.md) - documentation index.
- [install-windows](../guides/install-windows.md),
  [install-linux](../guides/install-linux.md),
  [install-macos](../guides/install-macos.md) - platform runbooks.
