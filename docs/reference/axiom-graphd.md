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
| doctor | available | Accepted positional; `doctor [--solution <id>]` executes and answers `NOT_READY`. |
| serve | available | Accepted positional; takes the instance lock, then reports `NOT_READY`. |
| status | available | Wired in task H-001: accepts `status --solution <id>` and answers `NOT_READY`. |
| solution | available | Wired in task H-001: accepts `solution register\|list\|remove` and answers `NOT_READY`. |
| changed | available | Wired in task H-001: accepts the explicit-hint and `--from-json` forms and answers `NOT_READY`. |
| queue | available | Wired in task H-001: accepts `queue list\|retry\|cancel` and answers `NOT_READY`. |
| reconcile | available | Wired in task H-001: accepts all three `--scope` forms and answers `NOT_READY`. |
| query | available | Wired in task H-001: accepts `query context\|impact` and answers `NOT_READY`. |
| update | available | Wired in task H-001: accepts `update check\|apply` and answers `NOT_READY`. |
| install | proposed | Not accepted by `parse`; belongs to the installation work package. |
| service | proposed | Not accepted by `parse`; belongs to the native lifecycle work package. |
| bootstrap | proposed | Not accepted by `parse`; belongs to the bootstrap work package. |
| host | proposed | Not accepted by `parse`; belongs to the host-configuration work package. |
<!-- END COMMAND STATUS -->

`available` means `parse` accepts the command; it does not mean the pipeline
behind it exists. Every verb wired in task H-001 accepts its full documented
argument surface and then answers `NOT_READY` (exit 4) with one stable reason
that names the binding it still needs. Sections 6 to 12 list those verbs, their
accepted forms and their reasons.

Global arguments:

| Argument | State | Applies to | Behaviour |
| -------- | ----- | ---------- | --------- |
| `--json` | available | every command | Machine-readable mode. Writes exactly one JSON object to stdout; diagnostics stay on stderr. |
| `--registry <path>` | available | `serve` only | Explicit registry config path, passed as argv. Supplying it for any other command is rejected. |
| `--help`, `-h` | available | - | Same as the `help` command. |
| `--version`, `-V` | available | - | Same as the `version` command. |
| `--solution <id>` | available | `doctor`, `status`, `changed`, `reconcile`, `queue`, `query`, `solution list`/`remove` | Named solution scope. Rejected for a verb that does not accept it. |
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
axiom-graphd doctor --json
```

- Arguments: optional `--solution <id>` (wired in task H-001); `--all` is proposed.
- Example response in this revision: none. The command does not produce a
  diagnostic report; it fails with a stable reason.
- Exit codes: `4` (`NOT_READY`) with `NOT_READY` and the reason that `doctor` has
  no status sources in this build and that the diagnostic inventory is
  implemented by a later work package. With `--json`, stdout is the error
  envelope `{code,message,retryable,details,request_id}` and nothing else; in
  text mode stdout stays empty and the diagnostic goes to stderr.
- Failure recovery: the diagnostic inventory is a later work package; use the
  version report and the platform runbooks
  ([install-windows](../guides/install-windows.md), [install-linux](../guides/install-linux.md),
  [install-macos](../guides/install-macos.md)) until it is implemented. `doctor` never
  repairs automatically, so a repair is never expected from it.

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
  config, then takes the single-owner instance lock at `AXIOM_HOME/run/daemon.lock`.
  It then reports that the reconcile worker loop is not part of this work package
  and exits. `serve` does not serve yet.
- Exit codes and recovery:

| Condition | Exit code | Recovery |
| --------- | --------- | -------- |
| Reconcile loop not implemented | `4` (`NOT_READY`) | Expected in this revision. Use the read-only/foreground path or wait for the owning work package. |
| `AXIOM_HOME` relative, remote, cloud-synchronised or a device path | `2` (`UNSAFE_HOME_PATH`) | Set an absolute `AXIOM_HOME` on a supported local filesystem. |
| Registry/config rejected or malformed | `2` (`CONFIG_INVALID`) | Fix the named field and re-run. Never delete the database to silence a config error. |
| Another owner holds the instance lock | `10` (`WRITER_ALREADY_RUNNING`) | Identify the owning process and coordinate. Never delete `run/daemon.lock` by guess. |
| Lock held but unusable | Retryable; bounded retry | Retry with a bounded wait, then report. |
| `--registry` supplied for another command | `2` (`VALIDATION_ERROR`) | Remove the flag; it applies only to `serve`. |

- `SIGINT`/`SIGTERM` request a bounded graceful drain, not queue deletion.
- Only one writer per bound output namespace and one daemon per OS user is
  allowed; the instance lock is how that is enforced.

## 6. `status`

```text
axiom-graphd status --solution <id>
axiom-graphd status --solution <id> --json
```

- Arguments: required `--solution <id>`; optional `--json`. Omitting `--solution`
  is a rejection, not a defaulted scope.
- Behaviour: accepts the full documented argument surface, then answers
  `NOT_READY`. The verb has no open store in this build, so it never reports a
  solution state it cannot verify. It is a wired slice (task H-001), not an
  implemented one.
- Exit codes: `4` (`NOT_READY`) with the reason that `status` has no open store
  in this build. With `--json`, stdout is exactly the error envelope
  `{code,message,retryable,details,request_id}`; in text mode stdout stays empty
  and the reason goes to stderr.
- Failure recovery: the open-store binding is owned by a later work package.
  Until it lands, read the project manifest and generation pointer through the
  frozen reader instead of asking this verb. Never delete a store to silence the
  reason.

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
- Behaviour: accepts each documented form, then answers `NOT_READY`. The verb
  performs no registry write in this build, so a `--apply` never mutates the
  user-owned registry. It is a wired slice (task H-001), not an implemented one.
- Exit codes: `4` (`NOT_READY`) with the reason that the user-owned registry
  write path is added by a later work package. With `--json`, stdout is exactly
  the error envelope; in text mode stdout stays empty and the reason goes to
  stderr.
- Failure recovery: registering a solution is owned by a later work package.
  Until then, edit the solution configuration by hand and re-run `solution list`
  when the write path lands. Never hand-edit a registry the verb refused to
  touch; a rejection here is the guard, not a bug.

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
- Behaviour: accepts all three scope forms, then answers `NOT_READY`. The verb
  builds no plan it cannot enqueue: the reconcile plan has no queue writer in
  this build. It is a wired slice (task H-001), not an implemented one.
- Exit codes: `4` (`NOT_READY`) with the reason that the reconcile plan has no
  queue writer. A malformed scope or timeout is `2` (`VALIDATION_ERROR`). With
  `--json`, stdout is exactly the error envelope; in text mode stdout stays empty
  and the reason goes to stderr.
- Failure recovery: the queue writer is owned by a later work package. Until it
  lands, run a full analysis pass out of band instead of expecting a partial
  reconcile. Never raise the timeout past its bound to force progress.

## 10. `queue`

```text
axiom-graphd queue list --solution <id> [--limit <n>]
axiom-graphd queue retry --job <id>
axiom-graphd queue cancel --job <id>
```

- Arguments: `list` takes required `--solution <id>` and optional `--limit <n>`,
  bounded from `1` to the queue maximum (`--limit 0` is rejected); `retry` and
  `cancel` take required `--job <id>`.
- Behaviour: accepts all three documented forms, then answers `NOT_READY`. The
  verb never reports or mutates a queue it cannot open: the operational queue has
  no open store in this build. It is a wired slice (task H-001), not an
  implemented one.
- Exit codes: `4` (`NOT_READY`) with the reason that the operational queue has no
  open store. A missing `--job` or an out-of-range `--limit` is `2`
  (`VALIDATION_ERROR`). With `--json`, stdout is exactly the error envelope; in
  text mode stdout stays empty and the reason goes to stderr.
- Failure recovery: the queue store binding is owned by a later work package.
  Until it lands, inspect queued work in the store directory directly. Never
  delete queue rows to clear a stuck job; `queue cancel` is the only sanctioned
  mutation, and it is not yet implemented.

## 11. `query`

```text
axiom-graphd query context --solution <id> (--symbol <name>|--node-id <id>) [--max-bytes <n>] [--max-nodes <n>] [--depth <n>]
axiom-graphd query impact --solution <id> (--symbol <name>|--node-id <id>) [--max-bytes <n>] [--max-nodes <n>] [--depth <n>]
```

- Arguments: required `--solution <id>` and exactly one of `--symbol <name>` or
  `--node-id <id>`; optional `--max-bytes <n>`, `--max-nodes <n>` and
  `--depth <n>`, each bounded by its own range (`--max-nodes 0` and `--depth 99`
  are rejected). Supplying both subject forms, or neither, is a rejection.
- Behaviour: accepts both `context` and `impact` forms, then answers
  `NOT_READY`. The verb never returns rows it cannot pin: bounded context and
  impact have no pinned snapshot source in this build. It is a wired slice (task
  H-001), not an implemented one.
- Exit codes: `4` (`NOT_READY`) with the reason that bounded context and impact
  have no pinned snapshot source. A malformed subject or out-of-range bound is
  `2` (`VALIDATION_ERROR`). With `--json`, stdout is exactly the error envelope;
  in text mode stdout stays empty and the reason goes to stderr.
- Failure recovery: the pinned-snapshot source is owned by a later work package.
  Until it lands, read the published generation through the frozen reader. Never
  widen `--max-nodes` or `--depth` past their bounds to force an answer; the
  bounds are contract.

## 12. `update`

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

## 13. Proposed commands (not implemented)

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
6 to 12 mirror exactly that.

## 14. Exit-code and envelope rules

- Every invocation returns exactly one frozen exit code. Code `1` is unassigned
  on purpose so a generic shell or runtime failure is never mistaken for an Axiom
  outcome.
- Text mode writes diagnostics to stderr and leaves stdout empty on failure.
- `--json` writes exactly one JSON object to stdout. On failure that object is
  the envelope `{code,message,retryable,details,request_id}` whose `code` is a
  stable `ErrorCode` spelling. Diagnostic prose never joins the JSON object, and
  no source path leaks into it.
- See [CLI-EXIT-CODES](../CLI-EXIT-CODES.md) for the complete frozen tables.

## 15. Related documents

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
