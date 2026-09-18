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
| doctor | available | Accepted positional; executes and reports `NOT_READY`. |
| serve | available | Accepted positional; takes the instance lock, then reports `NOT_READY`. |
| install | proposed | Not accepted by `parse`; belongs to the installation work package. |
| service | proposed | Not accepted by `parse`; belongs to the native lifecycle work package. |
| bootstrap | proposed | Not accepted by `parse`; belongs to the bootstrap work package. |
| host | proposed | Not accepted by `parse`; belongs to the host-configuration work package. |
| solution | proposed | Not accepted by `parse`; the module exists but is not wired into argv. |
| reconcile | proposed | Not accepted by `parse`; the module exists but is not wired into argv. |
| status | proposed | Not accepted by `parse`; belongs to the diagnostics work package. |
| query | proposed | Not accepted by `parse`; the module exists but is not wired into argv. |
| changed | proposed | Not accepted by `parse`; the module exists but is not wired into argv. |
| queue | proposed | Not accepted by `parse`; the module exists but is not wired into argv. |
| update | proposed | Not accepted by `parse`; the module exists but is not wired into argv. |
<!-- END COMMAND STATUS -->

Global arguments:

| Argument | State | Applies to | Behaviour |
| -------- | ----- | ---------- | --------- |
| `--json` | available | every command | Machine-readable mode. Writes exactly one JSON object to stdout; diagnostics stay on stderr. |
| `--registry <path>` | available | `serve` only | Explicit registry config path, passed as argv. Supplying it for any other command is rejected. |
| `--help`, `-h` | available | - | Same as the `help` command. |
| `--version`, `-V` | available | - | Same as the `version` command. |
| `--all` | proposed | `version` | Not accepted by this revision's `parse`. |
| `--dry-run`, `--apply` | proposed | `solution register` | Not accepted; documented by `../21-INSTALLATION.md` for the intended revision. |
| `--plan`, `--approve-digest` | proposed | `bootstrap apply` | Not accepted; documented by `../21-INSTALLATION-QUICKSTART.md`. |

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
  doctor [--json]                      print diagnostics (never repairs automatically)
  help, --help                         print this help

Options:
  --json    write exactly one JSON object to stdout; diagnostics go to stderr

Exit codes:
```

  The exit-code table then lists every frozen code and its meaning. Code `1`
  stays unassigned and is deliberately absent.
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

- Arguments: none in this revision. `--solution <id>` and `--all` are proposed.
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

## 6. Proposed commands (not implemented)

The following shapes appear in the installation contract and are **not**
implemented in this revision. They are listed so an operator is not surprised by
a rejection, and so a future implementation has a documented target.

| Proposed command | Target contract | Current behaviour |
| ---------------- | --------------- | ----------------- |
| `axiom install plan` / `axiom install apply` | [../21-INSTALLATION.md](../21-INSTALLATION.md) | Binary `axiom` does not exist in this repository; `install` is not an accepted `axiom-graphd` command. |
| `axiom service install`, then `axiom service start` / `status` / `uninstall --user` | [../21-INSTALLATION-QUICKSTART.md](../21-INSTALLATION-QUICKSTART.md) | Not accepted as a command. |
| `axiom host detect`, and `axiom bootstrap plan` / `apply` / `verify` | [../18-BOOTSTRAP-AND-MANAGED-INSTRUCTIONS](../18-BOOTSTRAP-AND-MANAGED-INSTRUCTIONS.md) | Not accepted as commands. |
| `axiom-graphd solution register`, `axiom-graphd solution list` | [../21-INSTALLATION.md](../21-INSTALLATION.md) | `crates/axiom-graphd/src/commands/solution.rs` exists, but `solution` is not wired into `parse` and is rejected. |
| `axiom-graphd reconcile`, `query`, `changed`, `queue`, `update`, `status` | [../WATCHER-QUEUE-AND-ANALYSIS](../WATCHER-QUEUE-AND-ANALYSIS.md) | Modules exist under `crates/axiom-graphd/src/commands/`, but none is wired into `parse`. |
| `axiom-mcp serve --host 127.0.0.1 --port 8766` | Owned by `axiom-mcp`, not this repository. | Out of scope for this reference; loopback-only binding is contract. |

Do not treat a module existing in `crates/` as a command: availability is decided
by `parse` in `crates/axiom-graphd/src/cli.rs`, and the table in section 1 mirrors
exactly that.

## 7. Exit-code and envelope rules

- Every invocation returns exactly one frozen exit code. Code `1` is unassigned
  on purpose so a generic shell or runtime failure is never mistaken for an Axiom
  outcome.
- Text mode writes diagnostics to stderr and leaves stdout empty on failure.
- `--json` writes exactly one JSON object to stdout. On failure that object is
  the envelope `{code,message,retryable,details,request_id}` whose `code` is a
  stable `ErrorCode` spelling. Diagnostic prose never joins the JSON object, and
  no source path leaks into it.
- See [CLI-EXIT-CODES](../CLI-EXIT-CODES.md) for the complete frozen tables.

## 8. Related documents

- [CLI-EXIT-CODES](../CLI-EXIT-CODES.md) - frozen exit-code and error-code
  tables.
- [../21-INSTALLATION](../21-INSTALLATION.md) and
  [../21-INSTALLATION-QUICKSTART](../21-INSTALLATION-QUICKSTART.md) - install
  contract.
- [../22-OPERATIONS-AND-TROUBLESHOOTING](../22-OPERATIONS-AND-TROUBLESHOOTING.md)
  - operator diagnostics.
- [../docs/README](../README.md) - documentation index.
- [install-windows](../guides/install-windows.md),
  [install-linux](../guides/install-linux.md),
  [install-macos](../guides/install-macos.md) - platform runbooks.
