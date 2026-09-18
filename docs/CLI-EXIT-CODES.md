# CLI exit codes

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Frozen CLI contract (task B-002).

Every `axiom-graphd` invocation returns exactly one of the process exit codes
below. The numbers are a stable interface: scripts, hook adapters and the
installation engine branch on them, so a number can only change through a
contract change in `axiom-specs` (`docs/16-CLI-AND-CONTROL-API.md` section 6,
Errors and exits).

`--help` prints the same table. Both are generated from
`graph_core::error::ExitCode::all()` (`exit_code_table()` in
`crates/axiom-graphd/src/cli.rs`), so the documentation and the enforced exit
status come from one source and cannot drift: the compile-time test
`cli_exit_code_doc_matches_the_frozen_contract` fails if this file disagrees with
the code it documents.

Exit code `1` stays unassigned on purpose, so a generic shell or runtime failure
is never mistaken for an Axiom outcome.

<!-- BEGIN GENERATED EXIT CODES -->
| Code | Meaning | Raised when |
| ---- | ------- | ----------- |
| 0 | success | The command completed successfully. |
| 1 | (unassigned) | Reserved; axiom never returns it. |
| 2 | validation | Flags, arguments or configuration were rejected. |
| 3 | not found | A referenced entity does not exist. |
| 4 | not ready/stale | The service is not ready, or the requested state is stale. |
| 5 | authorization | The caller is not authenticated or not permitted for this scope. |
| 6 | conflict | The request conflicts with current state. |
| 7 | timeout/busy | A bounded wait expired or the resource is busy; retry may work. |
| 8 | I/O internal | An I/O failure occurred, or an internal Axiom defect was detected. |
| 9 | incompatible | Input, runtime or schema is incompatible with this binary. |
| 10 | lock unavailable | A required cross-process lock is held by another owner. |
| 20 | partial multi-repo operation | A multi-repository operation partially succeeded. |
<!-- END GENERATED EXIT CODES -->

Token-for-token equal to `axiom-specs/docs/16-CLI-AND-CONTROL-API.md` section 6:

    0 success, 2 validation, 3 not found, 4 not ready/stale, 5 authorization, 6 conflict, 7 timeout/busy, 8 I/O internal, 9 incompatible, 10 lock unavailable, 20 partial multi-repo operation

Text mode writes diagnostics to stderr and leaves stdout empty. `--json` writes
exactly one JSON object to stdout: `0` on success, and on failure the error
envelope `{code,message,retryable,details,request_id}` whose `code` is a stable
`ErrorCode` spelling. Diagnostic prose never joins the JSON object.

## Error code to exit code

Every `AxiomError` carries one stable `ErrorCode`; `exit_code_for()` maps it to
the process exit code. The table is generated from `ErrorCode::all()` and
`exit_code_for()`, and the same compile-time test pins it.

| Error code | Exit code |
| ---------- | --------- |
| VALIDATION_ERROR | 2 |
| UNAUTHENTICATED | 5 |
| FORBIDDEN | 5 |
| NOT_FOUND | 3 |
| CONFLICT | 6 |
| INCOMPATIBLE_INPUT | 9 |
| RATE_LIMITED | 7 |
| NOT_READY | 4 |
| WRITER_ALREADY_RUNNING | 10 |
| WORKTREE_BUSY | 6 |
| MIGRATION_CHECKSUM_MISMATCH | 9 |
| MIGRATION_ORDER_CONFLICT | 9 |
| SCHEMA_NEWER_THAN_BINARY | 9 |
| SQLITE_UNSUPPORTED_VERSION | 9 |
| SQLITE_NETWORK_STORAGE_UNSUPPORTED | 9 |
| UNSAFE_HOME_PATH | 2 |
| UNSAFE_PORTABLE_PATH | 2 |
| CONFIG_INVALID | 2 |
| SHUTTING_DOWN | 4 |
| INTERNAL | 8 |

`RATE_LIMITED`, `NOT_READY`, `CONFLICT`, `WORKTREE_BUSY` and `SHUTTING_DOWN`
are retryable by default; every other code is not.

The wire spelling of each `ErrorCode` must not change without a contract change
in `axiom-specs`; the numeric exit status is likewise frozen.
