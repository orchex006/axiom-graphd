# Native operations and recovery runbooks (V2-026)

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Implementation/release
evidence is not implied.

This runbook covers normal native operation, how to read the two cutover
journals, how to roll back, what a coexistence refusal means, recovery after an
interrupted executable replacement, and the Windows / macOS / Linux differences.
Every claim names the source it comes from. Any step that has never been executed
on a real host is marked **UNVERIFIED** on purpose: an unproven answer must not
read as a proven one.

Read the markers before trusting a sentence.

| Marker | Meaning |
| --- | --- |
| **available** | The verb or module exists in this revision; the named source contains it. |
| **wired, not implemented** | `parse` accepts the verb and its whole documented argument surface, but the verb answers `NOT_READY` (exit 4) because the binding that would let it work belongs to a later work package (task H-001). It is never shown below as a working command. |
| **proposed** | Documented for a later work package. It is **not** runnable here and is never shown below as a command to run. |
| **UNVERIFIED** | The behaviour is decided by source only. No native execution, no real host mechanism and no platform certification backs it. |

A module under `crates/` is not a command. A verb is available only when `parse`
accepts it: `crates/axiom-graphd/src/cli.rs` and `crates/axiom/src/cli.rs`.

## 1. What actually runs today

Two binaries ship from this repository: `axiom-graphd` (`crates/axiom-graphd`)
and `axiom` (`crates/axiom-cli`). These verbs are parsed in this revision.
`version`, `help`, `serve`, `doctor`, `status`, `solution`, `reconcile`, `queue`
and `query` do work; `changed` and `update` are wired but still answer
`NOT_READY`.

| Verb | State | Source |
| --- | --- | --- |
| `axiom-graphd serve [--registry <path>] [--json]` | available | `cli.rs` arm `["serve"]`; acquires the instance lock and runs one bounded reconcile pass, publishing a generation |
| `axiom-graphd version [--json]` | available | `cli.rs` arm `["version"]` |
| `axiom-graphd help` (also `--help`, `-h`) | available | `cli.rs` arm `["help"]` and the empty argv case |
| `axiom-graphd doctor [--solution <id>] [--json]` | available | `cli.rs` slice `doctor`; prints a diagnostic report from the open store (`overall` may be `degraded`) |
| `axiom-graphd status --solution <id> [--json]` | available | `cli.rs` slice `status`; reads queue, freshness and coverage state from the open store |
| `axiom-graphd solution register|list|remove ...` | available | `cli.rs` slice `solution`; reads and writes the solution registry in the open store |
| `axiom-graphd changed ...` | wired, not implemented | `cli.rs` slice `changed` (task H-001); `NOT_READY` (the change-hint path has no binding source in argv) |
| `axiom-graphd reconcile ...` | available | `cli.rs` slice `reconcile`; enqueues the plan and runs the same bounded pass as `serve` |
| `axiom-graphd queue list|retry|cancel ...` | available | `cli.rs` slice `queue`; reads and steers the durable queue in the open store |
| `axiom-graphd query context|impact ...` | available | `cli.rs` slice `query`; answers from the project's pinned published generation |
| `axiom-graphd update check|apply ...` | wired, not implemented | `cli.rs` slice `update` (task H-001); `NOT_READY` (no trusted `axiom` CLI path in this build) |
| `axiom version [--all] [--json]` | available | `crates/axiom/src/cli.rs` arm `["version"]` |
| `axiom help` (also `--help`, `-h`) | available | `crates/axiom/src/cli.rs` |

**wired, not implemented** is a separate state on purpose (task H-001): the verb
and its arguments are accepted, then it answers `NOT_READY` (exit 4) with the
reason that names the missing binding. It is not a working verb, and no recovery
step below may be written as if it were one. Task H-002 left only `changed` and
`update` in that state; the other operator verbs are `available` and execute.

These verbs do **not** exist. Do not run them: `parse` rejects them as an
unrecognised command (`VALIDATION_ERROR`, exit 2), and no binary in this tree
implements the work.

| Not a verb | Why |
| --- | --- |
| `axiom-graphd migrate ...` | No positional arm in `cli.rs`. The migration crates are libraries only. |
| `axiom migrate apply`, `axiom migrate verify`, `axiom migrate rollback` | `migrate` is a recognised **pending** verb in `crates/axiom/src/cli.rs` (`PENDING_VERBS`) that maps to `NOT_READY` (exit 4). It plans, applies and rolls back nothing. |
| `axiom-graphd checkpoint ...`, `axiom-graphd snapshot ...` | Documented by the CLI contract, but no module owns them in this revision, so `parse` rejects them. |
| `axiom install ...`, `axiom service ...`, `axiom bootstrap ...`, `axiom host ...`, `axiom skills ...`, `axiom specs ...`, `axiom update ...`, `axiom doctor ...`, `axiom support-bundle ...` | Recognised pending verbs (`PENDING_VERBS`) that map to `NOT_READY` (exit 4). |
| `axiom-graphd rollback ...`, `axiom rollback ...` | No such verb exists at all. Recovery is a library call, not a command (see sections 4 and 6). |

Consequence for this runbook: every recovery sequence in sections 4, 5 and 6 is
described as a *mechanism and its contract*, because there is no command that
invokes it yet. Where a runbook step would normally be a shell command, this
document says so instead of inventing one.

## 2. Normal operation

### 2.1 Foreground daemon

```text
axiom-graphd serve
axiom-graphd serve --registry <path>
axiom-graphd serve --json --registry <path>
```

`serve` resolves `AXIOM_HOME`, verifies the destination, loads the service
config, takes the single-owner instance lock at `AXIOM_HOME/run/daemon.lock`
(`crates/axiom-graphd/src/instance_lock.rs`, `LOCK_FORMAT =
"axiom-daemon-lock-v1"`, plus the readable `run/daemon.owner.json` record), then
runs **one bounded reconcile pass** over every registered solution
(`crates/axiom-graphd/src/serve.rs`, task H-002). The pass resumes the checkpoint
lane, plans a stat-based inventory delta, analyses the changed files and
publishes the closed generation through the publication barrier (staging seal,
analysis commit, event-sequence bump, exclusive solution guard,
content-addressed install, atomic pointer replace, outbox acknowledgement). One
invocation publishes at most one generation per project and then exits `0` with
a report naming the published `generation_id` and `manifest_hash`.

What that means in practice:

- Only one daemon per OS user is allowed; the lock is how that is enforced. A
  second `serve` fails with `WRITER_ALREADY_RUNNING` (exit 10). Do not delete
  `run/daemon.lock` to clear it; identify the owning process first.
- `serve` runs one bounded pass, not a continuous loop. Re-run it (or use
  `reconcile`) to pick up the next change; there is no resident process in this
  revision.

A shutdown/graceful-drain contract exists as a library module
(`crates/axiom-graphd/src/lifecycle.rs`, task B-006): `ShutdownToken`,
`DEFAULT_SHUTDOWN_DEADLINE_MS = 90_000`, `SHUTDOWN_EXIT_CODE = NOT_READY`, and a
`DrainState` of `Running` / `Draining` / `Drained` / `DeadlineExpired`.
The bounded pass constructs a `ShutdownToken` and claims it per file, so the pass
stops at a file boundary if the deadline passes. **UNVERIFIED**: `serve` installs
no `SIGINT` / `SIGTERM` handler, so no signal-driven drain has ever run and the
reported `shutdown` state is the token's state at the end of the pass. Treat a
signal-driven drain as a design target, not as observed behaviour.

### 2.2 Opt-in per-user startup registration

Source: `crates/axiom/src/service/startup.rs` (task V2-022). This is a
host-neutral lifecycle over three per-host adapters. It is **not** reachable
from any CLI verb; it is a library API.

Two entry points:

- `ensure_registered(registration, consent: Consent, support, definitions, exec)`
  returns `RegistrationOutcome::Registered`, `AlreadyRegistered`, or
  `Foreground`.
- `remove_registered(registration, definitions, exec)` returns
  `RemovalOutcome::Removed` or `AlreadyRemoved`.

The properties that matter to an operator:

- **Opt-in.** A startup record is only ever created through `ensure_registered`,
  which takes the `Consent` token as its own argument. Registering cannot happen
  as a side effect of planning; enabling indexing does not register startup.
- **Idempotent.** `classify_definition(existing, rendered)` returns `Absent`,
  `Current` or `Superseded`. Only `Absent` and `Superseded` are written; a file
  that already holds the exact bytes is left alone, and a record the host already
  reports as registered returns `AlreadyRegistered` without running a second
  registration command.
- **Removable.** `remove_registered` unloads the record and deletes the
  definition this adapter owns. A second removal is `AlreadyRemoved`, not an
  error.
- **Foreground fallback, not a failure.** When `BackendSupport::Unsupported`,
  nothing is written, nothing is executed, and the run returns
  `RegistrationOutcome::Foreground` naming the documented foreground command.
- **No implicit elevation.** Only a per-user mechanism, only under
  `InstallScope::PerUser`, and only a definition inside the directory the
  adapter owns is ever written or deleted.

The definition file is reached only through the `DefinitionLedger` trait.
`SysDefinitions` is the single implementation that touches the host filesystem
(a plain `std::fs` write, read, remove); every test drives an in-memory ledger
instead. Refusal reasons carried on the error: `not-per-user-mechanism`,
`unsupported-scope`, `unknown-component`, `unsafe-definition-path`,
`foreign-definition`, `empty-definition`, `registry-exit`, `definition-io`.

**UNVERIFIED**: `schtasks.exe` (Windows), `systemctl --user` (Linux) and
`launchctl` (macOS) were never really executed. The adapters render the host
command and hand it to an injected `ServiceExec`; the real `SysExec`
(`crates/axiom/src/service/mod.rs`) spawns a process, but no test or command in
this tree binds it, so no startup record was ever created on a real host.

An operator needs two facts to reason about a startup record:

| Host | Mechanism (`ServiceKind`) | Program | Definition location | Documented foreground fallback |
| --- | --- | --- | --- | --- |
| Windows | `PerUserStartup` | `schtasks.exe` | inside the CLI install root | `axiom-graphd serve --registry <registry.json>` |
| Linux | `SystemdUserUnit` | `systemctl` | `~/.config/systemd/user/<component>.service` | `axiom-graphd serve --registry <registry.json>` |
| macOS | `LaunchAgent` | `launchctl` | `~/Library/LaunchAgents/<component>.plist` | `axiom-graphd serve --registry <registry.json>` |

### 2.3 Reconciling hints

Source: `crates/graph-watch/src/reconcile.rs` (task V2-014). A native filesystem
backend is a *hint* source, never the truth. For every observed batch the
`Reconciler` answers one of three things:

- `ReconcileOutcome::Apply` - the hint stream is trustworthy; act on these
  normalized hints.
- `ReconcileOutcome::Bounded` - do not act yet; confirm this bounded set of paths
  with an inventory scan or a polling snapshot.
- `ReconcileOutcome::FullScan` - a complete inventory is required.

A full scan is requested for a definite reason, named by `ReconcileTrigger`:
`BackendEvent`, `UnpairedRename`, `SaveAllBurst`, `UntrackedInput`,
`CaseOnlyRename`, `SymlinkBoundary`, `FirstPoll`. Two properties are load-bearing:
nothing is silently dropped (a path withheld by the input policy or absent from
the known inventory produces a bounded rescan request rather than a no-op), and a
missing native backend degrades to polling under `BackendPolicy::PreferNative`
rather than failing.

**UNVERIFIED**: the native Windows / macOS watcher legs are declared unverified in
the module itself. The decision logic is exercised through an injected
`ReconcileProbe`, so no native event stream has been observed on a real host.

## 3. Reading the two journals

There are two independent journals. They have different formats and different
owners; do not confuse them.

### 3.1 Migration apply journal (encoded text)

Source: `crates/migration/src/apply.rs` (tasks V2-011 / V2-012). This journal is
not JSON. It is a length-terminated field encoding: every field is followed by a
single LF byte (`FIELD_NEWLINE = 10`). Fields, in order:

```text
axiom-migration-apply-journal   (JOURNAL_MAGIC)
<schema_version>                 (APPLY_SCHEMA_VERSION = 1)
<solution_id>
<plan_digest>                    (64 lowercase hex)
<namespace>
<phase>                          fence | backup | stage | verify | cutover | complete | rollback
<fenced>                         1 | 0
<file_count>
  then per file, 9 fields each:
  <repo_id> <path> <action> <source> <staged> <backup> <expected_sha256> <previous_sha256> <state>
```

- `action` is `create`, `replace` or `regenerate`.
- `state` is `pending`, `staged`, `verified` or `cutover`.
- `source`, `staged`, `backup`, `expected_sha256` and `previous_sha256` may be
  empty; an empty hash field means "no hash recorded for this file".

How to read it like an operator:

1. Confirm the first field is exactly `axiom-migration-apply-journal`. Anything
   else is refused as a foreign document (`unknown-document`); do not try to
   interpret it.
2. Read `phase`. This is how far the run got. `cutover` means some destinations
   may already hold new bytes; `complete` means the run closed cleanly.
3. Read `fenced`. `0` means the old publisher was never proven quiescent, so no
   owned byte moved.
4. For each file, `state` says how far that file got, and `previous_sha256` is the
   hash of the bytes that were there before, which is what a rollback restores.

Parsing is strict by design: a magic mismatch, a malformed field, an unknown
phase or action, a rejected hash, a truncated document and trailing bytes are all
refused (`MIGRATION_JOURNAL_INVALID`). A text editor that rewrites the file's
line endings will therefore make it unreadable, which is intentional: the parser
refuses rather than guesses.

**UNVERIFIED / not wired**: the migration crate defines **no default journal
path**. `ApplyRequest` carries the output `namespace` plus `backup_root` and
`staging_root`, and the document is read and written only through the injected
`JournalStore` trait (`load` / `save`). No implementation of `JournalStore`,
`ApplyIo` or `WriterFence` exists outside `crates/migration/tests/apply.rs`
(in-memory doubles), so there is no on-disk location an operator could open
today. The path becomes real only when a native adapter is written.

### 3.2 Native replacement journal (JSON)

Source: `crates/axiom/src/update/native_apply.rs` (task V2-023). This journal is
JSON with `deny_unknown_fields`, schema version `JOURNAL_SCHEMA_VERSION = 1`, and
a hard parse bound of `MAX_JOURNAL_BYTES` = 64 KiB.

- Path: `journal_path(<destination_root>)` = `<destination_root>/native-apply-journal.json`
  (`JOURNAL_FILE`).
- Fields: `schema_version`, `component`, `version`, `target_version`, `revision`,
  `destination_root`, `portable_path`, `destination_path`, `backup_path`,
  `destination_sha256_before`, `actions`.
- `actions` is the ordered list this replacement performs: `stop`, `backup`,
  `stage`, `cutover`.
- `backup_path` points at the copied-aside previous bytes; the backup sibling uses
  the `BACKUP_SUFFIX` = `.axiom-backup`, and the staged sibling uses
  `STAGE_TEMP_SUFFIX` = `.axiom-staged`.

How to read it like an operator:

1. The journal is written **before** the destination is touched. If it exists, it
   describes the bytes the destination held before the replacement, with their
   digest in `destination_sha256_before`.
2. `component` must match the component you are recovering. A journal for another
   component is refused (`journal-component-mismatch`).
3. `backup_path` and `destination_sha256_before` are both required for a
   rollback. A journal that recorded no backup is refused
   (`journal-has-no-backup`).

The two hashes do different jobs: `destination_sha256_before` is the digest of
the bytes that were replaced, and it is what a restore is verified against, so a
backup that has been edited is refused (`backup-digest-mismatch`) instead of
being written over the installed executable.

## 4. Rolling back

### 4.1 Migration rollback

`rollback_journaled(request, io, journals)` undoes a completed **or** interrupted
cutover from the same journal.

- It deliberately does **not** re-observe the sources: a rollback restores the
  bytes a cutover replaced and must still work after the legacy sources were
  moved aside. It binds to the journal's solution id, plan digest and namespace
  instead, and refuses a foreign journal.
- A destination the run cut over is restored from its verified backup, or removed
  again when the cutover created it. A destination the run never reached is left
  exactly as it is. Every staged copy is discarded.
- Nothing is overwritten on the way back. A destination a human edited after the
  cutover, a destination deleted after it, and a backup whose bytes no longer
  match the recorded previous hash each block the rollback, which returns
  `MIGRATION_ROLLBACK_BLOCKED` with the blocking paths rather than clobbering
  them.

Outcomes and refusals:

| Result | Meaning |
| --- | --- |
| `RollbackStatus::RolledBack` (`rolled-back`) | the cutover was undone |
| `RollbackStatus::AlreadyRolledBack` (`already-rolled-back`) | the journal already recorded a completed rollback |
| `MIGRATION_ROLLBACK_REFUSED` (rule `no-journal`, `cutover-not-started`) | there is nothing this run may undo |
| `MIGRATION_ROLLBACK_BLOCKED` (rule `rollback-blocked`) | a human edit or a missing/drifted backup blocked the undo |

**UNVERIFIED / not wired**: there is no `axiom migrate rollback` verb and no
native `ApplyIo` / `JournalStore`, so this rollback cannot be invoked today. The
behaviour above is decided by source and covered by in-memory tests only.

### 4.2 Native executable rollback

`rollback_native_apply(journal_path, component, fs)` restores exactly the bytes a
journal recorded, and only those:

1. Read the journal; a missing one is `journal-missing`, an oversized one is
   `journal-too-large`, an unparsable one is `journal-unreadable`, another schema
   is `journal-schema-unsupported`, another component is
   `journal-component-mismatch`, and one with no backup is `journal-has-no-backup`.
2. Read the backup; a missing backup is `backup-missing` and a backup whose digest
   is not the recorded one is `backup-digest-mismatch` (fail closed).
3. Write the bytes back to `destination_path`, then read them again and compare;
   a mismatch is `restore-digest-mismatch`.

**UNVERIFIED / not wired**: the only `ActivationFs` implementations in the tree
are in-memory test doubles (`MemFs` in `native_apply.rs`, `MemoryFs` in
`rust_binary.rs`). There is no native adapter, and no `rollback` verb, so no
executable has ever been restored on a real host.

## 5. What "coexistence refused" means and what to do next

`check_coexistence(plan, authorized)` runs **before** the writer fence in
`apply_journaled`. It refuses a plan that would leave the legacy layout and the
V2 layout both live after the run - which would mean one logical output is
dual-written by two trees. It writes nothing when it refuses: not one byte and
not one journal.

It refuses with `MIGRATION_COEXISTENCE_REFUSED` (mapped to `Conflict`) under one
of three rules:

| Rule | What it caught | What the operator does next |
| --- | --- | --- |
| `legacy-destination` | A destination under `.agrimap-agent/knowledge/references/graph` or its historic misspelling `.agrimap-agent/knowledge/references/grahp`; every V2 destination must be under `.axiom/graph`. | Re-plan so every destination is under `.axiom/graph`. Do not edit the plan bytes by hand; rebuild it so its digest is honest. |
| `in-place-legacy-source` | A destination whose source is itself, so applying it would rewrite the legacy file in place and leave both layouts live. | Change the plan to a copy/move into the V2 tree instead of an in-place rewrite. |
| `destination-is-a-source` | A destination that is also an inventoried source, so a cutover would dual-write one file. | Separate the source inventory from the destination set; a path may be one or the other, not both. |

These are **quality refusals, not corruption**. The correct response is to change
the plan's inputs and re-approve a new digest, never to bypass the check. The
refusal is discovered before the fence precisely so that an operator never has to
recover from it.

**UNVERIFIED / not wired**: only exercised through the in-memory test doubles in
`crates/migration/tests/apply.rs`; no real migration was refused on a real tree,
because there is no native adapter and no `migrate` verb.

## 6. Recovery after an interrupted replacement

### 6.1 Migration: resume instead of re-deciding

`apply_journaled` persists the journal at every phase boundary, so an interrupted
run resumes from the journal. The phases, in fixed order:
`fence`, `backup`, `stage`, `verify`, `cutover`, `complete`.

- A file that is already cut over is recognised by its hash, so a resume never
  rewrites it. Even when a journal write after a cutover was lost, a destination
  that already holds exactly the bytes this run would have written counts as cut
  over - the resume does not guess.
- A failure during cutover restores the pre-cutover bytes from the verified
  backups.
- A destination whose bytes are no longer the bytes this cutover wrote (a human
  edit after cutover) is never overwritten: the run reports
  `MIGRATION_APPLY_INCOMPLETE` with the blocking path, and the human edit wins.
- The fence must hold: if the old publisher cannot be proven quiescent the run
  returns `MIGRATION_WRITER_STILL_PUBLISHING` and writes nothing. A backup, a
  staged file or a destination that is not the bytes the plan recorded is
  `MIGRATION_APPLY_HASH_MISMATCH`; a destination in a state this cutover may not
  start from is `MIGRATION_APPLY_CONFLICT`.

Run outcomes: `ApplyStatus::Applied` (`applied`), `Resumed` (`resumed`),
`AlreadyComplete` (`already-complete`). A third run over an already-applied
journal is a no-op.

### 6.2 Native replacement: the journal precedes the first byte

`native_apply` runs five phases in fixed order: `verify`, `journal`, `fence`,
`stage`, `cutover` (`APPLY_PHASES`).

- **Journal before bytes.** The rollback journal (`RollbackJournal`) and the
  copied-aside backup are persisted *before* the destination is touched, so a
  crash between the two still leaves a journal that describes the pre-replacement
  bytes.
- **One rename is the only mutation.** The previous bytes are read, copied to
  `<destination>.axiom-backup`, and recorded with their digest; the new bytes are
  written to `<destination>.axiom-staged` and read back; then one `rename`
  exchanges the destination. Nothing destructive happens before a refusal, and
  the destination is never truncated, so a crash before the rename leaves the
  installed executable byte-identical.
- **Recovery** is then `rollback_native_apply` over that journal (section 4.2).

Refusals an operator will meet on the update path:

| Refusal rule | Meaning |
| --- | --- |
| `destination-missing` | There is no installed executable to replace. A fresh install is `update::rust_binary`'s job, not a replacement. |
| `destination-in-use` | A process still holds the destination open. `Conflict`, `retryable=true`; stop the affected processes and retry. |
| `bytes-digest-mismatch` | The replacement bytes are not the artifact the release declares. |
| `already-current` | The release is no newer than the installed one. |
| `artifact-digest-mismatch`, `host-mismatch`, `version-mismatch`, `component-mismatch` | The verified artifact and the release disagree; nothing moved. |
| `journal-too-large` | The journal exceeded `MAX_JOURNAL_BYTES` (64 KiB). |

The full refusal set is the public `REFUSAL_RULES: [&str; 26]` array.

**UNVERIFIED / not wired**: the in-use fence cannot enumerate open handles
through `std`, so `NativeInUseProbe` reports `InUse::Unobservable` on a real
machine (see section 7). No real process is stopped: `crate::update::drain` and
`crate::service::control::plan_process_stop` are the intended partners but are
**not wired in** - neither is called from any command, so "stop the affected
processes first" is a manual operator step with no tool behind it yet. No native
`ActivationFs`, `FilesystemProbe` (other than `NativeFilesystemProbe`) or
`InUseProbe` adapter is bound to the real filesystem, and no native cutover has
been executed on any host.

## 7. Windows / macOS / Linux differences

The differences below are the ones that change an operator's actions.

| Concern | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Startup mechanism (`ServiceKind`) | `PerUserStartup`, a per-user Scheduled Task at logon (`schtasks.exe`) | `SystemdUserUnit`, a **user** unit (`systemctl --user`) when a user session bus exists | `LaunchAgent`, a per-user `LaunchAgents` plist (`launchctl`) |
| Definition location | inside the CLI install root | `~/.config/systemd/user/<component>.service` | `~/Library/LaunchAgents/<component>.plist` |
| No-backend fallback | foreground `axiom-graphd serve --registry <registry.json>` | foreground, unchanged; a distribution without systemd is **not** a platform failure | foreground `axiom-graphd serve --registry <registry.json>` |
| Path limit | `MAX_NATIVE_PATH_UNITS` = 260 code units unless the path is already verbatim (`\\?\`), then the limit does not apply | no limit imposed | no limit imposed |
| Open-handle observation | not observable through `std` | not observable through `std` | not observable through `std` |
| Storage class of a path | `StorageLocation::Unknown` (drive type is not available through `std`) | `StorageLocation::Local { volume_id }` from `metadata.dev()` | `StorageLocation::Local { volume_id }` from `metadata.dev()` |
| Link flavour observed | reported as `SymlinkKind::Symlink` (`std` cannot tell a junction from a symlink) | `SymlinkKind::Symlink` | `SymlinkKind::Symlink` |

Two platform consequences worth stating plainly, both derived from
`crates/platform/src/filesystem.rs`:

- The open-handle check (`check_open_handle_replacement`) can only answer
  `HandleCheck::Clear` or `HandleCheck::Unobservable` on every platform, because
  `EntryFacts::open_handles()` is `None` when the host cannot enumerate handles.
  `HandleCheck::Unobservable` means "an atomic rename is what protects a held
  handle", not "no handle exists". `NativeInUseProbe` maps that to
  `InUse::Unobservable` and records it rather than upgrading it to `Idle`.
- The same-filesystem rule for staging (`check_same_filesystem_staging`) refuses
  a volume it cannot classify (`classifiable-volume`). On Windows,
  `NativeFilesystemProbe::storage_location` returns `StorageLocation::Unknown`
  for every path, so that check cannot pass with the native probe as written.
  **UNVERIFIED, but source-decided**: a Windows native replacement through
  `check_replacement` would be refused on this rule until a real drive-type probe
  exists. This was not executed; it is read from the two functions above.

Per-user lock semantics also differ underneath: `crates/graph-core/src/locks.rs`
with `locks_windows.rs` and `locks_posix.rs`. Shared readers coexist and only the
exclusive writer is refused; readers coexist across processes on Windows, and the
writer is refused on POSIX. **UNVERIFIED**: no cross-process lock was exercised
on a real Windows or macOS host.

## 8. What is not wired yet

Collected in one place so nothing above reads as more proven than it is. Every
line here is **UNVERIFIED**.

- **No real process stop.** `crate::update::drain` (bounded drain;
  `DEFAULT_DRAIN_SECONDS` 30, `MIN` 0, `MAX` 300; phases `pause_new_work`,
  `drain_in_flight`, `resume`; outcomes `drained`, `timed_out`, `force_killed`;
  `DrainPolicy::default().allow_forced_kill == false`, and `drain` never kills)
  and `crate::service::control::plan_process_stop` (which refuses a
  `foreign-process` and needs an owned `ServiceOwnership` token) are library
  functions with tests only. Neither is called from any CLI verb, so the update
  path has no wired stop step.
- **No native adapter.** No implementation of `ApplyIo`, `WriterFence`,
  `JournalStore`, `ActivationFs`, `FilesystemProbe` (beyond
  `NativeFilesystemProbe`) or `InUseProbe` binds the injected traits to the real
  filesystem outside tests. `SysExec` exists and would spawn a process, but
  nothing in the tree invokes it.
- **`NativeFilesystemProbe` reports `Unobservable` for open handles.** Open
  handles cannot be enumerated through `std`, so the fence is a recorded gap, not
  a live lock check.
- **`schtasks` / `systemctl --user` / `launchctl` were never really executed.**
  The startup lifecycle renders the host command and hands it to an injected
  `ServiceExec`; that boundary is exercised only by recording/denying doubles.
- **No migrate or rollback CLI verb.** In `axiom`, `migrate`, `service`,
  `install`, `bootstrap` and the rest are recognised pending verbs that map to
  `NOT_READY` (exit 4), and the daemon rejects them as unrecognised commands.
  There is no command that reads a journal, resumes a cutover or rolls anything
  back. In `axiom-graphd`, `changed` and `update` are still
  wired-but-not-ready (task H-002); the other operator verbs execute.
- **No native platform certification.** The migration and native-apply gates ran
  in a Linux container; no native Windows or macOS cutover, junction/ACL
  behaviour, code-signing path or real lock was exercised.
- **No continuous reconcile loop.** `serve` runs one bounded pass and exits
  (task H-002); `crates/graph-watch` is bound as the reconcile source, but there
  is no resident loop and no `SIGINT`/`SIGTERM` handler. No continuous
  filesystem watcher is bound either - every pass plans a stat-based inventory,
  which is why `doctor` reports `watcher-degraded`.

## 9. How this runbook was verified

This is a documentation-only change. There is no Rust gate for it, and no
cargo/Docker command was run (a separate lane owns the container, and the Rust
gate is not required for a docs-only commit). Verification was: (1) each cited
identifier exists in the tree, checked with `rg`; (2) the repository's docs check
`tools/check-doc-status.py`.

Identifier checks (all exit 0; output in the named log):

| Check | Command shape | Exit | Log |
| --- | --- | --- | --- |
| migration apply identifiers | `rg -n "pub fn apply_journaled\|pub fn rollback_journaled\|pub fn check_coexistence\|MIGRATION_COEXISTENCE_REFUSED\|JOURNAL_MAGIC" crates/migration` | 0 | `_coord/logs/L47-identifiers.log` |
| native_apply identifiers | `rg -n "pub fn native_apply\|pub fn rollback_native_apply\|NativeInUseProbe\|Unobservable\|native-apply-journal.json" crates/axiom/src/update/native_apply.rs` | 0 | `_coord/logs/L47-identifiers.log` |
| startup / control / drain identifiers | `rg -n "pub fn ensure_registered\|pub fn remove_registered\|pub fn plan_process_stop\|pub fn drain" crates/axiom/src` | 0 | `_coord/logs/L47-identifiers2.log` |
| platform / reconcile identifiers | `rg -n "pub trait FilesystemProbe\|pub enum HandleCheck\|pub struct Reconciler\|ReconcileOutcome" crates/platform crates/graph-watch` | 0 | `_coord/logs/L47-identifiers3.log` |
| real CLI verbs only | `rg -n '\["serve"\]\|\["version"\]\|\["doctor"\]\|\["help"\]' crates/axiom-graphd/src/cli.rs` | 0 | `_coord/logs/L47-wiring.log` |
| drain/plan_process_stop/native_apply not wired | `rg -n "plan_process_stop\|drain\|native_apply" crates/axiom-graphd/src crates/axiom-cli/src` | 1 (no matches) | `_coord/logs/L47-wiring.log` |
| no native adapter implementations | `rg -n "impl ActivationFs\|impl JournalStore\|impl ApplyIo\|impl WriterFence" crates/` | 0 (all under `tests/` or `#[cfg(test)]`) | `_coord/logs/L47-wiring2.log`, `L47-wiring4.log` |
| `serve` installs no signal handler | `rg -n "SIGINT\|SIGTERM\|signal" crates/axiom-graphd/src` | 0 (no handler in `cli.rs`) | `_coord/logs/L47-signal.log` |
| docs check | `python tools/check-doc-status.py --root .` | 0 | `_coord/logs/L47-doc-check.log` |

That table records the V2-026 revision, when only `serve`, `version`, `doctor`
and `help` were parsed. Task H-001 wired the seven operator slices, and task
H-002 then bound six of them (`serve`, `doctor`, `status`, `solution`,
`reconcile`, `queue`, `query`) to the store, registry, queue and
pinned-generation pipeline, leaving `changed` and `update` wired-but-not-ready.
The "real CLI verbs only" row therefore no longer describes this revision; it is
kept as the record of what was checked when this runbook was written.

**UNVERIFIED (this runbook)**: no native command in this runbook was executed.
`axiom-graphd` was not built or run for this documentation change, no journal was
decoded on a real tree, no replacement was staged, and no rollback was performed.
The platform table is read from source, not observed. The `serve` bounded pass
itself is verified separately by task H-002 (Windows 11 x64): `solution register
--apply` exit 0, `serve --json` exit 0 publishing generation
`3e1996028b0ee400673115f6fadb8881c8daa024a74fc2d4a38a1617be618f34`, and a
second pass after a source edit publishing `588e49d7...` with
`inventory_changed:1`.

## 10. Related documents

- [21-INSTALLATION](21-INSTALLATION.md) and
  [21-INSTALLATION-QUICKSTART](21-INSTALLATION-QUICKSTART.md) - install contract.
- [22-OPERATIONS-AND-TROUBLESHOOTING](22-OPERATIONS-AND-TROUBLESHOOTING.md) -
  operator diagnostics.
- [guides/migration-plan](guides/migration-plan.md) - the plan and its digest.
- [guides/updates](guides/updates.md) - version checks, updates and rollback
  policy.
- [guides/install-windows](guides/install-windows.md),
  [guides/install-linux](guides/install-linux.md) and
  [guides/install-macos](guides/install-macos.md) - platform install runbooks.
- [reference/axiom-graphd](reference/axiom-graphd.md) - the command reference.
- [13-SQLITE-QUEUE-AND-RECONCILIATION](13-SQLITE-QUEUE-AND-RECONCILIATION.md) -
  hints, queue and reconciliation.
- [CLI-EXIT-CODES](CLI-EXIT-CODES.md) - frozen exit-code and error-code tables.
- [README](README.md) - documentation index.
