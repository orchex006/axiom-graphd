# Version checks, updates and rollback

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. This guide describes the
intended V2 behavior of the updater. It is documentation, not evidence that a
compiled updater exists; **no `update` command is invoked here, because the
command is not implemented yet.**

**Status: the check/plan policy exists in the library; the transaction does
not.** This page is the contract, not an observation, and **no `update` command
is invoked here**, because the `update` CLI command is still not implemented.
What exists in `crates/axiom/src/update/` are the seven policy modules of tasks
E-035 to E-041:

| Module | Task | What it decides |
|---|---|---|
| `crates/axiom/src/update/source.rs` | E-035 | the configured owner/repo/channel an update may come from; no source is invented from a component name |
| `crates/axiom/src/update/trust.rs` | E-036 | signed-metadata freshness, trust roots, and rollback/freeze protection |
| `crates/axiom/src/update/check.rs` | E-037 | the TTL- and offline-aware check decision; a check never downloads or runs an installer |
| `crates/axiom/src/update/resolve.rs` | E-038 | the compatibility set, so "latest" is never assumed compatible |
| `crates/axiom/src/update/plan.rs` | E-039 | the plan document (backups, drain, rollback feasibility) and the approval rule for a major change |
| `crates/axiom/src/update/drain.rs` | E-040 | the bounded drain, where a forced kill is never the default path |
| `crates/axiom/src/update/backup.rs` | E-041 | hash-verified DB and managed-state backups, without which an irreversible migration is refused |

Also present at this revision: the platform activation and the post-update
doctor, the state-aware rollback and the update policy (tasks E-042 to E-046),
the redacted support bundle (E-047) and the core release manifest with its
regression check (E-048). Every one of those is policy over injected inputs or
mutation through a small trait: none of them opens a socket, spawns a shell,
drains a real service, creates a tag or publishes anything on this host. What is
still absent is the `update` command line itself, which stays a recognised and
refused verb (`NOT_READY`), so the transaction exists as reviewable library
modules rather than as a runnable command. What else exists is the admission
guard and digest binding in the library, the portable refusal corpus under
`fixtures/update/`, and the checker described in section 9.

The normative policy for this slice is
`docs/20-VERSION-CHECK-UPDATE-RELEASE.md` in `axiom-specs`. Two rules decide
everything else:

- **Never `git pull` a branch and execute it.** Production updates come from
  published releases and their assets in repositories the user has allowlisted.
- **A checksum is not proof of publisher.** SHA-256 plus the transport proves
  completeness, not authorship. A signed metadata chain and a pinned trust root
  are required, and an unsigned or untrusted update is refused, not installed.

## 1. Version axes

Every component reports its own axis, and they move independently.

| Axis | Meaning | Example shape |
|---|---|---|
| spec | the specification revision; not a runtime | `2.0.0-draft.1` |
| axiom-graphd | Rust daemon and public CLI/control behavior | `0.1.0` at release |
| axiom-mcp | MCP tools and query contract | `0.1.0` at release |
| skills | workflow, template and script bundle | `0.1.0` at release |
| axiom CLI | bundled bootstrap/installer/updater | same core version as `axiom-graphd` |
| docs / conformance | co-located docs and pinned fixtures | inherits the owner version; no independent updater |
| graph_schema | portable data format major | integer `1` |
| control_api / queue_schema | control message and DB migration contracts | integer `1` |
| ecosystem release | a set of component versions that passed compatibility | independent SemVer |

A version result separates `installed`, `available`, `compatible`,
`channel`, `schema_range`, `update_policy`, `source_origin` and
`needs_restart`. An unknown or offline check must not be reported as up to date.

## 2. One check and update route per component

AC1 of this slice: every component has a route, and every route states its trust
requirement. No component is updated by a blind branch pull, and none is
auto-installed unsigned.

| Component | Check route | Update route | Trust requirement |
|---|---|---|---|
| axiom-graphd | `axiom-graphd version`, `axiom-graphd update check` | `axiom-graphd update apply --plan <file>` | signed release metadata, pinned trust root, approved plan digest, backup present |
| axiom-mcp | `axiom-mcp version`, `axiom-mcp update check` | `axiom-mcp update apply --plan <file>` | same trust chain; versioned virtual environment, never an in-place `pip install` over the active environment |
| axiom CLI (bundled core) | `axiom version --all`, `axiom update check` | `axiom update plan` then `axiom update apply --plan` | signed bundle plus approval digest; the external process performs the swap after the daemon exits |
| skills | `axiom skills version`, `axiom skills check` | `axiom skills update` | reviewed manifest and hash; activates a versioned directory and switches a pointer |
| specs / fixtures / docs | report the pinned immutable provenance | none | docs inherit the owner component version; there is no independent docs installer or updater |

Only `axiom version` and `axiom version --all` are implemented today. Every
`... check` and `... update` route in this table is a documented verb that the
CLI recognises and refuses with `NOT_READY` (exit 4) until its work package
ships.

Updating a global tool is **not** the same operation as updating the
`AGENTS.md` block in every repository. Bootstrap copies are planned separately,
because user text and a dirty worktree have to be checked for each repository
(see `docs/guides/bootstrap.md`).

## 3. Sources and trust

Production updates fetch from published GitHub releases and their assets in
**allowlisted** repositories that the user actually configured. Private
repositories use a credential helper, the OS store or a token environment
variable; the token is never recorded in a snapshot, a plan or a log.

The recommended flow is a TUF-compatible metadata flow through a maintained,
reviewed Rust library. Cryptographic protocols are not written by hand. Root,
targets, snapshot and timestamp metadata, expiry, rollback/freeze protection and
root rotation are required release gates. The draft uses `REPLACE_ME` for owner,
URLs and root public keys; an installer must **reject** values that were never
set, and must never download from an owner the agent guessed.

## 4. Check policy

- Auto-check runs in a CLI or daemon maintenance window, only if the network
  policy allows it, with a 24-hour TTL plus jitter, a 10-second request timeout
  and cached metadata.
- A network failure never stops graph queries; report the last successful check
  and mark the update information stale.
- `--offline` must not perform any network access at all.
- Auto-**apply is off by default.** A user may explicitly enable compatible
  patch auto-apply, and only with an idle window, a verified signed bundle, a
  backup, a rollback path and scoped grants. A major version, a schema
  migration, a host-configuration rewrite or a trust-root change always needs an
  explicit plan approval.

## 5. The planner and the approval binding

The planner reads the installed manifest, the spec/component pins and the host
capabilities, fetches and verifies cached metadata, resolves the component
dependency ranges and the graph read/write/schema compatibility, locks exact
artifact versions and hashes, and then produces a plan: old and new versions,
downloads, backup requirements, migrations, disk headroom, service
interruptions, host reconnection needs, bootstrap changes and rollback limits.

The plan digest covers every planner input — components, versions, revisions,
artifact hashes, migrations, backup, host, channel and expiry — while excluding
`plan_digest` and `approval` themselves. Therefore:

- a plan whose recorded digest does not match its body is rejected as
  `plan_digest_mismatch`;
- a plan changed after approval can never reuse the old approval and is rejected
  as `approval_stale`;
- apply re-checks that the installed state and the trust metadata still match
  before it touches the installation.

A plan is a proposal, not an approval. Supplying a plan without an approval
digest must refuse.

## 6. Install and update transaction

The order is fixed and every step is recoverable:

1. acquire the update coordinator lock;
2. download into an isolated cache;
3. verify metadata, hash, size and signature;
4. unpack with Zip-Slip, symlink and size-bomb defenses;
5. preflight space, toolchain and compatibility;
6. pause claiming new jobs; bounded-drain requests;
7. take a consistent database backup; migrate to a staged database copy;
8. stage versioned directories; run a smoke check;
9. swap the active install manifest; restart services;
10. run MCP health plus a fixture query; resume the queue; finalize the journal.

A multi-binary, database and skills replacement is **not** atomic, so a
transaction journal and crash recovery are mandatory. `axiom-graphd update`
must let an external updater process perform the swap after the daemon exits,
because Windows will not overwrite a running executable.

## 7. Rollback

Before applying, keep the old install manifest, a consistent database backup and
the before-hashes of owned configuration. If health fails: stop the new
processes, repoint the old versions, restore a **compatible** database backup,
clear the new unpublished outbox and cache, and reconcile inputs that changed
during the upgrade.

Two hard limits:

- If the new database schema cannot be rolled back, **never run the old binary
  against the new database.** Restore the old backup, or rebuild the index from
  source while preserving pending dirty hints with a new inventory.
- A rollback of generated instructions must check the current after-hash before
  restoring a backup, so a newer human edit is not discarded.

## 8. Development source updates

`--source-revision <sha>` is an advanced, opt-in development channel with a
separate install path. It requires a trusted repository allowlist, a clean
checkout, explicit build-script permission, locked dependencies and provenance.
A development build must not change the stable pin and must not be auto-applied
to every repository.

## 9. Worked example

The example below is one update admission decision as the engine models it. It is
read by `fixtures/guides/driver.py`, which checks that the guide still agrees
with the fixture corpus in `fixtures/update/`. No Rust test compiles this guide
at this revision, so only that checker fails when the page drifts
(`fixtures/guides/README.md` records how to run it).

<!-- BEGIN UPDATE EXAMPLE -->
```json
{
  "schema_version": 2,
  "check_command_available": false,
  "version_command_available": true,
  "pending_verb_exit_code": 4,
  "plan_command_available": false,
  "apply_command_available": false,
  "rollback_command_available": false,
  "auto_check_default": true,
  "auto_apply_default": false,
  "check_ttl_hours": 24,
  "check_uses_jitter": true,
  "check_timeout_seconds": 10,
  "offline_flag_performs_network": false,
  "git_pull_then_execute": false,
  "unsigned_auto_install": false,
  "approval_digest_required": true,
  "checksum_alone_proves_publisher": false,
  "trust": {
    "signed_metadata_required": true,
    "pinned_trust_root_required": true,
    "tuf_metadata_flow": true
  },
  "plan_digest_excludes": ["plan_digest", "approval"],
  "supporting_schema_major": 1,
  "decisions": ["admit", "refuse"],
  "refusal_reasons": [
    "signature-expired",
    "signer-untrusted",
    "schema-newer-than-binary",
    "backup-missing",
    "delegation-refused"
  ],
  "scenarios": [
    "valid-control",
    "signature-expired",
    "expiry-equal-to-creation",
    "signer-untrusted",
    "schema-newer-than-binary",
    "schema-equal-to-supported",
    "backup-missing",
    "approval-missing"
  ],
  "components": ["axiom-graphd", "axiom-mcp", "axiom", "skills"]
}
```
<!-- END UPDATE EXAMPLE -->

Every `refusal_reasons` entry and every `scenarios` identifier is recorded in
`fixtures/update/manifest.json`; the driver fails if the guide names a reason or
a scenario the corpus does not contain. `checksum_alone_proves_publisher` is
`false` because section 3 forbids treating a checksum as trust.

## 10. Safety, recovery and rollback summary

| Situation | Result |
|---|---|
| A branch head moved ahead of the released version | no update; the updater tracks released SemVer, not commits or timestamps |
| Metadata signature expired | refused as `signature-expired`; an expiry equal to the creation time is already not-after |
| A plan carries no signature | refused as `signer-untrusted`; absence is never implicit trust |
| Candidate schema major newer than the binary supports | refused as `schema-newer-than-binary`; never migrate the store downwards |
| Candidate schema major equal to the supported major | admitted; only a strictly newer major is refused |
| A required backup is missing | refused as `backup-missing`; the irreversible step is not attempted and the missing file is not created |
| A plan with no approval digest | refused as `delegation-refused`; admission is never the default |
| Trusted, unexpired, supported schema, backup present | admitted and delegated as program plus argv |
| Crash mid-transaction | the journal recovers; versioned directories and the install manifest pointer are reconciled |
| Health check fails after apply | rollback repoints the old versions and restores a compatible backup; the old binary is never run against a new schema |
| Network unavailable | queries keep working; the update information is reported stale, never "up to date" |

## 11. Status and limits

The updater is **not implemented as a command yet**. What exists is the policy
and activation transaction of tasks E-035 to E-048 in
`crates/axiom/src/update/` and `crates/axiom/src/support.rs`, the trust
and schema admission surface and the delegated argv handling in the library
(`crates/axiom-graphd/src/update_guard.rs`,
`crates/axiom-graphd/src/commands/update.rs`) plus the portable refusal corpus
in `fixtures/update/`. The admission surface names the five stable refusal
reasons as `REFUSAL_REASONS`, the schema ceiling as
`graph_store::migrations::CURRENT_SCHEMA_VERSION` (major `1`), the backup
check as `graph_store::backup::verify_backup`, and an unconfigured trust root
refuses every delegation (`UpdateTrust::Unconfigured`, task B-092). The daemon
binary `axiom-graphd` implements `help` and `version` and answers `doctor`,
`serve` and the seven operator verbs wired by task H-001 (`status`, `solution`,
`changed`, `reconcile`, `queue`, `query`, `update`) with `NOT_READY` (exit 4) -
reproduced by running the prebuilt binary
from the owner's primary checkout, whose `version` reports `build_revision` as
`unknown`, so that run corroborates the source here but is not a revision-bound
release run. The `axiom` argv layer exists here (task E-001) but this
documentation-only task did not build or run the `axiom` binary; the `axiom-mcp`
component and the `skills` bundle that section 2 names live in other
repositories and are not built here.

So today:

- **not available / unverified** — `update check`, `update plan`,
  `update apply --plan`, `update rollback` and the `skills ...` commands from
  section 2. The `update` and `skills` verbs are recognised as pending and map
  to `NOT_READY` (exit 4) in `crates/axiom/src/cli.rs`; they do not check, plan,
  apply or roll back anything. That mapping is source-verified, not observed -
  no `axiom` binary was built or run here.
- **available and unverified in this document** — `axiom version` and
  `axiom version --all` (task E-001). The workspace builds them, but this
  documentation-only task did not compile or run the `axiom` binary. The daemon
  binary's own `version` *was* run: it exits 0 and reports component
  `axiom-graphd`, spec `2.0.0-draft.1`, `graph_schema` 1 and SQLite 3.50.2
  below the 3.51.3 WAL baseline, with `build_revision` `unknown`.
- **not implemented** — a Rust regression test for this guide, and therefore any
  build-time protection against this page drifting from the guard it documents.
  Tasks D-005, D-009 and D-016 gave their guides a `*_guide.rs` oracle under
  `crates/axiom-graphd/tests/`; these three operations guides have none at this
  revision.
- **available and executed** — `fixtures/update/driver.py`, run offline by task
  D-014; it exits 0 and replays the hazard and boundary vectors against the
  refusal-reason set and the supported schema major, reporting
  `provenance_verified: false` because no signed provenance exists to verify.
  `fixtures/guides/driver.py` also exits 0.
- **available and unverified in this document** — the Rust fixture test
  `crates/axiom-graphd/tests/update_fixtures.rs`, which replays the same vectors
  through the real admission guard, schema ceiling and backup check and asserts
  that a refusal leaves the target tree byte-identical. It exists in the tree,
  but this documentation-only task did not compile or run it.
- **unverified** — no signed release bundle, trust root or release metadata was
  produced or consumed; no platform was certified; only Windows x64 was
  available, and the updater transaction itself was not executed on any OS.

See `docs/21-INSTALLATION.md` for where an update sits in a first install,
`docs/guides/bootstrap.md` for the separate bootstrap copy step, and
`docs/CLI-EXIT-CODES.md` for the frozen exit codes.
