# Multi-repo bootstrap operations

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. This guide describes the
intended V2 behavior of the bootstrap engine. It is documentation, not evidence
that a compiled `axiom` CLI or a working `bootstrap` command exists; **no
`axiom bootstrap ...` command is invoked in this guide, because that command is
not implemented yet.**

**Status: the bootstrap engine's policy half is implemented and unit-tested; the
operator command is not.** This page is the contract, not an observation. The
modules for tasks E-013 to E-025 exist under `crates/axiom/src/bootstrap/`; the
argv wiring, host adapters and skill bundles for E-026 to E-047 are still
`todo`. Beyond the engine, what exists is the `axiom` argv layer that recognises
the verb and refuses rather than pretending, the static bootstrap corpus under
`fixtures/bootstrap/`, and the checker described in section 6. Section 8 records
exactly what was executed and what was not.

The normative policy for this slice is
`docs/18-BOOTSTRAP-AND-MANAGED-INSTRUCTIONS.md`. Bootstrap writes two owned
things into a repository and then never touches anything else:

| Owned artifact | Path | Meaning |
|---|---|---|
| managed instruction block | `AGENTS.md` (a pointer block) | small, stable; tells an agent to read the policy |
| canonical policy | `.axiom/agent/POLICY.md` | the graph-usage policy for this repository |
| ownership manifest | `.axiom/agent/bootstrap.lock.json` | records what bootstrap last wrote |

The pointer block is small on purpose. The full policy is not inlined into every
host file, because that grows the host context on every request. The block still
```markdown
<!-- axiom-graph:begin -->
## Axiom Graph workflow
Before graph-assisted code changes, explicitly read `.axiom/agent/POLICY.md` and follow its graph freshness, query-budget and completion-verification rules. This block does not grant extra filesystem, network, commit or push permissions.
<!-- axiom-graph:end -->
```

The block intentionally does **not** restate the whole policy and does not
grant permissions: it points at `.axiom/agent/POLICY.md` and names the rules a
reader has to apply.

If a higher-priority or nested host instruction disagrees with the block, report
the disagreement. Do not overwrite it to give the graph precedence.

## 1. Plan, then apply

Bootstrap is a two-step operation, and the first step never writes to the target
repositories.

1. `axiom bootstrap plan` reads the explicitly registered solution and the
   target hosts and produces, per repository: the proposed operations, the
   before-hashes of affected files, the managed-block hashes, the template
   version and hash, destination-relative paths, a change classification, a
   proposed Git diff, the policy configuration and a plan `SHA256`.
2. `axiom bootstrap apply --plan <file> --approve-digest <sha256>` re-reads the
   exact approved plan, re-verifies root bindings, ownership and before-hashes,
   and rejects an expired or stale plan. Re-running must be idempotent.

Planning is read-only; applying is approval-bound. A plan whose inputs changed
after approval is refused rather than silently re-planned. **Plan is not
approval**: supplying a plan file without the approval digest must not apply
anything.

Path handling is strict. A plan must reject `..`, absolute paths, symlink escapes
and case collisions, and it must never auto-discover and rewrite every repository
under `HOME`.

## 2. The managed-merge algorithm

For each repository there is exactly one outcome, decided by the file and the
ownership manifest:

| Condition | Outcome |
|---|---|
| `AGENTS.md` does not exist | **append** an owned section; preserve the encoding policy |
| File exists but has no markers | **append** the section, preserving every byte outside it; existing human text is never reformatted |
| Exactly one marker pair, and the block hash matches the last applied hash | **replace** only the block with the new template |
| Markers present but no ownership manifest | **adopt only** through an explicit plan and approval; never assume ownership |
| Duplicate, missing, nested or out-of-order markers | **conflict**; report and refuse |
| A human edited inside the owned block | **conflict**; preserve the edit and refuse |
| A whole-file generated policy was edited | **conflict**, or a separate manual adoption; the human override belongs in `POLICY.local.md` |
| The ownership manifest names an owned policy that is missing | **conflict**; the manifest is not silently rewritten and the policy is not silently recreated |
| Nothing owned would change | **unchanged** (re-apply is a no-op) |

The rules that make this safe in practice:

- **Conflict means refuse and preserve.** A conflict never truncates, never
  relocates and never silently appends a second block.
- **Encoding is preserved outside the block.** CRLF, LF, a UTF-8 BOM and a
  missing final newline are recorded and kept; bootstrap never converts a whole
  repository to LF while it edits one block.
- **A marker inside a fenced code sample is not an active marker.** The
  managed-section detector must be aware of fence context, or a documentation
  example would be treated as real.

## 3. Apply, journal and rollback

Applying one repository takes a per-repository bootstrap lock, then:

1. re-check the before-hashes;
2. back up the affected bytes under `AXIOM_HOME`;
3. write a journal intent;
4. atomically write the owned files and configuration fragments;
5. verify the hashes of everything outside the owned content;
6. update `bootstrap.lock.json` as the *last* step;
7. mark the journal complete.

Several files in one repository are not one filesystem transaction, and several
repositories are even less atomic. The journal therefore has to handle a
half-applied state, and recovery must not lose user changes.

Rollback restores a backup **only when the current hash still equals the
after-hash that the installer wrote**. If the file changed since the write, the
rollback refuses and reports the divergence instead of discarding a newer human
edit.

## 4. Multiple repositories in one run

A multi-repository plan is applied per repository, not as one transaction. The
aggregate result is reported as success, conflict or blocked per repository, and
the default is to continue with the unaffected repositories while returning a
non-zero exit status (exit 20 for a partial multi-repository run). Bootstrap must
never claim that all repositories were updated when only some were.

## 5. Host adapters

The policy is portable; the host file names are not. The adapter writes a
managed pointer in the file the host actually reads and keeps canonical
`SKILL.md` content owned in one place, materialized as versioned copies with a
hash manifest. Symlinks are not the default, because Windows privileges and Git
portability differ. The adapter must detect the host version rather than writing
two layouts at once without a migration plan.

## 6. Worked example

The example below is one repository's bootstrap decision as the engine models
it. It is read by `fixtures/guides/driver.py`, which checks that the guide still
agrees with the fixture corpus in `fixtures/bootstrap/`. No Rust test compiles
this guide at this revision, so only that checker fails when the page drifts
(`fixtures/guides/README.md` records how to run it).

<!-- BEGIN BOOTSTRAP EXAMPLE -->
```json
{
  "schema_version": 2,
  "policy_path": ".axiom/agent/POLICY.md",
  "version_command_available": true,
  "pending_verb_exit_code": 4,
  "ownership_lock_path": ".axiom/agent/bootstrap.lock.json",
  "managed_block_path": "AGENTS.md",
  "begin_marker": "<!-- axiom-graph:begin -->",
  "end_marker": "<!-- axiom-graph:end -->",
  "plan_command_available": false,
  "apply_command_available": false,
  "plan_is_read_only": true,
  "apply_requires_approval_digest": true,
  "overwrite_unowned_content": false,
  "recursively_delete_axiom": false,
  "multi_repo_partial_exit_code": 20,
  "outcomes": ["append", "replace", "conflict", "unchanged"],
  "cases": [
    { "case": "lf_new_repo", "outcome": "append" },
    { "case": "lf_no_markers_human_text", "outcome": "append" },
    { "case": "crlf_no_markers_human_text", "outcome": "append" },
    { "case": "bom_no_markers_human_text", "outcome": "append" },
    { "case": "markers_in_fence", "outcome": "append" },
    { "case": "crlf_managed_block_reapply", "outcome": "replace" },
    { "case": "bom_managed_block_reapply", "outcome": "replace" },
    { "case": "unrelated_human_instructions", "outcome": "unchanged" },
    { "case": "missing_begin_marker", "outcome": "conflict" },
    { "case": "missing_end_marker", "outcome": "conflict" },
    { "case": "markers_out_of_order", "outcome": "conflict" },
    { "case": "duplicate_markers", "outcome": "conflict" },
    { "case": "edited_managed_block", "outcome": "conflict" },
    { "case": "edited_policy_file", "outcome": "conflict" },
    { "case": "unowned_policy", "outcome": "conflict" },
    { "case": "managed_policy_missing", "outcome": "conflict" }
  ]
}
```
<!-- END BOOTSTRAP EXAMPLE -->

Every `case` identifier and outcome is recorded in
`fixtures/bootstrap/vectors.json`; the driver fails if the guide names a vector
the corpus does not contain, or claims an outcome the corpus contradicts.

## 7. Safety, recovery and rollback

| Situation | Result |
|---|---|
| First run in a repository with no `AGENTS.md` | append the owned block and policy; other files are untouched |
| Repository with human instructions and no markers | append; every existing byte is preserved |
| Re-apply with no source change | unchanged; no file is rewritten |
| Human edited inside the managed block | conflict; the edit is preserved and reported |
| A lone begin or end marker | conflict; refuse rather than truncate or nest |
| Two candidate blocks | conflict; refuse rather than guess |
| A whole-file owned policy was edited | conflict; `POLICY.local.md` is the human override path |
| A plan whose inputs changed after approval | refused as stale; nothing is written |
| A plan file with no approval digest | refused; a plan is not approval |
| Crash between two owned files | journal recovery completes or rolls back the half-applied state without losing user changes |
| Rollback after a newer human edit | refused; the newer content wins and the divergence is reported |
| Several repositories, some conflicting | the unaffected repositories proceed; the run exits non-zero (20) and reports per-repository results |

Bootstrap never recursively deletes `.axiom` or `.agrimap-agent`, never weakens
authentication, and never force-pushes a repository to make a plan pass.

## 8. Status and limits

The bootstrap engine's **policy half is implemented and unit-tested**; the
operator surface is not. The modules for tasks E-013 to E-025 exist under
`crates/axiom/src/bootstrap/`:

- E-013 to E-021 — the approved repository set, fence-aware marker parsing,
  byte/BOM/newline-preserving text handling, the separate managed policy file,
  the ownership manifest, the reviewable read-only plan, before-hash
  re-verification with the apply lock, the journaled apply and the idempotent
  drift report;
- E-022 to E-025 — `crates/axiom/src/bootstrap/update.rs` (the version-gated
  managed update), `crates/axiom/src/bootstrap/gitignore.rs` (the
  marker-delimited ignore lane), `crates/axiom/src/bootstrap/commit_plan.rs`
  (the path-scoped, grant-gated commit proposal) and
  `crates/axiom/src/bootstrap/rollback.rs` (the hash-checked reverse of an
  apply).

Those modules are pure policy over bytes plus explicitly named host adapters;
they were exercised by the crate's unit tests inside the pinned Linux
verification container, not by a release build of the CLI. Two further things
exist, and both matter to an operator:

- the `axiom` argv layer (`crates/axiom-cli` over `crates/axiom`, task E-001)
  lists `bootstrap` among its documented-but-pending verbs and maps it to
  `NOT_READY` (exit code 4) with the verb name, so `axiom bootstrap ...` is
  never mistaken for a typo. That mapping is verified by reading
  `crates/axiom/src/cli.rs`; this documentation-only task did not build or run
  the `axiom` binary, so the observed exit status is unverified here even though
  the code path is not;
- the daemon binary `axiom-graphd` implements `help` and `version`; its
  `doctor` and `serve` verbs are recognised but answer `NOT_READY` (exit 4)
  because their status sources and reconcile worker belong to later work
  packages, and any other verb is rejected with a validation error (exit 2).
  Running the prebuilt binary from the owner's primary checkout reproduced
  exactly that (`help` and `version` exit 0, `doctor` `NOT_READY` exit 4,
  unknown verb `VALIDATION_ERROR` exit 2); its `version` reports
  `build_revision` as `unknown`, so that run corroborates the source in this
  worktree but is not a revision-bound release run.

So today:

- **implemented and unit-tested, not reachable from a CLI verb** — the whole
  engine above, including the managed update (E-022), the ignore lane (E-023),
  the commit proposal (E-024) and the rollback (E-025). The `bootstrap` verb is
  still recognised-and-refused, so it cannot drive any of them yet.
- **not available / unverified** — `axiom bootstrap plan`,
  `axiom bootstrap apply`, the plan digest and the apply journal described in
  sections 1 and 3. The `bootstrap` verb is recognised and refuses with
  `NOT_READY` (exit 4); it does not plan, diff, approve or apply anything.
- **not implemented** — a live `git` executor behind the commit proposal. Task
  E-024 records the `git` calls a granted run would make through an executor
  trait instead of running `git` from the engine, so no real staging, commit or
  push is performed by this slice.
- **available and unverified in this document** — `axiom version` and
  `axiom version --all` (task E-001). The workspace builds them, but this
  documentation-only task did not compile or run the `axiom` binary.
- **not implemented** — a Rust regression test for this guide, and therefore any
  build-time protection against this page drifting from the engine. Tasks D-005,
  D-009 and D-016 gave their guides a `*_guide.rs` oracle under
  `crates/axiom-graphd/tests/`; these three operations guides have none at this
  revision.
- **available and executed** — the static fixture corpus of the managed-merge
  algorithm and the Python checker: `fixtures/bootstrap/vectors.json`,
  `fixtures/bootstrap/README.md` and `fixtures/guides/driver.py`, all read
  offline by task D-013. The two Python drivers that ship with the corpus and
  its sibling run and exit 0 on this host. The corpus outcomes are what
  section 2 claims; the corpus is *not* replayed through Rust here.
- **available and unverified in this document** — the Rust fixture test
  `crates/axiom-graphd/tests/bootstrap_fixtures.rs`, which asserts the
  managed-merge algorithm and its conflict vectors. It exists in the tree, but
  this documentation-only task did not compile or run it.
- **reference only** — `axiom-specs/reference/bootstrap_reference.py` is an
  offline behavior reference for experimenting with managed `AGENTS.md` across
  repositories. It is not the production host configuration or updater, and it
  does not replace the Spec-E implementation.
- **not measured on non-Linux hosts** — the engine unit tests ran in a pinned
  Linux container, but no live daemon, no live repository and no native
  Windows/macOS runtime was exercised; encoding and privilege behavior on those
  hosts is described from the policy, not measured.

See `docs/22-OPERATIONS-AND-TROUBLESHOOTING.md` for the operator-state table,
`docs/21-INSTALLATION.md` for where bootstrap sits in a first install, and
`docs/CLI-EXIT-CODES.md` for the frozen exit codes.
