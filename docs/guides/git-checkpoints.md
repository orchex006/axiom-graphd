# Git checkpoints and merges

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. This guide describes the
intended V2 behavior of the engine. It is documentation, not evidence that a
compiled daemon, a checkpoint command or a released runtime exists, and no
command below is asserted to work today.

**Status: the checkpoint command surface is not implemented at this revision.**
This page is the contract, not an observation of a running engine. The library
halves exist: `crates/axiom-graphd/src/checkpoint/` holds the `staged`,
`worktree` and `commit` source selections, the deterministic export and the
merged-source verification (tasks B-088 to B-091), and `graph-watch` holds the
input classification. Nothing exposes them on argv and no released runtime
bundles them, and the operator surfaces this guide names are still `todo` in
their task cards: E-023 (Git-ignore planning for live output), E-024 (optional
scoped commit proposals) and E-025 (managed rollback). The F-021 staged and
merged checkpoint accuracy fixtures now ship as `tests/git_checkpoint.py` - they
exercise the real `git` program and argv, including the real `merge=union`
refusal, and they are not a Rust oracle.

The normative policy for this slice is
`docs/19-GIT-SNAPSHOTS-AND-MERGES.md`. This guide explains how an operator moves
between its three states without corrupting them. The one statement that makes
the rest safe: **a generated graph is never merged; it is regenerated from
merged source.**

## 1. Three states, not two

A project uses one repository, but three different kinds of content live in it.
Confusing them is the root cause of almost every checkpoint accident.

| State | Where it lives | Git | Written by |
|---|---|---|---|
| **Live ignored data** | project-relative output root (default `live/`) plus runtime state | ignored | the daemon, continuously |
| **Staged export** | the tracked checkpoint paths under the project output root | tracked (optional) | an explicit checkpoint command only |
| **Merged-source regeneration** | the same tracked checkpoint paths, rebuilt | tracked | a regenerate step after the source merge is final |

**Live ignored data** changes on every save and is deliberately invisible to
Git. The `.gitignore`/`.gitattributes` policy keeps `live/**`, staging,
database, WAL, queue, lease, lock, log, credential, local-binding and temporary
paths out of every diff, so no ordinary edit can create a tracked change.

**A staged export** is a checkpoint. It is *optional* and *explicit*: it is built
from a chosen source (section 2) and written only into the checkpoint lane. It is
never published on every debounce.

**Merged-source regeneration** is what happens after a merge. The merge is
resolved in the *source*, and then the checkpoint is rebuilt from the merged
source. It is not a merge of two graphs.

## 2. Choosing the checkpoint source

A checkpoint has exactly one source selection. Reusing the wrong one is how a
checkpoint silently stops matching the commit it accompanies.

| Selection | Reads | Must not | Notes |
|---|---|---|---|
| `--source staged` | the Git **index** as an isolated input tree | reset the working tree, stash or uncommit; read worktree bytes for a staged path | default; only staged source plus versioned config in the index is included |
| `--source worktree --verify-stable` | the live working tree | export while the tree is changing | a source inventory is taken before and after; a change between them is retried or refused as `WORKTREE_BUSY` |
| `--source commit --ref <sha>` | a clean checkout at that commit | embed the checkpoint's own containing commit SHA in a portable generation | used from CI with pinned analyzers |

Two boundaries are easy to get wrong and are covered by the fixture corpus in
`fixtures/git/` (see `fixtures/git/README.md`):

- A **partially staged** file (`partial-staging`) has index bytes that differ
  from the working tree. The checkpoint must carry the *staged* bytes. A path
  that is absent from the index is refused as `not-in-index`; it is never
  resolved from the working tree.
- A path deleted after being staged (`staged-then-deleted`) must still be
  readable from the index; the checkpoint must not fail because the file is gone
  from disk.

## 3. Building and committing a checkpoint

The intended sequence, once the checkpoint command exists, is:

1. prepare the source changes and stage only the task's files;
2. create the checkpoint from the staged source;
3. stage the checkpoint files that changed;
4. verify the checkpoint against the staged source, ignoring generated outputs;
5. inspect the diff;
6. commit.

A pre-commit hook can check the same thing, but a host or a local Git
configuration can bypass hooks, so CI must re-verify (section 6). The checkpoint
command itself must be an explicit invocation: there is no implicit export, and
the command must never mutate the user's index or working tree.

## 4. Merging source changes

Merge, rebase and cherry-pick touch the **source** first. The order is fixed:

1. resolve the source merge, including human-maintained configuration and
   annotations;
2. **regenerate** the checkpoint from the merged-source result;
3. validate that every catalog reference still resolves;
4. run the tests and CI.

A successful *textual* merge does not prove the graph semantics are correct.
Where a conflict lands inside generated output, the only safe resolutions are to
regenerate the owned output from the final source, or to remove and recreate the
owned output. Neither operation may delete human annotations.

The following are forbidden, because each one hides a real disagreement:

- configuring `merge=union` for node or edge files to make a conflict disappear;
- choosing one whole side ("take theirs") for a generated graph and claiming it
  matches the merged source;
- hand-picking individual nodes or edges from either side;
- treating a merged checkpoint as valid before it has been regenerated and
  re-validated against the final source.

Because the checkpoint is generated from source, there is no situation in which
union-merging two generated graphs is the correct recovery. Regenerate.

## 5. What "regenerated" means

Regeneration rebuilds the checkpoint from the merged source with the same
analyzer profile that produced it originally. Practical consequences:

- the merge commit and the checkpoint agree by construction, so a reviewer does
  not compare two independently produced graphs;
- references from another repository's catalog may point at a generation that is
  not yet pushed, so a release check must verify set completeness from the remote
  commit set, not from the local working tree;
- generated JSON is sorted and sharded deterministically, so a diff is still
  reviewable; reviewing it is expected, not optional.

The daemon must detect a branch or worktree epoch change and invalidate jobs that
belong to the previous source, because Git can modify a generated checkpoint
while a reader is reading it.

## 6. Size budgets and CI

Checkpoints are bounded artifacts, not archives:

| Budget | Default | On breach |
|---|---|---|
| checkpoint warning | > 20 MiB per project | report the size; consider a summary profile or reduced edge projection |
| generated PR diff warning | > 5 MiB | review before commit |
| hard stop | 100 MiB per project | refuse unless an explicit, reviewed override is given |

These are local product budgets, not GitHub upload limits. When a budget is
exceeded, reduce the artifact honestly (summary profile, reduced projection or
artifact mode) and advertise the reduced coverage; never omit relations silently.

CI runs on a clean checkout of the PR merge result with pinned analyzers, exports
to a separate temporary directory, compares the canonical payload with the
tracked checkpoint, verifies declared cross-repository references, and fails
with regenerate instructions instead of auto-pushing a fix onto a protected
branch. An artifact-only mode still keeps configuration, a summary and the
fingerprint in Git and must state its availability and retention explicitly.

## 7. Security

A generated graph can disclose architecture, private endpoint names, table names
and service names. Store it under the repository's access policy, do not promote
a snapshot to public automatically, and redact or skip connection strings,
`.env` values and token values *before* export rather than relying on a later
secret scan.

## 8. Worked example

The example below is a single checkpoint decision as the engine models it. It is
read by `fixtures/guides/driver.py`, which checks that the guide still agrees
with the fixture corpora in `fixtures/git/` and `fixtures/update/`. It is read
by nothing else: no Rust test compiles this guide into a test binary at this
revision, so only the Python checker fails when the page drifts
(`fixtures/guides/README.md` records how to run it).

<!-- BEGIN GIT CHECKPOINT EXAMPLE -->
```json
{
  "schema_version": 2,
  "lane": "tracked_checkpoint",
  "graphd_cli_verbs_available": ["help", "version"],
  "graphd_unbuilt_verb_exit_code": 4,
  "live_output_root": "live",
  "ignored_paths": [
    "live/**",
    ".axiom/.staging/**",
    ".axiom/queue.sqlite",
    ".axiom/queue.sqlite-wal",
    ".axiom/lease.json",
    ".axiom/local-bindings.json",
    "logs/**"
  ],
  "tracked_checkpoint_paths": [
    ".axiom/graph/checkpoint/current.json",
    ".axiom/graph/checkpoint/generations/shard-0000.json"
  ],
  "source_selections": ["staged", "worktree", "commit"],
  "default_source": "staged",
  "worktree_requires_stability_certificate": true,
  "checkpoint_export_requires_explicit_command": true,
  "input_classes": ["partial-staging", "rename", "merge", "untracked"],
  "boundary_input_classes": ["rename-without-content-change", "staged-then-deleted"],
  "merge_procedure": [
    "resolve-source",
    "regenerate-checkpoint-from-merged-source",
    "validate-catalog-references",
    "run-tests"
  ],
  "union_merge_generated_graphs": false,
  "hand_pick_graph_sides_after_merge": false,
  "size_warning_bytes_per_project": 20971520,
  "size_hard_stop_bytes_per_project": 104857600
}
```
<!-- END GIT CHECKPOINT EXAMPLE -->

The four `input_classes` and the two `boundary_input_classes` are the scenario
identifiers recorded in `fixtures/git/manifest.json`; the driver fails if the
guide names a class the corpus does not contain. `union_merge_generated_graphs`
is `false` because section 4 forbids it.

## 9. Guarantees, refusals and recovery

| Situation | Result |
|---|---|
| Ordinary save inside the live output root | one hint, no tracked change; live data stays ignored |
| `--source staged` with a partially staged file | the index bytes are exported; the working-tree bytes never leak in |
| A staged path missing from the index | refused as `not-in-index`, never a worktree fallback |
| A pure rename with unchanged content | reported as one rename, not as an edit |
| A staged-then-deleted path | still read from the index; the missing file is not an error |
| The working tree changes during `--source worktree` | bounded retry, then `WORKTREE_BUSY` (exit 6) |
| Merge conflict inside generated output | regenerate from the final source, or remove and recreate the owned output; human annotations are preserved |
| A stale checkpoint after a textual merge | detected by verify; reported `NOT_READY` (exit 4) rather than certified |
| Branch/worktree epoch change | old jobs are invalidated; the daemon does not serve a previous epoch as fresh |
| Checkpoint over the hard stop | refused unless an explicit, reviewed override is given |

Recovery never rewrites user work. Checkpoint files that are already in Git can
be restored through a reviewed Git operation; the engine does not auto-revert a
user's working tree, and it does not delete a valid generation before a
replacement is published.

## 10. Status and limits

The `checkpoint` source selection (`staged`, `worktree`, `commit`),
deterministic export and merged-source verification are implemented as library
modules in `axiom-graphd` (`crates/axiom-graphd/src/checkpoint/`), and the input
classification is implemented in `graph-watch`. The **argv surface that exposes
them is still not wired**: task H-001 wired the operator verbs `status`,
`solution`, `changed`, `reconcile`, `queue`, `query` and `update` into argv, so
`checkpoint`-style commands remain the exception. The `axiom-graphd` binary
implements `help` and `version`; `doctor`, `serve` and the seven verbs above are
recognised but answer `NOT_READY` (exit 4) because their status sources, queue
writer and store bindings belong to later work packages, and any other verb
(`checkpoint`, `snapshot`, `frobnicate`) is rejected with a validation error
(exit 2) rather than silently doing nothing. So today:

- **not available / unverified** — a `checkpoint create`-style command and the
  procedure in section 3; there is no released runtime binary either;
- **not implemented** — a Rust regression test for this guide. Tasks D-005,
  D-009 and D-016 gave their guides a `*_guide.rs` oracle under
  `crates/axiom-graphd/tests/`; these three operations guides have none at this
  revision, so no build fails when the page drifts. Adding the oracle belongs to
  the task that wires the checkpoint argv surface.
- **available and executed** — the Python guide checker
  `fixtures/guides/driver.py`, run offline by task D-012 as
  `python fixtures/guides/driver.py --spec-root <axiom-specs>` with exit 0. The
  component corpora it cross-references are also runnable offline:
  `fixtures/git/driver.py` and `fixtures/update/driver.py` each exit 0 when run
  directly with this host's Python.
- **available and unverified in this document** — the Rust fixture tests
  `crates/axiom-graphd/tests/git_input_fixtures.rs` and
  `crates/axiom-graphd/tests/update_fixtures.rs`. They exist in the tree, but
  this documentation-only task did not compile or run them.

See `docs/22-OPERATIONS-AND-TROUBLESHOOTING.md` for the operator-state table and
`docs/CLI-EXIT-CODES.md` for the frozen exit codes (`NOT_READY` is 4,
`WORKTREE_BUSY` is 6).
