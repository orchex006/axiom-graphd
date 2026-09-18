# Git checkpoint-input fixture corpus (F-009)

Reproducible Git scenarios that a checkpoint built from `--source staged` must
keep apart. The corpus is the deliverable named by task F-009
(`fixtures/git/` inside `axiom-graphd`); it is a conformance TEST VECTOR corpus,
not a promoted shared contract fixture.

## Contents

| Path | Purpose |
| --- | --- |
| `manifest.json` | Scenario list: kind, the input class each scenario must distinguish, the expected observation and the expected outcome. |
| `driver.py` | Deterministic driver. Rebuilds every scenario in a throwaway repository and checks the real `git status --porcelain=v1 -z --untracked-files=all` observation against `manifest.json`. |
| `README.md` | This file. |

The Rust regression test that consumes the same manifest lives in
`crates/axiom-graphd/tests/git_input_fixtures.rs`. It exercises the real
`graph_watch::git_observer` parser, the real
`graph_watch::checkpoint_inputs` classifier and the real
`axiom_graphd::checkpoint::staged` materializer against the real Git scenarios.

## Run the driver

```
python fixtures/git/driver.py
python fixtures/git/driver.py --json-out evidence/artifacts/F-009/fixtures-git-driver.json
```

Exit `0` means every scenario matched the manifest, `2` means at least one
scenario diverged, `1` means a usage or I/O failure.

## Determinism and native behaviour

* `git` is launched as a program plus argv, never as an interpolated shell
  string. No Bash, WSL, Docker or administrator rights are required.
* Author and committer identity and dates are fixed, `HOME`/`USERPROFILE` point
  at a throwaway directory, the system and global Git configuration are
  disabled, and `core.autocrlf=false` keeps bytes stable across platforms.
* Scenarios are created in `tempfile.mkdtemp` directories and never in the
  repository itself, so running the driver leaves no repository state behind.
* The driver only observes: mutation subcommands belong to scenario setup and
  never to the checkpoint code under test.

## Input classes

| Class | Scenario | What the checkpoint must distinguish |
| --- | --- | --- |
| `partial-staging` | `partial-staging`, `staged-then-deleted` | The index holds bytes that differ from the working tree, so the staged blob is the checkpoint input and the worktree copy must never leak in. Boundary: the worktree path may be gone while the index still holds the staged bytes. |
| `rename` | `rename`, `rename-without-content-change` | A delete plus an add of identical bytes is one rename (`R`), not an in-place edit; the old path is refused as `not-in-index` and the new path is materialized. Boundary: a pure rename keeps the blob digest. |
| `merge` | `merge` | `HEAD` is a merge commit with two parents, so the checkpoint records the merge relationship instead of treating the snapshot as a linear commit. |
| `untracked` | `untracked` | The path exists on disk but in neither the index nor `HEAD`, so it is never a staged checkpoint input. |

This is the F-009 rendering of the conformance invariant CF-012 in
`docs/24-TEST-STRATEGY-AND-RELEASE-GATES.md`: *staged source differs from the
working tree, therefore the checkpoint matches staged only*.

## Provenance

* Pinned specification revision: `1bf754298ba1bb266a77f13cded4bfe69484906f`
  (`axiom-specs`).
* Referenced shared example, bytes NOT copied into this corpus:
  `examples/snapshots/.axiom/graph/demo-solution/auth-api/checkpoint/current.json`,
  sha256 `16053ddc4d52833d419e4b85b9cfc2066273705473ff77365cdfc06c84b21b8e`.
  The example is referenced so this corpus stays derived rather than duplicated;
  no example byte is embedded here.

## Fixture status

* These vectors are NOT registered shared fixtures: no row is added to
  `axiom-specs/conformance/fixture-index.json`, `fixture_index_digest` is
  unchanged, and `conformance/ownership.json` is untouched.
* Promoting any vector here to a shared contract fixture requires an approved
  specification change; the promoted bytes must then live under `examples/` in
  `axiom-specs` and be indexed by `conformance/fixture-index.json`.
* `fixtures/README.md` at the repository root is owned by another task and is
  deliberately not modified by F-009.
