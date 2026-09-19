# Operations-guide contract fixtures (D-012, D-013, D-014)

Structural, cross-reference and honesty regression fixtures for the three
operator guides written by tasks D-012, D-013 and D-014:

| Guide | Task | Subject |
| --- | --- | --- |
| `docs/guides/git-checkpoints.md` | D-012 | Git checkpoints and merges |
| `docs/guides/bootstrap.md` | D-013 | Multi-repo bootstrap operations |
| `docs/guides/updates.md` | D-014 | Version checks, updates and rollback |

## Contents

| Path | Purpose |
| --- | --- |
| `manifest.json` | One entry per guide: the sentinel markers, the invariant fields the worked example must still hold, the prose distinctions that must survive, and the component fixture corpus every claimed fixture identifier must exist in. It also carries the three repository-level lists below. |
| `driver.py` | Deterministic driver. Re-reads the shipped guides and asserts the manifest, then asserts that every negative fixture below is rejected. |
| `negative/*.md` | Mutated copies of the same shape that the checker must reject: a union-merged graph example, a missing end sentinel, an overwrite-unowned bootstrap example and a blind `git pull` update example. |
| `README.md` | This file. |

### Repository-level manifest keys

| Key | Meaning |
| --- | --- |
| `target_artifacts` | Paths bootstrap writes into a *target* repository (for example `.axiom/agent/POLICY.md`). They are deliberately not present in this repository, so a backticked reference to one is not a broken link. |
| `cross_repo_paths` | Paths whose canonical copy lives in `axiom-specs`. The driver resolves them against `--spec-root` when one is given and reports them as skipped when it is not; a listed path that does not resolve under a supplied `--spec-root` is a failure. |
| `absent_paths` | A surface the guides explicitly document as *not implemented at this revision*. The driver fails if the path exists, so a later task cannot land the surface while the guides keep calling it absent. |

## Run the driver

```
python fixtures/guides/driver.py
python fixtures/guides/driver.py --spec-root ../axiom-specs
python fixtures/guides/driver.py --spec-root ../axiom-specs --json-out evidence/artifacts/D-012/fixtures-guides-driver.json
```

The first form performs the local checks. The second additionally resolves the
cross-repository references (the paths listed in `cross_repo_paths` and any
`axiom-specs/...` reference) against the pinned specification checkout; without
`--spec-root` those are reported as skipped in `cross_repo_refs_skipped` rather
than silently ignored.

Exit `0` means every guide matched and every negative fixture was rejected,
`2` means at least one divergence, `1` means a usage or I/O failure.

## What it checks

* The sentinel markers and the fenced JSON worked example are present and parse.
* The structured claims still hold: union-merging generated graphs is rejected,
  bootstrap never overwrites unowned content, an update is never a blind
  `git pull` and is never an unsigned auto-install, auto-apply stays off, and
  `--offline` performs no network access.
* Every fixture identifier a guide claims exists in the real component corpus:
  checkpoint input classes in `fixtures/git/manifest.json`, bootstrap vectors
  and their outcomes in `fixtures/bootstrap/vectors.json`, and update scenarios
  plus the refusal-reason set in `fixtures/update/manifest.json`. A guide that
  names a class, vector, scenario or reason the corpus does not contain fails.
* Every repository path a guide names in backticks resolves, so renaming or
  deleting a file cannot leave a dead reference behind in the documentation.
* Every path the guides document as not implemented really is absent
  (`absent_paths`), so the honesty statements cannot rot.
* Each negative fixture is rejected *for its documented reason*: the manifest
  records the problem text every mutation must produce, so a negative cannot
  pass by being rejected for an unrelated edit.
* The prose distinctions survive: the Git guide still names live ignored data,
  the staged export and merged-source regeneration separately; the bootstrap
  guide still names append, replace, conflict and unchanged; the update guide
  still names a check route, an update route and a trust requirement per
  component.

## Determinism and native behaviour

* Local JSON and Markdown only: no network, no shell, no Bash, WSL, Docker or
  administrator rights, and the driver never mutates the repository.
* The driver reads the fixture corpora it cross-references; it does not copy
  their bytes, so a corpus change is observed rather than duplicated.
* `--json-out` is the only write, and only to the path the caller names.

## Status of the surfaced contracts

These fixtures belong to a documentation lane. The three guides document
contracts that **this revision does not implement**: the checkpoint argv surface,
the bootstrap engine (tasks E-013 to E-034) and the updater (tasks E-035 to
E-045) are still `todo` in `axiom-specs`. The guides say so in their own status
sections, and `absent_paths` keeps the strongest of those statements
machine-checked.

## Relationship to a Rust oracle

There is **no** Rust oracle for these three guides at this revision. The three
older guides in this repository (`docs/guides/human-workflow.md` for D-009,
`docs/guides/solutions.md` for D-005, `docs/guides/troubleshooting.md` for
D-016) each have a companion
`crates/axiom-graphd/tests/*_guide.rs` that compiles the guide into a test binary
with `include_str!` and fails the build when the page drifts. These three
operations guides have no such test, so `fixtures/guides/driver.py` is the only
executed check; nothing fails a build when these pages drift.

If a later task adds the oracle, it must update the three guides and the
`absent_paths` entry in `fixtures/guides/manifest.json` in the same change, or
this driver fails on purpose.

## Provenance

* Pinned specification revision: `1bf754298ba1bb266a77f13cded4bfe69484906f`
  (`axiom-specs`, the revision recorded in `spec.lock.json`).
* Derived from the shipped guides and from the component fixture corpora in this
  repository. No bytes are copied from a shared contract fixture.

## Status: component-local, not shared

These are component-local regression fixtures for `axiom-graphd`. They are not
registered shared contract fixtures: no row is added to
`axiom-specs/conformance/fixture-index.json`, and
`conformance/ownership.json` is not touched. Promoting any fixture here to a
shared contract fixture requires an approved specification change.
