# K-106 downstream engine-owner follow-up preflight

Date: 2026-09-29 Asia/Bangkok. Scope: engine-owned recovery defect found by
`axiom-cli` K-106, plus unsigned local macos-x64 core candidate B `0.1.1`.
This is a follow-up on the existing K-102 owner branch; the completed K-102
0.1.0 report remains a point-in-time record and is not reinterpreted as B.

- Owner checkout: `axiom-graphd`, branch
  `feature/k-102-macos-core-candidate`, clean initial tree, base/head
  `fa90e5c6eea84b7bf63b375f7e5af9bcb32b1e78`; canonical origin
  `git@github.com:orchex006/axiom-graphd.git`. Existing detached K-102
  worktree was inspected with `git worktree list` and left untouched.
- Governance: read repository `AGENTS.md` and `Development.md`, canonical
  `axiom-specs/AGENTS.md` and `Development.md`, K-102/K-106 cards, and the
  update transaction contract. K-102 explicitly routes downstream
  engine-install/service defects back to the engine owner with regression.
- Immutable pin: `spec.lock.json` matches an extracted Git archive at
  `39759ac2311206059b00c44179a998f502e4e777` under
  `spec-lock-check.py --release --json` (`ok: true`). The current draft
  `specctl validate --task K-102 --stage before` passed. The historical
  pinned archive's K-102 checklist was not yet claimed and its `before`
  validation reports `checklist.unchecked:before.P1`; that does not invalidate
  the archive's exact contract digests.
- Draft coordination: `axiom-specs` branch `feature/k-106-macos-update`
  records `evidence/artifacts/K-106/engine-prepared-recovery-proposal.md`.
  Independent shared-update review remains pending. No compatibility or
  release claim follows from this draft proposal.
- Allowed owner changes: `crates/axiom/src/update/ecosystem_runtime.rs`,
  `crates/axiom/src/install/ecosystem.rs`,
  `crates/axiom/src/skills/install.rs`, focused engine tests under `crates/`,
  workspace version/dependency metadata,
  `release/` candidate tooling or manifest as needed, owner docs,
  `Changelog.md`, and `evidence/K-102/`. Preserve all unrelated content.
- Verification plan: positive prepared recovery before and after each pointer
  move; idempotent rollback and service ownership; negative malformed,
  foreign and human-edited journal/pointer/payload; native source-built A/B
  provenance, package/verify, executable versions and hashes; Rust format,
  clippy, targeted and workspace tests, release build. Record skipped or
  blocked cases. No tag, signing, publication or main integration.
