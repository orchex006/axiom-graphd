# K-106 downstream engine owner review — local B 0.1.1 source

Date: 2026-09-29 Asia/Bangkok. Owner: axiom-graphd. Scope is the downstream
K-106 prepared-journal recovery fix on the existing K-102 owner branch. The
original K-102 0.1.0 candidate and completion report remain historical.

The outer update journal now records the expected core transaction, plan,
artifact digests and skills pointer before any service drain or pointer move.
Explicit rollback accepts `prepared` only when each live pointer is either the
retained A pointer or this transaction's exact B candidate. It verifies A
payload bytes before drain; it verifies a moved B skills manifest and core
payload hashes before restoration. It restores both pointers, then reinstalls
an owned service, and can resume after a failed reinstall. Unknown/legacy
prepared journals without candidate identity, foreign transactions, changed
pointers and changed retained payloads are refused. Journal schema stays at 1;
the new optional field preserves older finalized/activated journal parsing.

Workspace version, VERSION, local dependency constraints, lockfile and unsigned
release declaration are 0.1.1. Build matrix documents B as a local candidate;
there is no tag, signature, notarization or publication. The draft K-106 spec
coordination proposal is not an independent contract review or main integration.

Checks on native macos-x64:
- `python3 tests/core_manifest.py`: pass, 3 positive and 12 negative legs.
- `cargo fmt --all --check`: pass.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: pass.
- `cargo test --workspace --locked --no-fail-fast --quiet`: 46 targets, 1,426
  passed, 0 failed after correcting VERSION. An extra focused prepared skills
  tamper test passed after this full run; it will be included in the final
  native candidate gate.
- `git diff --check`: pass. Changed-file private-key/token pattern scan: no
  matches.

Native source build, package verifier, full A/B installed transaction,
independent review and other platform lanes remain to be recorded. Rollback
of this source change is the owner branch commit revert before publication;
installed rollback is exercised separately by K-106.

Follow-up after the first native crash run: a retry of B after recovery
observed B files retained on disk but A still active. The generic ecosystem
installer treated present payloads as sufficient and did not move the core
pointer; the skills installer refused the existing B directory. The owner fix
now compares the active core pointer to the target artifacts and reactivates
an exact retained skills directory only after full inventory and hash checks.
Focused recovery tests cover successful retry and human-edited retained skills
refusal. The first 0.1.1 candidate archive is a superseded local build; a new
source-pinned candidate must be built and verified before final K-106 proof.
