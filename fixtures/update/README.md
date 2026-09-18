# Update and migration safe-refusal fixture corpus (F-010)

Portable update and migration vectors that a local installation must refuse
safely. The corpus is the deliverable named by task F-010 (`fixtures/update/`
inside `axiom-graphd`); it is a conformance TEST VECTOR corpus, not a promoted
shared contract fixture.

## Contents

| Path | Purpose |
| --- | --- |
| `manifest.json` | Scenario list: kind, the hazard class each scenario must distinguish, the vector path, the expected decision and the expected refusal reason. |
| `vectors/*.json` | One derived plan document per scenario, carrying the admission request and the expected decision. |
| `driver.py` | Deterministic driver. Checks that every vector agrees with the manifest, that the corpus covers every hazard class and carries boundary cases, and optionally that each referenced specification path still has the recorded digest. |
| `README.md` | This file. |

The Rust regression test that consumes the same manifest lives in
`crates/axiom-graphd/tests/update_fixtures.rs`. It replays every vector through
the real `axiom_graphd::update_guard::admit` admission surface, the real
`axiom_graphd::commands::update::delegate` argv delegation, the real
`graph_store::migrations` schema ceiling and the real
`graph_store::backup::verify_backup` check.

## Run the driver

```
python fixtures/update/driver.py
python fixtures/update/driver.py --spec-root ../axiom-specs
python fixtures/update/driver.py --json-out evidence/artifacts/F-010/fixtures-update-driver.json
```

Exit `0` means every vector matched the manifest, `2` means at least one
divergence, `1` means a usage or I/O failure. `--spec-root` is optional: without
it the driver checks the corpus alone, with it the driver also re-hashes each
`spec_contract.reference_path` under that root.

## Determinism and native behaviour

* The driver reads local JSON only: no network, no shell, no Bash, WSL, Docker
  or administrator rights, and it never mutates the repository or a target tree.
* The Rust test builds each target tree in a `tempfile` directory, hashes every
  byte before and after the admission call, and never points at a real
  installation.
* Where a real check already exists it is reused instead of re-implemented: the
  trust decision uses `commands::update::UpdateTrust`, the schema ceiling uses
  `graph_store::migrations::CURRENT_SCHEMA_VERSION`, the backup check uses
  `graph_store::backup::verify_backup`, and an admitted plan is delegated with
  the real argv-only `commands::update::delegate`.

## Hazard classes

| Class | Scenarios | What must be distinguished |
| --- | --- | --- |
| `expired-signature` | `signature-expired`, `expiry-equal-to-creation` | The trust metadata expiry is not after the plan creation time, so the signature can no longer be trusted. Boundary: an expiry equal to creation is already not-after. |
| `untrusted-signer` | `signer-untrusted` | The plan carries no signature, so the signer is absent and the plan is refused rather than treated as implicitly trusted. |
| `newer-schema` | `schema-newer-than-binary`, `schema-equal-to-supported` | A candidate schema major newer than this binary supports is refused explicitly instead of migrating the store downwards. Boundary: equality with the supported major is compatible. |
| `missing-backup` | `backup-missing` | The plan requires a backup that is not present, so the irreversible step is refused and the missing file is never created. |
| `approval-not-bound` | `approval-missing` | Supplying a plan is not approval; without the explicit approval digest the real delegation refuses, so admission is never the default. |
| `valid-control` | `valid-control` | A trusted, unexpired plan at a supported schema with a present backup is admitted and delegated as program plus argv. |

This is the F-010 rendering of the conformance invariants CF-021 and CF-026 in
`docs/24-TEST-STRATEGY-AND-RELEASE-GATES.md`: *tampered, expired or incompatible
update input is never installed* and *a schema future major produces an explicit
incompatible error instead of a downgrade*.

## Provenance

* Pinned specification revision: `1bf754298ba1bb266a77f13cded4bfe69484906f`
  (`axiom-specs`).
* Referenced shared examples, bytes NOT copied into this corpus: each vector
  records a `spec_contract.reference_path` plus its `reference_sha256` under
  `tests/fixtures/update-plan-contract/` and, for the valid control,
  `examples/update/update-plan.example.json`
  (`sha256 69dee6992cc7985011b94f91dd7f3f6dda4a86e47929c9c229120297fc0604a6`).
  The vectors are derived from the contract reasons those files assert; no
  example byte is embedded here, and `--spec-root` re-checks every digest.

## Fixture status

* These vectors are NOT registered shared fixtures: no row is added to
  `axiom-specs/conformance/fixture-index.json`, `fixture_index_digest` is
  unchanged, and `conformance/ownership.json` is untouched.
* Promoting any vector here to a shared contract fixture requires an approved
  specification change; the promoted bytes must then live under `examples/` in
  `axiom-specs` and be indexed by `conformance/fixture-index.json`.
* `fixtures/README.md` at the repository root is owned by another task and is
  deliberately not modified by F-010.
