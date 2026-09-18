# Release build matrix

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Implementation/release
evidence is not implied.

This file records which artifact each supported target produces, and the gate an
artifact must pass before it may be published. The gate is implemented in
`crates/axiom-graphd/src/release.rs` (task B-093) and is executed by a value
returning `PublishDecision`, so CI can assert it without publishing anything.

Source requirements: `axiom-specs/docs/20-VERSION-CHECK-UPDATE-RELEASE.md`
(versioned artifacts, pinned provenance, no independent throwaway release) and
`axiom-specs/docs/23-SECURITY-AND-TRUST.md` (signed release validation, pinned
trust root, SBOM, anti-rollback).

## 1. Targets

One workspace publishes both `axiom-graphd` and the `axiom` installation CLI, so
one version and one commit describe every row below. The version is
`[workspace.package].version`; the commit is the 40-character commit the build
ran from.

| Platform | Rust target triple | Artifact | Archive |
| -------- | ------------------ | -------- | ------- |
| `windows-x64` | `x86_64-pc-windows-msvc` | `axiom-graphd.exe`, `axiom.exe` | `axiom-<version>-windows-x64.zip` |
| `linux-x64` | `x86_64-unknown-linux-gnu` | `axiom-graphd`, `axiom` | `axiom-<version>-linux-x64.tar.gz` |
| `macos-arm64` | `aarch64-apple-darwin` | `axiom-graphd`, `axiom` | `axiom-<version>-macos-arm64.tar.gz` |

`TargetPlatform::all()` is the authoritative list of three. A platform outside it
is not built, and therefore has no row to publish.

## 2. Per-artifact metadata

Every artifact carries, and every row records, all of the following:

- `version` - the workspace version, never a placeholder.
- `source_commit` - the full 40-character commit the build ran from.
- `platform` - one of the three triples above.
- `signature` - the signing key id, or `unsigned`.
- `sbom_sha256` - SHA-256 of the artifact SBOM.

## 3. Publication gate

`release::decide` refuses publication, in this order, with a stable reason:

| Reason code | Refused when |
| ----------- | ------------ |
| `placeholder-metadata` | `version` contains `REPLACE`, `TODO`, `FILL_ME`, `unknown` or `latest`. |
| `sbom-missing` | `sbom_sha256` is absent, not 64 characters, or a placeholder. |
| `commit-not-pinned` | `source_commit` is not exactly 40 hexadecimal characters. |
| `unsigned-artifact` | `signature` is `unsigned`. |
| `signature-key-unknown` | `signature` names an empty or placeholder key id. |

Only an artifact that passes all five may be published. Consequences worth
stating plainly:

- A freshly built matrix is unsigned. `ReleaseMatrix::publishable()` on an
  unsigned matrix is therefore empty, and no release is published merely because
  the build succeeded.
- A short or abbreviated commit never reaches a published artifact, so every
  published artifact is attributable to a pinned commit.
- Unsigned or placeholder metadata cannot be published by asserting that it is
  fine; the refusal is a value the caller must handle.

## 4. What this file does not claim

- It does not claim a downloadable artifact exists for the version currently in
  the repository. The row describes the artifact a build of that target
  produces.
- It does not claim the Windows or macOS rows were built on this host. This
  workstream builds and tests `windows-x64`; the other rows are the declared
  matrix, and their verification depends on the release pipeline that pins the
  signing key.

## 5. Related contracts

- Exit codes: `docs/CLI-EXIT-CODES.md`.
- Update delegation and approval binding: `docs/16-CLI-AND-CONTROL-API.md`
  section 7, implemented in `crates/axiom-graphd/src/commands/update.rs`.