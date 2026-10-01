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
| `macos-x64` | `x86_64-apple-darwin` | `axiom-graphd`, `axiom` | `axiom-<version>-macos-x64.tar.gz` |

`TargetPlatform::all()` is the authoritative list of four. A platform outside it
is not built, and therefore has no row to publish.

## 2. Per-artifact metadata

Every artifact carries, and every row records, all of the following:

- `version` - the workspace version, never a placeholder.
- `source_commit` - the full 40-character commit the build ran from.
- `platform` - one of the four triples above.
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
- The checked-in core manifest remains an unsigned, unpublished declaration.
  K-006 can produce local Intel Mac and Linux x64 candidates from a pinned
  commit; those candidates do not certify or publish any row. Windows, WSL2
  and container lanes need their own final artifact/runtime evidence.

## 5. K-006 local native x64 candidates

After committing reviewed source and building both binaries with
`AXIOM_BUILD_REVISION=<40-hex commit> cargo build --release --locked -p axiom-cli -p axiom-graphd`,
`release/package_core.py` accepts only a clean checkout at that exact commit.
It runs both `version --json` commands and refuses a mixed revision, version,
schema set or a binary that is not native Intel Mac Mach-O / Linux x64 ELF. It
produces a deterministic tar.gz with
the two executables and `release-info.json`, a Cargo workspace package
inventory bound to `Cargo.lock`, and `candidate-manifest.json` with hashes,
toolchain identity and explicit `unsigned`/`not_published` status.

`release/verify_core_candidate.py --candidate-dir <dir>` checks the candidate
archive, SBOM, payload hashes, executable modes, embedded revision and both
native version commands without reading the source checkout. The K-006 native
test also corrupts the archive and version identity and expects refusal.
Candidate artifacts and verifier output are review inputs; neither command
signs, notarizes, tags, uploads or certifies the release.

K-102 records a lane-local Mac Intel candidate and graph/catalog from an
isolated real-source project. Its source, binary, archive and fixture hashes
are handed to K-105 and K-107. The fixture verifies a project in a repository
subdirectory so query cannot silently search the wrong output root.
The K-106 downstream owner follow-up uses workspace version `0.1.1` for a
separate unsigned, unpublished Mac Intel candidate B. Its source commit and
payload hashes must be recorded by the native candidate packager; the earlier
K-102 `0.1.0` evidence remains a separate point-in-time candidate.
Windows/WSL execution and published release
provenance remain separate aggregate gates.

## 6. Related contracts

K-308 prepares the Windows `0.1.2` core B input for K-306. This candidate is
built from one committed source revision with native MSVC x64 binaries; the
corrected K-302/K-305 Windows `0.1.1` candidate is A. The checked-in core
manifest describes the next unpublished workspace version, while the K-308
evidence names the exact candidate ZIP, SBOM and hashes. It does not claim a
published `v0.1.2` release.

- Exit codes: `docs/CLI-EXIT-CODES.md`.
- Update delegation and approval binding: `docs/16-CLI-AND-CONTROL-API.md`
  section 7, implemented in `crates/axiom-graphd/src/commands/update.rs`.
