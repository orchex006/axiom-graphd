# Native platform matrix (V2-030)

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Implementation/release
evidence is not implied by this document. It records only what was executed on a
real host, and it marks everything else `not_run` with the reason and the command
a real host would run.

Normative sources:

* `axiom-specs/contracts/cross-platform-v2.md` CP-01 - the four required release
  targets are `windows-x64`, `linux-x64`, `macos-arm64` and `macos-x64`, and no OS
  is supported merely because its target compiled.
* `axiom-specs/compatibility/platform-matrix.json` - `mandatory_targets` is
  exactly those four, each with `native_execution_required: true` and
  `certified: false` until a native execution record exists.

## 1. How to read the matrix

| Column | Meaning |
| --- | --- |
| `target` | One of the four mandatory targets. |
| `status` | `verified` - a real execution happened on that target and its hash is recorded. `not_run` - nothing ran, and the reason plus the command a real host would run are recorded. |
| `scope` | Exactly what the row's execution covered. A row never claims more than its scope. |
| `execution_identity` | The OS and architecture that were actually observed. |
| `command` | The exact command that was executed, or, for `not_run`, the exact command a real host must run. |
| `exit` | The observed process exit code, or `-` when nothing ran. |
| `artifact_sha256` | SHA-256 of the artifact this row certifies, or `-` when no artifact exists. |
| `toolchain` | The toolchain actually observed on that target, or `-` when none was observed. |
| `evidence` | The committed evidence file for this row. |
| `note` | The observed result, or, for `not_run`, the reason. |

Two rules make a row legitimate. `tests/native/check_matrix.py` enforces them and
so does the Rust test `crates/axiom-graphd/tests/native_matrix.rs`, which embeds
this file, so breaking either rule fails `cargo test`:

* a `verified` row must carry a recorded execution (command and exit code) **and**
  a recorded SHA-256, and both must really appear in the committed evidence file;
* a `not_run` row must carry a real reason and must **not** carry an invented
  artifact hash, toolchain identity or exit status.

A cross-compile is not native execution. A Linux or container reference result
does not certify Windows or macOS. No row below is `verified` on the strength of
a compile.

## 2. The matrix

<!-- BEGIN NATIVE MATRIX -->
| target | status | scope | execution_identity | command | exit | artifact_sha256 | toolchain | evidence | note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| windows-x64 | verified | native-binary-built-and-run | Windows 11 Pro 10.0.26200 x86_64 (rustc host x86_64-pc-windows-msvc) | target/debug/axiom-graphd.exe version --json | 0 | 77f15708dd1112053989d582750541c99a19dfbe529aaeda0a6d912baf363285 | rustc 1.85.0 (4d91de4e4 2025-02-17) cargo 1.85.0 (d73d2caf9 2024-12-31) target x86_64-pc-windows-msvc | evidence/V2-030/v2030-windows-native.txt | native Windows execution of the built artifact: exit 0, sqlite_version 3.50.2, wal baseline 3.51.3 not yet met |
| linux-x64 | verified | python-side-harnesses-in-wsl2 | Ubuntu 26.04.1 LTS under WSL2 kernel 6.18.33.2-microsoft-standard-WSL2 x86_64 glibc 2.43 | wsl -d Ubuntu -u thanatmet-t -- bash evidence/V2-030/run-wsl-linux.sh | 0 | f3241af25085428499fd08221bc813ea567b920b0a8ee40337a5cdcf12736876 | Python 3.14.4 sqlite3 3.46.1 cargo NOT-PRESENT | evidence/V2-030/v2030-wsl-linux.txt | real WSL2 Linux execution of the Python harnesses: runner exit 0, ten harnesses exit 0 and core_manifest.py exit 2 for a pre-existing stale lockfile hash; no Linux Rust binary was built |
| macos-x64 | not_run | none | - | cargo build --release --target x86_64-apple-darwin then target/x86_64-apple-darwin/release/axiom-graphd version --json | - | - | - | evidence/V2-030/v2030-macos-notrun.txt | no macOS host available in this environment |
| macos-arm64 | not_run | none | - | cargo build --release --target aarch64-apple-darwin then target/aarch64-apple-darwin/release/axiom-graphd version --json | - | - | - | evidence/V2-030/v2030-macos-notrun.txt | no macOS host available in this environment |
<!-- END NATIVE MATRIX -->

The set of targets above is exactly `mandatory_targets` of
`compatibility/platform-matrix.json`. No fifth row may be added to this table
without an ADR in `axiom-specs`, and no mandatory target may be dropped from it.

## 3. windows-x64 - verified

Host: Microsoft Windows 11 Pro build 26200 (10.0.26200), 64-bit, 13th Gen Intel
Core i7-1355U. Toolchain: the workspace pin `rust-toolchain.toml` channel
`1.85.0` (`rustc 1.85.0 (4d91de4e4 2025-02-17)`, `cargo 1.85.0 (d73d2caf9
2024-12-31)`), host triple `x86_64-pc-windows-msvc`. This is a real Windows
execution of the artifact the repository's own gates build, not a WSL or
cross-compile result.

Artifacts produced by `cargo build --locked` (exit 0, 49.85 s):

| Artifact | SHA-256 | Bytes |
| --- | --- | --- |
| `target/debug/axiom-graphd.exe` | `77f15708dd1112053989d582750541c99a19dfbe529aaeda0a6d912baf363285` | 2887680 |
| `target/debug/axiom.exe` | `6309b3e06c1252bede8cd707a43c277eeb855223abe2a8a8db211b090e0e6039` | 424448 |

Positive run. `axiom-graphd version --json` returned exit `0` with exactly one
JSON object on stdout and nothing on stderr:

```json
{"component":"axiom-graphd","version":"0.0.0-dev","spec_version":"2.0.0-draft.1","graph_schema":1,"control_api":1,"queue_schema":1,"build_revision":"unknown","update_status":"unconfigured","sqlite_version":"3.50.2","sqlite_wal_baseline":"3.51.3","sqlite_wal_supported":false,"analyzers":[]}
```

`sqlite_version` is the runtime fact AC1 asks for: the binary links the bundled
SQLite and reports `3.50.2` on this host. The WAL baseline of the pinned contract
(`3.51.3`) is not met, so `sqlite_wal_supported` is `false`.

`--help` returned exit `0` and printed the usage, the wired operator-slice forms
and the frozen exit-code table. `axiom version --all --json` also returned exit
`0`: the installation CLI ships from the same workspace at the same version.

Every verb task H-001 wired answers honestly. `status`, `doctor`, `reconcile`,
`queue list`, `solution list`, `changed`, `query context` and `update check` each
returned exit `4` (`NOT_READY`) with a stated reason naming the binding that a
later work package owns - for example `status has no open store in this build`.
They are recorded as exit 4, not as success and not as a failure of this task.
The complete stdout/stderr/exit capture is in `v2030-windows-native.txt`.

Negative and failure-boundary run. Eleven malformed invocations were executed on
the same binary and all eleven were rejected with exit `2` (`VALIDATION_ERROR`):
an unrecognised verb in text mode (stdout stays empty, the diagnostic goes to
stderr), the same verb with `--json` (exactly one error envelope on stdout), an
unrecognised option, an option whose value is missing at the end of argv, an
option whose value would start with `-`, an unknown subcommand, an out-of-enum
`--scope`, a missing required selector, a missing required mode switch, an
out-of-range `--limit` and a non-integer `--timeout`. The capture is in
`v2030-negative.txt`.

## 4. linux-x64 - real WSL2 Linux execution, scoped

WSL2 Ubuntu 26.04.1 LTS (kernel `6.18.33.2-microsoft-standard-WSL2`, glibc 2.43)
executed the repository's Python harnesses against this real tree. That is real
Linux execution, and it is labelled here as WSL2 Linux: it is **not** a
bare-metal Ubuntu 24.04 LTS certification, and it is **not** Windows evidence.
The leg was first run as
`wsl -d Ubuntu -u thanatmet-t -- bash evidence/V2-030/run-wsl-linux.sh`, and then
re-run at the same revision with the owner-specified form of the invocation,
`wsl -d Ubuntu -u thanatmet-t -- bash -lc '<command>'` where `<command>` is
`bash evidence/V2-030/run-wsl-linux.sh`. Both invocations were real, both exited
`0`, and the twelve files the runner writes (eleven per-harness logs plus the
manifest) were byte-identical between them, so the manifest digest below is stable
across both. `v2030-wsl-linux.txt` records both invocations and the second run's
verbatim capture.
`platform-matrix.json` does declare `wsl2-linux-x64` as its own delivery platform
with `evidence_target: linux-x64`, and this leg is the evidence that platform can
produce here under the rule `wsl_is_windows_evidence: false`; what a WSL host
cannot produce is a real `x86_64-unknown-linux-gnu` binary or the CP-10 gates, so
`linux-x64` stays `certified: false`.

WSL carries **no cargo**, so no `x86_64-unknown-linux-gnu` artifact was built and
this leg certifies **no Linux binary**. The artifact the row hashes is the run
manifest `evidence/V2-030/wsl-linux-manifest.json`
(`f3241af25085428499fd08221bc813ea567b920b0a8ee40337a5cdcf12736876`), which the
Linux run itself produces: kernel, distribution, interpreter, SQLite, and the
exit code plus harness/log digest of every harness.

Result: ten of the eleven harnesses exited `0`, and `core_manifest.py` exited
`2`. That single divergence is **pre-existing at the base revision and unrelated
to this task**: `release/core-manifest.json` records
`178068d5fe6d39d956ad6ea9354e034b52103822f706ae95e99cb88f335f030d` for
`Cargo.lock`, while `Cargo.lock` at this revision hashes to
`aadf2d19378ad7ace80ad7020a86dc1c40961f80e3f82fd48e087916dfe11de3`. The same
divergence reproduces natively on Windows. It is V2-021 territory, it is not
fixed here, and it is not hidden here.

## 5. macos-x64 and macos-arm64 - not_run

Reason, verbatim: `no macOS host available in this environment`. There is no
macOS machine, VM, Rosetta environment or reachable macOS runner for this
worktree, so neither Apple target was built, executed or hashed, and neither row
carries a digest. Cross-compiling an Apple target would not change this: CP-01
requires native execution. `v2030-macos-notrun.txt` records the reason and the
exact command a macOS x64 or arm64 host must run.

## 6. Reproducing

```text
# Windows leg (this host)
cargo build --locked
target/debug/axiom-graphd.exe version --json

# Linux leg (WSL2 Ubuntu; no cargo in WSL, so the Python harnesses run there)
wsl -d Ubuntu -u thanatmet-t -- bash evidence/V2-030/run-wsl-linux.sh
wsl -d Ubuntu -u thanatmet-t -- bash -lc 'bash evidence/V2-030/run-wsl-linux.sh'

# the matrix rules themselves
python tests/native/check_matrix.py
cargo test --locked -p axiom-graphd --test native_matrix
```

The per-harness logs of both legs are committed unchanged under
`evidence/V2-030/py-win/` and `evidence/V2-030/py-wsl/`. They are stored with LF
line endings, pinned by the `evidence/** text eol=lf` rule in `.gitattributes`,
so the SHA-256 digests recorded in `SUMMARY.txt` and in the two manifests
reproduce from a fresh checkout on any platform.

## 7. What is still open

* No macOS row is verified, and none can be from this environment.
* No Linux binary was built or run: the Linux leg covers the Python harnesses
  only, on WSL2 rather than on a bare-metal Ubuntu 24.04 LTS host.
* The CP-10 release gates (install/uninstall, queue restart, watcher recovery,
  Rust/Python locks, snapshot/GC races, UTF-8 path/case/CRLF handling, stdio and
  HTTP transports, offline read, migration, update/rollback, no-admin workflows)
  have not been executed natively for any target; `platform-matrix.json` keeps
  every target `certified: false` and this document does not change that.
* `core_manifest.py` fails at the base revision for the stale `Cargo.lock` hash
  recorded in `release/core-manifest.json` (see section 4).

## 8. Path decision recorded

The V2-030 card proposes `evidence/artifacts/V2-030/` for its evidence
artifacts. The owner instruction for this task fixed the evidence set as
`evidence/V2-030/` with an exact list of file names, and those names are the ones
every row above references. The evidence therefore lives at
`evidence/V2-030/`; nothing was moved or duplicated, and the earlier slice's
convention (`evidence/artifacts/H-001/`) is unchanged.