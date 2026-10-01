# K-309 owner review — Windows local runtime

Source: `4f8765a74ae5f077f53d092ddb4fea40d0c44fe3` on
`feature/k-309-windows-service-core`; pinned specs:
`1fa70816b81479fe1969d8673ef699eba15646d8`. This is an unsigned,
unpublished core `0.1.2` candidate. It does not certify or release Windows.

## Exact output

| Artifact | SHA-256 |
| --- | --- |
| Windows x64 core ZIP | `ba9e294cd112c7311b755ab9aad2d3713502c68925febb48359fec0fe1cc2c53` |
| Candidate manifest | `b33999d07c1a71d3ce00c93620870d08948eec6f0e010f7891d6c630717af7df` |
| SBOM | `04e1356239dc2bfc061caa06b32f8073537a728a6e64fc5b9b5491565c2a7f5f` |
| Packaged daemon | `2c85a61a8f03f433b5cde82ba05e70eeabdc4e3a56fd4c003cc733a023f86164` |
| Packaged CLI | `bd133345a68fded83678a625fe1abf8df7e4e7ed915cc85aaed9bd65c5483ae5` |

`release/package_core.py` produced identical ZIP, manifest and SBOM hashes
twice from a clean source worktree at the source revision. The native verifier
executed both binaries and accepted the candidate. The packaged C# fixture
published a graph, answered a checkpoint query, detected an edited source
symbol and refused an incompatible pointer; see `real-source-report.json`.

## Acceptance evidence

- **AC1:** The final packaged binary registered a per-user Scheduled Task with
  `Limited` principal. Public service start/status/stop/uninstall and a native
  C# query/watcher passed. The user-data sentinel survived; no task or daemon
  process remained after uninstall.
- **AC2:** Final-binary native transcripts show a changed scheduler export
  refused with `CONFLICT` exit 6, a different owner SID refused with
  `FORBIDDEN` exit 5, a changed definition, missing owner and stale generation
  each refused with `CONFLICT` exit 6. The task remained until the original
  state was restored and public owned uninstall ran. Link/foreign-path and
  idempotency boundaries also passed the scoped Windows service unit tests.
- **AC3:** `native-update-transcript.txt` records public `axiom update` from a
  separate test-only A daemon to the exact packaged B daemon above, with an
  owned service registered. Activation drained A, reinstalled and started B;
  rollback drained B, reinstalled and started A. Both stages had exactly one
  daemon process and a Running Limited task, and final uninstall left zero.
  A uses a debug build of the same K-309 service-capable code labelled
  `0.1.1-k309-test` solely to exercise distinct versioned destinations. It is
  not a released or accepted `0.1.1` core. B uses the exact `0.1.2` candidate
  daemon SHA above. The initial native run exposed a task left Ready; a later
  run exposed the asynchronous `/end` writer-lock race. Both faults were fixed
  before this final run.
- **AC4:** `cargo fmt --all -- --check`, scoped Windows service (25) and
  ecosystem update (15) unit tests, `cargo clippy --locked -p axiom-cli -p
  axiom-graphd --all-targets -- -D warnings`, full `axiom-graphd` crate tests
  (150 plus integration slices), release build, core manifest, package unit,
  native verifier and real-source fixture passed. The exact spec pin passed.
  The owner diff is confined to K-309 allowed paths, with docs and Changelog
  updated. Historical K-308 and earlier K-309 bytes remain separate.

## Scope and limits

The test root was isolated on D: and all native task/process state was removed
after each run. No WSL, Docker, Bash or elevation was used. The native test
proves graphd-owned service update orchestration with an exact B candidate;
K-010 still owns final installed distribution, MCP, migration and full Windows
lifecycle. K-601/K-602 require published trusted fixtures and other lane
results. No signature, release tag, publication, main merge or independent CI
rerun is claimed here.
