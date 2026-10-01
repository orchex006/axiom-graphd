# K-308 owner review

- Branch: `feature/k-308-windows-core-candidate`; source revision: `d548bdfcd34975abf08d6a88de335f9ae432f55c`. Exact draft spec pin: `9e34f1645414bf4502af417a95b9333cf2f86887`.
- Diff scope: shared Cargo version/path dependencies, root VERSION, LF checkout rule for Cargo.lock, unpublished core declaration, owner docs and task evidence. No user files or installed state changed.
- A: corrected K-302/K-305 native Windows core 0.1.1 ZIP SHA `1c834d5b3a594866183fca7356cb06a65443f8814dd29abc47c3bc6ef8c6ea29`. B: native Windows core 0.1.2 ZIP SHA `981ea1a4433cad32fe3c0e2372d22e4c75440fe66efd3afaa428158456bd8744`. The graph/control/queue schema set remains 1/1/1.
- Clean fresh worktree packaging reproduced the B ZIP, SBOM and manifest byte for byte. Packaged daemon and engine CLI both report 0.1.2 and the same source revision.
- Packaged daemon indexed actual C# source, query found `Demo.TokenSource`, persistent watcher observed `WatcherAdded` and advanced the catalog generation. Schema 99 fixture refused. Corrupt ZIP, wrong revision, manifest version, architecture and schema mutations refused.
- Required scoped checks passed: cargo fmt, all-target clippy, full `axiom-graphd` crate tests, Windows service adapter tests, core-manifest properties, packaging unit/regression, native fixture, release build and candidate verifier.
- Additional `cargo test --locked --workspace --quiet` was run and failed in `axiom` library: 542 passed, 46 failed. The failures are in pre-existing Unix path/host assertions and one production filesystem test with a Windows rename permission error; K-308 did not alter these modules. See `full-workspace.txt`. This limits the all-workspace green claim and remains follow-up work; it does not replace the passed native candidate checks.
- Candidate is unsigned and unpublished. Service CLI Windows limitation from K-305 persists. Independent update/release review and main integration remain separate gates.
