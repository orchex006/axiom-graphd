# Catalog runtime review — macOS x64 — 2026-09-22

- `serve` scans source from the resolved project membership root and publishes
  under the resolved repository root, matching SOURCE-OF-TRUST §4.
- A full solution batch hydrates or seals every member manifest before catalog
  publication. The writer verifies the manifest digest and source fingerprint,
  installs the immutable catalog generation, then atomically replaces its
  pointer.
- Catalog publication takes `admission.lock` exclusive followed by `data.lock`
  exclusive and releases data before admission. MCP reads the catalog once and
  opens the exact member generation; newer project pointers and absent members
  do not substitute a different generation.
- `solution register --apply` records `catalog_host_repo` and the accepted
  config hash under machine-local registered-solution metadata. A stale record
  or a multi-repository solution without a record is refused; a legacy single
  repository remains unambiguous.

Validation: `cargo fmt --check -p axiom-graphd`; catalog runtime 3 tests,
serve 9 tests, and solution command 5 tests passed on this host.
