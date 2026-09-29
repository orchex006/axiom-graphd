# Final local B 0.1.1 input for K-106

Owner source: `c4f643ebf7af95395d12cbba8572e7065254e8b4` on
`feature/k-102-macos-core-candidate`. Native Darwin x86_64 build used
`AXIOM_BUILD_REVISION=<source> cargo build --release --locked -p axiom-cli -p axiom-graphd`.
`release/package_core.py` and `release/verify_core_candidate.py` passed from
that clean checkout; the verifier checked both native executables and 94 SBOM
packages. The prior 0.1.1 local archive at `../downstream-b-0.1.1/` is
superseded because it lacked retained-candidate retry repair.

- Archive SHA-256: `edad423cba453c191dbebab2cc4ccd5b07aacd70a89c3245a89eb272d2c388f5`
- Candidate manifest SHA-256: `b062ad90e517b5b7040a59711615df7f15c4d1f174d7b4334a32c09e1674f556`
- SBOM SHA-256: `8bd4ed8442e680b1f6fad479975e45a3c9522f42d73f60dc9f76ad4d7a7c108f`
- `axiom` SHA-256: `08d72b12eaad63de2f40a626cc4ea5c8380cadba80412b58812c00cc77258089`
- `axiom-graphd` SHA-256: `2c0bad2a382d0ed960d350ba32c44112c023ea65bf9703b2c3a150b241718378`

This local candidate is unsigned, not notarized, not published and not a
release. K-106 owns installed A/B evidence; independent review and other
platform lanes remain open.
