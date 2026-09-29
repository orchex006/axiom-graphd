# Unsigned local core candidate B 0.1.1

Owner source commit: `47daa67fa1c52da0a1a28cffe4ca104c8da8b903`, branch
`feature/k-102-macos-core-candidate`. Built natively on Darwin x86_64 with
`AXIOM_BUILD_REVISION=<commit> cargo build --release --locked -p axiom-cli -p axiom-graphd`.
`release/package_core.py` and `release/verify_core_candidate.py` both exited 0
from the clean pinned checkout. The verifier reports two native executables,
94 SBOM packages, exact source revision and artifact hashes.

- Archive `axiom-0.1.1-macos-x64.tar.gz` SHA-256
  `862f97ec274bf88b977cbfc0255d18fe571fcee4b8d9d33e85c4bd05aa296ad4`
- Candidate manifest SHA-256
  `009cc6cedeab2f5e4b3340b71006b423f41ee8326c74622591bf2ae846729ea5`
- SBOM SHA-256
  `1323f55b66df35ad8244a8d70f9d1c925982cce76718a7b6c7231400d266d2ce`
- `axiom` binary SHA-256
  `edce1538218caf80ebedc24e8dd92e560f32c182cdef84e88bc34e82b850268a`
- `axiom-graphd` binary SHA-256
  `8cd123501485e4ad8ae13199ffd666a00a30ef6dbee79767ecd9bbafefcb427f`

This is local K-106 input, unsigned, not notarized and not published. The
K-102 0.1.0 report remains separate. Full installed A/B test is owned by
`axiom-cli`; independent review and cross-platform release gates remain open.
