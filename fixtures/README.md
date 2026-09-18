# axiom-graphd analyzer fixtures

These are component-local regression fixtures for the `graph-analyze` crate of
`axiom-graphd`. They pin what the pinned static-analysis adapters must extract
and, just as importantly, what they must explicitly refuse.

## Purpose

Each fixture directory holds tiny, deterministic sources plus an
`*.expected.json` manifest per fixture. The manifest records:

* the expected declarations (kind, name, semantic path, source span text);
* the literal inheritance headers and their expected base names;
* the expected resolution outcomes for declared call-site shapes;
* the cases the build must NOT claim to support, recorded as documented
  unsupported cases with the expected refusal or absence instead of a guess.

The executable half of each manifest is the integration test in
`crates/graph-analyze/tests/`. A manifest is a contract between the fixture and
that test; it is not a claim of full compiler semantics. The scan is a
signature-level narrow line scan, so overload resolution, generic dispatch,
dependency injection and runtime type selection are out of scope.

Layout:

* `csharp/` - the C# narrow-scan fixtures (task F-004).
* `typescript/` - the TypeScript and Angular-relevant fixtures (task F-005).

## Provenance

The fixtures are authored in this repository for the analyzer adapters that
already exist here. They are derived from the public behavior of the
`graph-analyze` modules (`csharp::declarations`, `imports`, `calls`, `types`,
`l3::angular_http`, `typescript::declarations`) and from the coverage contract
in `contracts/schemas/coverage.schema.json`. No fixture bytes were copied from
any shared contract fixture.

## Status: component-local, not shared

These are component-local regression fixtures and are **not shared contract fixtures**.
They are:

* owned by `axiom-graphd` and versioned with this repository;
* NOT registered in `axiom-specs/conformance/fixture-index.json`;
* NOT part of `conformance/ownership.json`;
* NOT editable copies of anything under `axiom-specs/conformance/fixtures/`.

Promoting any fixture here to a shared contract fixture requires an
approved spec change. After that approval the fixture must live under
`axiom-specs/examples/` and be indexed as a shared fixture; do not add a
shared fixture row that points at a path outside `examples/`.

## Adding a fixture

1. Add the smallest deterministic source that exercises the behavior.
2. Add the matching `*.expected.json` manifest.
3. Extend the owning crate's integration test to load and assert it.
4. Keep every unsupported case explicit: record the refusal or the absence,
   never an assumed symbol.
