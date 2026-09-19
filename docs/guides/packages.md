# Package and provenance versions

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Task: **E-034**
(`crates/axiom/src/packages.rs`). This page describes the intended V2 package
and provenance report. It is documentation, not evidence that a compiled
`axiom version --json` surface already prints this document; **no command is
invoked here.**

## The one rule

> Version report lists graphd/CLI as one core release, MCP and skills as
> independent components, plus pinned spec/fixture revisions. Documentation
> inherits owner versions; no standalone docs/conformance update packages are
> required.

## Why this is not `VersionReport`

`contracts/schemas/version-report.schema.json` is frozen at eight properties
with `additionalProperties: false`, so the ecosystem package view cannot be
added to `crate::version::VersionReport`. It is reported as its own document,
`PackagesReport`, built by `build_report` from injected inputs.

## One core release

`docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 1 requires the daemon and the
standalone CLI to be published from one locked workspace, at one version and one
revision. The report resolves two pins into a single `core_release` row whose
`components` are `["axiom-graphd", "axiom"]`. A pin pair whose versions disagree
is refused as `core_release_split`, and a version other than this build's
`CORE_VERSION` is refused as `core_version_mismatch`.

## Independent components

`axiom-mcp` and `skills` are published and updated independently. Each must be
present and pinned; the report never forces them to the core version. An unknown
component is refused as `unexpected_package_component` and a missing one as
`missing_independent_component`.

## Pinned spec and fixture revisions

The report carries the pinned specification baseline (`spec_version`,
`spec_revision`) and fixture provenance (`revision`, `index_sha256`). Fixtures
shipped by a component are component-local: they are *not* the shared contract
fixture index, so a claim that they are shared is refused as
`shared_fixture_index_not_supported` rather than relabelled.

## Documentation inherits

`docs` and `conformance` do not carry their own version. A row that declares one
is refused as `standalone_documentation_version`, a row with an unknown owner is
`documentation_owner_missing`, and `require_updatable` refuses to treat either as
an update package (`no_standalone_documentation_package`). The report therefore
lists exactly the components that carry their own update package:
`axiom-graphd`, `axiom`, `axiom-mcp`, `skills`.

## Refusals

| Rule | Meaning |
|---|---|
| `core_release_split` | the daemon and CLI pins disagree on version or revision |
| `core_version_mismatch` | the core version is not this build's `CORE_VERSION` |
| `core_component_mismatch` | the core pins are not the daemon and CLI |
| `core_revision_not_pinned` / `independent_revision_not_pinned` / `spec_revision_not_pinned` / `fixture_revision_not_pinned` | a revision is not a pinned 40-hex value |
| `unexpected_package_component` | a component is not a package of this ecosystem |
| `missing_independent_component` | `axiom-mcp` or `skills` is absent |
| `spec_version_mismatch` | the specification baseline is not this build's |
| `fixture_index_not_digest` | the fixture inventory digest is unusable |
| `shared_fixture_index_not_supported` | component-local fixtures were claimed to be shared |
| `unexpected_documentation_component` / `standalone_documentation_version` / `documentation_owner_missing` | a documentation row is not an inheriting one |
| `no_standalone_documentation_package` | documentation was treated as an update package |

## What is not implemented

`build_report` is a pure function of its inputs. It reads no Git object store,
no filesystem and no network; the only outputs are a validated value and its
canonical JSON text.