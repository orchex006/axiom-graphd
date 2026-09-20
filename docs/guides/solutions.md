# Multiple-project Solutions

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. This guide describes the
intended V2 behavior of the engine and CLI. It is documentation, not evidence
that a compiled daemon, installer or service exists.

## 1. What a Solution is

A **solution** is the unit an operator registers. One solution has:

- one portable `solution_id`;
- one or more **repositories**, each named by a logical `repo_id`;
- one or more **projects** per repository, each with its own `project_id`;
- exactly one **catalog host** repository, chosen by the operator.

Repository and project ids are logical names (`[a-z][a-z0-9-]{0,62}`). They are
not paths. The same repository can therefore hold several projects, and one
solution can span several repositories, without any id encoding a machine
location.

Each project claims a repository-relative source `path`: `"."` for the whole
repository, or a portable `/`-separated relative path. Two projects may share a
repository, but their claims must not overlap. `src/App` and `src/AppTests` are
a valid pair; `src/App` and `src/App/generated` are not, because the second
claim is nested inside the first and graph ownership would be ambiguous. The
membership check is segment-aware and refuses the overlap before any row is
written.

## 2. The catalog host

The catalog host is one of the member repositories. It carries the solution's
publication namespace `_catalog/` under the generated graph root, and it is the
single read commit point for the solution:

```text
<repository>/
  .axiom/
    graph/
      <solution-id>/
        <project-id>/            # one immutable generation vector per project
        _catalog/                # only in the chosen catalog-host repository
```

A catalog pins the exact `generation_id` and `source_fingerprint` of every
member project, across every repository of the solution. A member that vanishes
from the inputs is refused (`export-catalog-member-missing`) rather than
silently replaced by whatever generation happens to be newest, and a catalog
that names a generation that was never published fails verification. One query
therefore reads one catalog vector; the per-repository pointers are not an
independent source transaction.

## 3. Worked example: two repositories, four projects

The portable, Git-tracked file is
`.axiom/config/solutions/<solution-id>.json`. It contains logical ids,
repository-relative paths, and a `binding_key` per repository. It never
contains an absolute checkout path, a machine-local reference or a secret.

<!-- BEGIN SOLUTIONS EXAMPLE -->
```json
{
  "schema_version": 2,
  "solution_id": "demo-solution",
  "profile": "default",
  "catalog_host_repo": "repo-alpha",
  "repositories": [
    { "repo_id": "repo-alpha", "binding_key": "alpha" },
    { "repo_id": "repo-beta", "binding_key": "beta" }
  ],
  "projects": [
    { "project_id": "proj-app", "repo_id": "repo-alpha", "path": "src/App", "language_profile": "csharp-dotnet" },
    { "project_id": "proj-portal", "repo_id": "repo-alpha", "path": "src/Portal", "language_profile": "typescript-angular" },
    { "project_id": "proj-jobs", "repo_id": "repo-beta", "path": "services/Jobs", "language_profile": "csharp-dotnet" },
    { "project_id": "proj-tools", "repo_id": "repo-beta", "path": "tools/GraphTools", "language_profile": "mixed", "allow_untracked": true }
  ],
  "graph_output_root": ".axiom/graph",
  "ignore": [],
  "watch": { "debounce_ms": 250, "max_wait_ms": 2000, "inventory_interval_seconds": 300, "backend": "auto" },
  "queue": { "worker_limit": 2, "max_batch_files": 256, "max_batch_bytes": 33554432, "retry_limit": 3 },
  "semantic_links": [],
  "workspace_layout": 2
}
```
<!-- END SOLUTIONS EXAMPLE -->

`repo-alpha` holds two projects and is the catalog host; `repo-beta` holds two
more. Nothing in this file resolves a project to a filesystem location.

## 4. Local bindings stay local

The portable file names a repository by `repo_id` and points at a local
`binding_key`. The operator-provided, machine-local binding storage maps that
key to one absolute checkout path:

```text
AXIOM_HOME/config/registry.json      # machine-local; never committed
  bindings:
    alpha -> <absolute checkout of repo-alpha>
    beta  -> <absolute checkout of repo-beta>
```

Rules:

- The absolute checkout path lives only in machine-local state
  (`AXIOM_HOME/config/registry.json`) or an ignored local override. It is never
  written into `.axiom/config/**`, a graph snapshot or a catalog.
- An id is resolved to a path only through a declared binding. Guessing a path
  from `repo_id`, following `..`, or accepting a symlink that leaves the bound
  root is refused.
- Graph payloads store logical ids and repository-relative `/` paths only.
- A binding path that is not an absolute local path is rejected, and a portable
  path that is absolute, backslash-separated, contains a `..` segment, or
  carries a drive prefix is rejected as `UNSAFE_PORTABLE_PATH`.
- Copying the same logical solution between machines changes only the local
  binding; the portable config and every published generation digest are
  unchanged.

## 5. Operator flow (target interface)

```bash
axiom-graphd solution register --config .axiom/config/solutions/demo-solution.json --bindings <machine-local-bindings> --dry-run
axiom-graphd solution register --config .axiom/config/solutions/demo-solution.json --bindings <machine-local-bindings> --apply
axiom-graphd solution list --json
axiom-graphd reconcile --solution demo-solution --scope full --wait --timeout 30s --json
axiom-graphd status --solution demo-solution --json
```

The dry run reports every root, output path, excluded path, profile and
cross-project link, plus each collision, before anything is written. A missing
root is reported, never auto-cloned. When several projects share a repository,
each project must declare its own `path` so that no two projects claim the same
or a nested source or generated-output root.

## 6. Guarantees and refusals

| Situation | Result |
|---|---|
| Two projects in one repository with disjoint claims (`src/App`, `src/Portal`) | accepted; both projects are published into the shared catalog |
| Two projects with the same or a nested claim in one repository | refused with `CONFLICT` (`rule=root-overlap`) naming both owners |
| Duplicate `project_id` in one solution | refused with `CONFLICT` (`rule=duplicate-project-id`) |
| Absolute, backslash, `..` or drive-prefixed project `path` | refused with `UNSAFE_PORTABLE_PATH` |
| A project name that is not a portable id | refused with `VALIDATION_ERROR` |
| Catalog member absent without an explicit drop | refused with `export-catalog-member-missing` |
| Catalog naming an unpublished or mismatched generation | refused with `export-missing` / `export-integrity` |
| Two writers claiming one output namespace | refused with `WRITER_ALREADY_RUNNING` |
| One `binding_key` declared by two `repositories[]` entries | refused with `CONFLICT` (`rule=binding-key-duplicate`) |
| A declared `binding_key` with no local root, or a local key the solution does not declare | refused with `VALIDATION_ERROR` (`rule=binding-key-unresolved`) |
| A derived project root that leaves its bound local root | refused with `VALIDATION_ERROR` (`rule=project-root-escapes-binding`) |
| A `semantic_links[]` endpoint that is not a member project | refused with `VALIDATION_ERROR` (`rule=link-endpoint-not-member`) |
| An `http`, `sql` or `message` link with no `route_prefix` | refused with `VALIDATION_ERROR` (`rule=route-prefix-required`) |
| A `route_prefix` that is machine-local or credential-shaped | refused with `VALIDATION_ERROR` (`rule=route-prefix-not-portable-free-text`) |
| An observed service address that no declared alias matches | explicit unresolved result (`rule=alias-unresolved-host`), never a guessed project |
| An observed service address two different projects claim | refused with `CONFLICT` (`rule=alias-ambiguous-host`), never a tie broken by order |

## 7. Status and limits

The membership, path, binding, publication and catalog rules above are
implemented in `graph-core` and `graph-export`. The registered solution document
itself is read by `axiom-config` (`read_registered_solution`, task H-004): it
validates the whole membership claim set before returning anything, derives the
cross-service alias map from `semantic_links[].route_prefix`, and writes no row
and no file, so an accepted document is the only source of the cross-service
join. The L3 HTTP join consumes that map through
`SolutionMapping::from_registered_aliases(registered.l3_aliases())`; its alias
table is private and has no mutator, so a host cannot be resolved by a table a
caller built by hand. The registration CLI, the installer and the service lifecycle are separate
graphd tasks; until they ship, this guide documents the intended interface and
the invariants the engine already enforces. See `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` for the
durable-state contract and `docs/21-INSTALLATION.md` for the install runbook.
