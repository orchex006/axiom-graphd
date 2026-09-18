# Bootstrap human-edit conformance vectors (task F-008)

Owner: `axiom-graphd`. Task: F-008. Pinned specification revision:
`1bf754298ba1bb266a77f13cded4bfe69484906f`.

## What this corpus is

Small before-state trees for the managed AGENTS.md bootstrap/update contract.
Each vector under `vectors/<id>/before/` is a repository fragment that bootstrap
may be asked to update. `vectors.json` carries, per vector, the expected outcome
(`append`, `replace`, `conflict` or `unchanged`), the exact set of paths that may
change, the literal human text that must survive, and the expected BOM and
newline properties.

The vectors are byte-exact: `fixtures/bootstrap/.gitattributes` sets `-text` so
Git performs no end-of-line or encoding conversion on them. The LF, CRLF and
UTF-8 BOM variants of the same managed content are therefore committed and read
back as the same bytes on every platform.

Every vector is static input text plus an expected non-destructive outcome. No
vector contains a runtime log, captured output or recorded terminal session, and
the regression test executes nothing from the corpus.

This corpus is **not** a registered shared contract fixture. It adds no row to
`conformance/fixture-index.json` in `axiom-specs`, it does not change
`fixture_index_digest`, and it does not touch `conformance/ownership.json`.
Promoting any vector to a shared contract fixture requires an approved
specification change and must then live under `examples/` in `axiom-specs` and be
indexed there.

## Why the contract lives in the test

The production Rust managed-instructions updater does not exist in `axiom-graphd`
yet. `crates/axiom-graphd/src/commands/update.rs` implements version/trust
gating and delegated `update apply` argv handling only, and
`crates/axiom-graphd/src/control/` implements the control-token surface only.
Neither reads or rewrites a managed block. This corpus therefore targets the
documented contract as the executable oracle:
`crates/axiom-graphd/tests/bootstrap_fixtures.rs` implements the managed-merge
algorithm from `docs/18-BOOTSTRAP-AND-MANAGED-INSTRUCTIONS.md` section 4 and
section 5, the conformance rows CF-018 (reapply is a no-op outside owned
content), CF-019 (human-modified block or stale plan conflicts and preserves
content) and CF-020 (half bootstrap/update crash recovers without losing user
changes) of
`axiom-specs/docs/24-TEST-STRATEGY-AND-RELEASE-GATES.md`, and section 9 of
`axiom-specs/SOURCE-OF-TRUST.md` (markers, plan digests, before-hash checks,
preserved human text and encoding boundaries).

The test follows the semantics of the offline reference
`axiom-specs/reference/bootstrap_reference.py` so the same vectors can be
re-pointed at the Rust implementation when it lands without rewriting the
corpus. That gap is recorded as an F-008 limitation.

## Templates and provenance

`templates/AGENTS.block.md` and `templates/POLICY.md` are byte copies of
`axiom-specs/repo-seeds/axiom-skills/templates/bootstrap/AGENTS.block.md` and
`POLICY.md`. `vectors.json` pins their SHA-256, and the regression test asserts
the on-disk digests still match, so template drift fails the corpus instead of
silently changing every expected outcome.

Pinned digests:

- `AGENTS.block.md` SHA-256: `883dc46acab1cf4a834f3a2b24a63623ac1dd531841ee651f5301397aab13cde`
- `POLICY.md` SHA-256: `1b4972d3197a7579c7f31ea297da71e679d63e1d46e368aff6c5002f689c6d16`

Managed markers: `<!-- axiom-graph:begin -->` and `<!-- axiom-graph:end -->`.
An ownership manifest is `.axiom/agent/bootstrap.lock.json` with
`schema_version` 2, `template_version`, `managed_block_sha256` and
`policy_sha256`. The owned policy file is `.axiom/agent/POLICY.md`.

## Vector matrix

| Vector | Outcome | What it pins |
|---|---|---|
| `lf_new_repo` | append | Empty repository gets block, policy and ownership. |
| `lf_no_markers_human_text` | append | Human LF text is preserved and stays an exact prefix. |
| `crlf_no_markers_human_text` | append | CRLF bytes are preserved; the appended block uses CRLF. |
| `bom_no_markers_human_text` | append | The UTF-8 BOM stays a single leading BOM. |
| `missing_begin_marker` | conflict | A lone end marker must refuse, never truncate. |
| `missing_end_marker` | conflict | A lone begin marker must refuse, never nest a block. |
| `markers_out_of_order` | conflict | An inverted span is refused. |
| `duplicate_markers` | conflict | Two candidate blocks are refused. |
| `edited_managed_block` | conflict | A human edit inside the block is preserved. |
| `edited_policy_file` | conflict | A whole-file owned policy edit is preserved. |
| `unowned_policy` | conflict | An unowned policy file is not overwritten. |
| `managed_policy_missing` | conflict | Removed owned policy is not silently recreated. |
| `unrelated_human_instructions` | unchanged | Re-apply is a no-op outside owned content. |
| `crlf_managed_block_reapply` | replace | Only the owned CRLF span changes. |
| `bom_managed_block_reapply` | replace | BOM and outside bytes survive a replace. |
| `markers_in_fence` | append | Fenced marker examples are not active markers. |

## How the vectors are exercised

`cargo test -p axiom-graphd --locked --test bootstrap_fixtures` copies each
before tree into a temporary directory, runs the managed-merge oracle against it
and asserts the outcome, the exact changed-path set, byte-identical survival of
every other file, the preserved literals, the BOM/newline properties, and for
every conflict vector that the oracle returns a refusal and leaves every file
byte-identical. That refusal assertion is the negative/boundary evidence for
F-008 AC2.
