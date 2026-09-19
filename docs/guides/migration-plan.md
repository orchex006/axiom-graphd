# Migration plan and approval binding (V2-010)

`crates/migration` turns a V1 to V2 discovery decision into one reviewable plan
and refuses to apply a plan whose inputs moved underneath it. This guide is the
operator-facing summary; the normative rules live in
`axiom-specs/migrations/V1-TO-V2.md` sections 2 and 3 and
`axiom-specs/contracts/cross-platform-v2.md` CP-03.

## The two halves

- `crate::discover` (V2-009) decides *whether* a migration may run at all. It
  detects the legacy `graph` and `grahp` layouts independently and returns
  `MIGRATION_CONFLICT` instead of a decision when the sources cannot be resolved.
- `crate::plan` (V2-010) turns one decision into a plan. It inventories the
  exact bytes it was built from, seals them into one digest, and refuses to apply
  anything unless that digest was approved and those bytes are still the bytes on
  disk.

Neither half touches a filesystem. The adapter observes hashes and performs the
writes; the modules decide.

## Approving a plan

The plan digest is an *approval binding*, not publisher authentication. A
reviewer approves a digest, not a file name and not a timestamp:

1. Build the plan for the solution.
2. Read `plan.digest()`.
3. Apply with that exact digest.

`plan.apply(reviewed_digest, observed, now_seconds)` then refuses, in the order a
reviewer can act on:

| Refusal | Code | Meaning |
| --- | --- | --- |
| approval | `MIGRATION_PLAN_APPROVAL_MISMATCH` | the reviewed digest is not this plan's digest |
| conflict | `MIGRATION_CONFLICT` | an unresolved conflict is still recorded |
| expiry | `MIGRATION_PLAN_EXPIRED` | `now_seconds` is at or past the declared expiry |
| staleness | `MIGRATION_PLAN_STALE` | a source changed, disappeared, or a new source appeared |

A plan that changes any input — a source hash, a size, a decision, a preserved
block, an added conflict, the solution id, the creation time or the lifetime —
has a different digest, so a stale approval can never silently apply.

## Preserving human text

Human text is carried as preserved text, never as a change. Each block records
its path, its ownership hash and the marker pair it came from, and its reason is
either `proven-ownership-hash` (the V1-TO-V2 section 3 mechanism) or
`explicit-human-review`. A path cannot be both preserved and changed: adding one
after the other is refused as `MIGRATION_PLAN_UNRESOLVED_CHANGE`, so the plan
cannot pick a winner on the operator's behalf.

## What the plan refuses to guess

- `Regenerate` must not name a source; `Create` must name one and must not claim
  previous bytes; `Replace` must name one and must record the previous bytes.
- A human-owned destination is never changed.
- A change whose source is not in the same repository slice is unresolved.
- A repeated path inside one section is `MIGRATION_PLAN_DUPLICATE_PATH`.
- A value that is not 64 lowercase hex characters is
  `MIGRATION_PLAN_INVALID_HASH`; a path or slug that is not portable is refused
  through the shared `PathKey` policy (`UNSAFE_PORTABLE_PATH`).

## Not implemented here

The `axiom migrate plan|apply|verify|rollback` CLI verbs from
`migrations/V1-TO-V2.md` section 2 and real cutover execution are separate work.
This slice implements the plan document, its digest, its validation and its
apply-time refusals.
