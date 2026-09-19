# Skills version checks and approved updates

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Task: **E-033**
(`crates/axiom/src/skills/update.rs`). This page describes the intended V2
behavior of the skills check and update surfaces. It is documentation, not
evidence that a compiled `axiom skills check` command exists; **no command is
invoked here.**

## The two rules

> Check is read-only and apply uses an approved component plan; Markdown is not
> claimed to self-update without an executable.

## Check is read-only

`check_skills` reads through `SkillsSource`, which can only report what is
installed, what was published and what a bundle declares. There is no write,
download or process method on that trait, and the report itself records
`read_only = true`. The candidates come from the resolver input of E-038, so
"latest" is never inferred here.

Offline is a distinct, honest outcome. `--offline` returns before the candidate
list is consulted at all, so no reported value can depend on a network call, and
the check reports `offline` rather than guessing "up to date".

## Markdown is not a self-updater

A skills bundle is Markdown plus whatever the manifest authorises. When a bundle
declares no executable entry there is nothing in it that could run an update, so
the report says so:

- `self_update_available = false`
- `update_policy = instructional_bundle_no_self_update`
- `needs_restart = false`

`admit_self_update` refuses a request that treats such a bundle as self-updating
with `self_update_requires_executable`. The bundle is still installable; it just
is not claimed to update itself. A bundle that declares an executable entry
reports `executable_bundle_self_update_supported` and `needs_restart = true`.

## Apply uses the approved component plan

`plan_update` builds the frozen update-plan document for the `skills` component
through the single planner (E-039), never a second plan format. It requires
exactly one component row and that the row is `skills`, refusing
`skills_plan_component_count` or `plan_component_not_skills` otherwise.

`apply_update` admits that document — structure plus an approval whose digest
still matches the plan body — and only then installs the bundle it names,
through the E-032 versioned-directory installer. A plan that is unapproved, or
approved for a different body, is refused as `plan_not_approved` or
`plan_requires_approval`; a bundle that is not the plan's target is refused as
`plan_target_version_mismatch` or `plan_revision_mismatch`. Nothing is written
before those checks pass.

## Refusals

| Rule | Meaning |
|---|---|
| `unexpected_component` | the check constraints do not describe the `skills` component |
| `bundle_manifest_missing` | the selected version has no pinned declaration |
| `no_compatible_release` | the resolver found no compatible candidate |
| `self_update_requires_executable` | a Markdown-only bundle was treated as self-updating |
| `skills_plan_component_count` | the plan input does not carry exactly one component row |
| `plan_component_not_skills` | the plan row is not the skills component |
| `unsupported_component_action` | the row's action is outside the plan contract |
| `plan_not_approved` / `plan_requires_approval` | the plan body is not approved for its current digest |
| `plan_target_version_mismatch` / `plan_revision_mismatch` | the bundle is not the plan's target |

## What is not implemented

The check and the apply path are policy over injected inputs and a small
filesystem trait. Nothing here opens a socket, drains a real service or runs a
bundle script. The `axiom skills version/check/update` command lines are a
separate, still-pending slice.