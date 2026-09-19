# Installing versioned skill bundles

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Task: **E-032**
(`crates/axiom/src/skills/install.rs`). This page describes the intended V2
behavior of the skills installer. It is documentation, not evidence that a
compiled `axiom skills update apply` command exists; **no command is invoked
here.**

## The one rule

> Only validated declared skill paths are installed; unexpected executable files
> require explicit capability review.

A skills bundle is a versioned directory described by a reviewed manifest
(`bundle.json`). The installer never copies "whatever is in the package": it
installs exactly the files the manifest declares, and it refuses a file the
manifest did not declare. When the undeclared file can run code, the refusal is
named `unexpected_executable_capability_review_required` rather than being
folded into the generic undeclared-file case, because an executable is a
capability decision and not a packaging detail.

## The three steps

1. **Declare.** `SkillBundle::validate` validates the manifest: every path is a
   portable repository-relative path (through `graph_core::paths`, the one
   portability policy), every digest and size is usable, no path is declared
   twice, and an entry that can run code — `kind = "script"`, or an executable
   suffix such as `.sh` / `.ps1` / `.py` — must carry a non-empty capability
   review drawn from `read`, `write`, `execute`.
2. **Plan.** `plan_install` validates the staged payload against the
   declaration before a byte is written. A declared file that is missing, short
   or altered is named (`declared_file_missing`,
   `declared_file_size_mismatch`, `declared_file_hash_mismatch`); an undeclared
   non-executable is `undeclared_file`; an undeclared executable is
   `unexpected_executable_capability_review_required`.
3. **Install.** `install(plan, source, fs)` reads each planned file's staged
   bytes back from the payload source, re-verifies them against the plan
   (`staged_file_changed_since_plan`), and writes them into `skills/<version>/`.
   The install root is the only thing it mutates. It writes the reviewed
   manifest last inside that version directory, and only then replaces the
   `skills/current` pointer through a temporary sibling (`skills/current.next`). A crash before the pointer move therefore leaves the
   previous bundle active. An existing version directory is refused
   (`version_directory_exists`) because a built version is immutable.

## Capability review

`CAPABILITIES` is an allowlist, not a menu: `read`, `write`, `execute`. A bundle
cannot invent a capability that a host adapter would then have to interpret for
itself (`capability_not_reviewed`). Declaring an executable suffix under a
non-script `kind` is refused (`executable_kind_required`), so a `.sh` file can
never arrive labelled as an "instruction".

## Refusals

| Rule | Meaning |
|---|---|
| `manifest_schema_unsupported` | the manifest schema version is not this build's |
| `unexpected_component` | the manifest does not describe the `skills` component |
| `invalid_version` / `revision_not_pinned` / `spec_revision_not_pinned` | the version or a revision is unusable or unpinned |
| `unsafe_skill_path` | the path is not portable (absolute, drive, UNC, `..`) |
| `skill_path_shape_not_declared` | the path is not a two-segment `skill/file.ext` shape |
| `unsupported_entry_kind` | the kind is not `instruction`/`reference`/`asset`/`script` |
| `executable_kind_required` | an executable suffix was declared as a non-script |
| `capability_review_required` / `capability_not_reviewed` | an executable has no allow-listed capability review |
| `entry_digest_invalid` / `entry_too_large` / `bundle_empty` / `too_many_entries` / `duplicate_skill_path` | the declaration itself is unusable |
| `undeclared_file` / `unexpected_executable_capability_review_required` | the payload contains a file the manifest did not declare |
| `version_directory_exists` | the target version was already built |
| `staged_file_changed_since_plan` | a staged byte moved between planning and writing |

## What is not implemented

The installer is policy over an injected `PayloadSource` and `InstallFs`. The
only filesystem writer is the production `LocalInstallFs`, rooted at the install
root. Nothing here downloads a bundle, contacts a network, spawns a process or
executes a script: an entry declared as a script is *installed*, never run. The
`axiom skills update apply` command line is a separate, still-pending slice.