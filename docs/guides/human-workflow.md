# Human editing and reconciliation

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. This guide describes the
intended V2 behavior of the engine. It is documentation, not evidence that a
compiled daemon, installer or service exists.

## 1. The rule that decides everything else

A filesystem event is a *hint*, never the truth
(`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 9). The daemon decides
what changed by comparing its recorded inventory, not by trusting what an
editor, a formatter or an operating system told it. The practical consequence
for a human is simple: **save your work and stop thinking about the graph.**
There is no per-file submit step, no "reconcile this file" button and no
requirement to touch every changed path by hand.

## 2. An ordinary save

An editor writes a file in whatever way it likes: one atomic replace, several
truncate-and-write passes, or a burst of saves while you keep typing. The
watcher turns those events into hints, and the debouncer coalesces them:

- repeated saves of the *same* path produce **one** reconciliation entry, not
  one per save;
- paths changed in the same burst are released together as **one** batch;
- the batch waits for a short quiet period, but never longer than the hard
  maximum wait, so continuous typing cannot postpone reconciliation forever.

A batch is released either because the burst went quiet (`quiet_period`) or
because the oldest pending path reached the maximum wait (`maximum_wait`). Both
are normal and neither requires operator action.

## 3. Renames, including case-only renames

A rename is reported as one removal of the old path and one upsert of the new
path, with the previous path retained as the upsert's `origin`. On Windows a
case-only rename (`src/App.cs` -> `src/app.cs`) is detected as a rename of the
same file rather than as an unrelated delete plus create, so references are
re-pointed instead of dropped. On a case-sensitive filesystem the same two
events are genuinely two paths, and the guide's example records that boundary.

## 4. Formatter and generated output

Formatters, code generators and the daemon itself write files. Those writes are
never treated as input:

- the project-relative generated output root (default `live`) is excluded as
  `generated_graph_data`;
- build directories (`bin/`, `obj/`), dependency caches (`node_modules/`), Git
  metadata, queue state, database files and editor scratch files are excluded by
  their own rules;
- a secret file is not parsed even when it sits inside a tracked root.

So running a formatter, or letting the daemon publish a generation, does not
requeue the work it just wrote.

## 5. Edits made while the daemon was not running

Offline edits are the normal case for a laptop that was closed, a container that
was stopped or a machine that was rebooted. They are found by a complete
inventory scan at startup, not by replaying events that were never delivered:

- the startup inventory walks the bound root and records a digest per candidate
  path;
- a path whose digest differs is reported as modified, a path that appeared is
  created, and a path that is gone is removed;
- a first poll of the polling backend establishes a baseline and reports **no**
  changes, because it cannot honestly claim a difference it has not seen.

You do not have to re-save, touch or `git add` a file you edited while the
daemon was down.

## 6. Polling is the declared fallback

Native recursive events are preferred, but they are optional. The configured
policy decides what happens when the host cannot provide them:

| Policy | Native available | Result |
|---|---|---|
| `prefer_native` | yes | native events |
| `prefer_native` | no | polling, with the reason the host gave |
| `force_polling` | either | polling, with the forcing reason |
| `require_native` | no | refused with `NOT_READY`; the daemon does not start |

Polling compares successive snapshots of size and modification time, so it
observes the same create/modify/remove classes as the native backend. It is
slower to notice a change but needs nothing from the host, which is exactly why
it is the fallback rather than an error.

## 7. Worked example

The example below is a single editing session as the engine models it. It is
read by `crates/axiom-graphd/tests/human_workflow_guide.rs`, which replays each
field through the real debouncer, the real normalization, the real ignore
policy, the real polling watcher and the real backend selector.

<!-- BEGIN HUMAN WORKFLOW EXAMPLE -->
```json
{
  "schema_version": 2,
  "session_id": "demo-session",
  "debounce_ms": 250,
  "max_wait_ms": 2000,
  "save_burst": ["src/App.cs", "src/Widget.cs", "src/App.cs", "src/App.cs", "src/Widget.cs"],
  "rename": { "from": "src/Old.cs", "to": "src/New.cs" },
  "case_only_rename": { "from": "src/App.cs", "to": "src/app.cs" },
  "generated_output_root": "live",
  "formatter_writes": ["live/generations/shard-0000.json", "src/App.cs"],
  "offline_edits": {
    "modified": ["src/App.cs"],
    "created": ["src/Added.cs"],
    "removed": ["src/Removed.cs"]
  },
  "backend_preference": "prefer_native",
  "manual_file_submissions_required": 0
}
```
<!-- END HUMAN WORKFLOW EXAMPLE -->

The five saves in `save_burst` touch two distinct paths, so the session produces
one batch of two paths. The rename produces one removal and one upsert. The
formatter's write under `live/` is ignored while its write to `src/App.cs` is a
tracked source path. The offline edits are discovered by the inventory poll. No
field requires the user to submit a file.

## 8. Guarantees and refusals

| Situation | Result |
|---|---|
| Several saves of one path in one burst | one reconciliation entry, not one per save |
| Paths changed together | one released batch |
| Continuous typing | batch still released at the maximum wait |
| Ordinary rename | one removal (old) plus one upsert (new) carrying the origin |
| Case-only rename on Windows | detected as a rename of the same file |
| Formatter or daemon write under the generated output root | ignored as `generated_graph_data` |
| Edits made while the daemon was stopped | discovered by the startup inventory |
| First poll of the polling backend | baseline only; no change claimed |
| `require_native` on a host without native events | refused with `NOT_READY` |
| Reported path that is absolute, `..`, or otherwise non-portable | refused with `VALIDATION_ERROR`, never rewritten |

## 9. Status and limits

The debouncer, normalization, ignore policy, polling watcher, backend selector
and inventory planner described here are implemented in `graph-watch`. The
daemon wiring that consumes them, the installer and the service lifecycle are
separate graphd tasks; until they ship, this guide documents the intended
workflow and the invariants the engine already enforces. See
`docs/WATCHER-QUEUE-AND-ANALYSIS.md` for the module map and
`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` for the durable-state contract.
