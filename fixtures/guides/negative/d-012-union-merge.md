# NEGATIVE FIXTURE - must be rejected

This file is not a guide. It is a mutated copy of the D-012 worked example that
the guide-contract driver in `fixtures/guides/driver.py` must reject. The prose
still names live ignored data, the staged export and merged-source regeneration,
so the only difference from the shipped guide is the mutated field below.

<!-- BEGIN GIT CHECKPOINT EXAMPLE -->
```json
{
  "schema_version": 2,
  "default_source": "staged",
  "worktree_requires_stability_certificate": true,
  "checkpoint_export_requires_explicit_command": true,
  "input_classes": ["partial-staging", "rename", "merge", "untracked"],
  "boundary_input_classes": ["rename-without-content-change", "staged-then-deleted"],
  "union_merge_generated_graphs": true,
  "hand_pick_graph_sides_after_merge": false
}
```
<!-- END GIT CHECKPOINT EXAMPLE -->
