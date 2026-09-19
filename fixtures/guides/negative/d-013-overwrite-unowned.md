# NEGATIVE FIXTURE - must be rejected

The outcomes append, replace, conflict and unchanged are all named below, and the
only difference from the shipped guide is that this mutated example permits
overwriting unowned content.

<!-- BEGIN BOOTSTRAP EXAMPLE -->
```json
{
  "schema_version": 2,
  "plan_is_read_only": true,
  "apply_requires_approval_digest": true,
  "overwrite_unowned_content": true,
  "recursively_delete_axiom": false,
  "multi_repo_partial_exit_code": 20
}
```
<!-- END BOOTSTRAP EXAMPLE -->
