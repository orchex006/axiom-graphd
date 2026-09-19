# NEGATIVE FIXTURE - must be rejected

Every component needs a check route, an update route and a trust requirement, but
this mutated example accepts a blind branch pull as an update route.

<!-- BEGIN UPDATE EXAMPLE -->
```json
{
  "schema_version": 2,
  "auto_check_default": true,
  "auto_apply_default": false,
  "check_uses_jitter": true,
  "offline_flag_performs_network": false,
  "git_pull_then_execute": true,
  "unsigned_auto_install": false,
  "approval_digest_required": true,
  "checksum_alone_proves_publisher": false,
  "supporting_schema_major": 1,
  "components": ["axiom-graphd", "axiom-mcp", "axiom", "skills"],
  "plan_digest_excludes": ["plan_digest", "approval"]
}
```
<!-- END UPDATE EXAMPLE -->
