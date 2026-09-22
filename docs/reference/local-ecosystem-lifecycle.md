# Local ecosystem lifecycle (ADR-0014 draft)

The engine owns `$AXIOM_HOME/installs/ecosystem/current`, immutable versioned
payloads and their activation journals. Distribution `installed.json` is a
separate delivery record; it is not authority to delete engine files or change
the running daemon.

`axiom uninstall plan --out plan.json` reviews recorded core and skill bundle
files. `axiom uninstall apply --plan plan.json --approve-digest <digest>`
revalidates approval and ownership, removes the owned service first, then removes
only unchanged recorded runtime files. Edited and undeclared files survive.
Source, annotations, checkpoints, credentials and workspace instructions survive.
Activation journals, skill manifests and uninstall reports remain as recovery
evidence. The same approved transaction can be retried after interruption.

The service interface operates the canonical per-user LaunchAgent label
`com.axiom.axiom-graphd` on macOS. Its owned record includes the effective UID,
exact definition hash and active pointer hash. Foreign definitions or labels
are refused. Registration injects the scoped AXIOM_HOME into the daemon.
Service mutation and installation/removal share the maintenance lock.

The local update entrypoint is `axiom update plan --to <exact-version>
--bundle <directory> --out <plan.json>`. Apply requires its outer digest, which
binds the inner verified ecosystem plan and prior active state. Update and
rollback operate the engine pointer and coordinate an existing owned service.
`axiom update rollback --transaction <id>` addresses a recorded transaction,
not an arbitrary path. Retained payload hashes are verified before restoration.

These are feature-branch development interfaces. Native evidence under
`evidence/local-lifecycle-20260922/` states which executions actually passed.
Local unsigned development artifacts are not released-core certification.
