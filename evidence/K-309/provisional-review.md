# K-309 Windows owner review — in progress

Historical first candidate only. The final owner candidate and review are in
`final-4f/`; this file records the earlier source revision and its discovery
work without changing those bytes.

Source revision: `6223daa59e0bcc0f3c5312c1801fbd5a5783aa34` on
`feature/k-309-windows-service-core`. The unsigned core archive in this
directory has SHA-256
`e306718098f2ee66fe59412f182d14869021ef42c3e1c668cfe6551911b03a21`.
It is a local candidate, not a published release. The checked-out source was
independently repackaged from a clean worktree with identical archive, manifest
and SBOM bytes. `release/verify_core_candidate.py` passed after its first
temporary-directory cleanup encountered a transient Windows file lock.

Scoped format, clippy, Windows service, engine update, full `axiom-graphd`
crate, package regression, core manifest and spec pin checks passed. Their
actual command outputs are alongside this file. The packaged native real-source
C# fixture passed graph, query and watcher checks in `real-source-report.json`.

The exact packaged daemon and CLI binaries were used in a separate native
Windows 11 x64 Task Scheduler run under
`goals/run-logs/K-309/native-package-6223`. Public `axiom service install`
registered a per-user task with `RunLevel=Limited` and an explicit
`serve --axiom-home` action. Public start/status reported Running. The daemon
held the writer guard and published a C# graph: queries for
`Demo.TokenSource` and, after a source edit, `Demo.WatcherAdded` succeeded.
Idempotent install returned `already_registered`. Public stop/uninstall
removed the task, owned state and definition; the user-data sentinel remained.
The final process check found no `axiom-graphd` process. An initial watcher
probe used the unqualified symbol `WatcherAdded` and returned NOT_FOUND;
the qualified query and graph output verified the updated symbol. The native
run occurred only after moving 43.9 MB of prior agent-owned pytest scratch
from full C: to `goals/run-logs/K-309/quarantined-temp` on D:; no unrelated
user data was removed.

The exact packaged-binary rerun refused a changed definition on `service
status`, missing ownership with an existing task on both install and
uninstall, and stale active generation on start. Each returned `CONFLICT`
(exit 6) without replacing or removing the task. Disabling the registered
Scheduled Task changed its exported fingerprint; `service status` returned
`CONFLICT` (exit 6). Re-enabling it restored the exact export XML and owned
status/uninstall succeeded. Replacing the owner SID with a different valid SID
made `service status` return `FORBIDDEN` (exit 5). Original bytes were restored
from local backups before owned uninstall, which left no task or graphd
process and preserved user data. The replay output is retained in
`native-refusal-transcript.txt` (SHA-256
`c059c254a5fb592b96b7ff79fe774af964bd1f26e3e714db51dffe4efc64eeb5`).
Graphd-owned native service update/restart and
rollback remain unverified. Therefore K-309
stays `in_progress`; do not hand this archive to K-010 as a final accepted
service candidate. K-010 and released-fixture K-601/K-602 remain open.
