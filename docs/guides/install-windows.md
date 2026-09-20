# Windows first-install runbook

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Implementation/release evidence is not implied.

This runbook is the Windows x64 first-install procedure for the Axiom Graph
Ecosystem core release (`axiom-graphd` daemon plus `axiom` operations CLI). It is
a target contract with per-step availability, not a record of a completed
install: this repository currently contains no released artifact (`VERSION` is
`0.0.0-dev`), no installer, no installer CLI crate and no Windows
install/run/uninstall evidence. Commands and per-command exit codes are
single-sourced in [reference/axiom-graphd](../reference/axiom-graphd.md); the frozen
process exit table is single-sourced in [CLI-EXIT-CODES](../CLI-EXIT-CODES.md).

Do not read a `pending` row below as "runs with a warning"; it means the step has
no implementation in the pinned revision and cannot be executed at all.

## 1. Step availability

<!-- BEGIN RUNBOOK STATUS -->
| Step | State | Reason |
| ---- | ----- | ------ |
| 1 Prerequisites | available | Read-only checklist; nothing is executed. |
| 2 Approved release and trust setup | pending | No signed release archive exists; `axiom install` has no implementation in this build. |
| 3 Install the core release | pending | No installer, no archive and no `crates/axiom` crate exist in the pinned revision. |
| 4 Machine-local state and bindings | pending | `AXIOM_HOME` resolution exists in `graph-core`; the registry/binding commands (`status`, `solution`) are wired into argv and answer `NOT_READY` (exit 4) without reading or writing state. |
| 5 Opt-in user service | pending | No service adapter, registration or native lifecycle evidence exists. |
| 6 MCP handshake | pending | `axiom-mcp` is a separate repository and no handshake evidence exists for this host. |
| 7 First-run smoke test | pending | The daemon cannot serve: `serve` reports `NOT_READY`. |
| 8 Uninstall and uninstall verification | pending | No service registration or owned-file manifest exists to remove. |
<!-- END RUNBOOK STATUS -->

A step is `available` only when it is a read-only instruction. No row in this
runbook is `available` as an executable operation, because no binary artifact is
distributed with this revision.

## 2. Prerequisites

| Item | Requirement | Notes |
| ---- | ----------- | ----- |
| OS | Windows 11 x64 | `windows-x64` (`x86_64-pc-windows-msvc`) is a required release target in [release/build-matrix.md](../../release/build-matrix.md). No target is certified yet. |
| Privilege | Standard user | The default install, state and startup registration are per-user. No administrator elevation is required, and none may be requested by a step in this runbook. |
| Shell | PowerShell 5.1 or PowerShell 7 | The call operator `&` invokes an absolute executable path; no shell string is interpolated into an Axiom command. |
| Storage | Local fixed NTFS volume | Mutable state must be on a local disk. UNC/SMB shares, cloud-synchronised folders (OneDrive, Dropbox, Google Drive, iCloud, SharePoint) and Windows device paths are refused by the state-home policy in `crates/graph-core/src/paths.rs`. |
| Git | Optional | Required only for Git checkpoint and staged-source snapshot features, not for install or read-only query. |
| Rust toolchain | Not required | An end user consumes a prebuilt archive. Only a developer building the workspace needs the pinned toolchain from `rust-toolchain.toml`. |
| Python | Not required for the daemon | The optional MCP gateway is a separate component with its own locked environment. |
| WSL, Docker, Bash | Not required | Core operations must not depend on them. |

Path guidance that matters on Windows:

- Prefer a short checkout path. Long-path behaviour depends on the actual API
  and application, so a short path is a documented fallback rather than a
  guarantee, and machine-wide registry policy is never changed silently.
- Keep source roots inside the registered solution. Output paths are fixed
  relative locations beneath a registered repository; absolute or
  drive-prefixed payload paths are rejected.
- `AXIOM_HOME` must be an absolute path on a supported local filesystem.
  A relative override is rejected.

## 3. Approved release and trust setup

Target procedure (Step 2, `pending`). No step below was executed.

1. Choose the release owner/repository and trust root from the organisation the
   installation is actually for, and record that trusted-source configuration in
   operator documentation you control.
2. Download the `axiom-<version>-windows-x64.zip` bootstrap archive from that
   trusted release.
3. Verify the archive checksum and signature against the known root **before**
   executing anything from it. An offline verification procedure is required,
   because an installer that can only verify online cannot be trusted to verify.
4. Keep the extracted versioned directory and retain at least the previous
   working version for rollback.

Refusals that are contract, not preference:

- `curl | Invoke-Expression` (or any `curl | sh` shape) is never the default or
  documented runbook.
- Do not disable SmartScreen, antivirus, Device Guard or any other protection to
  make installation succeed. Signing and trust verification must satisfy
  distribution policy rather than bypass it.
- Do not lower a machine-wide PowerShell execution policy as a prerequisite.
- No machine-wide service and no elevation: an organisation policy that denies
  user-logon task creation is reported, not worked around by requesting
  administrator privilege automatically.

## 4. Install the core release

Target procedure (Step 3, `pending`). The installer CLI is not part of this
revision; see [reference/axiom-graphd](../reference/axiom-graphd.md) for the
availability table.

```text
axiom install plan  --bundle <verified-local-bundle> --out install-plan.json
axiom install apply --plan install-plan.json
```

- Install into a versioned directory under the user state home
  (`AXIOM_HOME/installs/<component>/<version>/`) and activate through a
  validated manifest/launcher, not a symlink-only active-version switch.
- Review the plan before applying it: component versions, OS paths, service
  changes, required permissions and planned network access.
- A global `PATH` change is never a prerequisite. Invoke the program by absolute
  path, for example `& "$env:LOCALAPPDATA\Axiom\...\axiom-graphd.exe" version`.
- A running core executable is never overwritten in place: install, drain,
  activate, verify, keep the rollback version.

## 5. Machine-local state and bindings

Target procedure (Step 4, `pending`). The state home and layout below are
implemented; the registry/binding commands (`status`, `solution`) are wired into
argv in this revision, but they answer `NOT_READY` (exit 4) and read or write no
binding.

Default state home on Windows:

```text
%LOCALAPPDATA%\Axiom
```

Override with an absolute `AXIOM_HOME`. The layout is fixed:

```text
AXIOM_HOME/
  config/registry.json
  instances/<local-instance-id>/index.sqlite
  instances/<local-instance-id>/solution.guard
  run/daemon.lock
  run/control.json
  secrets/
  installs/<component>/<version>/
  update-journal/
  logs/
```

- `config/registry.json` is the machine-local registry and holds the absolute
  checkout paths. Give it owner-only permissions; it is deliberately outside
  Git.
- Bindings are machine-local. Commit logical project IDs and repo-relative
  `/`-separated paths to `.axiom` files; never commit absolute checkout paths,
  SQLite files, credentials or tokens.
- Bind each logical repo ID to a native absolute checkout path through local
  bindings. A missing root is not auto-cloned; it is reported.
- Registration previews every root, output path, excluded path, profile and
  cross-project alias. The command shape for the intended revision is:

```text
axiom-graphd solution register --config solution.yaml --bindings bindings.json --dry-run
axiom-graphd solution register --config solution.yaml --bindings bindings.json --apply
axiom-graphd solution list --json
```

`solution` is not a command this build accepts; see the availability table in
[reference/axiom-graphd](../reference/axiom-graphd.md).

## 6. Opt-in user service

Target procedure (Step 5, `pending`). No service adapter exists in this
revision.

- Windows managed integration is a **current-user Scheduled Task at logon**. It
  is opt-in: no startup registration happens merely because indexing is enabled.
- The wrapper must use an absolute executable path plus argv with an explicit
  working directory. Never depend on a login-shell `PATH`.
- The adapter must implement install, status, start, stop, restart and uninstall,
  with restart backoff, log capture, migration of its own registration, and a
  tested non-admin denial path.
- Foreground mode is the baseline and must keep working without any managed
  service. A machine-wide service or a background run without a signed-in user
  is out of baseline and requires separate explicit approval.

## 7. MCP handshake

Target procedure (Step 6, `pending`). The MCP gateway (`axiom-mcp`) is owned by
a different repository; this runbook only records the handshake expectations.

- Bind loopback only (`127.0.0.1`, or an explicitly chosen IPv6 loopback).
  Wildcard binding is rejected.
- `--host 127.0.0.1 --port 8766` is the documented HTTP shape; stdio mode uses
  the same service contract and keeps stdout protocol-only with diagnostics on
  stderr.
- Credentials are scoped and separate from daemon-control authority. Never place
  a token in a portable config, a command line or a log.
- Handshake verification is a bounded query against a registered solution after
  `version` and `doctor` report a ready daemon. A mocked host handshake is not
  host certification.

## 8. First-run smoke test

Target procedure (Step 7, `pending`). The following invocations are the only CLI
surface this revision implements, and `serve` cannot yet serve:

```powershell
& "<install-dir>\axiom-graphd.exe" version --json
& "<install-dir>\axiom-graphd.exe" doctor --json
& "<install-dir>\axiom-graphd.exe" serve --registry "<AXIOM_HOME>\config\registry.json"
```

Expected today, from the implemented code path (not a captured run): `version
--json` prints the frozen version report plus runtime facts and exits `0`;
`doctor` exits `4` (`NOT_READY`) with the reason that the diagnostic inventory is
implemented by a later work package; `serve` takes the single-owner instance
lock, records that the reconcile worker loop is not part of this work package and
exits `4`. See [reference/axiom-graphd](../reference/axiom-graphd.md) for the exact
per-command contract.

## 9. Uninstall and uninstall verification

Target procedure (Step 8, `pending`).

- Default uninstall removes only owned executables and owned startup entries.
- Default uninstall **preserves** project source, annotations, checkpoint JSON,
  human instruction text and private state. Deleting state, credentials or the
  database cache requires separate explicit approval.
- Revoke or securely delete credentials according to OS policy. Never remove
  another host's plugins or MCP servers.
- Keep the uninstall report, and never recursively delete `.axiom` or a
  `.agrimap-agent` tree.

Verification of an uninstall is a positive/negative pair: the owned executable
and startup entry are gone, and the preserved categories above are byte-identical
to their pre-uninstall state.

## 10. Failure and recovery

| Symptom | Likely cause | Safe action |
| ------- | ------------ | ----------- |
| Archive checksum or signature mismatch | Tampered, truncated or wrong-owner artifact | Stop. Do not extract or execute. Re-obtain from the trusted source. |
| `UNSAFE_HOME_PATH` (exit 2) | Relative, remote, cloud-synchronised or device `AXIOM_HOME` | Point `AXIOM_HOME` at an absolute path on a local fixed volume. |
| `CONFIG_INVALID` (exit 2) | Registry or config rejected | Fix the named field; do not delete the database to silence it. |
| `WRITER_ALREADY_RUNNING` (exit 10) | Another owner holds `run/daemon.lock` | Find the owning process; never delete the lock by guess. |
| `NOT_READY` (exit 4) | Requested capability not implemented in this build | Use the documented foreground/read-only path or wait for the owning work package. |
| Task creation denied | Organisation policy | Report it and stay in foreground mode. Do not request machine-wide privilege automatically. |
| `PUBLISH_BLOCKED`-style sharing violation on publication | Open reader, antivirus or file handle | Bounded retry, close the offending reader. Never delete the current generation first. |

## 11. What is verified, and what is not

- Verified in this revision: the state-home default and layout, the storage
  classification of Windows paths, and the frozen exit/error tables, all by the
  repository's own unit tests and documented in
  [CLI-EXIT-CODES](../CLI-EXIT-CODES.md) and
  [reference/axiom-graphd](../reference/axiom-graphd.md).
- **Not verified:** every installation, trust-verification, service, MCP
  handshake and uninstall step in this runbook. No archive, signature, service,
  process or host handshake was exercised on any Windows host for this
  document. No Windows target is certified.
- The commands in sections 4, 5, 6 and 9 are documentation of an intended
  contract for a later work package; they are not accepted by any binary in this
  revision, except the `axiom-graphd solution` shape, which task H-001 wired into
  argv so it is accepted and then refused with `NOT_READY` (exit 4).

## 12. Related documents

- [reference/axiom-graphd](../reference/axiom-graphd.md) - commands, arguments,
  exit codes and failure recovery.
- [CLI-EXIT-CODES](../CLI-EXIT-CODES.md) - the frozen exit-code and error-code
  tables.
- [../21-INSTALLATION](../21-INSTALLATION.md) - the installation contract and
  its current status.
- [../21-INSTALLATION-QUICKSTART](../21-INSTALLATION-QUICKSTART.md) - the short
  native installation and quick-start contract.
- [../22-OPERATIONS-AND-TROUBLESHOOTING](../22-OPERATIONS-AND-TROUBLESHOOTING.md)
  - operations and recovery.
- [install-linux](install-linux.md) and [install-macos](install-macos.md) - the
  sibling platform runbooks.
