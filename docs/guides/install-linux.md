# Linux first-install runbook

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Implementation/release evidence is not implied.

This runbook is the Linux x64 first-install procedure for the Axiom Graph
Ecosystem core release (`axiom-graphd` daemon plus `axiom` operations CLI). It is
a target contract with per-step availability, not a record of a completed
install: this repository currently contains no released artifact (`VERSION` is
`0.0.0-dev`), no installer, no installer CLI crate and no Linux
install/run/uninstall evidence. Commands and per-command exit codes are
single-sourced in [reference/axiom-graphd](../reference/axiom-graphd.md); the frozen
process exit table is single-sourced in [CLI-EXIT-CODES](../CLI-EXIT-CODES.md).

Every step is per-user. **No step in this runbook requires `sudo`, `root`, a
setuid helper, or write access to a system-owned directory such as `/usr`,
`/opt` or `/etc`.**

## 1. Step availability

<!-- BEGIN RUNBOOK STATUS -->
| Step | State | Reason |
| ---- | ----- | ------ |
| 1 Prerequisites | available | Read-only checklist; nothing is executed. |
| 2 Approved release and trust setup | pending | No signed release archive exists; `axiom install` has no implementation in this build. |
| 3 Install the core release | pending | No installer, no archive and no `crates/axiom` crate exist in the pinned revision. |
| 4 Machine-local state and bindings | pending | `AXIOM_HOME` resolution exists in `graph-core`, but the registry/binding commands are not wired into argv. |
| 5 User-service detection and foreground fallback | pending | No service adapter, unit template or detection probe exists in this build. |
| 6 MCP handshake | pending | `axiom-mcp` is a separate repository and no handshake evidence exists for this host. |
| 7 First-run smoke test | pending | The daemon cannot serve: `serve` reports `NOT_READY`. |
| 8 Uninstall and uninstall verification | pending | No service registration or owned-file manifest exists to remove. |
<!-- END RUNBOOK STATUS -->

## 2. Prerequisites

| Item | Requirement | Notes |
| ---- | ----------- | ----- |
| OS | Linux x64, glibc | `linux-x64` (`x86_64-unknown-linux-gnu`) is a required release target with a reference baseline of Ubuntu 24.04 LTS. No target is certified yet. |
| Privilege | Ordinary user account | Everything is per-user. A step that would need root is a defect in the step, not a missing prerequisite. |
| Shell | POSIX `sh` or Bash | Shell snippets illustrate invocation only. Core logic never lives in a shell script alone. |
| Storage | Local fixed filesystem | Mutable state must be on a local disk; network mounts and cloud-synchronised directories are refused by the state-home policy in `crates/graph-core/src/paths.rs`. |
| systemd | Optional | Managed user service uses `systemd --user` **when it is available**. A distribution without systemd remains fully usable in foreground mode; "managed service unavailable" is not "platform unsupported". |
| Git | Optional | Required only for Git checkpoint and staged-source snapshot features. |
| Rust toolchain | Not required | An end user consumes a prebuilt archive. Only a developer building the workspace needs the pinned toolchain from `rust-toolchain.toml`. |
| Python | Not required for the daemon | The optional MCP gateway is a separate component with its own locked environment. |
| Bash, WSL, Docker | Not required | Core operations must not depend on them. |

## 3. Approved release and trust setup

Target procedure (Step 2, `pending`). No step below was executed.

1. Choose the release owner/repository and trust root from the organisation the
   installation is actually for, and record that trusted-source configuration in
   operator documentation you control.
2. Download the `axiom-<version>-linux-x64.tar.gz` bootstrap archive from that
   trusted release.
3. Verify the archive checksum and signature against the known root **before**
   extracting or executing anything from it, and make sure the verification
   procedure works offline. Verify the archive is not extracted with a
   layout-escaping path (Zip-Slip / `../` archive entries).
4. Extract to a user-writable directory and keep at least the previous working
   version for rollback. Executable permission bits are preserved by the archive;
   do not add a global `PATH` entry, and do not `chmod` a system directory.

Refusals that are contract, not preference:

- `curl | sh` is never the default or documented runbook.
- Do not `sudo` an installer, and do not claim a package manager will place
  files in a system-owned directory.
- Do not disable or bypass distribution protections to make installation
  succeed.

## 4. Install the core release

Target procedure (Step 3, `pending`). The installer CLI is not part of this
revision; see [reference/axiom-graphd](../reference/axiom-graphd.md).

```text
axiom install plan  --bundle <verified-local-bundle> --out install-plan.json
axiom install apply --plan install-plan.json
```

- Install into a versioned directory under the user state home
  (`AXIOM_HOME/installs/<component>/<version>/`) and activate through a
  validated manifest/launcher, not a symlink-only active-version switch.
- Review the plan before applying it: component versions, OS paths, service
  changes, required permissions and planned network access.
- Invoke the program by absolute or `./` path, for example
  `"$HOME/.local/state/axiom/installs/axiom-graphd/<version>/axiom-graphd" version`.
- A running core executable is never overwritten in place: install, drain,
  activate, verify, keep the rollback version.

## 5. Machine-local state and bindings

Target procedure (Step 4, `pending`). The state home and layout below are
implemented; the registry/binding commands are not wired into argv in this
revision.

Default state home on Linux:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/axiom
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

- `config/registry.json` holds the absolute checkout paths and is machine-local.
  Give it owner-only permissions (`0700` on the directory, `0600` on the file)
  and keep it out of Git.
- Permissions are checked as real ownership and mode bits on the filesystem, not
  as a string prefix. Do not place state in a world-writable location, and do not
  `chmod 777` anything to work around a denial.
- Bindings are machine-local: commit logical project IDs and repo-relative
  `/`-separated paths to `.axiom` files; never commit absolute checkout paths,
  SQLite files, credentials or tokens.
- A missing registered root is reported, never auto-cloned.

## 6. User-service detection and foreground fallback

Target procedure (Step 5, `pending`). No probe or unit template exists in this
revision; the decision procedure below is the contract the adapter must satisfy.

Detect managed-service availability without assuming it:

1. `systemctl --user` is present **and** a user D-Bus session is reachable
   (`XDG_RUNTIME_DIR` set, `DBUS_SESSION_BUS_ADDRESS` reachable, the user manager
   responds).
2. If yes, install a **user** unit (`systemd --user`) that runs the daemon in the
   foreground mode under the user manager. Do not enable `linger`, do not request
   privilege, and do not create a system unit.
3. If no, report managed-service-unavailable and continue in **foreground**
   mode. Foreground is the baseline on every platform and must not be degraded:
   a distribution without systemd is not a platform failure.

```text
# foreground baseline - always available
"$AXIOM_INSTALL/axiom-graphd" serve --registry "$AXIOM_HOME/config/registry.json"

# managed user service - only when detection above succeeds
axiom service install --user --component axiom-graphd
axiom service start   --component axiom-graphd
axiom service status  --component axiom-graphd
```

`axiom service ...` and `axiom-graphd serve` are not usable in this revision:
`service` is not an accepted command and `serve` exits `4` (`NOT_READY`) after
acquiring the instance lock.

The unit/wrapper must specify an absolute executable path, argv, working
directory and a minimal explicit environment. It must implement install, status,
start, stop, restart and uninstall, with restart backoff, log capture and a
tested non-privileged denial path. No startup registration happens merely
because indexing is enabled.

`SIGINT`/`SIGTERM` request a bounded graceful drain: accept no new claims,
finish or fence current work, persist pending dirty work and close the database
safely. It is not queue deletion.

## 7. MCP handshake

Target procedure (Step 6, `pending`). The MCP gateway (`axiom-mcp`) is owned by
a different repository; this runbook records only the handshake expectations.

- Bind loopback only (`127.0.0.1`, or an explicitly chosen IPv6 loopback);
  wildcard binding is rejected.
- `--host 127.0.0.1 --port 8766` is the documented HTTP shape; stdio mode uses
  the same service contract and keeps stdout protocol-only with diagnostics on
  stderr.
- Scope credentials to registered roots and keep MCP authority separate from
  daemon-control authority. Never place a token in a portable config, a command
  line or a log.
- Handshake verification is a bounded query against a registered solution after
  `version` and `doctor` report a ready daemon.

## 8. First-run smoke test

Target procedure (Step 7, `pending`). The following invocations are the only CLI
surface this revision implements, and `serve` cannot yet serve:

```sh
"$AXIOM_INSTALL/axiom-graphd" version --json
"$AXIOM_INSTALL/axiom-graphd" doctor --json
```

Expected today, from the implemented code path (not a captured run): `version
--json` prints the frozen version report plus runtime facts and exits `0`;
`doctor` exits `4` (`NOT_READY`) with the reason that the diagnostic inventory is
implemented by a later work package. See
[reference/axiom-graphd](../reference/axiom-graphd.md).

## 9. Uninstall and uninstall verification

Target procedure (Step 8, `pending`).

- Default uninstall removes only owned executables and the owned user unit; it
  never runs `sudo`, never deletes a system unit and never removes another host's
  plugins or MCP servers.
- Default uninstall **preserves** project source, annotations, checkpoint JSON,
  human instruction text and private state. Deleting state or credentials
  requires separate explicit approval.
- Keep the uninstall report and never recursively delete `.axiom` or a
  `.agrimap-agent` tree.

Verification of an uninstall is a positive/negative pair: the owned executable
and the owned user unit are gone (`systemctl --user status` fails to find the
unit), and the preserved categories above are byte-identical to their
pre-uninstall state.

## 10. Failure and recovery

| Symptom | Likely cause | Safe action |
| ------- | ------------ | ----------- |
| Archive checksum or signature mismatch | Tampered, truncated or wrong-owner artifact | Stop. Do not extract or execute. Re-obtain from the trusted source. |
| `UNSAFE_HOME_PATH` (exit 2) | Relative, remote or cloud-synchronised `AXIOM_HOME` | Point `AXIOM_HOME` at an absolute path on a local filesystem. |
| `CONFIG_INVALID` (exit 2) | Registry or config rejected | Fix the named field; do not delete the database to silence it. |
| `WRITER_ALREADY_RUNNING` (exit 10) | Another owner holds `run/daemon.lock` | Find the owning process; never delete the lock by guess. |
| `SQLITE_NETWORK_STORAGE_UNSUPPORTED` (exit 9) | State on NFS/SMB or a sync folder | Move state to a local volume. |
| `SQLITE_UNSUPPORTED_VERSION` (exit 9) | Linked runtime below the WAL baseline | Use the bundled/pinned runtime rather than a system library. |
| `NOT_READY` (exit 4) | Requested capability not implemented in this build | Use the documented foreground/read-only path or wait for the owning work package. |
| Managed service unavailable | No `systemd --user` session | Stay in foreground mode; this is not a platform failure. |
| Permission denied writing output | Source or output root not writable | Fix the real ownership/permission. Never redirect output elsewhere silently and never `chmod 777`. |

## 11. What is verified, and what is not

- Verified in this revision: the `XDG_STATE_HOME` default and the state layout,
  the storage classification rules, and the frozen exit/error tables, by the
  repository's own unit tests and documented in
  [CLI-EXIT-CODES](../CLI-EXIT-CODES.md) and
  [reference/axiom-graphd](../reference/axiom-graphd.md).
- **Not verified:** every installation, trust-verification, user-service
  detection, MCP handshake and uninstall step in this runbook. No archive,
  signature, unit file, process or host handshake was exercised on any Linux
  host for this document, and no Linux distribution was tested for
  `systemd --user` detection. No Linux target is certified.
- The `axiom install`, `axiom service` and `axiom-graphd solution` command shapes
  above document an intended contract for a later work package; they are not
  accepted by any binary in this revision.

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
- [install-windows](install-windows.md) and [install-macos](install-macos.md) -
  the sibling platform runbooks.
