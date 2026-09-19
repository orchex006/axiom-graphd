# macOS first-install runbook

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. Implementation/release evidence is not implied.

This runbook is the macOS first-install procedure for the Axiom Graph Ecosystem
core release (`axiom-graphd` daemon plus `axiom` operations CLI). It is a target
contract with per-step availability, not a record of a completed install: this
repository currently contains no released artifact (`VERSION` is `0.0.0-dev`), no
installer, no installer CLI crate and no macOS install/run/uninstall evidence.
Commands and per-command exit codes are single-sourced in
[reference/axiom-graphd](../reference/axiom-graphd.md); the frozen process exit
table is single-sourced in [CLI-EXIT-CODES](../CLI-EXIT-CODES.md).

This document distributes no secret. It contains no token, no credential, no
signing key and no trust-root private material, and it never instructs you to put
one into a configuration file, a command line or a plist.

## 1. Step availability

<!-- BEGIN RUNBOOK STATUS -->
| Step | State | Reason |
| ---- | ----- | ------ |
| 1 Prerequisites and architecture selection | pending | Target selection is defined, but no archive exists for either macOS architecture. |
| 2 Approved release and trust setup | pending | No signed or notarised release archive exists; `axiom install` has no implementation in this build. |
| 3 Install the core release | pending | No installer, no archive and no `crates/axiom` crate exist in the pinned revision. |
| 4 Machine-local state, bindings and filesystem permission checks | pending | `AXIOM_HOME` resolution and the storage policy exist, but the registry/binding commands are not wired into argv. |
| 5 User LaunchAgent | pending | No LaunchAgent template or service adapter exists in this build. |
| 6 MCP handshake | pending | `axiom-mcp` is a separate repository and no handshake evidence exists for this host. |
| 7 First-run smoke test | pending | The daemon cannot serve: `serve` reports `NOT_READY`. |
| 8 Uninstall and uninstall verification | pending | No LaunchAgent or owned-file manifest exists to remove. |
<!-- END RUNBOOK STATUS -->

## 2. Architecture selection and prerequisites

| Item | Requirement | Notes |
| ---- | ----------- | ----- |
| OS | macOS 14 or later | Required targets are `macos-arm64` and `macos-x64`; both are unbuilt and uncertified. |
| Architecture | Apple silicon (`aarch64`) or Intel (`x86_64`) | Choose the archive that matches the machine's native architecture. |
| Privilege | Ordinary user account | Installation, state and startup registration are per-user. Never `sudo`. |
| Storage | Local fixed volume | Mutable state must be on a local disk. iCloud Drive and other cloud-synchronised or network locations are refused by the state-home policy in `crates/graph-core/src/paths.rs`. |
| Git | Optional | Required only for Git checkpoint and staged-source snapshot features. |
| Rust toolchain | Not required | An end user consumes a prebuilt archive; only developers building the workspace need the pinned toolchain. |
| Python | Not required for the daemon | The optional MCP gateway is a separate component with its own locked environment. |
| Bash, Docker | Not required | Core operations must not depend on them. |

Select the architecture before downloading anything:

```sh
uname -m          # arm64  -> macos-arm64 archive
                  # x86_64 -> macos-x64 archive
```

Rules that follow from the matrix in
[release/build-matrix.md](../../release/build-matrix.md):

- `macos-arm64` (<code>aarch64-apple-darwin</code>) is the native target for Apple
  silicon; it must run natively, **not** under Rosetta.
- `macos-x64` (<code>x86_64-apple-darwin</code>) is the native target for Intel
  machines.
- Do not run the Intel archive under Rosetta on Apple silicon as a substitute for
  the arm64 archive, and do not treat a successful cross-compile as macOS
  runtime certification.

## 3. Approved release and trust setup

Target procedure (Step 2, `pending`). No step below was executed.

1. Choose the release owner/repository and trust root from the organisation the
   installation is actually for, and record that trusted-source configuration in
   operator documentation you control.
2. Download the `axiom-<version>-macos-<arch>.tar.gz` bootstrap archive for the
   selected architecture from that trusted release.
3. Verify the archive checksum and signature against the known root **before**
   extracting or executing anything, with a procedure that also works offline.
4. Validate provenance, signing and notarisation against normal macOS
   distribution policy. **Do not** instruct anyone to disable Gatekeeper, remove
   a quarantine attribute to defeat a check, or otherwise bypass a platform
   security control. A provenance failure is reported, not circumvented.
5. Extract to a user-writable directory and retain at least the previous working
   version for rollback. No global `PATH` change and no system directory write.

Refusals that are contract, not preference:

- `curl | sh` is never the default or documented runbook.
- No `sudo`, no launchd **system** daemon, no `/Library/...` installation, and no
  security-control bypass as a prerequisite.

## 4. Install the core release

Target procedure (Step 3, `pending`). The installer CLI is not part of this
revision; see [reference/axiom-graphd](../reference/axiom-graphd.md).

```text
axiom install plan  --bundle <verified-local-bundle> --out install-plan.json
axiom install apply --plan install-plan.json
```

- Install into a versioned directory under the user state home
  (`AXIOM_HOME/installs/<component>/<version>/`) and activate through a validated
  manifest/launcher rather than a symlink-only active-version switch.
- Review the plan before applying: component versions, paths, service changes,
  required permissions and planned network access.
- Invoke the program by absolute or `./` path, for example
  `"$HOME/Library/Application Support/Axiom/installs/axiom-graphd/<version>/axiom-graphd" version`.
- A running core executable is never overwritten in place: install, drain,
  activate, verify, keep the rollback version.

## 5. Machine-local state, bindings and permission checks

Target procedure (Step 4, `pending`). The state home, layout and storage policy
below are implemented; the registry/binding commands are not wired into argv in
this revision.

Default state home on macOS:

```text
$HOME/Library/Application Support/Axiom
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

Filesystem and permission checks that must hold before state is created:

| Check | Required outcome |
| ----- | ---------------- |
| Location | `AXIOM_HOME` is an absolute path on a local fixed volume. |
| Volume case sensitivity | Probed, never assumed. Case-only collisions are reported, and source path spelling is never silently lowercased or merged. |
| Cloud/sync placement | iCloud Drive, Dropbox, Google Drive, OneDrive/SharePoint and similar locations are refused for mutable state. |
| Symlinks | `AXIOM_HOME` and output destinations are not symlinks or alias escapes; resolve the real path and check containment before writing. |
| Ownership/permissions | The state directory is owner-only (for example `0700`); it is not group- or world-writable. Do not `chmod 777` to silence a denial. |
| Secrets placement | `AXIOM_HOME/secrets/` is owner-only. Credentials belong in the owner-only store or the platform credential store, never in a portable config, an argv, a plist or a log. |
| Source root | Registered source roots may be read-only; a repository that cannot be written is an error, not silently redirected elsewhere. |

- Bindings are machine-local: commit logical project IDs and repo-relative
  `/`-separated paths to `.axiom` files; never commit absolute checkout paths,
  SQLite files, tokens or credentials.
- A missing registered root is reported, never auto-cloned.

## 6. User LaunchAgent

Target procedure (Step 5, `pending`). No LaunchAgent template or adapter exists
in this revision.

- Managed integration is a **current-user LaunchAgent** in
  `$HOME/Library/LaunchAgents`. It is opt-in: no startup registration happens
  merely because indexing is enabled.
- The plist must use an absolute `ProgramArguments` executable path with the
  exact argv and an explicit `WorkingDirectory`. No login-shell `PATH`
  assumption, and no `shell -c "..."` indirection that would let a shell string
  become the command.
- Environment values that are not secrets may be declared explicitly. **Secrets
  are never placed in the plist**; if a credential is needed, reference the
  owner-only store or the platform credential store.
- The adapter must implement install, status, start, stop, restart and uninstall
  with restart backoff, log capture and a tested non-privileged denial path.
- Load/unload uses `launchctl` in the user domain only. Never install a launchd
  system daemon, and do not request `sudo` when load is refused; report it.
- Foreground mode remains the baseline and must keep working with no LaunchAgent.

## 7. MCP handshake

Target procedure (Step 6, `pending`). The MCP gateway (`axiom-mcp`) is owned by a
different repository; this runbook records only the handshake expectations.

- Bind loopback only (`127.0.0.1`, or an explicitly chosen IPv6 loopback).
  Wildcard binding is rejected.
- `--host 127.0.0.1 --port 8766` is the documented HTTP shape; stdio mode uses
  the same service contract, keeps stdout protocol-only and sends diagnostics to
  stderr.
- Scope credentials to registered roots and keep MCP authority separate from
  daemon-control authority. Tokens never appear in argv or logs; on macOS prefer
  the platform credential store for interactive use and the owner-only file store
  for non-interactive use.
- Handshake verification is a bounded query against a registered solution after
  `version` and `doctor` report a ready daemon. A mocked handshake is not host
  certification.

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

`Ctrl+C` requests a bounded graceful drain, not queue deletion.

## 9. Uninstall and uninstall verification

Target procedure (Step 8, `pending`).

- Default uninstall removes only owned executables and the owned LaunchAgent. It
  never uses `sudo`, never touches `/Library/LaunchDaemons` and never removes
  another host's plugins or MCP servers.
- Default uninstall **preserves** project source, annotations, checkpoint JSON,
  human instruction text and private state. Deleting state or credentials
  requires separate explicit approval, and credential revocation/secure deletion
  follows macOS policy.
- Keep the uninstall report and never recursively delete `.axiom` or a
  `.agrimap-agent` tree.

Verification of an uninstall is a positive/negative pair: the owned executable
and the LaunchAgent plist are gone (`launchctl print gui/$UID/<label>` no longer
resolves the job), and the preserved categories above are byte-identical to their
pre-uninstall state.

## 10. Failure and recovery

| Symptom | Likely cause | Safe action |
| ------- | ------------ | ----------- |
| Archive checksum or signature mismatch | Tampered, truncated or wrong-owner artifact | Stop. Do not extract or execute. Re-obtain from the trusted source. |
| Gatekeeper or notarisation refusal | Provenance/signing not valid for this distribution policy | Report the refusal. Never remove the quarantine flag to defeat the check. |
| Wrong-architecture binary (Bad CPU type) | arm64 archive on Intel, or Intel expectations on Apple silicon | Re-download the archive matching `uname -m`. Do not paper over it with Rosetta. |
| `UNSAFE_HOME_PATH` (exit 2) | Relative, iCloud/cloud-synchronised or network `AXIOM_HOME` | Point `AXIOM_HOME` at an absolute local path. |
| `CONFIG_INVALID` (exit 2) | Registry or config rejected | Fix the named field; do not delete the database to silence it. |
| `WRITER_ALREADY_RUNNING` (exit 10) | Another owner holds `run/daemon.lock` | Find the owning process; never delete the lock by guess. |
| `SQLITE_NETWORK_STORAGE_UNSUPPORTED` (exit 9) | State on a network or sync volume | Move state to a local volume. |
| `NOT_READY` (exit 4) | Requested capability not implemented in this build | Use the documented foreground/read-only path or wait for the owning work package. |
| `launchctl` load denied | Organisation policy or missing user session | Report it and stay in foreground mode. Do not request elevation automatically. |

## 11. What is verified, and what is not

- Verified in this revision: the macOS state-home default and state layout, the
  storage classification, the case-sensitivity/collision policy and the frozen
  exit/error tables, by the repository's own unit tests and documented in
  [CLI-EXIT-CODES](../CLI-EXIT-CODES.md) and
  [reference/axiom-graphd](../reference/axiom-graphd.md).
- **Not verified:** every installation, trust/notarisation, LaunchAgent, MCP
  handshake and uninstall step in this runbook. No archive, signature,
  notarisation, LaunchAgent, process or host handshake was exercised on any macOS
  host for this document. Rosetta behaviour was not tested because it is not
  supported as a substitute for the native archive. No macOS target is certified.
- The `axiom install` and `axiom service` command shapes above document an
  intended contract for a later work package; they are not accepted by any
  binary in this revision.

## 12. Related documents

- [reference/axiom-graphd](../reference/axiom-graphd.md) - commands, arguments,
  exit codes and failure recovery.
- [CLI-EXIT-CODES](../CLI-EXIT-CODES.md) - the frozen exit-code and error-code
  tables.
- [../21-INSTALLATION](../21-INSTALLATION.md) - the installation contract and its
  current status.
- [../21-INSTALLATION-QUICKSTART](../21-INSTALLATION-QUICKSTART.md) - the short
  native installation and quick-start contract.
- [../22-OPERATIONS-AND-TROUBLESHOOTING](../22-OPERATIONS-AND-TROUBLESHOOTING.md)
  - operations and recovery.
- [install-windows](install-windows.md) and [install-linux](install-linux.md) -
  the sibling platform runbooks.
