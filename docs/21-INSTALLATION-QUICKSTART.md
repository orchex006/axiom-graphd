# Native installation and quick start — V2

Owner: axiom-graphd. **Intended command contract; no downloadable runtime release is included in this specification.**

## Distribution

Publish an archive per required platform containing the `axiom` CLI and `axiom-graphd` daemon from the same core version. Windows uses `.exe`; Linux/macOS executable permissions are preserved. Verify trusted release provenance/signature and artifact hash before unpacking to a user-writable install directory. Do not suggest `curl | sh`, root installation, Gatekeeper bypass, or a global PATH change as a prerequisite. Python MCP uses a separate locked environment and official SDK; a user may use direct JSON without installing MCP.

## Foreground first

Invoke the program directly from its installation directory. On PowerShell the call operator supports a quoted executable path:

```powershell
& "C:\Users\Example\Apps\Axiom\axiom.exe" version
& "C:\Users\Example\Apps\Axiom\axiom-graphd.exe" serve
```

On Linux/macOS invoke the native program using an absolute or `./` path:

```sh
./axiom version
./axiom-graphd serve
```

Shell snippets illustrate invocation only. Internally use an executable path plus argv; do not require Bash to execute core operations. Ctrl+C requests bounded graceful shutdown, not queue deletion. `axiom doctor` reports native target, effective state root, bundled SQLite version, filesystem capabilities, service availability and missing release evidence.

## Workspace setup

Create the portable solution definition from the pinned config schema; `axiom-graphd solution register --config <file> --bindings <file> --dry-run` previews registration, followed by explicitly approved `--apply`. Bind each logical repo ID to a native absolute checkout path through local bindings. `axiom bootstrap plan` presents all managed-file changes; `axiom bootstrap apply --plan <file> --approve-digest <sha256>` verifies the approved plan, ownership hashes and unchanged baseline before writing. Re-running must be idempotent. Preserve existing AGENTS.md text and fail on stale plans or human modifications inside a managed block. Exact argv/options are governed by the CLI/control contract in the pinned spec.

`AXIOM_HOME` overrides private per-user state. Default local paths: Windows `%LOCALAPPDATA%\Axiom`, Linux `${XDG_STATE_HOME:-$HOME/.local/state}/axiom`, macOS `$HOME/Library/Application Support/Axiom`. Do not put SQLite, credentials or native absolute bindings into committed `.axiom` files. Use separate state per OS user/installation context; refuse a live store on a network/sync filesystem.

## Opt-in startup

Windows: a current-user scheduled task at logon. Linux: a user systemd unit when available; foreground mode remains supported without systemd. macOS: a current-user LaunchAgent. No startup registration happens merely because graph indexing is enabled. All wrappers call the same foreground daemon entrypoint, use absolute executable paths, protect token locations and have native start/stop/status/unregister tests. A Windows machine-wide Service is an optional later adapter, not the baseline.

## Upgrade and uninstall

Preview verified component updates, stop affected writers, preserve durable queue/state and recover a transactional update journal. Core executable replacement occurs only after the relevant processes stop. Validate compatibility and install health before removing rollback artifacts. Uninstall removes only owned executables/startup entries by default; workspace data, checkpoints and private state require separate explicit deletion approval. Never recursively delete `.axiom` or `.agrimap-agent`.

## Evidence gate

Run install, native foreground, bootstrap repeat/stale-plan, watcher fallback, snapshot-reader race, crash recovery, migration and update/rollback tests on each required OS/architecture. Cross-compiling and spec unit tests are insufficient. No platform is certified by this guide.
