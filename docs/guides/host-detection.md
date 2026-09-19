# Host detection (`axiom host detect`) — E-026

Owner: `axiom-graphd`. Implementation: `crates/axiom/src/hosts/detect.rs`.

`axiom host detect --json` reports which agent host is installed and **which exact
version answered**, so a host adapter never renders config for a release it merely
assumed. The report is produced by [`detect`] over the read-only [`HostProbe`]
surface; nothing in this path writes, installs or contacts the network.

## What the report says

Each host (`codex`, `claude`, `gemini`, `agy`) carries one record:

| Field | Meaning |
| --- | --- |
| `status` | `missing`, `launch_failed`, `version_unverified` or `detected` |
| `executable` | located program path, when one was found |
| `raw_version` | bounded, control-stripped version line the host printed |
| `version` | parsed `major.minor.patch[-prerelease]`, only when it parsed |
| `write_eligibility` | `auto_write` only for `detected`; otherwise `manual_review` |
| `warnings` | named rules, in the order they were raised |

Warning rules: `launch-failed`, `launch-exit`, `version-empty`,
`version-unparsed`, `version-output-too-large`, `program-path-unusable`,
`binary-stem-unconfirmed`.

## Rules the module enforces

- **An unknown version is not a supported release.** `version_unverified` and
  every failure state report `manual_review`, matching
  `25-HOST-ADAPTERS-AND-HOOKS.md` section 4: manual preview plus the
  instruction/CLI path, never an auto-written hook JSON.
- **Only bounded version output is parsed.** `major.major.patch` must fit
  9 digits per component, 64 bytes of prerelease, and 16 KiB of combined output;
  a date like `2026-09-19T00:00:00Z` is not a version.
- **SemVer ordering.** A prerelease sorts before its release, so `1.2.3-rc.1`
  is below `1.2.3`. `HostVersion::at_least` is the one comparison adapters use.
- **No shell.** `LocalHostProbe` launches `program` plus `argv`
  (`<stem> --version`) through `std::process::Command`; no argument is
  interpolated into a shell string.
- **No invented stems.** `agy` and `antigravity` are both probed, and the record
  carries `binary-stem-unconfirmed` until the documented AGY command stem is
  certified in the reviewed sources (S13–S16).

## Verification

```bash
cargo test -p axiom hosts::detect           # targeted, 11 tests
D:\SP-Billy\axiom\_coord\rust-verify.ps1 -RepoPath <worktree> -Image axiom-rust-git:1.85 -Memory 6g -Offline
```

The positive test launches a real script from a rooted temporary directory
through the production probe; the negatives cover an unknown version, a denied
launch, an oversized output, an empty output, a non-zero exit and an unusable
program path.

## Platform coverage and unrun checks

- Exercised in the pinned Linux container (`axiom-rust-git:1.85`); the
  `cfg(unix)` launch test runs there. `cargo test` on Windows and macOS is
  `not_run` on this host — MSVC is broken and the gates run in Docker only.
- A real `codex` / `claude` / `gemini` / `agy` installation on this machine is
  `not_run`: detection was exercised against an injected search path rooted in a
  temporary directory, and the real `~/.codex`, `~/.claude`, `~/.gemini` and AGY
  installs were never located or launched.
- Reproducible command for the unrun real-host probe:
  `axiom host detect --json` on a machine with the host installed.
