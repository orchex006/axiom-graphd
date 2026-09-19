# Host adapters — per-host MCP and instruction fragments (E-027 – E-030)

Owner: `axiom-graphd`. Implementation:
`crates/axiom/src/hosts/codex.rs`, `claude.rs`, `gemini.rs`, `antigravity.rs`.

Each installed agent host renders MCP and instruction configuration in **its own**
shape. `25-HOST-ADAPTERS-AND-HOOKS.md` section 5 is the reason this is four
adapters and not one JSON blob: Codex documents `url` + `bearer_token_env_var`
(S10), Gemini CLI documents `httpUrl` for Streamable HTTP (S18), Antigravity
documents `serverUrl` (S15) and Claude Code uses its native `type` + `url`
schema (S20). Copying one host's keys into another host's file produces a server
that host silently ignores, so every adapter here **validates** the shape and
**refuses** a field that belongs to another host instead of accepting it as an
unknown key.

Every adapter is a *planner*. `plan` renders a bounded fragment and `apply` is a
pure transformation of a document the caller already holds; none of them reads or
writes a real `~/.codex`, `~/.claude`, `~/.gemini` or AGY installation. The write
belongs to the bootstrap/install path that owns those files.

## Codex (E-027)

`crates/axiom/src/hosts/codex.rs`.

| Item | Value | Source |
| --- | --- | --- |
| config file | `~/.codex/config.toml` | S10 |
| instruction file | `<project>/AGENTS.md` | S09 |
| MCP table | `[mcp_servers.<name>]` | S10 |
| HTTP fields | `url`, `bearer_token_env_var` | S10 |

**Byte preservation, not a round trip.** Codex's file is TOML with human
comments. Re-rendering the whole document would drop the comments, the ordering
and the formatting a person owns, so this module parses only a **bounded subset**
of TOML far enough to (a) validate/refuse the one table it owns and (b) find that
table's exact byte span. The applied result is then either an append (the whole
existing text stays an exact prefix) or a span replacement (every byte outside
the managed table is untouched).

**Supported fields** inside `[mcp_servers.<name>]`: `url`,
`bearer_token_env_var`, `command`, `args`, `env`, `enabled`. A transport field
belonging to another host (`httpUrl`, `serverUrl`, `sseUrl`, `type`) is refused
as `unsupported-transport-field`, so a copy-pasted Gemini or AGY block fails
validation here instead of producing a server Codex ignores.

**Refusal rules:** `toml-unsupported-syntax` (`[[table]]`, inline tables, floats,
multi-line strings, unknown escapes — never guessed at), `unknown-field`,
`unsupported-transport-field`, `transport-missing`, `transport-conflict`,
`credential-literal-refused`, `credential-in-url-refused`,
`insecure-transport-refused` (non-loopback plaintext HTTP),
`toml-duplicate-key`, `output-too-large`, `unsafe-path`,
`existing-table-unsupported`, `table-already-present`.

Credentials are references only: `bearer_token_env_var` must be an environment
variable name, and a literal token or a `?token=`/`?api_key=` value in the URL is
refused. Refusal details are recorded under the redaction allowlist keys
(`rule`, `config_key`, `table`, `observed`, `actual`, `portable_path`,
`component`), so a refusal stays diagnosable after redaction.

### Tests

```bash
cargo test -p axiom hosts::codex
```

Positive: appending preserves every other server and the whole document; a
replacement moves nothing outside the managed table; a rendered block parses back
to the same server. Negative: a foreign transport field, an unknown field, a
transport conflict, a transport-less table, a literal credential, a credential in
the URL, plaintext remote HTTP, a `[[table]]`, an inline table, a float, a
multi-line string, a duplicate key, an oversized value and an oversized document.

## Platform coverage and unrun checks (all adapters)

- Exercised in the pinned Linux container (`axiom-rust-git:1.85`). `cargo test`
  on Windows and macOS is `not_run` on this host; the gates run in Docker only.
- The real-host effect is `not_run`: no real `~/.codex`, `~/.claude`,
  `~/.gemini` or AGY installation was read or written on this machine. Every
  adapter was exercised against injected documents and rooted temporary paths.
- No live daemon exists on this host, so the E-031 handshake against a real host
  is `not_run`; reproducible command: `axiom host verify --host <host> --json`.
