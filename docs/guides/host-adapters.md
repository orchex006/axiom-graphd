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

## Claude Code (E-028)

`crates/axiom/src/hosts/claude.rs`.

| Item | Value | Source |
| --- | --- | --- |
| user config | `~/.claude.json` | S20 |
| user instruction | `~/.claude/CLAUDE.md` | S12 |
| project config | `<project>/.mcp.json` | S20 |
| project instruction | `<project>/CLAUDE.md` | S12 |
| MCP object | `mcpServers` | S20 |
| HTTP fields | `type` + `url` (native schema) | S20 |
| policy object | `permissions` (never written) | S20 |

**Config scope and instruction discovery travel together.** `scope_files`
returns one scope's config file and instruction file as a single value, so a plan
cannot render a project-scoped server while claiming a user-scoped instruction
file. An unrecognised scope is refused (`unsupported-scope`) rather than mapped to
a default.

**Existing permissions are never widened.** Claude Code enforces tool permissions
from `permissions.allow`/`permissions.deny`. The merge touches only `mcpServers`,
so an existing `permissions` object, an existing `hooks` object and every unknown
top-level key survive by value, and `assert_permissions_not_widened` refuses a
request whose `permissions.allow` would add an entry the document does not already
hold - it walks the parsed object rather than matching the literal `allow` key, so
a nested or reordered object cannot slip a widening through.

**JSON is merged by value.** JSON has no comments, so a rewrite can lose only
whitespace and key order. The document is parsed with `serde_json` and
re-serialised, which normalises key order to sorted and indentation to two spaces.
That normalisation is a recorded limitation, not a preservation guarantee; every
*value* outside the managed entry survives.

### Tests

```bash
cargo test -p axiom hosts::claude
```

Positive: the two scopes pair a config file with an instruction file; appending
preserves every other server, the `permissions` object and unknown top-level keys;
replacing the managed entry changes only that entry; the fragment carries the
managed block markers. Negative: a foreign transport field, an unsupported scope,
a permission the document does not hold, a literal credential and a credential in
the URL, a relative or shell-carrying stdio command, a document outside the
schema, and an insert plan meeting an already-declared server.

## Platform coverage and unrun checks (all adapters)

- Exercised in the pinned Linux container (`axiom-rust-git:1.85`). `cargo test`
  on Windows and macOS is `not_run` on this host; the gates run in Docker only.
- The real-host effect is `not_run`: no real `~/.codex`, `~/.claude`,
  `~/.gemini` or AGY installation was read or written on this machine. Every
  adapter was exercised against injected documents and rooted temporary paths.
- No live daemon exists on this host, so the E-031 handshake against a real host
  is `not_run`; reproducible command: `axiom host verify --host <host> --json`.
