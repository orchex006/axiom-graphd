# Host verification — is the applied host really speaking MCP? (E-031)

Owner: `axiom-graphd`. Implementation: `crates/axiom/src/hosts/verify.rs`.

`25-HOST-ADAPTERS-AND-HOOKS.md` section 4 puts a verification step after the host
configuration is written. This guide records what that step must prove and, just
as importantly, what this machine could **not** prove.

## A running process is not an integration

The failure this layer is built against is the one an installer actually
produces: the endpoint answers, `initialize` returns a well-formed `serverInfo`,
the process is alive and the launcher reports success — and the host still has no
usable tool surface, because `tools/list` is empty, missing or refused.

So verification runs three real MCP JSON-RPC requests, in order:

| Step | Method | What must be true |
| --- | --- | --- |
| `initialize` | `initialize` | the body parses **and** `result.serverInfo.name` is the expected server |
| `tools_list` | `tools/list` | at least one named tool, and the expected read tool is among them |
| `test_query` | `tools/call` | the bounded query on that tool returns at least one record |

A status code is never the verdict. A `200` whose body is a JSON-RPC error is
refused, and a body that does not parse is refused.

## "The process started" has its own rule

When `initialize` succeeds and `tools/list` then fails in *any* way — a transport
that did not answer, a non-success status, an unparsable body, or an empty tool
list — the refusal is `process-started-is-not-integration`. That rule exists so a
caller that only checked that the process started cannot report it as an
integration: `VerifyReport::started_without_tools()` is true exactly for that
state, and the report's `refusal()` carries the rule.

A tool surface that exists but does not expose the expected read tool is refused
separately as `tool-not-found`, and an answering tool that returns nothing is
`test-query-empty` rather than a pass.

## Bounded and fail-closed

- Bodies are parsed only up to 256 KiB (`body-too-large`).
- A `tools/list` answer may carry at most 512 tools, each name at most 128 bytes.
- The bounded test query is at most 1 KiB and asks for one row.
- An expectation that cannot be checked — empty server name, empty tool, empty or
  oversized query, zero record floor — refuses the run instead of passing
  vacuously.
- Nothing here opens a socket, spawns a process or writes a file: answers arrive
  through the `HostTransport` trait, so the same decision runs over a live host
  and over the in-memory doubles in the tests.

## Platform coverage and unrun checks

- Exercised in the pinned Linux container (`axiom-rust-git:1.85`) against the
  `HostTransport` double. The live effect is **`not_run`**: no Codex, Claude,
  Gemini or AGY host is installed in the build environment, so no real MCP
  handshake was performed. Reproducible command on a machine with the host
  installed: `axiom host verify --host <host> --json`.
- No native Windows or macOS runtime is available on this host, so the platform
  leg of the verification is `not_run`; the logic is platform-independent by
  construction (it sees only request answers).
- No test reads or writes a real host configuration: the doubles supply every
  answer.

## Tests

```bash
cargo test -p axiom hosts::verify
```

Positive: a real `tools/list` plus a bounded `tools/call` integrates, and the
double records that the three methods were actually sent with the expected tool
and `"limit":1`; a content-block answer carrying rows counts as answered.
Negative and boundary: an initialize that succeeds with no tool surface (empty
list, `404`, transport failure) is `process-started-is-not-integration`; a `200`
with a JSON-RPC error body is not a handshake; a different `serverInfo.name`; a
tool surface without the expected tool; a test query that indexes nothing; a
transport failure; an oversized body; and expectations that cannot be checked.
