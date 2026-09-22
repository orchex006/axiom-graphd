# Persistent foreground lifecycle preflight

Scope: persistent `axiom-graphd serve` foreground loop and process regressions.
Branch: `feature/v2-021-local-macos-delivery`; base: `5e43650`.

The primary tree was already dirty before this task. This task owns only
`crates/axiom-graphd/src/serve.rs`, required CLI/runtime test files, and this
local evidence directory. No release, pin, ledger, shared changelog, catalog
runtime, or existing dirty baseline file is in scope.

Verified governance: `axiom-graphd/AGENTS.md`, local `Development.md`, and
`axiom-specs` revision `1faecdefc1303d069290c708eb7525035b22833c`.
Pinned `cross-platform-v2.md` CP-08 requires foreground `serve`, SIGINT/SIGTERM
bounded graceful drain, no new claims after drain begins, pending-work
persistence, and safe close. The current local CLI reference section 5 records
the missing loop and signals as an implementation gap.

Existing seams: `serve::run_bounded` is retained for one-shot `reconcile`;
`ShutdownToken` already fences claims and reports drain state; `graph-watch`
already has portable polling snapshots. The persistent path will keep the
daemon lock for its lifetime, run startup inventory, poll at a nonzero interval,
run a periodic full fallback, and use a safe signal handler to request the
existing token. No busy-spin and no native watcher claim are permitted.
