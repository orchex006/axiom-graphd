# Default-WAL native lifecycle evidence

`sqlite-default-wal-e2e-success.log` is the successful, redacted run of the
primary native `target/local-macos/axiom-graphd` binary. It runs against a
fresh scoped copy of the already reviewed fixture content and records the exact
argv shape and exit code for `version`, `solution register`, `serve`, and
`query context`.

The log replaces the temporary fixture root with `<scoped-temp-root>` and its
home with `<scoped-home>`. Re-run from the primary workspace root with an
existing equivalent fixture by setting `AXIOM_SQLITE_E2E_ROOT` to that root and
running `sh evidence/engine-readiness-20260922/run-sqlite-default-wal-e2e.sh`.

The adjacent SHA-256 record was calculated after redaction. This is local
native evidence only; it does not claim a signed release or certification.

`run-sqlite-default-wal-e2e-standalone.sh` is the cleanup-safe replacement. It
builds a fresh scoped root from the adjacent portable source/config templates,
writes only a runtime-local binding, and removes that root on exit.
