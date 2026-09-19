# Graph-work benchmark (F-030)

Owner: `axiom-graphd`. `index_workload.py` is the F-030 workload harness: it
builds a real dataset on disk, runs a real cold index, a warm no-op pass and a
series of real incremental passes over it, and measures wall time, process CPU
time, peak resident set size, files read, bytes read, symbol and edge counts,
closure size and published artifact bytes.

`axiom-specs/docs/26-PERFORMANCE-AND-TOKEN-EVALUATION.md` states the rule this
harness exists to obey: there is no benchmark runtime in the specification
package, every number there is a design budget or an acceptance target, and no
target may be **claimed** without measured data on reference hardware and a
recorded dataset. The harness therefore prints every specification budget with
`claimed: false` and reports each one `not_run` together with the command that
would measure it for real.

## Running

```bash
python benchmarks/index_workload.py --tier small
python benchmarks/index_workload.py --tier small --json-out report.json
python benchmarks/index_workload.py --projects 1 --files-per-project 3
```

The tiers follow the specification: `small` is 3 projects and 2,001 source
files, `medium` 10 and 10,000, `large` 30 and 50,010. `--projects` and
`--files-per-project` override the tier and are what the three-file smoke run
uses. The dataset is a temporary tree outside the repository and is removed on
exit unless `--keep` is given.

Exit codes match the other component harnesses in `tests/`: `0` every property
held and every negative leg was rejected, `2` a divergence (printed as
`PROBLEM:`), `1` a usage or I/O failure.

## What is real and what is modelled

* **Real.** The dataset and its bytes; the file reads and content hashes; wall
  clock, CPU time and peak RSS; the file, symbol, edge and closure counts; the
  published artifact bytes; and the incremental-versus-full-rebuild oracle,
  which compares the digest set, the symbol table, the edge set and the
  canonical artifact bytes of an incremental pass against a cold rebuild of the
  same bytes.
* **Modelled.** The indexer. The production cold and incremental index is Rust
  (`graph-analyze` / `graph-export`); this harness cannot link a Rust crate, so
  it runs a deterministic Python indexer over the same input shape and reports
  the Rust measurement as `not_run` with the reproducible
  `cargo test -p graph-analyze --locked`. Its fast path is deliberately
  content-addressed - the warm pass still reads and hashes every file and only
  skips the parse - so the boundary leg below is meaningful.
* **Not claimed.** Every specification target, including the warm bounded query
  p95 and the no-edit daemon CPU budget, which need the real daemon and are
  reported `not_run`.

## Negative and boundary legs

Each of these is exercised on every run, and each must be caught:

* a deliberately stale incremental pass - told that a changed file was
  unchanged - must not equal a full rebuild;
* a same-size rewrite with the file mtime restored must still be noticed, which
  is true for a content digest and not for an mtime-and-size cache;
* an unknown symbol must close to nothing rather than raise;
* a project with no source files must index to an empty graph without crashing.

## Recorded run

`--tier small` on this host (Windows, CPython 3.13) measured 2,001 files and
605,535 bytes: a cold index of 31.6 s wall and 1.16 s CPU at 34.8 MB peak RSS;
a warm no-op pass of 0.11 s wall reparsing no files; a one-file edit of 0.13 s
wall; a burst save of 100 files of 1.76 s wall; 8,004 symbols and 9,999 edges;
a closure of 2,668 symbols; and a 406,101-byte artifact. All four negative legs
were rejected and no specification target was claimed. These are measurements
of this harness on this host, not a certification of the Rust index.

The host has no MSVC toolchain and no unprivileged way to run a second platform
runtime, so native Windows/macOS runtime evidence and the real Rust measurement
are reported `not_run` rather than assumed.
