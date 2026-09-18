# Troubleshooting by failure code

Owner: `axiom-graphd`. Spec baseline: `2.0.0-draft.1`. This guide describes how
to read an Axiom failure and what to do about it. It is documentation, not
evidence that a compiled daemon, installer or service exists.

## 1. Read the failure, not the reflex

`docs/CLI-EXIT-CODES.md` freezes the process exit status and the `ErrorCode`
table; `docs/22-OPERATIONS-AND-TROUBLESHOOTING.md` owns the operator state table.
Two questions decide the response to any failure:

1. **Which symbol is it?** The process exit code, or the `code` field of the
   `--json` error envelope. These are stable; prose is not.
2. **Is it retryable?** `retryable: true` means the identical request may succeed
   later. It does not mean the work is finished, and it does not mean the
   operator should wait without bound.

Do not fix a symptom by weakening a check. Deleting the database to clear a
stale report, disabling freshness verification to silence a refusal, and forcing
WAL onto shared storage are all things the product refuses on purpose.

## 2. The five conditions this guide separates

| Condition | First signal | Error code | Exit | Retryable | Recovery |
|---|---|---|---|---|---|
| Missing daemon | `doctor` watcher mode `disabled` (`watcher-degraded`) | none raised | - | no | Start the daemon, or read the last published generation offline |
| Stale graph | `status` reports `full_scan_required` with dirty files pending | `NOT_READY` | 4 | yes | Wait for reconcile or a full inventory scan |
| Corrupt shard | generation validation reports an integrity fault | `export-integrity` | - | no | Keep the last valid generation and rebuild from source |
| Queue delay | a `RETRY_WAIT` job; `doctor` reports `queue-retry-wait` | `RATE_LIMITED` | 7 | yes | Wait for the bounded backoff |
| Unsupported host | the storage behind the state path is a share or a cloud folder | `SQLITE_NETWORK_STORAGE_UNSUPPORTED` | 9 | no | Move `AXIOM_HOME` to local disk |

The five are *different* conditions because their first signal, their
retryability and their recovery all differ. Each section below names what the
condition is **not**, because confusing one with another is the usual operator
mistake.

## 3. Missing daemon

The daemon is not running, so nothing is watching the bound roots. This is not a
data fault: the graph is not wrong, it is simply not being updated.

- `doctor` reports the watcher mode as `disabled` and raises the
  `watcher-degraded` diagnostic, so the overall state is `degraded` rather than
  `healthy`.
- A degraded report is still an *answering* report: the database probe and the
  catalog probe still run, so `degraded` is distinguishable from `unavailable`.

Recovery: start the daemon, or answer the question from the last published
generation without one (installation section H: a valid checkpoint, trusted
bindings and the coordination lock are enough for a snapshot query). Do **not**
re-register the solution or reset the database.

This is not a stale graph: a missing daemon produces no `NOT_READY` and no dirty
file count, and starting it is the fix rather than waiting.

## 4. Stale graph

The graph is behind its sources. Freshness is a first-class observation, not an
error: `status` reports `full_scan_required` and the number of dirty files, and a
bounded query that needs an event the graph has not indexed yet returns
`NOT_READY` (exit code 4).

`NOT_READY` is retryable by default, because the reconciliation that will catch
the graph up is already scheduled. Recovery: wait for the queue to reach the
target event sequence, or force a full inventory scan.

This is not a corrupt shard: a stale graph answers with the generation it has and
says so. It is not a queue delay either: the work has not failed and is not
backing off, it is simply pending.

## 5. Corrupt shard

Before a generation is published, validation checks three separate claims: the
manifest is self-consistent, every named file matches its recorded bytes, length
and record count, and every published line is still in canonical form. The
distinct symbols are:

| Validation result | Code | Means |
|---|---|---|
| a shard's bytes no longer match the manifest | `export-integrity` | corruption |
| `manifest.json` is absent or unreadable | `export-missing` | an incomplete generation |
| a line is valid but not canonical | `export-not-canonical` | a writer that bypassed canonicalization |

An integrity fault is not transient: retrying the identical bytes cannot help,
so the retry decision is to give up rather than to schedule a delay. Recovery:
keep the last known-valid catalog generation, rebuild from source, and never
overwrite the last good generation with the damaged one.

This is not a queue delay (which *is* retryable) and not a stale graph (which
answers with older but valid data).

## 6. Queue delay

A delay is the queue working as designed. A *transient* failure - `NOT_READY`,
`RATE_LIMITED`, `CONFLICT`, `WORKTREE_BUSY` or `SHUTTING_DOWN` - is requeued
after a bounded exponential backoff: 250 ms doubling to a 10 s ceiling, plus
deterministic jitter. While jobs wait, `doctor` reports `queue-retry-wait` and
the queue census shows a non-zero `retry_wait` count.

Recovery: wait. The delay is bounded, self-clearing and needs no operator action;
do not cancel and re-create the job, and do not raise the retry budget to hurry
it up.

This is not a permanent failure. `VALIDATION_ERROR`, `INCOMPATIBLE_INPUT`,
`INTERNAL` and the other non-retryable codes are given up immediately with no
delay at all. The `retryable` flag in the error envelope and the
`retry_wait`/`failed` counts in `doctor` separate the two, and the same transient
signal must never be inherited by a permanently failing job.

## 7. Unsupported host

Mutable Axiom state must live on local disk. A state path classified as a
network share, a cloud-synchronised folder or an unsupported device is refused
with `SQLITE_NETWORK_STORAGE_UNSUPPORTED` (exit code 9), which is not retryable:
the same host and the same path will be refused again.

The refusal has two spellings. When local storage is required, the rule is
`mutable-state-local-storage-only`; when the operator has explicitly degraded to
`journal_mode = DELETE`, the remaining refusal is `wal-local-storage-only`,
because write-ahead logging is still unsafe there.

Recovery: move `AXIOM_HOME` (and any other mutable state path) to local disk. A
read-only or offline query may still be served from a valid checkpoint, but do
not disable the storage check or point mutable state back at the share.

This is not a stale graph (exit 4, retryable) and not a stopped per-user service
(a missing daemon, which reports `degraded` and is repaired by starting it).

## 8. Worked example

The example below is the five conditions as the product models them. It is read
by `crates/axiom-graphd/tests/troubleshooting_guide.rs`, which replays each
condition through the real doctor report, the real `status` report, the real
generation validator, the real retry classifier and the real store opener.

<!-- BEGIN TROUBLESHOOTING EXAMPLE -->
```json
{
  "schema_version": 2,
  "solution_id": "demo-solution",
  "conditions": [
    {
      "condition": "missing-daemon",
      "first_signal": "watcher-disabled",
      "error_code": null,
      "exit_code": null,
      "retryable": false,
      "recovery": "start-the-daemon-or-read-the-last-published-generation"
    },
    {
      "condition": "stale-graph",
      "first_signal": "full-scan-required",
      "error_code": "NOT_READY",
      "exit_code": 4,
      "retryable": true,
      "recovery": "wait-for-reconcile-or-a-full-inventory-scan"
    },
    {
      "condition": "corrupt-shard",
      "first_signal": "export-integrity",
      "error_code": "export-integrity",
      "exit_code": null,
      "retryable": false,
      "recovery": "keep-the-last-valid-generation-and-rebuild-from-source"
    },
    {
      "condition": "queue-delay",
      "first_signal": "queue-retry-wait",
      "error_code": "RATE_LIMITED",
      "exit_code": 7,
      "retryable": true,
      "recovery": "wait-for-the-bounded-backoff"
    },
    {
      "condition": "unsupported-host",
      "first_signal": "sqlite-network-storage-unsupported",
      "error_code": "SQLITE_NETWORK_STORAGE_UNSUPPORTED",
      "exit_code": 9,
      "retryable": false,
      "recovery": "move-axiom-home-to-local-disk"
    }
  ]
}
```
<!-- END TROUBLESHOOTING EXAMPLE -->

Exactly two of the five conditions are retryable (`stale-graph` and
`queue-delay`), and the two faults the operator must repair (`corrupt-shard` and
`unsupported-host`) are not. The exit codes that exist (4, 7 and 9) are distinct,
and the two conditions that raise no error at all (`missing-daemon`,
`corrupt-shard`) are distinguished by their first signal, not by a number.

## 9. Guarantees and refusals

| Situation | Result |
|---|---|
| `doctor` watcher mode `disabled` | overall `degraded`, `watcher-degraded`; never rendered `healthy` |
| `status` `full_scan_required` with dirty files | reported honestly; graph stays usable but behind |
| A bounded query needing an unindexed event | `NOT_READY`, exit 4, retryable |
| A shard whose bytes no longer match the manifest | `export-integrity`, not retried |
| A missing or unreadable `manifest.json` | `export-missing`, distinct from corruption |
| A non-canonical published line | `export-not-canonical`, distinct from corruption |
| A transient queue failure | requeued after a bounded backoff, `queue-retry-wait` |
| A permanent queue failure | given up immediately; no delay is granted |
| Mutable state on shared/remote storage | `SQLITE_NETWORK_STORAGE_UNSUPPORTED`, exit 9, not retried |
| Read-only query from a valid checkpoint | allowed without a daemon |

## 10. Status and limits

The doctor report, the `status` report, the retry classifier and the store
opener described here are implemented in `axiom-graphd`, `graph-queue`,
`graph-export` and `graph-store`. The daemon wiring that turns these into a
long-running service, the installer and the service lifecycle are separate
graphd tasks; until they ship, this guide documents the intended operator
response and the invariants the engine already enforces. See
`docs/CLI-EXIT-CODES.md` for the frozen code table and
`docs/22-OPERATIONS-AND-TROUBLESHOOTING.md` for the wider state table.
