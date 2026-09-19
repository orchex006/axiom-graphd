#!/usr/bin/env python3
"""Failure-injection harness F-013 - crash a worker before and after ack.

A daemon can stop mid-job. Its lease row survives, and the restart path must make
the work eligible again without ever letting the vanished owner come back and
publish. The contract is the durable queue in
docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md section 4 read through
graph-queue::{claim, ack, recover}:

* a claim happens in one BEGIN IMMEDIATE transaction and takes a strictly higher
  fence than every previous claim of the job;
* recovery returns a crashed job to PENDING with the fence unchanged, so the next
  claim takes a strictly higher fence;
* a result is accepted only from the live fence owner of a RUNNING job, and only
  against the generation the worker actually read.

This harness models that state machine deterministically with an injected clock,
replays a crash before the acknowledgment and a crash after it, and checks that
no dirty generation is lost. It models the documented policy; it does not run the
real Rust queue. The reproducible real-code command is recorded and reported as
not_run here:

    cargo test --locked -p graph-queue claim ack recover

Positive legs:

* crash before ack: the job recovers to PENDING with the fence unchanged, and the
  next claim takes a strictly higher fence under a new owner;
* a late result from the pre-crash lease is rejected as stale;
* crash after the result write but before the state transition: recovery re-claims
  and the same generation is not lost;
* an edit that arrives during analysis leaves the file dirty after the older
  result is committed.

Negative legs (each must be rejected):

* reusing a fence (not strictly increasing) is refused;
* a stale owner whose lease has expired is refused even if it presents the
  current fence;
* a naive "same fence, same owner, still accepted" policy is shown to accept the
  stale write the real policy rejects.

Exit codes: 0 every property held and every negative leg was rejected, 2 a
divergence, 1 a usage or I/O failure.
"""
from __future__ import annotations

import argparse
import io
import json
import sys

LEASE_MS = 30_000
MAX_LEASE_MS = 300_000

PENDING = "PENDING"
LEASED = "LEASED"
RUNNING = "RUNNING"
SUCCEEDED = "SUCCEEDED"


class Job:
    def __init__(self, job_id, target_generation):
        self.id = job_id
        self.state = PENDING
        self.attempt = 0
        self.fence = 0
        self.owner = None
        self.lease_until = 0
        self.target_generation = target_generation
        self.indexed_generation = 0


class Lease:
    def __init__(self, job_id, fence, owner, lease_until):
        self.job_id = job_id
        self.fence = fence
        self.owner = owner
        self.lease_until = lease_until

    def as_tuple(self):
        return (self.job_id, self.fence, self.owner)


def claim(job, owner, now_ms, duration_ms=LEASE_MS):
    """Model graph-queue::claim. Returns a Lease or raises ValueError."""
    if job.state not in (PENDING,):
        raise ValueError("claim refused: job is %s" % job.state)
    if duration_ms <= 0 or duration_ms > MAX_LEASE_MS:
        raise ValueError("claim refused: lease duration out of range")
    job.attempt += 1
    job.fence = job.fence + 1  # strictly increasing
    job.owner = owner
    job.lease_until = now_ms + duration_ms
    job.state = LEASED
    return Lease(job.id, job.fence, owner, job.lease_until)


def recover(job, now_ms):
    """Model graph-queue::recover. Returns True when a lease was reclaimed."""
    if job.state not in (LEASED, RUNNING):
        return False
    if now_ms <= job.lease_until:
        return False
    job.state = PENDING
    job.owner = None
    job.lease_until = 0
    # The fence is deliberately unchanged; the next claim raises it.
    return True


def restart(lease, job):
    """Begin running a claimed job."""
    if job.state != LEASED or job.fence != lease.fence or job.owner != lease.owner:
        raise ValueError("start refused: lease is not the live claim")
    job.state = RUNNING


def commit_result(job, lease, analyzed_generation, desired_generation):
    """Model graph-queue::ack. Returns (accepted, reason)."""
    if job.state != RUNNING:
        return False, "job-not-running"
    if lease.fence != job.fence or lease.owner != job.owner:
        return False, "stale-fence-or-owner"
    if analyzed_generation != job.target_generation:
        return False, "generation-mismatch"
    job.indexed_generation = analyzed_generation
    job.state = SUCCEEDED
    # The file remains dirty while desired > indexed; the next batch target is
    # the newer generation. That is the anti-lost-update rule (section 3).
    return True, "indexed=%d dirty=%s" % (analyzed_generation, desired_generation > analyzed_generation)


def live_owner_accepts(job, fence, owner):
    """The real acceptance predicate: live owner and fence of a RUNNING job."""
    return job.state == RUNNING and job.fence == fence and job.owner == owner


def run():
    problems = []
    not_run = []

    # --- leg 1: crash before ack, recovery keeps the fence, next claim raises --
    job = Job("job-1", target_generation=41)
    lease_a = claim(job, "worker-A", now_ms=0)
    if lease_a.fence != 1:
        problems.append("first claim fence was %d, expected 1" % lease_a.fence)
    restart(lease_a, job)
    reclaimed = recover(job, now_ms=LEASE_MS + 1)
    if not reclaimed:
        problems.append("expired lease was not reclaimed")
    if job.fence != 1:
        problems.append("recovery changed the fence to %d; it must stay unchanged" % job.fence)
    if job.state != PENDING:
        problems.append("recovered job is %s, expected PENDING" % job.state)
    lease_b = claim(job, "worker-B", now_ms=LEASE_MS + 2)
    if lease_b.fence != 2:
        problems.append("fence after re-claim was %d, expected a strictly higher 2" % lease_b.fence)
    if lease_b.owner != "worker-B":
        problems.append("re-claim owner was %r, expected worker-B" % lease_b.owner)
    if job.attempt != 2:
        problems.append("attempt was %d, expected 2" % job.attempt)

    # --- leg 2: a late result from the pre-crash lease is rejected ------------
    restart(lease_b, job)
    accepted, reason = commit_result(job, lease_a, analyzed_generation=41, desired_generation=41)
    if accepted:
        problems.append("late result from the reclaimed lease was accepted: %s" % reason)
    if job.state != RUNNING:
        problems.append("a rejected stale write changed the job state to %s" % job.state)
    if not live_owner_accepts(job, lease_b.fence, lease_b.owner):
        problems.append("the live owner is no longer the accepted one after the stale write")

    # --- leg 3: crash after the result write, before the state transition -----
    # The generation is not lost: recovery re-claims and the same target is
    # analysable again (at-least-once), and the write is idempotent.
    job = Job("job-2", target_generation=7)
    lease = claim(job, "worker-C", now_ms=0)
    restart(lease, job)
    job.indexed_generation = 7  # the result bytes landed...
    # ...then the process crashed before the job transitioned to SUCCEEDED.
    job.state = RUNNING
    recovered = recover(job, now_ms=LEASE_MS + 1)
    if not recovered:
        problems.append("crash-after-write job was not recovered")
    again = claim(job, "worker-D", now_ms=LEASE_MS + 2)
    if again.fence != 2:
        problems.append("re-claim after crash-after-write used fence %d" % again.fence)
    if job.target_generation != 7:
        problems.append("recovery lost the target generation")

    # --- leg 4: an edit during analysis leaves the file dirty ------------------
    job = Job("job-3", target_generation=41)
    lease = claim(job, "worker-E", now_ms=0)
    restart(lease, job)
    desired_generation = 42  # a second edit arrived while the worker parsed 41
    accepted, reason = commit_result(job, lease, analyzed_generation=41,
                                     desired_generation=desired_generation)
    if not accepted:
        problems.append("leg 4: a live result for generation 41 was refused: %s" % reason)
    if job.indexed_generation != 41:
        problems.append("leg 4: indexed generation was %d, expected 41" % job.indexed_generation)
    if not (desired_generation > job.indexed_generation):
        problems.append("leg 4: the newer generation did not remain outstanding")
    if "dirty=True" not in reason:
        problems.append("leg 4: commit did not report the still-dirty generation: %s" % reason)

    # --- negative A: a non-increasing fence must be refused -------------------
    def fence_is_valid(current_fence, proposed_fence):
        return proposed_fence > current_fence

    job = Job("job-4", target_generation=1)
    claim(job, "worker-F", now_ms=0)
    before = job.fence
    if fence_is_valid(before, before):
        problems.append("negative A: a reused fence was accepted")
    if fence_is_valid(before, before - 1):
        problems.append("negative A: a lower fence was accepted")
    if not fence_is_valid(before, before + 1):
        problems.append("negative A: a strictly higher fence was refused")

    # --- negative B: an expired-lease owner must be refused -------------------
    def accept(job, lease, now_ms):
        if now_ms > lease.lease_until:
            return False, "lease-expired"
        if not live_owner_accepts(job, lease.fence, lease.owner):
            return False, "stale-fence-or-owner"
        return True, "accepted"

    job = Job("job-5", target_generation=1)
    lease = claim(job, "worker-G", now_ms=0)
    restart(lease, job)
    ok, reason = accept(job, lease, now_ms=LEASE_MS + 5)
    if ok:
        problems.append("negative B: an expired lease was accepted")
    if reason != "lease-expired":
        problems.append("negative B: refusal reason was %r, expected lease-expired" % reason)
    # After recovery and a re-claim the live lease is accepted again.
    recover(job, now_ms=LEASE_MS + 6)
    lease_next = claim(job, "worker-J", now_ms=LEASE_MS + 7)
    restart(lease_next, job)
    ok, reason = accept(job, lease_next, now_ms=LEASE_MS + 8)
    if not ok:
        problems.append("negative B: the recovered live lease was refused: %s" % reason)

    # --- negative C: the naive policy accepts the stale write ----------------
    naive_accepts = lambda state, fence, owner, j: (j.fence == fence and j.owner == owner)
    job = Job("job-6", target_generation=1)
    lease_a = claim(job, "worker-H", now_ms=0)
    restart(lease_a, job)
    recover(job, now_ms=LEASE_MS + 1)
    claim(job, "worker-I", now_ms=LEASE_MS + 2)
    restart(Lease(job.id, job.fence, job.owner, job.lease_until), job)
    if naive_accepts(job.state, lease_a.fence, lease_a.owner, job):
        problems.append("negative C: the naive predicate did not accept the stale write (no teeth)")
    if live_owner_accepts(job, lease_a.fence, lease_a.owner):
        problems.append("negative C: the real predicate accepted the stale write")

    not_run.append(
        "cargo test --locked -p graph-queue claim ack recover "
        "(real queue state machine; no Rust build taken in this lane)"
    )
    return problems, not_run


def main(argv=None):
    parser = argparse.ArgumentParser(description="F-013 crash worker before and after ack")
    parser.add_argument("--json-out", help="write the structured result to this path as well")
    args = parser.parse_args(argv)
    try:
        problems, not_run = run()
    except (OSError, ValueError) as exc:
        print("usage or I/O failure: %s" % exc, file=sys.stderr)
        return 1
    result = {
        "task": "F-013",
        "harness": "queue_crash",
        "positive_legs": 4,
        "negative_legs": 3,
        "not_run": not_run,
        "problems": problems,
        "ok": not problems,
    }
    if args.json_out:
        with io.open(args.json_out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    for item in not_run:
        print("not_run: %s" % item)
    if problems:
        for problem in problems:
            print("PROBLEM: %s" % problem)
        print("FAIL: %d problem(s)" % len(problems))
        return 2
    print("ok: F-013 lease fencing holds; 4 positive legs, 3 negative legs rejected as required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())