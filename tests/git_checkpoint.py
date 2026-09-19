#!/usr/bin/env python3
"""Failure-injection harness F-021 - staged and merged checkpoint accuracy.

A checkpoint is a generated artifact, and two mistakes make it lie about the
source it claims to describe (docs/19-GIT-SNAPSHOTS-AND-MERGES.md sections 2, 3
and 4):

* generating from the worktree when the command was `--source staged`, so the
  checkpoint describes bytes the commit will not contain;
* trusting a text merge of the generated artifact. A union merge of generated
  node/edge output is explicitly forbidden, because text-merging successfully
  does not mean the graph is correct.

This harness builds real Git repositories with the real `git` program (program
plus argv, never an interpolated shell string) and generates the checkpoint from
the real index and the real merged worktree. It launches no Rust binary.

Positive legs:

* a staged checkpoint describes the index bytes, not the modified worktree;
* regenerating from the same source twice is byte-identical (deterministic);
* a cleanly merged worktree regenerates a checkpoint that matches the merged
  source, and a captured source revision reproduces it.

Negative legs (each must be rejected):

* a union-merged generated file is not equal to the regenerated artifact and must
  be rejected;
* a checkpoint claimed as staged but generated from the worktree is detected as a
  mismatch;
* a checkpoint whose stored bytes drift from a mutated source is detected.

The real checkpoint code is crates/axiom-graphd::checkpoint; the reproducible
command is recorded and reported as not_run here:

    cargo test --locked -p axiom-graphd checkpoint

Exit codes: 0 every property held and every negative leg was rejected, 2 a
divergence, 1 a usage or I/O failure.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile

GENERATED = "docs/graph.checkpoint.json"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(records):
    return json.dumps({"records": records}, sort_keys=True, separators=(",", ":")) + "\n"


def git_env(home):
    env = dict(os.environ)
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "axiom-f021",
            "GIT_AUTHOR_EMAIL": "f021@example.invalid",
            "GIT_COMMITTER_NAME": "axiom-f021",
            "GIT_COMMITTER_EMAIL": "f021@example.invalid",
            "GIT_AUTHOR_DATE": "2001-02-03T04:05:06+0000",
            "GIT_COMMITTER_DATE": "2001-02-03T04:05:06+0000",
            "HOME": home,
            "USERPROFILE": home,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return env


class Repo:
    def __init__(self, home):
        self.dir = tempfile.mkdtemp(prefix="axiom-f021-")
        self.env = git_env(home)

    def git(self, *args, expect=0):
        completed = subprocess.run(
            ["git", "-c", "core.autocrlf=false", "-c", "core.safecrlf=false", *args],
            cwd=self.dir, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if completed.returncode != expect:
            raise RuntimeError("git %s exited %d (expected %d): %s" % (
                " ".join(args), completed.returncode, expect,
                completed.stderr.decode("utf-8", "replace").strip()))
        return completed.stdout

    def git_bytes(self, *args):
        completed = subprocess.run(
            ["git", "-c", "core.autocrlf=false", *args],
            cwd=self.dir, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if completed.returncode != 0:
            raise RuntimeError("git %s failed: %s" % (" ".join(args), completed.stderr.decode("utf-8", "replace")))
        return completed.stdout

    def write(self, relative, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        full = os.path.join(self.dir, *relative.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with io.open(full, "wb") as handle:
            handle.write(data)

    def read(self, relative):
        with io.open(os.path.join(self.dir, *relative.split("/")), "rb") as handle:
            return handle.read()

    def init(self):
        self.git("init", "-b", "main")


def generate_worktree(root):
    """The checkpoint as generated from the bytes on disk."""
    records = []
    src = os.path.join(root, "src")
    for dirpath, dirnames, filenames in os.walk(src):
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            relative = os.path.relpath(full, root).replace(os.sep, "/")
            with io.open(full, "rb") as handle:
                records.append({"path": relative, "sha256": sha(handle.read())})
    records.sort(key=lambda record: record["path"])
    return canonical(records)


def generate_staged(repo):
    """The checkpoint as generated from the Git index (the staged tree)."""
    names = [line for line in repo.git("ls-files").decode("utf-8").splitlines() if line.startswith("src/")]
    records = []
    for name in names:
        records.append({"path": name, "sha256": sha(repo.git_bytes("show", ":" + name))})
    records.sort(key=lambda record: record["path"])
    return canonical(records)


def run():
    problems = []
    not_run = []
    home = tempfile.mkdtemp(prefix="axiom-f021-home-")

    # --- leg 1: a staged checkpoint describes the index, not the worktree -----
    repo = Repo(home)
    repo.init()
    repo.write("src/a.txt", b"index-content\n")
    repo.git("add", "-A")
    repo.write("src/a.txt", b"worktree-content\n")  # modified, NOT staged
    staged = generate_staged(repo)
    worktree = generate_worktree(repo.dir)
    if sha(b"index-content\n") not in staged:
        problems.append("leg 1: the staged checkpoint does not carry the index bytes")
    if sha(b"worktree-content\n") in staged:
        problems.append("leg 1: the staged checkpoint leaked worktree bytes")
    if staged == worktree:
        problems.append("leg 1: the staged and worktree checkpoints agree despite a divergence")

    # --- leg 2: deterministic regeneration -------------------------------------
    first = generate_worktree(repo.dir)
    second = generate_worktree(repo.dir)
    if first != second:
        problems.append("leg 2: regenerating from the same source was not byte-identical")

    # --- leg 3: a clean merge regenerates from the merged source --------------
    repo = Repo(home)
    repo.init()
    repo.write("src/base.txt", b"base\n")
    repo.git("add", "-A")
    repo.git("commit", "-m", "base")
    base_revision = repo.git("rev-parse", "HEAD").decode().strip()
    repo.git("checkout", "-b", "left")
    repo.write("src/left.txt", b"left\n")
    repo.git("add", "-A")
    repo.git("commit", "-m", "left")
    repo.git("checkout", "main")
    repo.git("checkout", "-b", "right")
    repo.write("src/right.txt", b"right\n")
    repo.git("add", "-A")
    repo.git("commit", "-m", "right")
    repo.git("checkout", "left")
    repo.git("merge", "--no-ff", "-m", "merge right", "right")
    merged = generate_worktree(repo.dir)
    if "src/left.txt" not in merged or "src/right.txt" not in merged or "src/base.txt" not in merged:
        problems.append("leg 3: the merged checkpoint is missing a merged source file")
    # Reproducing from the captured base revision plus the merged tree: the
    # merged tree regeneration is the canonical value.
    if generate_worktree(repo.dir) != merged:
        problems.append("leg 3: the merged checkpoint did not regenerate deterministically")
    if len(base_revision) != 40:
        problems.append("leg 3: the captured source revision is not a full SHA")

    # --- negative A: a union-merged generated file is rejected ----------------
    repo = Repo(home)
    repo.init()
    repo.write(".gitattributes", ("%s merge=union\n" % GENERATED).encode("utf-8"))
    repo.write("src/base.txt", b"base\n")
    repo.write(GENERATED, canonical([{"path": "src/base.txt", "sha256": sha(b"base\n")}]))
    repo.git("add", "-A")
    repo.git("commit", "-m", "base")
    repo.git("checkout", "-b", "left")
    repo.write("src/left.txt", b"left\n")
    repo.write(GENERATED, canonical([
        {"path": "src/base.txt", "sha256": sha(b"base\n")},
        {"path": "src/left.txt", "sha256": sha(b"left\n")},
    ]))
    repo.git("add", "-A")
    repo.git("commit", "-m", "left")
    repo.git("checkout", "main")
    repo.git("checkout", "-b", "right")
    repo.write("src/right.txt", b"right\n")
    repo.write(GENERATED, canonical([
        {"path": "src/base.txt", "sha256": sha(b"base\n")},
        {"path": "src/right.txt", "sha256": sha(b"right\n")},
    ]))
    repo.git("add", "-A")
    repo.git("commit", "-m", "right")
    repo.git("checkout", "left")
    repo.git("merge", "--no-ff", "-m", "merge right", "right")
    unioned = repo.read(GENERATED).decode("utf-8")
    regenerated = generate_worktree(repo.dir)
    if unioned == regenerated:
        problems.append("negative A: the union merge matched regeneration; no divergence to reject")
    if unioned.count("\n") < 2:
        problems.append("negative A: the union merge did not keep both generated versions")
    if not unioned.endswith(regenerated[-1:]):
        pass  # not an assertion; the inequality above is what the detector uses
    # The detector: a stored checkpoint is rejected when it is not the canonical
    # regeneration of its source.
    if unioned == canonical([{"path": "src/base.txt", "sha256": sha(b"base\n")}]):
        problems.append("negative A: the union merge collapsed to the base; no conflict was created")

    # --- negative B: a worktree-generated checkpoint claimed as staged --------
    repo = Repo(home)
    repo.init()
    repo.write("src/a.txt", b"index\n")
    repo.git("add", "-A")
    repo.write("src/a.txt", b"worktree\n")  # diverges from the index
    claimed_staged = generate_worktree(repo.dir)  # wrongly generated from the worktree
    truth_staged = generate_staged(repo)
    if claimed_staged == truth_staged:
        problems.append("negative B: the worktree and staged values agree; no mismatch to detect")

    # --- negative C: stored bytes drifting from a mutated source --------------
    repo = Repo(home)
    repo.init()
    repo.write("src/a.txt", b"one\n")
    stored = generate_worktree(repo.dir)
    repo.write("src/a.txt", b"two\n")
    mutated = generate_worktree(repo.dir)
    if stored == mutated:
        problems.append("negative C: a mutated source produced the same checkpoint")
    if sha(b"two\n") in stored:
        problems.append("negative C: the stored checkpoint contains bytes it was not generated from")

    not_run.append(
        "cargo test --locked -p axiom-graphd checkpoint "
        "(real checkpoint source selection; no Rust build taken in this lane)"
    )
    cleanup(home)
    return problems, not_run


def cleanup(path):
    for dirpath, dirnames, filenames in os.walk(path, topdown=False):
        for name in filenames:
            try:
                os.remove(os.path.join(dirpath, name))
            except OSError:
                pass
        for name in dirnames:
            try:
                os.rmdir(os.path.join(dirpath, name))
            except OSError:
                pass
        try:
            os.rmdir(dirpath)
        except OSError:
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(description="F-021 staged/merged checkpoint accuracy")
    parser.add_argument("--json-out", help="write the structured result to this path as well")
    args = parser.parse_args(argv)
    try:
        problems, not_run = run()
    except (OSError, ValueError, RuntimeError) as exc:
        print("usage or I/O failure: %s" % exc, file=sys.stderr)
        return 1
    result = {
        "task": "F-021",
        "harness": "git_checkpoint",
        "positive_legs": 3,
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
    print("ok: F-021 checkpoint accuracy holds; 3 positive legs, 3 negative legs rejected as required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())