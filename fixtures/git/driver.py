#!/usr/bin/env python3
"""Deterministic driver for the fixtures/git checkpoint-input corpus (F-009).

Builds every scenario in a throwaway repository and observes it exactly the way
the checkpoint code does: `git` is launched as a program plus argv, never as an
interpolated shell string, so no Bash, WSL, Docker or administrator rights are
involved.  The observation is checked against manifest.json; the process exits
non-zero when a scenario does not match, so the driver is a real check and not a
report generator.

Usage:
    python fixtures/git/driver.py [--manifest PATH] [--json-out PATH]

Exit codes:
    0  every scenario matched the manifest
    2  at least one scenario did not match the manifest
    1  usage or I/O failure
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

STATUS = {
    "A": "added",
    "M": "modified",
    "D": "deleted",
    "R": "renamed",
    "C": "copied",
    "T": "type-changed",
    "U": "conflicted",
    "?": "untracked",
}

BYTE_COMPARE_PATH = {
    "partial-staging": "src/app.rs",
    "rename": "src/new.rs",
    "rename-without-content-change": "src/moved.rs",
    "staged-then-deleted": "src/gone.rs",
}


def git_env(home):
    env = dict(os.environ)
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "axiom-f009",
            "GIT_AUTHOR_EMAIL": "f009@example.invalid",
            "GIT_COMMITTER_NAME": "axiom-f009",
            "GIT_COMMITTER_EMAIL": "f009@example.invalid",
            "GIT_AUTHOR_DATE": "2001-02-03T04:05:06+0000",
            "GIT_COMMITTER_DATE": "2001-02-03T04:05:06+0000",
            "HOME": home,
            "USERPROFILE": home,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return env


class Repo:
    def __init__(self, env):
        self.dir = tempfile.mkdtemp(prefix="axiom-f009-")
        self.env = env
        self.init()

    def git(self, *args, expect=0):
        completed = subprocess.run(
            ["git", "-c", "core.autocrlf=false", "-c", "core.safecrlf=false", *args],
            cwd=self.dir,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if completed.returncode != expect:
            raise RuntimeError(
                "git {} exited {} (expected {}): {}".format(
                    " ".join(args),
                    completed.returncode,
                    expect,
                    completed.stderr.decode("utf-8", "replace").strip(),
                )
            )
        return completed

    def init(self):
        try:
            self.git("init", "-q", "-b", "main")
        except RuntimeError:
            self.git("init", "-q")
            self.git("symbolic-ref", "HEAD", "refs/heads/main")
        self.git("config", "user.name", "axiom-f009")
        self.git("config", "user.email", "f009@example.invalid")

    def write(self, rel, text):
        path = os.path.join(self.dir, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with io.open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)

    def remove(self, rel):
        path = os.path.join(self.dir, rel.replace("/", os.sep))
        if os.path.exists(path):
            os.remove(path)

    def commit_all(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def head(self):
        return self.git("rev-parse", "HEAD").stdout.decode("utf-8").strip()

    def porcelain(self):
        return self.git(
            "--no-optional-locks", "status", "--porcelain=v1", "-z", "--untracked-files=all"
        ).stdout

    def merge_parents(self, revision="HEAD"):
        text = self.git("cat-file", "commit", revision).stdout.decode("utf-8", "replace")
        return sum(1 for line in text.splitlines() if line.startswith("parent "))

    def index_bytes(self, path):
        completed = subprocess.run(
            ["git", "-c", "core.autocrlf=false", "show", ":" + path],
            cwd=self.dir,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if completed.returncode != 0:
            return None
        return completed.stdout

    def worktree_bytes(self, path):
        full = os.path.join(self.dir, path.replace("/", os.sep))
        if not os.path.exists(full):
            return None
        with io.open(full, "rb") as handle:
            return handle.read()


def observe(repo):
    raw = repo.porcelain()
    fields = [field for field in raw.split(b"\x00") if field]
    staged, unstaged, untracked = [], [], []
    index = 0
    while index < len(fields):
        record = fields[index].decode("utf-8", "replace")
        index += 1
        status_index = record[0]
        status_worktree = record[1]
        path = record[3:]
        origin = None
        if status_index in "RC" or status_worktree in "RC":
            origin = fields[index].decode("utf-8", "replace")
            index += 1
        if status_index == "?" and status_worktree == "?":
            untracked.append({"path": path, "status": "untracked"})
            continue
        if status_index != " ":
            entry = {"path": path, "status": STATUS.get(status_index, "unknown")}
            if origin is not None:
                entry["previous_path"] = origin
            staged.append(entry)
        if status_worktree != " ":
            entry = {"path": path, "status": STATUS.get(status_worktree, "unknown")}
            if origin is not None:
                entry["previous_path"] = origin
            unstaged.append(entry)
    return {
        "staged": staged,
        "unstaged": unstaged,
        "untracked": untracked,
        "merge_parents": repo.merge_parents(),
        "raw_status_records": [field.decode("utf-8", "replace") for field in fields],
    }


def classify(observed):
    classes = []
    staged_paths = [entry["path"] for entry in observed["staged"]]
    unstaged_paths = [entry["path"] for entry in observed["unstaged"]]
    if any(path in unstaged_paths for path in staged_paths):
        classes.append("partial-staging")
    if any(entry["status"] == "renamed" for entry in observed["staged"]):
        classes.append("rename")
    if observed["merge_parents"] >= 2:
        classes.append("merge")
    if observed["untracked"]:
        classes.append("untracked")
    return classes


def digest(data):
    if data is None:
        return None
    return hashlib.sha256(data).hexdigest()


def build(scenario, env):
    """Build one scenario and return its repository handle."""
    repo = Repo(env)
    sid = scenario["id"]
    if sid == "partial-staging":
        repo.write("src/app.rs", "value = 1\n")
        repo.commit_all("base")
        repo.write("src/app.rs", "value = 2\n")
        repo.git("add", "src/app.rs")
        repo.write("src/app.rs", "value = 3\n")
    elif sid == "rename":
        repo.write("src/old.rs", "fn kept() {}\n")
        repo.commit_all("base")
        repo.git("rm", "-q", "src/old.rs")
        repo.write("src/new.rs", "fn kept() {}\n")
        repo.git("add", "-A")
    elif sid == "merge":
        repo.write("src/base.rs", "fn base() {}\n")
        repo.write("src/left.rs", "fn left() {}\n")
        repo.write("src/right.rs", "fn right() {}\n")
        repo.commit_all("base")
        repo.git("checkout", "-q", "-b", "side")
        repo.write("src/right.rs", "fn right() { /* side */ }\n")
        repo.commit_all("side")
        repo.git("checkout", "-q", "main")
        repo.write("src/left.rs", "fn left() { /* main */ }\n")
        repo.commit_all("main")
        repo.git("merge", "--no-ff", "-q", "-m", "merge side", "side")
    elif sid == "untracked":
        repo.write("src/base.rs", "fn base() {}\n")
        repo.commit_all("base")
        repo.write("notes/new.txt", "not staged\n")
    elif sid == "rename-without-content-change":
        repo.write("src/kept.rs", "fn kept() {}\n")
        repo.commit_all("base")
        repo.git("mv", "src/kept.rs", "src/moved.rs")
    elif sid == "staged-then-deleted":
        repo.write("src/gone.rs", "fn gone() {}\n")
        repo.commit_all("base")
        repo.write("src/gone.rs", "fn gone() { /* staged */ }\n")
        repo.git("add", "src/gone.rs")
        repo.remove("src/gone.rs")
    else:
        raise RuntimeError("unknown scenario: " + sid)
    return repo


def main():
    parser = argparse.ArgumentParser(description="F-009 git checkpoint-input fixture driver")
    parser.add_argument("--manifest", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifest.json"))
    parser.add_argument("--json-out")
    arguments = parser.parse_args()

    with io.open(arguments.manifest, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    version = subprocess.run(["git", "--version"], stdout=subprocess.PIPE).stdout.decode("utf-8").strip()
    home = tempfile.mkdtemp(prefix="axiom-f009-home-")
    env = git_env(home)

    results = []
    ok = True
    for scenario in manifest["scenarios"]:
        repo = build(scenario, env)
        observed = observe(repo)
        classes = classify(observed)
        compare_path = BYTE_COMPARE_PATH.get(scenario["id"])
        index_data = repo.index_bytes(compare_path) if compare_path else None
        worktree_data = repo.worktree_bytes(compare_path) if compare_path else None
        observed["staged_bytes_equal_worktree_bytes"] = (
            index_data == worktree_data if compare_path else True
        )
        expected = scenario["expected"]
        matches = (
            observed["staged"] == expected["staged"]
            and observed["unstaged"] == expected["unstaged"]
            and observed["untracked"] == expected["untracked"]
            and observed["merge_parents"] == expected["merge_parents"]
            and observed["staged_bytes_equal_worktree_bytes"] == expected["staged_bytes_equal_worktree_bytes"]
            and classes == scenario["must_distinguish"]
        )
        ok = ok and matches
        results.append(
            {
                "id": scenario["id"],
                "kind": scenario.get("kind", "primary"),
                "classes": classes,
                "must_distinguish": scenario["must_distinguish"],
                "expected_outcome": scenario["expected_outcome"],
                "observed": observed,
                "expected": expected,
                "byte_compare_path": compare_path,
                "index_blob_sha256": digest(index_data),
                "worktree_blob_sha256": digest(worktree_data),
                "matches": matches,
            }
        )

    report = {
        "corpus": manifest["corpus"],
        "task": manifest["task"],
        "driver": "fixtures/git/driver.py",
        "git_version": version,
        "manifest": os.path.basename(arguments.manifest),
        "scenarios": results,
        "ok": ok,
    }
    text = json.dumps(report, indent=2) + "\n"
    if arguments.json_out:
        with io.open(arguments.json_out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    sys.stdout.write(text)
    return 0 if ok else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:  # noqa: BLE001 - the driver reports its own failures
        sys.stderr.write("driver failed: {}\n".format(error))
        sys.exit(1)
