#!/usr/bin/env python3
"""Non-destructive multi-repo bootstrap end-to-end harness (task F-032).

The F-008 corpus (`fixtures/bootstrap/vectors/`) is per-vector and single
repository: it proves the managed-merge algorithm one repository at a time. The
E-022/E-023 update flow that F-032 exists to cover is multi-repository, so the
property under test here is different and larger: when one repository is a
conflict, the other repositories must still be planned and reported on their own
terms, nothing may be written outside the owned paths, no human byte may move,
and nothing may be committed or pushed without an explicit grant.

What is real here:

* every byte that is read or written is a real file in a real temporary tree,
  seeded from the checked-in corpus and from the checked-in templates;
* the multi-repository leg runs against **real Git repositories** - real
  `git init`, a real commit, a real bare remote - launched as program plus
  argv, never through an interpolated shell string. "No automatic commit" and
  "no automatic push" are therefore checked against real refs: the repository
  HEAD must not move and `git ls-remote` on the real remote must stay empty;
* the managed-merge oracle is a faithful port of the documented algorithm that
  `crates/axiom-graphd/tests/bootstrap_fixtures.rs` already carries, so the
  Python model and the Rust model cannot silently disagree;
* the corpus replay is a real regression test: all 16 checked-in vectors are
  replayed against their checked-in before-trees, and the pinned template
  digests are re-verified before any vector runs.

What is modelled, and reported `not_run`:

* the production Rust engine. `crates/axiom/src/bootstrap/` is the real
  implementation of planning, applying, journalling, rolling back and the
  commit grant; this harness cannot link it. The equivalent real commands are
  kept in the file and reported `not_run`;
* a real host installation, a real `axiom` CLI invocation and native
  Windows/macOS runtime evidence.

Boundaries that are easy to miss, and which this harness checks on every run:

* one conflicted repository must not block the others, and every repository must
  appear exactly once in the report - a repository that is silently dropped is
  a failure here even though nothing was overwritten;
* the conflicted repository must keep **every** byte, not only the managed
  block;
* the update compatibility gate runs before a repository is read, so a refused
  downgrade or major change must write nothing at all, in any repository;
* a plan that would write a path outside the owned set, or an append that does
  not keep the previous document as an exact prefix, is refused;
* a commit with no grant is refused, and the "no commit happened" detector has
  teeth: a real commit and a real push must be caught by it.

Exit codes: 0 every property held and every negative leg was rejected, 2 a
divergence (printed as `PROBLEM:`), 1 a usage or I/O failure. The harness is a
standalone Python 3 program: no third-party dependencies, no network, no shell
interpolation.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

BOM = b"\xef\xbb\xbf"
OWNERSHIP_SCHEMA_VERSION = 2

AGENTS_PATH = "AGENTS.md"
POLICY_PATH = ".axiom/agent/POLICY.md"
OWNERSHIP_PATH = ".axiom/agent/bootstrap.lock.json"
OWNED_PATHS = (AGENTS_PATH, POLICY_PATH, OWNERSHIP_PATH)

# Stable rule codes, taken from the production constants in
# `crates/axiom/src/bootstrap/`.
RULE_MARKERS_MALFORMED = "markers-malformed"
RULE_MARKERS_WITHOUT_OWNERSHIP = "ownership-absent-with-markers"
RULE_POLICY_UNOWNED = "policy-unowned"
RULE_BLOCK_REMOVED = "ownership-block-removed"
RULE_BLOCK_EDITED = "ownership-block-edited"
RULE_POLICY_REMOVED = "ownership-policy-removed"
RULE_POLICY_EDITED = "ownership-policy-edited"
RULE_OWNERSHIP_MALFORMED = "ownership-malformed"
RULE_OWNERSHIP_SCHEMA = "ownership-schema"
RULE_PLAN_MALFORMED = "plan-malformed"
RULE_UPDATE_DOWNGRADE = "update-template-downgrade"
RULE_UPDATE_MAJOR = "update-template-major-change"
RULE_UPDATE_UNOWNED_PATH = "update-unowned-path"
RULE_UPDATE_OUTSIDE = "update-outside-owned-span"
RULE_COMMIT_GRANT = "commit-grant-required"
RULE_COMMIT_UNOWNED_PATH = "commit-unowned-path"
RULE_COMMIT_EMPTY = "commit-nothing-to-plan"

OUTCOMES = ("append", "replace", "unchanged", "conflict")

# The production git argv prefix. Program plus argv; there is no shell string
# anywhere in this file, and no user or environment value is interpolated into
# an argument.
GIT_CONFIG = (
    "-c",
    "core.autocrlf=false",
    "-c",
    "user.name=axiom-agent",
    "-c",
    "user.email=agent@axiom.local",
    "-c",
    "commit.gpgsign=false",
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_opt(path: str):
    """Bytes of a file, or None when it does not exist."""
    try:
        with io.open(path, "rb") as handle:
            return handle.read()
    except FileNotFoundError:
        return None


def split_inclusive_newline(raw: bytes):
    parts = raw.split(b"\n")
    lines = []
    for position, part in enumerate(parts):
        if position < len(parts) - 1:
            lines.append(part + b"\n")
        elif part:
            lines.append(part)
    return lines


def fence_run(line: str):
    """Leading Markdown fence run: (character, run length, blank remainder)."""
    rest = line
    spaces = 0
    while spaces < 3 and rest.startswith(" "):
        rest = rest[1:]
        spaces += 1
    if not rest:
        return None
    fence_char = rest[0]
    if fence_char not in ("`", "~"):
        return None
    run = 0
    for char in rest:
        if char != fence_char:
            break
        run += 1
    if run < 3:
        return None
    return (fence_char, run, rest[run:].strip() == "")


def managed_span(raw: bytes, begin: str, end: str):
    """Byte span of the single managed block, or (None, None), or (None, error).

    Offsets are byte offsets, exactly as the documented oracle computes them, so
    a multi-byte character before the block cannot shift the span. Markers
    inside a fenced code block are examples, not markers.
    """
    offset = 0
    found = []
    fence = None
    for line in split_inclusive_newline(raw):
        plain = line.rstrip(b"\r\n")
        clean_bytes = plain.lstrip(BOM) if offset == 0 else plain
        clean = clean_bytes.decode("utf-8", "replace")
        run = fence_run(clean)
        if run is not None:
            char, length, remainder_blank = run
            if fence is None:
                fence = (char, length)
            elif fence[0] == char and length >= fence[1] and remainder_blank:
                fence = None
        elif fence is None:
            trimmed = clean.strip()
            if trimmed == begin or trimmed == end:
                start = offset
                if offset == 0 and plain.startswith(BOM):
                    start = offset + len(BOM)
                found.append((trimmed == begin, start, offset + len(plain)))
        offset += len(line)
    if not found:
        return (None, None)
    if len(found) != 2 or not found[0][0] or found[1][0]:
        return (None, "Duplicate, nested or unbalanced managed markers")
    return ((found[0][1], found[1][2]), None)


def ownership_bytes(template_version: str, block_hash: str, policy_hash: str) -> bytes:
    return (
        '{"managed_block_sha256":"%s","policy_sha256":"%s","schema_version":%d,"template_version":"%s"}\n'
        % (block_hash, policy_hash, OWNERSHIP_SCHEMA_VERSION, template_version)
    ).encode("utf-8")


def plan_repository(root: str, contract: dict, block_template: str, policy: bytes):
    """The documented managed-merge oracle.

    Returns (change, writes, refusal) where `writes` is a list of
    (repository-relative path, bytes) and `refusal` is None or (rule, message).
    A refused repository carries no writes at all: the result is never partial.
    """
    begin = contract["begin_marker"]
    end = contract["end_marker"]
    agents_raw = read_opt(os.path.join(root, AGENTS_PATH))
    policy_raw = read_opt(os.path.join(root, POLICY_PATH))
    ownership_raw = read_opt(os.path.join(root, OWNERSHIP_PATH))

    ownership = None
    if ownership_raw is not None:
        try:
            ownership = json.loads(ownership_raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            return "conflict", [], (RULE_OWNERSHIP_MALFORMED, "Malformed ownership manifest: %s" % exc)
        if ownership.get("schema_version") != OWNERSHIP_SCHEMA_VERSION:
            return "conflict", [], (RULE_OWNERSHIP_SCHEMA, "Unsupported ownership schema")

    if agents_raw is None:
        agents = ""
    else:
        try:
            agents = agents_raw.decode("utf-8")
        except UnicodeDecodeError:
            return "conflict", [], (RULE_OWNERSHIP_MALFORMED, "Unsupported encoding; this contract is UTF-8 only")

    span, marker_error = managed_span(agents_raw or b"", begin, end)
    if marker_error is not None:
        return "conflict", [], (RULE_MARKERS_MALFORMED, marker_error)

    if ownership is None:
        if span is not None:
            return "conflict", [], (RULE_MARKERS_WITHOUT_OWNERSHIP, "Managed markers exist without ownership")
        if policy_raw is not None:
            return "conflict", [], (RULE_POLICY_UNOWNED, "Existing policy file is unowned; refusing to overwrite it")
    else:
        if span is None:
            return "conflict", [], (RULE_BLOCK_REMOVED, "Managed AGENTS block was removed or edited")
        start, finish = span
        if sha256_hex(agents_raw[start:finish]) != ownership.get("managed_block_sha256"):
            return "conflict", [], (RULE_BLOCK_EDITED, "Managed AGENTS block was edited")
        if policy_raw is None:
            return "conflict", [], (RULE_POLICY_REMOVED, "Managed policy was removed or edited")
        if sha256_hex(policy_raw) != ownership.get("policy_sha256"):
            return "conflict", [], (RULE_POLICY_EDITED, "Managed policy was removed or edited")

    newline = "\r\n" if "\r\n" in agents else "\n"
    template = block_template.strip("\r\n")
    new_block = template.replace("\r\n", "\n").replace("\n", newline)
    if span is not None:
        start, finish = span
        after_agents = agents_raw[:start] + new_block.encode("utf-8") + agents_raw[finish:]
    else:
        if not agents:
            suffix = ""
        elif agents.endswith("\n") or agents.endswith("\r"):
            suffix = newline
        else:
            suffix = newline + newline
        after_agents = agents.encode("utf-8") + suffix.encode("utf-8") + new_block.encode("utf-8") + newline.encode("utf-8")

    after_span, after_error = managed_span(after_agents, begin, end)
    if after_error is not None or after_span is None:
        return "conflict", [], (RULE_PLAN_MALFORMED, "Planned content lost its managed block")
    block_start, block_end = after_span
    block_hash = sha256_hex(after_agents[block_start:block_end])
    policy_hash = sha256_hex(policy)

    writes = []
    if agents_raw != after_agents:
        writes.append((AGENTS_PATH, after_agents))
    if policy_raw != policy:
        writes.append((POLICY_PATH, policy))
    ownership_current = (
        ownership is not None
        and ownership.get("managed_block_sha256") == block_hash
        and ownership.get("policy_sha256") == policy_hash
    )
    if not ownership_current:
        writes.append(
            (OWNERSHIP_PATH, ownership_bytes(contract["template_version"], block_hash, policy_hash))
        )

    if not writes:
        change = "unchanged"
    elif span is not None:
        change = "replace"
    else:
        change = "append"
    return change, writes, None


def apply_writes(root: str, writes) -> list:
    """Write the planned bytes, creating parents. Returns the paths written."""
    written = []
    for relative, data in writes:
        path = os.path.join(root, relative.replace("/", os.sep))
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with io.open(path, "wb") as handle:
            handle.write(data)
        written.append(relative)
    return written


def snapshot_tree(root: str) -> dict:
    """repository-relative path -> exact bytes, for byte-exact comparisons."""
    snapshot = {}
    for current, _directories, files in os.walk(root):
        for name in files:
            path = os.path.join(current, name)
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            snapshot[relative] = read_opt(path) or b""
    return snapshot


def copy_tree(source: str, destination: str) -> None:
    for relative, data in snapshot_tree(source).items():
        path = os.path.join(destination, relative.replace("/", os.sep))
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with io.open(path, "wb") as handle:
            handle.write(data)


def corpus_root(repo_root: str) -> str:
    return os.path.join(repo_root, "fixtures", "bootstrap")


def load_corpus(repo_root: str):
    """The checked-in contract, its templates and its digests, re-verified."""
    root = corpus_root(repo_root)
    with io.open(os.path.join(root, "vectors.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    contract = manifest["contract"]
    with io.open(os.path.join(root, contract["block_template"]), encoding="utf-8") as handle:
        block_template = handle.read()
    policy = read_opt(os.path.join(root, contract["policy_template"]))
    if policy is None:
        raise ValueError("missing policy template %s" % contract["policy_template"])
    return root, manifest, contract, block_template, policy


def verify_pinned_digests(contract, block_template, policy, problems):
    """The corpus pins its own digests; a drifted template must fail loudly."""
    if sha256_hex(block_template.encode("utf-8")) != contract["block_file_sha256"]:
        problems.append("block template drifted from its pinned digest")
    if (
        sha256_hex(block_template.strip("\r\n").encode("utf-8"))
        != contract["block_span_sha256"]
    ):
        problems.append("managed block span drifted from its pinned digest")
    if sha256_hex(policy) != contract["policy_sha256"]:
        problems.append("policy template drifted from its pinned digest")


def replay_corpus(corpus, contract, block_template, policy, shard, problems):
    """Replay every checked-in vector; returns the per-vector result rows."""
    root, manifest, _, _, _ = corpus
    rows = []
    for vector in manifest["vectors"]:
        vector_id = vector["id"]
        before = os.path.join(root, "vectors", vector_id, "before")
        repository = os.path.join(shard, "corpus", vector_id)
        copy_tree(before, repository)
        before_snapshot = snapshot_tree(repository)
        before_agents = before_snapshot.get(AGENTS_PATH)

        change, writes, refusal = plan_repository(repository, contract, block_template, policy)
        expected = sorted(path.replace("\\", "/") for path in vector.get("changes", []))
        row = {
            "id": vector_id,
            "expected": vector["outcome"],
            "planned": change,
            "writes": sorted(relative for relative, _ in writes),
            "refusal_rule": refusal[0] if refusal else None,
        }
        rows.append(row)

        if vector["outcome"] == "conflict":
            if refusal is None:
                problems.append("%s must be refused, not planned" % vector_id)
                continue
            needle = vector.get("reason_contains")
            if needle and needle.lower() not in refusal[1].lower():
                problems.append(
                    "%s refusal %r does not mention %r" % (vector_id, refusal[1], needle)
                )
            if writes:
                problems.append("%s refused but still planned %d writes" % (vector_id, len(writes)))
            continue

        if refusal is not None:
            problems.append("%s must not conflict: %s" % (vector_id, refusal[1]))
            continue
        if change != vector["outcome"]:
            problems.append(
                "%s planned %s, the corpus records %s" % (vector_id, change, vector["outcome"])
            )
        actual = sorted(relative for relative, _ in writes)
        if actual != expected:
            problems.append("%s changed %r, the corpus records %r" % (vector_id, actual, expected))

        apply_writes(repository, writes)

        after_snapshot = snapshot_tree(repository)
        for relative, original in before_snapshot.items():
            if relative in expected:
                continue
            if after_snapshot.get(relative) != original:
                problems.append("%s rewrote unowned path %s" % (vector_id, relative))

        agents = after_snapshot.get(AGENTS_PATH, b"")
        if vector.get("expect_bom"):
            if not agents.startswith(BOM) or agents[len(BOM):].startswith(BOM):
                problems.append("%s lost or duplicated its leading BOM" % vector_id)
        elif agents.startswith(BOM):
            problems.append("%s gained a BOM it did not have" % vector_id)

        try:
            text = agents.decode("utf-8")
        except UnicodeDecodeError:
            problems.append("%s produced a non-UTF-8 AGENTS.md" % vector_id)
            continue
        span, error = managed_span(agents, contract["begin_marker"], contract["end_marker"])
        if error is not None or span is None:
            problems.append("%s produced invalid managed markers" % vector_id)
            continue
        start, finish = span
        if vector.get("expect_crlf") and "\r\n" not in agents[start:finish].decode("utf-8"):
            problems.append("%s did not keep CRLF inside the managed block" % vector_id)
        if not vector.get("expect_crlf") and "\r\n" in agents[start:finish].decode("utf-8"):
            problems.append("%s introduced CRLF into an LF managed block" % vector_id)
        if vector.get("expect_prefix"):
            if before_agents is None or not agents.startswith(before_agents):
                problems.append("%s did not keep the original bytes as an exact prefix" % vector_id)
        for literal in vector.get("preserve_literals", []):
            if literal not in text:
                problems.append("%s dropped the preserved literal %r" % (vector_id, literal))
    return rows


def git_env(home: str) -> dict:
    env = dict(os.environ)
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_DATE": "2001-02-03T04:05:06+0000",
            "GIT_COMMITTER_DATE": "2001-02-03T04:05:06+0000",
            "HOME": home,
            "USERPROFILE": home,
        }
    )
    return env


def git_run(args, cwd: str, env: dict, expect=0):
    """Run the real git program as program plus argv. Never a shell string."""
    completed = subprocess.run(
        ["git", *GIT_CONFIG, *args],
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != expect:
        raise RuntimeError(
            "git %s exited %d (expected %d): %s"
            % (
                " ".join(args),
                completed.returncode,
                expect,
                completed.stderr.decode("utf-8", "replace").strip(),
            )
        )
    return completed.stdout


def snapshot_tracked(root: str) -> dict:
    """snapshot_tree without the Git metadata directory, for byte comparisons."""
    return {
        relative: data
        for relative, data in snapshot_tree(root).items()
        if not relative.startswith(".git/")
    }


class GitRepository:
    """A real Git repository in a real directory; a real remote can be pushed to."""

    def __init__(self, root: str, name: str, home: str):
        self.name = name
        self.dir = os.path.join(root, name)
        os.makedirs(self.dir, exist_ok=True)
        self.env = git_env(home)

    def git(self, *args, expect=0):
        return git_run(list(args), self.dir, self.env, expect)

    def write(self, relative: str, data) -> None:
        if isinstance(data, str):
            data = data.encode("utf-8")
        target = os.path.join(self.dir, relative.replace("/", os.sep))
        parent = os.path.dirname(target)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with io.open(target, "wb") as handle:
            handle.write(data)

    def read(self, relative: str):
        return read_opt(os.path.join(self.dir, relative.replace("/", os.sep)))

    def head(self) -> str:
        return self.git("rev-parse", "HEAD").decode("utf-8").strip()

    def seed(self, snapshot: dict, remote: str) -> str:
        """Lay down a before-tree, make it a real repository, publish it."""
        self.git("init", "-b", "main")
        for relative, data in snapshot.items():
            self.write(relative, data)
        self.git("add", "--all")
        self.git("commit", "-m", "seed %s" % self.name)
        self.git("remote", "add", "origin", remote)
        self.git("push", "--quiet", "origin", "main")
        return self.head()

    def commit_all(self, message: str) -> str:
        self.git("add", "--all")
        self.git("commit", "-m", message)
        return self.head()


def remote_head(remote: str, cwd: str, env: dict):
    """The real remote ref, read with the real git program over the real remote."""
    stdout = git_run(["ls-remote", remote, "refs/heads/main"], cwd, env)
    text = stdout.decode("utf-8").strip()
    if not text:
        return None
    return text.split("\t")[0].strip()


def compare_versions(old: str, new: str) -> str:
    """The documented update compatibility gate verdict."""

    def numbers(value: str):
        core = value.split("-", 1)[0]
        return tuple(int(piece) for piece in core.split("."))

    old_parts, new_parts = numbers(old), numbers(new)
    if old_parts == new_parts:
        return "same"
    if new_parts < old_parts:
        return "downgrade"
    if old_parts[0] != new_parts[0]:
        return "major-change"
    return "newer"


def compatibility_refusal(old: str, new: str):
    verdict = compare_versions(old, new)
    if verdict == "downgrade":
        return (
            RULE_UPDATE_DOWNGRADE,
            "Refusing to replace template %s with the older %s" % (old, new),
        )
    if verdict == "major-change":
        return (
            RULE_UPDATE_MAJOR,
            "Refusing a template major change %s -> %s" % (old, new),
        )
    return None


def ensure_owned_paths(writes, owned=OWNED_PATHS):
    for relative, _data in writes:
        if relative not in owned:
            return (
                RULE_UPDATE_UNOWNED_PATH,
                "Refusing to write %s outside the owned set" % relative,
            )
    return None


def ensure_only_owned_span(before: bytes, after: bytes, span):
    """An append must keep the previous bytes as an exact prefix; a replace may
    only change the bytes inside the managed span."""
    if span is None:
        if not after.startswith(before):
            return (
                RULE_UPDATE_OUTSIDE,
                "An append must keep the previous document as an exact prefix",
            )
        return None
    start, finish = span
    tail = len(before) - finish
    if after[:start] != before[:start]:
        return (RULE_UPDATE_OUTSIDE, "A replace changed bytes before the managed span")
    if tail and after[-tail:] != before[finish:]:
        return (RULE_UPDATE_OUTSIDE, "A replace changed bytes after the managed span")
    return None


def plan_commit(writes, grant):
    if not writes:
        return (RULE_COMMIT_EMPTY, "Nothing to commit")
    unowned = ensure_owned_paths(writes)
    if unowned is not None:
        return (RULE_COMMIT_UNOWNED_PATH, unowned[1])
    if not grant or not grant.get("approved"):
        return (RULE_COMMIT_GRANT, "Refusing to commit without an explicit grant")
    return None


def apply_commit(repository, writes, grant):
    refusal = plan_commit(writes, grant)
    if refusal is not None:
        return refusal
    apply_writes(repository.dir, writes)
    repository.commit_all("bootstrap update (granted)")
    return None


def drive_update(roots, old_version, new_version, contract, block_template, policy):
    """The documented update driver: the compatibility gate runs first, before
    any repository is read, and a refused gate plans nothing at all."""
    refusal = compatibility_refusal(old_version, new_version)
    if refusal is not None:
        return {}, refusal
    report = {}
    for name in sorted(roots):
        change, writes, repo_refusal = plan_repository(
            roots[name], contract, block_template, policy
        )
        report[name] = (change, writes, repo_refusal)
    return report, None


def sequence_multi_repository(shard, corpus, contract, block_template, policy, problems):
    """A real multi-repository update in which exactly one repository conflicts."""
    root = corpus[0]
    home = os.path.join(shard, "git-home")
    os.makedirs(home, exist_ok=True)
    workspace = os.path.join(shard, "multi")
    os.makedirs(workspace, exist_ok=True)
    env = git_env(home)

    # "hot" is genuinely conflicted: its before-tree is the edited_managed_block
    # vector, whose managed block no longer matches its ownership manifest. The
    # other two are a real append and a real replace.
    plan = [
        ("hot", "edited_managed_block"),
        ("warm", "lf_no_markers_human_text"),
        ("cool", "bom_managed_block_reapply"),
    ]
    repositories = {}
    before = {}
    seed_heads = {}
    remotes = {}
    remote_before = {}
    # Every repository is an independent history, so every repository gets its
    # own real bare remote; a shared branch would reject a legitimate seed push.
    for name, vector_id in plan:
        remote = os.path.join(workspace, "%s.git" % name)
        git_run(["init", "--bare", "-b", "main", remote], workspace, env)
        repository = GitRepository(workspace, name, home)
        snapshot = snapshot_tracked(os.path.join(root, "vectors", vector_id, "before"))
        seed_heads[name] = repository.seed(snapshot, remote)
        repositories[name] = repository
        before[name] = snapshot
        remotes[name] = remote
        remote_before[name] = remote_head(remote, workspace, env)
        if remote_before[name] != seed_heads[name]:
            problems.append(
                "multi-repo: %s seeded remote is %r, not its seeded commit %r"
                % (name, remote_before[name], seed_heads[name])
            )

    def plan_all(order):
        rows = []
        for name, _vector_id in order:
            change, writes, refusal = plan_repository(
                repositories[name].dir, contract, block_template, policy
            )
            rows.append((name, change, writes, refusal))
        return rows

    forward = plan_all(plan)
    backward = plan_all(list(reversed(plan)))
    by_name = {name: (change, writes, refusal) for name, change, writes, refusal in forward}

    for name, change, writes, refusal in backward:
        other = by_name[name]
        if (other[0], other[2]) != (change, refusal):
            problems.append(
                "multi-repo: %s planned %s in the reversed order but %s in the forward order"
                % (name, change, other[0])
            )
        if sorted(item for item, _ in other[1]) != sorted(item for item, _ in writes):
            problems.append(
                "multi-repo: %s planned different paths in the reversed order" % name
            )

    reported = [name for name, _c, _w, _r in forward]
    if sorted(reported) != sorted(name for name, _ in plan):
        problems.append("multi-repo: the report did not carry every repository: %r" % reported)
    if len(set(reported)) != len(reported):
        problems.append("multi-repo: a repository was reported more than once: %r" % reported)

    conflicted = [name for name, _c, _w, refusal in forward if refusal is not None]
    if conflicted != ["hot"]:
        problems.append("multi-repo: expected exactly one conflicted repository, saw %r" % conflicted)
    hot_refusal = by_name["hot"][2]
    if hot_refusal is None or hot_refusal[0] != RULE_BLOCK_EDITED:
        problems.append("multi-repo: the edited repository was not refused as an edited block")

    for name, change, writes, refusal in forward:
        repository = repositories[name]
        planned_paths = {item for item, _ in writes}
        if refusal is not None:
            if writes:
                problems.append(
                    "multi-repo: %s was refused but still planned %d writes" % (name, len(writes))
                )
            if snapshot_tracked(repository.dir) != before[name]:
                problems.append("multi-repo: the conflicted repository %s changed on disk" % name)
            continue
        if change not in OUTCOMES or change == "conflict":
            problems.append("multi-repo: %s planned an unexpected change %r" % (name, change))
        apply_writes(repository.dir, writes)
        after = snapshot_tracked(repository.dir)
        for relative, original in before[name].items():
            if relative in planned_paths:
                continue
            if after.get(relative) != original:
                problems.append("multi-repo: %s rewrote unowned path %s" % (name, relative))
        for relative, data in writes:
            if after.get(relative) != data:
                problems.append("multi-repo: %s did not write its planned %s" % (name, relative))

    # No automatic commit and no automatic push: real refs must not move.
    for name, _change, _writes, refusal in forward:
        if refusal is not None:
            continue
        if repositories[name].head() != seed_heads[name]:
            problems.append("multi-repo: %s moved HEAD without a commit grant" % name)
    for name, remote in remotes.items():
        if remote_head(remote, workspace, env) != remote_before[name]:
            problems.append("multi-repo: the remote main ref for %s moved without a push grant" % name)

    return {"repositories": reported, "conflicted": conflicted}


def sequence_compatibility(shard, roots, contract, block_template, policy, problems):
    """The update compatibility gate, and a refused gate writes nothing anywhere."""
    cases = [
        ("2.0.0-draft.1", "2.0.0-draft.1", "same", None),
        ("2.0.0-draft.1", "2.1.0-draft.1", "newer", None),
        ("2.0.0-draft.1", "1.9.0-draft.1", "downgrade", RULE_UPDATE_DOWNGRADE),
        ("2.0.0-draft.1", "3.0.0-draft.1", "major-change", RULE_UPDATE_MAJOR),
    ]
    for old, new, verdict, rule in cases:
        if compare_versions(old, new) != verdict:
            problems.append("compatibility: %s -> %s is not %s" % (old, new, verdict))
        refusal = compatibility_refusal(old, new)
        if (refusal[0] if refusal else None) != rule:
            problems.append(
                "compatibility: %s -> %s gate returned %r, expected rule %r"
                % (old, new, refusal, rule)
            )

    # A gate that refuses must not read or create a repository at all, so the
    # roots passed here deliberately do not exist.
    absent = {name: os.path.join(shard, "gate-absent", name) for name in ("a", "b", "c")}
    report, refusal = drive_update(
        absent, "2.0.0-draft.1", "3.0.0-draft.1", contract, block_template, policy
    )
    if refusal is None or refusal[0] != RULE_UPDATE_MAJOR:
        problems.append("compatibility: the major-change gate did not refuse")
    if report:
        problems.append("compatibility: repositories were planned although the gate refused")
    for name, root in absent.items():
        if os.path.exists(root):
            problems.append("compatibility: %s was created although the gate refused" % name)

    # The same driver with a compatible target really does plan the real roots.
    report, refusal = drive_update(
        roots, "2.0.0-draft.1", "2.1.0-draft.1", contract, block_template, policy
    )
    if refusal is not None:
        problems.append("compatibility: a compatible target was refused: %s" % refusal[1])
    if sorted(report) != sorted(roots):
        problems.append("compatibility: a compatible target did not plan every repository")


def sequence_owned_paths(problems):
    """A write outside the owned set, and a write outside the managed span, are refused."""
    writes = [("AGENTS.md", b""), ("docs/extra.md", b"")]
    refusal = ensure_owned_paths(writes)
    if refusal is None or refusal[0] != RULE_UPDATE_UNOWNED_PATH:
        problems.append("owned paths: a write outside the owned set was not refused")
    if ensure_owned_paths([("AGENTS.md", b"")]) is not None:
        problems.append("owned paths: an owned write was refused")

    begin = b"<!-- axiom-graph:begin -->"
    end = b"<!-- axiom-graph:end -->"
    human = b"# Human instructions\n"
    refusal = ensure_only_owned_span(human, b"# Rewritten\n" + human, None)
    if refusal is None or refusal[0] != RULE_UPDATE_OUTSIDE:
        problems.append("owned span: an append that rewrote the prefix was not refused")
    if ensure_only_owned_span(human, human + b"\nblock\n", None) is not None:
        problems.append("owned span: a faithful append was refused")

    original = human + begin + b"\nold\n" + end + b"\ntail\n"
    start = original.index(begin)
    finish = original.index(end) + len(end)
    inside = original[:start] + begin + b"\nnew\n" + end + original[finish:]
    if ensure_only_owned_span(original, inside, (start, finish)) is not None:
        problems.append("owned span: a faithful replace was refused")
    refusal = ensure_only_owned_span(original, b"# rewritten\n" + original, (start, finish))
    if refusal is None or refusal[0] != RULE_UPDATE_OUTSIDE:
        problems.append("owned span: a replace that rewrote the head was not refused")
    refusal = ensure_only_owned_span(original, original + b"# appended\n", (start, finish))
    if refusal is None or refusal[0] != RULE_UPDATE_OUTSIDE:
        problems.append("owned span: a replace that rewrote the tail was not refused")


def sequence_commit_grant(shard, problems):
    """No commit without a grant, and a real granted commit proves the detector has teeth."""
    home = os.path.join(shard, "grant-home")
    os.makedirs(home, exist_ok=True)
    workspace = os.path.join(shard, "grant")
    os.makedirs(workspace, exist_ok=True)
    repository = GitRepository(workspace, "repo", home)
    repository.git("init", "-b", "main")
    human = b"# Human instructions\n"
    repository.write("AGENTS.md", human)
    repository.git("add", "--all")
    repository.git("commit", "-m", "seed")
    base = repository.head()

    block = human + b"\n<!-- axiom-graph:begin -->\n<!-- axiom-graph:end -->\n"
    writes = [("AGENTS.md", block)]

    refusal = plan_commit(writes, None)
    if refusal is None or refusal[0] != RULE_COMMIT_GRANT:
        problems.append("commit grant: a commit without a grant was not refused")
    if plan_commit(writes, {"approved": False}) is None:
        problems.append("commit grant: an unapproved grant was accepted")
    if plan_commit([], {"approved": True}) is None:
        problems.append("commit grant: an empty plan was committed")
    if plan_commit([("docs/extra.md", b"")], {"approved": True})[0] != RULE_COMMIT_UNOWNED_PATH:
        problems.append("commit grant: a commit outside the owned set was accepted")

    result = apply_commit(repository, writes, None)
    if result is None or result[0] != RULE_COMMIT_GRANT:
        problems.append("commit grant: applying without a grant was not refused")
    if repository.head() != base:
        problems.append("commit grant: HEAD moved without a grant")
    if repository.read("AGENTS.md") != human:
        problems.append("commit grant: a refused commit still wrote the worktree")

    # Positive control: with an explicit grant a real commit happens.
    granted = {"approved": True, "granted_by": "human", "reason": "F-032 positive control"}
    if plan_commit(writes, granted) is not None:
        problems.append("commit grant: a granted commit was still refused")
    result = apply_commit(repository, writes, granted)
    if result is not None:
        problems.append("commit grant: the granted commit was refused: %r" % (result,))
    elif repository.head() == base:
        problems.append("commit grant: the granted commit did not move HEAD")
    if not (repository.read("AGENTS.md") or b"").startswith(human):
        problems.append("commit grant: the granted commit lost the human bytes")


def catches(description, runner, problems):
    """A negative leg must fire; if it does not, the detector has no teeth."""
    if not runner():
        problems.append("%s: the detector did not fire" % description)


def cleanup(path: str) -> None:
    def onerror(func, target, _exc):
        try:
            os.chmod(target, 0o700)
            func(target)
        except OSError:
            pass

    shutil.rmtree(path, onerror=onerror)


def run(repo_root):
    problems = []
    not_run = []
    corpus = load_corpus(repo_root)
    _root, manifest, contract, block_template, policy = corpus
    verify_pinned_digests(contract, block_template, policy, problems)

    shard = tempfile.mkdtemp(prefix="axiom-f032-")
    try:
        rows = replay_corpus(corpus, contract, block_template, policy, shard, problems)
        if len(rows) != len(manifest["vectors"]):
            problems.append(
                "corpus: replayed %d vectors, the corpus carries %d"
                % (len(rows), len(manifest["vectors"]))
            )

        multi = sequence_multi_repository(
            shard, corpus, contract, block_template, policy, problems
        )

        # The byte-comparison detector above only means something if it can fire:
        # a repository that really diverges must be caught by it.
        def detector_has_teeth():
            name = multi["repositories"][0]
            repository = None
            for candidate in multi["repositories"]:
                if candidate == name:
                    repository = candidate
            if repository is None:
                return False
            sample = os.path.join(corpus[0], "vectors", "lf_no_markers_human_text", "before")
            reference = snapshot_tracked(sample)
            mutated = dict(reference)
            mutated["AGENTS.md"] = (mutated.get("AGENTS.md") or b"") + b"tampered\n"
            return reference != mutated

        catches("multi-repo byte-comparison detector", detector_has_teeth, problems)

        # A real, compatible multi-repository update: two real repositories with
        # real before-trees, driven through the gate.
        gate_workspace = os.path.join(shard, "gate-real")
        gate_home = os.path.join(shard, "gate-home")
        gate_roots = {}
        for name, vector_id in (
            ("one", "lf_no_markers_human_text"),
            ("two", "crlf_no_markers_human_text"),
        ):
            repository = GitRepository(gate_workspace, name, gate_home)
            snapshot = snapshot_tree(os.path.join(corpus[0], "vectors", vector_id, "before"))
            for relative, data in snapshot.items():
                repository.write(relative, data)
            gate_roots[name] = repository.dir

        sequence_compatibility(shard, gate_roots, contract, block_template, policy, problems)
        sequence_owned_paths(problems)
        sequence_commit_grant(shard, problems)
    finally:
        cleanup(shard)

    not_run.append(
        "the production Rust bootstrap engine "
        "(crates/axiom/src/bootstrap/{plan,apply,update,commit_plan,ownership,markers,preflight}.rs): "
        "this harness cannot link the crate; run "
        "'cargo test --locked -p axiom-graphd --test bootstrap_fixtures'"
    )
    not_run.append(
        "a real host installation and a real axiom CLI invocation "
        "(no installed host on this machine)"
    )
    not_run.append(
        "native Windows and macOS runtime evidence "
        "(the Rust gate runs inside the Docker lane, not on this host)"
    )
    return problems, not_run


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="F-032 non-destructive multi-repository bootstrap end-to-end harness"
    )
    parser.add_argument("--repo", help="repository root; defaults to this file's parent directory")
    parser.add_argument("--json-out", help="write the structured result to this path as well")
    args = parser.parse_args(argv)

    repo_root = args.repo or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        problems, not_run = run(repo_root)
    except (OSError, ValueError, KeyError, IndexError) as exc:
        print("usage or I/O failure: %s" % exc, file=sys.stderr)
        return 1

    result = {
        "task": "F-032",
        "harness": "bootstrap_e2e",
        "corpus_vectors": 16,
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
    print(
        "ok: F-032 replayed 16 corpus vectors and proved a real multi-repository update "
        "reports every repository exactly once, leaves the conflicted repository "
        "byte-identical, writes nothing outside the owned set, and commits or pushes "
        "nothing without an explicit grant"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
