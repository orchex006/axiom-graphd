#!/usr/bin/env python3
"""Status checker for the axiom-graphd install runbooks and command reference.

Tasks D-002, D-003, D-004 and D-006 deliver four documents under docs/guides and
docs/reference. Those documents are honest only if their availability tables
agree with the real CLI surface and every relative link resolves. This checker
reads the four markdown deliverables plus the accepted-verb declaration in the
real CLI source (crates/axiom-graphd/src/cli.rs) and fails on any disagreement.
It never builds, never executes the Rust binary and never touches the network.

Usage:
    python tools/check-doc-status.py --root <repository root>
    python tools/check-doc-status.py --self-test

Exit codes:
    0  every check passed
    2  at least one check failed (each failure is printed as `FAIL <reason>`)

`--self-test` runs the same validators over deliberately broken inputs and
requires every one of them to be rejected, so a green repository run cannot be
vacuous.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile

RUNBOOKS = (
    "docs/guides/install-windows.md",
    "docs/guides/install-linux.md",
    "docs/guides/install-macos.md",
)
REFERENCE = "docs/reference/axiom-graphd.md"
DELIVERABLES = RUNBOOKS + (REFERENCE,)
DOC_INDEX = "docs/README.md"
CLI_SOURCE = "crates/axiom-graphd/src/cli.rs"

HOUSE_LINE = "Implementation/release evidence is not implied."
RUNBOOK_STATES = {"available", "pending"}
REFERENCE_STATES = {"available", "proposed"}

RUNBOOK_MARKERS = ("<!-- BEGIN RUNBOOK STATUS -->", "<!-- END RUNBOOK STATUS -->")
REFERENCE_MARKERS = ("<!-- BEGIN COMMAND STATUS -->", "<!-- END COMMAND STATUS -->")

# The concepts AC1 requires every install runbook to cover. Each pattern is
# matched case-insensitively against the whole document.
RUNBOOK_TOPICS = (
    ("prerequisites", r"prerequisite"),
    ("approved release/trust setup", r"trust"),
    ("bindings", r"binding"),
    ("user service", r"service|launchagent|systemd|scheduled task"),
    ("MCP handshake", r"\bmcp\b"),
    ("uninstall verification", r"uninstall"),
)

CELL_RE = re.compile(r"^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|")
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
VERBS_MARKER = "pub const ACCEPTED_VERBS: &[&str] = &["
VERB_RE = re.compile(r'"([a-z0-9][a-z0-9-]*)"')

SECRET_PATTERNS = (
    ("aws access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("openai-style key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "literal password assignment",
        re.compile(r"(?i)\bpassword\s*[:=]\s*[\"']?[^\s\"'`|]{6,}"),
    ),
    (
        "literal secret/token assignment",
        re.compile(
            r"(?i)\b(secret|api[_-]?key|access[_-]?token)\s*[:=]\s*[\"']?[A-Za-z0-9/+_-]{12,}"
        ),
    ),
)


class CheckError(Exception):
    """A structural problem that stops the scan (e.g. a missing file)."""


def read_text(root, rel):
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        raise CheckError("missing required file: %s" % rel)
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def status_table(text, begin, end):
    """Return [(name, state), ...] from the table between the two markers."""
    if begin not in text or end not in text:
        raise CheckError("missing status markers %r / %r" % (begin, end))
    segment = text.split(begin, 1)[1].split(end, 1)[0]
    rows = []
    for line in segment.splitlines():
        match = CELL_RE.match(line.strip())
        if not match:
            continue
        name = match.group(1).strip()
        state = match.group(2).strip()
        if set(state) <= set("-: "):  # markdown separator row
            continue
        if state == "State" or name in ("Command", "Step"):  # header row
            continue
        rows.append((name, state))
    if not rows:
        raise CheckError("status table between %r and %r has no data rows" % (begin, end))
    return rows


def accepted_commands(cli_src):
    """The verbs `parse` really accepts, read from the CLI's own declaration.

    `cli.rs` declares its accepted verbs once, in `ACCEPTED_VERBS`, so this
    checker does not depend on the parser's internal shape. The unit test
    `accepted_verbs_match_the_parser_in_both_directions` in `cli.rs` proves that
    declaration still agrees with `parse` in both directions; this function
    compares the documents against that same declaration.
    """
    start = cli_src.find(VERBS_MARKER)
    if start == -1:
        raise CheckError("cli.rs no longer declares ACCEPTED_VERBS")
    end = cli_src.find("];", start)
    if end == -1:
        raise CheckError("cli.rs ACCEPTED_VERBS declaration is unterminated")
    verbs = set(VERB_RE.findall(cli_src[start:end]))
    if not verbs:
        raise CheckError("cli.rs ACCEPTED_VERBS declaration lists no verb")
    return verbs


def section_for(text, name):
    for chunk in re.split(r"^##\s+", text, flags=re.M):
        lines = chunk.splitlines()
        if lines and ("`%s`" % name) in lines[0]:
            return chunk
    return ""


def check_runbook(text, label):
    problems = []
    if HOUSE_LINE not in text:
        problems.append("%s: missing the honest house-style line" % label)
    rows = status_table(text, *RUNBOOK_MARKERS)
    states = [state for _, state in rows]
    for name, state in rows:
        if state not in RUNBOOK_STATES:
            problems.append("%s: step %r uses unknown state %r" % (label, name, state))
    if "pending" not in states:
        problems.append(
            "%s: no step is marked pending although no install artifact exists" % label
        )
    lowered = text.lower()
    for topic, pattern in RUNBOOK_TOPICS:
        if not re.search(pattern, lowered):
            problems.append("%s: AC1 topic %r is not covered" % (label, topic))
    return problems


def check_reference(text, cli_src):
    problems = []
    if HOUSE_LINE not in text:
        problems.append("%s: missing the honest house-style line" % REFERENCE)
    rows = status_table(text, *REFERENCE_MARKERS)
    states = {}
    for name, state in rows:
        if state not in REFERENCE_STATES:
            problems.append("reference: row %r uses unknown state %r" % (name, state))
        states.setdefault(state, set()).add(name.strip("`"))

    accepted = accepted_commands(cli_src)
    available = states.get("available", set())
    proposed = states.get("proposed", set())

    if available != accepted:
        problems.append(
            "reference available set %s != accepted positional commands %s"
            % (sorted(available), sorted(accepted))
        )
    overlap = proposed & accepted
    if overlap:
        problems.append(
            "reference marks accepted commands as proposed: %s" % sorted(overlap)
        )
    # `accepted` is read from cli.rs itself, so the overlap check above is the
    # whole disagreement test: a proposed row that cli.rs accepts is caught
    # there, and a proposed row cli.rs never accepted stays honestly proposed.

    # AC1: every implemented command has a section with arguments, exit codes
    # and a failure-recovery or behaviour statement.
    for name in sorted(available):
        if not re.search(r"^##\s+\d+\.\s+`%s`" % re.escape(name), text, re.M):
            problems.append("reference has no numbered section for %r" % name)
            continue
        section = section_for(text, name)
        for label, pattern in (
            ("arguments", r"-\s*Arguments"),
            ("exit codes", r"Exit code"),
            ("failure recovery or behaviour", r"Failure recovery|Behaviour"),
        ):
            if not re.search(pattern, section):
                problems.append("reference section for %r is missing %s" % (name, label))
    if not proposed:
        problems.append("reference labels no command as proposed")
    return problems


def check_links(root, rel, text):
    problems = []
    base = os.path.dirname(os.path.join(root, rel))
    for target in LINK_RE.findall(text):
        target = target.strip()
        if not target or target.startswith("#"):
            continue
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target):
            continue  # external scheme such as http: or mailto:
        path_part = target.split("#", 1)[0].split("?", 1)[0]
        if not path_part:
            continue
        resolved = os.path.normpath(os.path.join(base, path_part))
        if not os.path.exists(resolved):
            problems.append("%s: link target %r does not resolve" % (rel, target))
    return problems


def check_secrets(rel, text):
    problems = []
    for label, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            problems.append("%s: possible %s in deliverable" % (rel, label))
    return problems


def check_index(root, index_text):
    problems = []
    for rel in DELIVERABLES:
        target = os.path.relpath(rel, os.path.dirname(DOC_INDEX)).replace(os.sep, "/")
        if ("(%s)" % target) not in index_text:
            problems.append("%s: missing link to %s" % (DOC_INDEX, rel))
    return problems


def run(root):
    """Return a list of problem strings; empty means every check passed."""
    texts = {}
    for rel in DELIVERABLES:
        texts[rel] = read_text(root, rel)
    cli_src = read_text(root, CLI_SOURCE)
    index_text = read_text(root, DOC_INDEX)

    problems = []
    problems += check_index(root, index_text)
    for rel in RUNBOOKS:
        problems += check_runbook(texts[rel], rel)
    problems += check_reference(texts[REFERENCE], cli_src)
    for rel in DELIVERABLES:
        problems += check_links(root, rel, texts[rel])
        problems += check_secrets(rel, texts[rel])
    return problems


# --------------------------------------------------------------------------
# Self-test: build a synthetic repository, prove the clean copy passes, then
# prove each single mutation is rejected.
# --------------------------------------------------------------------------

CLI_FIXTURE = (
    "pub const ACCEPTED_VERBS: &[&str] = &[\n"
    '    "help",\n'
    '    "version",\n'
    '    "doctor",\n'
    '    "serve",\n'
    "];\n"
)

REFERENCE_FIXTURE = (
    "# axiom-graphd command reference\n\n"
    + HOUSE_LINE
    + "\n\n<!-- BEGIN COMMAND STATUS -->\n"
    "| Command | State | Evidence |\n| --- | --- | --- |\n"
    "| help | available | accepted |\n"
    "| version | available | accepted |\n"
    "| doctor | available | executes |\n"
    "| serve | available | executes |\n"
    "| install | proposed | not accepted |\n"
    "<!-- END COMMAND STATUS -->\n\n"
    "## 2. `help`\n- Arguments: none.\n- Exit codes: 0.\n- Failure recovery: n/a.\n\n"
    "## 3. `version`\n- Arguments: none.\n- Exit codes: 0.\n- Failure recovery: n/a.\n\n"
    "## 4. `doctor`\n- Arguments: none.\n- Exit codes: 4.\n- Failure recovery: n/a.\n\n"
    "## 5. `serve`\n- Arguments: none.\n- Exit codes: 4.\n- Behaviour: takes the lock.\n\n"
    "## 6. Proposed commands\ninstall is proposed.\n"
)

RUNBOOK_FIXTURE = (
    "# Install runbook\n\n"
    + HOUSE_LINE
    + "\n\n<!-- BEGIN RUNBOOK STATUS -->\n"
    "| Step | State | Reason |\n| --- | --- | --- |\n"
    "| 1 Prerequisites | available | read-only checklist |\n"
    "| 2 Approved release and trust setup | pending | no artifact |\n"
    "| 3 Install the core release | pending | no installer |\n"
    "| 4 Machine-local state and bindings | pending | not wired |\n"
    "| 5 User service | pending | no adapter |\n"
    "| 6 MCP handshake | pending | separate repository |\n"
    "| 7 First-run smoke test | pending | cannot serve |\n"
    "| 8 Uninstall and uninstall verification | pending | nothing to remove |\n"
    "<!-- END RUNBOOK STATUS -->\n\nSee [reference](../reference/axiom-graphd.md).\n"
)


def _write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def _materialize(root, overrides=None):
    overrides = overrides or {}
    _write(root, CLI_SOURCE, overrides.get(CLI_SOURCE, CLI_FIXTURE))
    _write(root, REFERENCE, overrides.get(REFERENCE, REFERENCE_FIXTURE))
    for rel in RUNBOOKS:
        _write(root, rel, overrides.get(rel, RUNBOOK_FIXTURE))
    seen = []
    for rel in DELIVERABLES:
        target = os.path.relpath(rel, os.path.dirname(DOC_INDEX)).replace(os.sep, "/")
        seen.append("- [%s](%s)" % (os.path.basename(rel), target))
    _write(root, DOC_INDEX, overrides.get(DOC_INDEX, "# docs\n\n" + "\n".join(seen) + "\n"))


def self_test():
    """Prove the checker rejects each class of drift it claims to catch."""
    failures = []
    cases = []

    def case(label, overrides):
        cases.append((label, overrides))

    case("reference marks a proposed command available",
         {REFERENCE: REFERENCE_FIXTURE.replace("| install | proposed |", "| install | available |")})
    case("reference claims a command cli.rs does not accept",
         {REFERENCE: REFERENCE_FIXTURE.replace("| serve | available |", "| serve | proposed |")})
    case("cli.rs drops a documented command",
         {CLI_SOURCE: CLI_FIXTURE.replace('    "serve",\n', "")})
    case("runbook uses an invented state",
         {RUNBOOKS[0]: RUNBOOK_FIXTURE.replace("| 3 Install the core release | pending |",
                                               "| 3 Install the core release | done |")})
    case("runbook loses the honest house-style line",
         {RUNBOOKS[1]: RUNBOOK_FIXTURE.replace(HOUSE_LINE + "\n", "")})
    case("runbook drops an AC1 topic",
         {RUNBOOKS[2]: RUNBOOK_FIXTURE.replace("| 6 MCP handshake | pending | separate repository |\n", "")})
    case("deliverable has a broken relative link",
         {REFERENCE: REFERENCE_FIXTURE + "\nSee [missing](no-such-doc.md).\n"})
    case("index omits a deliverable",
         {DOC_INDEX: "# docs\n\n- [one](guides/install-windows.md)\n"})
    case("deliverable embeds an access key",
         {RUNBOOKS[0]: RUNBOOK_FIXTURE + "\nAKIAIOSFODNN7EXAMPLE\n"})
    case("status markers are removed",
         {REFERENCE: REFERENCE_FIXTURE.replace("<!-- BEGIN COMMAND STATUS -->", "")})

    with tempfile.TemporaryDirectory() as tmp:
        _materialize(tmp)
        clean = run(tmp)
        if clean:
            failures.append("clean fixture was rejected: %s" % clean)

    for label, overrides in cases:
        with tempfile.TemporaryDirectory() as tmp:
            _materialize(tmp, overrides)
            try:
                problems = run(tmp)
            except CheckError as exc:
                problems = [str(exc)]
            if not problems:
                failures.append("self-test case not caught: %s" % label)

    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root to scan")
    parser.add_argument("--self-test", action="store_true", help="run internal negative controls")
    args = parser.parse_args(argv)

    if args.self_test:
        failures = self_test()
        if failures:
            for failure in failures:
                print("FAIL %s" % failure)
            return 2
        print("PASS self-test: all negative controls rejected, clean fixture accepted")
        return 0

    try:
        problems = run(args.root)
    except CheckError as exc:
        print("FAIL %s" % exc)
        return 2

    if problems:
        for problem in problems:
            print("FAIL %s" % problem)
        return 2
    print(
        "PASS doc status: %d deliverables agree with %s and every relative link resolves"
        % (len(DELIVERABLES), CLI_SOURCE)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
