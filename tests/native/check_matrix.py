#!/usr/bin/env python3
"""Matrix validator for the native platform matrix (task V2-030).

`tests/native/README.md` is the only native-execution record this repository
owns. It is honest only if a `verified` row is backed by a real execution and a
real artifact hash, and if an unperformed target is `not_run` with a stated
reason and no invented digest. This checker reads the table between the
`<!-- BEGIN NATIVE MATRIX -->` and `<!-- END NATIVE MATRIX -->` markers, reads
the committed evidence files the rows name, and fails on any disagreement.

It never builds, never executes the Rust binary and never touches the network.

Usage:
    python tests/native/check_matrix.py [--root <repository root>]
    python tests/native/check_matrix.py --self-test

Exit codes:
    0  every row is legitimate
    1  a usage or I/O failure (the document or an evidence file is unreadable)
    2  at least one matrix problem (each is printed as `FAIL <reason>`)

`--self-test` runs the same validators over deliberately broken copies of the
document and requires every break to be rejected, so a green repository run
cannot be vacuous.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tempfile

README = "tests/native/README.md"
BEGIN = "<!-- BEGIN NATIVE MATRIX -->"
END = "<!-- END NATIVE MATRIX -->"

# `compatibility/platform-matrix.json` declares exactly these four mandatory
# targets with native_execution_required: true. A fifth row is an ADR in
# axiom-specs, not a local edit; a missing row is a dropped mandatory target.
MANDATORY_TARGETS = ("windows-x64", "linux-x64", "macos-x64", "macos-arm64")
MACOS_TARGETS = ("macos-x64", "macos-arm64")
MACOS_NOT_RUN_REASON = "no macOS host available in this environment"

COLUMNS = (
    "target",
    "status",
    "scope",
    "execution_identity",
    "command",
    "exit",
    "artifact_sha256",
    "toolchain",
    "evidence",
    "note",
)

STATUSES = ("verified", "not_run")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EXIT_CODE = re.compile(r"^[0-9]+$")
ANY_DIGEST = re.compile(r"\b[0-9a-f]{64}\b")


class MatrixError(Exception):
    """A structural problem that stops the row scan (e.g. a missing marker)."""


def read_text(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def parse_matrix(readme_text):
    """Return the matrix rows as dicts, or raise MatrixError."""
    if BEGIN not in readme_text or END not in readme_text:
        raise MatrixError("missing matrix markers %r / %r" % (BEGIN, END))
    segment = readme_text.split(BEGIN, 1)[1].split(END, 1)[0]

    lines = [line.strip() for line in segment.splitlines() if line.strip().startswith("|")]
    if not lines:
        raise MatrixError("matrix markers enclose no table rows")

    def cells(line):
        return [cell.strip() for cell in line.strip("|").split("|")]

    header = cells(lines[0])
    if tuple(header) != COLUMNS:
        raise MatrixError("matrix header is %r, expected %r" % (header, list(COLUMNS)))

    rows = []
    for line in lines[1:]:
        values = cells(line)
        if all(set(value) <= set("-: ") for value in values):  # separator row
            continue
        if len(values) != len(COLUMNS):
            raise MatrixError("matrix row has %d cells, expected %d: %s"
                              % (len(values), len(COLUMNS), line))
        rows.append(dict(zip(COLUMNS, values)))
    if not rows:
        raise MatrixError("matrix table has no data rows")
    return rows


def problem(line, message):
    return "line %d: %s" % (line, message)


def check_rows(rows, root, line_of_row):
    """Return a list of problem strings; empty means every row is legitimate."""
    problems = []

    seen = [row["target"] for row in rows]
    for target in seen:
        if seen.count(target) > 1:
            problems.append("target %r appears more than once" % target)
    for target in MANDATORY_TARGETS:
        if target not in seen:
            problems.append("mandatory target %r has no row" % target)
    for target in seen:
        if target not in MANDATORY_TARGETS:
            problems.append("target %r is not one of the four mandatory targets %r"
                            % (target, list(MANDATORY_TARGETS)))

    for row in rows:
        target = row["target"]
        where = line_of_row.get(target, 0)
        status = row["status"]

        if status not in STATUSES:
            problems.append(problem(where, "%s: status %r is not one of %r"
                                    % (target, status, list(STATUSES))))
            continue
        if not row["scope"] or row["scope"] == "-":
            problems.append(problem(where, "%s: scope is empty" % target))
        if not row["command"] or row["command"] == "-":
            problems.append(problem(where, "%s: no command is recorded" % target))
        if not row["note"] or row["note"] == "-":
            problems.append(problem(where, "%s: no observed result or reason is recorded" % target))

        evidence_rel = row["evidence"]
        if not evidence_rel or evidence_rel == "-":
            problems.append(problem(where, "%s: no evidence file is named" % target))
            continue
        evidence_path = os.path.join(root, evidence_rel.replace("/", os.sep))
        if not os.path.isfile(evidence_path):
            problems.append(problem(where, "%s: evidence file %s does not exist"
                                    % (target, evidence_rel)))
            continue
        evidence_text = read_text(evidence_path)

        if status == "verified":
            problems += check_verified(row, target, where, evidence_text)
        else:
            problems += check_not_run(row, target, where, evidence_text, evidence_rel)

    return problems


def check_verified(row, target, where, evidence_text):
    problems = []
    if not EXIT_CODE.match(row["exit"]):
        problems.append(problem(where, "%s: verified row has no recorded exit code (exit=%r)"
                                % (target, row["exit"])))
    if not HEX64.match(row["artifact_sha256"]):
        problems.append(problem(where, "%s: verified row has no recorded artifact sha256 (artifact_sha256=%r)"
                                % (target, row["artifact_sha256"])))
    else:
        if row["artifact_sha256"] not in evidence_text:
            problems.append(problem(where, "%s: artifact sha256 %s does not appear in %s"
                                    % (target, row["artifact_sha256"], row["evidence"])))
    if not row["toolchain"] or row["toolchain"] == "-":
        problems.append(problem(where, "%s: verified row has no recorded toolchain identity" % target))
    if row["scope"] == "none":
        problems.append(problem(where, "%s: verified row claims scope 'none'" % target))
    if row["execution_identity"] == "-":
        problems.append(problem(where, "%s: verified row has no observed execution identity" % target))
    if EXIT_CODE.match(row["exit"]):
        record = re.compile(r"(?mi)^[^\n]*\bexit\b[^\n]*[:=]\s*%s\s*$" % re.escape(row["exit"]))
        if not record.search(evidence_text):
            problems.append(problem(where, "%s: exit %s is not recorded in %s"
                                    % (target, row["exit"], row["evidence"])))
    return problems


def check_not_run(row, target, where, evidence_text, evidence_rel):
    problems = []
    for column in ("exit", "artifact_sha256", "toolchain", "execution_identity"):
        if row[column] != "-":
            problems.append(problem(where, "%s: not_run row carries a %s value (%r); unperformed work has no digest, toolchain or status"
                                    % (target, column, row[column])))
    if row["scope"] != "none":
        problems.append(problem(where, "%s: not_run row claims scope %r; an unperformed target covers nothing"
                                % (target, row["scope"])))
    for column in ("note", "command", "execution_identity", "toolchain", "artifact_sha256"):
        if ANY_DIGEST.search(row[column]):
            problems.append(problem(where, "%s: not_run row invents a digest in %s (%r)"
                                    % (target, column, row[column])))
    if row["note"] not in evidence_text:
        problems.append(problem(where, "%s: the stated reason does not appear in %s"
                                % (target, evidence_rel)))
    if target in MACOS_TARGETS and row["note"] != MACOS_NOT_RUN_REASON:
        problems.append(problem(where, "%s: reason is %r, must be %r"
                                % (target, row["note"], MACOS_NOT_RUN_REASON)))
    return problems


def row_lines(readme_text):
    """Map target -> 1-based line number in the whole document, best effort."""
    lines = readme_text.splitlines()
    inside = False
    mapping = {}
    for number, line in enumerate(lines, start=1):
        if BEGIN in line:
            inside = True
            continue
        if END in line:
            inside = False
            continue
        if not inside:
            continue
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) == len(COLUMNS) and cells[0] in MANDATORY_TARGETS + ("target",):
            if cells[0] != "target":
                mapping[cells[0]] = number
    return mapping


def run(root):
    """Return a list of problem strings; empty means every row is legitimate."""
    readme_path = os.path.join(root, README.replace("/", os.sep))
    if not os.path.isfile(readme_path):
        raise MatrixError("missing required file: %s" % README)
    readme_text = read_text(readme_path)
    rows = parse_matrix(readme_text)
    return check_rows(rows, root, row_lines(readme_text))


# --------------------------------------------------------------------------
# Self-test: prove the validator rejects each class of drift it claims to
# catch, over copies of the real document and the real evidence files.
# --------------------------------------------------------------------------

WINDOWS_HASH = "77f15708dd1112053989d582750541c99a19dfbe529aaeda0a6d912baf363285"
ABSENT_HASH = "deadbeef" * 8


def _case_readmes(readme_text):
    """Yield (label, mutated document) pairs; every one must be rejected."""

    yield (
        "a mandatory target row is removed",
        "\n".join(line for line in readme_text.splitlines()
                  if not line.startswith("| windows-x64 | verified |")) + "\n",
    )
    yield (
        "a fifth, non-mandatory target row is added",
        readme_text.replace(
            "<!-- END NATIVE MATRIX -->",
            "| linux-arm64 | not_run | none | - | cargo build | - | - | - | "
            "evidence/V2-030/v2030-macos-notrun.txt | no host |\n<!-- END NATIVE MATRIX -->",
        ),
    )
    yield (
        "a verified row loses its artifact hash",
        readme_text.replace(WINDOWS_HASH, "-"),
    )
    yield (
        "a verified row records a hash the evidence does not contain",
        readme_text.replace(WINDOWS_HASH, ABSENT_HASH),
    )
    yield (
        "a not_run row carries an invented digest",
        readme_text.replace(
            "| macos-x64 | not_run | none | - |",
            "| macos-x64 | not_run | none | - |",
        ).replace(
            "| no macOS host available in this environment |\n"
            "| macos-arm64 | not_run",
            "| no macOS host available in this environment %s |\n"
            "| macos-arm64 | not_run" % ABSENT_HASH,
        ),
    )
    yield (
        "a not_run row carries an exit status",
        readme_text.replace(
            "| macos-x64 | not_run | none | - | cargo build --release --target x86_64-apple-darwin "
            "then target/x86_64-apple-darwin/release/axiom-graphd version --json | - |",
            "| macos-x64 | not_run | none | - | cargo build --release --target x86_64-apple-darwin "
            "then target/x86_64-apple-darwin/release/axiom-graphd version --json | 0 |",
        ),
    )
    yield (
        "a not_run row carries no reason",
        readme_text.replace("| no macOS host available in this environment |", "| - |"),
    )
    yield (
        "a macOS row states the wrong reason",
        readme_text.replace("| no macOS host available in this environment |",
                            "| the host is Windows |"),
    )
    yield (
        "a verified row loses its exit code",
        readme_text.replace(
            "| target/debug/axiom-graphd.exe version --json | 0 |",
            "| target/debug/axiom-graphd.exe version --json | - |",
        ),
    )
    yield (
        "the matrix header is renamed",
        readme_text.replace("| target | status | scope |", "| platform | status | scope |"),
    )
    yield (
        "the matrix markers are removed",
        readme_text.replace(BEGIN, "").replace(END, ""),
    )
    yield (
        "a row gains an extra cell",
        readme_text.replace(
            "| macos-arm64 | not_run | none | - |",
            "| macos-arm64 | not_run | none | - | extra |",
        ),
    )
    yield (
        "a verified row claims scope 'none'",
        readme_text.replace("| windows-x64 | verified | native-binary-built-and-run |",
                            "| windows-x64 | verified | none |"),
    )



def self_test(root):
    """Return a list of failures; empty means every negative control was caught."""
    failures = []
    readme_path = os.path.join(root, README.replace("/", os.sep))
    readme_text = read_text(readme_path)

    def materialize(tmp, document):
        target = os.path.join(tmp, "tests", "native")
        os.makedirs(target, exist_ok=True)
        with open(os.path.join(target, "README.md"), "w", encoding="utf-8") as handle:
            handle.write(document)
        shutil.copytree(os.path.join(root, "evidence"),
                        os.path.join(tmp, "evidence"),
                        dirs_exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        materialize(tmp, readme_text)
        try:
            clean = run(tmp)
        except MatrixError as exc:
            clean = [str(exc)]
        if clean:
            failures.append("clean copy was rejected: %s" % clean)

    for label, document in _case_readmes(readme_text):
        if document == readme_text:
            failures.append("self-test case did not change the document: %s" % label)
            continue
        with tempfile.TemporaryDirectory() as tmp:
            materialize(tmp, document)
            try:
                problems = run(tmp)
            except MatrixError as exc:
                problems = [str(exc)]
            if not problems:
                failures.append("self-test case not caught: %s" % label)

    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=None, help="repository root to scan")
    parser.add_argument("--self-test", action="store_true", help="run internal negative controls")
    args = parser.parse_args(argv)

    root = args.root
    if root is None:
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    if not os.path.isdir(root):
        print("FAIL repository root does not exist: %s" % root)
        return 1

    try:
        if args.self_test:
            failures = self_test(root)
            if failures:
                for failure in failures:
                    print("FAIL %s" % failure)
                return 2
            print("PASS self-test: every negative control rejected, clean copy accepted")
            return 0
        problems = run(root)
    except MatrixError as exc:
        print("FAIL %s" % exc)
        return 1
    except OSError as exc:
        print("FAIL %s" % exc)
        return 1

    if problems:
        for problem in problems:
            print("FAIL %s" % problem)
        return 2
    print("PASS native matrix: all four mandatory targets are legitimate and every evidence file backs its row")
    return 0


if __name__ == "__main__":
    sys.exit(main())
