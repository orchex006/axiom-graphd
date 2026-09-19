#!/usr/bin/env python3
"""Deterministic guide-contract driver for the axiom-graphd operations guides.

Tasks D-012, D-013 and D-014 each produce one operator guide under
``docs/guides/``. Each guide carries one fenced JSON worked example between
sentinel markers. This driver re-reads the shipped guides and asserts, without
network access and without executing project code:

* every guide still keeps its sentinel markers and a parseable JSON block;
* the guide structured claims still hold (for example, that union-merging
  generated graphs is rejected, that bootstrap never overwrites unowned content
  and that an update is never a blind git pull);
* every fixture identifier the guide claims - a checkpoint input class, a
  bootstrap vector, an update scenario or a refusal reason - exists in the real
  component fixture corpus under ``fixtures/`` and, where the corpus records an
  outcome, that the guide agrees with it;
* every repository path a guide names in backticks resolves, so a renamed or
  deleted file cannot leave a dead reference behind in the documentation;
* an artifact a guide explicitly documents as not existing really is absent, so
  the guide cannot keep claiming an unimplemented surface after a later lane
  implements it (see ``absent_paths`` in ``fixtures/guides/manifest.json``);
* the required distinctions survive in prose (the guide still names live
  ignored data, the staged export and merged-source regeneration separately).

The negative half matters as much as the positive half: ``fixtures/guides/
negative/`` holds mutated copies of the same shape, and this driver fails if the
checker accepts any of them. That is the proof the checks have teeth.

It reads and writes local files only. It launches no process, needs no shell, no
Bash, WSL, Docker or administrator rights, and never mutates the repository.

Exit codes: ``0`` every guide matched and every negative fixture was rejected,
``2`` at least one divergence, ``1`` a usage or I/O failure.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
JSON_FENCE = "```json"
CLOSE_FENCE = "```"

# A backticked repository path with a documentation, source, data or lock
# extension. The guides reference files this way instead of with Markdown
# links, so this is the reference set the existence check has to resolve.
PATH_REF = re.compile(
    r"`([A-Za-z0-9_./-]+\.(?:md|rs|json|py|sql|toml|lock|example))`"
)


def load(path):
    with io.open(path, encoding="utf-8") as handle:
        return json.load(handle)


def extract_example(text, begin, end):
    """Return the fenced json example between the sentinel markers, or None."""
    if begin not in text or end not in text:
        return None
    after_begin = text.split(begin, 1)[1]
    if end not in after_begin:
        return None
    block = after_begin.split(end, 1)[0]
    start = block.find(JSON_FENCE)
    if start < 0:
        return None
    rest = block[start + len(JSON_FENCE):]
    close = rest.find(CLOSE_FENCE)
    if close < 0:
        return None
    try:
        return json.loads(rest[:close].strip())
    except ValueError:
        return None


def fixture_rows(path, list_name, id_field):
    fixture = load(path)
    rows = fixture.get(list_name)
    if not isinstance(rows, list):
        raise ValueError("fixture %s has no list %s" % (path, list_name))
    return {row[id_field]: row for row in rows if isinstance(row, dict) and id_field in row}


def check_path_refs(text, root, spec_root, target_artifacts, cross_repo_paths, absent_paths):
    """Return (problems, skipped) for every backticked path in one guide.

    A reference is resolved against the repository root. An entry of
    ``target_artifacts`` names a file bootstrap writes into a *target*
    repository, so it is not expected to exist here. An entry of
    ``cross_repo_paths`` is canonical in another repository: it is resolved
    against ``--spec-root`` when one is given and reported as skipped
    otherwise. An entry of ``absent_paths`` is a surface the guide documents as
    not implemented, and is checked for absence separately.
    """
    problems = []
    skipped = []
    for reference in sorted(set(PATH_REF.findall(text))):
        if reference in target_artifacts or reference in absent_paths:
            continue
        if reference in cross_repo_paths:
            if not spec_root:
                skipped.append(reference)
                continue
            # An `axiom-specs/...` reference is spelled with the checkout name
            # for the reader's benefit; under --spec-root the checkout *is* the
            # root, so the prefix is dropped before joining.
            spec_relative = reference[len("axiom-specs/"):] if reference.startswith("axiom-specs/") else reference
            candidates = [os.path.join(spec_root, spec_relative)]
            if reference.startswith("docs/"):
                candidates.append(os.path.join(root, reference))
            if not any(os.path.exists(candidate) for candidate in candidates):
                problems.append("cross-repo path reference does not resolve under --spec-root: %s" % reference)
            continue
        if reference.startswith("axiom-specs/"):
            if not spec_root:
                skipped.append(reference)
                continue
            candidate = os.path.join(spec_root, reference[len("axiom-specs/"):])
            if not os.path.exists(candidate):
                problems.append("axiom-specs path reference does not resolve: %s" % reference)
            continue
        if not os.path.exists(os.path.join(root, reference)):
            problems.append("path reference does not resolve: %s" % reference)
    return problems, skipped


def check_absent_paths(root, absent_paths):
    """Return one problem per path the guides document as not existing.

    This is the honesty check. The guides describe contracts that this revision
    does not implement. If a later task implements one of them, the driver fails
    instead of letting the guide keep calling it absent.
    """
    problems = []
    for entry in absent_paths:
        path = entry["path"]
        if os.path.exists(os.path.join(root, path)):
            problems.append(
                "%s now exists, so the guides no longer describe this revision; update the guides and "
                "fixtures/guides/manifest.json together (recorded reason: %s)" % (path, entry.get("reason", "none"))
            )
    return problems


def check_guide(entry, text, root, spec_root, config):
    """Return the list of problems found in one guide example text."""
    problems = []
    skipped = []
    low = text.lower()
    for phrase in entry.get("must_mention", []):
        if phrase.lower() not in low:
            problems.append("missing required distinction: %r" % phrase)

    example = extract_example(text, entry["begin"], entry["end"])
    if example is None:
        problems.append("missing sentinel markers or an unparseable json example")
        return problems, skipped

    for key, expected in entry.get("expect_fields", {}).items():
        actual = example.get(key)
        if actual != expected:
            problems.append("%s is %r, expected %r" % (key, actual, expected))
    for key in entry.get("require_true_fields", []):
        if example.get(key) is not True:
            problems.append("%s must be true, found %r" % (key, example.get(key)))
    for key, required in entry.get("expect_list_contains", {}).items():
        actual = example.get(key)
        if not isinstance(actual, list):
            problems.append("%s must be a list, found %r" % (key, actual))
            continue
        for item in required:
            if item not in actual:
                problems.append("%s must contain %r" % (key, item))

    for ref in entry.get("fixture_refs", []):
        fixture_path = os.path.join(root, ref["path"])
        if not os.path.exists(fixture_path):
            problems.append("referenced fixture corpus is missing: %s" % ref["path"])
            continue
        try:
            rows = fixture_rows(fixture_path, ref["list"], ref["id_field"])
        except ValueError as exc:
            problems.append(str(exc))
            continue
        fixture = load(fixture_path)
        for field in ref.get("claim_fields", []):
            for claimed in example.get(field, []) or []:
                if claimed not in rows:
                    problems.append("%s claims unknown fixture id %r from %s" % (field, claimed, ref["path"]))
        for mapping in ref.get("claim_map_fields", []):
            value_field = mapping.get("fixture_value_field", "outcome")
            for row in example.get(mapping["field"], []) or []:
                if not isinstance(row, dict) or mapping["key"] not in row:
                    problems.append("%s entry is missing %r" % (mapping["field"], mapping["key"]))
                    continue
                claimed_id = row[mapping["key"]]
                if claimed_id not in rows:
                    problems.append("%s claims unknown fixture id %r from %s" % (mapping["field"], claimed_id, ref["path"]))
                    continue
                recorded = rows[claimed_id].get(value_field)
                if mapping["value"] in row and recorded is not None and row[mapping["value"]] != recorded:
                    problems.append("%s says %s is %r but %s records %r" % (claimed_id, mapping["value"], row[mapping["value"]], ref["path"], recorded))
        for field in ref.get("require_set_equal", []):
            claimed = example.get(field)
            recorded = fixture.get(field)
            if not isinstance(claimed, list):
                problems.append("%s must be a list, found %r" % (field, claimed))
            elif set(claimed) != set(recorded or []):
                problems.append("%s must equal the corpus set %r, found %r" % (field, recorded, claimed))

    ref_problems, ref_skipped = check_path_refs(
        text,
        root,
        spec_root,
        set(config.get("target_artifacts", [])),
        set(config.get("cross_repo_paths", [])),
        {item["path"] for item in config.get("absent_paths", [])},
    )
    problems.extend(ref_problems)
    skipped.extend(ref_skipped)
    return problems, skipped


def run(root, spec_root=None):
    manifest = load(os.path.join(root, "fixtures", "guides", "manifest.json"))
    problems = []
    skipped = []
    checked = 0

    problems.extend(check_absent_paths(root, manifest.get("absent_paths", [])))

    for entry in manifest["guides"]:
        path = os.path.join(root, entry["path"])
        if not os.path.exists(path):
            problems.append("%s: guide is missing: %s" % (entry["id"], entry["path"]))
            continue
        with io.open(path, encoding="utf-8") as handle:
            text = handle.read()
        checked += 1
        guide_problems, guide_skipped = check_guide(entry, text, root, spec_root, manifest)
        for problem in guide_problems:
            problems.append("%s (%s): %s" % (entry["id"], entry["path"], problem))
        skipped.extend(guide_skipped)

    by_id = {entry["id"]: entry for entry in manifest["guides"]}
    negatives = manifest.get("negative", [])
    for negative in negatives:
        entry = by_id[negative["guide"]]
        path = os.path.join(root, negative["path"])
        if not os.path.exists(path):
            problems.append("negative fixture is missing: %s" % negative["path"])
            continue
        with io.open(path, encoding="utf-8") as handle:
            text = handle.read()
        negative_problems, _ = check_guide(entry, text, root, spec_root, manifest)
        if not negative_problems:
            problems.append("negative fixture was accepted but it must be rejected (%s): %s" % (negative["reason"], negative["path"]))
            continue
        joined = " ".join(negative_problems)
        for marker in negative.get("expect_problem_contains", []):
            if marker not in joined:
                problems.append(
                    "negative fixture %s was rejected, but not for its documented reason: %r is missing from %r"
                    % (negative["path"], marker, joined)
                )
    return checked, len(negatives), problems, sorted(set(skipped))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check the axiom-graphd operations guides against the fixture corpora.")
    parser.add_argument("--root", default=ROOT, help="repository root (default: this checkout)")
    parser.add_argument("--spec-root", help="axiom-specs checkout, to resolve cross-repository references")
    parser.add_argument("--json-out", help="write the structured result to this path as well")
    args = parser.parse_args(argv)
    try:
        checked, negatives, problems, skipped = run(
            os.path.abspath(args.root),
            os.path.abspath(args.spec_root) if args.spec_root else None,
        )
    except (OSError, ValueError, KeyError) as exc:
        print("usage or I/O failure: %s" % exc, file=sys.stderr)
        return 1
    result = {
        "corpus": "ops-guides",
        "guides_checked": checked,
        "negative_fixtures_checked": negatives,
        "spec_root": args.spec_root,
        "cross_repo_refs_skipped": skipped,
        "problems": problems,
        "ok": not problems,
    }
    if args.json_out:
        with io.open(args.json_out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    if problems:
        for problem in problems:
            print("PROBLEM: %s" % problem)
        print("FAIL: %d problem(s) across %d guide(s)" % (len(problems), checked))
        return 2
    print("ok: %d guide(s) matched; %d negative fixture(s) were rejected as required" % (checked, negatives))
    if skipped:
        print("note: %d cross-repository reference(s) not resolved without --spec-root" % len(skipped))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
