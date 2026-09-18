#!/usr/bin/env python3
"""Deterministic driver for the update and migration fixture corpus (F-010).

The corpus lives in ``fixtures/update/``: a manifest plus one JSON vector per
scenario. This driver checks that the corpus is internally consistent and that
every vector declares the decision the manifestation surface must reach, so a
vector can never silently disagree with the manifest it is listed in.

It reads and writes local files only. It launches no process, needs no shell,
no Bash, WSL, Docker or administrator rights, and never mutates the repository.

Exit codes: ``0`` every scenario matches the manifest, ``2`` at least one
divergence, ``1`` a usage or I/O failure.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
REQUEST_KEYS = (
    "plan_path", "component", "target_version", "canonical_digest", "approve_digest",
    "plan_created_at", "trust_metadata_expiry", "trust_root", "allowed_components",
    "signature_present", "candidate_schema_version", "backup_required",
    "backup_relative_path", "backup_present",
)


def load(path):
    with io.open(path, encoding="utf-8") as handle:
        return json.load(handle)


def check(manifest, root, spec_root=None):
    problems = []
    reasons = set(manifest["refusal_reasons"])
    decisions = set(manifest["decisions"])
    classes = set()
    boundaries = 0
    seen_ids = set()
    for scenario in manifest["scenarios"]:
        sid = scenario["id"]
        if sid in seen_ids:
            problems.append("duplicate scenario id: %s" % sid)
        seen_ids.add(sid)
        classes.add(scenario["class"])
        if scenario["kind"] == "boundary":
            boundaries += 1
        vector_path = os.path.join(root, scenario["vector"])
        if not os.path.exists(vector_path):
            problems.append("%s: vector file is missing: %s" % (sid, scenario["vector"]))
            continue
        vector = load(vector_path)
        if vector.get("vector_id") != sid:
            problems.append("%s: vector_id is %r" % (sid, vector.get("vector_id")))
        if vector.get("class") != scenario["class"]:
            problems.append("%s: class is %r" % (sid, vector.get("class")))
        if vector.get("kind") != scenario["kind"]:
            problems.append("%s: kind is %r" % (sid, vector.get("kind")))
        expected = vector.get("expected", {})
        if expected.get("decision") != scenario["expected"]["decision"]:
            problems.append("%s: decision is %r" % (sid, expected.get("decision")))
        if expected.get("reason") != scenario["expected"]["reason"]:
            problems.append("%s: reason is %r" % (sid, expected.get("reason")))
        if expected.get("decision") not in decisions:
            problems.append("%s: unknown decision %r" % (sid, expected.get("decision")))
        if expected.get("decision") == "refuse" and expected.get("reason") not in reasons:
            problems.append("%s: unknown refusal reason %r" % (sid, expected.get("reason")))
        if expected.get("decision") == "admit" and expected.get("reason") is not None:
            problems.append("%s: an admitted vector must not carry a refusal reason" % sid)
        request = vector.get("request", {})
        for key in REQUEST_KEYS:
            if key not in request:
                problems.append("%s: request is missing %s" % (sid, key))
        for key in ("canonical_digest",):
            if not DIGEST.match(str(request.get(key, ""))):
                problems.append("%s: %s is not a sha256 digest" % (sid, key))
        if request.get("approve_digest") is not None and not DIGEST.match(str(request["approve_digest"])):
            problems.append("%s: approve_digest is not a sha256 digest" % sid)
        for key in ("plan_created_at", "trust_metadata_expiry"):
            if not TIMESTAMP.match(str(request.get(key, ""))):
                problems.append("%s: %s is not a UTC timestamp" % (sid, key))
        if not isinstance(request.get("candidate_schema_version"), int):
            problems.append("%s: candidate_schema_version is not an integer" % sid)
        if not isinstance(request.get("signature_present"), bool):
            problems.append("%s: signature_present is not a boolean" % sid)
        contract = vector.get("spec_contract", {})
        reference = contract.get("reference_path")
        if not reference:
            problems.append("%s: spec_contract.reference_path is empty" % sid)
        elif not DIGEST.match(str(contract.get("reference_sha256", ""))):
            problems.append("%s: spec_contract.reference_sha256 is not a sha256 digest" % sid)
        elif spec_root:
            target = os.path.join(spec_root, reference.replace("/", os.sep))
            if not os.path.exists(target):
                problems.append("%s: referenced specification file is missing: %s" % (sid, reference))
            else:
                with open(target, "rb") as handle:
                    observed = hashlib.sha256(handle.read()).hexdigest()
                if observed != contract["reference_sha256"]:
                    problems.append("%s: referenced specification digest drifted: %s" % (sid, reference))
    for klass in manifest["hazard_classes"]:
        if klass not in classes:
            problems.append("hazard class is not distinguished: %s" % klass)
    if boundaries == 0:
        problems.append("the corpus carries no boundary scenario")
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description="check the F-010 update fixture corpus")
    parser.add_argument("--json-out", help="write the deterministic report to this path")
    parser.add_argument("--spec-root", help="also verify each referenced specification path and digest under this root")
    args = parser.parse_args(argv)
    root = HERE
    try:
        manifest = load(os.path.join(HERE, "manifest.json"))
    except (OSError, ValueError) as exc:
        print("cannot read the manifest: %s" % exc, file=sys.stderr)
        return 1
    problems = check(manifest, root, args.spec_root)
    report = {
        "corpus": manifest["corpus"],
        "task": manifest["task"],
        "scenarios": len(manifest["scenarios"]),
        "boundaries": sum(1 for s in manifest["scenarios"] if s["kind"] == "boundary"),
        "hazard_classes": len(manifest["hazard_classes"]),
        "refusal_reasons": len(manifest["refusal_reasons"]),
        "provenance_verified": bool(args.spec_root),
        "ok": not problems,
        "problems": problems,
    }
    if args.json_out:
        text = json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
        with io.open(args.json_out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    print(json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True))
    if problems:
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
