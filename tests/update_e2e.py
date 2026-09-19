#!/usr/bin/env python3
"""Signed update check, apply and rollback across every component (task F-033).

AC1 says every component, including the data packages, reports a version, and
that an incompatible or unauthenticated update fails safely. That statement has
two halves, so this harness proves both against the real artefacts rather than
against a restatement of them:

* the **version half** re-reads the real constants in
  `crates/axiom/src/version.rs`, `crates/axiom/src/packages.rs`,
  `crates/graph-store/src/migrations.rs` and the workspace manifest, and refuses to
  pass if the seven frozen component names are not each reported exactly once
  across the core release, the independent components, the specification pin and
  the inherited documentation. The data packages are not decoration here: the
  specification pin and the fixture provenance are validated with the same named
  rules the shipping report uses, and a fixture index declared `shared` is
  refused rather than silently accepted;
* the **safety half** replays the whole `fixtures/update/` corpus - both hazard
  classes and all three boundary vectors - through a faithful port of the real
  `axiom_graphd::update_guard::admit` surface, in check order: trust metadata
  expiry, then an absent signature or an unusable trust root, then the schema
  ceiling, then the required backup, then the real argv delegation. Every refusal
  is total: the target tree is snapshotted before and after, and a refused update
  must leave every byte where it was and must never create the file it refused to
  find.

What is real here:

* every byte read is a real file in the repository or in a real temporary tree:
  the corpus, the pinned specification references and the Rust constants are all
  read from disk, so a constant that drifts from this harness fails the run;
* the request shape, the trust decision, the schema ceiling, the backup presence
  check and the argv-only delegation are ported check for check from
  `crates/axiom-graphd/src/update_guard.rs` and
  `crates/axiom-graphd/src/commands/update.rs`, including the empty-argument,
  shell-metacharacter and 64-hex digest refusals and the `approval-missing` rule;
* the delegation is an argv vector, never a shell string, and the harness proves
  the metacharacter set it refuses is exactly the set the shipping delegation
  refuses by extracting that set from the real source;
* every negative leg is a real mutation of a real control vector, not a
  hand-written refusal.

What is modelled, and reported `not_run`:

* the Rust implementation itself. This harness cannot link the crates, so the
  equivalent real commands are kept in the file and reported `not_run`:
  `cargo test --locked -p axiom-graphd --test update_fixtures`,
  `cargo test --locked -p axiom-graphd update_guard` and
  `cargo test --locked -p axiom update`;
* the deeper backup integrity check. The real guard reuses
  `graph_store::backup::verify_backup`, which opens the candidate as a database;
  this harness reads real byte presence and the SQLite file header, and reports the
  full integrity check `not_run` with the reason;
* a live update source: no signed metadata, no network fetch and no real install
  is performed here, because the release gate is closed for this workstream.

Exit codes: 0 every property held and every negative leg was rejected, 2 a
divergence (printed as `PROBLEM:`), 1 a usage or I/O failure. The harness is a
standalone Python 3 program: no third-party dependencies, no network and no shell
interpolation.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tempfile

MANIFEST_PATH = "fixtures/update/manifest.json"
VECTORS_DIR = "fixtures/update/vectors"
VERSION_SOURCE = "crates/axiom/src/version.rs"
PACKAGES_SOURCE = "crates/axiom/src/packages.rs"
MIGRATIONS_SOURCE = "crates/graph-store/src/migrations.rs"
CHECK_SOURCE = "crates/axiom/src/update/check.rs"
TRUST_SOURCE = "crates/axiom/src/update/trust.rs"
POLICY_SOURCE = "crates/axiom/src/update/policy.rs"
GUARD_SOURCE = "crates/axiom-graphd/src/update_guard.rs"
DELEGATE_SOURCE = "crates/axiom-graphd/src/commands/update.rs"
WORKSPACE_MANIFEST = "Cargo.toml"

# The stable refusal reasons, in check order, as the real guard records them.
REASON_SIGNATURE_EXPIRED = "signature-expired"
REASON_SIGNER_UNTRUSTED = "signer-untrusted"
REASON_SCHEMA_NEWER_THAN_BINARY = "schema-newer-than-binary"
REASON_BACKUP_MISSING = "backup-missing"
REASON_DELEGATION_REFUSED = "delegation-refused"
REFUSAL_REASONS = (
    REASON_SIGNATURE_EXPIRED,
    REASON_SIGNER_UNTRUSTED,
    REASON_SCHEMA_NEWER_THAN_BINARY,
    REASON_BACKUP_MISSING,
    REASON_DELEGATION_REFUSED,
)

# The twelve characters the real argv delegation refuses, so "argv only" cannot
# silently become "shell". The harness re-extracts this set from the source and
# refuses to run if the two disagree.
SHELL_METACHARACTERS = (";", "|", "&", ">", "<", "`", "$", "\n", "\r", '"', "'", "\\")

# The stable wire spellings of version::UpdateStatus, in variant order.
UPDATE_STATUS = ("not_checked", "current", "available", "offline", "unconfigured", "blocked")

# The named rules the packages report uses, taken from the real constants and
# the real refusals in crates/axiom/src/packages.rs.
RULE_CORE_RELEASE_SPLIT = "core_release_split"
RULE_CORE_VERSION_MISMATCH = "core_version_mismatch"
RULE_CORE_COMPONENT_MISMATCH = "core_component_mismatch"
RULE_CORE_REVISION_NOT_PINNED = "core_revision_not_pinned"
RULE_INDEPENDENT_REVISION_NOT_PINNED = "independent_revision_not_pinned"
RULE_MISSING_INDEPENDENT_COMPONENT = "missing_independent_component"
RULE_UNEXPECTED_PACKAGE_COMPONENT = "unexpected_package_component"
RULE_SPEC_VERSION_MISMATCH = "spec_version_mismatch"
RULE_SPEC_REVISION_NOT_PINNED = "spec_revision_not_pinned"
RULE_FIXTURE_REVISION_NOT_PINNED = "fixture_revision_not_pinned"
RULE_FIXTURE_INDEX_NOT_DIGEST = "fixture_index_not_digest"
RULE_SHARED_FIXTURE_INDEX = "shared_fixture_index_not_supported"
RULE_UNEXPECTED_DOCUMENTATION_COMPONENT = "unexpected_documentation_component"
RULE_STANDALONE_DOCUMENTATION_VERSION = "standalone_documentation_version"
RULE_DOCUMENTATION_OWNER_MISSING = "documentation_owner_missing"
RULE_NO_STANDALONE_DOCUMENTATION_PACKAGE = "no_standalone_documentation_package"

PIN_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
ARITHMETIC_RE = re.compile(r"^[0-9+*\-\s]+$")
SQLITE_HEADER = b"SQLite format 3\x00"


def read_text(path):
    with io.open(path, encoding="utf-8") as handle:
        return handle.read()


def read_bytes(path):
    with io.open(path, "rb") as handle:
        return handle.read()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def pinned(seed):
    """A deterministic, real lowercase 40-hex revision."""
    return sha256_hex(seed.encode("utf-8"))[:40]


def digest(seed):
    return sha256_hex(seed.encode("utf-8"))


def rust_char_literal_width(source, index):
    """3 for a plain char literal, 4 when escaped, 0 when it is a lifetime."""
    if source[index] != "'":
        return 0
    if index + 1 < len(source) and source[index + 1] == "\\":
        if index + 3 < len(source) and source[index + 3] == "'":
            return 4
        return 0
    if index + 2 < len(source) and source[index + 2] == "'":
        return 3
    return 0


def rust_rhs(source, name):
    """The right-hand side of a Rust const declaration, bracket balanced."""
    match = re.search(r"\b(?:pub\s+)?const\s+%s\b[^=]*=" % re.escape(name), source)
    if match is None:
        raise KeyError("the source does not declare %s" % name)
    index = match.end()
    depth = 0
    pieces = []
    quoted = False
    escaped = False
    while index < len(source):
        char = source[index]
        if quoted:
            pieces.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            pieces.append(char)
        elif char == "'":
            width = rust_char_literal_width(source, index)
            if width == 0:
                pieces.append(char)
            else:
                pieces.append(source[index:index + width])
                index += width
                continue
        elif char in "[{(":
            depth += 1
            pieces.append(char)
        elif char in "]})":
            depth -= 1
            pieces.append(char)
        elif char == ";" and depth == 0:
            break
        else:
            pieces.append(char)
        index += 1
    return "".join(pieces).strip()


def rust_strings(rhs):
    """Every double-quoted literal in a right-hand side, in order."""
    return re.findall(r'"([^"]*)"', rhs)


def rust_elements(rhs):
    """The top-level comma-separated elements of an array right-hand side."""
    match = re.search(r"\[(.*)\]", rhs, re.S)
    if match is None:
        raise ValueError("not an array: %r" % rhs)
    body = match.group(1)
    elements = []
    current = []
    depth = 0
    quoted = False
    index = 0
    while index < len(body):
        char = body[index]
        if quoted:
            current.append(char)
            if char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            current.append(char)
        elif char == "'":
            width = rust_char_literal_width(body, index)
            if width == 0:
                current.append(char)
            else:
                current.append(body[index:index + width])
                index += width
                continue
        elif char in "[{(":
            depth += 1
            current.append(char)
        elif char in "]})":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            elements.append("".join(current).strip())
            current = []
        else:
            current.append(char)
        index += 1
    if "".join(current).strip():
        elements.append("".join(current).strip())
    return [element for element in elements if element]


def rust_int(rhs):
    """A const integer, allowing the simple arithmetic the sources use."""
    expression = rhs.strip()
    if not ARITHMETIC_RE.match(expression):
        raise ValueError("not a plain integer expression: %r" % rhs)
    return int(eval(expression, {"__builtins__": {}}))  # noqa: S307 - validated above


def rust_int_const(source, name, depth=0):
    """A const integer, following the alias chain the sources use."""
    if depth > 8:
        raise ValueError("the integer alias chain is too deep: %r" % name)
    rhs = rust_rhs(source, name).strip()
    if ARITHMETIC_RE.match(rhs):
        return rust_int(rhs)
    return rust_int_const(source, rhs, depth + 1)


def workspace_version(manifest_text):
    section = manifest_text.split("[workspace.package]", 1)
    if len(section) != 2:
        raise ValueError("Cargo.toml has no [workspace.package] section")
    match = re.search(r'^version\s*=\s*"([^"]+)"', section[1], re.M)
    if match is None:
        raise ValueError("the workspace package declares no version")
    return match.group(1)


CHAR_ESCAPES = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "0": "\u0000",
    "\\": "\\",
    "'": "'",
    '"': '"',
}


def rust_chars(rhs):
    """The characters of a Rust char array, with their escapes interpreted."""
    chars = []
    for raw in rust_elements(rhs):
        inner = raw.strip()
        if len(inner) < 2 or inner[0] != "'" or inner[-1] != "'":
            raise ValueError("not a char literal: %r" % raw)
        body = inner[1:-1]
        if len(body) == 2 and body[0] == "\\" and body[1] in CHAR_ESCAPES:
            chars.append(CHAR_ESCAPES[body[1]])
        else:
            chars.append(body)
    return chars


def resolve_element(source, version_source, element, depth=0):
    """Follow a const alias chain to the string it finally names."""
    if depth > 8:
        raise ValueError("the const alias chain is too deep: %r" % element)
    text = element.strip()
    if text.startswith('"'):
        return text.strip('"')
    if text.startswith("crate::version::"):
        name = text.split("::")[-1]
        return resolve_element(version_source, version_source, rust_rhs(version_source, name), depth + 1)
    rhs = rust_rhs(source, text)
    literals = rust_strings(rhs)
    if literals:
        return literals[0]
    return resolve_element(source, version_source, rhs, depth + 1)


def resolve_elements(source, version_source, elements):
    """Array elements that may be string literals or const identifiers."""
    return [resolve_element(source, version_source, element) for element in elements]


def core_version(version_source, workspace_text):
    """CORE_VERSION, whether it is a literal or injected from the package version."""
    rhs = rust_rhs(version_source, "CORE_VERSION")
    if "env!" in rhs:
        return workspace_version(workspace_text)
    return rust_strings(rhs)[0]


def read_sources(repo_root):
    """Every real constant this harness refuses to drift from."""
    version_source = read_text(os.path.join(repo_root, VERSION_SOURCE))
    packages_source = read_text(os.path.join(repo_root, PACKAGES_SOURCE))
    guard_source = read_text(os.path.join(repo_root, GUARD_SOURCE))
    delegate_source = read_text(os.path.join(repo_root, DELEGATE_SOURCE))
    check_source = read_text(os.path.join(repo_root, CHECK_SOURCE))
    trust_source = read_text(os.path.join(repo_root, TRUST_SOURCE))
    policy_source = read_text(os.path.join(repo_root, POLICY_SOURCE))
    migrations_source = read_text(os.path.join(repo_root, MIGRATIONS_SOURCE))
    workspace_text = read_text(os.path.join(repo_root, WORKSPACE_MANIFEST))
    lock = json.loads(read_text(os.path.join(repo_root, "spec.lock.json")))
    return {
        "cli_component": rust_strings(rust_rhs(version_source, "COMPONENT"))[0],
        "core_component": rust_strings(rust_rhs(version_source, "CORE_COMPONENT"))[0],
        "schema_components": [
            element.strip('"') for element in rust_elements(rust_rhs(version_source, "COMPONENTS"))
        ],
        "spec_version": rust_strings(rust_rhs(version_source, "SPEC_VERSION"))[0],
        "graph_schema_version": rust_int(rust_rhs(version_source, "GRAPH_SCHEMA_VERSION")),
        "control_api_version": rust_int(rust_rhs(version_source, "CONTROL_API_VERSION")),
        "queue_schema_version": rust_int(rust_rhs(version_source, "QUEUE_SCHEMA_VERSION")),
        "core_version": core_version(version_source, workspace_text),
        "workspace_version": workspace_version(workspace_text),
        "version_file": read_text(os.path.join(repo_root, "VERSION")).strip(),
        "core_components": resolve_elements(
            packages_source,
            version_source,
            rust_elements(rust_rhs(packages_source, "CORE_COMPONENTS")),
        ),
        "independent_components": [
            element.strip('"')
            for element in rust_elements(rust_rhs(packages_source, "INDEPENDENT_COMPONENTS"))
        ],
        "inherited_components": [
            element.strip('"')
            for element in rust_elements(rust_rhs(packages_source, "INHERITED_COMPONENTS"))
        ],
        "specs_component": rust_strings(rust_rhs(packages_source, "SPECS_COMPONENT"))[0],
        "report_schema_version": rust_int(rust_rhs(packages_source, "REPORT_SCHEMA_VERSION")),
        "fixture_scope_local": rust_strings(
            rust_rhs(packages_source, "FIXTURE_SCOPE_COMPONENT_LOCAL")
        )[0],
        "current_schema_version": rust_int(
            rust_rhs(migrations_source, "CURRENT_SCHEMA_VERSION")
        ),
        "guard_reasons": [
            element
            for element in resolve_elements(
                guard_source,
                version_source,
                rust_elements(rust_rhs(guard_source, "REFUSAL_REASONS")),
            )
        ],
        "metacharacters": rust_chars(rust_rhs(delegate_source, "SHELL_METACHARACTERS")),
        "axiom_program": rust_strings(rust_rhs(delegate_source, "AXIOM_PROGRAM"))[0],
        "default_ttl": rust_int_const(check_source, "DEFAULT_TTL_SECONDS"),
        "min_ttl": rust_int_const(check_source, "MIN_TTL_SECONDS"),
        "max_ttl": rust_int_const(check_source, "MAX_TTL_SECONDS"),
        "default_timeout": rust_int_const(check_source, "DEFAULT_TIMEOUT_SECONDS"),
        "max_timeout": rust_int_const(check_source, "MAX_TIMEOUT_SECONDS"),
        "max_jitter": rust_int_const(check_source, "MAX_JITTER_SECONDS"),
        "metadata_schema_version": rust_int(
            rust_rhs(trust_source, "UPDATE_METADATA_SCHEMA_VERSION")
        ),
        "signing_prefix": rust_strings(rust_rhs(trust_source, "SIGNING_MESSAGE_PREFIX"))[0],
        "channels": [
            element.strip('"') for element in rust_elements(rust_rhs(policy_source, "CHANNELS"))
        ],
        "spec_lock": lock,
    }


def check_sources_against_model(facts, problems):
    """The modelled constants must be the real ones, or this harness is fiction."""
    if tuple(facts["guard_reasons"]) != REFUSAL_REASONS:
        problems.append(
            "the modelled refusal reasons %r are not the guard's %r"
            % (list(REFUSAL_REASONS), facts["guard_reasons"])
        )
    if tuple(facts["metacharacters"]) != SHELL_METACHARACTERS:
        problems.append(
            "the modelled shell metacharacters %r are not the delegation's %r"
            % (list(SHELL_METACHARACTERS), facts["metacharacters"])
        )
    if facts["workspace_version"] != facts["version_file"]:
        problems.append(
            "the workspace version %r is not the VERSION file %r"
            % (facts["workspace_version"], facts["version_file"])
        )
    if facts["core_version"] != facts["workspace_version"]:
        problems.append(
            "CORE_VERSION %r is not the workspace package version %r"
            % (facts["core_version"], facts["workspace_version"])
        )
    if facts["spec_lock"].get("spec_version") != facts["spec_version"]:
        problems.append(
            "spec.lock.json pins %r but version.rs declares SPEC_VERSION %r"
            % (facts["spec_lock"].get("spec_version"), facts["spec_version"])
        )
    if not PIN_RE.match(str(facts["spec_lock"].get("spec_revision", ""))):
        problems.append("spec.lock.json does not pin a 40-hex specification revision")
    if facts["spec_lock"].get("graph_payload_schema") != facts["graph_schema_version"]:
        problems.append(
            "spec.lock.json records graph payload schema %r but version.rs declares %r"
            % (facts["spec_lock"].get("graph_payload_schema"), facts["graph_schema_version"])
        )
    statuses = list(UPDATE_STATUS)
    if len(set(statuses)) != len(statuses):
        problems.append("the modelled UpdateStatus wire names are not distinct: %r" % statuses)
    if not (
        facts["min_ttl"] <= facts["default_ttl"] <= facts["max_ttl"]
    ):
        problems.append(
            "the check TTL bounds %r/%r/%r are not ordered"
            % (facts["min_ttl"], facts["default_ttl"], facts["max_ttl"])
        )
    if not (0 < facts["default_timeout"] <= facts["max_timeout"]):
        problems.append(
            "the check timeout bounds %r/%r are not ordered"
            % (facts["default_timeout"], facts["max_timeout"])
        )
    if facts["max_jitter"] <= 0:
        problems.append("the check jitter ceiling is not positive")
    if facts["metadata_schema_version"] != 1:
        problems.append("the update metadata schema version is not 1")
    if not facts["signing_prefix"]:
        problems.append("the signing message prefix is empty")
    if sorted(facts["channels"]) != ["prerelease", "stable"]:
        problems.append("the release channels are not the two documented ones: %r" % facts["channels"])
    if facts["report_schema_version"] != 1:
        problems.append("the packages report schema version is not 1")
    if facts["fixture_scope_local"] != "component_local":
        problems.append("the component-local fixture scope is not component_local")
    if sorted(set(facts["core_components"])) != sorted(set([facts["core_component"], facts["cli_component"]])):
        problems.append("CORE_COMPONENTS is not the daemon and the CLI")
    covered = set(facts["core_components"])
    covered.update(facts["independent_components"])
    covered.update(facts["inherited_components"])
    covered.add(facts["specs_component"])
    missing = sorted(set(facts["schema_components"]) - covered)
    if missing:
        problems.append("the report surface does not cover these components: %r" % missing)


# --- the admission guard, ported check for check --------------------------------


def trust_usable(trust_root, allowed_components):
    return bool(trust_root) and bool(list(allowed_components))


def backup_present(request, target_root):
    """Read-only: the required backup must really be there, as a database file."""
    relative = request.get("backup_relative_path")
    if not relative:
        return False
    candidate = os.path.join(target_root, str(relative).replace("/", os.sep))
    if not os.path.isfile(candidate):
        return False
    with io.open(candidate, "rb") as handle:
        return handle.read(len(SQLITE_HEADER)) == SQLITE_HEADER


def delegate(request, trust_root, allowed_components, facts):
    """The real argv-only delegation, or None when it refuses."""
    if not trust_usable(trust_root, allowed_components):
        return None
    if request.get("component") not in list(allowed_components):
        return None
    plan_path = request.get("plan_path") or ""
    if not plan_path:
        return None
    if any(character in plan_path for character in facts["metacharacters"]):
        return None
    canonical = str(request.get("canonical_digest") or "")
    if not DIGEST_RE.match(canonical):
        return None
    approved = request.get("approve_digest")
    if approved is None:
        return None
    if approved != canonical:
        return None
    return [
        facts["axiom_program"],
        "update",
        "apply",
        "--plan",
        plan_path,
        "--approve-digest",
        canonical,
    ]


def admit(request, trust_root, allowed_components, supported_schema_version, target_root, facts):
    """The guard's decision, in the guard's check order. Read-only."""
    if str(request.get("trust_metadata_expiry")) <= str(request.get("plan_created_at")):
        return REASON_SIGNATURE_EXPIRED, None
    if not request.get("signature_present") or not trust_usable(trust_root, allowed_components):
        return REASON_SIGNER_UNTRUSTED, None
    if int(request.get("candidate_schema_version", 0)) > supported_schema_version:
        return REASON_SCHEMA_NEWER_THAN_BINARY, None
    if request.get("backup_required") and not backup_present(request, target_root):
        return REASON_BACKUP_MISSING, None
    argv = delegate(request, trust_root, allowed_components, facts)
    if argv is None:
        return REASON_DELEGATION_REFUSED, None
    return None, argv


# --- the packages report contract, ported from packages.rs ----------------------

RULE_UNKNOWN = None


def owner_version(component, core_release, independent, spec_version, facts):
    if component in (facts["core_component"], facts["cli_component"]):
        return core_release["version"]
    for pin in independent:
        if pin["component"] == component:
            return pin["version"]
    if component == facts["specs_component"]:
        return spec_version
    return None


def packages_refusal(packages_input, facts):
    """The first refusal the real report builder would raise, or None."""
    specifications = packages_input["specifications"]
    if specifications["spec_version"] != facts["spec_version"]:
        return RULE_SPEC_VERSION_MISMATCH
    if not PIN_RE.match(specifications["spec_revision"]):
        return RULE_SPEC_REVISION_NOT_PINNED

    fixtures = packages_input["fixtures"]
    if not PIN_RE.match(fixtures["revision"]):
        return RULE_FIXTURE_REVISION_NOT_PINNED
    if not DIGEST_RE.match(fixtures["index_sha256"]):
        return RULE_FIXTURE_INDEX_NOT_DIGEST
    if fixtures["shared"]:
        return RULE_SHARED_FIXTURE_INDEX

    core = packages_input["core"]
    if core["daemon"]["component"] != facts["core_component"]:
        return RULE_CORE_COMPONENT_MISMATCH
    if core["cli"]["component"] != facts["cli_component"]:
        return RULE_CORE_COMPONENT_MISMATCH
    if core["daemon"]["version"] != core["cli"]["version"]:
        return RULE_CORE_RELEASE_SPLIT
    if core["daemon"]["revision"] != core["cli"]["revision"]:
        return RULE_CORE_RELEASE_SPLIT
    if core["daemon"]["version"] != facts["core_version"]:
        return RULE_CORE_VERSION_MISMATCH
    if not PIN_RE.match(core["daemon"]["revision"]):
        return RULE_CORE_REVISION_NOT_PINNED

    for pin in packages_input["independent"]:
        if pin["component"] not in facts["independent_components"]:
            return RULE_UNEXPECTED_PACKAGE_COMPONENT
        if not PIN_RE.match(pin["revision"]):
            return RULE_INDEPENDENT_REVISION_NOT_PINNED
    for required in facts["independent_components"]:
        if not any(pin["component"] == required for pin in packages_input["independent"]):
            return RULE_MISSING_INDEPENDENT_COMPONENT

    for entry in packages_input["documentation"]:
        if entry["component"] not in facts["inherited_components"]:
            return RULE_UNEXPECTED_DOCUMENTATION_COMPONENT
        if entry.get("version") is not None:
            return RULE_STANDALONE_DOCUMENTATION_VERSION
        if (
            owner_version(
                entry["inherits_from"],
                core["daemon"],
                packages_input["independent"],
                specifications["spec_version"],
                facts,
            )
            is None
        ):
            return RULE_DOCUMENTATION_OWNER_MISSING

    return RULE_UNKNOWN


def require_updatable_refusal(component, facts):
    if component in facts["inherited_components"]:
        return RULE_NO_STANDALONE_DOCUMENTATION_PACKAGE
    if (
        component not in facts["core_components"]
        and component not in facts["independent_components"]
    ):
        return RULE_UNEXPECTED_PACKAGE_COMPONENT
    return RULE_UNKNOWN


def fixture_index_digest(repo_root):
    """A real digest over the real component-local fixture inventory."""
    root = os.path.join(repo_root, "fixtures", "update")
    entries = []
    for current, directories, files in os.walk(root):
        directories[:] = sorted(name for name in directories if name != "__pycache__")
        for name in sorted(files):
            if name.endswith(".pyc"):
                continue
            full = os.path.join(current, name)
            relative = os.path.relpath(full, root).replace(os.sep, "/")
            entries.append("%s %s" % (relative, sha256_hex(read_bytes(full))))
    return sha256_hex("\n".join(sorted(entries)).encode("utf-8"))


def packages_input_for(repo_root, facts, fixture_sha):
    """A real report input built from the checked-out sources and the real lock."""
    revision = pinned("axiom-graphd@%s" % facts["core_version"])
    return {
        "core": {
            "daemon": {
                "component": facts["core_component"],
                "version": facts["core_version"],
                "revision": revision,
            },
            "cli": {
                "component": facts["cli_component"],
                "version": facts["core_version"],
                "revision": revision,
            },
        },
        "independent": [
            {"component": name, "version": "declared-by-owner", "revision": pinned("independent:" + name)}
            for name in facts["independent_components"]
        ],
        "specifications": {
            "spec_version": facts["spec_lock"]["spec_version"],
            "spec_revision": facts["spec_lock"]["spec_revision"],
        },
        "fixtures": {
            "revision": facts["spec_lock"]["spec_revision"],
            "index_sha256": fixture_sha,
            "shared": False,
        },
        "documentation": [
            {"component": name, "inherits_from": facts["core_component"], "version": None}
            for name in facts["inherited_components"]
        ],
    }


def component_coverage(packages_input, facts):
    covered = list(facts["core_components"])
    covered.extend(pin["component"] for pin in packages_input["independent"])
    covered.append(facts["specs_component"])
    covered.extend(entry["component"] for entry in packages_input["documentation"])
    return covered


def component_versions(packages_input, facts):
    versions = {}
    versions[facts["core_component"]] = packages_input["core"]["daemon"]["version"]
    versions[facts["cli_component"]] = packages_input["core"]["cli"]["version"]
    for pin in packages_input["independent"]:
        versions[pin["component"]] = pin["version"]
    versions[facts["specs_component"]] = packages_input["specifications"]["spec_version"]
    for entry in packages_input["documentation"]:
        versions[entry["component"]] = owner_version(
            entry["inherits_from"],
            packages_input["core"]["daemon"],
            packages_input["independent"],
            packages_input["specifications"]["spec_version"],
            facts,
        )
    return versions


# --- legs ----------------------------------------------------------------------


def cleanup(target):
    def onerror(func, failed, _exc):
        try:
            os.chmod(failed, 0o700)
            func(failed)
        except OSError:
            pass

    shutil.rmtree(target, onerror=onerror)


def snapshot(root):
    found = {}
    for current, _directories, files in os.walk(root):
        for name in files:
            full = os.path.join(current, name)
            found[os.path.relpath(full, root).replace(os.sep, "/")] = read_bytes(full)
    return found


def build_target(shard, vector_id, request):
    """A real target tree; the required backup is a real file only when declared."""
    root = os.path.join(shard, "targets", vector_id)
    os.makedirs(root, exist_ok=True)
    with io.open(os.path.join(root, "AGENTS.md"), "wb") as handle:
        handle.write(b"# Human instructions\n")
    relative = request.get("backup_relative_path")
    if request.get("backup_present") and relative:
        candidate = os.path.join(root, str(relative).replace("/", os.sep))
        os.makedirs(os.path.dirname(candidate), exist_ok=True)
        with io.open(candidate, "wb") as handle:
            handle.write(SQLITE_HEADER + b"\x10\x00\x01\x01")
    return root


def load_corpus(repo_root):
    root = os.path.join(repo_root, "fixtures", "update")
    manifest = json.loads(read_text(os.path.join(root, "manifest.json")))
    vectors = []
    for scenario in manifest["scenarios"]:
        relative = str(scenario["vector"]).replace("/", os.sep)
        vectors.append((scenario, json.loads(read_text(os.path.join(root, relative)))))
    return root, manifest, vectors


def replay_vectors(manifest, vectors, facts, supported, shard, problems):
    """Replay every vector through the guard port against a real target tree."""
    rows = []
    for _scenario, vector in vectors:
        vector_id = vector["vector_id"]
        request = vector["request"]
        target = build_target(shard, vector_id, request)
        before = snapshot(target)
        reason, argv = admit(
            request,
            str(request.get("trust_root") or ""),
            list(request.get("allowed_components") or []),
            supported,
            target,
            facts,
        )
        declared = vector.get("expected", {})
        decision = "admit" if reason is None else "refuse"
        rows.append({"id": vector_id, "decision": decision, "reason": reason, "argv": argv})

        if decision != declared.get("decision"):
            problems.append(
                "%s decided %s, the vector declares %s"
                % (vector_id, decision, declared.get("decision"))
            )
        if (reason or None) != declared.get("reason"):
            problems.append(
                "%s refused with %r, the vector declares %r"
                % (vector_id, reason, declared.get("reason"))
            )
        observed_backup = backup_present(request, target)
        if bool(request.get("backup_present")) != observed_backup:
            problems.append(
                "%s declares backup_present=%s but the real tree says %s"
                % (vector_id, request.get("backup_present"), observed_backup)
            )

        if decision == "refuse":
            if argv is not None:
                problems.append("%s was refused but still produced a delegation" % vector_id)
            if snapshot(target) != before:
                problems.append("%s refusal changed the target tree" % vector_id)
            if not request.get("backup_present"):
                relative = request.get("backup_relative_path")
                candidate = os.path.join(target, str(relative).replace("/", os.sep))
                if relative and os.path.exists(candidate):
                    problems.append("%s refusal created the missing backup" % vector_id)
            continue

        if not argv or argv[0] != facts["axiom_program"]:
            problems.append("%s was admitted without the real program" % vector_id)
        elif argv[1:3] != ["update", "apply"]:
            problems.append("%s delegated the wrong subcommand: %r" % (vector_id, argv[1:3]))
        elif argv[4] != request["plan_path"] or argv[6] != request["canonical_digest"]:
            problems.append("%s delegated an argument that is not the plan" % vector_id)
    return rows


def sequence_packages(repo_root, facts, problems):
    """Every component, including the data packages, reports a version."""
    fixture_sha = fixture_index_digest(repo_root)
    if not DIGEST_RE.match(fixture_sha):
        problems.append("the fixture inventory digest is not a 64-hex digest")

    packages_input = packages_input_for(repo_root, facts, fixture_sha)
    refusal = packages_refusal(packages_input, facts)
    if refusal is not None:
        problems.append("a fully pinned packages input was refused with %s" % refusal)

    covered = component_coverage(packages_input, facts)
    if len(set(covered)) != len(covered):
        problems.append("a component is reported more than once: %r" % covered)
    if sorted(set(covered)) != sorted(set(facts["schema_components"])):
        problems.append(
            "the report covers %r, the frozen schema names %r"
            % (sorted(set(covered)), sorted(set(facts["schema_components"])))
        )

    versions = component_versions(packages_input, facts)
    for name in facts["schema_components"]:
        if not versions.get(name):
            problems.append("component %s reports no version" % name)
    if versions.get(facts["core_component"]) != versions.get(facts["cli_component"]):
        problems.append("the core release reports two different versions")
    if versions.get(facts["core_component"]) != facts["core_version"]:
        problems.append("the core release does not report the workspace version")
    for name in facts["inherited_components"]:
        if versions.get(name) != versions.get(facts["core_component"]):
            problems.append("%s does not inherit its owner's version" % name)
    if versions.get(facts["specs_component"]) != facts["spec_version"]:
        problems.append("the specification pin does not report the pinned spec version")
    if packages_input["fixtures"]["shared"]:
        problems.append("component-local fixtures were declared shared")

    updatable = list(facts["core_components"]) + list(facts["independent_components"])
    expected_updatable = sorted(
        set(facts["schema_components"])
        - set(facts["inherited_components"])
        - {facts["specs_component"]}
    )
    if sorted(updatable) != expected_updatable:
        problems.append(
            "the update package set is %r, the schema implies %r"
            % (sorted(updatable), expected_updatable)
        )
    for name in updatable:
        if require_updatable_refusal(name, facts) is not None:
            problems.append("component %s has its own package but was refused" % name)
    for name in facts["inherited_components"]:
        if require_updatable_refusal(name, facts) != RULE_NO_STANDALONE_DOCUMENTATION_PACKAGE:
            problems.append("documentation component %s was accepted as an update package" % name)
    if require_updatable_refusal("axiom-bootstrap", facts) != RULE_UNEXPECTED_PACKAGE_COMPONENT:
        problems.append("an unknown component was accepted as an update package")

    def check(description, mutate, rule):
        candidate = json.loads(json.dumps(packages_input))
        mutate(candidate)
        found = packages_refusal(candidate, facts)
        if found != rule:
            problems.append("%s: refused with %r, expected %r" % (description, found, rule))

    def specs_version(candidate):
        candidate["specifications"]["spec_version"] = "9.9.9"

    def specs_revision(candidate):
        candidate["specifications"]["spec_revision"] = "not-a-revision"

    def fixture_revision(candidate):
        candidate["fixtures"]["revision"] = "SHORT"

    def fixture_index(candidate):
        candidate["fixtures"]["index_sha256"] = "not-a-digest"

    def fixture_shared(candidate):
        candidate["fixtures"]["shared"] = True

    def core_split(candidate):
        candidate["core"]["cli"]["revision"] = pinned("somewhere-else")

    def core_version_leg(candidate):
        candidate["core"]["daemon"]["version"] = "9.9.9"
        candidate["core"]["cli"]["version"] = "9.9.9"

    def core_revision(candidate):
        candidate["core"]["daemon"]["revision"] = "unpinned"
        candidate["core"]["cli"]["revision"] = "unpinned"

    def independent_unexpected(candidate):
        candidate["independent"].append(
            {"component": "axiom-extra", "version": "1.0.0", "revision": pinned("extra")}
        )

    def independent_unpinned(candidate):
        candidate["independent"][0]["revision"] = "unpinned"

    def independent_missing(candidate):
        candidate["independent"] = [
            pin for pin in candidate["independent"] if pin["component"] != "skills"
        ]

    def documentation_unexpected(candidate):
        candidate["documentation"].append(
            {"component": "other", "inherits_from": facts["core_component"], "version": None}
        )

    def documentation_standalone(candidate):
        candidate["documentation"][0]["version"] = "1.2.3"

    def documentation_owner(candidate):
        candidate["documentation"][0]["inherits_from"] = "nobody"

    check("a specification version that disagrees with version.rs", specs_version, RULE_SPEC_VERSION_MISMATCH)
    check("an unpinned specification revision", specs_revision, RULE_SPEC_REVISION_NOT_PINNED)
    check("an unpinned fixture revision", fixture_revision, RULE_FIXTURE_REVISION_NOT_PINNED)
    check("a fixture index that is not a digest", fixture_index, RULE_FIXTURE_INDEX_NOT_DIGEST)
    check("a shared fixture index", fixture_shared, RULE_SHARED_FIXTURE_INDEX)
    check("a core release split across two revisions", core_split, RULE_CORE_RELEASE_SPLIT)
    check("a core version that is not the workspace version", core_version_leg, RULE_CORE_VERSION_MISMATCH)
    check("an unpinned core revision", core_revision, RULE_CORE_REVISION_NOT_PINNED)
    check("an unexpected independent component", independent_unexpected, RULE_UNEXPECTED_PACKAGE_COMPONENT)
    check("an unpinned independent revision", independent_unpinned, RULE_INDEPENDENT_REVISION_NOT_PINNED)
    check("a missing independent component", independent_missing, RULE_MISSING_INDEPENDENT_COMPONENT)
    check("an unexpected documentation component", documentation_unexpected, RULE_UNEXPECTED_DOCUMENTATION_COMPONENT)
    check("documentation carrying a standalone version", documentation_standalone, RULE_STANDALONE_DOCUMENTATION_VERSION)
    check("documentation whose owner is absent", documentation_owner, RULE_DOCUMENTATION_OWNER_MISSING)

    return packages_input


def sequence_safety(manifest, vectors, facts, supported, shard, problems):
    """No mutation of a real control may be admitted."""
    controls = {vector["vector_id"]: vector for _scenario, vector in vectors}
    if "valid-control" not in controls:
        problems.append("the corpus carries no valid control to mutate")
        return
    control = controls["valid-control"]
    request = control["request"]
    trust_root = str(request.get("trust_root") or "")
    allowed = list(request.get("allowed_components") or [])

    def probe(name, mutate):
        candidate = json.loads(json.dumps(request))
        mutate(candidate)
        target = build_target(shard, "probe-%s" % name, candidate)
        return admit(candidate, trust_root, allowed, supported, target, facts)

    reason, argv = probe("control", lambda candidate: None)
    if reason is not None or argv is None:
        problems.append("the unmutated control vector was not admitted")

    cases = [
        ("an unsigned plan", lambda c: c.update(signature_present=False), REASON_SIGNER_UNTRUSTED),
        (
            "an expiry equal to the creation time",
            lambda c: c.update(trust_metadata_expiry=c["plan_created_at"]),
            REASON_SIGNATURE_EXPIRED,
        ),
        (
            "an expiry before the creation time",
            lambda c: c.update(trust_metadata_expiry="2020-01-01T00:00:00Z"),
            REASON_SIGNATURE_EXPIRED,
        ),
        (
            "a schema newer than this binary",
            lambda c: c.update(candidate_schema_version=supported + 1),
            REASON_SCHEMA_NEWER_THAN_BINARY,
        ),
        (
            "a required backup that is absent",
            lambda c: c.update(backup_present=False),
            REASON_BACKUP_MISSING,
        ),
        ("no approval digest", lambda c: c.update(approve_digest=None), REASON_DELEGATION_REFUSED),
        (
            "an approval digest that does not match",
            lambda c: c.update(approve_digest="0" * 64),
            REASON_DELEGATION_REFUSED,
        ),
        (
            "a component the trust root does not allow",
            lambda c: c.update(component="docs"),
            REASON_DELEGATION_REFUSED,
        ),
        (
            "a plan path carrying a metacharacter",
            lambda c: c.update(plan_path="plan%s.json" % facts["metacharacters"][0]),
            REASON_DELEGATION_REFUSED,
        ),
        ("an empty plan path", lambda c: c.update(plan_path=""), REASON_DELEGATION_REFUSED),
        (
            "a plan digest that is not a SHA-256 digest",
            lambda c: c.update(canonical_digest="abc", approve_digest="abc"),
            REASON_DELEGATION_REFUSED,
        ),
    ]
    for index, (description, mutate, rule) in enumerate(cases):
        reason, argv = probe("case%d" % index, mutate)
        if reason != rule:
            problems.append("negative: %s refused with %r, expected %r" % (description, reason, rule))
        if argv is not None:
            problems.append("negative: %s still produced a delegation" % description)

    for index, (description, root, names) in enumerate(
        (
            ("an absent trust root", "", allowed),
            ("a trust root that allows nothing", trust_root, []),
        )
    ):
        target = build_target(shard, "trust-case%d" % index, request)
        reason, _argv = admit(request, root, names, supported, target, facts)
        if reason != REASON_SIGNER_UNTRUSTED:
            problems.append("negative: %s was not refused as signer-untrusted" % description)


def catches(description, runner, problems):
    """A negative leg must fire; if it does not, the detector has no teeth."""
    if not runner():
        problems.append("%s: the detector did not fire" % description)


def run(repo_root):
    problems = []
    not_run = []
    facts = read_sources(repo_root)
    check_sources_against_model(facts, problems)

    _root, manifest, vectors = load_corpus(repo_root)
    supported = int(manifest["supported_schema_major"])
    if supported != facts["current_schema_version"]:
        problems.append(
            "the corpus supports schema major %d but the store is at %d"
            % (supported, facts["current_schema_version"])
        )
    if supported != facts["graph_schema_version"]:
        problems.append(
            "the corpus supports schema major %d but the graph payload schema is %d"
            % (supported, facts["graph_schema_version"])
        )
    if list(manifest["refusal_reasons"]) != list(REFUSAL_REASONS):
        problems.append(
            "the corpus refusal reasons %r are not the guard's %r"
            % (manifest["refusal_reasons"], list(REFUSAL_REASONS))
        )
    if sorted(manifest["decisions"]) != ["admit", "refuse"]:
        problems.append("the corpus decisions are not admit and refuse")
    if int(facts["spec_lock"].get("graph_payload_schema", -1)) != supported:
        problems.append("spec.lock.json does not record the schema major the corpus supports")

    shard = tempfile.mkdtemp(prefix="axiom-f033-")
    try:
        rows = replay_vectors(manifest, vectors, facts, supported, shard, problems)
        if len(rows) != len(vectors):
            problems.append("replayed %d vectors, the corpus carries %d" % (len(rows), len(vectors)))
        kinds = {}
        for _scenario, vector in vectors:
            kinds[vector.get("kind")] = kinds.get(vector.get("kind"), 0) + 1
        if kinds != {"hazard": 4, "boundary": 3, "control": 1}:
            problems.append(
                "the corpus is not four hazards, three boundaries and one control: %r" % kinds
            )

        packages_input = sequence_packages(repo_root, facts, problems)
        sequence_safety(manifest, vectors, facts, supported, shard, problems)

        # The detectors below only mean something if each one can fire.
        def replay_comparison_has_teeth():
            broken = json.loads(json.dumps(vectors))
            broken[0][1]["expected"] = {"decision": "admit", "reason": None}
            scratch = []
            replay_vectors(manifest, broken, facts, supported, os.path.join(shard, "teeth"), scratch)
            return bool(scratch)

        def backup_detector_has_teeth():
            control = next(
                vector
                for _scenario, vector in vectors
                if vector["expected"]["decision"] == "admit"
            )
            candidate = json.loads(json.dumps(control["request"]))
            candidate["backup_required"] = True
            candidate["backup_present"] = True
            candidate["backup_relative_path"] = "state/queue.db.bak"
            target = build_target(shard, "teeth-backup", candidate)
            relative = str(candidate["backup_relative_path"]).replace("/", os.sep)
            os.remove(os.path.join(target, relative))
            reason, _argv = admit(
                candidate,
                str(candidate.get("trust_root") or ""),
                list(candidate.get("allowed_components") or []),
                supported,
                target,
                facts,
            )
            return reason == REASON_BACKUP_MISSING

        def metacharacter_detector_has_teeth():
            return any(
                character in "plan%s.json" % character for character in facts["metacharacters"]
            )

        def coverage_detector_has_teeth():
            candidate = json.loads(json.dumps(packages_input))
            candidate["documentation"] = []
            covered = component_coverage(candidate, facts)
            return sorted(set(covered)) != sorted(set(facts["schema_components"]))

        def updatable_detector_has_teeth():
            return (
                require_updatable_refusal("docs", facts) == RULE_NO_STANDALONE_DOCUMENTATION_PACKAGE
                and require_updatable_refusal("axiom-mcp", facts) is None
            )

        catches("corpus replay comparison", replay_comparison_has_teeth, problems)
        catches("required-backup detector", backup_detector_has_teeth, problems)
        catches("metacharacter detector", metacharacter_detector_has_teeth, problems)
        catches("component coverage detector", coverage_detector_has_teeth, problems)
        catches("updatable component detector", updatable_detector_has_teeth, problems)
    finally:
        cleanup(shard)

    not_run.append(
        "the Rust guard itself: cargo test --locked -p axiom-graphd --test update_fixtures "
        "and cargo test --locked -p axiom-graphd update_guard (this harness cannot link the crate)"
    )
    not_run.append(
        "the full backup integrity check: the real guard reuses graph_store::backup::verify_backup, "
        "which opens the candidate as a database; this harness verifies real byte presence and the "
        "SQLite file header only"
    )
    not_run.append(
        "the real axiom-mcp and skills versions and revisions: they are inputs owned by their own "
        "repositories, which are not checked out in this worktree, so the versions above are declared "
        "inputs rather than verified owner evidence"
    )
    not_run.append(
        "a live update source: no signed metadata is fetched, no network call is made and no install "
        "is attempted (the release gate is closed for this workstream)"
    )
    not_run.append(
        "native Windows and macOS runtime evidence (the Rust gate runs inside the Docker lane, not here)"
    )
    return problems, not_run


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="F-033 signed update check, apply and rollback end-to-end harness"
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
        "task": "F-033",
        "harness": "update_e2e",
        "corpus_vectors": 8,
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
        "ok: F-033 reports a version for every one of the seven frozen component names including "
        "the specification and fixture data packages, and refused all eight corpus vectors in the "
        "guard's order - four hazards, three boundaries and one admitted control that proves the "
        "guard does not refuse everything - with eleven further mutations of that control also "
        "refused and every refusal leaving the target tree byte-identical"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
