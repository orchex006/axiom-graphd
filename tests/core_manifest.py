#!/usr/bin/env python3
"""Release manifest check E-048 - one core release carrying daemon plus CLI.

`axiom-specs/docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 9 makes a release a
set of immutable artifacts built from one approved commit, carrying checksums, an
SBOM and signatures, and it forbids placeholder metadata. `release/core-manifest.json`
declares that release for this repository; this harness is the regression check
over it, so a manifest that drifts from the real workspace files fails here
instead of at release time.

Verified for real here (no Docker, no network, no third-party module):

* composition - exactly one release, exactly the daemon (`axiom-graphd`) and the
  installation CLI (`axiom`), the same version and the same revision for both, and
  no separate bootstrap component;
* version provenance - the declared version equals
  `Cargo.toml [workspace.package].version` and both component crates are listed
  workspace members;
* source provenance - the recorded SHA-256 of `Cargo.toml` and `Cargo.lock` is
  recomputed from the real bytes on disk;
* targets - exactly the three triples declared in
  `crates/axiom-graphd/src/release.rs`, each shipping both executables, with an
  archive and an SBOM whose declared state is internally consistent;
* compatibility - `spec_version`, `graph_schema_version`, `control_api_version`
  and `queue_schema_version` equal the constants in `crates/axiom/src/version.rs`;
* honesty - a published release must be pinned, built, signed and tagged, so the
  checked-in manifest must be *not* publishable and must not claim otherwise.

Reported as not_run, because a real release action is outside this workstream and
the release gate stays closed:

* building and hashing the per-target archives;
* producing and hashing the SBOMs;
* signing with the release key;
* creating the tag and publishing;
* clean-user installation evidence from a signed artifact.

Negative legs (each must be caught by the same validator):

* the two components carrying different revisions;
* a reintroduced `axiom-bootstrap` component;
* a component version that disagrees with the workspace version;
* an archive marked built with a placeholder or short digest;
* a target that ships only the daemon and not the CLI;
* a target triple that `release.rs` does not declare;
* a compatibility block that drifts from `crates/axiom/src/version.rs`;
* a tampered source digest;
* a publication state that claims `published` while nothing was built.

Exit codes: 0 every property held and every negative leg was rejected, 2 a
divergence, 1 a usage or I/O failure.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
import platform
import re
import sys

MANIFEST_PATH = os.path.join("release", "core-manifest.json")
CARGO_TOML = "Cargo.toml"
CARGO_LOCK = "Cargo.lock"
VERSION_RS = os.path.join("crates", "axiom", "src", "version.rs")
RELEASE_RS = os.path.join("crates", "axiom-graphd", "src", "release.rs")

HEX = "0123456789abcdef"
PLACEHOLDERS = ("replace", "todo", "fill_me", "fillme", "unknown", "latest", "example", "changeme")

# name -> role, exactly the components one core release may contain.
EXPECTED_COMPONENTS = {"axiom-graphd": "daemon", "axiom": "cli"}

# platform -> (os, arch, rust target), exactly the rows build-matrix.md declares.
EXPECTED_TARGETS = {
    "windows-x64": ("windows", "x86_64", "x86_64-pc-windows-msvc"),
    "linux-x64": ("linux", "x86_64", "x86_64-unknown-linux-gnu"),
    "macos-arm64": ("macos", "aarch64", "aarch64-apple-darwin"),
}

# os -> the daemon and the CLI each archive must carry.
EXPECTED_EXECUTABLES = {
    "windows": ("axiom-graphd.exe", "axiom.exe"),
    "linux": ("axiom-graphd", "axiom"),
    "macos": ("axiom-graphd", "axiom"),
}


def read_text(path):
    with io.open(path, encoding="utf-8") as handle:
        return handle.read()


def read_json(path):
    with io.open(path, encoding="utf-8") as handle:
        return json.load(handle)


def sha256_file(path):
    digest = hashlib.sha256()
    with io.open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_digest(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in HEX for character in value)
        and not looks_placeholder(value)
    )


def is_commit(value):
    return isinstance(value, str) and len(value) == 40 and all(character in HEX for character in value)


def looks_placeholder(value):
    if not isinstance(value, str):
        return True
    lowered = value.lower()
    return any(marker in lowered for marker in PLACEHOLDERS)


def toml_block(text, header):
    """The body of one `[header]` section, or an empty string."""
    match = re.search(r"^\[%s\]\s*$(.*?)(?=^\[|\Z)" % re.escape(header), text, re.M | re.S)
    return match.group(1) if match else ""


def workspace_version(toml_text):
    match = re.search(r'^version\s*=\s*"([^"]+)"', toml_block(toml_text, "workspace.package"), re.M)
    return match.group(1) if match else None


def workspace_members(toml_text):
    match = re.search(r"members\s*=\s*\[(.*?)\]", toml_block(toml_text, "workspace"), re.S)
    if not match:
        return []
    return re.findall(r'"([^"]+)"', match.group(1))


def rust_str_const(source, name):
    match = re.search(r'pub const %s:\s*&str\s*=\s*"([^"]*)"' % re.escape(name), source)
    return match.group(1) if match else None


def rust_u32_const(source, name):
    match = re.search(r"pub const %s:\s*u32\s*=\s*(\d+)" % re.escape(name), source)
    return int(match.group(1)) if match else None

def problems_in(manifest, repo_root):
    """Every property `release/core-manifest.json` must satisfy.

    An empty list means the declaration is internally consistent, agrees with
    `Cargo.toml` and `crates/axiom/src/version.rs`, and matches the source bytes
    it records.
    """
    problems = []

    if manifest.get("manifest_version") != 1:
        problems.append("manifest_version must be 1, got %r" % manifest.get("manifest_version"))
    if manifest.get("manifest_kind") != "axiom-core-release":
        problems.append("manifest_kind must be axiom-core-release, got %r" % manifest.get("manifest_kind"))
    if manifest.get("owner_repository") != "axiom-graphd":
        problems.append("owner_repository must be axiom-graphd, got %r" % manifest.get("owner_repository"))

    release = manifest.get("release")
    if not isinstance(release, dict):
        return problems + ["release must be an object"]

    version = release.get("version")
    revision = release.get("revision")

    components = release.get("components")
    if not isinstance(components, list):
        return problems + ["release.components must be a list"]
    names = [component.get("name") for component in components]
    if sorted(name for name in names if name is not None) != sorted(EXPECTED_COMPONENTS) or len(names) != len(EXPECTED_COMPONENTS):
        problems.append(
            "components must be exactly %s, got %r" % (sorted(EXPECTED_COMPONENTS), names)
        )
    for component in components:
        name = component.get("name")
        expected_role = EXPECTED_COMPONENTS.get(name)
        if expected_role is not None and component.get("role") != expected_role:
            problems.append("component %s role %r != %r" % (name, component.get("role"), expected_role))
        if component.get("version") != version:
            problems.append(
                "component %s version %r does not agree with the release version %r"
                % (name, component.get("version"), version)
            )
        if component.get("revision") != revision:
            problems.append(
                "component %s revision %r is not the same revision as the release %r"
                % (name, component.get("revision"), revision)
            )
        if "bootstrap" in (name or "").lower():
            problems.append("component %s reintroduces a separate bootstrap component" % name)
    if release.get("separate_bootstrap_component") is not None:
        problems.append("separate_bootstrap_component must be null: there is no second bootstrap release")

    toml_path = os.path.join(repo_root, CARGO_TOML)
    toml_text = read_text(toml_path) if os.path.isfile(toml_path) else None
    if toml_text is None:
        problems.append("%s is missing" % CARGO_TOML)
    else:
        declared = workspace_version(toml_text)
        if declared != version:
            problems.append(
                "release version %r does not agree with %s [workspace.package].version %r"
                % (version, CARGO_TOML, declared)
            )
        members = workspace_members(toml_text)
        for component in components:
            package_path = component.get("cargo_package")
            if package_path not in members:
                problems.append(
                    "component %s cargo_package %r is not a workspace member"
                    % (component.get("name"), package_path)
                )

    source = release.get("source")
    if not isinstance(source, dict):
        problems.append("release.source must be an object")
    else:
        for digest_key, path_key in (
            ("workspace_toml_sha256", "workspace_toml"),
            ("lockfile_sha256", "lockfile"),
        ):
            relative = source.get(path_key)
            if not isinstance(relative, str) or not relative:
                problems.append("release.source.%s must name a file" % path_key)
                continue
            absolute = os.path.join(repo_root, relative)
            if not os.path.isfile(absolute):
                problems.append("release.source.%s names a missing file %r" % (path_key, relative))
                continue
            recorded = source.get(digest_key)
            actual = sha256_file(absolute)
            if not is_digest(recorded):
                problems.append("release.source.%s is not a 64-hex digest: %r" % (digest_key, recorded))
            elif recorded != actual:
                problems.append(
                    "release.source.%s records %s but %s hashes to %s"
                    % (digest_key, recorded, relative, actual)
                )

    targets = release.get("targets")
    if not isinstance(targets, list) or not targets:
        problems.append("release.targets must be a non-empty list")
        targets = []

    release_rs_path = os.path.join(repo_root, RELEASE_RS)
    release_rs = read_text(release_rs_path) if os.path.isfile(release_rs_path) else ""
    if not release_rs:
        problems.append("%s is missing, so no target triple can be confirmed" % RELEASE_RS)

    declared_platforms = [target.get("platform") for target in targets]
    if sorted(declared_platforms) != sorted(EXPECTED_TARGETS):
        problems.append(
            "targets must be exactly %s, got %r" % (sorted(EXPECTED_TARGETS), declared_platforms)
        )

    for target in targets:
        platform_name = target.get("platform")
        row = EXPECTED_TARGETS.get(platform_name)
        if row is None:
            problems.append("target platform %r is not a declared build-matrix row" % platform_name)
            continue
        os_name, arch, triple = row
        if target.get("os") != os_name or target.get("arch") != arch:
            problems.append(
                "target %s must be os=%r arch=%r, got os=%r arch=%r"
                % (platform_name, os_name, arch, target.get("os"), target.get("arch"))
            )
        if target.get("rust_target") != triple:
            problems.append(
                "target %s must name the triple %r, got %r"
                % (platform_name, triple, target.get("rust_target"))
            )
        elif triple not in release_rs:
            problems.append(
                "target %s triple %r is not declared in %s" % (platform_name, triple, RELEASE_RS)
            )
        executables = target.get("executables")
        expected_executables = set(EXPECTED_EXECUTABLES.get(os_name, ()))
        if not isinstance(executables, list) or set(executables) != expected_executables:
            problems.append(
                "target %s must ship the daemon and the CLI exactly (%s), got %r"
                % (platform_name, sorted(expected_executables), executables)
            )
        for kind in ("archive", "sbom"):
            block = target.get(kind)
            if not isinstance(block, dict):
                problems.append("target %s %s must be an object" % (platform_name, kind))
                continue
            name = block.get("name")
            if not isinstance(name, str) or not name or looks_placeholder(name):
                problems.append("target %s %s name is a placeholder: %r" % (platform_name, kind, name))
            elif version and str(version) not in name:
                problems.append(
                    "target %s %s name %r does not carry the release version %r"
                    % (platform_name, kind, name, version)
                )
            state = block.get("state")
            digest = block.get("sha256")
            if state == "not_built":
                if digest is not None:
                    problems.append(
                        "target %s %s is not_built but records a digest %r" % (platform_name, kind, digest)
                    )
            elif state == "built":
                if not is_digest(digest):
                    problems.append(
                        "target %s %s is built but its digest is not 64-hex: %r"
                        % (platform_name, kind, digest)
                    )
            else:
                problems.append("target %s %s has an unknown state %r" % (platform_name, kind, state))
        target_signature = target.get("signature")
        if not isinstance(target_signature, dict):
            problems.append("target %s signature must be an object" % platform_name)
        else:
            state = target_signature.get("state")
            if state not in ("required", "signed"):
                problems.append(
                    "target %s signature state %r is neither required nor signed" % (platform_name, state)
                )
            elif state == "signed" and not target_signature.get("key_id"):
                problems.append("target %s is signed but records no key id" % platform_name)
            elif state == "required" and target_signature.get("key_id") is not None:
                problems.append("target %s is required but records a key id" % platform_name)

    compatibility = release.get("compatibility")
    if not isinstance(compatibility, dict):
        problems.append("release.compatibility must be an object")
    else:
        version_rs_path = os.path.join(repo_root, VERSION_RS)
        version_rs = read_text(version_rs_path) if os.path.isfile(version_rs_path) else ""
        if not version_rs:
            problems.append("%s is missing, so compatibility cannot be checked" % VERSION_RS)
        else:
            expected_compatibility = {
                "spec_version": rust_str_const(version_rs, "SPEC_VERSION"),
                "graph_schema_version": rust_u32_const(version_rs, "GRAPH_SCHEMA_VERSION"),
                "control_api_version": rust_u32_const(version_rs, "CONTROL_API_VERSION"),
                "queue_schema_version": rust_u32_const(version_rs, "QUEUE_SCHEMA_VERSION"),
            }
            for key, expected in expected_compatibility.items():
                if expected is None:
                    problems.append("could not read %s from %s" % (key, VERSION_RS))
                elif compatibility.get(key) != expected:
                    problems.append(
                        "compatibility.%s is %r but %s declares %r"
                        % (key, compatibility.get(key), VERSION_RS, expected)
                    )

    revision_state = release.get("revision_state")
    if is_commit(revision):
        if revision_state != "pinned":
            problems.append("a pinned revision must record revision_state pinned, got %r" % revision_state)
    elif revision == "unpinned":
        if revision_state != "not_pinned":
            problems.append("an unpinned release must record revision_state not_pinned, got %r" % revision_state)
    else:
        problems.append(
            "release.revision must be a 40-hex commit or the literal 'unpinned', got %r" % revision
        )

    signature = release.get("signature")
    if not isinstance(signature, dict):
        problems.append("release.signature must be an object")
    else:
        state = signature.get("state")
        if state not in ("required", "signed"):
            problems.append("release.signature.state %r is neither required nor signed" % state)
        elif state == "signed" and not signature.get("key_id"):
            problems.append("release.signature is signed but records no key id")
        elif state == "required" and signature.get("key_id") is not None:
            problems.append("release.signature is required but records a key id")

    publication = release.get("publication")
    if not isinstance(publication, dict):
        problems.append("release.publication must be an object")
    else:
        state = publication.get("state")
        if state not in ("not_published", "published"):
            problems.append(
                "release.publication.state %r is neither not_published nor published" % state
            )
        if state == "published":
            if not is_commit(revision):
                problems.append("release.publication is published while the revision is not pinned")
            if publication.get("tag") != "v%s" % version:
                problems.append(
                    "release.publication is published but its tag is %r, expected v%s"
                    % (publication.get("tag"), version)
                )
            release_signature_state = signature.get("state") if isinstance(signature, dict) else None
            if release_signature_state != "signed":
                problems.append(
                    "release.publication is published while the signature state is %r"
                    % release_signature_state
                )
            for target in targets:
                platform_name = target.get("platform")
                for kind in ("archive", "sbom"):
                    if (target.get(kind) or {}).get("state") != "built":
                        problems.append(
                            "release.publication is published while target %s %s is not built"
                            % (platform_name, kind)
                        )
                if (target.get("signature") or {}).get("state") != "signed":
                    problems.append(
                        "release.publication is published while target %s is not signed" % platform_name
                    )
        elif state == "not_published" and publication.get("tag") is not None:
            problems.append(
                "a not_published release must not carry a tag, got %r" % publication.get("tag")
            )
    return problems


def publishability_refusal(manifest):
    """The first reason this declaration cannot be published, or None."""
    release = manifest.get("release") or {}
    if not is_commit(release.get("revision")):
        return "revision is not pinned"
    signature = release.get("signature") or {}
    if signature.get("state") != "signed":
        return "signature state is %r" % signature.get("state")
    publication = release.get("publication") or {}
    if publication.get("state") != "published":
        return "publication state is %r" % publication.get("state")
    return None

def host_targets():
    """This host as (os, arch) plus the build-matrix rows it matches."""
    system = platform.system().lower()
    if system == "darwin":
        system = "macos"
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64", "x64"):
        machine = "x86_64"
    elif machine in ("arm64", "aarch64"):
        machine = "aarch64"
    matched = [
        name
        for name, (os_name, arch, _triple) in EXPECTED_TARGETS.items()
        if (os_name, arch) == (system, machine)
    ]
    return system, machine, matched


def run(repo_root):
    problems = []
    not_run = []

    manifest = read_json(os.path.join(repo_root, MANIFEST_PATH))
    release = manifest.get("release") or {}
    version = release.get("version")
    components = release.get("components") or []
    targets = release.get("targets") or []
    publication = release.get("publication") or {}

    # --- positive leg 1: consistent, and true of the real sources --------------
    inconsistencies = problems_in(manifest, repo_root)
    for item in inconsistencies:
        problems.append("positive 1: %s" % item)

    # --- positive leg 2: one release, daemon plus CLI, one version ------------
    print("release: name=%s version=%s revision=%s publication=%s" % (
        release.get("name"), version, release.get("revision"), publication.get("state")))
    for component in components:
        print("component: %s role=%s version=%s revision=%s" % (
            component.get("name"), component.get("role"), component.get("version"), component.get("revision")))
    versions = {component.get("version") for component in components}
    revisions = {component.get("revision") for component in components}
    if len(components) != len(EXPECTED_COMPONENTS) or versions != {version} or revisions != {release.get("revision")}:
        problems.append(
            "positive 2: the components do not share one version and one revision with the release"
        )
    if any("bootstrap" in (component.get("name") or "").lower() for component in components):
        problems.append("positive 2: a separate bootstrap component is present")

    # --- positive leg 3: this host is one of the declared targets -------------
    system, machine, matched = host_targets()
    print("host: os=%s arch=%s -> %s" % (system, machine, ",".join(matched) if matched else "outside the build matrix"))
    if not matched:
        not_run.append(
            "host identity %s/%s is outside the declared build matrix, so the per-host target row is "
            "not exercised on this machine" % (system, machine)
        )
    for target in targets:
        if target.get("platform") in matched:
            payloads = [(target.get(kind) or {}).get("name") for kind in ("archive", "sbom")]
            declared = [
                isinstance(name, str)
                and name.endswith((".zip", ".tar.gz", ".json"))
                and "REPLACE" not in name.upper()
                and (name.find(str(version)) >= 0)
                for name in payloads
            ]
            if not all(declared):
                problems.append(
                    "positive 3: target %s payload names are not the declared archive and SBOM: %r"
                    % (target.get("platform"), payloads)
                )

    # --- honest state: no unverifiable publication claim ----------------------
    refusal = publishability_refusal(manifest)
    print("publication: state=%s publishable=%s first_refusal=%s" % (
        publication.get("state"), refusal is None, refusal))
    if publication.get("state") == "published" and (refusal is not None or inconsistencies):
        problems.append(
            "honesty: the manifest claims published but is not publishable (%s)"
            % (refusal or "internally inconsistent")
        )
    if refusal is not None:
        not_run.append(
            "signing, tagging and publishing: %s (the release gate is closed for this workstream: "
            "no tag, no release, no publish)" % refusal
        )
    not_run.append("building and hashing the three per-target archives (no release artifact is built in this workstream)")
    not_run.append("producing and hashing the per-target SBOMs")
    not_run.append("signing the release and each archive with the release key")
    not_run.append("clean-user installation evidence from a signed artifact")
    not_run.append("cargo test --locked -p axiom-graphd (the real release code; the Rust gate runs in the Docker lane, not here)")

    # --- negative legs: the same validator must catch each mutation -----------
    def catches(description, needle, mutate):
        candidate = copy.deepcopy(manifest)
        mutate(candidate)
        found = problems_in(candidate, repo_root)
        if not any(needle in item for item in found):
            problems.append("%s: not caught (problems=%r)" % (description, found))

    def leg_a(candidate):
        candidate["release"]["components"][1]["revision"] = "0" * 40

    def leg_b(candidate):
        candidate["release"]["components"].append({
            "name": "axiom-bootstrap",
            "role": "bootstrap",
            "version": version,
            "revision": release.get("revision"),
            "cargo_package": "crates/bootstrap",
        })

    def leg_c(candidate):
        candidate["release"]["components"][0]["version"] = "9.9.9"

    def leg_d(candidate):
        candidate["release"]["targets"][0]["archive"] = {
            "name": "axiom-%s-windows-x64.zip" % version,
            "state": "built",
            "sha256": "REPLACE_ME",
        }

    def leg_e(candidate):
        candidate["release"]["targets"][0]["executables"] = ["axiom-graphd.exe"]

    def leg_f(candidate):
        candidate["release"]["targets"][0]["rust_target"] = "x86_64-unknown-freebsd"

    def leg_g(candidate):
        candidate["release"]["compatibility"]["graph_schema_version"] = 99

    def leg_h(candidate):
        candidate["release"]["source"]["workspace_toml_sha256"] = "0" * 64

    def leg_i(candidate):
        candidate["release"]["publication"] = {"state": "published", "tag": "v%s" % version}

    catches("negative A (components carrying different revisions)", "same revision", leg_a)
    catches("negative B (a reintroduced bootstrap component)", "components must be exactly", leg_b)
    catches("negative C (a component version that disagrees)", "does not agree with the release version", leg_c)
    catches("negative D (a built archive with a placeholder digest)", "64-hex", leg_d)
    catches("negative E (a target shipping only the daemon)", "daemon and the CLI", leg_e)
    catches("negative F (a target triple that is not the declared one)", "must name the triple", leg_f)
    catches("negative G (compatibility drifting from version.rs)", "version.rs", leg_g)
    catches("negative H (a tampered source digest)", "hashes to", leg_h)
    catches("negative I (published while nothing is built)", "published", leg_i)

    return problems, not_run


def main(argv=None):
    parser = argparse.ArgumentParser(description="E-048 core release manifest check")
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
        "task": "E-048",
        "harness": "core_manifest",
        "positive_legs": 3,
        "negative_legs": 9,
        "manifest": MANIFEST_PATH,
        "host": "%s/%s" % (platform.system().lower(), platform.machine().lower()),
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
        "ok: E-048 one core release carries axiom-graphd and axiom from the same version and revision; "
        "3 positive legs hold and 9 negative legs were rejected as required"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
