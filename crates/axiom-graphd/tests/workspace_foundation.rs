//! Workspace-foundation contract test (task B-001).
//!
//! B-001 delivers the workspace itself, so its regression test re-reads the real
//! manifest and policy files and re-derives the foundation invariants instead of
//! calling a runtime API:
//!
//! * one locked workspace owning the three component crates,
//! * an exact toolchain channel (never a moving ref) with rustfmt and clippy,
//! * warnings denied in both the manifest and the repository build policy,
//! * a committed lockfile with every dependency version pinned,
//! * a dependency-audit policy that denies yanked crates, wildcard bounds,
//!   unknown registries and unknown Git sources,
//! * LF-only text for source, manifest and documentation files.
//!
//! `foundation_problems` is a pure function of the file contents, so the same
//! evaluator that accepts the shipped workspace is also pointed at mutated
//! copies: losing any single rule must be reported. That is the negative and
//! boundary half of B-001 AC2.

use std::fs;
use std::path::{Path, PathBuf};

/// The files that together define the B-001 foundation contract.
struct Foundation<'a> {
    cargo_toml: &'a str,
    toolchain: &'a str,
    cargo_config: &'a str,
    deny: &'a str,
    lockfile: &'a str,
    version: &'a str,
    editorconfig: &'a str,
    gitattributes: &'a str,
}

/// Workspace member directories that must stay inside the single core release.
const MEMBER_CRATES: [&str; 3] = [
    "crates/graph-core",
    "crates/graph-store",
    "crates/axiom-graphd",
];

/// Locked package names that prove the lockfile covers the whole workspace.
const LOCKED_PACKAGES: [&str; 3] = ["graph-core", "graph-store", "axiom-graphd"];

/// Channels that move, and therefore cannot certify a build.
const MOVING_CHANNELS: [&str; 6] = ["stable", "beta", "nightly", "main", "master", "develop"];

/// Value of a `key = "value"` line, ignoring inline keys such as
/// `serde = { version = "1.0.210" }` and longer siblings such as `rust-version`.
fn key_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let rest = line
            .trim()
            .strip_prefix(key)?
            .trim_start()
            .strip_prefix('=')?
            .trim();
        let rest = rest.strip_prefix('"')?;
        Some(&rest[..rest.find('"')?])
    })
}

/// Every violation of the workspace foundation contract, sorted.
fn foundation_problems(f: &Foundation<'_>) -> Vec<String> {
    let mut problems: Vec<String> = Vec::new();

    if key_value(f.cargo_toml, "resolver") != Some("2") {
        problems.push(String::from("cargo-toml: resolver must be 2"));
    }
    if key_value(f.cargo_toml, "rust-version") != Some("1.85") {
        problems.push(String::from("cargo-toml: rust-version must pin 1.85"));
    }
    for member in MEMBER_CRATES {
        if !f.cargo_toml.contains(member) {
            problems.push(format!("cargo-toml: missing workspace member {member}"));
        }
    }
    for rule in ["warnings = \"deny\"", "unsafe_code = \"deny\""] {
        if !f.cargo_toml.contains(rule) {
            problems.push(format!("cargo-toml: missing lint rule {rule}"));
        }
    }

    match key_value(f.toolchain, "channel") {
        None => problems.push(String::from("toolchain: channel must be declared")),
        Some(channel) => {
            if MOVING_CHANNELS.contains(&channel) {
                problems.push(format!("toolchain: moving channel {channel} is not a pin"));
            } else if !channel.starts_with(|c: char| c.is_ascii_digit())
                || channel.matches('.').count() < 2
            {
                problems.push(format!(
                    "toolchain: channel {channel} is not an exact version"
                ));
            }
        }
    }
    for component in ["rustfmt", "clippy"] {
        if !f.toolchain.contains(component) {
            problems.push(format!("toolchain: missing component {component}"));
        }
    }

    if !(f.cargo_config.contains("\"-D\"") && f.cargo_config.contains("\"warnings\"")) {
        problems.push(String::from("cargo-config: rustflags must deny warnings"));
    }
    let lint = key_value(f.cargo_config, "lint").unwrap_or_default();
    if !(lint.contains("clippy") && lint.contains("--locked") && lint.contains("-D warnings")) {
        problems.push(String::from(
            "cargo-config: lint alias must run clippy --locked with -D warnings",
        ));
    }
    let verify = key_value(f.cargo_config, "verify").unwrap_or_default();
    if !(verify.contains("test") && verify.contains("--locked")) {
        problems.push(String::from(
            "cargo-config: verify alias must run the locked test suite",
        ));
    }
    let fmt_check = key_value(f.cargo_config, "fmt-check").unwrap_or_default();
    if !(fmt_check.contains("fmt") && fmt_check.contains("--check")) {
        problems.push(String::from(
            "cargo-config: fmt-check alias must check formatting",
        ));
    }

    for rule in [
        "[advisories]",
        "yanked = \"deny\"",
        "[licenses]",
        "allow = [",
        "[bans]",
        "wildcards = \"deny\"",
        "[sources]",
        "unknown-registry = \"deny\"",
        "unknown-git = \"deny\"",
    ] {
        if !f.deny.contains(rule) {
            problems.push(format!("deny: missing audit rule {rule}"));
        }
    }

    if f.lockfile.trim().is_empty() {
        problems.push(String::from("lockfile: must be committed and non-empty"));
    }
    for package in LOCKED_PACKAGES {
        if !f.lockfile.contains(&format!("name = \"{package}\"")) {
            problems.push(format!("lockfile: missing package {package}"));
        }
    }
    if f.lockfile.contains("version = \"*\"") {
        problems.push(String::from("lockfile: wildcard dependency version"));
    }

    if f.version.trim() != key_value(f.cargo_toml, "version").unwrap_or_default() {
        problems.push(String::from(
            "version: VERSION must match workspace.package.version",
        ));
    }

    if !f.editorconfig.contains("end_of_line = lf") {
        problems.push(String::from("editorconfig: LF line endings required"));
    }
    for pattern in ["*.rs text eol=lf", "*.toml text eol=lf", "*.md text eol=lf"] {
        if !f.gitattributes.contains(pattern) {
            problems.push(format!("gitattributes: missing LF rule {pattern}"));
        }
    }

    problems.sort();
    problems
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn read(root: &Path, name: &str) -> String {
    let path = root.join(name);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// One mutation of a single foundation file, with the problem it must provoke.
struct Case {
    file: &'static str,
    from: &'static str,
    to: &'static str,
    marker: &'static str,
}

const fn cases(
    file: &'static str,
    from: &'static str,
    to: &'static str,
    marker: &'static str,
) -> Case {
    Case {
        file,
        from,
        to,
        marker,
    }
}

#[test]
fn the_shipped_workspace_satisfies_the_foundation_contract() {
    let root = workspace_root();
    let cargo_toml = read(&root, "Cargo.toml");
    let toolchain = read(&root, "rust-toolchain.toml");
    let cargo_config = read(&root, ".cargo/config.toml");
    let deny = read(&root, "deny.toml");
    let lockfile = read(&root, "Cargo.lock");
    let version = read(&root, "VERSION");
    let editorconfig = read(&root, ".editorconfig");
    let gitattributes = read(&root, ".gitattributes");
    let foundation = Foundation {
        cargo_toml: &cargo_toml,
        toolchain: &toolchain,
        cargo_config: &cargo_config,
        deny: &deny,
        lockfile: &lockfile,
        version: &version,
        editorconfig: &editorconfig,
        gitattributes: &gitattributes,
    };
    let problems = foundation_problems(&foundation);
    assert!(
        problems.is_empty(),
        "the shipped workspace violates B-001: {problems:?}"
    );
}

#[test]
fn losing_any_single_foundation_rule_is_reported() {
    let root = workspace_root();
    let base_cargo_toml = read(&root, "Cargo.toml");
    let base_toolchain = read(&root, "rust-toolchain.toml");
    let base_cargo_config = read(&root, ".cargo/config.toml");
    let base_deny = read(&root, "deny.toml");
    let base_lockfile = read(&root, "Cargo.lock");
    let base_version = read(&root, "VERSION");
    let base_editorconfig = read(&root, ".editorconfig");
    let base_gitattributes = read(&root, ".gitattributes");

    let mutations = [
        cases(
            "cargo_toml",
            "resolver = \"2\"",
            "resolver = \"1\"",
            "cargo-toml: resolver",
        ),
        cases(
            "cargo_toml",
            "rust-version = \"1.85\"",
            "rust-version = \"1.80\"",
            "cargo-toml: rust-version",
        ),
        cases(
            "cargo_toml",
            "warnings = \"deny\"",
            "warnings = \"warn\"",
            "cargo-toml: missing lint rule",
        ),
        cases(
            "toolchain",
            "channel = \"1.85.0\"",
            "channel = \"stable\"",
            "moving channel",
        ),
        cases(
            "toolchain",
            "channel = \"1.85.0\"",
            "channel = \"1.85\"",
            "not an exact version",
        ),
        cases(
            "toolchain",
            "[\"rustfmt\", \"clippy\"]",
            "[\"rustfmt\"]",
            "missing component clippy",
        ),
        cases(
            "cargo_config",
            "\"-D\", \"warnings\"",
            "\"-Dwarnings\"",
            "cargo-config: rustflags",
        ),
        cases(
            "cargo_config",
            "lint = \"clippy --locked --all-targets -- -D warnings\"",
            "lint = \"clippy --all-targets\"",
            "cargo-config: lint alias",
        ),
        cases(
            "cargo_config",
            "verify = \"test --locked --all-targets\"",
            "verify = \"test --all-targets\"",
            "cargo-config: verify alias",
        ),
        cases(
            "cargo_config",
            "fmt-check = \"fmt --all -- --check\"",
            "fmt-check = \"fmt --all\"",
            "cargo-config: fmt-check alias",
        ),
        cases(
            "deny",
            "yanked = \"deny\"",
            "yanked = \"warn\"",
            "deny: missing audit rule yanked",
        ),
        cases(
            "deny",
            "wildcards = \"deny\"",
            "wildcards = \"allow\"",
            "deny: missing audit rule wildcards",
        ),
        cases("version", "0.0.0-dev", "0.0.1-dev", "version: VERSION"),
        cases(
            "editorconfig",
            "end_of_line = lf",
            "end_of_line = crlf",
            "editorconfig: LF line endings",
        ),
        cases(
            "gitattributes",
            "*.rs text eol=lf",
            "*.rs text eol=crlf",
            "missing LF rule *.rs text eol=lf",
        ),
    ];

    let clean = Foundation {
        cargo_toml: &base_cargo_toml,
        toolchain: &base_toolchain,
        cargo_config: &base_cargo_config,
        deny: &base_deny,
        lockfile: &base_lockfile,
        version: &base_version,
        editorconfig: &base_editorconfig,
        gitattributes: &base_gitattributes,
    };
    assert!(
        foundation_problems(&clean).is_empty(),
        "boundary: the unmutated workspace must stay accepted"
    );

    // Boundary: a lockfile that is absent, or that admits a wildcard bound, is
    // refused even though every other rule still holds.
    let missing_lock = Foundation {
        lockfile: "",
        ..clean
    };
    let problems = foundation_problems(&missing_lock);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("must be committed and non-empty")),
        "an absent lockfile must be refused, got {problems:?}"
    );

    let wildcard_lock = Foundation {
        lockfile: "name = \"axiom-graphd\"\nversion = \"*\"\n",
        ..clean
    };
    let problems = foundation_problems(&wildcard_lock);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("wildcard dependency version")),
        "a wildcard dependency bound must be refused, got {problems:?}"
    );

    for case in mutations {
        let mut cargo_toml = base_cargo_toml.clone();
        let mut toolchain = base_toolchain.clone();
        let mut cargo_config = base_cargo_config.clone();
        let mut deny = base_deny.clone();
        let mut lockfile = base_lockfile.clone();
        let mut version = base_version.clone();
        let mut editorconfig = base_editorconfig.clone();
        let mut gitattributes = base_gitattributes.clone();
        let target = match case.file {
            "cargo_toml" => &mut cargo_toml,
            "toolchain" => &mut toolchain,
            "cargo_config" => &mut cargo_config,
            "deny" => &mut deny,
            "lockfile" => &mut lockfile,
            "version" => &mut version,
            "editorconfig" => &mut editorconfig,
            "gitattributes" => &mut gitattributes,
            other => panic!("unknown foundation file {other}"),
        };
        assert!(
            target.contains(case.from),
            "fixture drift: {} no longer contains {:?}",
            case.file,
            case.from
        );
        let mutated = target.replace(case.from, case.to);
        *target = mutated;

        let foundation = Foundation {
            cargo_toml: &cargo_toml,
            toolchain: &toolchain,
            cargo_config: &cargo_config,
            deny: &deny,
            lockfile: &lockfile,
            version: &version,
            editorconfig: &editorconfig,
            gitattributes: &gitattributes,
        };
        let problems = foundation_problems(&foundation);
        assert!(
            problems.iter().any(|problem| problem.contains(case.marker)),
            "mutation of {} ({:?} -> {:?}) must report {:?}, got {problems:?}",
            case.file,
            case.from,
            case.to,
            case.marker
        );
    }
}
