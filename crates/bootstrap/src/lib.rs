//! The bootstrap application release boundary (V2-002).
//!
//! V2-002's acceptance criterion is a property of the *workspace*, not of a
//! runtime: one core revision owns both bootstrap application and daemon
//! lifecycle, so no separately versioned installer process is required. The
//! bootstrap engine itself lives in `crates/axiom/src/bootstrap/**` (one crate,
//! one version). This package is the witness that keeps that claim checkable:
//! [`witness`] re-reads the workspace manifests and reports what is actually
//! declared, so a future change that introduces a separately versioned installer
//! package or a second core version fails `cargo test -p axiom-bootstrap`
//! instead of passing silently.

use std::fmt;
use std::path::{Path, PathBuf};

/// The crate that owns the bootstrap engine.
pub const BOOTSTRAP_ENGINE_CRATE: &str = "axiom";
/// The bootstrap engine sources, inside the core crate.
pub const BOOTSTRAP_ENGINE_DIR: &str = "crates/axiom/src/bootstrap";
/// The daemon crate, published from the same revision.
pub const DAEMON_CRATE: &str = "axiom-graphd";
/// The installation/operations CLI, published from the same revision.
pub const CLI_CRATE: &str = "axiom-cli";
/// The one release boundary this workspace uses.
pub const RELEASE_BOUNDARY: &str = "one workspace, one core version, one publish";
/// There is no separately versioned installer process.
pub const SEPARATELY_VERSIONED_INSTALLER: bool = false;
/// Bootstrap application is owned by the same core revision as the daemon.
pub const BOOTSTRAP_IS_CORE_REVISION: bool = true;
/// Package or binary names that would indicate a separately shipped installer.
pub const INSTALLER_NAME_MARKERS: [&str; 2] = ["installer", "setup"];

/// What one manifest declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFacts {
    /// The package directory, relative to the workspace root.
    pub member: String,
    /// The declared package name.
    pub name: String,
    /// True when the manifest inherits `version` from the workspace.
    pub inherits_workspace_version: bool,
    /// The declared binary target names.
    pub binaries: Vec<String>,
}

impl ManifestFacts {
    /// True when this package or a binary of it looks like a separately shipped
    /// installer.
    #[must_use]
    pub fn looks_like_an_installer(&self) -> bool {
        let marker = |value: &str| {
            let lowered = value.to_ascii_lowercase();
            INSTALLER_NAME_MARKERS
                .iter()
                .any(|candidate| lowered.contains(candidate))
        };
        marker(&self.name) || self.binaries.iter().any(|binary| marker(binary))
    }
}

impl fmt::Display for ManifestFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} ({}{})",
            self.name,
            self.member,
            if self.inherits_workspace_version {
                ", version.workspace"
            } else {
                ", pinned version"
            }
        )
    }
}

/// What the workspace actually declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseBoundaryWitness {
    /// The single workspace version.
    pub workspace_version: String,
    /// Every member, with its version inheritance and binary targets.
    pub members: Vec<ManifestFacts>,
    /// True when the bootstrap engine sources exist in the core crate.
    pub bootstrap_engine_dir_exists: bool,
}

impl ReleaseBoundaryWitness {
    /// Members that would be a separately versioned installer.
    #[must_use]
    pub fn separate_installer_candidates(&self) -> Vec<&ManifestFacts> {
        self.members
            .iter()
            .filter(|member| member.looks_like_an_installer())
            .collect()
    }

    /// Members that do not inherit the workspace version, which would break the
    /// one-core-version claim.
    #[must_use]
    pub fn members_with_pinned_versions(&self) -> Vec<&ManifestFacts> {
        self.members
            .iter()
            .filter(|member| !member.inherits_workspace_version)
            .collect()
    }

    /// The binary crate names, in manifest order.
    #[must_use]
    pub fn binary_crates(&self) -> Vec<&str> {
        self.members
            .iter()
            .filter(|member| !member.binaries.is_empty())
            .map(|member| member.name.as_str())
            .collect()
    }
}

impl fmt::Display for ReleaseBoundaryWitness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "core {} across {} members",
            self.workspace_version,
            self.members.len()
        )
    }
}

fn read_to_string(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// Parse the manifest facts this crate checks, without a TOML dependency.
///
/// # Errors
/// Returns the reason the manifest could not be read or parsed.
pub fn read_manifest(workspace_root: &Path, member: &str) -> Result<ManifestFacts, String> {
    let path = workspace_root.join(member).join("Cargo.toml");
    let text = read_to_string(&path)?;
    let name = find_assignment(&text, "name")
        .ok_or_else(|| format!("{}: no package name", path.display()))?;
    let inherits_workspace_version = text.lines().any(|line| {
        let line = line.trim();
        line == "version.workspace = true" || line == "version = { workspace = true }"
    });
    let binaries = find_binary_names(&text);
    Ok(ManifestFacts {
        member: member.to_string(),
        name,
        inherits_workspace_version,
        binaries,
    })
}

/// The `[workspace.package] version` of the workspace root manifest.
///
/// # Errors
/// Returns the reason the manifest could not be read or parsed.
pub fn workspace_version(workspace_root: &Path) -> Result<String, String> {
    let path = workspace_root.join("Cargo.toml");
    let text = read_to_string(&path)?;
    let mut in_section = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_section = trimmed == "[workspace.package]";
            continue;
        }
        if in_section {
            if let Some(value) = parse_assignment(trimmed, "version") {
                return Ok(value);
            }
        }
    }
    Err(format!(
        "{}: no [workspace.package] version",
        path.display()
    ))
}

/// The member directories declared by the workspace root manifest.
///
/// # Errors
/// Returns the reason the manifest could not be read or parsed.
pub fn workspace_members(workspace_root: &Path) -> Result<Vec<String>, String> {
    let path = workspace_root.join("Cargo.toml");
    let text = read_to_string(&path)?;
    let mut members = Vec::new();
    let mut collecting = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if !collecting {
            if let Some(rest) = trimmed.strip_prefix("members") {
                if rest.trim_start().starts_with('=') {
                    collecting = !rest.contains(']');
                }
            }
            continue;
        }
        if trimmed.starts_with(']') {
            break;
        }
        let entry = trimmed.trim_end_matches(',').trim();
        let entry = entry.trim_matches('"');
        if !entry.is_empty() {
            members.push(entry.to_string());
        }
    }
    if members.is_empty() {
        return Err(format!("{}: no workspace members", path.display()));
    }
    Ok(members)
}

/// Read the whole workspace and report what it declares.
///
/// # Errors
/// Returns the reason a manifest could not be read or parsed.
pub fn witness(workspace_root: &Path) -> Result<ReleaseBoundaryWitness, String> {
    let workspace_version = workspace_version(workspace_root)?;
    let members = workspace_members(workspace_root)?
        .into_iter()
        .map(|member| read_manifest(workspace_root, &member))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ReleaseBoundaryWitness {
        workspace_version,
        members,
        bootstrap_engine_dir_exists: workspace_root.join(BOOTSTRAP_ENGINE_DIR).is_dir(),
    })
}

/// The workspace root, derived from this crate's manifest directory.
///
/// # Panics
/// Panics only when the crate is built outside a workspace member layout, which
/// the workspace guarantees cannot happen.
#[must_use]
pub fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| manifest_dir.clone())
}

fn find_assignment(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find_map(|line| parse_assignment(line.trim(), key))
}

fn parse_assignment(line: &str, key: &str) -> Option<String> {
    let rest = line.strip_prefix(key)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim();
    let value = rest.trim_matches('"');
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn find_binary_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_binary_section = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_binary_section = trimmed == "[[bin]]";
            continue;
        }
        if in_binary_section {
            if let Some(value) = parse_assignment(trimmed, "name") {
                names.push(value);
            }
        }
    }
    names
}
