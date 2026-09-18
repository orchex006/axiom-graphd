//! State-home resolution and portable-path policy (task B-003).
//!
//! `AXIOM_HOME` defaults come from SOURCE-OF-TRUST.md section 1 and
//! docs/10-ARCHITECTURE.md section D: Windows `%LOCALAPPDATA%/Axiom`, Linux
//! `${XDG_STATE_HOME:-~/.local/state}/axiom`, macOS
//! `~/Library/Application Support/Axiom`. An explicit override must be an
//! absolute local path; relative, remote/shared, cloud-synchronised and device
//! paths are refused (CP-03, CP-04).
//!
//! Resolution is pure: it never touches the filesystem, so behaviour is
//! identical in tests and at runtime. Native containment and symlink checks are
//! separate (see [`AxiomHome::verify_destination`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{AxiomError, ErrorCode};

/// Maximum accepted byte length of a portable repository-relative path.
pub const MAX_PORTABLE_PATH_BYTES: usize = 4096;
/// Maximum accepted byte length of one portable path segment.
pub const MAX_PORTABLE_SEGMENT_BYTES: usize = 255;
/// Whole-repository project binding (CP-03).
pub const WHOLE_REPO_BINDING: &str = ".";

/// Operating system family the path policy applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Platform {
    /// Platform could not be determined; defaults cannot be resolved.
    #[default]
    Unknown,
    /// Microsoft Windows.
    Windows,
    /// Linux and other XDG-style Unix systems.
    Linux,
    /// Apple macOS.
    MacOs,
}

impl Platform {
    /// Platform this binary was compiled for.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Unknown
        }
    }

    /// Stable name used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::MacOs => "macos",
        }
    }
}

/// Host facts needed to resolve the state home. Injected so resolution is
/// deterministic and testable on any platform.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathEnvironment {
    /// Platform whose defaults apply.
    pub platform: Platform,
    /// Explicit `AXIOM_HOME` override.
    pub axiom_home: Option<String>,
    /// Windows `%LOCALAPPDATA%`.
    pub local_app_data: Option<String>,
    /// `XDG_STATE_HOME`.
    pub xdg_state_home: Option<String>,
    /// User home directory (`HOME` or `%USERPROFILE%`).
    pub home_dir: Option<String>,
}

impl PathEnvironment {
    /// Read the current process environment.
    #[must_use]
    pub fn for_current_process() -> Self {
        let read = |key: &str| std::env::var(key).ok().filter(|v| !v.trim().is_empty());
        Self {
            platform: Platform::current(),
            axiom_home: read("AXIOM_HOME"),
            local_app_data: read("LOCALAPPDATA"),
            xdg_state_home: read("XDG_STATE_HOME"),
            home_dir: read("HOME").or_else(|| read("USERPROFILE")),
        }
    }
}

/// Rough storage classification for a path.
///
/// This is the lexical policy used before any native volume probe. `graph-store`
/// refines it with a native probe (task B-009) because a share can also be
/// mounted on a drive letter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClass {
    /// Ordinary local disk.
    LocalDisk,
    /// UNC/SMB or otherwise shared/remote storage.
    NetworkShare,
    /// Known cloud-synchronisation location.
    CloudSynced,
    /// Windows device namespace or other non-file path.
    UnsupportedDevice,
}

impl StorageClass {
    /// Stable name used in diagnostics and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalDisk => "local_disk",
            Self::NetworkShare => "network_share",
            Self::CloudSynced => "cloud_synced",
            Self::UnsupportedDevice => "unsupported_device",
        }
    }

    /// True when mutable Axiom state must not live here.
    #[must_use]
    pub const fn is_unsafe_for_mutable_state(self) -> bool {
        !matches!(self, Self::LocalDisk)
    }
}

/// Cloud-synchronised folder names that must never hold mutable Axiom state.
const CLOUD_SYNC_SEGMENTS: &[&str] = &[
    "box sync",
    "boxdrive",
    "dropbox",
    "google drive",
    "googledrive",
    "icloud",
    "onedrive",
    "sharepoint",
];

/// Classify a path lexically, without filesystem access.
#[must_use]
pub fn classify_storage_lexically(path: &str) -> StorageClass {
    if path.starts_with(r"\\?\") || path.starts_with(r"\\.\") {
        return StorageClass::UnsupportedDevice;
    }
    if path.starts_with(r"\\") || path.starts_with("//") {
        return StorageClass::NetworkShare;
    }
    for segment in path.split(['/', '\\']) {
        let lower = segment.to_ascii_lowercase();
        if CLOUD_SYNC_SEGMENTS.iter().any(|known| *known == lower) {
            return StorageClass::CloudSynced;
        }
    }
    StorageClass::LocalDisk
}

/// True when `value` is a portable Axiom identifier (`^[a-z][a-z0-9-]{0,62}$`).
#[must_use]
pub fn is_portable_id(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    let rest: String = chars.collect();
    rest.len() <= 62
        && rest
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn reserved_windows_stem(stem: &str) -> bool {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    const RESERVED_SUPERSCRIPT: &[&str] = &[
        "COM\u{b9}",
        "COM\u{b2}",
        "COM\u{b3}",
        "LPT\u{b9}",
        "LPT\u{b2}",
        "LPT\u{b3}",
    ];
    let upper = stem.to_ascii_uppercase();
    RESERVED.contains(&upper.as_str()) || RESERVED_SUPERSCRIPT.iter().any(|r| *r == upper)
}

/// Validate a portable repository-relative path (CP-03).
///
/// Rejects absolute, drive, UNC, device and backslash-separated paths, `.`/`..`
/// segments, empty segments, NUL/control characters, Windows-reserved names,
/// alternate-data-stream syntax and trailing dots/spaces. Source path case and
/// non-ASCII spelling (for example Thai file names) are preserved.
///
/// # Errors
/// Returns [`ErrorCode::UnsafePortablePath`] with redacted context.
pub fn validate_portable_relative_path(path: &str) -> Result<(), AxiomError> {
    let reject = |reason: &str, portable_path: &str| -> AxiomError {
        AxiomError::new(
            ErrorCode::UnsafePortablePath,
            format!("path rejected: {reason}"),
        )
        .with_detail("portable_path", portable_path)
    };

    if path.is_empty() {
        return Err(reject("empty path", path));
    }
    if path.len() > MAX_PORTABLE_PATH_BYTES {
        return Err(reject("path exceeds the byte budget", path)
            .with_detail("limit", MAX_PORTABLE_PATH_BYTES.to_string()));
    }
    if path.chars().any(char::is_control) {
        return Err(reject("path contains control characters", path));
    }
    if path.contains('\\') {
        return Err(reject("backslash separators are not portable", path));
    }
    if path.starts_with('/') {
        return Err(reject("absolute path is not portable", path));
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(reject("drive-qualified path is not portable", path));
    }
    if is_portable_reserved_or_unsafe(path) {
        return Err(reject("component violates the portability policy", path));
    }
    for segment in path.split('/') {
        if segment.is_empty() {
            return Err(reject("empty path segment", path));
        }
        if segment == "." || segment == ".." {
            return Err(reject("relative traversal segment", path));
        }
        if segment.len() > MAX_PORTABLE_SEGMENT_BYTES {
            return Err(reject("segment exceeds the byte budget", path));
        }
        if segment.ends_with('.') || segment.ends_with(' ') {
            return Err(reject("trailing dot or space is not portable", path));
        }
        if segment.contains(':') {
            return Err(reject("alternate-data-stream syntax is not portable", path));
        }
        let stem = segment.split('.').next().unwrap_or(segment);
        if reserved_windows_stem(stem) {
            return Err(reject("Windows-reserved device name is not portable", path));
        }
    }
    Ok(())
}

fn is_portable_reserved_or_unsafe(path: &str) -> bool {
    // Device namespaces are only reachable through a leading separator, already
    // rejected above; this keeps the check explicit for generated paths.
    path.starts_with(r"\\?\") || path.starts_with(r"\\.\")
}

/// Validate a project `source_root` binding: either `.` (whole repository) or a
/// portable repository-relative path (CP-03).
///
/// # Errors
/// Returns [`ErrorCode::UnsafePortablePath`] for anything else.
pub fn validate_project_root_binding(path: &str) -> Result<(), AxiomError> {
    if path == WHOLE_REPO_BINDING {
        return Ok(());
    }
    validate_portable_relative_path(path)
}

/// Detect case-only portability collisions in a set of repository-relative
/// paths (CP-03).
///
/// Unicode NFC/NFD canonical-equivalence detection requires a normalisation
/// table and belongs to the identifier/portability tasks (B-050); this function
/// detects case hazards only and says so in its error context.
///
/// # Errors
/// Returns [`ErrorCode::UnsafePortablePath`] naming the first colliding path.
pub fn detect_case_collisions<'a, I>(paths: I) -> Result<(), AxiomError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen: BTreeMap<String, &str> = BTreeMap::new();
    for path in paths {
        let folded = path.to_lowercase();
        if let Some(first) = seen.get(folded.as_str()) {
            return Err(AxiomError::new(
                ErrorCode::UnsafePortablePath,
                "case-only path collision detected before publication",
            )
            .with_detail("portable_path", path)
            .with_detail("observed", *first)
            .with_detail("rule", "case-only-collision"));
        }
        seen.insert(folded, path);
    }
    Ok(())
}

/// Resolved `AXIOM_HOME`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AxiomHome {
    root: PathBuf,
}

impl AxiomHome {
    /// Resolve the state home from host facts.
    ///
    /// # Errors
    /// - [`ErrorCode::UnsafeHomePath`] when an override is relative, remote,
    ///   cloud-synchronised or a device path.
    /// - [`ErrorCode::ConfigInvalid`] when a required host default is missing or
    ///   the platform is unknown.
    pub fn resolve(env: &PathEnvironment) -> Result<Self, AxiomError> {
        let candidate = match env.axiom_home.as_deref().map(str::trim) {
            Some(override_path) if !override_path.is_empty() => {
                let class = classify_storage_lexically(override_path);
                if !is_absolute_host_path(override_path) {
                    return Err(AxiomError::new(
                        ErrorCode::UnsafeHomePath,
                        "AXIOM_HOME must be an absolute local path",
                    )
                    .with_detail("config_key", "AXIOM_HOME")
                    .with_detail("storage_class", class.as_str()));
                }
                if class.is_unsafe_for_mutable_state() {
                    return Err(AxiomError::new(
                        ErrorCode::UnsafeHomePath,
                        "AXIOM_HOME must not be shared, remote or cloud-synchronised storage",
                    )
                    .with_detail("config_key", "AXIOM_HOME")
                    .with_detail("storage_class", class.as_str()));
                }
                override_path.to_string()
            }
            _ => default_home(env)?,
        };

        if candidate.chars().any(|c| c.is_control()) {
            return Err(AxiomError::new(
                ErrorCode::UnsafeHomePath,
                "AXIOM_HOME contains control characters",
            )
            .with_detail("config_key", "AXIOM_HOME"));
        }
        let trimmed = candidate.trim_end_matches(['/', '\\']);
        if trimmed.is_empty() {
            return Err(AxiomError::new(
                ErrorCode::UnsafeHomePath,
                "AXIOM_HOME resolved to filesystem root",
            )
            .with_detail("config_key", "AXIOM_HOME"));
        }
        if !is_absolute_host_path(trimmed) {
            return Err(
                AxiomError::new(ErrorCode::ConfigInvalid, "AXIOM_HOME is not absolute")
                    .with_detail("config_key", "AXIOM_HOME"),
            );
        }
        Ok(Self {
            root: PathBuf::from(trimmed),
        })
    }

    /// Resolved root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `config/registry.json`.
    #[must_use]
    pub fn config_registry(&self) -> PathBuf {
        self.root.join("config").join("registry.json")
    }

    /// `instances/`.
    #[must_use]
    pub fn instances_dir(&self) -> PathBuf {
        self.root.join("instances")
    }

    /// `instances/<workspace-instance>/`.
    ///
    /// # Errors
    /// Returns [`ErrorCode::ValidationError`] for a non-portable instance id.
    pub fn instance_dir(&self, instance_id: &str) -> Result<PathBuf, AxiomError> {
        ensure_portable_id(instance_id, "instance_id")?;
        Ok(self.instances_dir().join(instance_id))
    }

    /// `instances/<workspace-instance>/index.sqlite`.
    ///
    /// # Errors
    /// Returns [`ErrorCode::ValidationError`] for a non-portable instance id.
    pub fn instance_db(&self, instance_id: &str) -> Result<PathBuf, AxiomError> {
        Ok(self.instance_dir(instance_id)?.join("index.sqlite"))
    }

    /// `instances/<workspace-instance>/solution.guard`.
    ///
    /// # Errors
    /// Returns [`ErrorCode::ValidationError`] for a non-portable instance id.
    pub fn instance_guard(&self, instance_id: &str) -> Result<PathBuf, AxiomError> {
        Ok(self.instance_dir(instance_id)?.join("solution.guard"))
    }

    /// `run/`.
    #[must_use]
    pub fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }

    /// `run/daemon.lock` - single-daemon ownership record (task B-004).
    #[must_use]
    pub fn daemon_lock(&self) -> PathBuf {
        self.run_dir().join("daemon.lock")
    }

    /// `run/control.json` - port/token-file discovery, owner-only.
    #[must_use]
    pub fn control_file(&self) -> PathBuf {
        self.run_dir().join("control.json")
    }

    /// `secrets/` - never committed, never exported.
    #[must_use]
    pub fn secrets_dir(&self) -> PathBuf {
        self.root.join("secrets")
    }

    /// `logs/`.
    #[must_use]
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    /// `installs/`.
    #[must_use]
    pub fn installs_dir(&self) -> PathBuf {
        self.root.join("installs")
    }

    /// `install-state.json`.
    #[must_use]
    pub fn install_state_file(&self) -> PathBuf {
        self.root.join("install-state.json")
    }

    /// `update-journal/`.
    #[must_use]
    pub fn update_journal_dir(&self) -> PathBuf {
        self.root.join("update-journal")
    }

    /// Verify the resolved destination is safe to create state in.
    ///
    /// Rejects an existing symlink/reparse-point root (CP-03). Missing
    /// directories are allowed: the caller creates them with owner-only ACLs.
    ///
    /// # Errors
    /// Returns [`ErrorCode::UnsafeHomePath`] when the root exists but is a
    /// symbolic link or is not a directory.
    pub fn verify_destination(&self) -> Result<(), AxiomError> {
        match std::fs::symlink_metadata(&self.root) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(AxiomError::new(
                ErrorCode::UnsafeHomePath,
                "AXIOM_HOME must not be a symbolic link",
            )
            .with_detail("config_key", "AXIOM_HOME")),
            Ok(metadata) if !metadata.is_dir() => Err(AxiomError::new(
                ErrorCode::UnsafeHomePath,
                "AXIOM_HOME exists but is not a directory",
            )
            .with_detail("config_key", "AXIOM_HOME")),
            Ok(_) => Ok(()),
            Err(_) => Ok(()),
        }
    }
}

fn ensure_portable_id(value: &str, config_key: &str) -> Result<(), AxiomError> {
    if is_portable_id(value) {
        return Ok(());
    }
    Err(AxiomError::new(
        ErrorCode::ValidationError,
        "identifier is not a portable slug",
    )
    .with_detail("config_key", config_key)
    .with_detail("observed", value))
}

/// True when `path` is absolute on the host: a drive/UNC path on Windows, or a
/// rooted path on POSIX. Deliberately syntactic, so it is deterministic in tests
/// and never touches the filesystem.
#[must_use]
pub fn is_absolute_host_path(path: &str) -> bool {
    if path.starts_with('/') || path.starts_with(r"\\") || path.starts_with("//") {
        return true;
    }
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

fn default_home(env: &PathEnvironment) -> Result<String, AxiomError> {
    match env.platform {
        Platform::Windows => {
            let base = env
                .local_app_data
                .as_deref()
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| {
                    AxiomError::new(
                        ErrorCode::ConfigInvalid,
                        "AXIOM_HOME cannot be resolved: %LOCALAPPDATA% is not set",
                    )
                    .with_detail("config_key", "LOCALAPPDATA")
                })?;
            Ok(join_host(base, "Axiom"))
        }
        Platform::Linux => {
            let xdg = env
                .xdg_state_home
                .as_deref()
                .filter(|v| !v.trim().is_empty());
            let base = match xdg {
                Some(state_home) if is_absolute_host_path(state_home) => state_home.to_string(),
                _ => {
                    let home = env
                        .home_dir
                        .as_deref()
                        .filter(|v| !v.trim().is_empty())
                        .ok_or_else(|| {
                            AxiomError::new(
                            ErrorCode::ConfigInvalid,
                            "AXIOM_HOME cannot be resolved: XDG_STATE_HOME and HOME are both unset",
                        )
                        .with_detail("config_key", "HOME")
                        })?;
                    format!("{}/.local/state", home.trim_end_matches('/'))
                }
            };
            Ok(join_host(&base, "axiom"))
        }
        Platform::MacOs => {
            let home = env
                .home_dir
                .as_deref()
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| {
                    AxiomError::new(
                        ErrorCode::ConfigInvalid,
                        "AXIOM_HOME cannot be resolved: HOME is not set",
                    )
                    .with_detail("config_key", "HOME")
                })?;
            Ok(join_host(
                home.trim_end_matches('/'),
                "Library/Application Support/Axiom",
            ))
        }
        Platform::Unknown => Err(AxiomError::new(
            ErrorCode::ConfigInvalid,
            "AXIOM_HOME cannot be resolved on an unsupported platform",
        )
        .with_detail("config_key", "AXIOM_HOME")),
    }
}

fn join_host(base: &str, suffix: &str) -> String {
    let separator = if base.contains('\\') { '\\' } else { '/' };
    format!(
        "{}{}{}",
        base.trim_end_matches(['/', '\\']),
        separator,
        suffix
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn windows_env() -> PathEnvironment {
        PathEnvironment {
            platform: Platform::Windows,
            axiom_home: None,
            local_app_data: Some(r"C:\Users\me\AppData\Local".to_string()),
            xdg_state_home: None,
            home_dir: Some(r"C:\Users\me".to_string()),
        }
    }

    #[test]
    fn platform_defaults_are_deterministic() {
        let resolved = AxiomHome::resolve(&windows_env()).expect("windows default");
        assert_eq!(
            resolved.root().to_string_lossy(),
            r"C:\Users\me\AppData\Local\Axiom"
        );

        let linux = PathEnvironment {
            platform: Platform::Linux,
            xdg_state_home: Some("/state".to_string()),
            home_dir: Some("/home/me".to_string()),
            ..PathEnvironment::default()
        };
        assert_eq!(
            AxiomHome::resolve(&linux)
                .expect("xdg default")
                .root()
                .to_string_lossy(),
            "/state/axiom"
        );

        let linux_fallback = PathEnvironment {
            platform: Platform::Linux,
            xdg_state_home: None,
            home_dir: Some("/home/me/".to_string()),
            ..PathEnvironment::default()
        };
        assert_eq!(
            AxiomHome::resolve(&linux_fallback)
                .expect("home default")
                .root()
                .to_string_lossy(),
            "/home/me/.local/state/axiom"
        );

        let macos = PathEnvironment {
            platform: Platform::MacOs,
            home_dir: Some("/Users/me".to_string()),
            ..PathEnvironment::default()
        };
        assert_eq!(
            AxiomHome::resolve(&macos)
                .expect("macos default")
                .root()
                .to_string_lossy(),
            "/Users/me/Library/Application Support/Axiom"
        );
    }

    #[test]
    fn explicit_override_wins_and_is_normalised() {
        let env = PathEnvironment {
            axiom_home: Some(r"D:\axiom-state\".to_string()),
            ..windows_env()
        };
        let resolved = AxiomHome::resolve(&env).expect("override");
        assert_eq!(resolved.root().to_string_lossy(), r"D:\axiom-state");

        let relative = PathEnvironment {
            axiom_home: Some("axiom-state".to_string()),
            ..windows_env()
        };
        let err = AxiomHome::resolve(&relative).expect_err("relative override refused");
        assert_eq!(err.code(), ErrorCode::UnsafeHomePath);
    }

    #[test]
    fn unsafe_shared_home_is_refused() {
        let cases = [
            r"\\server\share\Axiom",
            "//server/share/axiom",
            r"C:\Users\me\OneDrive\Axiom",
            r"\\?\C:\Axiom",
        ];
        for case in cases {
            let env = PathEnvironment {
                axiom_home: Some(case.to_string()),
                ..windows_env()
            };
            let err = AxiomHome::resolve(&env).expect_err("unsafe override refused");
            assert_eq!(err.code(), ErrorCode::UnsafeHomePath, "case {case}");
            assert!(
                err.details().contains_key("storage_class"),
                "storage class recorded for {case}"
            );
        }
    }

    #[test]
    fn missing_host_defaults_fail_before_start() {
        let env = PathEnvironment {
            platform: Platform::Windows,
            ..PathEnvironment::default()
        };
        assert_eq!(
            AxiomHome::resolve(&env)
                .expect_err("no localappdata")
                .code(),
            ErrorCode::ConfigInvalid
        );
        let unknown = PathEnvironment {
            platform: Platform::Unknown,
            home_dir: Some("/home/me".to_string()),
            ..PathEnvironment::default()
        };
        assert_eq!(
            AxiomHome::resolve(&unknown)
                .expect_err("unknown platform")
                .code(),
            ErrorCode::ConfigInvalid
        );
    }

    #[test]
    fn state_layout_matches_the_architecture_contract() {
        let home = AxiomHome::resolve(&windows_env()).expect("home");
        let root = home.root().to_string_lossy().replace('\\', "/");
        assert!(home
            .config_registry()
            .to_string_lossy()
            .replace('\\', "/")
            .ends_with("config/registry.json"));
        assert!(home
            .instance_db("ws-1")
            .expect("db")
            .to_string_lossy()
            .replace('\\', "/")
            .ends_with("instances/ws-1/index.sqlite"));
        assert!(home
            .instance_guard("ws-1")
            .expect("guard")
            .to_string_lossy()
            .replace('\\', "/")
            .ends_with("instances/ws-1/solution.guard"));
        assert!(home
            .daemon_lock()
            .to_string_lossy()
            .replace('\\', "/")
            .ends_with("run/daemon.lock"));
        assert!(home
            .control_file()
            .to_string_lossy()
            .replace('\\', "/")
            .ends_with("run/control.json"));
        assert!(home
            .secrets_dir()
            .to_string_lossy()
            .replace('\\', "/")
            .ends_with("secrets"));
        assert!(root.ends_with("Axiom"));
    }

    #[test]
    fn instance_ids_must_be_portable_slugs() {
        let home = AxiomHome::resolve(&windows_env()).expect("home");
        assert!(home.instance_dir("ws-1").is_ok());
        for bad in ["WS-1", "ws 1", "../etc", "", "1-ws"] {
            assert_eq!(
                home.instance_dir(bad).expect_err("bad id").code(),
                ErrorCode::ValidationError,
                "id {bad}"
            );
        }
    }

    #[test]
    fn portable_paths_accept_unicode_and_reject_hazards() {
        for good in ["src/a.cs", "src/ไฟล์หลัก/a.cs", ".", "a/b/c.ts", "x-1/y_2.cs"]
        {
            if good == "." {
                assert!(validate_project_root_binding(good).is_ok());
                assert!(validate_portable_relative_path(good).is_err());
            } else {
                assert!(validate_portable_relative_path(good).is_ok(), "path {good}");
            }
        }
        let bad = [
            "",
            "/etc/passwd",
            r"src\a.cs",
            "src/../a.cs",
            "C:/src/a.cs",
            "src//a.cs",
            "src/a.cs/",
            "CON",
            "src/nul.txt",
            "src/a.cs.",
            "src/a.cs ",
            "src/a:b.cs",
            "src/a\u{0}b.cs",
            "src/a\nb.cs",
        ];
        for case in bad {
            assert_eq!(
                validate_portable_relative_path(case)
                    .expect_err("rejected")
                    .code(),
                ErrorCode::UnsafePortablePath,
                "path {case:?}"
            );
        }
    }

    #[test]
    fn case_only_collisions_are_detected() {
        let err = detect_case_collisions(["src/A.cs", "src/a.cs"]).expect_err("collision");
        assert_eq!(err.code(), ErrorCode::UnsafePortablePath);
        assert_eq!(
            err.details().get("portable_path").map(String::as_str),
            Some("src/a.cs")
        );
        assert_eq!(
            err.details().get("observed").map(String::as_str),
            Some("src/A.cs")
        );
        assert!(detect_case_collisions(["src/A.cs", "src/B.cs"]).is_ok());
        assert!(detect_case_collisions(["src/ไฟล์.cs", "src/ไฟล์.ts"]).is_ok());
    }

    #[test]
    fn storage_classification_covers_shared_and_cloud_paths() {
        assert_eq!(
            classify_storage_lexically(r"C:\axiom"),
            StorageClass::LocalDisk
        );
        assert_eq!(
            classify_storage_lexically(r"\\server\share"),
            StorageClass::NetworkShare
        );
        assert_eq!(
            classify_storage_lexically(r"C:\Users\me\OneDrive\axiom"),
            StorageClass::CloudSynced
        );
        assert_eq!(
            classify_storage_lexically(r"\\?\C:\axiom"),
            StorageClass::UnsupportedDevice
        );
        assert!(!classify_storage_lexically("/mnt/network").is_unsafe_for_mutable_state());
    }
}
