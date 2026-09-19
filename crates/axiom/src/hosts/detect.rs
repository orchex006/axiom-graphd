//! Detection of installed agent hosts and their actual versions (task E-026).
//!
//! `axiom host detect --json` has to answer "which agent host is installed here,
//! and which exact version?" *before* any adapter is allowed to render config for
//! it. `axiom-specs/repo-seeds/axiom-skills/docs/25-HOST-ADAPTERS-AND-HOOKS.md`
//! section 4 pins the rule this module implements:
//!
//! > `axiom host detect` report installed version, capabilities documented/tested,
//! > template match and warnings. Unknown version must choose manual preview /
//! > instruction + CLI path, not autowrite assumed hook JSON.
//!
//! So detection never returns a version it did not read from the host itself, and
//! a host whose version could not be read is reported with
//! [`WriteEligibility::ManualReview`] rather than being treated as a supported
//! release. Three properties make that structural:
//!
//! * Every host fact arrives through [`HostProbe`], whose whole surface is
//!   locate-and-run. There is no write, no config edit, no install and no network
//!   method to call, so `host detect` cannot mutate a real installation.
//! * A version is only parsed when it matches a bounded
//!   `major.minor.patch[-prerelease]` shape. Free-form or oversized output stays
//!   unverified and keeps the host in manual review.
//! * A binary stem that has not been certified for a host is reported as a
//!   warning, so a "missing" AGY is never mistaken for "not installed" when the
//!   stem itself is still unconfirmed.
//!
//! Launches use program plus argv through [`LocalHostProbe`]; no argument is ever
//! re-interpreted by a shell.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::Platform;
use serde::{Deserialize, Serialize};

/// Schema version of the detection report this build emits.
pub const DETECTION_SCHEMA_VERSION: u32 = 1;

/// Largest combined version output this module will look at.
pub const MAX_VERSION_OUTPUT_BYTES: usize = 16 * 1024;

/// Largest accepted executable path in a report.
pub const MAX_EXECUTABLE_PATH_BYTES: usize = 4096;

/// Largest accepted prerelease identifier inside a parsed version.
pub const MAX_PRERELEASE_BYTES: usize = 64;

/// Largest accepted `major`/`minor`/`patch` digit run, which bounds the parse.
pub const MAX_VERSION_DIGITS: usize = 9;

/// Longest raw version line kept for diagnostics.
pub const MAX_RAW_VERSION_BYTES: usize = 200;

/// The documented, non-interactive version argv every adapter uses.
pub const VERSION_ARGV: [&str; 1] = ["--version"];

/// Warning: the host executable was found but could not be launched.
pub const RULE_LAUNCH_FAILED: &str = "launch-failed";
/// Warning: the executable exited non-zero while reporting its version.
pub const RULE_LAUNCH_EXIT: &str = "launch-exit";
/// Warning: no version text was produced.
pub const RULE_VERSION_EMPTY: &str = "version-empty";
/// Warning: version text was produced but is not a bounded version-shaped value.
pub const RULE_VERSION_UNPARSED: &str = "version-unparsed";
/// Warning: version output exceeded [`MAX_VERSION_OUTPUT_BYTES`].
pub const RULE_VERSION_OUTPUT_TOO_LARGE: &str = "version-output-too-large";
/// Warning: a located executable path is unusable (relative, oversized, control bytes).
pub const RULE_PROGRAM_PATH_UNUSABLE: &str = "program-path-unusable";
/// Warning: this host's binary stem is not certified yet, so `missing` is weaker.
pub const RULE_BINARY_STEM_UNCONFIRMED: &str = "binary-stem-unconfirmed";

/// Agent host this workspace can adapt to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKind {
    /// OpenAI Codex CLI.
    Codex,
    /// Anthropic Claude Code.
    Claude,
    /// Google Gemini CLI.
    Gemini,
    /// AGY / Antigravity.
    Antigravity,
}

impl HostKind {
    /// Every host, in report order.
    #[must_use]
    pub const fn all() -> &'static [HostKind] {
        &[
            HostKind::Codex,
            HostKind::Claude,
            HostKind::Gemini,
            HostKind::Antigravity,
        ]
    }

    /// Stable wire spelling used in JSON and diagnostics.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Gemini => "gemini",
            Self::Antigravity => "agy",
        }
    }

    /// Program stems probed for this host, in preference order.
    #[must_use]
    pub const fn binary_stems(self) -> &'static [&'static str] {
        match self {
            Self::Codex => &["codex"],
            Self::Claude => &["claude"],
            Self::Gemini => &["gemini"],
            // The documented AGY command stem is not confirmed in the reviewed
            // sources (S13-S16), so both spellings in use are probed and the
            // report carries `binary-stem-unconfirmed`.
            Self::Antigravity => &["agy", "antigravity"],
        }
    }

    /// Whether the binary stems above are confirmed by a reviewed source.
    #[must_use]
    pub const fn binary_stem_certified(self) -> bool {
        !matches!(self, Self::Antigravity)
    }

    /// Parse a wire spelling back to a host.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        let lowered = value.trim().to_ascii_lowercase();
        Self::all()
            .iter()
            .copied()
            .find(|host| host.wire() == lowered)
    }
}

/// A bounded `major.minor.patch[-prerelease]` version read from a host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostVersion {
    /// Major component.
    pub major: u64,
    /// Minor component.
    pub minor: u64,
    /// Patch component.
    pub patch: u64,
    /// Prerelease identifier, without the leading `-`.
    pub prerelease: Option<String>,
}

impl HostVersion {
    /// Parse the first version-shaped value in `text`, bounded by
    /// [`MAX_VERSION_DIGITS`] and [`MAX_PRERELEASE_BYTES`].
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        for (start, byte) in bytes.iter().enumerate() {
            if !byte.is_ascii_digit() {
                continue;
            }
            if let Some(version) = Self::parse_at(text, start) {
                return Some(version);
            }
        }
        None
    }

    fn parse_at(text: &str, start: usize) -> Option<Self> {
        let rest = &text[start..];
        let bytes = rest.as_bytes();
        let mut parts = [0u64; 3];
        let mut cursor = 0usize;
        for (slot, part) in parts.iter_mut().enumerate() {
            let digits_start = cursor;
            while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
                cursor += 1;
            }
            let digits = cursor - digits_start;
            if digits == 0 || digits > MAX_VERSION_DIGITS {
                return None;
            }
            *part = rest[digits_start..cursor].parse().ok()?;
            if slot < 2 {
                if bytes.get(cursor) != Some(&b'.') {
                    return None;
                }
                cursor += 1;
            }
        }
        let mut prerelease = None;
        if bytes.get(cursor) == Some(&b'-') {
            let start = cursor + 1;
            let mut end = start;
            while end < bytes.len() {
                let ch = bytes[end];
                if ch.is_ascii_alphanumeric() || ch == b'.' || ch == b'-' {
                    end += 1;
                } else {
                    break;
                }
            }
            if end == start || end - start > MAX_PRERELEASE_BYTES {
                return None;
            }
            prerelease = Some(rest[start..end].to_owned());
        }
        Some(Self {
            major: parts[0],
            minor: parts[1],
            patch: parts[2],
            prerelease,
        })
    }

    /// Whether this version is at or above `floor`, with a prerelease sorted
    /// before the release it precedes (SemVer 2.0.0 rule 11).
    #[must_use]
    pub fn at_least(&self, floor: &Self) -> bool {
        self >= floor
    }

    /// Stable rendering used in diagnostics and comparison evidence.
    #[must_use]
    pub fn render(&self) -> String {
        match &self.prerelease {
            Some(tag) => format!("{}.{}.{}-{}", self.major, self.minor, self.patch, tag),
            None => format!("{}.{}.{}", self.major, self.minor, self.patch),
        }
    }
}

impl PartialOrd for HostVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HostVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.prerelease, &other.prerelease) {
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (Some(_), None) => std::cmp::Ordering::Less,
                (Some(left), Some(right)) => left.cmp(right),
            })
    }
}

/// What detection could observe about one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostStatus {
    /// No executable was found on the probed search path.
    Missing,
    /// An executable was found but could not be run successfully.
    LaunchFailed,
    /// The host ran, but its version could not be read as a bounded version.
    VersionUnverified,
    /// The host ran and reported a parsed version.
    Detected,
}

impl HostStatus {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::LaunchFailed => "launch_failed",
            Self::VersionUnverified => "version_unverified",
            Self::Detected => "detected",
        }
    }
}

/// Whether an adapter may render config from this detection without a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteEligibility {
    /// A parsed version was read from the host itself.
    AutoWrite,
    /// Manual preview plus instruction/CLI path only: the version is unknown.
    ManualReview,
}

impl WriteEligibility {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoWrite => "auto_write",
            Self::ManualReview => "manual_review",
        }
    }
}

/// One host and everything detection observed about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDetection {
    /// Host this record describes.
    pub host: HostKind,
    /// What detection observed.
    pub status: HostStatus,
    /// Located executable, when one was found.
    pub executable: Option<String>,
    /// Bounded raw version line as reported by the host.
    pub raw_version: Option<String>,
    /// Parsed version, present only when the host reported one.
    pub version: Option<HostVersion>,
    /// Whether an adapter may write config from this record.
    pub write_eligibility: WriteEligibility,
    /// Named warnings, in the order they were raised.
    pub warnings: Vec<String>,
}

impl HostDetection {
    /// Whether the host itself was found and answered.
    #[must_use]
    pub fn is_installed(&self) -> bool {
        matches!(
            self.status,
            HostStatus::Detected | HostStatus::VersionUnverified
        )
    }

    /// Whether a human must review before any config is rendered.
    #[must_use]
    pub fn needs_manual_review(&self) -> bool {
        self.write_eligibility == WriteEligibility::ManualReview
    }
}

/// The whole detection report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostReport {
    /// Schema of this report.
    pub schema_version: u32,
    /// Platform whose search path was probed.
    pub platform: String,
    /// One record per [`HostKind::all`].
    pub hosts: Vec<HostDetection>,
}

impl HostReport {
    /// The record for `host`.
    #[must_use]
    pub fn host(&self, host: HostKind) -> Option<&HostDetection> {
        self.hosts.iter().find(|record| record.host == host)
    }

    /// Hosts detected with a parsed version.
    #[must_use]
    pub fn installed(&self) -> Vec<&HostDetection> {
        self.hosts
            .iter()
            .filter(|record| record.status == HostStatus::Detected)
            .collect()
    }

    /// Hosts a human must review before configuration.
    #[must_use]
    pub fn manual_review(&self) -> Vec<&HostDetection> {
        self.hosts
            .iter()
            .filter(|record| record.needs_manual_review())
            .collect()
    }
}

/// Captured output of one launched program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessOutput {
    /// Process exit code, or `-1` when the host reported no code.
    pub code: i32,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
}

/// Read-only host facts detection needs: locate a program, run it, read output.
///
/// The trait deliberately has no write, no install and no network method, so
/// `host detect` cannot change a real installation even by accident.
pub trait HostProbe: std::fmt::Debug {
    /// Locate an installed program by its stem on the probed search path.
    fn locate(&self, stem: &str) -> Option<String>;

    /// Launch `program` with `argv` and capture its bounded output.
    ///
    /// # Errors
    /// [`ErrorCode::Forbidden`] when the host denies the launch;
    /// [`ErrorCode::Internal`] when the program cannot be spawned.
    fn run(&self, program: &str, argv: &[String]) -> Result<ProcessOutput, AxiomError>;
}

/// Production probe: the real search path and real program launches.
#[derive(Debug, Clone, Default)]
pub struct LocalHostProbe {
    path_dirs: Vec<PathBuf>,
    extensions: Vec<String>,
}

impl LocalHostProbe {
    /// Probe the current process search path.
    #[must_use]
    pub fn for_current_process() -> Self {
        let separator = if cfg!(windows) { ';' } else { ':' };
        let path_dirs = std::env::var("PATH")
            .unwrap_or_default()
            .split(separator)
            .map(str::trim)
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from)
            .collect();
        let extensions = std::env::var("PATHEXT")
            .map(|value| {
                value
                    .split(';')
                    .map(|ext| ext.trim().to_ascii_lowercase())
                    .filter(|ext| !ext.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|_| default_extensions());
        Self {
            path_dirs,
            extensions,
        }
    }

    /// Probe an injected search path. Tests use a rooted temporary directory so
    /// no real host installation is read or launched.
    #[must_use]
    pub fn with_path_dirs(path_dirs: Vec<PathBuf>) -> Self {
        Self {
            path_dirs,
            extensions: default_extensions(),
        }
    }

    fn candidates(&self, stem: &str) -> Vec<String> {
        let mut candidates = vec![stem.to_owned()];
        for extension in &self.extensions {
            candidates.push(format!("{stem}{extension}"));
        }
        candidates
    }
}

fn default_extensions() -> Vec<String> {
    if cfg!(windows) {
        vec![".exe", ".cmd", ".bat"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    } else {
        Vec::new()
    }
}

impl HostProbe for LocalHostProbe {
    fn locate(&self, stem: &str) -> Option<String> {
        if stem.is_empty() || stem.contains(['/', '\\']) {
            return None;
        }
        for dir in &self.path_dirs {
            for candidate in self.candidates(stem) {
                let path = dir.join(&candidate);
                if path.is_file() {
                    if let Some(text) = path.to_str() {
                        return Some(text.to_owned());
                    }
                }
            }
        }
        None
    }

    fn run(&self, program: &str, argv: &[String]) -> Result<ProcessOutput, AxiomError> {
        let output = std::process::Command::new(program)
            .args(argv)
            .output()
            .map_err(|error| {
                let code = if error.kind() == std::io::ErrorKind::PermissionDenied {
                    ErrorCode::Forbidden
                } else {
                    ErrorCode::Internal
                };
                AxiomError::new(
                    code,
                    format!("the host program could not be launched: {error}"),
                )
                .with_detail("rule", RULE_LAUNCH_FAILED)
                .with_detail("program", program)
            })?;
        Ok(ProcessOutput {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Scripted probe: the search-path double used by the tests.
#[derive(Debug, Default)]
pub struct MemoryHostProbe {
    programs: BTreeMap<String, String>,
    outputs: BTreeMap<String, Result<ProcessOutput, AxiomError>>,
    launched: std::cell::RefCell<Vec<(String, Vec<String>)>>,
}

impl MemoryHostProbe {
    /// Register a located executable for `stem`.
    #[must_use]
    pub fn with_program(mut self, stem: &str, path: &str) -> Self {
        self.programs.insert(stem.to_owned(), path.to_owned());
        self
    }

    /// Register the successful version output for `program`.
    #[must_use]
    pub fn with_version_output(mut self, program: &str, text: &str) -> Self {
        self.outputs.insert(
            program.to_owned(),
            Ok(ProcessOutput {
                code: 0,
                stdout: text.to_owned(),
                stderr: String::new(),
            }),
        );
        self
    }

    /// Register a captured output verbatim, including non-zero exits.
    #[must_use]
    pub fn with_output(mut self, program: &str, output: ProcessOutput) -> Self {
        self.outputs.insert(program.to_owned(), Ok(output));
        self
    }

    /// Register a launch failure for `program`.
    #[must_use]
    pub fn with_launch_failure(mut self, program: &str, code: ErrorCode) -> Self {
        self.outputs.insert(
            program.to_owned(),
            Err(AxiomError::new(code, "the scripted launch failed")
                .with_detail("rule", RULE_LAUNCH_FAILED)),
        );
        self
    }

    /// Every launch this probe observed, as `(program, argv)`.
    #[must_use]
    pub fn launches(&self) -> Vec<(String, Vec<String>)> {
        self.launched.borrow().clone()
    }
}

impl HostProbe for MemoryHostProbe {
    fn locate(&self, stem: &str) -> Option<String> {
        self.programs.get(stem).cloned()
    }

    fn run(&self, program: &str, argv: &[String]) -> Result<ProcessOutput, AxiomError> {
        self.launched
            .borrow_mut()
            .push((program.to_owned(), argv.to_vec()));
        match self.outputs.get(program) {
            Some(Ok(output)) => Ok(output.clone()),
            Some(Err(error)) => Err(error.clone()),
            None => Err(AxiomError::new(
                ErrorCode::NotFound,
                "the scripted probe has no output for this program",
            )
            .with_detail("rule", RULE_LAUNCH_FAILED)
            .with_detail("program", program)),
        }
    }
}

/// Detect every host through `probe`.
#[must_use]
pub fn detect(probe: &impl HostProbe) -> HostReport {
    HostReport {
        schema_version: DETECTION_SCHEMA_VERSION,
        platform: Platform::current().as_str().to_owned(),
        hosts: HostKind::all()
            .iter()
            .copied()
            .map(|host| detect_host(probe, host))
            .collect(),
    }
}

/// Detect one host through `probe`.
///
/// Never returns an error: a host that cannot be probed is reported as
/// [`HostStatus::Missing`] or [`HostStatus::LaunchFailed`] with a named warning,
/// exactly like `axiom doctor` reports findings instead of repairing them.
#[must_use]
pub fn detect_host(probe: &impl HostProbe, host: HostKind) -> HostDetection {
    let mut warnings = Vec::new();
    if !host.binary_stem_certified() {
        warnings.push(RULE_BINARY_STEM_UNCONFIRMED.to_owned());
    }

    let mut executable = None;
    for stem in host.binary_stems() {
        let Some(path) = probe.locate(stem) else {
            continue;
        };
        if is_usable_program_path(&path) {
            executable = Some(path);
            break;
        }
        warnings.push(format!("{RULE_PROGRAM_PATH_UNUSABLE}:{stem}"));
    }

    let Some(program) = executable else {
        return HostDetection {
            host,
            status: HostStatus::Missing,
            executable: None,
            raw_version: None,
            version: None,
            write_eligibility: WriteEligibility::ManualReview,
            warnings,
        };
    };

    let argv: Vec<String> = VERSION_ARGV.iter().map(|arg| (*arg).to_owned()).collect();
    let output = match probe.run(&program, &argv) {
        Ok(output) => output,
        Err(error) => {
            warnings.push(format!("{RULE_LAUNCH_FAILED}:{}", error.message()));
            return HostDetection {
                host,
                status: HostStatus::LaunchFailed,
                executable: Some(program),
                raw_version: None,
                version: None,
                write_eligibility: WriteEligibility::ManualReview,
                warnings,
            };
        }
    };

    let raw = raw_version_line(&output);
    if output.stdout.len() + output.stderr.len() > MAX_VERSION_OUTPUT_BYTES {
        warnings.push(RULE_VERSION_OUTPUT_TOO_LARGE.to_owned());
        return HostDetection {
            host,
            status: HostStatus::VersionUnverified,
            executable: Some(program),
            raw_version: raw,
            version: None,
            write_eligibility: WriteEligibility::ManualReview,
            warnings,
        };
    }
    if output.code != 0 {
        warnings.push(format!("{RULE_LAUNCH_EXIT}:{}", output.code));
        return HostDetection {
            host,
            status: HostStatus::LaunchFailed,
            executable: Some(program),
            raw_version: raw,
            version: None,
            write_eligibility: WriteEligibility::ManualReview,
            warnings,
        };
    }

    let version = raw.as_deref().and_then(HostVersion::parse);
    let Some(version) = version else {
        warnings.push(if raw.is_none() {
            RULE_VERSION_EMPTY.to_owned()
        } else {
            RULE_VERSION_UNPARSED.to_owned()
        });
        return HostDetection {
            host,
            status: HostStatus::VersionUnverified,
            executable: Some(program),
            raw_version: raw,
            version: None,
            write_eligibility: WriteEligibility::ManualReview,
            warnings,
        };
    };

    HostDetection {
        host,
        status: HostStatus::Detected,
        executable: Some(program),
        raw_version: raw,
        version: Some(version),
        write_eligibility: WriteEligibility::AutoWrite,
        warnings,
    }
}

/// Whether a located path may be recorded and launched.
fn is_usable_program_path(path: &str) -> bool {
    !path.trim().is_empty()
        && path.len() <= MAX_EXECUTABLE_PATH_BYTES
        && !path.chars().any(char::is_control)
        && Path::new(path).is_absolute()
        && !path.contains('"')
}

/// First non-empty line of stdout, then stderr, bounded and control-stripped.
fn raw_version_line(output: &ProcessOutput) -> Option<String> {
    let line = output
        .stdout
        .lines()
        .chain(output.stderr.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())?;
    let cleaned: String = line.chars().filter(|ch| !ch.is_control()).collect();
    if cleaned.len() <= MAX_RAW_VERSION_BYTES {
        return Some(cleaned);
    }
    let mut bounded = cleaned;
    let mut cut = MAX_RAW_VERSION_BYTES;
    while cut > 0 && !bounded.is_char_boundary(cut) {
        cut -= 1;
    }
    bounded.truncate(cut);
    Some(bounded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reported_version_is_parsed_and_eligible_for_config() {
        let probe = MemoryHostProbe::default()
            .with_program("codex", "/opt/hosts/codex")
            .with_version_output("/opt/hosts/codex", "codex-cli 0.42.0\n");
        let record = detect_host(&probe, HostKind::Codex);
        assert_eq!(record.status, HostStatus::Detected);
        assert_eq!(record.write_eligibility, WriteEligibility::AutoWrite);
        assert_eq!(
            record.version,
            Some(HostVersion {
                major: 0,
                minor: 42,
                patch: 0,
                prerelease: None,
            })
        );
        assert_eq!(record.raw_version.as_deref(), Some("codex-cli 0.42.0"));
        assert_eq!(
            probe.launches(),
            vec![("/opt/hosts/codex".to_owned(), vec!["--version".to_owned()])]
        );
    }

    #[test]
    fn an_unknown_version_stays_unconfigured_pending_review() {
        let probe = MemoryHostProbe::default()
            .with_program("gemini", "/opt/hosts/gemini")
            .with_version_output("/opt/hosts/gemini", "gemini version unknown\n");
        let record = detect_host(&probe, HostKind::Gemini);
        assert_eq!(record.status, HostStatus::VersionUnverified);
        assert!(record.version.is_none());
        assert!(record.needs_manual_review());
        assert!(record.is_installed());
        assert_eq!(record.warnings, vec![RULE_VERSION_UNPARSED.to_owned()]);
    }

    #[test]
    fn a_missing_host_is_missing_and_never_configured() {
        let probe = MemoryHostProbe::default();
        let record = detect_host(&probe, HostKind::Claude);
        assert_eq!(record.status, HostStatus::Missing);
        assert!(record.executable.is_none());
        assert!(record.needs_manual_review());
        assert!(!record.is_installed());
        assert!(probe.launches().is_empty());
    }

    #[test]
    fn a_nonzero_exit_is_a_failed_launch_with_the_raw_line_kept() {
        let probe = MemoryHostProbe::default()
            .with_program("claude", "/opt/hosts/claude")
            .with_output(
                "/opt/hosts/claude",
                ProcessOutput {
                    code: 2,
                    stdout: "claude 1.0.1\n".to_owned(),
                    stderr: "deprecated invocation\n".to_owned(),
                },
            );
        let record = detect_host(&probe, HostKind::Claude);
        assert_eq!(record.status, HostStatus::LaunchFailed);
        assert!(record.version.is_none());
        assert_eq!(record.raw_version.as_deref(), Some("claude 1.0.1"));
        assert!(record.warnings.contains(&format!("{RULE_LAUNCH_EXIT}:2")));
        assert!(record.needs_manual_review());
    }

    #[test]
    fn a_denied_launch_reports_the_rule_instead_of_a_version() {
        let probe = MemoryHostProbe::default()
            .with_program("codex", "/opt/hosts/codex")
            .with_launch_failure("/opt/hosts/codex", ErrorCode::Forbidden);
        let failure = probe
            .run("/opt/hosts/codex", &["--version".to_owned()])
            .expect_err("the scripted launch fails");
        assert_eq!(failure.code(), ErrorCode::Forbidden);
        assert_eq!(
            failure.details().get("rule").map(String::as_str),
            Some(RULE_LAUNCH_FAILED)
        );
        let record = detect_host(&probe, HostKind::Codex);
        assert_eq!(record.status, HostStatus::LaunchFailed);
        assert!(record.warnings[0].starts_with(RULE_LAUNCH_FAILED));
        assert!(record.needs_manual_review());
    }

    #[test]
    fn oversized_and_empty_output_stay_unverified() {
        let oversized = "x".repeat(MAX_VERSION_OUTPUT_BYTES + 1);
        let probe = MemoryHostProbe::default()
            .with_program("codex", "/opt/hosts/codex")
            .with_version_output("/opt/hosts/codex", &oversized);
        let record = detect_host(&probe, HostKind::Codex);
        assert_eq!(record.status, HostStatus::VersionUnverified);
        assert!(record
            .warnings
            .contains(&RULE_VERSION_OUTPUT_TOO_LARGE.to_owned()));

        let empty = MemoryHostProbe::default()
            .with_program("codex", "/opt/hosts/codex")
            .with_version_output("/opt/hosts/codex", "   \n\n");
        let record = detect_host(&empty, HostKind::Codex);
        assert_eq!(record.status, HostStatus::VersionUnverified);
        assert_eq!(record.raw_version, None);
        assert_eq!(record.warnings, vec![RULE_VERSION_EMPTY.to_owned()]);
    }

    #[test]
    fn an_unusable_program_path_is_refused_with_a_warning() {
        for path in ["", "codex", "/opt/hosts/co\u{7}dex"] {
            let probe = MemoryHostProbe::default().with_program("codex", path);
            let record = detect_host(&probe, HostKind::Codex);
            assert_eq!(record.status, HostStatus::Missing);
            assert!(record
                .warnings
                .contains(&format!("{RULE_PROGRAM_PATH_UNUSABLE}:codex")));
            assert!(probe.launches().is_empty());
        }
    }

    #[test]
    fn the_uncertified_stem_is_reported_for_agy() {
        let probe = MemoryHostProbe::default()
            .with_program("agy", "/opt/hosts/agy")
            .with_version_output("/opt/hosts/agy", "1.4.0\n");
        let report = detect(&probe);
        let record = report.host(HostKind::Antigravity).expect("a record");
        assert_eq!(record.status, HostStatus::Detected);
        assert_eq!(
            record.warnings,
            vec![RULE_BINARY_STEM_UNCONFIRMED.to_owned()]
        );
        assert_eq!(
            report.host(HostKind::Codex).expect("a record").status,
            HostStatus::Missing
        );
        assert_eq!(report.installed().len(), 1);
        assert_eq!(report.manual_review().len(), 3);
        assert_eq!(report.schema_version, DETECTION_SCHEMA_VERSION);
    }

    #[test]
    fn version_ordering_follows_semver_prerelease_rules() {
        let release = HostVersion::parse("codex 1.2.3").expect("a version");
        let prerelease = HostVersion::parse("codex 1.2.3-rc.1").expect("a version");
        let older = HostVersion::parse("codex 1.2.2").expect("a version");
        assert!(release > prerelease);
        assert!(prerelease > older);
        assert!(release.at_least(&prerelease));
        assert!(!older.at_least(&release));
        assert_eq!(prerelease.render(), "1.2.3-rc.1");
        assert_eq!(HostVersion::parse("gemini 1.2"), None);
        assert_eq!(HostVersion::parse("no digits here"), None);
        assert_eq!(
            HostVersion::parse("2026-09-19T00:00:00Z"),
            None,
            "a date is not a version"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_real_launch_from_a_rooted_temp_path_is_detected() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("a temp dir");
        let program = dir.path().join("codex");
        std::fs::write(&program, "#!/bin/sh\necho codex-cli 1.0.0\n").expect("a script");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
            .expect("an executable");

        let probe = LocalHostProbe::with_path_dirs(vec![dir.path().to_path_buf()]);
        let record = detect_host(&probe, HostKind::Codex);
        assert_eq!(record.status, HostStatus::Detected);
        assert_eq!(record.raw_version.as_deref(), Some("codex-cli 1.0.0"));
        assert_eq!(record.version.expect("a version").render(), "1.0.0");
        assert!(record.executable.expect("a path").ends_with("codex"));

        // The injected path is the only one probed: the real host path is untouched.
        let absent = detect_host(&probe, HostKind::Claude);
        assert_eq!(absent.status, HostStatus::Missing);
    }

    #[test]
    fn the_wire_vocabulary_round_trips() {
        for host in HostKind::all() {
            assert_eq!(HostKind::from_wire(host.wire()), Some(*host));
        }
        assert_eq!(HostKind::from_wire(" AGY "), Some(HostKind::Antigravity));
        assert_eq!(HostKind::from_wire("unknown-host"), None);
        assert_eq!(HostKind::all().len(), 4);
    }
}
