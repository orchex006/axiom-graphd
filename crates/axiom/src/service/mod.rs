//! Service adapters for the `axiom` CLI (tasks E-008..E-011).
//!
//! `21-INSTALLATION.md` section E makes one managed user process per component
//! the supported way to run the daemon and the gateway, and pins the per-host
//! mechanism: a per-user startup record on Windows, a systemd user unit on
//! Linux and a launchd agent on macOS. Section E is explicit that the choice is
//! per-user, that the adapter must cover logs, restart policy, stop and
//! uninstall, and that with no administrator permission the installer must fall
//! back to the foreground rather than change a machine-wide policy.
//!
//! This module holds the platform-neutral pieces every adapter shares:
//!
//! * [`Consent`] - the token that says a human saw the reviewed plan and agreed
//!   to register a startup record. It is required, not implied.
//! * [`RestartPolicy`] - how a managed process is restarted after a failure,
//!   validated so a policy cannot ask for an unbounded restart loop.
//! * [`StartupTrigger`] - when the managed process starts (logon, for now).
//!
//! The per-host adapters live beside it: [`windows`] implements the Windows
//! per-user Scheduled Task, [`linux`] the systemd user unit and [`macos`] the
//! launchd agent. [`control`] is the host-neutral start/stop/status surface over
//! all three (task E-011), so a front end never chooses a host command itself.

use serde::{Deserialize, Serialize};

use crate::discovery::ServiceKind;

pub mod control;
pub mod linux;
pub mod macos;
pub mod startup;
pub mod windows;

/// Directory, relative to the install root, that holds service definitions and
/// their rendered task/unit files.
pub const SERVICE_DIRECTORY: &str = "service";

/// Directory, relative to the install root, that holds the managed process logs.
pub const SERVICE_LOG_DIRECTORY: &str = "logs";

/// Upper bound on `max_attempts` in [`RestartPolicy`], matching the largest
/// count Windows Task Scheduler accepts.
pub const MAX_RESTART_ATTEMPTS: u32 = 999;

/// Upper bound, in seconds, on the restart delay in [`RestartPolicy`].
pub const MAX_RESTART_DELAY_SECONDS: u32 = 86_400;

/// Reason recorded when a restart policy asks for something out of range.
pub const REASON_RESTART_POLICY: &str = "restart-policy-out-of-range";

/// Explicit human consent to register a startup record.
///
/// Installation registers a startup record that runs a program after the user
/// signs in. That is a change to the user's session, so a front end must ask
/// first; this token is how the front end states that it did. The tuple field
/// is private, so the token cannot be produced with a struct literal - calling
/// [`Consent::explicit`] is the only way to make one, and it is always passed
/// to an adapter as its own argument rather than buried in a request struct.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Consent(());

impl Consent {
    /// The consent token, returned only from a deliberate call.
    #[must_use]
    pub const fn explicit() -> Self {
        Self(())
    }
}

/// When a managed process starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupTrigger {
    /// Start when the user signs in. The per-user default on every host.
    Logon,
}

impl StartupTrigger {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Logon => "logon",
        }
    }
}

/// How a managed process is restarted after it fails.
///
/// `on_failure: false` is the explicit "never restart" policy; when it is
/// `true` the delay and attempt count must be inside the range the host
/// scheduler accepts, so a policy cannot declare an unbounded restart loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartPolicy {
    /// Whether the host scheduler restarts the process after a failure.
    pub on_failure: bool,
    /// Seconds to wait before a restart; `0` when `on_failure` is `false`.
    pub delay_seconds: u32,
    /// Restart attempts before the scheduler gives up; `0` when `on_failure`
    /// is `false`.
    pub max_attempts: u32,
}

impl RestartPolicy {
    /// The explicit "never restart" policy.
    #[must_use]
    pub const fn never() -> Self {
        Self {
            on_failure: false,
            delay_seconds: 0,
            max_attempts: 0,
        }
    }

    /// A bounded on-failure policy.
    #[must_use]
    pub const fn on_failure(delay_seconds: u32, max_attempts: u32) -> Self {
        Self {
            on_failure: true,
            delay_seconds,
            max_attempts,
        }
    }

    /// True when this policy is inside the accepted range.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        if !self.on_failure {
            return self.delay_seconds == 0 && self.max_attempts == 0;
        }
        self.max_attempts >= 1
            && self.max_attempts <= MAX_RESTART_ATTEMPTS
            && self.delay_seconds >= 1
            && self.delay_seconds <= MAX_RESTART_DELAY_SECONDS
    }
}

/// One scheduler command: a program and its arguments, never a shell string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceOperation {
    /// Human-readable action name (`register`, `start`, ...).
    pub description: String,
    /// Program to run, by name or absolute path.
    pub program: String,
    /// Arguments, one per element.
    pub args: Vec<String>,
}

impl ServiceOperation {
    /// Machine-readable rendering of the command.
    ///
    /// # Errors
    /// [graph_core::error::ErrorCode::Internal] when the command cannot be
    /// serialised.
    pub fn to_json(&self) -> Result<String, graph_core::error::AxiomError> {
        serde_json::to_string(self).map_err(|error| {
            graph_core::error::AxiomError::new(
                graph_core::error::ErrorCode::Internal,
                "the service operation is not serialisable",
            )
            .with_detail("observed", error.to_string())
        })
    }

    /// One-line human rendering of the command.
    #[must_use]
    pub fn text(&self) -> String {
        let mut line = self.program.clone();
        for arg in &self.args {
            line.push(' ');
            line.push_str(arg);
        }
        format!("{}: {line}\n", self.description)
    }
}

/// Result of one scheduler invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceOutput {
    /// Process exit code.
    pub code: i32,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
}

/// The whole process surface of a service adapter.
///
/// The adapters render their host commands and hand them to an implementation
/// of this trait, so no test spawns a scheduler, a `systemctl` or a `launchctl`
/// and no argument is ever re-interpreted by a shell.
pub trait ServiceExec {
    /// Run one operation, returning its captured output.
    ///
    /// # Errors
    /// [graph_core::error::ErrorCode::Internal] when the process cannot be
    /// spawned; [graph_core::error::ErrorCode::Forbidden] when the host denies
    /// the operation.
    fn run(
        &self,
        operation: &ServiceOperation,
    ) -> Result<ServiceOutput, graph_core::error::AxiomError>;
}

/// Production executor: spawns the host program with program plus argv.
#[derive(Debug, Clone, Copy, Default)]
pub struct SysExec;

impl ServiceExec for SysExec {
    fn run(
        &self,
        operation: &ServiceOperation,
    ) -> Result<ServiceOutput, graph_core::error::AxiomError> {
        let output = std::process::Command::new(&operation.program)
            .args(&operation.args)
            .output()
            .map_err(|error| {
                graph_core::error::AxiomError::new(
                    graph_core::error::ErrorCode::Internal,
                    format!("the host program could not be launched: {}", error),
                )
                .with_detail("program", &operation.program)
            })?;
        Ok(ServiceOutput {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}
/// Stable wire spelling of a [`ServiceKind`], shared by every adapter.
#[must_use]
pub const fn mechanism_wire(kind: ServiceKind) -> &'static str {
    match kind {
        ServiceKind::PerUserStartup => "per_user_startup",
        ServiceKind::SystemdUserUnit => "systemd_user_unit",
        ServiceKind::LaunchAgent => "launch_agent",
        ServiceKind::SystemService => "system_service",
    }
}

/// The service after a successful registration on any host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledService {
    /// Component the service starts.
    pub component: String,
    /// Registered task or unit name.
    pub task_name: String,
    /// The mechanism, one of [`ServiceKind`].
    pub mechanism: ServiceKind,
    /// The scope, always per-user for the managed adapters.
    pub scope: crate::install::plan::InstallScope,
    /// Absolute host path of the definition written beside the install root.
    pub definition_path: String,
    /// Absolute host log file.
    pub log_file: String,
    /// Restart policy.
    pub restart: RestartPolicy,
}

impl InstalledService {
    /// Machine-readable rendering of the installed service.
    ///
    /// # Errors
    /// [graph_core::error::ErrorCode::Internal] when the service cannot be
    /// serialised.
    pub fn to_json(&self) -> Result<String, graph_core::error::AxiomError> {
        serde_json::to_string_pretty(self).map_err(|error| {
            graph_core::error::AxiomError::new(
                graph_core::error::ErrorCode::Internal,
                "the installed service is not serialisable",
            )
            .with_detail("observed", error.to_string())
        })
    }

    /// One-line human rendering of the installed service.
    #[must_use]
    pub fn text(&self) -> String {
        format!(
            "{}: {} ({}) scope={} log={}\n",
            self.component,
            self.task_name,
            mechanism_wire(self.mechanism),
            self.scope.as_str(),
            self.log_file,
        )
    }
}
/// True when `child` is inside `parent`, comparing separators module-insensitively.
#[must_use]
pub(crate) fn is_under(parent: &str, child: &str) -> bool {
    fn normalise(path: &str) -> String {
        let mut out = path.replace('\\', "/");
        while out.ends_with('/') {
            out.pop();
        }
        out.to_ascii_lowercase()
    }
    let parent = normalise(parent);
    let child = normalise(child);
    child.len() > parent.len()
        && child.starts_with(&parent)
        && child.as_bytes()[parent.len()] == b'/'
}

/// Escape the five XML metacharacters.
#[must_use]
pub(crate) fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}
