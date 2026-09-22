//! macOS per-user startup adapter: a launchd LaunchAgent (task E-010).
//!
//! `21-INSTALLATION.md` section E pins the macOS mechanism as a *launchd agent*
//! and keeps it per-user: the agent lives in the user's own
//! `~/Library/LaunchAgents` and is controlled in that user's launchd namespace.
//!
//! ## What this module guarantees (AC1)
//!
//! * The agent label and the plist path are both derived from the user's own
//!   home directory. [`plan_agent`] refuses a plist path that is not under
//!   `<home>/Library/LaunchAgents`, so a definition can never be written into a
//!   system location or another user's tree.
//! * [`plan_removal`] refuses a label this adapter does not own *and* a plist
//!   outside the user's agent directory, so an invalid or foreign configuration
//!   fails closed: it produces no `launchctl` operation and no file to delete,
//!   and therefore cannot remove an unrelated agent.
//! * As on every host, a system-scoped or elevated request is refused
//!   `Forbidden` before anything is rendered.
//!
//! ## Why execution is a trait
//!
//! The same [`ServiceExec`] boundary the other adapters use drives `launchctl`,
//! so no test spawns a process and the rendered command is program plus argv.

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{is_absolute_host_path, validate_portable_relative_path};
use serde::{Deserialize, Serialize};

use crate::discovery::{ServiceKind, INSTALLABLE_COMPONENTS};
use crate::install::plan::{under, InstallScope};
use crate::service::{
    is_under, xml_escape, Consent, InstalledService, RestartPolicy, ServiceExec, ServiceOperation,
    StartupTrigger, REASON_RESTART_POLICY, SERVICE_LOG_DIRECTORY,
};

/// The mechanism this adapter implements, in the shared service vocabulary.
pub const MECHANISM: ServiceKind = ServiceKind::LaunchAgent;

/// Host identifiers this adapter serves.
pub const HOSTS: [&str; 2] = ["macos-arm64", "macos-x64"];

/// The controller the adapter drives, by name only.
pub const LAUNCHCTL_PROGRAM: &str = "launchctl";

/// Reverse-DNS prefix of every agent label the adapter owns.
pub const LABEL_PREFIX: &str = "com.axiom.";

/// User agent directory, relative to the user's home.
pub const USER_AGENT_DIR: &str = "Library/LaunchAgents";

/// Suffix of an agent definition.
pub const PLIST_SUFFIX: &str = ".plist";

/// Reason recorded when a request is not per-user.
pub const REASON_UNSUPPORTED_SCOPE: &str = "unsupported-scope";

/// Reason recorded when a request asks the adapter to elevate.
pub const REASON_ELEVATION_REQUESTED: &str = "elevation-requested";

/// Reason recorded when a component is not one the CLI installs.
pub const REASON_UNKNOWN_COMPONENT: &str = "unknown-component";

/// Reason recorded when a required host path is not absolute.
pub const REASON_UNSAFE_PATH: &str = "unsafe-path";

/// Reason recorded when a log file is not inside the install root's log tree.
pub const REASON_LOG_OUTSIDE_ROOT: &str = "log-outside-install-root";

/// Reason recorded when a plist is not inside the user's agent directory.
pub const REASON_AGENT_OUTSIDE_HOME: &str = "agent-outside-user-directory";

/// Reason recorded when a program argument is not a safe argument.
pub const REASON_UNSAFE_ARGUMENT: &str = "unsafe-argument";

/// Reason recorded when a label is not one this adapter owns.
pub const REASON_FOREIGN_AGENT: &str = "foreign-agent";

/// Reason recorded when `launchctl` exits non-zero.
pub const REASON_CONTROLLER_EXIT: &str = "controller-exit";
/// Reason recorded when a launchd user domain is not a concrete user identity.
pub const REASON_UNSAFE_USER_ID: &str = "unsafe-user-id";

/// Engine-owned identity of the launchd user domain an operation may affect.
///
/// This is intentionally separate from paths and labels: a caller cannot
/// select a launchd domain by spelling a home directory or a service name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchdIdentity {
    /// Numeric effective user id of the active per-user launchd domain.
    pub user_id: u32,
}

impl LaunchdIdentity {
    /// Construct one non-root per-user launchd identity.
    ///
    /// The CLI must compare this value with the current effective UID before
    /// executing it; this constructor only makes an invalid domain impossible.
    pub fn new(user_id: u32) -> Result<Self, AxiomError> {
        if user_id == 0 {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_UNSAFE_USER_ID,
                "0",
                "a managed LaunchAgent cannot target the root launchd domain",
            ));
        }
        Ok(Self { user_id })
    }

    /// The launchctl domain argument for this identity.
    #[must_use]
    pub fn domain(self) -> String {
        format!("gui/{}", self.user_id)
    }
}

/// What one registration needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosServiceRequest {
    /// Component from [`INSTALLABLE_COMPONENTS`] this agent starts.
    pub component: String,
    /// Absolute host path of the component executable.
    pub executable: String,
    /// Program arguments, passed as argv; never a shell string.
    pub args: Vec<String>,
    /// Absolute host working directory for the process.
    pub working_directory: String,
    /// Absolute host install root that owns the logs.
    pub install_root: String,
    /// Absolute host path of the user's home directory.
    pub home: String,
    /// Absolute host path the managed process writes its log to.
    pub log_file: String,
    /// Installation scope; only [`InstallScope::PerUser`] is accepted.
    pub scope: InstallScope,
    /// When the process starts.
    pub trigger: StartupTrigger,
    /// How the process is restarted after a failure.
    pub restart: RestartPolicy,
    /// A caller asking for elevation; must be `false`.
    pub request_elevation: bool,
}

impl MacosServiceRequest {
    /// A per-user logon request for one component and executable.
    #[must_use]
    pub fn new(
        component: impl Into<String>,
        executable: impl Into<String>,
        working_directory: impl Into<String>,
        install_root: impl Into<String>,
        home: impl Into<String>,
    ) -> Self {
        let component = component.into();
        let install_root = install_root.into();
        let log_file = under(
            &install_root,
            &[SERVICE_LOG_DIRECTORY, &format!("{component}.log")],
        );
        Self {
            component,
            executable: executable.into(),
            args: vec!["serve".to_owned()],
            working_directory: working_directory.into(),
            install_root,
            home: home.into(),
            log_file,
            scope: InstallScope::PerUser,
            trigger: StartupTrigger::Logon,
            restart: RestartPolicy::never(),
            request_elevation: false,
        }
    }

    /// Replace the program arguments.
    #[must_use]
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Replace the restart policy.
    #[must_use]
    pub fn with_restart(mut self, restart: RestartPolicy) -> Self {
        self.restart = restart;
        self
    }

    /// Replace the log destination.
    #[must_use]
    pub fn with_log_file(mut self, log_file: impl Into<String>) -> Self {
        self.log_file = log_file.into();
        self
    }
}

/// A fully rendered, reviewable per-user LaunchAgent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchAgent {
    /// Component the agent starts.
    pub component: String,
    /// Agent label, `com.axiom.<component>`.
    pub label: String,
    /// The mechanism, always [`MECHANISM`].
    pub mechanism: ServiceKind,
    /// The scope, always per-user.
    pub scope: InstallScope,
    /// When the agent starts.
    pub trigger: StartupTrigger,
    /// Restart policy the agent declares.
    pub restart: RestartPolicy,
    /// Absolute host path of the executable.
    pub executable: String,
    /// Arguments passed as argv.
    pub args: Vec<String>,
    /// Absolute host working directory.
    pub working_directory: String,
    /// Absolute host log file.
    pub log_file: String,
    /// Absolute host path of the rendered plist.
    pub plist_path: String,
    /// The rendered plist.
    pub plist: String,
}

impl LaunchAgent {
    /// Machine-readable rendering of the agent.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the agent cannot be serialised.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        serde_json::to_string_pretty(self).map_err(|error| {
            AxiomError::new(ErrorCode::Internal, "the launch agent is not serialisable")
                .with_detail("observed", error.to_string())
        })
    }

    /// The operation that loads the agent into the user's namespace.
    #[must_use]
    pub fn load_operation(&self) -> ServiceOperation {
        ServiceOperation {
            description: "load".to_owned(),
            program: LAUNCHCTL_PROGRAM.to_owned(),
            args: vec!["load".to_owned(), "-w".to_owned(), self.plist_path.clone()],
        }
    }
}

/// Render the modern launchd registration command for an owned agent.
#[must_use]
pub fn bootstrap_operation(agent: &LaunchAgent, identity: LaunchdIdentity) -> ServiceOperation {
    ServiceOperation {
        description: "bootstrap".to_owned(),
        program: LAUNCHCTL_PROGRAM.to_owned(),
        args: vec![
            "bootstrap".to_owned(),
            identity.domain(),
            agent.plist_path.clone(),
        ],
    }
}

/// Render the modern launchd removal command for an owned plist.
pub fn bootout_operation(
    label: &str,
    plist_path: &str,
    home: &str,
    identity: LaunchdIdentity,
) -> Result<ServiceOperation, AxiomError> {
    let removal = plan_removal(label, plist_path, home)?;
    Ok(ServiceOperation {
        description: "bootout".to_owned(),
        program: LAUNCHCTL_PROGRAM.to_owned(),
        args: vec!["bootout".to_owned(), identity.domain(), removal.plist_path],
    })
}

/// Remove a live owned label when its plist was already removed by a partial
/// cleanup. The label is validated before it is placed in the GUI target.
pub fn bootout_target_operation(
    label: &str,
    identity: LaunchdIdentity,
) -> Result<ServiceOperation, AxiomError> {
    owned_label(label)?;
    Ok(ServiceOperation {
        description: "bootout".to_owned(),
        program: LAUNCHCTL_PROGRAM.to_owned(),
        args: vec![
            "bootout".to_owned(),
            format!("{}/{}", identity.domain(), label),
        ],
    })
}

/// Render status for an owned agent in one explicit user domain.
pub fn status_operation_for_user(
    label: &str,
    identity: LaunchdIdentity,
) -> Result<ServiceOperation, AxiomError> {
    owned_label(label)?;
    Ok(ServiceOperation {
        description: "status".to_owned(),
        program: LAUNCHCTL_PROGRAM.to_owned(),
        args: vec![
            "print".to_owned(),
            format!("{}/{}", identity.domain(), label),
        ],
    })
}

/// Start an owned agent in its explicit per-user launchd domain.
pub fn kickstart_operation(
    label: &str,
    identity: LaunchdIdentity,
) -> Result<ServiceOperation, AxiomError> {
    owned_label(label)?;
    Ok(ServiceOperation {
        description: "kickstart".to_owned(),
        program: LAUNCHCTL_PROGRAM.to_owned(),
        args: vec![
            "kickstart".to_owned(),
            "-k".to_owned(),
            format!("{}/{}", identity.domain(), label),
        ],
    })
}

/// Request graceful termination of an owned agent in its explicit user domain.
pub fn kill_operation(
    label: &str,
    identity: LaunchdIdentity,
) -> Result<ServiceOperation, AxiomError> {
    owned_label(label)?;
    Ok(ServiceOperation {
        description: "kill".to_owned(),
        program: LAUNCHCTL_PROGRAM.to_owned(),
        args: vec![
            "kill".to_owned(),
            "SIGTERM".to_owned(),
            format!("{}/{}", identity.domain(), label),
        ],
    })
}

/// A removal that is proven to touch only this adapter's own agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRemoval {
    /// Agent label that is unloaded.
    pub label: String,
    /// The plist that is the only file removed.
    pub plist_path: String,
    /// Operations that unload the agent.
    pub operations: Vec<ServiceOperation>,
    /// Files the removal deletes; the owned plist only.
    pub files: Vec<String>,
}

/// A refusal that changes nothing on the host.
fn refuse(code: ErrorCode, rule: &str, observed: &str, message: &str) -> AxiomError {
    AxiomError::new(code, message)
        .with_detail("rule", rule)
        .with_detail("observed", observed)
}

/// The agent label owned by one component.
///
/// # Errors
/// [ErrorCode::ValidationError] when the component is not installable or its
/// name is not a safe segment.
pub fn agent_label(component: &str) -> Result<String, AxiomError> {
    if !INSTALLABLE_COMPONENTS.contains(&component)
        || validate_portable_relative_path(component).is_err()
    {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_UNKNOWN_COMPONENT,
            component,
            "the component is not one the CLI installs",
        ));
    }
    Ok(format!("{LABEL_PREFIX}{component}"))
}

/// Check that a label is one this adapter owns.
fn owned_label(label: &str) -> Result<(), AxiomError> {
    let Some(component) = label.strip_prefix(LABEL_PREFIX) else {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_FOREIGN_AGENT,
            label,
            "the agent is not owned by axiom",
        ));
    };
    if INSTALLABLE_COMPONENTS.contains(&component)
        && validate_portable_relative_path(component).is_ok()
    {
        Ok(())
    } else {
        Err(refuse(
            ErrorCode::ValidationError,
            REASON_FOREIGN_AGENT,
            label,
            "the agent is not owned by axiom",
        ))
    }
}

/// Render the property list for one per-user agent.
fn render_plist(label: &str, request: &MacosServiceRequest, axiom_home: &str) -> String {
    let MacosServiceRequest {
        executable,
        args,
        working_directory,
        log_file,
        install_root,
        restart,
        ..
    } = request;
    let mut lines: Vec<String> = Vec::new();
    lines.push(r#"<?xml version="1.0" encoding="UTF-8"?>"#.to_owned());
    lines.push(
        r#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">"#
            .to_owned(),
    );
    lines.push(r#"<plist version="1.0">"#.to_owned());
    lines.push("<dict>".to_owned());
    lines.push("  <key>Label</key>".to_owned());
    lines.push(format!("  <string>{}</string>", xml_escape(label)));
    lines.push("  <key>ProgramArguments</key>".to_owned());
    lines.push("  <array>".to_owned());
    lines.push(format!("    <string>{}</string>", xml_escape(executable)));
    for argument in args {
        lines.push(format!("    <string>{}</string>", xml_escape(argument)));
    }
    lines.push("  </array>".to_owned());
    lines.push("  <key>WorkingDirectory</key>".to_owned());
    lines.push(format!(
        "  <string>{}</string>",
        xml_escape(working_directory)
    ));
    lines.push("  <key>RunAtLoad</key>".to_owned());
    lines.push("  <true/>".to_owned());
    lines.push("  <key>KeepAlive</key>".to_owned());
    if restart.on_failure {
        lines.push("  <dict>".to_owned());
        lines.push("    <key>SuccessfulExit</key>".to_owned());
        lines.push("    <false/>".to_owned());
        lines.push("  </dict>".to_owned());
        lines.push("  <key>ThrottleInterval</key>".to_owned());
        lines.push(format!("  <integer>{}</integer>", restart.delay_seconds));
    } else {
        lines.push("  <false/>".to_owned());
    }
    lines.push("  <key>StandardOutPath</key>".to_owned());
    lines.push(format!("  <string>{}</string>", xml_escape(log_file)));
    lines.push("  <key>StandardErrorPath</key>".to_owned());
    lines.push(format!("  <string>{}</string>", xml_escape(log_file)));
    lines.push("  <key>EnvironmentVariables</key>".to_owned());
    lines.push("  <dict>".to_owned());
    lines.push("    <key>AXIOM_INSTALL_ROOT</key>".to_owned());
    lines.push(format!("    <string>{}</string>", xml_escape(install_root)));
    lines.push("    <key>AXIOM_HOME</key>".to_owned());
    lines.push(format!("    <string>{}</string>", xml_escape(axiom_home)));
    lines.push("  </dict>".to_owned());
    lines.push("</dict>".to_owned());
    lines.push("</plist>".to_owned());
    lines.push(String::new());
    lines.join("\n")
}

/// Render and validate one per-user agent without touching the host.
///
/// # Errors
/// [ErrorCode::Forbidden] when the request is system-scoped or asks to elevate;
/// [ErrorCode::ValidationError] for an unknown component, a relative path, a
/// log file outside the install root, a plist path outside the user's agent
/// directory, an argument with a NUL byte, or an out-of-range restart policy.
pub fn plan_agent(request: &MacosServiceRequest) -> Result<LaunchAgent, AxiomError> {
    if request.scope != InstallScope::PerUser || request.request_elevation {
        return Err(refuse(
            ErrorCode::Forbidden,
            if request.request_elevation {
                REASON_ELEVATION_REQUESTED
            } else {
                REASON_UNSUPPORTED_SCOPE
            },
            request.scope.as_str(),
            "a per-user agent cannot be system-scoped or elevated",
        ));
    }
    let label = agent_label(&request.component)?;
    for path in [
        &request.executable,
        &request.working_directory,
        &request.install_root,
        &request.home,
        &request.log_file,
    ] {
        if !is_absolute_host_path(path) {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_UNSAFE_PATH,
                path,
                "the path must be absolute for this host",
            ));
        }
    }
    if !is_under(&request.install_root, &request.log_file) {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_LOG_OUTSIDE_ROOT,
            &request.log_file,
            "the log file must live under the install root",
        ));
    }
    let plist_path = under(
        &request.home,
        &[USER_AGENT_DIR, &format!("{label}{PLIST_SUFFIX}")],
    );
    if !is_under(&request.home, &plist_path) {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_AGENT_OUTSIDE_HOME,
            &plist_path,
            "the agent must live under the user's own LaunchAgents directory",
        ));
    }
    for argument in &request.args {
        if argument.contains('\0') {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_UNSAFE_ARGUMENT,
                "nul-byte",
                "an argument must not contain a NUL byte",
            ));
        }
    }
    if !request.restart.is_valid() {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_RESTART_POLICY,
            &format!("{:?}", request.restart),
            "the restart policy is out of range",
        ));
    }
    let axiom_home = std::path::Path::new(&request.install_root)
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or_else(|| {
            refuse(
                ErrorCode::ValidationError,
                REASON_UNSAFE_PATH,
                &request.install_root,
                "install root cannot derive AXIOM_HOME",
            )
        })?
        .to_string_lossy()
        .into_owned();
    let plist = render_plist(&label, request, &axiom_home);
    Ok(LaunchAgent {
        component: request.component.clone(),
        label,
        mechanism: MECHANISM,
        scope: InstallScope::PerUser,
        trigger: request.trigger,
        restart: request.restart,
        executable: request.executable.clone(),
        args: request.args.clone(),
        working_directory: request.working_directory.clone(),
        log_file: request.log_file.clone(),
        plist_path,
        plist,
    })
}

/// Plan a removal that can only touch this adapter's own agent.
///
/// A foreign label, a relative path, or a plist outside the user's own
/// `LaunchAgents` directory is refused, so an invalid configuration fails
/// without producing any operation that could unload or delete an unrelated
/// agent.
///
/// # Errors
/// [ErrorCode::ValidationError] when the label is not owned, or when the home
/// or plist path is not an absolute path inside the user's agent directory.
pub fn plan_removal(label: &str, plist_path: &str, home: &str) -> Result<AgentRemoval, AxiomError> {
    owned_label(label)?;
    if !is_absolute_host_path(home) || !is_absolute_host_path(plist_path) {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_UNSAFE_PATH,
            plist_path,
            "the home and plist paths must be absolute for this host",
        ));
    }
    let agent_dir = under(home, &[USER_AGENT_DIR]);
    if !is_under(&agent_dir, plist_path) {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_AGENT_OUTSIDE_HOME,
            plist_path,
            "the plist is not under the user's own LaunchAgents directory",
        ));
    }
    Ok(AgentRemoval {
        label: label.to_owned(),
        plist_path: plist_path.to_owned(),
        operations: vec![ServiceOperation {
            description: "unload".to_owned(),
            program: LAUNCHCTL_PROGRAM.to_owned(),
            args: vec!["unload".to_owned(), "-w".to_owned(), plist_path.to_owned()],
        }],
        files: vec![plist_path.to_owned()],
    })
}

/// The operation that starts one owned agent.
///
/// # Errors
/// [ErrorCode::ValidationError] when the label is not owned by axiom.
pub fn start_operation(label: &str) -> Result<ServiceOperation, AxiomError> {
    owned_label(label)?;
    Ok(ServiceOperation {
        description: "start".to_owned(),
        program: LAUNCHCTL_PROGRAM.to_owned(),
        args: vec!["start".to_owned(), label.to_owned()],
    })
}

/// The operation that stops one owned agent.
///
/// # Errors
/// [ErrorCode::ValidationError] when the label is not owned by axiom.
pub fn stop_operation(label: &str) -> Result<ServiceOperation, AxiomError> {
    owned_label(label)?;
    Ok(ServiceOperation {
        description: "stop".to_owned(),
        program: LAUNCHCTL_PROGRAM.to_owned(),
        args: vec!["stop".to_owned(), label.to_owned()],
    })
}

/// The operation that reports one owned agent's status.
///
/// # Errors
/// [ErrorCode::ValidationError] when the label is not owned by axiom.
pub fn status_operation(label: &str) -> Result<ServiceOperation, AxiomError> {
    owned_label(label)?;
    Ok(ServiceOperation {
        description: "status".to_owned(),
        program: LAUNCHCTL_PROGRAM.to_owned(),
        args: vec!["list".to_owned(), label.to_owned()],
    })
}

/// Register one per-user agent through the executor.
///
/// # Errors
/// Whatever [`plan_agent`] refuses; [ErrorCode::Internal] when `launchctl`
/// exits non-zero.
pub fn install_agent(
    request: &MacosServiceRequest,
    _consent: Consent,
    exec: &impl ServiceExec,
) -> Result<InstalledService, AxiomError> {
    let agent = plan_agent(request)?;
    let output = exec.run(&agent.load_operation())?;
    if output.code != 0 {
        return Err(refuse(
            ErrorCode::Internal,
            REASON_CONTROLLER_EXIT,
            &output.code.to_string(),
            &format!("launchctl refused the load: {}", output.stderr.trim()),
        ));
    }
    Ok(InstalledService {
        component: agent.component,
        task_name: agent.label,
        mechanism: MECHANISM,
        scope: InstallScope::PerUser,
        definition_path: agent.plist_path,
        log_file: agent.log_file,
        restart: agent.restart,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{ServiceOutput, MAX_RESTART_ATTEMPTS, MAX_RESTART_DELAY_SECONDS};
    use std::cell::RefCell;

    const ROOT: &str = "/Users/billy/Axiom";
    const EXE: &str = "/Users/billy/Axiom/versions/1.0.0/axiom-graphd";
    const WORKDIR: &str = "/Users/billy/Axiom/versions/1.0.0";
    const HOME: &str = "/Users/billy";

    fn sample() -> MacosServiceRequest {
        MacosServiceRequest::new("axiom-graphd", EXE, WORKDIR, ROOT, HOME)
    }

    struct RecordingExec {
        operations: RefCell<Vec<ServiceOperation>>,
        result: ServiceOutput,
    }

    impl RecordingExec {
        fn succeeding() -> Self {
            Self {
                operations: RefCell::new(Vec::new()),
                result: ServiceOutput {
                    code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                },
            }
        }

        fn failing(code: i32) -> Self {
            Self {
                operations: RefCell::new(Vec::new()),
                result: ServiceOutput {
                    code,
                    stdout: String::new(),
                    stderr: "Could not find specified service".to_owned(),
                },
            }
        }
    }

    impl ServiceExec for RecordingExec {
        fn run(&self, operation: &ServiceOperation) -> Result<ServiceOutput, AxiomError> {
            self.operations.borrow_mut().push(operation.clone());
            Ok(self.result.clone())
        }
    }

    fn rule(error: &AxiomError) -> String {
        error
            .details()
            .get("rule")
            .cloned()
            .unwrap_or_else(|| "<none>".to_owned())
    }

    #[test]
    fn a_per_user_agent_is_rendered_under_the_user_agent_directory() {
        let agent = plan_agent(&sample()).expect("a per-user agent is accepted");
        assert_eq!(agent.mechanism, ServiceKind::LaunchAgent);
        assert_eq!(agent.scope, InstallScope::PerUser);
        assert_eq!(agent.label, "com.axiom.axiom-graphd");
        assert_eq!(
            agent.plist_path,
            "/Users/billy/Library/LaunchAgents/com.axiom.axiom-graphd.plist"
        );
        assert!(is_under(HOME, &agent.plist_path));
        assert!(agent.plist.contains("<key>Label</key>"));
        assert!(agent
            .plist
            .contains("<string>com.axiom.axiom-graphd</string>"));
        assert!(agent.plist.contains("<key>ProgramArguments</key>"));
        assert!(agent.plist.contains("<string>serve</string>"));
        assert!(agent.plist.contains("<key>WorkingDirectory</key>"));
        assert!(agent.plist.contains("<key>RunAtLoad</key>"));
        assert!(agent.plist.contains("<true/>"));
        assert!(agent.plist.contains("  <key>KeepAlive</key>\n  <false/>"));
        assert!(agent
            .plist
            .contains("<string>/Users/billy/Axiom/logs/axiom-graphd.log</string>"));
        assert!(agent.plist.contains("<key>AXIOM_INSTALL_ROOT</key>"));
    }

    #[test]
    fn an_on_failure_policy_is_rendered_as_a_bounded_keep_alive() {
        let agent = plan_agent(&sample().with_restart(RestartPolicy::on_failure(60, 3)))
            .expect("a per-user agent is accepted");
        assert!(agent.plist.contains("  <key>KeepAlive</key>\n  <dict>"));
        assert!(agent.plist.contains("<key>SuccessfulExit</key>"));
        assert!(agent
            .plist
            .contains("  <key>ThrottleInterval</key>\n  <integer>60</integer>"));
    }

    #[test]
    fn an_install_loads_the_agent_and_reports_it() {
        let exec = RecordingExec::succeeding();
        let installed = install_agent(&sample(), Consent::explicit(), &exec)
            .expect("a per-user agent is accepted");
        assert_eq!(installed.task_name, "com.axiom.axiom-graphd");
        assert_eq!(installed.mechanism, ServiceKind::LaunchAgent);
        assert_eq!(installed.scope, InstallScope::PerUser);
        assert!(installed.definition_path.contains(USER_AGENT_DIR));
        let recorded = exec.operations.borrow();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].program, LAUNCHCTL_PROGRAM);
        assert_eq!(
            recorded[0].args,
            vec![
                "load",
                "-w",
                "/Users/billy/Library/LaunchAgents/com.axiom.axiom-graphd.plist"
            ]
        );
    }

    #[test]
    fn explicit_user_domain_operations_never_use_legacy_load_or_unload() {
        let agent = plan_agent(&sample()).expect("a per-user agent is accepted");
        let identity = LaunchdIdentity::new(501).expect("a non-root user is accepted");
        assert_eq!(
            bootstrap_operation(&agent, identity).args,
            vec!["bootstrap", "gui/501", agent.plist_path.as_str()]
        );
        assert_eq!(
            bootout_operation(&agent.label, &agent.plist_path, HOME, identity)
                .expect("owned plist is removable")
                .args,
            vec!["bootout", "gui/501", agent.plist_path.as_str()]
        );
        assert_eq!(
            status_operation_for_user(&agent.label, identity)
                .expect("owned label is accepted")
                .args,
            vec!["print", "gui/501/com.axiom.axiom-graphd"]
        );
        assert_eq!(
            rule(&LaunchdIdentity::new(0).expect_err("root must be refused")),
            REASON_UNSAFE_USER_ID
        );
    }

    #[test]
    fn the_agent_is_serialisable_and_carries_its_label() {
        let agent = plan_agent(&sample()).expect("a per-user agent is accepted");
        let json = agent.to_json().expect("the agent serialises");
        assert!(json.contains("\"label\": \"com.axiom.axiom-graphd\""));
    }

    #[test]
    fn modern_start_and_stop_are_bound_to_one_gui_user_domain() {
        let identity = LaunchdIdentity::new(501).unwrap();
        let label = agent_label("axiom-graphd").unwrap();
        let start = kickstart_operation(&label, identity).unwrap();
        let stop = kill_operation(&label, identity).unwrap();
        let bootout = bootout_target_operation(&label, identity).unwrap();
        assert_eq!(
            start.args,
            vec!["kickstart", "-k", "gui/501/com.axiom.axiom-graphd"]
        );
        assert_eq!(
            stop.args,
            vec!["kill", "SIGTERM", "gui/501/com.axiom.axiom-graphd"]
        );
        assert_eq!(
            bootout.args,
            vec!["bootout", "gui/501/com.axiom.axiom-graphd"]
        );
    }

    #[test]
    fn a_removal_targets_only_the_owned_plist() {
        let removal = plan_removal(
            "com.axiom.axiom-graphd",
            "/Users/billy/Library/LaunchAgents/com.axiom.axiom-graphd.plist",
            HOME,
        )
        .expect("the owned agent is removable");
        assert_eq!(removal.files, vec![removal.plist_path.clone()]);
        assert_eq!(removal.operations.len(), 1);
        assert_eq!(
            removal.operations[0].args,
            vec![
                "unload",
                "-w",
                "/Users/billy/Library/LaunchAgents/com.axiom.axiom-graphd.plist"
            ]
        );
    }

    #[test]
    fn a_system_scoped_request_is_refused() {
        let mut request = sample();
        request.scope = InstallScope::System;
        let error = plan_agent(&request).expect_err("a system scope is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule(&error), REASON_UNSUPPORTED_SCOPE);
    }

    #[test]
    fn an_elevation_request_is_refused() {
        let mut request = sample();
        request.request_elevation = true;
        let error = plan_agent(&request).expect_err("an elevation request is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule(&error), REASON_ELEVATION_REQUESTED);
    }

    #[test]
    fn an_unknown_component_or_unsafe_path_is_refused() {
        let request = MacosServiceRequest::new("axiom-other", EXE, WORKDIR, ROOT, HOME);
        assert_eq!(
            rule(&plan_agent(&request).unwrap_err()),
            REASON_UNKNOWN_COMPONENT
        );

        let mut request = sample();
        request.executable = "axiom-graphd".to_owned();
        assert_eq!(rule(&plan_agent(&request).unwrap_err()), REASON_UNSAFE_PATH);

        let mut request = sample();
        request.home = "Users/billy".to_owned();
        assert_eq!(rule(&plan_agent(&request).unwrap_err()), REASON_UNSAFE_PATH);
    }

    #[test]
    fn a_log_file_outside_the_install_root_is_refused() {
        let request = sample().with_log_file("/var/log/axiom-graphd.log");
        let error = plan_agent(&request).expect_err("a foreign log path is refused");
        assert_eq!(rule(&error), REASON_LOG_OUTSIDE_ROOT);
    }

    #[test]
    fn an_argument_with_a_nul_byte_is_refused() {
        let request = sample().with_args(vec!["serve\0--evil".to_owned()]);
        assert_eq!(
            rule(&plan_agent(&request).unwrap_err()),
            REASON_UNSAFE_ARGUMENT
        );
    }

    #[test]
    fn an_out_of_range_restart_policy_is_refused() {
        for policy in [
            RestartPolicy::on_failure(0, 3),
            RestartPolicy::on_failure(60, 0),
            RestartPolicy::on_failure(60, MAX_RESTART_ATTEMPTS + 1),
            RestartPolicy::on_failure(MAX_RESTART_DELAY_SECONDS + 1, 3),
        ] {
            let error = plan_agent(&sample().with_restart(policy))
                .expect_err("an out-of-range policy is refused");
            assert_eq!(rule(&error), REASON_RESTART_POLICY);
        }
    }

    #[test]
    fn a_foreign_agent_is_refused_by_control_operations() {
        for label in [
            "org.other.agent",
            "com.axiom.evil",
            "com.axiom.",
            "com.axiom.Axiom-Graphd",
            "com.axiom.axiom-graphd.evil",
        ] {
            let error = stop_operation(label).expect_err("a foreign label is refused");
            assert_eq!(error.code(), ErrorCode::ValidationError);
            assert_eq!(rule(&error), REASON_FOREIGN_AGENT);
        }
        assert_eq!(
            stop_operation("com.axiom.axiom-graphd").unwrap().args,
            vec!["stop", "com.axiom.axiom-graphd"]
        );
        assert_eq!(
            status_operation("com.axiom.axiom-mcp").unwrap().args,
            vec!["list", "com.axiom.axiom-mcp"]
        );
        assert_eq!(
            start_operation("com.axiom.axiom-mcp").unwrap().args,
            vec!["start", "com.axiom.axiom-mcp"]
        );
    }

    #[test]
    fn a_removal_refuses_a_foreign_label_and_a_plist_outside_the_agent_directory() {
        let error = plan_removal(
            "com.other.agent",
            "/Users/billy/Library/LaunchAgents/com.other.agent.plist",
            HOME,
        )
        .expect_err("a foreign label is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(rule(&error), REASON_FOREIGN_AGENT);

        for plist in [
            "/Users/billy/Downloads/com.axiom.axiom-graphd.plist",
            "/Users/other/Library/LaunchAgents/com.axiom.axiom-graphd.plist",
            "/Library/LaunchDaemons/com.axiom.axiom-graphd.plist",
            "Library/LaunchAgents/com.axiom.axiom-graphd.plist",
        ] {
            let error = plan_removal("com.axiom.axiom-graphd", plist, HOME)
                .expect_err("a plist outside the user agent directory is refused");
            assert_eq!(error.code(), ErrorCode::ValidationError);
            assert!(matches!(
                rule(&error).as_str(),
                "agent-outside-user-directory" | "unsafe-path"
            ));
        }
    }

    #[test]
    fn a_non_zero_controller_exit_is_refused() {
        let exec = RecordingExec::failing(1);
        let error = install_agent(&sample(), Consent::explicit(), &exec)
            .expect_err("a failed controller exit is an error");
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(rule(&error), REASON_CONTROLLER_EXIT);
    }
}
