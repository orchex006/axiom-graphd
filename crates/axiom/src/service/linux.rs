//! Linux per-user startup adapter: a systemd user unit (task E-009).
//!
//! `21-INSTALLATION.md` section E pins the Linux mechanism as a *systemd user
//! unit* and states the fallback rule plainly: where the managed mechanism is
//! not available, the installer uses the foreground and does not change a
//! machine-wide policy. A systemd user unit needs a user session bus, which a
//! headless or container host does not have, so this adapter detects user
//! systemd *before* it plans anything and refuses to install when it is absent,
//! naming the documented foreground command to use instead.
//!
//! ## What this module guarantees (AC1)
//!
//! * [`detect_user_systemd`] is the only availability check and it is pure over
//!   an injected [`SystemdProbe`], so a host with no session bus is a test case
//!   rather than an environment.
//! * [`install_unit`] refuses with `NotReady` when user systemd is unavailable
//!   and carries [`FOREGROUND_FALLBACK`] as the documented manual path, so the
//!   installer never claims a managed service it did not create.
//! * The unit, like every managed definition here, is per-user: a system-scoped
//!   or elevated request is refused `Forbidden` before anything is rendered, and
//!   the unit path is required to live under the user's own systemd directory.
//!
//! ## Why execution is a trait
//!
//! The same [`ServiceExec`] boundary the Windows adapter uses drives
//! `systemctl --user`, so no test spawns a process and the rendered command is
//! program plus argv, never a shell string.

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{is_absolute_host_path, validate_portable_relative_path};
use serde::{Deserialize, Serialize};

use crate::discovery::{ServiceKind, INSTALLABLE_COMPONENTS};
use crate::install::plan::{under, InstallScope};
use crate::service::{
    is_under, Consent, InstalledService, RestartPolicy, ServiceExec, ServiceOperation,
    StartupTrigger, REASON_RESTART_POLICY, SERVICE_DIRECTORY, SERVICE_LOG_DIRECTORY,
};

/// The mechanism this adapter implements, in the shared service vocabulary.
pub const MECHANISM: ServiceKind = ServiceKind::SystemdUserUnit;

/// Host identifier this adapter serves.
pub const HOST: &str = "linux-x64";

/// The controller the adapter drives, by name only.
pub const SYSTEMCTL_PROGRAM: &str = "systemctl";

/// Suffix of a user unit file.
pub const UNIT_SUFFIX: &str = ".service";

/// User unit directory, relative to the user's home.
pub const USER_UNIT_DIR: &str = ".config/systemd/user";

/// The documented manual path when user systemd is unavailable.
pub const FOREGROUND_FALLBACK: &str = "axiom-graphd serve --registry <registry.json>";

/// Reason recorded when a request is not per-user.
pub const REASON_UNSUPPORTED_SCOPE: &str = "unsupported-scope";

/// Reason recorded when a request asks the adapter to elevate.
pub const REASON_ELEVATION_REQUESTED: &str = "elevation-requested";

/// Reason recorded when a component is not one the CLI installs.
pub const REASON_UNKNOWN_COMPONENT: &str = "unknown-component";

/// Reason recorded when a required host path is not absolute.
pub const REASON_UNSAFE_PATH: &str = "unsafe-path";

/// Reason recorded when a unit is not inside the user's own systemd directory.
pub const REASON_UNIT_OUTSIDE_HOME: &str = "unit-outside-user-directory";

/// Reason recorded when a program argument is not a safe argument.
pub const REASON_UNSAFE_ARGUMENT: &str = "unsafe-argument";

/// Reason recorded when a log file is not inside the install root's log tree.
pub const REASON_LOG_OUTSIDE_ROOT: &str = "log-outside-install-root";

/// Reason recorded when a unit name is not one this adapter owns.
pub const REASON_FOREIGN_UNIT: &str = "foreign-unit";

/// Reason recorded when user systemd is not available on this host.
pub const REASON_SYSTEMD_UNAVAILABLE: &str = "systemd-unavailable";

/// Reason recorded when `systemctl` exits non-zero.
pub const REASON_CONTROLLER_EXIT: &str = "controller-exit";

/// Whether this host has a usable user systemd.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSystemd {
    /// True when a managed user unit can be installed and controlled here.
    pub available: bool,
    /// Why it is unavailable, when it is.
    pub reason: Option<String>,
}

impl UserSystemd {
    /// A host with a usable user systemd.
    #[must_use]
    pub fn available() -> Self {
        Self {
            available: true,
            reason: None,
        }
    }

    /// A host without a usable user systemd, and why.
    #[must_use]
    pub fn unavailable(reason: &str) -> Self {
        Self {
            available: false,
            reason: Some(reason.to_owned()),
        }
    }

    /// The reason it is unavailable, or `None` when it is available.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Stable wire spelling of the availability state.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        if self.available {
            "available"
        } else {
            "unavailable"
        }
    }
}

/// Everything [`detect_user_systemd`] inspects, injected so detection is pure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdProbe {
    /// `XDG_RUNTIME_DIR`, when the session sets it.
    pub xdg_runtime_dir: Option<String>,
    /// Whether `XDG_RUNTIME_DIR` actually exists on this host.
    pub runtime_dir_exists: bool,
    /// Whether a `systemctl` supporting `--user` was found on `PATH`.
    pub systemctl_user_available: bool,
}

/// Decide whether a managed user unit can be installed on this host.
///
/// The rules are the ones that actually distinguish a systemd user session from
/// a headless process: the `systemctl` binary must support `--user`, the
/// session must publish an absolute `XDG_RUNTIME_DIR`, and that directory must
/// exist (it holds the user bus socket).
#[must_use]
pub fn detect_user_systemd(probe: &SystemdProbe) -> UserSystemd {
    if !probe.systemctl_user_available {
        return UserSystemd::unavailable("no-systemctl-user-binary");
    }
    let Some(runtime_dir) = probe.xdg_runtime_dir.as_deref() else {
        return UserSystemd::unavailable("no-xdg-runtime-dir");
    };
    if runtime_dir.is_empty() {
        return UserSystemd::unavailable("empty-xdg-runtime-dir");
    }
    if !is_absolute_host_path(runtime_dir) {
        return UserSystemd::unavailable("relative-xdg-runtime-dir");
    }
    if !probe.runtime_dir_exists {
        return UserSystemd::unavailable("no-user-session-bus");
    }
    UserSystemd::available()
}

/// What one registration needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxServiceRequest {
    /// Component from [`INSTALLABLE_COMPONENTS`] this unit starts.
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

impl LinuxServiceRequest {
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

/// A fully rendered, reviewable per-user unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdUnit {
    /// Component the unit starts.
    pub component: String,
    /// Unit name, `axiom-<component>.service`.
    pub unit_name: String,
    /// The mechanism, always [`MECHANISM`].
    pub mechanism: ServiceKind,
    /// The scope, always per-user.
    pub scope: InstallScope,
    /// When the unit starts.
    pub trigger: StartupTrigger,
    /// Restart policy the unit declares.
    pub restart: RestartPolicy,
    /// Absolute host path of the executable.
    pub executable: String,
    /// Arguments passed as argv.
    pub args: Vec<String>,
    /// Absolute host working directory.
    pub working_directory: String,
    /// Absolute host log file.
    pub log_file: String,
    /// Absolute host path of the rendered unit file.
    pub unit_path: String,
    /// The rendered unit file.
    pub text: String,
}

impl SystemdUnit {
    /// Machine-readable rendering of the unit.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the unit cannot be serialised.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        serde_json::to_string_pretty(self).map_err(|error| {
            AxiomError::new(ErrorCode::Internal, "the unit is not serialisable")
                .with_detail("observed", error.to_string())
        })
    }

    /// The operation that reloads the user manager after writing the unit.
    #[must_use]
    pub fn reload_operation(&self) -> ServiceOperation {
        ServiceOperation {
            description: "reload".to_owned(),
            program: SYSTEMCTL_PROGRAM.to_owned(),
            args: vec!["--user".to_owned(), "daemon-reload".to_owned()],
        }
    }

    /// The operation that enables and starts the unit.
    pub fn enable_operation(&self) -> Result<ServiceOperation, AxiomError> {
        enable_operation(&self.unit_name)
    }
}

/// A refusal that changes nothing on the host.
fn refuse(code: ErrorCode, rule: &str, observed: &str, message: &str) -> AxiomError {
    AxiomError::new(code, message)
        .with_detail("rule", rule)
        .with_detail("observed", observed)
}

/// The unit name owned by one component.
///
/// # Errors
/// [ErrorCode::ValidationError] when the component is not installable or its
/// name is not a safe segment.
pub fn unit_name(component: &str) -> Result<String, AxiomError> {
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
    Ok(format!("{component}{UNIT_SUFFIX}"))
}

/// Render one argument using the systemd quoting rule: quote an argument that
/// is empty or contains whitespace, escaping `\` and `"` with a backslash.
fn quote_argument(argument: &str) -> String {
    if argument.is_empty() {
        return "\"\"".to_owned();
    }
    if argument.contains(char::is_whitespace) || argument.contains('"') {
        let mut escaped = String::with_capacity(argument.len());
        for ch in argument.chars() {
            if ch == '"' || ch == '\\' {
                escaped.push('\\');
            }
            escaped.push(ch);
        }
        return format!("\"{escaped}\"");
    }
    argument.to_owned()
}

/// The `ExecStart=` command line for one unit.
fn exec_start(args: &[String]) -> String {
    args.iter()
        .map(|argument| quote_argument(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Render the unit file for one per-user definition.
fn render_unit(
    component: &str,
    executable: &str,
    args: &[String],
    working_directory: &str,
    log_file: &str,
    install_root: &str,
    restart: RestartPolicy,
) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push("[Unit]".to_owned());
    lines.push(format!(
        "Description=Axiom managed process for {component} (per-user)"
    ));
    lines.push("PartOf=default.target".to_owned());
    lines.push(String::new());
    lines.push("[Service]".to_owned());
    lines.push("Type=simple".to_owned());
    lines.push(format!("ExecStart={executable} {}", exec_start(args)));
    lines.push(format!("WorkingDirectory={working_directory}"));
    if restart.on_failure {
        lines.push("Restart=on-failure".to_owned());
        lines.push(format!("RestartSec={}s", restart.delay_seconds));
        lines.push(format!(
            "StartLimitIntervalSec={}s",
            restart.delay_seconds.saturating_mul(restart.max_attempts)
        ));
        lines.push(format!("StartLimitBurst={}", restart.max_attempts));
    } else {
        lines.push("Restart=no".to_owned());
    }
    lines.push(format!("StandardOutput=append:{log_file}"));
    lines.push(format!("StandardError=append:{log_file}"));
    lines.push(format!("Environment=AXIOM_INSTALL_ROOT={install_root}"));
    lines.push(String::new());
    lines.push("[Install]".to_owned());
    lines.push("WantedBy=default.target".to_owned());
    lines.push(String::new());
    lines.join("\n")
}

/// Render and validate one per-user unit without touching the host.
///
/// # Errors
/// [ErrorCode::Forbidden] when the request is system-scoped or asks to elevate;
/// [ErrorCode::ValidationError] for an unknown component, a relative path, a
/// log file outside the install root, a unit path outside the user's home, an
/// argument with a NUL byte, or an out-of-range restart policy.
pub fn plan_unit(request: &LinuxServiceRequest) -> Result<SystemdUnit, AxiomError> {
    if request.scope != InstallScope::PerUser || request.request_elevation {
        return Err(refuse(
            ErrorCode::Forbidden,
            if request.request_elevation {
                REASON_ELEVATION_REQUESTED
            } else {
                REASON_UNSUPPORTED_SCOPE
            },
            request.scope.as_str(),
            "a per-user unit cannot be system-scoped or elevated",
        ));
    }
    let unit_name = unit_name(&request.component)?;
    for (rule, path) in [
        (REASON_UNSAFE_PATH, &request.executable),
        (REASON_UNSAFE_PATH, &request.working_directory),
        (REASON_UNSAFE_PATH, &request.install_root),
        (REASON_UNSAFE_PATH, &request.home),
        (REASON_UNSAFE_PATH, &request.log_file),
    ] {
        if !is_absolute_host_path(path) {
            return Err(refuse(
                ErrorCode::ValidationError,
                rule,
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
    let unit_path = under(&request.home, &[USER_UNIT_DIR, unit_name.as_str()]);
    if !is_under(&request.home, &unit_path) {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_UNIT_OUTSIDE_HOME,
            &unit_path,
            "the unit must live under the user's own systemd directory",
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
    let text = render_unit(
        &request.component,
        &request.executable,
        &request.args,
        &request.working_directory,
        &request.log_file,
        &request.install_root,
        request.restart,
    );
    Ok(SystemdUnit {
        component: request.component.clone(),
        unit_name,
        mechanism: MECHANISM,
        scope: InstallScope::PerUser,
        trigger: request.trigger,
        restart: request.restart,
        executable: request.executable.clone(),
        args: request.args.clone(),
        working_directory: request.working_directory.clone(),
        log_file: request.log_file.clone(),
        unit_path,
        text,
    })
}

/// Check that a unit name is one this adapter owns.
fn owned_unit(unit_name: &str) -> Result<(), AxiomError> {
    let Some(component) = unit_name.strip_suffix(UNIT_SUFFIX) else {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_FOREIGN_UNIT,
            unit_name,
            "the unit is not owned by axiom",
        ));
    };
    if INSTALLABLE_COMPONENTS.contains(&component)
        && validate_portable_relative_path(component).is_ok()
    {
        Ok(())
    } else {
        Err(refuse(
            ErrorCode::ValidationError,
            REASON_FOREIGN_UNIT,
            unit_name,
            "the unit is not owned by axiom",
        ))
    }
}

/// The operation that enables and starts one owned unit.
///
/// # Errors
/// [ErrorCode::ValidationError] when the unit is not owned by axiom.
pub fn enable_operation(unit_name: &str) -> Result<ServiceOperation, AxiomError> {
    owned_unit(unit_name)?;
    Ok(ServiceOperation {
        description: "enable".to_owned(),
        program: SYSTEMCTL_PROGRAM.to_owned(),
        args: vec![
            "--user".to_owned(),
            "enable".to_owned(),
            "--now".to_owned(),
            unit_name.to_owned(),
        ],
    })
}

/// The operation that starts one owned unit.
///
/// # Errors
/// [ErrorCode::ValidationError] when the unit is not owned by axiom.
pub fn start_operation(unit_name: &str) -> Result<ServiceOperation, AxiomError> {
    owned_unit(unit_name)?;
    Ok(ServiceOperation {
        description: "start".to_owned(),
        program: SYSTEMCTL_PROGRAM.to_owned(),
        args: vec![
            "--user".to_owned(),
            "start".to_owned(),
            unit_name.to_owned(),
        ],
    })
}

/// The operation that stops one owned unit.
///
/// # Errors
/// [ErrorCode::ValidationError] when the unit is not owned by axiom.
pub fn stop_operation(unit_name: &str) -> Result<ServiceOperation, AxiomError> {
    owned_unit(unit_name)?;
    Ok(ServiceOperation {
        description: "stop".to_owned(),
        program: SYSTEMCTL_PROGRAM.to_owned(),
        args: vec!["--user".to_owned(), "stop".to_owned(), unit_name.to_owned()],
    })
}

/// The operation that reports one owned unit's status.
///
/// # Errors
/// [ErrorCode::ValidationError] when the unit is not owned by axiom.
pub fn status_operation(unit_name: &str) -> Result<ServiceOperation, AxiomError> {
    owned_unit(unit_name)?;
    Ok(ServiceOperation {
        description: "status".to_owned(),
        program: SYSTEMCTL_PROGRAM.to_owned(),
        args: vec![
            "--user".to_owned(),
            "status".to_owned(),
            "--no-pager".to_owned(),
            unit_name.to_owned(),
        ],
    })
}

/// The operation that disables and stops one owned unit before removal.
///
/// # Errors
/// [ErrorCode::ValidationError] when the unit is not owned by axiom.
pub fn uninstall_operation(unit_name: &str) -> Result<ServiceOperation, AxiomError> {
    owned_unit(unit_name)?;
    Ok(ServiceOperation {
        description: "uninstall".to_owned(),
        program: SYSTEMCTL_PROGRAM.to_owned(),
        args: vec![
            "--user".to_owned(),
            "disable".to_owned(),
            "--now".to_owned(),
            unit_name.to_owned(),
        ],
    })
}

/// Detect user systemd and register one per-user unit through the executor.
///
/// # Errors
/// [ErrorCode::NotReady] when user systemd is unavailable, carrying
/// [`FOREGROUND_FALLBACK`]; whatever [`plan_unit`] refuses; [ErrorCode::Internal]
/// when the controller exits non-zero.
pub fn install_unit(
    request: &LinuxServiceRequest,
    _consent: Consent,
    probe: &SystemdProbe,
    exec: &impl ServiceExec,
) -> Result<InstalledService, AxiomError> {
    let systemd = detect_user_systemd(probe);
    if !systemd.available {
        return Err(AxiomError::new(
            ErrorCode::NotReady,
            format!("user systemd is not available on this host; use the foreground: {FOREGROUND_FALLBACK}"),
        )
        .with_detail("rule", REASON_SYSTEMD_UNAVAILABLE)
        .with_detail("observed", systemd.reason().unwrap_or("unknown"))
        .with_detail("expected", FOREGROUND_FALLBACK));
    }
    let unit = plan_unit(request)?;
    for operation in [unit.reload_operation(), unit.enable_operation()?] {
        let output = exec.run(&operation)?;
        if output.code != 0 {
            return Err(refuse(
                ErrorCode::Internal,
                REASON_CONTROLLER_EXIT,
                &output.code.to_string(),
                &format!(
                    "the user manager refused {}: {}",
                    operation.description,
                    output.stderr.trim()
                ),
            ));
        }
    }
    Ok(InstalledService {
        component: unit.component,
        task_name: unit.unit_name,
        mechanism: MECHANISM,
        scope: InstallScope::PerUser,
        definition_path: unit.unit_path,
        log_file: unit.log_file,
        restart: unit.restart,
    })
}

/// The install root a service definition directory lives under, for discovery.
#[must_use]
pub fn definition_directory(install_root: &str) -> String {
    under(install_root, &[SERVICE_DIRECTORY])
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{ServiceOutput, MAX_RESTART_ATTEMPTS, MAX_RESTART_DELAY_SECONDS};
    use std::cell::RefCell;

    const ROOT: &str = "/opt/axiom";
    const EXE: &str = "/opt/axiom/versions/1.0.0/axiom-graphd";
    const WORKDIR: &str = "/opt/axiom/versions/1.0.0";
    const HOME: &str = "/home/billy";

    fn sample() -> LinuxServiceRequest {
        LinuxServiceRequest::new("axiom-graphd", EXE, WORKDIR, ROOT, HOME)
    }

    fn ready_probe() -> SystemdProbe {
        SystemdProbe {
            xdg_runtime_dir: Some("/run/user/1000".to_owned()),
            runtime_dir_exists: true,
            systemctl_user_available: true,
        }
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
                    stderr: "Failed to connect to bus".to_owned(),
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
    fn a_user_systemd_session_is_detected() {
        assert!(detect_user_systemd(&ready_probe()).available);
    }

    #[test]
    fn a_host_without_a_user_session_bus_is_unavailable() {
        let mut probe = ready_probe();
        probe.runtime_dir_exists = false;
        let systemd = detect_user_systemd(&probe);
        assert!(!systemd.available);
        assert_eq!(systemd.reason(), Some("no-user-session-bus"));
        assert_eq!(systemd.as_str(), "unavailable");
    }

    #[test]
    fn a_host_without_a_runtime_dir_or_systemctl_is_unavailable() {
        let mut probe = ready_probe();
        probe.xdg_runtime_dir = None;
        assert_eq!(
            detect_user_systemd(&probe).reason(),
            Some("no-xdg-runtime-dir")
        );

        let mut probe = ready_probe();
        probe.systemctl_user_available = false;
        assert_eq!(
            detect_user_systemd(&probe).reason(),
            Some("no-systemctl-user-binary")
        );

        let mut probe = ready_probe();
        probe.xdg_runtime_dir = Some("run/user/1000".to_owned());
        assert_eq!(
            detect_user_systemd(&probe).reason(),
            Some("relative-xdg-runtime-dir")
        );
    }

    #[test]
    fn an_install_refuses_when_user_systemd_is_absent_and_names_the_fallback() {
        let mut probe = ready_probe();
        probe.runtime_dir_exists = false;
        let error = install_unit(
            &sample(),
            Consent::explicit(),
            &probe,
            &RecordingExec::succeeding(),
        )
        .expect_err("no user systemd means no managed unit");
        assert_eq!(error.code(), ErrorCode::NotReady);
        assert_eq!(rule(&error), REASON_SYSTEMD_UNAVAILABLE);
        assert_eq!(
            error.details().get("expected").map(String::as_str),
            Some(FOREGROUND_FALLBACK)
        );
    }

    #[test]
    fn a_per_user_unit_is_rendered_under_the_user_systemd_directory() {
        let unit = plan_unit(&sample()).expect("a per-user unit is accepted");
        assert_eq!(unit.mechanism, ServiceKind::SystemdUserUnit);
        assert_eq!(unit.scope, InstallScope::PerUser);
        assert_eq!(unit.unit_name, "axiom-graphd.service");
        assert!(is_under(HOME, &unit.unit_path));
        assert!(unit.unit_path.contains(USER_UNIT_DIR));
        assert!(unit.text.contains("[Unit]"));
        assert!(unit.text.contains("WantedBy=default.target"));
        assert!(unit.text.contains("Restart=no"));
        assert!(unit
            .text
            .contains("StandardOutput=append:/opt/axiom/logs/axiom-graphd.log"));
    }

    #[test]
    fn an_on_failure_policy_is_rendered_as_a_bounded_restart() {
        let unit = plan_unit(&sample().with_restart(RestartPolicy::on_failure(60, 3)))
            .expect("a per-user unit is accepted");
        assert!(unit.text.contains("Restart=on-failure"));
        assert!(unit.text.contains("RestartSec=60s"));
        assert!(unit.text.contains("StartLimitBurst=3"));
    }

    #[test]
    fn an_install_registers_the_unit_and_reports_it() {
        let exec = RecordingExec::succeeding();
        let installed = install_unit(&sample(), Consent::explicit(), &ready_probe(), &exec)
            .expect("user systemd is available");
        assert_eq!(installed.task_name, "axiom-graphd.service");
        assert_eq!(installed.mechanism, ServiceKind::SystemdUserUnit);
        assert_eq!(installed.scope, InstallScope::PerUser);
        let recorded = exec.operations.borrow();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].args, vec!["--user", "daemon-reload"]);
        assert_eq!(
            recorded[1].args,
            vec!["--user", "enable", "--now", "axiom-graphd.service"]
        );
    }

    #[test]
    fn an_argument_with_a_space_is_quoted() {
        let unit = plan_unit(&sample().with_args(vec![
            "--registry".to_owned(),
            "/home/billy/Axiom Home/registry.json".to_owned(),
        ]))
        .expect("a per-user unit is accepted");
        assert!(unit
            .text
            .contains("--registry \"/home/billy/Axiom Home/registry.json\""));
    }

    #[test]
    fn a_system_scoped_request_is_refused() {
        let mut request = sample();
        request.scope = InstallScope::System;
        let error = plan_unit(&request).expect_err("a system scope is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule(&error), REASON_UNSUPPORTED_SCOPE);
    }

    #[test]
    fn an_elevation_request_is_refused() {
        let mut request = sample();
        request.request_elevation = true;
        let error = plan_unit(&request).expect_err("an elevation request is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule(&error), REASON_ELEVATION_REQUESTED);
    }

    #[test]
    fn an_unknown_component_or_unsafe_path_is_refused() {
        let request = LinuxServiceRequest::new("axiom-other", EXE, WORKDIR, ROOT, HOME);
        assert_eq!(
            rule(&plan_unit(&request).unwrap_err()),
            REASON_UNKNOWN_COMPONENT
        );

        let mut request = sample();
        request.executable = "axiom-graphd".to_owned();
        assert_eq!(rule(&plan_unit(&request).unwrap_err()), REASON_UNSAFE_PATH);
    }

    #[test]
    fn a_log_file_outside_the_install_root_is_refused() {
        let request = sample().with_log_file("/var/log/axiom-graphd.log");
        let error = plan_unit(&request).expect_err("a foreign log path is refused");
        assert_eq!(rule(&error), REASON_LOG_OUTSIDE_ROOT);
    }

    #[test]
    fn an_argument_with_a_nul_byte_is_refused() {
        let request = sample().with_args(vec!["serve\0--evil".to_owned()]);
        assert_eq!(
            rule(&plan_unit(&request).unwrap_err()),
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
            let error = plan_unit(&sample().with_restart(policy))
                .expect_err("an out-of-range policy is refused");
            assert_eq!(rule(&error), REASON_RESTART_POLICY);
        }
    }

    #[test]
    fn a_foreign_unit_is_refused_by_control_operations() {
        for name in ["nginx.service", "axiom-evil.service", "axiom-graphd"] {
            let error = stop_operation(name).expect_err("a foreign unit is refused");
            assert_eq!(error.code(), ErrorCode::ValidationError);
            assert_eq!(rule(&error), REASON_FOREIGN_UNIT);
        }
        assert_eq!(
            status_operation("axiom-mcp.service").unwrap().args,
            vec!["--user", "status", "--no-pager", "axiom-mcp.service"]
        );
    }

    #[test]
    fn a_non_zero_controller_exit_is_refused() {
        let exec = RecordingExec::failing(1);
        let error = install_unit(&sample(), Consent::explicit(), &ready_probe(), &exec)
            .expect_err("a failed controller exit is an error");
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(rule(&error), REASON_CONTROLLER_EXIT);
    }
}
