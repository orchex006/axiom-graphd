//! Windows per-user startup adapter: a Scheduled Task at logon (task E-008).
//!
//! `21-INSTALLATION.md` section E is the contract this module implements. The
//! managed choice on Windows is a *per-user startup mechanism* whose tested
//! default is a Scheduled Task registered for the current user (`design
//! choice`), registered at sign-in, with a log destination, a restart policy,
//! and a stop and uninstall path. It must not need administrator permission:
//! where elevation would be required the installer uses the foreground instead
//! and never edits a machine-wide execution policy.
//!
//! ## What makes "no silent machine-wide elevation" structural (AC1)
//!
//! The refusals are not warnings a caller can ignore:
//!
//! * [`WindowsServiceRequest::scope`] must be [`InstallScope::PerUser`]; a
//!   system-scoped request is refused with `Forbidden` before anything is
//!   rendered, so this adapter cannot register a machine-wide task.
//! * [`WindowsServiceRequest::request_elevation`] must be `false`; asking the
//!   adapter to elevate is refused for the same reason, so a front end cannot
//!   silently request a privileged registration.
//! * The rendered task principal is fixed at `InteractiveToken` /
//!   `LeastPrivilege`, and the trigger is a per-user logon trigger, so the task
//!   runs as the signed-in user and not as an administrator.
//! * Installing requires an explicit [`Consent`] token as its own argument, so
//!   a registration cannot happen as a side effect of building a request.
//!
//! ## Why execution is a trait
//!
//! [`ServiceExec`] is the whole process surface, so the tests exercise a
//! registration against an in-memory recorder and a policy that denies the
//! scheduler against a denying double. The rendered command is program plus
//! argv - never a shell string - so an argument can never be re-interpreted by
//! `cmd.exe`. The production [`SysExec`] is the only implementation that
//! spawns a process.

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{is_absolute_host_path, validate_portable_relative_path};
use serde::{Deserialize, Serialize};

use crate::discovery::{ServiceKind, INSTALLABLE_COMPONENTS};
use crate::install::plan::{under, InstallScope};
use crate::service::{
    is_under, Consent, InstalledService, RestartPolicy, ServiceExec, ServiceOperation,
    StartupTrigger, SERVICE_DIRECTORY, SERVICE_LOG_DIRECTORY,
};

/// The mechanism this adapter implements, in the shared service vocabulary.
pub const MECHANISM: ServiceKind = ServiceKind::PerUserStartup;

/// Host identifier this adapter serves.
pub const HOST: &str = "windows-x64";

/// The scheduler CLI the adapter drives, by name only.
pub const SCHEDULER_PROGRAM: &str = "schtasks.exe";

/// Prefix of every task name the adapter owns.
pub const TASK_NAME_PREFIX: &str = "Axiom\\";

/// Suffix of the rendered task definition beside the install root.
pub const TASK_FILE_SUFFIX: &str = ".task.xml";

/// `version` attribute of the Task Scheduler XML this build emits.
pub const TASK_XML_VERSION: &str = "1.2";

/// The scheduler task folder every task name is registered under.
pub const TASK_FOLDER: &str = "Axiom";

/// Reason recorded when a request is not per-user.
pub const REASON_UNSUPPORTED_SCOPE: &str = "unsupported-scope";

/// Reason recorded when a request asks the adapter to elevate.
pub const REASON_ELEVATION_REQUESTED: &str = "elevation-requested";

/// Reason recorded when a component is not one the CLI installs.
pub const REASON_UNKNOWN_COMPONENT: &str = "unknown-component";

/// Reason recorded when a required host path is not absolute.
pub const REASON_UNSAFE_PATH: &str = "unsafe-path";

/// Reason recorded when a program argument is not a safe command-line argument.
pub const REASON_UNSAFE_ARGUMENT: &str = "unsafe-argument";

/// Reason recorded when a log file is not inside the install root's log tree.
pub const REASON_LOG_OUTSIDE_ROOT: &str = "log-outside-install-root";

/// Reason recorded when a task name is not one this adapter owns.
pub const REASON_FOREIGN_TASK: &str = "foreign-task";

/// Reason recorded when the host scheduler exits non-zero.
pub const REASON_SCHEDULER_EXIT: &str = "scheduler-exit";

/// What one registration needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsServiceRequest {
    /// Component from [`INSTALLABLE_COMPONENTS`] this task starts.
    pub component: String,
    /// Absolute host path of the component executable.
    pub executable: String,
    /// Program arguments, passed as argv; never a shell string.
    pub args: Vec<String>,
    /// Absolute host working directory for the process.
    pub working_directory: String,
    /// Absolute host install root that owns the definition and logs.
    pub install_root: String,
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

impl WindowsServiceRequest {
    /// A per-user logon request for one component and executable.
    ///
    /// `install_root` fixes the definition and log destinations; the caller
    /// overrides the arguments and restart policy with the builders below.
    #[must_use]
    pub fn new(
        component: impl Into<String>,
        executable: impl Into<String>,
        working_directory: impl Into<String>,
        install_root: impl Into<String>,
    ) -> Self {
        let component = component.into();
        let install_root = install_root.into();
        let log_file = under(
            &install_root,
            &[SERVICE_LOG_DIRECTORY, &format!("{component}.log")],
        );
        let args = vec!["serve".to_owned()];
        Self {
            component,
            executable: executable.into(),
            args,
            working_directory: working_directory.into(),
            install_root,
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

/// A fully rendered, reviewable per-user task definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTaskDefinition {
    /// Component the task starts.
    pub component: String,
    /// Registered task name.
    pub task_name: String,
    /// The mechanism, always [`MECHANISM`].
    pub mechanism: ServiceKind,
    /// The scope, always per-user.
    pub scope: InstallScope,
    /// When the task starts.
    pub trigger: StartupTrigger,
    /// Restart policy the task declares.
    pub restart: RestartPolicy,
    /// Absolute host path of the executable the task runs.
    pub executable: String,
    /// Arguments passed as argv.
    pub args: Vec<String>,
    /// Absolute host working directory.
    pub working_directory: String,
    /// Absolute host log file the managed process writes to.
    pub log_file: String,
    /// Absolute host path the definition is written to.
    pub definition_path: String,
    /// The rendered Task Scheduler XML.
    pub xml: String,
}

impl WindowsTaskDefinition {
    /// Machine-readable rendering of the definition.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the definition cannot be serialised.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        serde_json::to_string_pretty(self).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the task definition is not serialisable",
            )
            .with_detail("observed", error.to_string())
        })
    }

    /// The operation that registers this definition with the scheduler.
    #[must_use]
    pub fn register_operation(&self) -> ServiceOperation {
        ServiceOperation {
            description: "register".to_owned(),
            program: SCHEDULER_PROGRAM.to_owned(),
            args: vec![
                "/create".to_owned(),
                "/tn".to_owned(),
                self.task_name.clone(),
                "/xml".to_owned(),
                self.definition_path.clone(),
                "/f".to_owned(),
            ],
        }
    }
}

/// A refusal that changes nothing on the host.
fn refuse(code: ErrorCode, rule: &str, observed: &str, message: &str) -> AxiomError {
    AxiomError::new(code, message)
        .with_detail("rule", rule)
        .with_detail("observed", observed)
}

/// The task name owned by one component.
///
/// # Errors
/// [ErrorCode::ValidationError] when the component is not installable or its
/// name is not a safe path segment.
pub fn task_name(component: &str) -> Result<String, AxiomError> {
    if !INSTALLABLE_COMPONENTS.contains(&component) {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_UNKNOWN_COMPONENT,
            component,
            "the component is not one the CLI installs",
        ));
    }
    validate_portable_relative_path(component).map_err(|_| {
        refuse(
            ErrorCode::ValidationError,
            REASON_UNKNOWN_COMPONENT,
            component,
            "the component name is not a safe task segment",
        )
    })?;
    Ok(format!("{TASK_NAME_PREFIX}{component}"))
}

/// Escape the five XML metacharacters.
fn xml_escape(value: &str) -> String {
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

/// Render one command-line argument using the standard Windows rule: quote an
/// argument that is empty or contains space or tab, and double embedded quotes.
fn quote_argument(argument: &str) -> String {
    if argument.is_empty() {
        return "\"\"".to_owned();
    }
    if argument.contains(' ') || argument.contains('\t') || argument.contains('"') {
        let escaped = argument.replace('"', "\"\"");
        return format!("\"{escaped}\"");
    }
    argument.to_owned()
}

/// The command line for one definition, arguments quoted for the scheduler.
fn command_line(args: &[String]) -> String {
    args.iter()
        .map(|argument| quote_argument(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Render the Task Scheduler XML for one per-user definition.
fn render_task_xml(
    component: &str,
    task_name: &str,
    executable: &str,
    args: &[String],
    working_directory: &str,
    restart: RestartPolicy,
) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(r#"<?xml version="1.0" encoding="UTF-8"?>"#.to_owned());
    lines.push(format!(
        r#"<Task version="{TASK_XML_VERSION}" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">"#
    ));
    lines.push("  <RegistrationInfo>".to_owned());
    lines.push(format!(
        "    <Description>Axiom managed process for {} (per-user).</Description>",
        xml_escape(component)
    ));
    lines.push(format!("    <URI>{}</URI>", xml_escape(task_name)));
    lines.push("  </RegistrationInfo>".to_owned());
    lines.push("  <Triggers>".to_owned());
    lines.push("    <LogonTrigger>".to_owned());
    lines.push("      <Enabled>true</Enabled>".to_owned());
    lines.push("    </LogonTrigger>".to_owned());
    lines.push("  </Triggers>".to_owned());
    lines.push("  <Principals>".to_owned());
    lines.push(r#"    <Principal id="Author">"#.to_owned());
    lines.push("      <LogonType>InteractiveToken</LogonType>".to_owned());
    lines.push("      <RunLevel>LeastPrivilege</RunLevel>".to_owned());
    lines.push("    </Principal>".to_owned());
    lines.push("  </Principals>".to_owned());
    lines.push("  <Settings>".to_owned());
    lines.push("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>".to_owned());
    lines.push("    <StartWhenAvailable>true</StartWhenAvailable>".to_owned());
    lines.push("    <AllowHardTerminate>true</AllowHardTerminate>".to_owned());
    lines.push("    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>".to_owned());
    lines.push("    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>".to_owned());
    if restart.on_failure {
        lines.push("    <RestartOnFailure>".to_owned());
        lines.push(format!(
            "      <Interval>PT{}S</Interval>",
            restart.delay_seconds
        ));
        lines.push(format!("      <Count>{}</Count>", restart.max_attempts));
        lines.push("    </RestartOnFailure>".to_owned());
    }
    lines.push("    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>".to_owned());
    lines.push("    <Enabled>true</Enabled>".to_owned());
    lines.push("  </Settings>".to_owned());
    lines.push(r#"  <Actions Context="Author">"#.to_owned());
    lines.push("    <Exec>".to_owned());
    lines.push(format!(
        "      <Command>{}</Command>",
        xml_escape(executable)
    ));
    lines.push(format!(
        "      <Arguments>{}</Arguments>",
        xml_escape(&command_line(args))
    ));
    lines.push(format!(
        "      <WorkingDirectory>{}</WorkingDirectory>",
        xml_escape(working_directory)
    ));
    lines.push("    </Exec>".to_owned());
    lines.push("  </Actions>".to_owned());
    lines.push("</Task>".to_owned());
    lines.push(String::new());
    lines.join("\n")
}

/// Render and validate one per-user task definition without touching the host.
///
/// # Errors
/// [ErrorCode::Forbidden] when the request is system-scoped or asks to elevate;
/// [ErrorCode::ValidationError] for an unknown component, a relative executable,
/// working directory, install root or log file, a log file outside the install
/// root, an argument with a NUL byte, or an out-of-range restart policy.
pub fn plan_task(request: &WindowsServiceRequest) -> Result<WindowsTaskDefinition, AxiomError> {
    if request.scope != InstallScope::PerUser || request.request_elevation {
        return Err(refuse(
            ErrorCode::Forbidden,
            if request.request_elevation {
                REASON_ELEVATION_REQUESTED
            } else {
                REASON_UNSUPPORTED_SCOPE
            },
            request.scope.as_str(),
            "a per-user startup record cannot be system-scoped or elevated",
        ));
    }
    let task_name = task_name(&request.component)?;
    for (rule, path) in [
        (REASON_UNSAFE_PATH, &request.executable),
        (REASON_UNSAFE_PATH, &request.working_directory),
        (REASON_UNSAFE_PATH, &request.install_root),
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
            crate::service::REASON_RESTART_POLICY,
            &format!("{:?}", request.restart),
            "the restart policy is out of range",
        ));
    }
    let definition_path = under(
        &request.install_root,
        &[
            SERVICE_DIRECTORY,
            &format!("{}.task.xml", request.component),
        ],
    );
    let xml = render_task_xml(
        &request.component,
        &task_name,
        &request.executable,
        &request.args,
        &request.working_directory,
        request.restart,
    );
    Ok(WindowsTaskDefinition {
        component: request.component.clone(),
        task_name,
        mechanism: MECHANISM,
        scope: InstallScope::PerUser,
        trigger: request.trigger,
        restart: request.restart,
        executable: request.executable.clone(),
        args: request.args.clone(),
        working_directory: request.working_directory.clone(),
        log_file: request.log_file.clone(),
        definition_path,
        xml,
    })
}

/// Register one per-user task through the injected executor.
///
/// The consent token is required and separate from the request, so a
/// registration always follows a deliberate call.
///
/// # Errors
/// Whatever [`plan_task`] refuses, plus [ErrorCode::Internal] when the
/// scheduler exits non-zero or cannot be launched.
pub fn install_task(
    request: &WindowsServiceRequest,
    _consent: Consent,
    exec: &impl ServiceExec,
) -> Result<InstalledService, AxiomError> {
    let definition = plan_task(request)?;
    let operation = definition.register_operation();
    let output = exec.run(&operation)?;
    if output.code != 0 {
        return Err(refuse(
            ErrorCode::Internal,
            REASON_SCHEDULER_EXIT,
            &output.code.to_string(),
            &format!(
                "the scheduler refused the registration: {}",
                output.stderr.trim()
            ),
        ));
    }
    Ok(InstalledService {
        component: definition.component,
        task_name: definition.task_name,
        mechanism: MECHANISM,
        scope: InstallScope::PerUser,
        definition_path: definition.definition_path,
        log_file: definition.log_file,
        restart: definition.restart,
    })
}

/// Check that a task name is one this adapter registered.
fn owned_task(task_name: &str) -> Result<(), AxiomError> {
    let Some(segment) = task_name.strip_prefix(TASK_NAME_PREFIX) else {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_FOREIGN_TASK,
            task_name,
            "the task is not owned by axiom",
        ));
    };
    if INSTALLABLE_COMPONENTS.contains(&segment) && validate_portable_relative_path(segment).is_ok()
    {
        Ok(())
    } else {
        Err(refuse(
            ErrorCode::ValidationError,
            REASON_FOREIGN_TASK,
            task_name,
            "the task is not owned by axiom",
        ))
    }
}

/// The scheduler operation that starts one owned task.
///
/// # Errors
/// [ErrorCode::ValidationError] when the task is not owned by axiom.
pub fn start_operation(task_name: &str) -> Result<ServiceOperation, AxiomError> {
    owned_task(task_name)?;
    Ok(ServiceOperation {
        description: "start".to_owned(),
        program: SCHEDULER_PROGRAM.to_owned(),
        args: vec!["/run".to_owned(), "/tn".to_owned(), task_name.to_owned()],
    })
}

/// The scheduler operation that stops one owned task.
///
/// # Errors
/// [ErrorCode::ValidationError] when the task is not owned by axiom.
pub fn stop_operation(task_name: &str) -> Result<ServiceOperation, AxiomError> {
    owned_task(task_name)?;
    Ok(ServiceOperation {
        description: "stop".to_owned(),
        program: SCHEDULER_PROGRAM.to_owned(),
        args: vec!["/end".to_owned(), "/tn".to_owned(), task_name.to_owned()],
    })
}

/// The scheduler operation that reports one owned task's status.
///
/// # Errors
/// [ErrorCode::ValidationError] when the task is not owned by axiom.
pub fn status_operation(task_name: &str) -> Result<ServiceOperation, AxiomError> {
    owned_task(task_name)?;
    Ok(ServiceOperation {
        description: "status".to_owned(),
        program: SCHEDULER_PROGRAM.to_owned(),
        args: vec![
            "/query".to_owned(),
            "/tn".to_owned(),
            task_name.to_owned(),
            "/fo".to_owned(),
            "LIST".to_owned(),
            "/v".to_owned(),
        ],
    })
}

/// The scheduler operation that removes one owned task.
///
/// # Errors
/// [ErrorCode::ValidationError] when the task is not owned by axiom.
pub fn uninstall_operation(task_name: &str) -> Result<ServiceOperation, AxiomError> {
    owned_task(task_name)?;
    Ok(ServiceOperation {
        description: "uninstall".to_owned(),
        program: SCHEDULER_PROGRAM.to_owned(),
        args: vec![
            "/delete".to_owned(),
            "/tn".to_owned(),
            task_name.to_owned(),
            "/f".to_owned(),
        ],
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{ServiceOutput, MAX_RESTART_ATTEMPTS, MAX_RESTART_DELAY_SECONDS};
    use std::cell::RefCell;

    const ROOT: &str = r"C:\Axiom";
    const EXE: &str = r"C:\Axiom\versions\1.0.0\axiom-graphd.exe";
    const WORKDIR: &str = r"C:\Axiom\versions\1.0.0";

    fn sample() -> WindowsServiceRequest {
        WindowsServiceRequest::new("axiom-graphd", EXE, WORKDIR, ROOT)
    }

    /// Records every operation and returns one canned result.
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
                    stdout: "SUCCESS".to_owned(),
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
                    stderr: "ERROR: Access is denied.".to_owned(),
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

    /// A host that denies the scheduler, as a locked-down policy would.
    struct DenyingExec;

    impl ServiceExec for DenyingExec {
        fn run(&self, _operation: &ServiceOperation) -> Result<ServiceOutput, AxiomError> {
            Err(refuse(
                ErrorCode::Forbidden,
                "test-denied",
                "schtasks.exe",
                "the host policy denied the scheduler",
            ))
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
    fn a_per_user_task_is_rendered_with_a_logon_trigger_and_least_privilege() {
        let definition = plan_task(&sample()).expect("a per-user request is accepted");
        assert_eq!(definition.mechanism, ServiceKind::PerUserStartup);
        assert_eq!(definition.scope, InstallScope::PerUser);
        assert_eq!(definition.task_name, r"Axiom\axiom-graphd");
        assert!(definition.xml.contains("<LogonTrigger>"));
        assert!(definition
            .xml
            .contains("<LogonType>InteractiveToken</LogonType>"));
        assert!(definition
            .xml
            .contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(definition.xml.contains(r"<URI>Axiom\axiom-graphd</URI>"));
        assert!(definition
            .xml
            .contains("<Command>C:\\Axiom\\versions\\1.0.0\\axiom-graphd.exe</Command>"));
    }

    #[test]
    fn the_definition_is_registered_beside_the_install_root() {
        let definition = plan_task(&sample()).expect("a per-user request is accepted");
        assert!(definition.definition_path.contains(SERVICE_DIRECTORY));
        assert!(definition
            .definition_path
            .ends_with("axiom-graphd.task.xml"));
        assert!(is_under(ROOT, &definition.log_file));
        assert!(definition.log_file.ends_with("axiom-graphd.log"));
    }

    #[test]
    fn an_install_registers_the_task_and_reports_it() {
        let exec = RecordingExec::succeeding();
        let installed = install_task(
            &sample().with_restart(RestartPolicy::on_failure(60, 3)),
            Consent::explicit(),
            &exec,
        )
        .expect("the scheduler accepted the registration");
        assert_eq!(installed.task_name, r"Axiom\axiom-graphd");
        assert_eq!(installed.mechanism, ServiceKind::PerUserStartup);
        assert_eq!(installed.scope, InstallScope::PerUser);
        assert_eq!(installed.restart, RestartPolicy::on_failure(60, 3));
        let recorded = exec.operations.borrow();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].program, SCHEDULER_PROGRAM);
        assert_eq!(recorded[0].args[0], "/create");
        assert!(recorded[0].args.contains(&"/xml".to_owned()));
    }

    #[test]
    fn the_install_operation_uses_program_and_argv_never_a_shell() {
        let definition = plan_task(&sample()).expect("a per-user request is accepted");
        let operation = definition.register_operation();
        assert_eq!(operation.program, SCHEDULER_PROGRAM);
        assert!(!operation.program.eq_ignore_ascii_case("cmd"));
        for argument in &operation.args {
            assert!(!argument.eq_ignore_ascii_case("/c"));
            assert!(!argument.contains("&&"));
        }
    }

    #[test]
    fn control_operations_target_only_the_owned_task() {
        let name = r"Axiom\axiom-mcp";
        assert_eq!(
            start_operation(name).unwrap().args,
            vec!["/run", "/tn", name]
        );
        assert_eq!(
            stop_operation(name).unwrap().args,
            vec!["/end", "/tn", name]
        );
        assert_eq!(
            uninstall_operation(name).unwrap().args,
            vec!["/delete", "/tn", name, "/f"]
        );
        let status = status_operation(name).unwrap();
        assert_eq!(
            status.args,
            vec!["/query", "/tn", name, "/fo", "LIST", "/v"]
        );
    }

    #[test]
    fn an_argument_with_a_space_is_quoted_and_a_quote_doubled() {
        let definition = plan_task(&sample().with_args(vec![
            "--registry".to_owned(),
            r"C:\Axiom Home\registry.json".to_owned(),
            "a\"b".to_owned(),
        ]))
        .expect("a per-user request is accepted");
        assert!(definition
            .xml
            .contains("--registry &quot;C:\\Axiom Home\\registry.json&quot;"));
        assert!(definition.xml.contains("&quot;a&quot;&quot;b&quot;"));
    }

    #[test]
    fn an_on_failure_policy_is_rendered_as_a_bounded_restart() {
        let definition =
            plan_task(&sample().with_restart(RestartPolicy::on_failure(60, 3))).expect("accepted");
        assert!(definition.xml.contains("<RestartOnFailure>"));
        assert!(definition.xml.contains("<Interval>PT60S</Interval>"));
        assert!(definition.xml.contains("<Count>3</Count>"));

        let never = plan_task(&sample()).expect("accepted");
        assert!(!never.xml.contains("<RestartOnFailure>"));
    }

    #[test]
    fn a_system_scoped_request_is_refused() {
        let mut request = sample();
        request.scope = InstallScope::System;
        let error = plan_task(&request).expect_err("a system scope is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule(&error), REASON_UNSUPPORTED_SCOPE);
    }

    #[test]
    fn an_elevation_request_is_refused() {
        let mut request = sample();
        request.request_elevation = true;
        let error = plan_task(&request).expect_err("an elevation request is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule(&error), REASON_ELEVATION_REQUESTED);
    }

    #[test]
    fn an_unknown_component_is_refused() {
        let request = WindowsServiceRequest::new("axiom-other", EXE, WORKDIR, ROOT);
        let error = plan_task(&request).expect_err("an unknown component is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(rule(&error), REASON_UNKNOWN_COMPONENT);
    }

    #[test]
    fn a_relative_path_is_refused() {
        let mut request = sample();
        request.executable = r"axiom-graphd.exe".to_owned();
        let error = plan_task(&request).expect_err("a relative executable is refused");
        assert_eq!(rule(&error), REASON_UNSAFE_PATH);

        let mut request = sample();
        request.working_directory = "versions/1.0.0".to_owned();
        assert_eq!(rule(&plan_task(&request).unwrap_err()), REASON_UNSAFE_PATH);
    }

    #[test]
    fn a_log_file_outside_the_install_root_is_refused() {
        let request = sample().with_log_file(r"C:\Other\axiom-graphd.log");
        let error = plan_task(&request).expect_err("a foreign log path is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(rule(&error), REASON_LOG_OUTSIDE_ROOT);
    }

    #[test]
    fn an_argument_with_a_nul_byte_is_refused() {
        let request = sample().with_args(vec!["serve\0--evil".to_owned()]);
        let error = plan_task(&request).expect_err("a NUL byte is refused");
        assert_eq!(rule(&error), REASON_UNSAFE_ARGUMENT);
    }

    #[test]
    fn an_out_of_range_restart_policy_is_refused() {
        for policy in [
            RestartPolicy::on_failure(0, 3),
            RestartPolicy::on_failure(60, 0),
            RestartPolicy::on_failure(60, MAX_RESTART_ATTEMPTS + 1),
            RestartPolicy::on_failure(MAX_RESTART_DELAY_SECONDS + 1, 3),
            RestartPolicy {
                on_failure: false,
                delay_seconds: 5,
                max_attempts: 0,
            },
        ] {
            let error = plan_task(&sample().with_restart(policy))
                .expect_err("an out-of-range policy is refused");
            assert_eq!(rule(&error), crate::service::REASON_RESTART_POLICY);
        }
    }

    #[test]
    fn a_restart_policy_at_the_boundary_is_accepted() {
        assert!(plan_task(&sample().with_restart(RestartPolicy::on_failure(1, 1))).is_ok());
        assert!(plan_task(&sample().with_restart(RestartPolicy::on_failure(
            MAX_RESTART_DELAY_SECONDS,
            MAX_RESTART_ATTEMPTS
        )))
        .is_ok());
        assert!(plan_task(&sample().with_restart(RestartPolicy::never())).is_ok());
    }

    #[test]
    fn a_foreign_task_name_is_refused_by_control_operations() {
        for name in [
            r"Other\axiom-graphd",
            r"Axiom\evil app",
            r"Axiom\..\escape",
            "axiom-graphd",
        ] {
            let error = stop_operation(name).expect_err("a foreign task is refused");
            assert_eq!(error.code(), ErrorCode::ValidationError);
            assert_eq!(rule(&error), REASON_FOREIGN_TASK);
        }
        assert!(start_operation(r"Axiom\axiom-graphd").is_ok());
    }

    #[test]
    fn a_denied_registration_surfaces_forbidden_without_success() {
        let error = install_task(&sample(), Consent::explicit(), &DenyingExec)
            .expect_err("a denied registration is an error");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert!(!error.message().contains("SUCCESS"));
    }

    #[test]
    fn a_non_zero_scheduler_exit_is_refused() {
        let exec = RecordingExec::failing(1);
        let error = install_task(&sample(), Consent::explicit(), &exec)
            .expect_err("a failed scheduler exit is an error");
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(rule(&error), REASON_SCHEDULER_EXIT);
    }
}
