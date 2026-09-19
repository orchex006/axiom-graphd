//! Host-neutral service control for the `axiom` CLI (task E-011).
//!
//! `21-INSTALLATION.md` section E names the control commands an operator uses
//! after an install (`axiom service start --component ...`,
//! `axiom service status --component ...`, and stop/uninstall) and requires that
//! they act on the managed per-user process. This module is the one host-neutral
//! control surface over the three adapters ([`super::windows`],
//! [`super::linux`], [`super::macos`]): it decides which instance a command may
//! touch, renders the host command, and hands it to a [`ServiceExec`].
//!
//! ## What this module guarantees (AC1)
//!
//! *Commands affect only owned component instances.* Control never starts from a
//! name the caller supplies. It starts from the [`InstalledService`] the adapter
//! returned at install, and [`ServiceOwnership::claim`] re-derives the
//! registered name from the component with the same adapter that created it. A
//! name that does not match the component, an unknown component, a mechanism the
//! CLI does not manage, and a definition outside the directory that mechanism
//! owns are all refused, so a command cannot be aimed at another component's
//! instance or at a foreign name. Each adapter then re-checks ownership itself
//! before rendering, so the guarantee does not depend on this module alone.
//!
//! *PID reuse cannot target another process.* No rendered operation ever
//! contains a process id. A pid is only accepted together with the ownership
//! token, and the token is derived from the identity of the definition the
//! instance was started from, so a pid that has been recycled - a new process
//! that inherited a dead instance's number - carries no token this install
//! minted and is refused. [`ServiceOwnership::bind_process`] mints the token
//! only for a pid the caller observed running the owned definition, and
//! [`plan_process_stop`] verifies it again before planning; the pid is still
//! never rendered into the operation, because the controller acts on the owned
//! name.

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::is_absolute_host_path;
use serde::{Deserialize, Serialize};

use crate::discovery::ServiceKind;
use crate::install::plan::InstallScope;
use crate::service::{
    is_under, linux, macos, mechanism_wire, windows, InstalledService, ServiceExec,
    ServiceOperation, ServiceOutput, SERVICE_DIRECTORY,
};

/// Reason recorded when a component is not one the CLI installs.
pub const REASON_UNKNOWN_COMPONENT: &str = "unknown-component";

/// Reason recorded when the mechanism is not one the CLI manages.
pub const REASON_FOREIGN_MECHANISM: &str = "foreign-mechanism";

/// Reason recorded when a request is not per-user.
pub const REASON_UNSUPPORTED_SCOPE: &str = "unsupported-scope";

/// Reason recorded when a registered name does not match its component.
pub const REASON_OWNERSHIP_MISMATCH: &str = "ownership-mismatch";

/// Reason recorded when a definition is not inside the directory the mechanism
/// owns for one user.
pub const REASON_DEFINITION_OUTSIDE_OWNED_DIR: &str = "definition-outside-owned-directory";

/// Reason recorded when a process id or token does not belong to this install.
pub const REASON_FOREIGN_PROCESS: &str = "foreign-process";

/// Reason recorded when a control verb is not one this CLI implements.
pub const REASON_UNKNOWN_ACTION: &str = "unknown-action";

/// Reason recorded when the host controller exits non-zero for start or stop.
pub const REASON_CONTROLLER_EXIT: &str = "controller-exit";

/// A refusal that changes nothing on the host.
fn refuse(code: ErrorCode, rule: &str, observed: &str, message: &str) -> AxiomError {
    AxiomError::new(code, message)
        .with_detail("rule", rule)
        .with_detail("observed", observed)
}

/// Compare two host paths module-insensitively for identity.
fn normalise_path(value: &str) -> String {
    let mut out = value.replace('\\', "/");
    while out.ends_with('/') {
        out.pop();
    }
    out.to_ascii_lowercase()
}

/// The two directories one install owns for one user.
///
/// Windows keeps its definition in the CLI's own install root; the POSIX
/// adapters keep theirs in the user's own startup directory, which is why both
/// roots are needed to decide whether a definition is this install's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRoots {
    /// Absolute host path of the CLI's install root.
    pub install_root: String,
    /// Absolute host path of the user's home directory.
    pub home: String,
}

impl ControlRoots {
    /// The roots of one install.
    #[must_use]
    pub fn new(install_root: impl Into<String>, home: impl Into<String>) -> Self {
        Self {
            install_root: install_root.into(),
            home: home.into(),
        }
    }
}

/// What one control command does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlAction {
    /// Start the owned instance.
    Start,
    /// Stop the owned instance.
    Stop,
    /// Report the owned instance's status.
    Status,
}

impl ControlAction {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Status => "status",
        }
    }

    /// Parse one control verb from a front end.
    ///
    /// # Errors
    /// [ErrorCode::ValidationError] when the verb is not implemented.
    pub fn parse(value: &str) -> Result<Self, AxiomError> {
        match value {
            "start" => Ok(Self::Start),
            "stop" => Ok(Self::Stop),
            "status" => Ok(Self::Status),
            _ => Err(refuse(
                ErrorCode::ValidationError,
                REASON_UNKNOWN_ACTION,
                value,
                "the control action is not one this CLI implements",
            )),
        }
    }
}
/// The one instance of a component this install owns.
///
/// The record is the output of a successful install plus the directories the
/// install owns; it is not a claim the caller can compose. Its [`Self::token`]
/// names the definition identity, which is what a process id is later bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceOwnership {
    /// Component the instance runs.
    pub component: String,
    /// The host mechanism that registered it.
    pub mechanism: ServiceKind,
    /// The registered name: task name, unit name or agent label.
    pub owned_name: String,
    /// Absolute host path of the definition that created the instance.
    pub definition_path: String,
    /// Absolute host install root that owns the definition.
    pub install_root: String,
    /// Absolute host path of the user's home directory.
    pub home: String,
}

impl ServiceOwnership {
    /// Claim the instance one installed service record describes.
    ///
    /// # Errors
    /// [ErrorCode::Forbidden] when the service is not per-user or its mechanism
    /// is not one the CLI manages; [ErrorCode::ValidationError] when the
    /// component is unknown, the registered name does not match the component,
    /// or the definition is not an absolute path inside the directory that
    /// mechanism owns for this user.
    pub fn claim(installed: &InstalledService, roots: &ControlRoots) -> Result<Self, AxiomError> {
        if installed.scope != InstallScope::PerUser {
            return Err(refuse(
                ErrorCode::Forbidden,
                REASON_UNSUPPORTED_SCOPE,
                installed.scope.as_str(),
                "only a per-user instance is controlled by this CLI",
            ));
        }
        let owned_name = owned_name_for(installed.mechanism, &installed.component)?;
        if owned_name != installed.task_name {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_OWNERSHIP_MISMATCH,
                &installed.task_name,
                "the registered name does not belong to this component",
            ));
        }
        if !is_absolute_host_path(&installed.definition_path) {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_DEFINITION_OUTSIDE_OWNED_DIR,
                &installed.definition_path,
                "the definition path must be absolute for this host",
            ));
        }
        let owned_directory = definition_directory(installed.mechanism, roots);
        if !is_under(&owned_directory, &installed.definition_path) {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_DEFINITION_OUTSIDE_OWNED_DIR,
                &installed.definition_path,
                "the definition must live inside the directory this install owns",
            ));
        }
        Ok(Self {
            component: installed.component.clone(),
            mechanism: installed.mechanism,
            owned_name,
            definition_path: installed.definition_path.clone(),
            install_root: roots.install_root.clone(),
            home: roots.home.clone(),
        })
    }

    /// The identity token of the definition this instance was started from.
    #[must_use]
    pub fn token(&self) -> String {
        format!(
            "{}:{}:{}",
            mechanism_wire(self.mechanism),
            self.component,
            normalise_path(&self.definition_path)
        )
    }

    /// Bind an observed process to this ownership record.
    ///
    /// The caller states which definition it observed the process running; only
    /// a process observed on *this* definition yields a usable reference, so a
    /// pid that now belongs to something else is refused here rather than
    /// discovered later.
    ///
    /// # Errors
    /// [ErrorCode::ValidationError] when the pid is zero or the observed
    /// definition is not an absolute path; [ErrorCode::Forbidden] when the
    /// observed definition is not the owned one.
    pub fn bind_process(
        &self,
        pid: u32,
        observed_definition: &str,
    ) -> Result<ProcessRef, AxiomError> {
        if pid == 0 {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_FOREIGN_PROCESS,
                "pid=0",
                "a process id must be a real process",
            ));
        }
        if !is_absolute_host_path(observed_definition) {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_FOREIGN_PROCESS,
                observed_definition,
                "the observed definition must be an absolute path",
            ));
        }
        if normalise_path(observed_definition) != normalise_path(&self.definition_path) {
            return Err(refuse(
                ErrorCode::Forbidden,
                REASON_FOREIGN_PROCESS,
                observed_definition,
                "the process was not observed running this install's definition",
            ));
        }
        Ok(ProcessRef {
            pid,
            owner_token: self.token(),
        })
    }

    /// Machine-readable rendering of the ownership record.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the record cannot be serialised.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        serde_json::to_string_pretty(self).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the ownership record is not serialisable",
            )
            .with_detail("observed", error.to_string())
        })
    }

    /// One-line human rendering of the ownership record.
    #[must_use]
    pub fn text(&self) -> String {
        format!(
            "{}: {} ({}) definition={}\n",
            self.component,
            self.owned_name,
            mechanism_wire(self.mechanism),
            self.definition_path,
        )
    }
}

/// The registered name one mechanism uses for one component.
///
/// # Errors
/// [ErrorCode::Forbidden] when the mechanism is not one the CLI manages;
/// [ErrorCode::ValidationError] when the component is not installable.
fn owned_name_for(mechanism: ServiceKind, component: &str) -> Result<String, AxiomError> {
    match mechanism {
        ServiceKind::PerUserStartup => windows::task_name(component),
        ServiceKind::SystemdUserUnit => linux::unit_name(component),
        ServiceKind::LaunchAgent => macos::agent_label(component),
        ServiceKind::SystemService => Err(refuse(
            ErrorCode::Forbidden,
            REASON_FOREIGN_MECHANISM,
            mechanism_wire(mechanism),
            "a system service is not managed by this CLI",
        )),
    }
}

/// The directory one mechanism owns for one user's definitions.
fn definition_directory(mechanism: ServiceKind, roots: &ControlRoots) -> String {
    match mechanism {
        ServiceKind::PerUserStartup => {
            crate::install::plan::under(&roots.install_root, &[SERVICE_DIRECTORY])
        }
        ServiceKind::SystemdUserUnit => {
            crate::install::plan::under(&roots.home, &[linux::USER_UNIT_DIR])
        }
        ServiceKind::LaunchAgent => {
            crate::install::plan::under(&roots.home, &[macos::USER_AGENT_DIR])
        }
        ServiceKind::SystemService => roots.install_root.clone(),
    }
}
/// A reference to one running process, bound to the definition it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRef {
    /// Process id as observed by the caller.
    pub pid: u32,
    /// The ownership token the observation produced.
    pub owner_token: String,
}

impl ProcessRef {
    /// Prove this reference belongs to the given ownership record.
    ///
    /// # Errors
    /// [ErrorCode::Forbidden] when the token names another definition, which is
    /// the case for a pid that was recycled by a later process.
    pub fn verify(&self, ownership: &ServiceOwnership) -> Result<(), AxiomError> {
        if self.pid == 0 || self.owner_token != ownership.token() {
            return Err(refuse(
                ErrorCode::Forbidden,
                REASON_FOREIGN_PROCESS,
                &format!("pid={}", self.pid),
                "the process is not an instance this install owns",
            ));
        }
        Ok(())
    }
}

/// A reviewed control command for one owned instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPlan {
    /// Component the command affects.
    pub component: String,
    /// What the command does.
    pub action: ControlAction,
    /// The host mechanism that registered the instance.
    pub mechanism: ServiceKind,
    /// The registered name the controller is pointed at.
    pub owned_name: String,
    /// The definition identity the command is bound to.
    pub owner_token: String,
    /// The host commands, program plus argv.
    pub operations: Vec<ServiceOperation>,
}

impl ControlPlan {
    /// Machine-readable rendering of the plan.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the plan cannot be serialised.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        serde_json::to_string_pretty(self).map_err(|error| {
            AxiomError::new(ErrorCode::Internal, "the control plan is not serialisable")
                .with_detail("observed", error.to_string())
        })
    }

    /// One-line human rendering of each planned command.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = format!(
            "{}: {} {}\n",
            self.action.as_str(),
            self.component,
            self.owned_name
        );
        for operation in &self.operations {
            out.push_str(&operation.text());
        }
        out
    }
}

/// Plan one control command for one owned instance.
///
/// # Errors
/// [ErrorCode::Forbidden] when the mechanism is not managed;
/// [ErrorCode::ValidationError] when the adapter refuses the registered name.
pub fn plan_control(
    ownership: &ServiceOwnership,
    action: ControlAction,
) -> Result<ControlPlan, AxiomError> {
    let operation = dispatch(ownership.mechanism, &ownership.owned_name, action)?;
    Ok(ControlPlan {
        component: ownership.component.clone(),
        action,
        mechanism: ownership.mechanism,
        owned_name: ownership.owned_name.clone(),
        owner_token: ownership.token(),
        operations: vec![operation],
    })
}

/// Plan the stop of one observed process, refusing a pid that is not this
/// install's.
///
/// The pid is deliberately not rendered into the operation: the controller acts
/// on the owned name, so a pid can never become a target on its own.
///
/// # Errors
/// [ErrorCode::Forbidden] when the reference does not belong to `ownership`, as
/// a recycled pid would not; otherwise whatever [`plan_control`] refuses.
pub fn plan_process_stop(
    ownership: &ServiceOwnership,
    process: &ProcessRef,
) -> Result<ControlPlan, AxiomError> {
    process.verify(ownership)?;
    plan_control(ownership, ControlAction::Stop)
}

/// Render the host command for one mechanism.
///
/// # Errors
/// [ErrorCode::Forbidden] when the mechanism is not managed;
/// [ErrorCode::ValidationError] when the adapter refuses the name.
fn dispatch(
    mechanism: ServiceKind,
    owned_name: &str,
    action: ControlAction,
) -> Result<ServiceOperation, AxiomError> {
    match mechanism {
        ServiceKind::PerUserStartup => match action {
            ControlAction::Start => windows::start_operation(owned_name),
            ControlAction::Stop => windows::stop_operation(owned_name),
            ControlAction::Status => windows::status_operation(owned_name),
        },
        ServiceKind::SystemdUserUnit => match action {
            ControlAction::Start => linux::start_operation(owned_name),
            ControlAction::Stop => linux::stop_operation(owned_name),
            ControlAction::Status => linux::status_operation(owned_name),
        },
        ServiceKind::LaunchAgent => match action {
            ControlAction::Start => macos::start_operation(owned_name),
            ControlAction::Stop => macos::stop_operation(owned_name),
            ControlAction::Status => macos::status_operation(owned_name),
        },
        ServiceKind::SystemService => Err(refuse(
            ErrorCode::Forbidden,
            REASON_FOREIGN_MECHANISM,
            mechanism_wire(mechanism),
            "a system service is not managed by this CLI",
        )),
    }
}

/// What one executed control command reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlOutcome {
    /// Component the command affected.
    pub component: String,
    /// What the command did.
    pub action: ControlAction,
    /// The controller's exit code.
    pub code: i32,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
}

impl ControlOutcome {
    /// Whether the controller reported success.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        self.code == 0
    }

    /// Machine-readable rendering of the outcome.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the outcome cannot be serialised.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        serde_json::to_string_pretty(self).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the control outcome is not serialisable",
            )
            .with_detail("observed", error.to_string())
        })
    }
}

/// Execute one planned control command.
///
/// `start` and `stop` must succeed: a non-zero controller exit is
/// [ErrorCode::Internal], because the instance was not controlled. `status` is
/// an observation, so a non-zero exit is carried in the outcome instead: both
/// `systemctl --user status` and `schtasks.exe /query` exit non-zero for a
/// stopped or absent instance, and that is information rather than a failure.
///
/// # Errors
/// Whatever [`ServiceExec`] refuses, and [ErrorCode::Internal] when a start or
/// stop exits non-zero.
pub fn run_control(
    plan: &ControlPlan,
    exec: &impl ServiceExec,
) -> Result<ControlOutcome, AxiomError> {
    let mut outcome = ControlOutcome {
        component: plan.component.clone(),
        action: plan.action,
        code: 0,
        stdout: String::new(),
        stderr: String::new(),
    };
    for operation in &plan.operations {
        let ServiceOutput {
            code,
            stdout,
            stderr,
        } = exec.run(operation)?;
        outcome.code = code;
        outcome.stdout = stdout;
        outcome.stderr = stderr;
        if code != 0 && plan.action != ControlAction::Status {
            return Err(refuse(
                ErrorCode::Internal,
                REASON_CONTROLLER_EXIT,
                &code.to_string(),
                &format!(
                    "the host controller did not {} the instance: {}",
                    plan.action.as_str(),
                    outcome.stderr.trim(),
                ),
            ));
        }
    }
    Ok(outcome)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const ROOT: &str = r"C:\Axiom";
    const HOME: &str = r"C:\Users\billy";
    const DEF: &str = r"C:\Axiom\service\axiom-graphd.task.xml";

    fn roots() -> ControlRoots {
        ControlRoots::new(ROOT, HOME)
    }

    fn installed(component: &str, task_name: &str, definition_path: &str) -> InstalledService {
        InstalledService {
            component: component.to_owned(),
            task_name: task_name.to_owned(),
            mechanism: ServiceKind::PerUserStartup,
            scope: InstallScope::PerUser,
            definition_path: definition_path.to_owned(),
            log_file: format!(r"{ROOT}\logs\{component}.log"),
            restart: crate::service::RestartPolicy::never(),
        }
    }

    fn ownership() -> ServiceOwnership {
        ServiceOwnership::claim(
            &installed("axiom-graphd", r"Axiom\axiom-graphd", DEF),
            &roots(),
        )
        .expect("the installed service is owned")
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
                    stdout: "SUCCESS".to_owned(),
                    stderr: String::new(),
                },
            }
        }

        fn exiting(code: i32) -> Self {
            Self {
                operations: RefCell::new(Vec::new()),
                result: ServiceOutput {
                    code,
                    stdout: String::new(),
                    stderr: "ERROR: The system cannot find the file specified.".to_owned(),
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
    fn a_control_command_targets_only_the_owned_task() {
        let ownership = ownership();
        assert_eq!(ownership.owned_name, r"Axiom\axiom-graphd");
        assert_eq!(ownership.component, "axiom-graphd");

        let plan = plan_control(&ownership, ControlAction::Start).expect("start is planned");
        assert_eq!(plan.operations.len(), 1);
        assert_eq!(plan.operations[0].program, windows::SCHEDULER_PROGRAM);
        assert_eq!(
            plan.operations[0].args,
            vec!["/run", "/tn", r"Axiom\axiom-graphd"]
        );
        assert_eq!(plan.owner_token, ownership.token());

        let stop = plan_control(&ownership, ControlAction::Stop).expect("stop is planned");
        assert_eq!(
            stop.operations[0].args,
            vec!["/end", "/tn", r"Axiom\axiom-graphd"]
        );
    }

    #[test]
    fn every_managed_mechanism_dispatches_to_its_own_adapter() {
        let linux_service = InstalledService {
            component: "axiom-graphd".to_owned(),
            task_name: "axiom-graphd.service".to_owned(),
            mechanism: ServiceKind::SystemdUserUnit,
            scope: InstallScope::PerUser,
            definition_path: "/home/billy/.config/systemd/user/axiom-graphd.service".to_owned(),
            log_file: "/opt/axiom/logs/axiom-graphd.log".to_owned(),
            restart: crate::service::RestartPolicy::never(),
        };
        let linux_ownership = ServiceOwnership::claim(
            &linux_service,
            &ControlRoots::new("/opt/axiom", "/home/billy"),
        )
        .expect("the Linux unit is owned");
        let plan = plan_control(&linux_ownership, ControlAction::Start).expect("planned");
        assert_eq!(
            plan.operations[0].args,
            vec!["--user", "start", "axiom-graphd.service"]
        );

        let mac_service = InstalledService {
            component: "axiom-graphd".to_owned(),
            task_name: "com.axiom.axiom-graphd".to_owned(),
            mechanism: ServiceKind::LaunchAgent,
            scope: InstallScope::PerUser,
            definition_path: "/Users/billy/Library/LaunchAgents/com.axiom.axiom-graphd.plist"
                .to_owned(),
            log_file: "/Users/billy/Axiom/logs/axiom-graphd.log".to_owned(),
            restart: crate::service::RestartPolicy::never(),
        };
        let mac_ownership = ServiceOwnership::claim(
            &mac_service,
            &ControlRoots::new("/Users/billy/Axiom", "/Users/billy"),
        )
        .expect("the macOS agent is owned");
        let plan = plan_control(&mac_ownership, ControlAction::Status).expect("planned");
        assert_eq!(plan.operations[0].program, macos::LAUNCHCTL_PROGRAM);
        assert_eq!(
            plan.operations[0].args,
            vec!["list", "com.axiom.axiom-graphd"]
        );
    }

    #[test]
    fn a_start_or_stop_that_the_host_refuses_is_an_error() {
        for action in [ControlAction::Start, ControlAction::Stop] {
            let plan = plan_control(&ownership(), action).expect("planned");
            let exec = RecordingExec::exiting(1);
            let error = run_control(&plan, &exec).expect_err("a refused control is an error");
            assert_eq!(error.code(), ErrorCode::Internal);
            assert_eq!(rule(&error), REASON_CONTROLLER_EXIT);
            assert_eq!(exec.operations.borrow().len(), 1);
        }
    }

    #[test]
    fn a_status_exit_code_is_reported_rather_than_raised() {
        let plan = plan_control(&ownership(), ControlAction::Status).expect("planned");
        let exec = RecordingExec::exiting(1);
        let outcome = run_control(&plan, &exec).expect("status is an observation");
        assert_eq!(outcome.code, 1);
        assert!(!outcome.succeeded());
        assert_eq!(outcome.component, "axiom-graphd");
    }

    #[test]
    fn a_successful_control_reports_the_controller_output() {
        let plan = plan_control(&ownership(), ControlAction::Start).expect("planned");
        let exec = RecordingExec::succeeding();
        let outcome = run_control(&plan, &exec).expect("start succeeds");
        assert!(outcome.succeeded());
        assert_eq!(outcome.stdout, "SUCCESS");
        assert_eq!(exec.operations.borrow()[0].description, "start");
    }

    #[test]
    fn a_name_that_does_not_match_its_component_is_refused() {
        let error = ServiceOwnership::claim(
            &installed("axiom-graphd", r"Axiom\axiom-mcp", DEF),
            &roots(),
        )
        .expect_err("a mismatched name is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(rule(&error), REASON_OWNERSHIP_MISMATCH);

        let error = ServiceOwnership::claim(
            &installed("axiom-other", r"Axiom\axiom-other", DEF),
            &roots(),
        )
        .expect_err("an unknown component is refused");
        assert_eq!(rule(&error), REASON_UNKNOWN_COMPONENT);
    }

    #[test]
    fn a_definition_outside_the_owned_directory_is_refused() {
        for definition in [
            r"D:\Other\service\axiom-graphd.task.xml",
            r"C:\Axiom",
            r"service\axiom-graphd.task.xml",
        ] {
            let error = ServiceOwnership::claim(
                &installed("axiom-graphd", r"Axiom\axiom-graphd", definition),
                &roots(),
            )
            .expect_err("a foreign definition is refused");
            assert_eq!(rule(&error), REASON_DEFINITION_OUTSIDE_OWNED_DIR);
        }

        let linux_service = InstalledService {
            component: "axiom-graphd".to_owned(),
            task_name: "axiom-graphd.service".to_owned(),
            mechanism: ServiceKind::SystemdUserUnit,
            scope: InstallScope::PerUser,
            definition_path: "/opt/axiom/service/axiom-graphd.service".to_owned(),
            log_file: "/opt/axiom/logs/axiom-graphd.log".to_owned(),
            restart: crate::service::RestartPolicy::never(),
        };
        let error = ServiceOwnership::claim(
            &linux_service,
            &ControlRoots::new("/opt/axiom", "/home/billy"),
        )
        .expect_err("a unit outside the user systemd directory is refused");
        assert_eq!(rule(&error), REASON_DEFINITION_OUTSIDE_OWNED_DIR);
    }

    #[test]
    fn a_non_user_scope_or_an_unmanaged_mechanism_is_refused() {
        let mut service = installed("axiom-graphd", r"Axiom\axiom-graphd", DEF);
        service.scope = InstallScope::System;
        let error =
            ServiceOwnership::claim(&service, &roots()).expect_err("a system scope is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule(&error), REASON_UNSUPPORTED_SCOPE);

        let mut service = installed("axiom-graphd", r"Axiom\axiom-graphd", DEF);
        service.mechanism = ServiceKind::SystemService;
        let error =
            ServiceOwnership::claim(&service, &roots()).expect_err("a system service is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule(&error), REASON_FOREIGN_MECHANISM);
    }

    #[test]
    fn a_recycled_pid_cannot_be_bound_to_the_owned_instance() {
        let ownership = ownership();
        for observed in [
            r"D:\Other\service\axiom-graphd.task.xml",
            r"C:\Axiom\service\axiom-mcp.task.xml",
            "axiom-graphd",
        ] {
            assert!(ownership.bind_process(4321, observed).is_err());
        }
        let error = ownership
            .bind_process(4321, r"C:\Axiom\service\axiom-mcp.task.xml")
            .expect_err("another instance's path is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule(&error), REASON_FOREIGN_PROCESS);

        let error = ownership
            .bind_process(0, DEF)
            .expect_err("pid zero is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(rule(&error), REASON_FOREIGN_PROCESS);
    }

    #[test]
    fn a_token_from_another_install_cannot_stop_this_instance() {
        let ownership = ownership();
        let process = ownership
            .bind_process(4321, DEF)
            .expect("the owned definition binds");
        assert!(process.verify(&ownership).is_ok());

        let other = ServiceOwnership::claim(
            &installed(
                "axiom-graphd",
                r"Axiom\axiom-graphd",
                r"C:\Axiom-2\service\axiom-graphd.task.xml",
            ),
            &ControlRoots::new(r"C:\Axiom-2", HOME),
        )
        .expect("the second install is owned");
        assert_ne!(other.token(), ownership.token());
        let error = process
            .verify(&other)
            .expect_err("a token from another install is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule(&error), REASON_FOREIGN_PROCESS);

        let error = plan_process_stop(
            &ownership,
            &ProcessRef {
                pid: 4321,
                owner_token: other.token(),
            },
        )
        .expect_err("a stale pid is refused");
        assert_eq!(rule(&error), REASON_FOREIGN_PROCESS);
        assert_eq!(process.pid, 4321);
    }

    #[test]
    fn a_stop_bound_to_the_owned_process_never_renders_the_pid() {
        let ownership = ownership();
        let process = ownership
            .bind_process(4321, DEF)
            .expect("the owned definition binds");
        let plan = plan_process_stop(&ownership, &process).expect("the owned process stops");
        assert_eq!(plan.action, ControlAction::Stop);
        assert_eq!(
            plan.operations[0].args,
            vec!["/end", "/tn", r"Axiom\axiom-graphd"]
        );
        assert!(!plan.operations[0]
            .args
            .iter()
            .any(|arg| arg.contains("4321")));
    }

    #[test]
    fn a_control_verb_is_parsed_and_an_unknown_one_is_refused() {
        assert_eq!(ControlAction::parse("start").unwrap(), ControlAction::Start);
        assert_eq!(ControlAction::parse("stop").unwrap(), ControlAction::Stop);
        assert_eq!(
            ControlAction::parse("status").unwrap(),
            ControlAction::Status
        );
        let error = ControlAction::parse("restart").expect_err("an unknown verb is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(rule(&error), REASON_UNKNOWN_ACTION);
    }

    #[test]
    fn the_ownership_record_and_the_plan_are_serialisable() {
        let ownership = ownership();
        let json = ownership.to_json().expect("the record serialises");
        assert!(json.contains(r#""owned_name": "Axiom\\axiom-graphd""#));
        assert!(ownership.text().contains("axiom-graphd"));

        let plan = plan_control(&ownership, ControlAction::Stop).expect("planned");
        let json = plan.to_json().expect("the plan serialises");
        assert!(json.contains("\"action\": \"stop\""));
        assert!(plan.text().contains("stop: axiom-graphd"));
    }
}
