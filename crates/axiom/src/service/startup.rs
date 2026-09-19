//! Host-neutral, opt-in per-user startup registration (task V2-022).
//!
//! The three per-host adapters ([`crate::service::windows`],
//! [`crate::service::linux`], [`crate::service::macos`]) own what a Scheduled
//! Task, a systemd user unit and a LaunchAgent look like, and each of them
//! already refuses a machine-wide scope and requires an explicit [`Consent`].
//! What none of them owns alone is the part that has to hold for all three at
//! once:
//!
//! * **opt-in** - a startup record is only ever created through
//!   [`ensure_registered`], which takes the [`Consent`] token as its own
//!   argument, so registering cannot happen as a side effect of planning;
//! * **idempotent** - the rendered definition is compared with the bytes already
//!   on disk ([`classify_definition`]) before anything is written, so a second
//!   run rewrites nothing, and a record the host already reports as registered
//!   is reported [`RegistrationOutcome::AlreadyRegistered`] without issuing a
//!   second registration command;
//! * **removable** - [`remove_registered`] unloads the record and deletes the
//!   definition this adapter owns, and a second removal is
//!   [`RemovalOutcome::AlreadyRemoved`] rather than an error;
//! * **a foreground fallback, not a failure** - when the host cannot offer the
//!   per-user backend ([`BackendSupport::Unsupported`]) nothing is written and
//!   nothing is executed, and the run returns
//!   [`RegistrationOutcome::Foreground`] naming the documented foreground
//!   command, so an unsupported backend never breaks foreground mode;
//! * **no implicit elevation** - only a per-user mechanism, only under
//!   [`InstallScope::PerUser`], and only a definition inside the directory this
//!   adapter owns is ever written or deleted.
//!
//! The per-host planners stay the single place that renders a task, a unit or a
//! plist: [`StartupRegistration::for_task`], [`StartupRegistration::for_unit`]
//! and [`StartupRegistration::for_agent`] take their output and add only what
//! the neutral lifecycle needs.
//!
//! ## Why the byte boundary is a trait
//!
//! [`DefinitionLedger`] is the whole file surface, so the tests exercise every
//! state - absent, current, superseded, removed, already removed - against an
//! in-memory ledger and never touch a real service directory.
//! [`SysDefinitions`] is the only implementation that writes to the host.

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{is_absolute_host_path, validate_portable_relative_path};
use serde::{Deserialize, Serialize};

use crate::discovery::ServiceKind;
use crate::install::plan::{under, InstallScope};
use crate::service::{
    is_under, linux, macos, mechanism_wire, windows, Consent, InstalledService, RestartPolicy,
    ServiceExec, ServiceOperation, SERVICE_DIRECTORY,
};

/// Refusal rule: the mechanism is not a per-user mechanism.
pub const REASON_NOT_PER_USER_MECHANISM: &str = "not-per-user-mechanism";

/// Refusal rule: the registration is not per-user scoped.
pub const REASON_UNSUPPORTED_SCOPE: &str = "unsupported-scope";

/// Refusal rule: the component is not one the CLI installs.
pub const REASON_UNKNOWN_COMPONENT: &str = "unknown-component";

/// Refusal rule: the definition path is not an absolute host path.
pub const REASON_UNSAFE_DEFINITION_PATH: &str = "unsafe-definition-path";

/// Refusal rule: the definition is not inside the directory this adapter owns.
pub const REASON_FOREIGN_DEFINITION: &str = "foreign-definition";

/// Refusal rule: the registration renders no definition bytes.
pub const REASON_EMPTY_DEFINITION: &str = "empty-definition";

/// Refusal rule: the per-user backend refused a registration command.
pub const REASON_REGISTRY_EXIT: &str = "registry-exit";

/// Refusal rule: the definition file could not be read, written or removed.
pub const REASON_DEFINITION_IO: &str = "definition-io";

/// The documented foreground command for the Windows mechanism, used when the
/// per-user backend cannot run on this host.
pub const WINDOWS_FOREGROUND: &str = "axiom-graphd serve --registry <registry.json>";

/// The documented foreground command for the systemd user mechanism.
pub const LINUX_FOREGROUND: &str = linux::FOREGROUND_FALLBACK;

/// The documented foreground command for the launchd agent mechanism.
pub const MACOS_FOREGROUND: &str = "axiom-graphd serve --registry <registry.json>";

/// The documented foreground command for one per-user mechanism.
///
/// This is what a caller runs instead when the host cannot offer the per-user
/// backend; it is named in [`RegistrationOutcome::Foreground`] rather than
/// turned into a failure, so an unsupported backend does not break foreground
/// mode.
#[must_use]
pub const fn foreground_command(mechanism: ServiceKind) -> &'static str {
    match mechanism {
        ServiceKind::PerUserStartup => WINDOWS_FOREGROUND,
        ServiceKind::SystemdUserUnit => LINUX_FOREGROUND,
        ServiceKind::LaunchAgent => MACOS_FOREGROUND,
        ServiceKind::SystemService => LINUX_FOREGROUND,
    }
}

/// What this host can say about the per-user backend a registration targets.
///
/// `Unsupported` is the honest answer for a host without the mechanism - a
/// container without user systemd, or a Windows build without Task Scheduler
/// available to the user - and it is not an error: it is the reason the run
/// names the foreground instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BackendSupport {
    /// The per-user backend can run here; `registered` is what the host says
    /// about the record this registration names.
    Available {
        /// Whether the host already reports this record as registered.
        registered: bool,
    },
    /// The host cannot offer this per-user backend.
    Unsupported {
        /// Stable rule the detector reported.
        rule: String,
        /// What the detector observed.
        observed: String,
    },
}

impl BackendSupport {
    /// The backend can run here and the record is not registered yet.
    #[must_use]
    pub const fn available() -> Self {
        Self::Available { registered: false }
    }

    /// The backend can run here and the host already reports the record.
    #[must_use]
    pub const fn registered() -> Self {
        Self::Available { registered: true }
    }

    /// The host cannot offer this per-user backend.
    #[must_use]
    pub fn unsupported(rule: impl Into<String>, observed: impl Into<String>) -> Self {
        Self::Unsupported {
            rule: rule.into(),
            observed: observed.into(),
        }
    }

    /// Whether the backend can run here.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    /// Whether the host already reports the record as registered.
    #[must_use]
    pub const fn is_registered(&self) -> bool {
        matches!(self, Self::Available { registered: true })
    }
}

/// What the definition already on disk is, compared with the bytes a
/// registration renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefinitionState {
    /// No definition file exists yet.
    Absent,
    /// The file already holds exactly the bytes this run would write.
    Current,
    /// The file exists but holds different bytes, so this run supersedes them.
    Superseded,
}

impl DefinitionState {
    /// Stable spelling used in evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Current => "current",
            Self::Superseded => "superseded",
        }
    }
}

/// Classify the definition a registration finds, without writing anything.
///
/// This is what makes a second registration a no-op instead of a rewrite: only
/// `Absent` and `Superseded` are written, and a file that already holds the
/// exact bytes this run renders is left alone. A torn or hand-edited file is
/// therefore reported as superseded and rewritten rather than trusted.
#[must_use]
pub fn classify_definition(existing: Option<&str>, rendered: &str) -> DefinitionState {
    match existing {
        None => DefinitionState::Absent,
        Some(bytes) if bytes == rendered => DefinitionState::Current,
        Some(_) => DefinitionState::Superseded,
    }
}

/// The whole file surface the startup lifecycle needs.
///
/// The definitions live outside the install root on Linux and macOS (in the
/// user's own `systemd/user` and `LaunchAgents` directories) and inside it on
/// Windows, so the lifecycle cannot assume it owns a whole tree; it owns one
/// file per registration, and this trait is the only way it reaches it.
pub trait DefinitionLedger {
    /// Read one definition, or `None` when it does not exist.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the file exists but cannot be read.
    fn read(&self, path: &str) -> Result<Option<String>, AxiomError>;

    /// Write one definition, replacing any previous bytes.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the file cannot be written.
    fn write(&self, path: &str, bytes: &str) -> Result<(), AxiomError>;

    /// Delete one definition. A file that is already absent is not an error.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the file exists but cannot be removed.
    fn remove(&self, path: &str) -> Result<(), AxiomError>;
}

/// The only [`DefinitionLedger`] that touches the host filesystem.
///
/// The definition is written with a plain write rather than through a
/// temporary file and a rename: a definition is ours, it is compared by content
/// on the next run (so a torn write is reported as superseded and rewritten),
/// and rename-onto-an-existing-file is not a portable operation. Nothing here
/// elevates or changes a permission.
#[derive(Debug, Clone, Copy, Default)]
pub struct SysDefinitions;

impl DefinitionLedger for SysDefinitions {
    fn read(&self, path: &str) -> Result<Option<String>, AxiomError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Some(text)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(refuse(
                ErrorCode::Internal,
                REASON_DEFINITION_IO,
                path,
                &format!("the definition could not be read: {error}"),
            )),
        }
    }

    fn write(&self, path: &str, bytes: &str) -> Result<(), AxiomError> {
        std::fs::write(path, bytes).map_err(|error| {
            refuse(
                ErrorCode::Internal,
                REASON_DEFINITION_IO,
                path,
                &format!("the definition could not be written: {error}"),
            )
        })
    }

    fn remove(&self, path: &str) -> Result<(), AxiomError> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(refuse(
                ErrorCode::Internal,
                REASON_DEFINITION_IO,
                path,
                &format!("the definition could not be removed: {error}"),
            )),
        }
    }
}

/// Refuse a component the CLI never installs.
///
/// Each per-host planner already renders only owned names, so every constructor
/// calls this first to fail with the precise rule rather than the host adapter's
/// general "foreign name" refusal. It is repeated in
/// [`StartupRegistration::validated`] so the invariant holds for any future
/// constructor.
///
/// # Errors
/// [ErrorCode::ValidationError] with [`REASON_UNKNOWN_COMPONENT`].
fn check_component(component: &str) -> Result<(), AxiomError> {
    if crate::discovery::INSTALLABLE_COMPONENTS.contains(&component)
        && validate_portable_relative_path(component).is_ok()
    {
        Ok(())
    } else {
        Err(refuse(
            ErrorCode::ValidationError,
            REASON_UNKNOWN_COMPONENT,
            component,
            "the component is not one the CLI installs",
        ))
    }
}

/// One reviewed per-user registration: the definition to write and the commands
/// that register and remove it.
///
/// A registration is built from a per-host planned definition, so the rendering
/// stays in one place per host. Validation is structural: a registration that is
/// not per-user scoped, not a per-user mechanism, not an installable component,
/// or whose definition is not inside the directory this adapter owns cannot be
/// built at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupRegistration {
    component: String,
    task_name: String,
    mechanism: ServiceKind,
    scope: InstallScope,
    definition_path: String,
    owned_root: String,
    rendered: String,
    register: Vec<ServiceOperation>,
    remove_ops: Vec<ServiceOperation>,
    log_file: String,
    restart: RestartPolicy,
}

impl StartupRegistration {
    /// The registration for one planned Windows Scheduled Task.
    ///
    /// # Errors
    /// [ErrorCode::ValidationError] when the component is not installable, the
    /// definition is not an absolute path inside
    /// `<install_root>/service`, or nothing was rendered;
    /// [ErrorCode::Forbidden] when the registration is not per-user scoped.
    pub fn for_task(
        definition: &windows::WindowsTaskDefinition,
        install_root: &str,
    ) -> Result<Self, AxiomError> {
        check_component(&definition.component)?;
        Self {
            component: definition.component.clone(),
            task_name: definition.task_name.clone(),
            mechanism: definition.mechanism,
            scope: definition.scope,
            definition_path: definition.definition_path.clone(),
            owned_root: under(install_root, &[SERVICE_DIRECTORY]),
            rendered: definition.xml.clone(),
            register: vec![definition.register_operation()],
            remove_ops: vec![windows::uninstall_operation(&definition.task_name)?],
            log_file: definition.log_file.clone(),
            restart: definition.restart,
        }
        .validated()
    }

    /// The registration for one planned systemd user unit.
    ///
    /// # Errors
    /// [ErrorCode::ValidationError] when the component is not installable, the
    /// unit is not an absolute path inside `<home>/.config/systemd/user`, or
    /// nothing was rendered; [ErrorCode::Forbidden] when the registration is not
    /// per-user scoped.
    pub fn for_unit(unit: &linux::SystemdUnit, home: &str) -> Result<Self, AxiomError> {
        check_component(&unit.component)?;
        Self {
            component: unit.component.clone(),
            task_name: unit.unit_name.clone(),
            mechanism: unit.mechanism,
            scope: unit.scope,
            definition_path: unit.unit_path.clone(),
            owned_root: under(home, &[linux::USER_UNIT_DIR]),
            rendered: unit.text.clone(),
            register: vec![unit.reload_operation(), unit.enable_operation()?],
            remove_ops: vec![linux::uninstall_operation(&unit.unit_name)?],
            log_file: unit.log_file.clone(),
            restart: unit.restart,
        }
        .validated()
    }

    /// The registration for one planned macOS LaunchAgent.
    ///
    /// # Errors
    /// [ErrorCode::ValidationError] when the component is not installable, the
    /// plist is not an absolute path inside `<home>/Library/LaunchAgents`, or
    /// nothing was rendered; [ErrorCode::Forbidden] when the registration is not
    /// per-user scoped.
    pub fn for_agent(agent: &macos::LaunchAgent, home: &str) -> Result<Self, AxiomError> {
        check_component(&agent.component)?;
        let removal = macos::plan_removal(&agent.label, &agent.plist_path, home)?;
        Self {
            component: agent.component.clone(),
            task_name: agent.label.clone(),
            mechanism: agent.mechanism,
            scope: agent.scope,
            definition_path: agent.plist_path.clone(),
            owned_root: under(home, &[macos::USER_AGENT_DIR]),
            rendered: agent.plist.clone(),
            register: vec![agent.load_operation()],
            remove_ops: removal.operations,
            log_file: agent.log_file.clone(),
            restart: agent.restart,
        }
        .validated()
    }

    /// Refuse a registration that could not be reached by the per-user adapters.
    fn validated(self) -> Result<Self, AxiomError> {
        check_component(&self.component)?;
        if self.mechanism == ServiceKind::SystemService {
            return Err(refuse(
                ErrorCode::Forbidden,
                REASON_NOT_PER_USER_MECHANISM,
                mechanism_wire(self.mechanism),
                "only a per-user startup mechanism can be registered here",
            ));
        }
        if self.scope != InstallScope::PerUser {
            return Err(refuse(
                ErrorCode::Forbidden,
                REASON_UNSUPPORTED_SCOPE,
                self.scope.as_str(),
                "a per-user startup record cannot be system-scoped",
            ));
        }
        if !is_absolute_host_path(&self.definition_path) || !is_absolute_host_path(&self.owned_root)
        {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_UNSAFE_DEFINITION_PATH,
                &self.definition_path,
                "the definition and the owned directory must be absolute for this host",
            ));
        }
        if !is_under(&self.owned_root, &self.definition_path) {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_FOREIGN_DEFINITION,
                &self.definition_path,
                "the definition is not inside the directory this adapter owns",
            ));
        }
        if self.rendered.trim().is_empty() {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_EMPTY_DEFINITION,
                &self.definition_path,
                "the registration rendered no definition bytes",
            ));
        }
        if self.register.is_empty() || self.remove_ops.is_empty() {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_EMPTY_DEFINITION,
                &self.definition_path,
                "the registration has no command to register or remove it",
            ));
        }
        Ok(self)
    }

    /// The component this record starts.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    /// The registered task name, unit name or agent label.
    #[must_use]
    pub fn task_name(&self) -> &str {
        &self.task_name
    }

    /// The per-user mechanism.
    #[must_use]
    pub const fn mechanism(&self) -> ServiceKind {
        self.mechanism
    }

    /// The scope, always [`InstallScope::PerUser`].
    #[must_use]
    pub const fn scope(&self) -> InstallScope {
        self.scope
    }

    /// The definition file this registration owns.
    #[must_use]
    pub fn definition_path(&self) -> &str {
        &self.definition_path
    }

    /// The directory this adapter owns the definition inside.
    #[must_use]
    pub fn owned_root(&self) -> &str {
        &self.owned_root
    }

    /// The rendered definition bytes.
    #[must_use]
    pub fn rendered(&self) -> &str {
        &self.rendered
    }

    /// The commands that register the record, in order.
    #[must_use]
    pub fn register_operations(&self) -> &[ServiceOperation] {
        &self.register
    }

    /// The commands that remove the record, in order.
    #[must_use]
    pub fn remove_operations(&self) -> &[ServiceOperation] {
        &self.remove_ops
    }

    /// The documented foreground command for this mechanism.
    #[must_use]
    pub const fn foreground_command(&self) -> &'static str {
        foreground_command(self.mechanism)
    }

    /// The record as it is reported once it is registered.
    #[must_use]
    pub fn installed_service(&self) -> InstalledService {
        InstalledService {
            component: self.component.clone(),
            task_name: self.task_name.clone(),
            mechanism: self.mechanism,
            scope: self.scope,
            definition_path: self.definition_path.clone(),
            log_file: self.log_file.clone(),
            restart: self.restart,
        }
    }
}

/// The fallback a host takes when it cannot offer the per-user backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ForegroundPlan {
    /// Component the foreground would run.
    pub component: String,
    /// The mechanism the host could not offer.
    pub mechanism: ServiceKind,
    /// The stable rule the detector reported.
    pub rule: String,
    /// What the detector observed.
    pub observed: String,
    /// The documented foreground command to run instead.
    pub command: String,
}

impl ForegroundPlan {
    /// One-line human rendering.
    #[must_use]
    pub fn text(&self) -> String {
        format!(
            "{}: {} unavailable ({}: {}); run the foreground instead: {}\n",
            self.component,
            mechanism_wire(self.mechanism),
            self.rule,
            self.observed,
            self.command
        )
    }
}

/// What one opt-in registration run did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationOutcome {
    /// The definition was written and the per-user backend accepted the record.
    Registered(InstalledService),
    /// The definition was already exactly these bytes and the host already had
    /// the record; no definition was rewritten and no registration command ran.
    AlreadyRegistered(InstalledService),
    /// The host cannot offer this per-user backend; nothing was written and
    /// nothing was executed.
    Foreground(ForegroundPlan),
}

impl RegistrationOutcome {
    /// Stable spelling used in evidence.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Registered(_) => "registered",
            Self::AlreadyRegistered(_) => "already_registered",
            Self::Foreground(_) => "foreground",
        }
    }

    /// The registered record, when there is one.
    #[must_use]
    pub const fn installed(&self) -> Option<&InstalledService> {
        match self {
            Self::Registered(service) | Self::AlreadyRegistered(service) => Some(service),
            Self::Foreground(_) => None,
        }
    }

    /// The foreground fallback, when the backend could not run.
    #[must_use]
    pub const fn foreground(&self) -> Option<&ForegroundPlan> {
        match self {
            Self::Foreground(plan) => Some(plan),
            Self::Registered(_) | Self::AlreadyRegistered(_) => None,
        }
    }
}

/// Register one per-user startup record, opt-in and idempotent.
///
/// The [`Consent`] token is a separate argument, so a startup record can only be
/// created after a deliberate call. When the host cannot offer the per-user
/// backend the run writes nothing, executes nothing and returns
/// [`RegistrationOutcome::Foreground`] naming the documented foreground
/// command. When the host already reports the record, the definition is
/// refreshed only if it had drifted and no registration command is issued, so a
/// second run is a no-op. When the record is not registered yet, the definition
/// is made current before the registration commands run, because the command
/// reads that file.
///
/// # Errors
/// [ErrorCode::Internal] with [`REASON_REGISTRY_EXIT`] when the per-user
/// backend refuses a registration command, and whatever the injected
/// [`DefinitionLedger`] or [`ServiceExec`] reports.
pub fn ensure_registered(
    registration: &StartupRegistration,
    _consent: Consent,
    support: &BackendSupport,
    definitions: &impl DefinitionLedger,
    exec: &impl ServiceExec,
) -> Result<RegistrationOutcome, AxiomError> {
    if let BackendSupport::Unsupported { rule, observed } = support {
        return Ok(RegistrationOutcome::Foreground(ForegroundPlan {
            component: registration.component.clone(),
            mechanism: registration.mechanism,
            rule: rule.clone(),
            observed: observed.clone(),
            command: registration.foreground_command().to_owned(),
        }));
    }

    let existing = definitions.read(&registration.definition_path)?;
    if classify_definition(existing.as_deref(), &registration.rendered) != DefinitionState::Current
    {
        definitions.write(&registration.definition_path, &registration.rendered)?;
    }

    let installed = registration.installed_service();
    if support.is_registered() {
        return Ok(RegistrationOutcome::AlreadyRegistered(installed));
    }
    for operation in registration.register_operations() {
        run_registry(operation, exec)?;
    }
    Ok(RegistrationOutcome::Registered(installed))
}

/// What one removal run did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemovalOutcome {
    /// The record was unloaded and the definition deleted.
    Removed {
        /// Component the record started.
        component: String,
        /// The mechanism that was registered.
        mechanism: ServiceKind,
        /// The definition file that was deleted.
        definition_path: String,
    },
    /// There was nothing left to remove: no definition existed.
    AlreadyRemoved {
        /// Component the record started.
        component: String,
        /// The mechanism that would have been removed.
        mechanism: ServiceKind,
    },
}

impl RemovalOutcome {
    /// Stable spelling used in evidence.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Removed { .. } => "removed",
            Self::AlreadyRemoved { .. } => "already_removed",
        }
    }
}

/// Remove one per-user startup record and its definition, idempotently.
///
/// The record is unloaded before its definition is deleted, so a backend that
/// refuses leaves the definition in place for the next attempt. A registration
/// whose definition no longer exists is
/// [`RemovalOutcome::AlreadyRemoved`] and runs no command at all, which is what
/// makes a second removal a no-op that cannot fail. Only the definition this
/// registration owns is ever deleted.
///
/// # Errors
/// [ErrorCode::Internal] with [`REASON_REGISTRY_EXIT`] when the per-user
/// backend refuses the removal, and whatever the injected [`DefinitionLedger`]
/// or [`ServiceExec`] reports.
pub fn remove_registered(
    registration: &StartupRegistration,
    definitions: &impl DefinitionLedger,
    exec: &impl ServiceExec,
) -> Result<RemovalOutcome, AxiomError> {
    let existing = definitions.read(&registration.definition_path)?;
    if existing.is_none() {
        return Ok(RemovalOutcome::AlreadyRemoved {
            component: registration.component.clone(),
            mechanism: registration.mechanism,
        });
    }
    for operation in registration.remove_operations() {
        run_registry(operation, exec)?;
    }
    definitions.remove(&registration.definition_path)?;
    Ok(RemovalOutcome::Removed {
        component: registration.component.clone(),
        mechanism: registration.mechanism,
        definition_path: registration.definition_path.clone(),
    })
}

/// Run one backend command, refusing a non-zero exit.
fn run_registry(operation: &ServiceOperation, exec: &impl ServiceExec) -> Result<(), AxiomError> {
    let output = exec.run(operation)?;
    if output.code != 0 {
        return Err(refuse(
            ErrorCode::Internal,
            REASON_REGISTRY_EXIT,
            &output.code.to_string(),
            &format!(
                "the per-user backend refused {}: {}",
                operation.description,
                output.stderr.trim()
            ),
        ));
    }
    Ok(())
}

/// A refusal that changes nothing on the host.
fn refuse(code: ErrorCode, rule: &str, observed: &str, message: &str) -> AxiomError {
    AxiomError::new(code, message)
        .with_detail("rule", rule)
        .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{ServiceKind, ServiceOutput, StartupTrigger};
    use graph_core::error::ErrorCode;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    const HOME: &str = "/home/dev";
    const COMPONENT: &str = "axiom-graphd";

    /// In-memory definition files: the whole file surface without a host.
    #[derive(Default)]
    struct MemDefinitions {
        files: RefCell<BTreeMap<String, String>>,
        writes: RefCell<Vec<String>>,
        removes: RefCell<Vec<String>>,
    }

    impl MemDefinitions {
        fn holding(path: &str, bytes: &str) -> Self {
            let ledger = Self::default();
            ledger
                .files
                .borrow_mut()
                .insert(path.to_owned(), bytes.to_owned());
            ledger
        }

        fn contents(&self, path: &str) -> Option<String> {
            self.files.borrow().get(path).cloned()
        }

        fn write_count(&self) -> usize {
            self.writes.borrow().len()
        }

        fn remove_count(&self) -> usize {
            self.removes.borrow().len()
        }
    }

    impl DefinitionLedger for MemDefinitions {
        fn read(&self, path: &str) -> Result<Option<String>, AxiomError> {
            Ok(self.files.borrow().get(path).cloned())
        }

        fn write(&self, path: &str, bytes: &str) -> Result<(), AxiomError> {
            self.writes.borrow_mut().push(path.to_owned());
            self.files
                .borrow_mut()
                .insert(path.to_owned(), bytes.to_owned());
            Ok(())
        }

        fn remove(&self, path: &str) -> Result<(), AxiomError> {
            self.removes.borrow_mut().push(path.to_owned());
            self.files.borrow_mut().remove(path);
            Ok(())
        }
    }

    /// Executor that records every command and answers with one fixed exit.
    #[derive(Default)]
    struct RecordingExec {
        seen: RefCell<Vec<ServiceOperation>>,
        code: i32,
    }

    impl RecordingExec {
        fn ok() -> Self {
            Self::default()
        }

        fn failing(code: i32) -> Self {
            Self {
                seen: RefCell::new(Vec::new()),
                code,
            }
        }

        fn count(&self) -> usize {
            self.seen.borrow().len()
        }

        fn descriptions(&self) -> Vec<String> {
            self.seen
                .borrow()
                .iter()
                .map(|operation| operation.description.clone())
                .collect()
        }
    }

    impl ServiceExec for RecordingExec {
        fn run(&self, operation: &ServiceOperation) -> Result<ServiceOutput, AxiomError> {
            self.seen.borrow_mut().push(operation.clone());
            Ok(ServiceOutput {
                code: self.code,
                stdout: String::new(),
                stderr: if self.code == 0 {
                    String::new()
                } else {
                    "the backend refused".to_owned()
                },
            })
        }
    }

    /// Executor that records the definition bytes visible when each command ran.
    struct OrderingExec<'a> {
        definitions: &'a MemDefinitions,
        path: String,
        seen_at_run: RefCell<Vec<Option<String>>>,
    }

    impl ServiceExec for OrderingExec<'_> {
        fn run(&self, _operation: &ServiceOperation) -> Result<ServiceOutput, AxiomError> {
            self.seen_at_run
                .borrow_mut()
                .push(self.definitions.contents(&self.path));
            Ok(ServiceOutput {
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn unit_path() -> String {
        format!("{HOME}/.config/systemd/user/{COMPONENT}.service")
    }

    fn unit(definition_path: &str) -> linux::SystemdUnit {
        linux::SystemdUnit {
            component: COMPONENT.to_owned(),
            unit_name: format!("{COMPONENT}.service"),
            mechanism: linux::MECHANISM,
            scope: InstallScope::PerUser,
            trigger: StartupTrigger::Logon,
            restart: RestartPolicy::on_failure(5, 3),
            executable: format!("{HOME}/axiom/versions/1.0.0/axiom-graphd"),
            args: vec!["serve".to_owned()],
            working_directory: format!("{HOME}/axiom"),
            log_file: format!("{HOME}/axiom/logs/axiom-graphd.log"),
            unit_path: definition_path.to_owned(),
            text: "[Unit]\nDescription=Axiom graph daemon\n".to_owned(),
        }
    }

    fn registration() -> StartupRegistration {
        StartupRegistration::for_unit(&unit(&unit_path()), HOME)
            .expect("the planned unit is a valid per-user registration")
    }

    fn rule_of(error: &AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    #[test]
    fn classify_definition_distinguishes_absent_current_and_superseded() {
        assert_eq!(
            classify_definition(None, "rendered"),
            DefinitionState::Absent
        );
        assert_eq!(
            classify_definition(Some("rendered"), "rendered"),
            DefinitionState::Current
        );
        assert_eq!(
            classify_definition(Some("stale"), "rendered"),
            DefinitionState::Superseded
        );
        assert_eq!(DefinitionState::Absent.as_str(), "absent");
        assert_eq!(DefinitionState::Current.as_str(), "current");
        assert_eq!(DefinitionState::Superseded.as_str(), "superseded");
    }

    #[test]
    fn opt_in_registration_writes_the_definition_and_runs_the_commands_in_order() {
        let registration = registration();
        let definitions = MemDefinitions::default();
        let exec = RecordingExec::ok();
        let outcome = ensure_registered(
            &registration,
            Consent::explicit(),
            &BackendSupport::available(),
            &definitions,
            &exec,
        )
        .expect("an available backend registers the record");

        match outcome {
            RegistrationOutcome::Registered(installed) => {
                assert_eq!(installed.component, COMPONENT);
                assert_eq!(installed.mechanism, ServiceKind::SystemdUserUnit);
                assert_eq!(installed.scope, InstallScope::PerUser);
                assert_eq!(installed.definition_path, unit_path());
            }
            other => panic!("expected Registered, got {other:?}"),
        }
        assert_eq!(
            definitions.contents(&unit_path()).as_deref(),
            Some(registration.rendered()),
            "the rendered unit must be on disk after registration"
        );
        assert_eq!(exec.descriptions(), vec!["reload", "enable"]);
    }

    #[test]
    fn the_definition_is_visible_before_the_registration_commands_run() {
        let registration = registration();
        let definitions = MemDefinitions::default();
        let exec = OrderingExec {
            definitions: &definitions,
            path: unit_path(),
            seen_at_run: RefCell::new(Vec::new()),
        };
        ensure_registered(
            &registration,
            Consent::explicit(),
            &BackendSupport::available(),
            &definitions,
            &exec,
        )
        .expect("an available backend registers the record");

        let seen = exec.seen_at_run.borrow();
        assert_eq!(seen.len(), 2, "both registration commands must run");
        assert_eq!(
            seen[0].as_deref(),
            Some(registration.rendered()),
            "systemctl must see the unit file before it reloads the user manager"
        );
    }

    #[test]
    fn a_second_run_over_an_unchanged_definition_is_idempotent() {
        let registration = registration();
        let definitions =
            MemDefinitions::holding(&registration.definition_path, registration.rendered());
        let exec = RecordingExec::ok();
        let outcome = ensure_registered(
            &registration,
            Consent::explicit(),
            &BackendSupport::registered(),
            &definitions,
            &exec,
        )
        .expect("an already registered record is not an error");

        assert!(matches!(outcome, RegistrationOutcome::AlreadyRegistered(_)));
        assert_eq!(outcome.as_str(), "already_registered");
        assert_eq!(
            definitions.write_count(),
            0,
            "an unchanged definition must not be rewritten"
        );
        assert_eq!(
            exec.count(),
            0,
            "an already registered record must not be registered twice"
        );
    }

    #[test]
    fn a_superseded_definition_is_rewritten_rather_than_trusted() {
        let registration = registration();
        let definitions = MemDefinitions::holding(&registration.definition_path, "hand edited\n");
        let exec = RecordingExec::ok();
        ensure_registered(
            &registration,
            Consent::explicit(),
            &BackendSupport::available(),
            &definitions,
            &exec,
        )
        .expect("a stale definition does not block registration");

        assert_eq!(definitions.write_count(), 1);
        assert_eq!(
            definitions.contents(&unit_path()).as_deref(),
            Some(registration.rendered())
        );
    }

    #[test]
    fn an_absent_definition_is_repaired_even_when_the_host_already_reports_the_record() {
        let registration = registration();
        let definitions = MemDefinitions::default();
        let exec = RecordingExec::ok();
        let outcome = ensure_registered(
            &registration,
            Consent::explicit(),
            &BackendSupport::registered(),
            &definitions,
            &exec,
        )
        .expect("the record is already registered, nothing to run");

        assert!(matches!(outcome, RegistrationOutcome::AlreadyRegistered(_)));
        assert_eq!(
            definitions.write_count(),
            1,
            "the missing unit is rewritten"
        );
        assert_eq!(exec.count(), 0);
    }

    #[test]
    fn an_unsupported_backend_names_the_foreground_and_touches_nothing() {
        let registration = registration();
        let definitions = MemDefinitions::default();
        let exec = RecordingExec::ok();
        let support = BackendSupport::unsupported("systemd-user-unavailable", "no user bus");
        assert!(!support.is_available());
        assert!(!support.is_registered());

        let outcome = ensure_registered(
            &registration,
            Consent::explicit(),
            &support,
            &definitions,
            &exec,
        )
        .expect("an unsupported backend is a foreground answer, not a failure");

        match outcome {
            RegistrationOutcome::Foreground(plan) => {
                assert_eq!(plan.component, COMPONENT);
                assert_eq!(plan.mechanism, ServiceKind::SystemdUserUnit);
                assert_eq!(plan.rule, "systemd-user-unavailable");
                assert_eq!(plan.observed, "no user bus");
                assert_eq!(plan.command, LINUX_FOREGROUND);
                assert!(plan.text().contains("foreground"));
            }
            other => panic!("expected Foreground, got {other:?}"),
        }
        assert_eq!(definitions.write_count(), 0);
        assert_eq!(definitions.contents(&unit_path()), None);
        assert_eq!(exec.count(), 0);
    }

    #[test]
    fn a_refused_backend_keeps_the_definition_for_the_next_attempt() {
        let registration = registration();
        let definitions = MemDefinitions::default();
        let exec = RecordingExec::failing(5);
        let error = ensure_registered(
            &registration,
            Consent::explicit(),
            &BackendSupport::available(),
            &definitions,
            &exec,
        )
        .expect_err("a non-zero backend exit must refuse");

        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(rule_of(&error), Some(REASON_REGISTRY_EXIT));
        assert_eq!(
            definitions.contents(&unit_path()).as_deref(),
            Some(registration.rendered()),
            "the definition is not destroyed when the backend refuses"
        );
        assert_eq!(exec.count(), 1, "the run stops at the first refusal");
    }

    #[test]
    fn removal_unloads_the_record_deletes_the_definition_and_is_idempotent() {
        let registration = registration();
        let definitions =
            MemDefinitions::holding(&registration.definition_path, registration.rendered());
        let exec = RecordingExec::ok();
        let outcome =
            remove_registered(&registration, &definitions, &exec).expect("removal succeeds");

        assert_eq!(outcome.as_str(), "removed");
        match &outcome {
            RemovalOutcome::Removed {
                definition_path, ..
            } => assert_eq!(definition_path, &unit_path()),
            other => panic!("expected Removed, got {other:?}"),
        }
        assert_eq!(exec.descriptions(), vec!["uninstall"]);
        assert_eq!(definitions.remove_count(), 1);
        assert_eq!(definitions.contents(&unit_path()), None);

        let second = remove_registered(&registration, &definitions, &exec)
            .expect("a second removal succeeds");
        assert!(matches!(second, RemovalOutcome::AlreadyRemoved { .. }));
        assert_eq!(second.as_str(), "already_removed");
        assert_eq!(exec.count(), 1, "a second removal runs no command");
        assert_eq!(definitions.remove_count(), 1);
    }

    #[test]
    fn a_refused_removal_keeps_the_definition() {
        let registration = registration();
        let definitions =
            MemDefinitions::holding(&registration.definition_path, registration.rendered());
        let exec = RecordingExec::failing(3);
        let error = remove_registered(&registration, &definitions, &exec)
            .expect_err("a non-zero backend exit must refuse the removal");

        assert_eq!(rule_of(&error), Some(REASON_REGISTRY_EXIT));
        assert_eq!(
            definitions.contents(&unit_path()).as_deref(),
            Some(registration.rendered()),
            "a refused unload must not delete the definition"
        );
        assert_eq!(definitions.remove_count(), 0);
    }

    #[test]
    fn a_definition_outside_the_owned_directory_is_refused() {
        let error =
            StartupRegistration::for_unit(&unit("/etc/systemd/user/axiom-graphd.service"), HOME)
                .expect_err("a definition outside the user unit directory must be refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(rule_of(&error), Some(REASON_FOREIGN_DEFINITION));
    }

    #[test]
    fn a_relative_definition_path_is_refused() {
        let error = StartupRegistration::for_unit(&unit("service/axiom-graphd.service"), HOME)
            .expect_err("a relative definition path must be refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(rule_of(&error), Some(REASON_UNSAFE_DEFINITION_PATH));
    }

    #[test]
    fn a_system_scoped_registration_is_refused() {
        let mut planned = unit(&unit_path());
        planned.scope = InstallScope::System;
        let error = StartupRegistration::for_unit(&planned, HOME)
            .expect_err("a system-scoped startup record must be refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule_of(&error), Some(REASON_UNSUPPORTED_SCOPE));
    }

    #[test]
    fn a_machine_wide_mechanism_is_refused() {
        let mut planned = unit(&unit_path());
        planned.mechanism = ServiceKind::SystemService;
        let error = StartupRegistration::for_unit(&planned, HOME)
            .expect_err("a machine-wide mechanism must be refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule_of(&error), Some(REASON_NOT_PER_USER_MECHANISM));
    }

    #[test]
    fn an_uninstallable_component_is_refused() {
        let mut planned = unit(&unit_path());
        planned.component = "rogue".to_owned();
        let error = StartupRegistration::for_unit(&planned, HOME)
            .expect_err("a component the CLI never installs must be refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(rule_of(&error), Some(REASON_UNKNOWN_COMPONENT));
    }

    #[test]
    fn an_empty_rendered_definition_is_refused() {
        let mut planned = unit(&unit_path());
        planned.text = "   \n".to_owned();
        let error = StartupRegistration::for_unit(&planned, HOME)
            .expect_err("a registration that renders nothing must be refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(rule_of(&error), Some(REASON_EMPTY_DEFINITION));
    }

    #[test]
    fn the_lifecycle_is_host_neutral_across_the_three_planned_definitions() {
        let task = windows::WindowsTaskDefinition {
            component: COMPONENT.to_owned(),
            task_name: format!("{}{COMPONENT}", windows::TASK_NAME_PREFIX),
            mechanism: windows::MECHANISM,
            scope: InstallScope::PerUser,
            trigger: StartupTrigger::Logon,
            restart: RestartPolicy::on_failure(5, 3),
            executable: r"C:\Axiom\versions\1.0.0\axiom-graphd.exe".to_owned(),
            args: vec!["serve".to_owned()],
            working_directory: r"C:\Axiom".to_owned(),
            log_file: r"C:\Axiom\logs\axiom-graphd.log".to_owned(),
            definition_path: r"C:\Axiom\service\axiom-graphd.xml".to_owned(),
            xml: "<Task/>".to_owned(),
        };
        let windows_registration = StartupRegistration::for_task(&task, r"C:\Axiom")
            .expect("the planned task is a valid per-user registration");
        assert_eq!(
            windows_registration.mechanism(),
            ServiceKind::PerUserStartup
        );
        assert_eq!(
            windows_registration.owned_root().replace('\\', "/"),
            "C:/Axiom/service",
            "the owned directory is the install root's service directory on any host"
        );
        assert_eq!(
            windows_registration.foreground_command(),
            WINDOWS_FOREGROUND
        );

        let agent = macos::LaunchAgent {
            component: COMPONENT.to_owned(),
            label: format!("{}{COMPONENT}", macos::LABEL_PREFIX),
            mechanism: macos::MECHANISM,
            scope: InstallScope::PerUser,
            trigger: StartupTrigger::Logon,
            restart: RestartPolicy::on_failure(5, 3),
            executable: "/Users/dev/axiom/versions/1.0.0/axiom-graphd".to_owned(),
            args: vec!["serve".to_owned()],
            working_directory: "/Users/dev/axiom".to_owned(),
            log_file: "/Users/dev/axiom/logs/axiom-graphd.log".to_owned(),
            plist_path: "/Users/dev/Library/LaunchAgents/com.axiom.axiom-graphd.plist".to_owned(),
            plist: "<plist/>".to_owned(),
        };
        let macos_registration = StartupRegistration::for_agent(&agent, "/Users/dev")
            .expect("the planned agent is a valid per-user registration");
        assert_eq!(macos_registration.mechanism(), ServiceKind::LaunchAgent);
        assert_eq!(macos_registration.foreground_command(), MACOS_FOREGROUND);
        assert_eq!(
            macos_registration.register_operations().len(),
            1,
            "one load command registers a launch agent"
        );
        assert_eq!(macos_registration.remove_operations().len(), 1);
    }

    #[test]
    fn the_host_ledger_reads_writes_and_removes_one_real_file() {
        let dir = std::env::temp_dir().join(format!("axiom-v2-022-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("the temp directory is creatable");
        let path = dir.join("axiom-graphd.service");
        let path = path.to_str().expect("the temp path is utf-8").to_owned();

        let ledger = SysDefinitions;
        assert_eq!(
            ledger.read(&path).expect("an absent file reads as None"),
            None
        );
        ledger.write(&path, "hello").expect("the file is writable");
        assert_eq!(
            ledger.read(&path).expect("the file is readable"),
            Some("hello".to_owned())
        );
        ledger
            .write(&path, "world")
            .expect("the file is rewritable");
        assert_eq!(
            ledger.read(&path).expect("the file is readable"),
            Some("world".to_owned())
        );
        ledger.remove(&path).expect("the file is removable");
        assert_eq!(ledger.read(&path).expect("the file is gone"), None);
        ledger
            .remove(&path)
            .expect("removing an absent file is not an error");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
