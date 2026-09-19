//! Planned uninstall of the runtime components one install owns (task E-012).
//!
//! `21-INSTALLATION.md` section I pins what an uninstall may and may not do: the
//! plan removes services, runtime components and owned bootstrap blocks
//! *separately*; project source, annotations, checkpoint JSON and user
//! instructions are preserved by default; credentials are revoked and
//! secure-deleted per OS policy; database and cache cleanup needs an explicit
//! option; an uninstall report is kept; and no other host's plugins or MCP
//! servers are removed.
//!
//! ## What this module guarantees (AC1)
//!
//! *Preserved by default.* [`plan_uninstall`] always states the four preserved
//! classes, and every removal it plans is checked against the paths the request
//! asked to preserve: a removal that equals or sits inside a preserved path is
//! refused as `preserved-path`. User data is never in a default plan: the
//! [`UninstallClass::UserData`] group exists only when the caller presents a
//! [`PurgeApproval`], which - like the service adapters' `Consent` - has a
//! private field and can only be produced by the deliberate call
//! [`PurgeApproval::explicit`], so a front end cannot purge user data by passing
//! a flag.
//!
//! *Only what this install owns.* Every removal must live in a directory this
//! install owns: runtime, credential and cache paths inside the install root,
//! and service definitions inside the directory the mechanism owns for that user
//! (the check is [`crate::service::control::ServiceOwnership::claim`], the same
//! ownership proof the control surface uses). A bootstrap block must carry this
//! CLI's own block marker, so a block in another tool's configuration cannot be
//! named into a plan at all - and because another host's plugin or MCP
//! configuration lives outside the install root and carries no `axiom:` block,
//! it is unreachable both ways.
//!
//! *The plan is not the deletion.* This module plans the removal, drives the
//! service controller to unregister the managed instances, and renders the
//! uninstall report. It has no file-removal path of its own, so nothing here can
//! delete user content: the files a plan names are removed by the CLI from the
//! reviewed plan. The plan's own report file is reserved and can never be listed
//! for removal.

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::is_absolute_host_path;
use serde::{Deserialize, Serialize};

use crate::discovery::ServiceKind;
use crate::service::control::{ControlRoots, ServiceOwnership};
use crate::service::{
    is_under, linux, macos, mechanism_wire, windows, InstalledService, ServiceExec,
    ServiceOperation, ServiceOutput,
};

/// Name of the uninstall report kept inside the install root.
pub const REPORT_FILE_NAME: &str = "uninstall-report.json";

/// Prefix of a bootstrap block this CLI wrote into a user-owned document.
pub const BLOCK_ID_PREFIX: &str = "axiom:";

/// Reason recorded when a required path is not an absolute host path.
pub const REASON_UNSAFE_PATH: &str = "unsafe-path";

/// Reason recorded when a removal is not inside a directory this install owns.
pub const REASON_OUTSIDE_OWNED_DIRECTORY: &str = "outside-owned-directory";

/// Reason recorded when user data is named for purging without the separate
/// explicit approval.
pub const REASON_PURGE_APPROVAL_REQUIRED: &str = "purge-approval-required";

/// Reason recorded when a bootstrap block is not one this CLI wrote.
pub const REASON_FOREIGN_BOOTSTRAP_BLOCK: &str = "foreign-bootstrap-block";

/// Reason recorded when a removal would touch a path the request preserves.
pub const REASON_PRESERVED_PATH: &str = "preserved-path";

/// Reason recorded when a removal names the plan's own report file.
pub const REASON_REPORT_PATH_RESERVED: &str = "report-path-reserved";

/// Reason recorded when a request names nothing to remove.
pub const REASON_NOTHING_TO_REMOVE: &str = "nothing-to-remove";

/// Reason recorded when the mechanism is not one the CLI manages.
pub const REASON_FOREIGN_MECHANISM: &str = "foreign-mechanism";

/// Reason recorded when the host controller exits non-zero.
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

/// Separate, explicit approval to purge user data.
///
/// The tuple field is private, so this token cannot be produced with a struct
/// literal: [`PurgeApproval::explicit`] is the only way to make one. It is
/// passed to [`plan_uninstall`] as its own argument rather than buried in the
/// request, so the approval is visible at the call site.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeApproval(());

impl PurgeApproval {
    /// The approval token, returned only from a deliberate call.
    #[must_use]
    pub const fn explicit() -> Self {
        Self(())
    }
}

/// Human content an uninstall preserves unless it is explicitly purged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Preserved {
    /// The user's project source trees.
    ProjectSource,
    /// Annotations the user made.
    Annotations,
    /// Checkpoint JSON written by the daemon.
    CheckpointJson,
    /// The user's own instructions to their agents.
    UserInstructions,
}

impl Preserved {
    /// Every preserved class, in reporting order.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::ProjectSource,
            Self::Annotations,
            Self::CheckpointJson,
            Self::UserInstructions,
        ]
    }

    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProjectSource => "project_source",
            Self::Annotations => "annotations",
            Self::CheckpointJson => "checkpoint_json",
            Self::UserInstructions => "user_instructions",
        }
    }
}

/// One bootstrap block this CLI wrote into a document it does not own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapBlock {
    /// Absolute host path of the document holding the block.
    pub path: String,
    /// The block's managed id, which must carry [`BLOCK_ID_PREFIX`].
    pub block_id: String,
}

/// One independently reviewable part of a removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UninstallClass {
    /// Managed service registrations, removed by unregistering them.
    Services,
    /// Installed runtime trees, removed by deleting them.
    Runtime,
    /// Owned blocks inside user-owned documents, removed by editing the block.
    Bootstrap,
    /// Local service credentials, revoked and secure-deleted per OS policy.
    Credentials,
    /// Database and cache state, purged only under the explicit option.
    Cache,
    /// User data, purged only under a separate explicit approval.
    UserData,
}

impl UninstallClass {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Services => "services",
            Self::Runtime => "runtime",
            Self::Bootstrap => "bootstrap",
            Self::Credentials => "credentials",
            Self::Cache => "cache",
            Self::UserData => "user_data",
        }
    }

    /// What the CLI does with the members of this group.
    #[must_use]
    pub const fn action(self) -> &'static str {
        match self {
            Self::Services => "unregister",
            Self::Runtime => "remove",
            Self::Bootstrap => "remove-block",
            Self::Credentials => "revoke-and-secure-delete",
            Self::Cache => "purge",
            Self::UserData => "purge",
        }
    }
}
/// One group of removals in a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalGroup {
    /// What kind of removal this is.
    pub class: UninstallClass,
    /// Absolute host paths the group removes, or the definitions it rewrites.
    pub files: Vec<String>,
    /// Host commands that unregister a managed instance, program plus argv.
    pub operations: Vec<ServiceOperation>,
}

impl RemovalGroup {
    /// An empty group, used when a class is not part of this plan.
    fn empty(class: UninstallClass) -> Self {
        Self {
            class,
            files: Vec::new(),
            operations: Vec::new(),
        }
    }

    /// Whether this group removes nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.operations.is_empty()
    }

    /// Machine-readable rendering of the group.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the group cannot be serialised.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        serde_json::to_string_pretty(self).map_err(|error| {
            AxiomError::new(ErrorCode::Internal, "the removal group is not serialisable")
                .with_detail("observed", error.to_string())
        })
    }

    /// One-line human rendering of the group.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = format!("{} ({})", self.class.as_str(), self.class.action());
        for file in &self.files {
            out.push_str("\n  file ");
            out.push_str(file);
        }
        for operation in &self.operations {
            out.push('\n');
            out.push_str(operation.text().trim_end());
        }
        out.push('\n');
        out
    }
}

/// Everything one uninstall request knows it owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UninstallRequest {
    /// Absolute host path of the install root.
    pub install_root: String,
    /// Absolute host path of the user's home directory.
    pub home: String,
    /// The managed services to unregister.
    pub services: Vec<InstalledService>,
    /// Absolute host paths of the installed runtime trees.
    pub runtime_paths: Vec<String>,
    /// The owned bootstrap blocks to remove.
    pub bootstrap_blocks: Vec<BootstrapBlock>,
    /// Absolute host paths of the local credential state.
    pub credential_paths: Vec<String>,
    /// Absolute host paths of database and cache state.
    pub cache_paths: Vec<String>,
    /// Whether the explicit cache/DB cleanup option was given.
    pub purge_caches: bool,
    /// Absolute host paths the caller asks to purge.
    pub purge_paths: Vec<String>,
    /// Whether the caller asks to purge user data.
    pub purge_data: bool,
    /// Absolute host paths that must survive this uninstall.
    pub preserve_paths: Vec<String>,
}

impl UninstallRequest {
    /// An uninstall request for one install root and one user, planning only the
    /// default removal classes.
    #[must_use]
    pub fn new(install_root: impl Into<String>, home: impl Into<String>) -> Self {
        Self {
            install_root: install_root.into(),
            home: home.into(),
            services: Vec::new(),
            runtime_paths: Vec::new(),
            bootstrap_blocks: Vec::new(),
            credential_paths: Vec::new(),
            cache_paths: Vec::new(),
            purge_caches: false,
            purge_paths: Vec::new(),
            purge_data: false,
            preserve_paths: Vec::new(),
        }
    }

    /// The managed services to unregister.
    #[must_use]
    pub fn with_services(mut self, services: Vec<InstalledService>) -> Self {
        self.services = services;
        self
    }

    /// The installed runtime trees to remove.
    #[must_use]
    pub fn with_runtime_paths(mut self, runtime_paths: Vec<String>) -> Self {
        self.runtime_paths = runtime_paths;
        self
    }

    /// The owned bootstrap blocks to remove.
    #[must_use]
    pub fn with_bootstrap_blocks(mut self, blocks: Vec<BootstrapBlock>) -> Self {
        self.bootstrap_blocks = blocks;
        self
    }

    /// The local credential state to revoke and secure-delete.
    #[must_use]
    pub fn with_credential_paths(mut self, credential_paths: Vec<String>) -> Self {
        self.credential_paths = credential_paths;
        self
    }

    /// The database and cache state, purged only with the explicit option.
    #[must_use]
    pub fn with_cache_paths(mut self, cache_paths: Vec<String>) -> Self {
        self.cache_paths = cache_paths;
        self
    }

    /// Ask for the explicit database/cache cleanup.
    #[must_use]
    pub const fn with_cache_purge(mut self, purge_caches: bool) -> Self {
        self.purge_caches = purge_caches;
        self
    }

    /// Ask to purge user data; requires a [`PurgeApproval`] to plan.
    #[must_use]
    pub fn with_data_purge(mut self, purge_paths: Vec<String>) -> Self {
        self.purge_paths = purge_paths;
        self.purge_data = true;
        self
    }

    /// Paths that must survive this uninstall.
    #[must_use]
    pub fn with_preserve_paths(mut self, preserve_paths: Vec<String>) -> Self {
        self.preserve_paths = preserve_paths;
        self
    }
}

/// A reviewed uninstall plan, and the report of what it preserves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UninstallPlan {
    /// Absolute host path of the install root.
    pub install_root: String,
    /// The uninstall report path, reserved and never removed by this plan.
    pub report_path: String,
    /// The independently reviewable removal groups, in report order.
    pub groups: Vec<RemovalGroup>,
    /// The human content classes this plan preserves.
    pub preserved: Vec<Preserved>,
    /// The concrete paths this plan preserves.
    pub preserved_paths: Vec<String>,
}

impl UninstallPlan {
    /// One removal group, when this plan has it.
    #[must_use]
    pub fn group(&self, class: UninstallClass) -> Option<&RemovalGroup> {
        self.groups.iter().find(|group| group.class == class)
    }

    /// Whether this plan removes anything in one class.
    #[must_use]
    pub fn removes(&self, class: UninstallClass) -> bool {
        self.group(class).is_some_and(|group| !group.is_empty())
    }

    /// Whether this plan preserves one class of human content.
    #[must_use]
    pub fn preserves(&self, class: Preserved) -> bool {
        self.preserved.contains(&class)
    }

    /// Every absolute host path this plan removes.
    #[must_use]
    pub fn files(&self) -> Vec<String> {
        self.groups
            .iter()
            .flat_map(|group| group.files.iter().cloned())
            .collect()
    }

    /// Machine-readable rendering of the plan.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the plan cannot be serialised.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        serde_json::to_string_pretty(self).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the uninstall plan is not serialisable",
            )
            .with_detail("observed", error.to_string())
        })
    }

    /// One-line human rendering of the plan.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = format!("uninstall {}\n", self.install_root);
        for class in Preserved::all() {
            if self.preserves(class) {
                out.push_str("preserve ");
                out.push_str(class.as_str());
                out.push('\n');
            }
        }
        for group in &self.groups {
            if group.is_empty() {
                continue;
            }
            out.push_str(&group.text());
        }
        out.push_str(&format!("report {}\n", self.report_path));
        out
    }
}
/// The unregister command and the definition files of one owned service.
///
/// # Errors
/// Whatever [`ServiceOwnership::claim`] refuses - an unknown component, a name
/// that is not the component's, a non-per-user scope, an unmanaged mechanism or
/// a definition outside the mechanism's own directory - and
/// [ErrorCode::Forbidden] for an unmanaged mechanism.
fn service_removal(
    service: &InstalledService,
    roots: &ControlRoots,
) -> Result<(Vec<ServiceOperation>, Vec<String>), AxiomError> {
    let ownership = ServiceOwnership::claim(service, roots)?;
    let files = vec![ownership.definition_path.clone()];
    match ownership.mechanism {
        ServiceKind::PerUserStartup => Ok((
            vec![windows::uninstall_operation(&ownership.owned_name)?],
            files,
        )),
        ServiceKind::SystemdUserUnit => Ok((
            vec![linux::uninstall_operation(&ownership.owned_name)?],
            files,
        )),
        ServiceKind::LaunchAgent => {
            let removal = macos::plan_removal(
                &ownership.owned_name,
                &ownership.definition_path,
                &roots.home,
            )?;
            Ok((removal.operations, removal.files))
        }
        ServiceKind::SystemService => Err(refuse(
            ErrorCode::Forbidden,
            REASON_FOREIGN_MECHANISM,
            mechanism_wire(ownership.mechanism),
            "a system service is not managed by this CLI",
        )),
    }
}

/// Refuse a path that is not absolute, or is not inside a directory this install
/// owns, or is the plan's own report file.
fn guard_owned_path(path: &str, root: &str, report_path: &str) -> Result<String, AxiomError> {
    if !is_absolute_host_path(path) {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_UNSAFE_PATH,
            path,
            "the path must be absolute for this host",
        ));
    }
    if !is_under(root, path) {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_OUTSIDE_OWNED_DIRECTORY,
            path,
            "the path must live inside a directory this install owns",
        ));
    }
    if normalise_path(path) == normalise_path(report_path) {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_REPORT_PATH_RESERVED,
            path,
            "the uninstall report is kept, never removed",
        ));
    }
    Ok(path.to_owned())
}

/// Refuse a removal that would touch a path the request preserves.
fn guard_preserved(path: &str, preserve_paths: &[String]) -> Result<(), AxiomError> {
    for preserved in preserve_paths {
        if normalise_path(path) == normalise_path(preserved) || is_under(preserved, path) {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_PRESERVED_PATH,
                path,
                "the removal would touch a path this request preserves",
            ));
        }
    }
    Ok(())
}

/// Plan one uninstall from the state this install owns.
///
/// The plan always states the four preserved classes. A request that asks to
/// purge user data without presenting a [`PurgeApproval`] is refused, so user
/// data can never appear in a plan a human did not separately approve.
///
/// # Errors
/// [ErrorCode::Forbidden] when user data is named for purging without the
/// separate approval; [ErrorCode::ValidationError] for a relative path, a
/// removal outside a directory this install owns, a bootstrap block without this
/// CLI's marker, a removal of a preserved path or of the report file, and a
/// request that names nothing to remove.
pub fn plan_uninstall(
    request: &UninstallRequest,
    approval: Option<&PurgeApproval>,
) -> Result<UninstallPlan, AxiomError> {
    if !is_absolute_host_path(&request.install_root) {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_UNSAFE_PATH,
            &request.install_root,
            "the install root must be absolute for this host",
        ));
    }
    if request.purge_data && approval.is_none() {
        return Err(refuse(
            ErrorCode::Forbidden,
            REASON_PURGE_APPROVAL_REQUIRED,
            &request.install_root,
            "purging user data needs a separate explicit approval",
        ));
    }
    for preserved in &request.preserve_paths {
        if !is_absolute_host_path(preserved) {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_UNSAFE_PATH,
                preserved,
                "a preserved path must be absolute for this host",
            ));
        }
    }
    let report_path = crate::install::plan::under(&request.install_root, &[REPORT_FILE_NAME]);

    let mut groups: Vec<RemovalGroup> = Vec::new();

    let mut services = RemovalGroup::empty(UninstallClass::Services);
    let roots = ControlRoots::new(&request.install_root, &request.home);
    for service in &request.services {
        let (operations, files) = service_removal(service, &roots)?;
        services.operations.extend(operations);
        services.files.extend(files);
    }
    groups.push(services);

    let mut runtime = RemovalGroup::empty(UninstallClass::Runtime);
    for path in &request.runtime_paths {
        runtime
            .files
            .push(guard_owned_path(path, &request.install_root, &report_path)?);
    }
    groups.push(runtime);

    let mut bootstrap = RemovalGroup::empty(UninstallClass::Bootstrap);
    for block in &request.bootstrap_blocks {
        if !is_absolute_host_path(&block.path) {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_UNSAFE_PATH,
                &block.path,
                "the document must be an absolute path for this host",
            ));
        }
        let Some(block_id) = block.block_id.strip_prefix(BLOCK_ID_PREFIX) else {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_FOREIGN_BOOTSTRAP_BLOCK,
                &block.block_id,
                "the block is not one this CLI wrote",
            ));
        };
        if block_id.trim().is_empty() {
            return Err(refuse(
                ErrorCode::ValidationError,
                REASON_FOREIGN_BOOTSTRAP_BLOCK,
                &block.block_id,
                "the block is not one this CLI wrote",
            ));
        }
        bootstrap.files.push(block.path.clone());
    }
    groups.push(bootstrap);

    let mut credentials = RemovalGroup::empty(UninstallClass::Credentials);
    for path in &request.credential_paths {
        credentials
            .files
            .push(guard_owned_path(path, &request.install_root, &report_path)?);
    }
    groups.push(credentials);

    let mut cache = RemovalGroup::empty(UninstallClass::Cache);
    if request.purge_caches {
        for path in &request.cache_paths {
            cache
                .files
                .push(guard_owned_path(path, &request.install_root, &report_path)?);
        }
    }
    groups.push(cache);

    let mut user_data = RemovalGroup::empty(UninstallClass::UserData);
    if request.purge_data {
        for path in &request.purge_paths {
            if !is_absolute_host_path(path) {
                return Err(refuse(
                    ErrorCode::ValidationError,
                    REASON_UNSAFE_PATH,
                    path,
                    "a purge path must be absolute for this host",
                ));
            }
            user_data.files.push(path.clone());
        }
    }
    groups.push(user_data);

    for group in &groups {
        for path in &group.files {
            guard_preserved(path, &request.preserve_paths)?;
        }
    }

    if groups.iter().all(RemovalGroup::is_empty) {
        return Err(refuse(
            ErrorCode::ValidationError,
            REASON_NOTHING_TO_REMOVE,
            &request.install_root,
            "the request names nothing this install can remove",
        ));
    }

    Ok(UninstallPlan {
        install_root: request.install_root.clone(),
        report_path,
        groups,
        preserved: Preserved::all().to_vec(),
        preserved_paths: request.preserve_paths.clone(),
    })
}

/// What one executed uninstall did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UninstallOutcome {
    /// Absolute host path of the install root.
    pub install_root: String,
    /// Where the CLI writes the uninstall report.
    pub report_path: String,
    /// The removal groups, in report order.
    pub groups: Vec<RemovalGroup>,
    /// The human content classes this uninstall preserved.
    pub preserved: Vec<Preserved>,
    /// The controller's exit code, or `0` when no controller ran.
    pub code: i32,
    /// Captured standard error of the last controller invocation.
    pub stderr: String,
}

impl UninstallOutcome {
    /// Whether the controller reported success.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        self.code == 0
    }

    /// The uninstall report, which the CLI keeps at [`Self::report_path`].
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the report cannot be serialised.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        serde_json::to_string_pretty(self).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the uninstall report is not serialisable",
            )
            .with_detail("observed", error.to_string())
        })
    }
}

/// Drive the service controller for one planned uninstall.
///
/// The controller unregisters the managed instances; the file removals named by
/// the plan are performed by the CLI from the reviewed plan, which is why this
/// function has no file-removal path.
///
/// # Errors
/// Whatever [`ServiceExec`] refuses, and [ErrorCode::Internal] when the host
/// controller exits non-zero.
pub fn run_uninstall(
    plan: &UninstallPlan,
    exec: &impl ServiceExec,
) -> Result<UninstallOutcome, AxiomError> {
    let mut outcome = UninstallOutcome {
        install_root: plan.install_root.clone(),
        report_path: plan.report_path.clone(),
        groups: plan.groups.clone(),
        preserved: plan.preserved.clone(),
        code: 0,
        stderr: String::new(),
    };
    for group in &plan.groups {
        for operation in &group.operations {
            let ServiceOutput { code, stderr, .. } = exec.run(operation)?;
            outcome.code = code;
            outcome.stderr = stderr;
            if code != 0 {
                return Err(refuse(
                    ErrorCode::Internal,
                    REASON_CONTROLLER_EXIT,
                    &code.to_string(),
                    &format!(
                        "the host controller did not unregister the instance: {}",
                        outcome.stderr.trim(),
                    ),
                ));
            }
        }
    }
    Ok(outcome)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const ROOT: &str = "/srv/axiom";
    const HOME: &str = "/home/billy";
    const UNIT: &str = "/home/billy/.config/systemd/user/axiom-graphd.service";
    const RUNTIME: &str = "/srv/axiom/versions/1.0.0";
    const SOURCE: &str = "/home/billy/projects/demo";

    fn linux_service() -> InstalledService {
        InstalledService {
            component: "axiom-graphd".to_owned(),
            task_name: "axiom-graphd.service".to_owned(),
            mechanism: ServiceKind::SystemdUserUnit,
            scope: crate::install::plan::InstallScope::PerUser,
            definition_path: UNIT.to_owned(),
            log_file: "/srv/axiom/logs/axiom-graphd.log".to_owned(),
            restart: crate::service::RestartPolicy::never(),
        }
    }

    fn windows_service(task_name: &str, definition_path: &str) -> InstalledService {
        InstalledService {
            component: "axiom-graphd".to_owned(),
            task_name: task_name.to_owned(),
            mechanism: ServiceKind::PerUserStartup,
            scope: crate::install::plan::InstallScope::PerUser,
            definition_path: definition_path.to_owned(),
            log_file: "/srv/axiom/logs/axiom-graphd.log".to_owned(),
            restart: crate::service::RestartPolicy::never(),
        }
    }

    fn sample() -> UninstallRequest {
        UninstallRequest::new(ROOT, HOME)
            .with_services(vec![linux_service()])
            .with_runtime_paths(vec![RUNTIME.to_owned()])
            .with_bootstrap_blocks(vec![BootstrapBlock {
                path: "/home/billy/AGENTS.md".to_owned(),
                block_id: "axiom:agents-v1".to_owned(),
            }])
            .with_credential_paths(vec!["/srv/axiom/credentials/index.json".to_owned()])
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
                    stderr: "Failed to disable unit".to_owned(),
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
    fn a_default_plan_separates_the_removal_classes_and_preserves_user_content() {
        let plan = plan_uninstall(&sample(), None).expect("the default plan is accepted");
        assert_eq!(plan.install_root, ROOT);
        assert_eq!(plan.report_path, "/srv/axiom/uninstall-report.json");
        for class in Preserved::all() {
            assert!(plan.preserves(class), "{} is preserved", class.as_str());
        }

        let services = plan
            .group(UninstallClass::Services)
            .expect("a services group exists");
        assert_eq!(services.files, vec![UNIT.to_owned()]);
        assert_eq!(
            services.operations[0].args,
            vec!["--user", "disable", "--now", "axiom-graphd.service"]
        );
        let runtime = plan
            .group(UninstallClass::Runtime)
            .expect("a runtime group");
        assert_eq!(runtime.files, vec![RUNTIME.to_owned()]);
        assert!(runtime.operations.is_empty());
        let bootstrap = plan
            .group(UninstallClass::Bootstrap)
            .expect("a bootstrap group");
        assert_eq!(bootstrap.files, vec!["/home/billy/AGENTS.md".to_owned()]);
        let credentials = plan
            .group(UninstallClass::Credentials)
            .expect("a credentials group");
        assert_eq!(
            credentials.files,
            vec!["/srv/axiom/credentials/index.json".to_owned()]
        );
        assert_eq!(credentials.class.action(), "revoke-and-secure-delete");
    }

    #[test]
    fn a_default_plan_removes_no_cache_and_no_user_data() {
        let request = sample()
            .with_cache_paths(vec!["/srv/axiom/cache/graph.db".to_owned()])
            .with_data_purge(vec![SOURCE.to_owned()]);
        let approval = PurgeApproval::explicit();
        let plan = plan_uninstall(&request, Some(&approval)).expect("accepted");
        assert!(plan.removes(UninstallClass::UserData));
        assert!(!plan.removes(UninstallClass::Cache));

        let plan = plan_uninstall(
            &sample().with_cache_paths(vec!["/srv/axiom/cache/graph.db".to_owned()]),
            None,
        )
        .expect("accepted");
        assert!(!plan.removes(UninstallClass::Cache));
    }

    #[test]
    fn cache_state_is_purged_only_under_the_explicit_option() {
        let request = sample()
            .with_cache_paths(vec!["/srv/axiom/cache/graph.db".to_owned()])
            .with_cache_purge(true);
        let plan = plan_uninstall(&request, None).expect("accepted");
        let cache = plan.group(UninstallClass::Cache).expect("a cache group");
        assert_eq!(cache.files, vec!["/srv/axiom/cache/graph.db".to_owned()]);
        assert_eq!(cache.class.action(), "purge");
    }

    #[test]
    fn purging_user_data_without_separate_approval_is_refused() {
        let request = sample().with_data_purge(vec![SOURCE.to_owned()]);
        let error = plan_uninstall(&request, None).expect_err("an unapproved purge is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule(&error), REASON_PURGE_APPROVAL_REQUIRED);

        let approval = PurgeApproval::explicit();
        let plan =
            plan_uninstall(&request, Some(&approval)).expect("the approved purge is planned");
        let user_data = plan
            .group(UninstallClass::UserData)
            .expect("a user data group");
        assert_eq!(user_data.files, vec![SOURCE.to_owned()]);
        assert!(plan.preserves(Preserved::ProjectSource));
    }

    #[test]
    fn a_removal_outside_the_install_root_is_refused() {
        for path in [
            "/home/billy/projects/demo/notes.txt",
            "/etc/axiom/other.json",
            "cache/graph.db",
            "/Users/billy/.config/claude/mcp.json",
        ] {
            let error = plan_uninstall(&sample().with_runtime_paths(vec![path.to_owned()]), None)
                .expect_err("a foreign path is refused");
            assert_eq!(error.code(), ErrorCode::ValidationError);
            assert!(matches!(
                rule(&error).as_str(),
                "outside-owned-directory" | "unsafe-path"
            ));
        }
    }

    #[test]
    fn a_bootstrap_block_this_cli_did_not_write_is_refused() {
        for block_id in ["claude:mcp", "agents-v1", "axiom:", "axiom:  "] {
            let request = sample().with_bootstrap_blocks(vec![BootstrapBlock {
                path: "/home/billy/.claude/mcp.json".to_owned(),
                block_id: block_id.to_owned(),
            }]);
            let error = plan_uninstall(&request, None).expect_err("a foreign block is refused");
            assert_eq!(error.code(), ErrorCode::ValidationError);
            assert_eq!(rule(&error), REASON_FOREIGN_BOOTSTRAP_BLOCK);
        }
    }

    #[test]
    fn a_removal_of_a_preserved_path_is_refused() {
        for path in [
            "/srv/axiom/versions/1.0.0",
            "/srv/axiom/versions/1.0.0/bin/graphd",
        ] {
            let request = sample()
                .with_runtime_paths(vec![path.to_owned()])
                .with_preserve_paths(vec![
                    "/home/billy/projects/demo".to_owned(),
                    "/srv/axiom/versions/1.0.0".to_owned(),
                ]);
            let error = plan_uninstall(&request, None).expect_err("a preserved path is refused");
            assert_eq!(error.code(), ErrorCode::ValidationError);
            assert_eq!(rule(&error), REASON_PRESERVED_PATH);
        }
    }

    #[test]
    fn a_preserved_path_must_be_absolute() {
        let request = sample().with_preserve_paths(vec!["projects/demo".to_owned()]);
        let error = plan_uninstall(&request, None).expect_err("a relative preserve is refused");
        assert_eq!(rule(&error), REASON_UNSAFE_PATH);
    }

    #[test]
    fn the_uninstall_report_is_kept_and_cannot_be_removed() {
        let plan = plan_uninstall(&sample(), None).expect("accepted");
        assert!(!plan.files().contains(&plan.report_path));
        let json = plan.to_json().expect("the plan serialises");
        assert!(json.contains("\"report_path\": \"/srv/axiom/uninstall-report.json\""));

        let error = plan_uninstall(
            &sample().with_runtime_paths(vec!["/srv/axiom/uninstall-report.json".to_owned()]),
            None,
        )
        .expect_err("the report path is reserved");
        assert_eq!(rule(&error), REASON_REPORT_PATH_RESERVED);
    }

    #[test]
    fn a_request_that_names_nothing_is_refused() {
        let error = plan_uninstall(&UninstallRequest::new(ROOT, HOME), None)
            .expect_err("an empty request is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(rule(&error), REASON_NOTHING_TO_REMOVE);

        let error = plan_uninstall(&UninstallRequest::new("srv/axiom", HOME), None)
            .expect_err("a relative install root is refused");
        assert_eq!(rule(&error), REASON_UNSAFE_PATH);
    }

    #[test]
    fn the_unregister_command_matches_each_mechanism() {
        let request = UninstallRequest::new(ROOT, HOME).with_services(vec![windows_service(
            "Axiom\\axiom-graphd",
            "/srv/axiom/service/axiom-graphd.task.xml",
        )]);
        let plan = plan_uninstall(&request, None).expect("accepted");
        let services = plan
            .group(UninstallClass::Services)
            .expect("a services group");
        assert_eq!(services.operations[0].program, windows::SCHEDULER_PROGRAM);
        assert_eq!(
            services.operations[0].args,
            vec!["/delete", "/tn", "Axiom\\axiom-graphd", "/f"]
        );
        assert_eq!(
            services.files,
            vec!["/srv/axiom/service/axiom-graphd.task.xml".to_owned()]
        );
    }

    #[test]
    fn a_service_that_is_not_this_installs_is_refused() {
        let error = plan_uninstall(
            &UninstallRequest::new(ROOT, HOME).with_services(vec![windows_service(
                "Axiom\\axiom-mcp",
                "/srv/axiom/service/axiom-graphd.task.xml",
            )]),
            None,
        )
        .expect_err("a mismatched name is refused");
        assert_eq!(rule(&error), "ownership-mismatch");

        let error = plan_uninstall(
            &UninstallRequest::new(ROOT, HOME).with_services(vec![windows_service(
                "Axiom\\axiom-graphd",
                "/etc/axiom/axiom-graphd.task.xml",
            )]),
            None,
        )
        .expect_err("a foreign definition is refused");
        assert_eq!(rule(&error), "definition-outside-owned-directory");
    }

    #[test]
    fn a_non_user_scope_service_is_refused() {
        let mut service = linux_service();
        service.scope = crate::install::plan::InstallScope::System;
        let error = plan_uninstall(
            &UninstallRequest::new(ROOT, HOME).with_services(vec![service]),
            None,
        )
        .expect_err("a system instance is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule(&error), "unsupported-scope");
    }

    #[test]
    fn an_uninstall_unregisters_only_the_owned_service_and_renders_the_report() {
        let plan = plan_uninstall(&sample(), None).expect("accepted");
        let exec = RecordingExec::succeeding();
        let outcome = run_uninstall(&plan, &exec).expect("the uninstall runs");
        assert!(outcome.succeeded());
        let recorded = exec.operations.borrow();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].description, "uninstall");
        assert_eq!(
            recorded[0].args,
            vec!["--user", "disable", "--now", "axiom-graphd.service"]
        );

        let report = outcome.to_json().expect("the report serialises");
        assert!(report.contains("\"report_path\": \"/srv/axiom/uninstall-report.json\""));
        assert!(report.contains("\"project_source\""));
        assert_eq!(outcome.preserved, Preserved::all().to_vec());
    }

    #[test]
    fn a_non_zero_controller_exit_is_refused() {
        let plan = plan_uninstall(&sample(), None).expect("accepted");
        let exec = RecordingExec::failing(1);
        let error = run_uninstall(&plan, &exec).expect_err("a refused unregister is an error");
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(rule(&error), REASON_CONTROLLER_EXIT);
    }

    #[test]
    fn an_empty_class_is_not_reported_as_removed() {
        let plan = plan_uninstall(&sample(), None).expect("accepted");
        assert!(plan.removes(UninstallClass::Services));
        assert!(plan.removes(UninstallClass::Runtime));
        assert!(plan.removes(UninstallClass::Bootstrap));
        assert!(plan.removes(UninstallClass::Credentials));
        assert!(!plan.removes(UninstallClass::Cache));
        assert!(!plan.removes(UninstallClass::UserData));
        let text = plan.text();
        assert!(text.contains("preserve project_source"));
        assert!(text.contains("report /srv/axiom/uninstall-report.json"));
        assert!(!text.contains("cache (purge)"));
    }
}
