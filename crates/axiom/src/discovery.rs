//! Read-only discovery of an existing Axiom installation (task E-003).
//!
//! `axiom doctor --all --json` has to answer "what is installed, who owns the
//! service, which paths are usable" *before* anything is installed, updated or
//! repaired, and `docs/16-CLI-AND-CONTROL-API.md` section 4 pins the answer as
//! diagnostics with **no automatic repair**. This module is that observation
//! layer and nothing else: it detects the installed component versions, the
//! install roots, the service definitions and their owner, and the access it has
//! to the paths it will need, and it reports a missing privilege as an
//! actionable finding instead of changing the machine.
//!
//! The read-only guarantee is structural rather than a promise:
//!
//! * Every host read goes through [`ReadOnlyProbe`], whose whole surface is
//!   observe/read. There is no create, write, rename, delete, chmod, launch or
//!   network method to call, so the engine cannot mutate the host, even by
//!   accident.
//! * Access is *observed*, never probed by writing a sentinel file: a denied
//!   path is reported, not tested with a write.
//! * The one real probe, [`LocalProbe`], only uses `symlink_metadata`,
//!   `metadata` and a bounded read-only `File::open`.
//!
//! Two rules from the installation contract shape the findings. The default
//! install is per-user and never elevates, so a *system*-scoped service
//! definition is reported (owner `system`) rather than adopted; and a missing
//! home, a denied path or a malformed install record is a finding with a
//! concrete next step, never a silent repair.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{classify_storage_lexically, AxiomHome, PathEnvironment, Platform};
use serde::{Deserialize, Serialize};

use crate::version::SPEC_VERSION;

/// Schema version of the discovery report this build emits.
pub const DISCOVERY_SCHEMA_VERSION: u32 = 1;

/// Components that can be installed and serviced by the `axiom` CLI.
///
/// `docs/16-CLI-AND-CONTROL-API.md` section 4 names `axiom-graphd` and
/// `axiom-mcp` for `service`/`start`/`stop`/`status`/`uninstall` and installs
/// the CLI itself, so these three are the installable set. Every one is a
/// member of the frozen [`COMPONENTS`] vocabulary from the version report.
pub const INSTALLABLE_COMPONENTS: [&str; 3] = ["axiom-graphd", "axiom-mcp", "axiom"];

/// Per-component install record read by discovery.
pub const VERSION_FILE: &str = "version.json";

/// Upper bound on the bytes discovery will read from a component install record.
pub const MAX_VERSION_FILE_BYTES: u64 = 64 * 1024;

/// What discovery could observe about one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// The path does not exist. Not a failure: nothing is installed yet.
    Missing,
    /// The path exists and could be read.
    Readable,
    /// The path exists but the current user may not read it.
    Denied,
}

impl Access {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Readable => "readable",
            Self::Denied => "denied",
        }
    }
}

/// Access the installer will need to a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    /// The installer only reads it.
    Read,
    /// The installer creates or updates state under it.
    Write,
}

/// Kind of service definition that owns a component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceKind {
    /// Windows per-user managed startup record.
    PerUserStartup,
    /// systemd user unit.
    SystemdUserUnit,
    /// macOS per-user LaunchAgent.
    LaunchAgent,
    /// A system-scoped unit, task or daemon owned by the administrator.
    SystemService,
}

/// Who owns an installed service definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceOwner {
    /// Owned by the current user; the default install scope.
    PerUser,
    /// Owned by the administrator; an explicit, non-default scope.
    System,
    /// No definition was found for this component.
    Absent,
}
/// One installable component and the version discovery found installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentState {
    /// Component name from [`INSTALLABLE_COMPONENTS`].
    pub component: String,
    /// Install root discovery looked in.
    pub install_root: String,
    /// Access observed at the install root.
    pub access: Access,
    /// Version recorded by the installed component, when readable.
    pub installed_version: Option<String>,
    /// Build revision recorded by the installed component, when readable.
    pub installed_revision: Option<String>,
}

/// One component service definition discovery found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceState {
    /// Component the definition belongs to.
    pub component: String,
    /// Kind of definition, or [`ServiceKind::SystemService`] for a system scope.
    pub kind: ServiceKind,
    /// Owner of the definition the component is installed under.
    pub owner: ServiceOwner,
    /// Definition path, when a definition exists.
    pub definition_path: Option<String>,
}

/// One path discovery needs, with the access it observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathState {
    /// Stable role name (`axiom_home`, `installs`, `run`, `logs`, `secrets`).
    pub role: String,
    /// Absolute host path.
    pub path: String,
    /// Access observed.
    pub access: Access,
    /// Access the installer will need.
    pub requirement: Requirement,
    /// Lexical storage class of the path, when it was classified.
    pub storage_class: Option<String>,
}

/// Machine-readable reason for one discovery finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCode {
    /// `AXIOM_HOME` (or the platform default) could not be resolved.
    HomeUnresolved,
    /// The resolved home does not exist yet; nothing is installed there.
    HomeMissing,
    /// The current user may not read a path discovery needs.
    PermissionDenied,
    /// A component install record could not be read as a version object.
    MalformedState,
    /// A system-scoped service definition owns a component.
    SystemScopedService,
    /// The resolved home is not safe to hold mutable state.
    UnsafeStorage,
}

/// One actionable discovery finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// Machine-readable reason.
    pub code: FindingCode,
    /// Path role the finding belongs to, when the finding is path-scoped.
    pub role: Option<String>,
    /// Path the finding names, when known.
    pub path: Option<String>,
    /// Access observed at the path, or [`Access::Missing`] when not path-scoped.
    pub observed: Access,
    /// The concrete next step for the operator. Never empty.
    pub remediation: String,
}

/// The discovery report: what is installed and what discovery could observe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryReport {
    /// Report schema version.
    pub schema_version: u32,
    /// Specification baseline this build implements.
    pub spec_version: String,
    /// Always `true`: discovery observes and never modifies.
    pub read_only: bool,
    /// Resolved `AXIOM_HOME`, when it could be resolved.
    pub home: Option<String>,
    /// Installable components, in [`INSTALLABLE_COMPONENTS`] order.
    pub components: Vec<ComponentState>,
    /// Service definitions, in component order.
    pub services: Vec<ServiceState>,
    /// Paths the installer needs, in role order.
    pub paths: Vec<PathState>,
    /// Findings, in a deterministic order.
    pub findings: Vec<Finding>,
}
impl DiscoveryReport {
    /// True when discovery found nothing that blocks an install.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.findings.is_empty()
    }

    /// Refuse a report that violates the emitted contract.
    ///
    /// # Errors
    ///
    /// Fails closed when the report is not schema version
    /// [`DISCOVERY_SCHEMA_VERSION`], when it claims to have modified something,
    /// when its spec baseline is not this build's, or when a finding carries no
    /// remediation.
    pub fn validate(&self) -> Result<(), AxiomError> {
        if self.schema_version != DISCOVERY_SCHEMA_VERSION {
            return Err(AxiomError::new(
                ErrorCode::Internal,
                "the discovery report carries an unsupported schema version",
            )
            .with_detail("expected", DISCOVERY_SCHEMA_VERSION.to_string())
            .with_detail("actual", self.schema_version.to_string()));
        }
        if !self.read_only {
            return Err(AxiomError::new(
                ErrorCode::Internal,
                "discovery is read-only and must report read_only true",
            )
            .with_detail("observed", self.read_only.to_string()));
        }
        if self.spec_version != SPEC_VERSION {
            return Err(AxiomError::new(
                ErrorCode::Internal,
                "the discovery report violates the specification baseline",
            )
            .with_detail("expected", SPEC_VERSION)
            .with_detail("actual", &self.spec_version));
        }
        for finding in &self.findings {
            if finding.remediation.trim().is_empty() {
                return Err(AxiomError::new(
                    ErrorCode::Internal,
                    "every discovery finding carries an actionable remediation",
                )
                .with_detail("rule", "finding_remediation_not_empty"));
            }
        }
        Ok(())
    }

    /// One compact JSON line for `--json` mode.
    ///
    /// # Errors
    ///
    /// Fails closed through [`Self::validate`], then on a serialisation defect.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        self.validate()?;
        serde_json::to_string(self).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the discovery report is not serialisable",
            )
            .with_detail("observed", error.to_string())
        })
    }

    /// A short human summary, one line per component, service, path and finding.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::new();
        out.push_str(if self.ok() {
            "installation ok"
        } else {
            "installation has findings"
        });
        out.push('\n');
        match self.home.as_deref() {
            Some(home) => out.push_str(&format!("home: {home}\n")),
            None => out.push_str("home: unresolved\n"),
        }
        for component in &self.components {
            out.push_str(&format!(
                "component: {} version={} access={}\n",
                component.component,
                component.installed_version.as_deref().unwrap_or("-"),
                component.access.as_str(),
            ));
        }
        for service in &self.services {
            out.push_str(&format!(
                "service: {} owner={:?} kind={:?}\n",
                service.component, service.owner, service.kind
            ));
        }
        for path in &self.paths {
            out.push_str(&format!(
                "path: {} {} access={}\n",
                path.role,
                path.path,
                path.access.as_str(),
            ));
        }
        for finding in &self.findings {
            out.push_str(&format!(
                "finding: {:?} role={} path={}\n  fix: {}\n",
                finding.code,
                finding.role.as_deref().unwrap_or("-"),
                finding.path.as_deref().unwrap_or("-"),
                finding.remediation,
            ));
        }
        out
    }
}

/// The read-only host surface discovery reads through.
///
/// The trait is deliberately tiny and has no mutating method, so an
/// implementation of it cannot change the machine. Tests implement it to script
/// observations; [`LocalProbe`] implements it over the real filesystem.
pub trait ReadOnlyProbe {
    /// Host facts used to resolve the state home.
    fn path_environment(&self) -> PathEnvironment;

    /// Root holding administrator-owned service definitions, when the platform
    /// has one. Never written.
    fn system_definition_root(&self) -> Option<PathBuf>;

    /// Observe one path.
    fn observe(&self, path: &Path) -> Access;

    /// Read one small text file, bounded by [`MAX_VERSION_FILE_BYTES`].
    ///
    /// Returns `None` for a missing, unreadable, malformed-UTF-8 or oversized
    /// file; callers already have [`ReadOnlyProbe::observe`] for the access.
    fn read_text(&self, path: &Path) -> Option<String>;
}
/// Read-only probe over the real local filesystem.
#[derive(Debug, Clone)]
pub struct LocalProbe {
    environment: PathEnvironment,
    system_root: Option<PathBuf>,
}

impl LocalProbe {
    /// Probe the current process environment and the real filesystem.
    #[must_use]
    pub fn for_current_process() -> Self {
        let environment = PathEnvironment::for_current_process();
        let system_root = system_definition_root_for(&environment);
        Self {
            environment,
            system_root,
        }
    }

    /// Probe with an explicit `AXIOM_HOME`, keeping the rest of the current
    /// process environment. Used by the evidence harness and by tests.
    #[must_use]
    pub fn with_home(home: impl Into<String>) -> Self {
        let mut environment = PathEnvironment::for_current_process();
        environment.axiom_home = Some(home.into());
        let system_root = system_definition_root_for(&environment);
        Self {
            environment,
            system_root,
        }
    }

    /// Probe over a fully injected environment, for a deterministic fixture.
    #[must_use]
    pub fn with_environment(environment: PathEnvironment, system_root: Option<PathBuf>) -> Self {
        Self {
            environment,
            system_root,
        }
    }
}

impl ReadOnlyProbe for LocalProbe {
    fn path_environment(&self) -> PathEnvironment {
        self.environment.clone()
    }

    fn system_definition_root(&self) -> Option<PathBuf> {
        self.system_root.clone()
    }

    fn observe(&self, path: &Path) -> Access {
        match std::fs::symlink_metadata(path) {
            Ok(_) => match std::fs::metadata(path) {
                Ok(_) => Access::Readable,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Access::Missing,
                Err(_) => Access::Denied,
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Access::Missing,
            Err(_) => Access::Denied,
        }
    }

    fn read_text(&self, path: &Path) -> Option<String> {
        let file = std::fs::File::open(path).ok()?;
        let mut text = String::new();
        file.take(MAX_VERSION_FILE_BYTES)
            .read_to_string(&mut text)
            .ok()?;
        Some(text)
    }
}

/// Administrator-owned service-definition root for a platform.
///
/// Windows reads the `ProgramData` directory; Linux uses `/etc`; macOS uses
/// `/Library/LaunchDaemons`. The root is only ever read.
#[must_use]
pub fn system_definition_root_for(environment: &PathEnvironment) -> Option<PathBuf> {
    match environment.platform {
        Platform::Windows => std::env::var("ProgramData")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| PathBuf::from(value).join("axiom")),
        Platform::Linux => Some(PathBuf::from("/etc")),
        Platform::MacOs => Some(PathBuf::from("/Library/LaunchDaemons")),
        Platform::Unknown => None,
    }
}

/// Per-user service definition the installer owns for one component.
///
/// Windows stores the managed-startup record under the Axiom home; Linux uses
/// the systemd user unit directory; macOS uses `~/Library/LaunchAgents`.
/// Returns `None` when the platform has no per-user scope (unknown platform) or
/// the environment lacks the directory it needs.
#[must_use]
pub fn per_user_definition(
    environment: &PathEnvironment,
    home: &AxiomHome,
    component: &str,
) -> Option<(PathBuf, ServiceKind)> {
    match environment.platform {
        Platform::Windows => Some((
            home.run_dir()
                .join("services")
                .join(format!("{component}.startup.json")),
            ServiceKind::PerUserStartup,
        )),
        Platform::Linux => {
            // `PathEnvironment` models no `XDG_CONFIG_HOME`, and the systemd
            // user unit directory is exactly `${XDG_CONFIG_HOME:-~/.config}`,
            // so the per-user config root is derived from the home directory.
            let home_dir = environment
                .home_dir
                .as_deref()
                .filter(|value| !value.trim().is_empty())?;
            Some((
                PathBuf::from(home_dir)
                    .join(".config")
                    .join("systemd")
                    .join("user")
                    .join(format!("{component}.service")),
                ServiceKind::SystemdUserUnit,
            ))
        }
        Platform::MacOs => {
            let home_dir = environment
                .home_dir
                .as_deref()
                .filter(|value| !value.trim().is_empty())?;
            Some((
                PathBuf::from(home_dir)
                    .join("Library")
                    .join("LaunchAgents")
                    .join(format!("{component}.plist")),
                ServiceKind::LaunchAgent,
            ))
        }
        Platform::Unknown => None,
    }
}

/// Administrator-owned service definition for one component.
#[must_use]
pub fn system_definition(
    environment: &PathEnvironment,
    system_root: &Path,
    component: &str,
) -> Option<PathBuf> {
    match environment.platform {
        Platform::Windows => Some(
            system_root
                .join("services")
                .join(format!("{component}.service.json")),
        ),
        Platform::Linux => Some(
            system_root
                .join("systemd")
                .join("system")
                .join(format!("{component}.service")),
        ),
        Platform::MacOs => Some(system_root.join(format!("{component}.plist"))),
        Platform::Unknown => None,
    }
}
/// Discover the installation read-only.
///
/// Never creates, writes, renames, deletes, launches or contacts anything; see
/// the module documentation for the structural guarantee.
#[must_use]
pub fn discover(probe: &impl ReadOnlyProbe) -> DiscoveryReport {
    let environment = probe.path_environment();
    let mut findings: Vec<Finding> = Vec::new();

    let home = match AxiomHome::resolve(&environment) {
        Ok(home) => Some(home),
        Err(error) => {
            findings.push(Finding {
                code: FindingCode::HomeUnresolved,
                role: Some("axiom_home".to_string()),
                path: environment.axiom_home.clone(),
                observed: Access::Missing,
                remediation: format!(
                    "set AXIOM_HOME to an absolute path on local disk (or provide the platform \
                     default the resolver names) and re-run `axiom doctor --all --json`; \
                     discovery never creates the directory ({})",
                    error.message()
                ),
            });
            None
        }
    };

    let mut paths = Vec::new();
    let mut components = Vec::new();
    if let Some(home) = home.as_ref() {
        let roles: [(&str, PathBuf, Requirement); 5] = [
            ("axiom_home", home.root().to_path_buf(), Requirement::Write),
            ("installs", home.installs_dir(), Requirement::Write),
            ("run", home.run_dir(), Requirement::Write),
            ("logs", home.logs_dir(), Requirement::Write),
            ("secrets", home.secrets_dir(), Requirement::Write),
        ];
        for (role, path, requirement) in roles {
            let access = probe.observe(&path);
            let display = portable_display(&path);
            let class = classify_storage_lexically(&portable_path(&path));
            paths.push(PathState {
                role: role.to_string(),
                path: display.clone(),
                access,
                requirement,
                storage_class: Some(class.as_str().to_string()),
            });
            if access == Access::Denied {
                findings.push(Finding {
                    code: FindingCode::PermissionDenied,
                    role: Some(role.to_string()),
                    path: Some(display.clone()),
                    observed: access,
                    remediation: format!(
                        "grant the current user read/write on {display}, or install per-user \
                         under AXIOM_HOME; the installer never elevates and never edits OS policy"
                    ),
                });
            }
            if role == "axiom_home" {
                if access == Access::Missing {
                    findings.push(Finding {
                        code: FindingCode::HomeMissing,
                        role: Some(role.to_string()),
                        path: Some(display.clone()),
                        observed: access,
                        remediation: format!(
                            "run `axiom install plan --bundle <verified-local-bundle> --out \
                             install-plan.json` then `axiom install apply --plan \
                             install-plan.json` to create {display} with owner-only permissions; \
                             nothing is installed yet, and discovery creates nothing"
                        ),
                    });
                }
                if class.is_unsafe_for_mutable_state() {
                    findings.push(Finding {
                        code: FindingCode::UnsafeStorage,
                        role: Some(role.to_string()),
                        path: Some(display.clone()),
                        observed: access,
                        remediation: format!(
                            "move AXIOM_HOME off {display}: {} storage must not hold mutable Axiom \
                             state",
                            class.as_str()
                        ),
                    });
                }
            }
        }

        for component in INSTALLABLE_COMPONENTS {
            let install_root = home.installs_dir().join(component);
            let access = probe.observe(&install_root);
            let record = install_root.join(VERSION_FILE);
            let mut installed_version = None;
            let mut installed_revision = None;
            if access == Access::Readable {
                match probe.read_text(&record) {
                    Some(text) => match parse_install_record(&text, component) {
                        Ok((version, revision)) => {
                            installed_version = Some(version);
                            installed_revision = Some(revision);
                        }
                        Err(rule) => findings.push(Finding {
                            code: FindingCode::MalformedState,
                            role: Some("installs".to_string()),
                            path: Some(portable_display(&record)),
                            observed: Access::Readable,
                            remediation: format!(
                                "repair {} so it is a JSON object with component={component}, \
                                 version and build_revision ({rule}); re-run `axiom install apply` \
                                 to replace it. Discovery never rewrites the record",
                                portable_display(&record)
                            ),
                        }),
                    },
                    None => findings.push(Finding {
                        code: FindingCode::MalformedState,
                        role: Some("installs".to_string()),
                        path: Some(portable_display(&record)),
                        observed: Access::Readable,
                        remediation: format!(
                            "{} is not readable as UTF-8 text within {MAX_VERSION_FILE_BYTES} \
                             bytes; repair it or re-run `axiom install apply`. Discovery never \
                             rewrites the record",
                            portable_display(&record)
                        ),
                    }),
                }
            }
            components.push(ComponentState {
                component: component.to_string(),
                install_root: portable_display(&install_root),
                access,
                installed_version,
                installed_revision,
            });
        }
    } else {
        for component in INSTALLABLE_COMPONENTS {
            components.push(ComponentState {
                component: component.to_string(),
                install_root: String::new(),
                access: Access::Missing,
                installed_version: None,
                installed_revision: None,
            });
        }
    }
    let mut services = Vec::new();
    for component in INSTALLABLE_COMPONENTS {
        let per_user = home
            .as_ref()
            .and_then(|home| per_user_definition(&environment, home, component));
        let system = probe
            .system_definition_root()
            .and_then(|root| system_definition(&environment, &root, component));

        let per_user_present = per_user
            .as_ref()
            .is_some_and(|(path, _)| probe.observe(path) == Access::Readable);
        let system_present = system
            .as_ref()
            .is_some_and(|path| probe.observe(path) == Access::Readable);

        let (kind, owner, definition_path) = if per_user_present {
            let (path, kind) = per_user
                .as_ref()
                .expect("per-user present implies definition");
            (*kind, ServiceOwner::PerUser, Some(portable_display(path)))
        } else if system_present {
            let path = system.as_ref().expect("system present implies definition");
            (
                ServiceKind::SystemService,
                ServiceOwner::System,
                Some(portable_display(path)),
            )
        } else {
            (
                per_user
                    .as_ref()
                    .map_or(ServiceKind::SystemService, |(_, kind)| *kind),
                ServiceOwner::Absent,
                None,
            )
        };

        if owner == ServiceOwner::System {
            let path = definition_path.clone().unwrap_or_default();
            findings.push(Finding {
                code: FindingCode::SystemScopedService,
                role: Some(component.to_string()),
                path: Some(path.clone()),
                observed: Access::Readable,
                remediation: format!(
                    "remove the administrator-owned definition {path} and install the per-user \
                     managed startup instead (`axiom service install --user --component \
                     {component}`); a system-wide service is an explicit admin option and is not \
                     the default, and discovery never uninstalls it"
                ),
            });
        }

        services.push(ServiceState {
            component: component.to_string(),
            kind,
            owner,
            definition_path,
        });
    }

    let report = DiscoveryReport {
        schema_version: DISCOVERY_SCHEMA_VERSION,
        spec_version: SPEC_VERSION.to_string(),
        read_only: true,
        home: home.as_ref().map(|home| portable_display(home.root())),
        components,
        services,
        paths,
        findings,
    };
    debug_assert!(report.validate().is_ok(), "discovery emits a valid report");
    report
}

/// Parse one component install record.
///
/// Returns the version and build revision, or the rule that was violated.
fn parse_install_record(text: &str, component: &str) -> Result<(String, String), &'static str> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|_| "not_json_object")?;
    let object = value.as_object().ok_or("not_json_object")?;
    let recorded = object
        .get("component")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing_component")?;
    if recorded != component {
        return Err("component_mismatch");
    }
    let version = object
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or("missing_version")?;
    let revision = object
        .get("build_revision")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or("missing_build_revision")?;
    Ok((version.to_string(), revision.to_string()))
}

/// Split-free portable form of a path for the wire report.
fn portable_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Display form of a path in the report.
fn portable_display(path: &Path) -> String {
    portable_path(path)
}
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    use graph_core::paths::{AxiomHome, PathEnvironment, Platform};

    use super::{
        discover, per_user_definition, portable_display, Access, DiscoveryReport, FindingCode,
        LocalProbe, ReadOnlyProbe, ServiceKind, ServiceOwner, DISCOVERY_SCHEMA_VERSION,
        INSTALLABLE_COMPONENTS, VERSION_FILE,
    };
    use crate::version::COMPONENTS;

    /// Deterministic Windows fixture environment: the per-user definition lives
    /// under the Axiom home, so a fixture tree is self-contained.
    fn windows_environment(home: &Path) -> PathEnvironment {
        PathEnvironment {
            platform: Platform::Windows,
            axiom_home: Some(home.to_string_lossy().to_string()),
            local_app_data: None,
            xdg_state_home: None,
            home_dir: None,
        }
    }

    /// Byte digest of every file under `root`, so a read-only claim is provable.
    fn tree_manifest(root: &Path) -> BTreeMap<String, String> {
        let mut manifest = BTreeMap::new();
        let mut stack = vec![PathBuf::from(root)];
        while let Some(directory) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .expect("entry is under root")
                    .to_string_lossy()
                    .replace('\\', "/");
                if path.is_dir() {
                    manifest.insert(relative, String::from("<dir>"));
                    stack.push(path);
                } else {
                    let bytes = std::fs::read(&path).expect("fixture file reads");
                    manifest.insert(relative, graph_export::sha256_hex(&bytes));
                }
            }
        }
        manifest
    }

    fn write(path: &Path, text: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("fixture parent");
        }
        std::fs::write(path, text).expect("fixture file");
    }

    /// Scripted probe for the denied-privilege case: the real filesystem cannot
    /// be asked to deny access without changing an ACL, which discovery must
    /// never do.
    struct ScriptedProbe {
        environment: PathEnvironment,
        system_root: Option<PathBuf>,
        denied: Vec<PathBuf>,
    }

    impl ReadOnlyProbe for ScriptedProbe {
        fn path_environment(&self) -> PathEnvironment {
            self.environment.clone()
        }

        fn system_definition_root(&self) -> Option<PathBuf> {
            self.system_root.clone()
        }

        fn observe(&self, path: &Path) -> Access {
            if self.denied.iter().any(|denied| denied == path) {
                return Access::Denied;
            }
            match std::fs::symlink_metadata(path) {
                Ok(_) => Access::Readable,
                Err(_) => Access::Missing,
            }
        }

        fn read_text(&self, _path: &Path) -> Option<String> {
            None
        }
    }

    #[test]
    fn discovers_versions_paths_and_service_owner_without_touching_the_tree() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("axiom-home");
        write(
            &home.join("installs").join("axiom-graphd").join(VERSION_FILE),
            "{\"component\":\"axiom-graphd\",\"version\":\"0.2.0\",\"build_revision\":\"abc1234\"}\n",
        );
        write(
            &home.join("installs").join("axiom").join(VERSION_FILE),
            "{\"component\":\"axiom\",\"version\":\"0.2.0\",\"build_revision\":\"abc1234\"}\n",
        );
        write(
            &home
                .join("run")
                .join("services")
                .join("axiom-graphd.startup.json"),
            "{\"scope\":\"per-user\"}\n",
        );
        let before = tree_manifest(temp.path());

        let probe = LocalProbe::with_environment(windows_environment(&home), None);
        let report = discover(&probe);

        assert!(report.ok(), "findings: {:?}", report.findings);
        assert_eq!(report.schema_version, DISCOVERY_SCHEMA_VERSION);
        assert!(report.read_only);
        report.validate().expect("valid report");

        let graphd = report
            .components
            .iter()
            .find(|component| component.component == "axiom-graphd")
            .expect("graphd component");
        assert_eq!(graphd.installed_version.as_deref(), Some("0.2.0"));
        assert_eq!(graphd.installed_revision.as_deref(), Some("abc1234"));

        let service = report
            .services
            .iter()
            .find(|service| service.component == "axiom-graphd")
            .expect("graphd service");
        assert_eq!(service.owner, ServiceOwner::PerUser);
        assert_eq!(service.kind, ServiceKind::PerUserStartup);
        assert!(service.definition_path.is_some());

        let uninstalled = report
            .services
            .iter()
            .find(|service| service.component == "axiom-mcp")
            .expect("mcp service");
        assert_eq!(uninstalled.owner, ServiceOwner::Absent);

        // The read-only claim: the tree is byte-identical after discovery.
        assert_eq!(before, tree_manifest(temp.path()));
    }

    /// Linux fixture: no `LOCALAPPDATA`, so the per-user scope is `~/.config`.
    fn linux_environment() -> PathEnvironment {
        PathEnvironment {
            platform: Platform::Linux,
            axiom_home: Some(String::from("/srv/axiom")),
            local_app_data: None,
            xdg_state_home: Some(String::from("/home/agent/.local/state")),
            home_dir: Some(String::from("/home/agent")),
        }
    }

    /// macOS fixture: the per-user scope is `~/Library/LaunchAgents`.
    fn macos_environment() -> PathEnvironment {
        PathEnvironment {
            platform: Platform::MacOs,
            axiom_home: Some(String::from(
                "/Users/agent/Library/Application Support/Axiom",
            )),
            local_app_data: None,
            xdg_state_home: None,
            home_dir: Some(String::from("/Users/agent")),
        }
    }

    /// The negative case for E-003 AC1: a missing privilege is *reported*, never
    /// repaired. A scripted probe is required because denying access on the real
    /// filesystem would mean changing an ACL, which discovery must never do.
    #[test]
    fn a_missing_privilege_is_reported_as_an_actionable_finding() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("axiom-home");
        let environment = windows_environment(&home);
        let resolved = AxiomHome::resolve(&environment).expect("home resolves");
        let probe = ScriptedProbe {
            environment,
            system_root: None,
            denied: vec![resolved.secrets_dir()],
        };
        let before = tree_manifest(temp.path());

        let report = discover(&probe);

        assert!(!report.ok(), "a denied path is a finding");
        let secrets = report
            .paths
            .iter()
            .find(|path| path.role == "secrets")
            .expect("secrets path");
        assert_eq!(secrets.access, Access::Denied);

        let finding = report
            .findings
            .iter()
            .find(|finding| finding.code == FindingCode::PermissionDenied)
            .expect("permission finding");
        assert_eq!(finding.role.as_deref(), Some("secrets"));
        assert_eq!(finding.observed, Access::Denied);
        assert!(
            finding.remediation.contains("secrets"),
            "{}",
            finding.remediation
        );
        assert!(
            finding.remediation.contains("never elevates"),
            "{}",
            finding.remediation
        );

        // The finding is the whole response: nothing was repaired or created.
        assert_eq!(before, tree_manifest(temp.path()), "the tree is untouched");
    }

    /// A home that does not exist yet is reported with the concrete next step,
    /// and discovery creates nothing while reporting it.
    #[test]
    fn an_absent_home_is_reported_and_nothing_is_created() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("not-installed");
        let probe = LocalProbe::with_environment(windows_environment(&home), None);
        let before = tree_manifest(temp.path());

        let report = discover(&probe);

        assert!(!report.ok());
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.code == FindingCode::HomeMissing)
            .expect("home missing finding");
        assert!(
            finding.remediation.contains("install plan"),
            "{}",
            finding.remediation
        );
        assert!(
            finding.remediation.contains("creates nothing"),
            "{}",
            finding.remediation
        );
        assert!(!home.exists(), "discovery creates nothing");
        assert_eq!(before, tree_manifest(temp.path()), "the tree is untouched");
    }

    /// A system-scoped definition is flagged for the operator, not adopted: the
    /// default install is per-user and never elevates.
    #[test]
    fn a_system_scoped_service_is_flagged_rather_than_adopted() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("axiom-home");
        let system_root = temp.path().join("system-root");
        write(
            &system_root
                .join("services")
                .join("axiom-graphd.service.json"),
            "{\"scope\":\"system\"}\n",
        );
        let probe = ScriptedProbe {
            environment: windows_environment(&home),
            system_root: Some(system_root),
            denied: Vec::new(),
        };

        let report = discover(&probe);

        let service = report
            .services
            .iter()
            .find(|service| service.component == "axiom-graphd")
            .expect("graphd service");
        assert_eq!(service.owner, ServiceOwner::System);
        assert_eq!(service.kind, ServiceKind::SystemService);
        assert!(service.definition_path.is_some());

        let finding = report
            .findings
            .iter()
            .find(|finding| finding.code == FindingCode::SystemScopedService)
            .expect("system scope finding");
        assert!(
            finding.remediation.contains("--user"),
            "{}",
            finding.remediation
        );
        assert!(
            finding.remediation.contains("never uninstalls"),
            "{}",
            finding.remediation
        );
    }

    /// A record that names the wrong component is reported with the exact rule
    /// that failed, and discovery never rewrites it.
    #[test]
    fn a_malformed_install_record_is_reported_with_its_rule() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("axiom-home");
        write(
            &home.join("installs").join("axiom-mcp").join(VERSION_FILE),
            "{\"component\":\"axiom-graphd\",\"version\":\"1.0.0\",\"build_revision\":\"deadbee\"}\n",
        );
        let probe = LocalProbe::with_environment(windows_environment(&home), None);

        let report = discover(&probe);

        assert!(!report.ok());
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.code == FindingCode::MalformedState)
            .expect("malformed finding");
        assert!(
            finding.remediation.contains("component_mismatch"),
            "{}",
            finding.remediation
        );
        assert!(
            finding.remediation.contains("never rewrites"),
            "{}",
            finding.remediation
        );
        let mcp = report
            .components
            .iter()
            .find(|component| component.component == "axiom-mcp")
            .expect("mcp component");
        assert!(mcp.installed_version.is_none());
    }

    /// Boundary: the installable set stays inside the frozen component
    /// vocabulary, and a report with a foreign spec baseline is refused.
    #[test]
    fn the_installable_set_is_a_subset_of_the_frozen_components() {
        for component in INSTALLABLE_COMPONENTS {
            assert!(
                COMPONENTS.contains(&component),
                "{component} is not part of the frozen component vocabulary"
            );
        }
        assert!(INSTALLABLE_COMPONENTS.contains(&crate::version::COMPONENT));

        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("axiom-home");
        let probe = LocalProbe::with_environment(windows_environment(&home), None);
        let mut report: DiscoveryReport = discover(&probe);
        report
            .validate()
            .expect("a report from discover() is valid");

        report.spec_version = String::from("not-this-build");
        let error = report
            .validate()
            .expect_err("a foreign spec baseline is refused");
        assert!(error.message().contains("baseline"), "{}", error.message());
    }

    /// The per-user definition follows each platform convention, and a platform
    /// with no per-user scope names no definition at all.
    #[test]
    fn the_per_user_definition_follows_the_platform_convention() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("axiom-home");

        let windows = windows_environment(&home);
        let resolved = AxiomHome::resolve(&windows).expect("windows home resolves");
        let (path, kind) = per_user_definition(&windows, &resolved, "axiom-mcp").expect("windows");
        assert_eq!(kind, ServiceKind::PerUserStartup);
        assert!(
            portable_display(&path).contains("/services/"),
            "{}",
            portable_display(&path)
        );

        let linux = linux_environment();
        let resolved = AxiomHome::resolve(&linux).expect("linux home resolves");
        let (path, kind) = per_user_definition(&linux, &resolved, "axiom-mcp").expect("linux");
        assert_eq!(kind, ServiceKind::SystemdUserUnit);
        assert!(
            portable_display(&path).ends_with("systemd/user/axiom-mcp.service"),
            "{}",
            portable_display(&path)
        );

        let macos = macos_environment();
        let resolved = AxiomHome::resolve(&macos).expect("macos home resolves");
        let (path, kind) = per_user_definition(&macos, &resolved, "axiom-mcp").expect("macos");
        assert_eq!(kind, ServiceKind::LaunchAgent);
        assert!(
            portable_display(&path).ends_with("Library/LaunchAgents/axiom-mcp.plist"),
            "{}",
            portable_display(&path)
        );

        let unknown = PathEnvironment {
            platform: Platform::Unknown,
            ..linux_environment()
        };
        let resolved = AxiomHome::resolve(&unknown).expect("home still resolves");
        assert!(per_user_definition(&unknown, &resolved, "axiom-mcp").is_none());
    }
}
