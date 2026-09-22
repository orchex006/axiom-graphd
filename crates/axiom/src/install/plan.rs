//! Dry-run component installation plan for the `axiom` CLI (task E-004).
//!
//! `docs/16-CLI-AND-CONTROL-API.md` section 4 pins the command pair
//! `axiom install plan --bundle <signed-bundle> --out install-plan.json` and
//! `axiom install apply --plan install-plan.json`, and
//! `21-INSTALLATION.md` section C pins what a human must be able to review
//! *before* anything is installed: component versions, OS paths, service
//! changes, required permissions and planned network access, with the default
//! install per-user and never elevated.
//!
//! This module is the dry-run half of that pair. It turns one already
//! downloaded, local bundle manifest into the reviewable plan document.
//!
//! ## The no-side-effect boundary is structural (AC1)
//!
//! "No writes and no network execution during a dry run" is not a promise this
//! module makes about itself; it is a property of the shapes it offers:
//!
//! * [`read_bundle_manifest`] is the only filesystem call in the module. It
//!   opens `bundle.json` read-only, reads at most [`MAX_MANIFEST_BYTES`] and has
//!   no create/write/rename/delete/chmod/launch path to reach.
//! * [`plan_install`] takes a parsed manifest, a caller-supplied
//!   [`PlanContext`] and a [`DryRun`] token, all by reference. It has no file
//!   handle, no socket, no process and no clock: the plan id and timestamp are
//!   injected by the caller, so planning is deterministic and cannot download,
//!   install or touch the bundle directory even by accident.
//! * The plan reports the *declared* digest and location of every artifact and
//!   marks each transfer `executed: false`. Verifying those bytes against
//!   trusted metadata is task E-005's job, so this module never claims an
//!   artifact is verified.
//!
//! ## One digest, one approval binding
//!
//! `docs/16-CLI-AND-CONTROL-API.md` section 7 requires `install apply` to bind
//! approval to the exact canonical plan digest. The install plan therefore does
//! not define a second digest: [`sealed`] reuses [`crate::plan::seal_digest`],
//! the one canonical encoder and digest of this workspace. An approval recorded
//! against one plan can never activate a plan whose components, versions,
//! destinations or permissions changed, because all of them are inside the
//! digested body.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{is_absolute_host_path, validate_portable_relative_path, Platform};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::version::SPEC_VERSION;

/// `schema_version` of the install-plan document this build emits.
pub const INSTALL_PLAN_SCHEMA_VERSION: u64 = 1;

/// `plan_kind` that marks a document as an install plan rather than an update
/// plan; the two share the approval binding but not the planner inputs.
pub const PLAN_KIND: &str = "install";

/// Host identifiers a plan may declare, in the order the CLI reports them.
pub const HOSTS: [&str; 4] = ["windows-x64", "linux-x64", "macos-arm64", "macos-x64"];

/// Host identifier for one already-detected platform/architecture pair.
///
/// [`HOSTS`] is the only accepted spelling and this is the only place the
/// mapping lives, so the planner, the daemon and the `install_plan_probe`
/// example cannot drift apart about which host they plan for.
///
/// A pair this build cannot name stays `"unknown"`: `plan_ecosystem` refuses an
/// undeclared host with its own frozen code, which is the honest outcome. Both
/// macOS architectures are declared, so the macOS answer depends on the
/// architecture and not on the OS alone.
#[must_use]
pub fn host_identifier_for(platform: Platform, architecture: &str) -> &'static str {
    match (platform, architecture) {
        (Platform::Windows, "x86_64") => "windows-x64",
        (Platform::Linux, "x86_64") => "linux-x64",
        (Platform::MacOs, "aarch64") => "macos-arm64",
        (Platform::MacOs, "x86_64") => "macos-x64",
        _ => "unknown",
    }
}

/// Host identifier this build plans for, from the compiled-in target facts.
///
/// The architecture comes from `cfg!` rather than a runtime probe: a plan has
/// to name the host the running binary was built for, and a runtime probe would
/// let a cross-built binary plan for the machine that merely launched it.
#[must_use]
pub fn host_identifier() -> String {
    let architecture = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        "unknown"
    };
    host_identifier_for(Platform::current(), architecture).to_string()
}

/// Components the `axiom` CLI installs and services.
///
/// It is `discovery::INSTALLABLE_COMPONENTS` itself, not a copy: a second list
/// would let the planner and the doctor disagree about what an install is.
pub const COMPONENTS: [&str; 3] = crate::discovery::INSTALLABLE_COMPONENTS;

/// Component actions a plan may announce, in the order it reports them.
pub const ACTIONS: [&str; 4] = ["install", "upgrade", "reinstall", "noop"];

/// Installation scopes a plan may declare. `per_user` is the default.
pub const SCOPES: [&str; 2] = ["per_user", "system"];

/// Where one artifact comes from.
pub const SOURCE_KINDS: [&str; 2] = ["local_bundle", "release_url"];

/// Artifact kinds a bundle may declare.
pub const ARTIFACT_KINDS: [&str; 3] = ["binary", "python", "assets"];

/// Permission identifiers a bundle may require for one component.
pub const PERMISSIONS: [&str; 5] = ["read", "write", "execute", "network", "elevated"];

/// Service mechanisms a plan may announce.
pub const SERVICE_MECHANISMS: [&str; 5] = [
    "per_user_startup",
    "systemd_user_unit",
    "launch_agent",
    "system_service",
    "none",
];

/// Service actions a plan may announce.
pub const SERVICE_ACTIONS: [&str; 3] = ["install", "upgrade", "none"];

/// Release channels a bundle may declare.
pub const CHANNELS: [&str; 2] = ["stable", "prerelease"];

/// `schema_version` of the bundle manifest this build reads.
pub const BUNDLE_SCHEMA_VERSION: u64 = 1;

/// Name of the manifest inside the verified local bundle directory.
pub const BUNDLE_MANIFEST_FILE: &str = "bundle.json";

/// Upper bound on the bytes this module reads from a bundle manifest.
pub const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

/// Directory under the install root that holds one directory per version.
///
/// `21-INSTALLATION.md` section C requires a versioned directory, and one
/// directory per version is what makes `install apply` an atomic pointer move
/// and keeps a rollback to the previous version possible.
pub const VERSIONS_DIRECTORY: &str = "versions";

/// Directory that holds verified-but-not-yet-activated bytes.
///
/// Staging lives outside [`VERSIONS_DIRECTORY`], so a partial download can never
/// land in the activated tree.
pub const STAGING_DIRECTORY: &str = "staging";

/// `21-INSTALLATION.md` section C: keep at least one previous working version.
pub const MIN_KEEP_PREVIOUS_VERSIONS: u64 = 1;

/// Who owns the files an install writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallScope {
    /// Owned by the current user; the default, and never elevated.
    PerUser,
    /// Owned by the administrator; an explicit, non-default scope.
    System,
}

impl InstallScope {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PerUser => "per_user",
            Self::System => "system",
        }
    }

    /// Every accepted value, for contract tests and the refusal messages.
    #[must_use]
    pub const fn all() -> &'static [InstallScope] {
        &[Self::PerUser, Self::System]
    }
}

/// What the plan does with one component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentAction {
    /// The component is not installed and will be.
    Install,
    /// A different version is installed and will be replaced.
    Upgrade,
    /// The same version is installed and will be written again.
    Reinstall,
    /// The same version is already installed; nothing will change.
    Noop,
}

impl ComponentAction {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Upgrade => "upgrade",
            Self::Reinstall => "reinstall",
            Self::Noop => "noop",
        }
    }

    /// Every accepted value, in the order [`ACTIONS`] reports them.
    #[must_use]
    pub const fn all() -> &'static [ComponentAction] {
        &[Self::Install, Self::Upgrade, Self::Reinstall, Self::Noop]
    }
}

/// Where one artifact comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// A file inside the verified local bundle directory; no network.
    LocalBundle,
    /// A release location the caller fetched into the bundle beforehand.
    ReleaseUrl,
}

impl SourceKind {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalBundle => "local_bundle",
            Self::ReleaseUrl => "release_url",
        }
    }

    /// Every accepted value, for contract tests.
    #[must_use]
    pub const fn all() -> &'static [SourceKind] {
        &[Self::LocalBundle, Self::ReleaseUrl]
    }
}

/// What one artifact is, which decides how it is activated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// A compiled executable or daemon binary.
    Binary,
    /// A Python distribution installed beside the daemon.
    Python,
    /// Read-only data, fixtures or documentation shipped with a component.
    Assets,
}

impl ArtifactKind {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Python => "python",
            Self::Assets => "assets",
        }
    }

    /// Every accepted value, for contract tests.
    #[must_use]
    pub const fn all() -> &'static [ArtifactKind] {
        &[Self::Binary, Self::Python, Self::Assets]
    }
}

/// How a component is made to start with the user session or the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceMechanism {
    /// Windows per-user managed startup record (the default Windows choice).
    PerUserStartup,
    /// systemd user unit.
    SystemdUserUnit,
    /// macOS per-user LaunchAgent.
    LaunchAgent,
    /// A system-scoped unit, task or daemon owned by the administrator.
    SystemService,
    /// The component installs no service definition.
    #[serde(rename = "none")]
    Absent,
}

impl ServiceMechanism {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PerUserStartup => "per_user_startup",
            Self::SystemdUserUnit => "systemd_user_unit",
            Self::LaunchAgent => "launch_agent",
            Self::SystemService => "system_service",
            Self::Absent => "none",
        }
    }

    /// True when this mechanism is only reachable with administrator rights.
    #[must_use]
    pub const fn is_system(self) -> bool {
        matches!(self, Self::SystemService)
    }

    /// Every accepted value, in the order [`SERVICE_MECHANISMS`] reports them.
    #[must_use]
    pub const fn all() -> &'static [ServiceMechanism] {
        &[
            Self::PerUserStartup,
            Self::SystemdUserUnit,
            Self::LaunchAgent,
            Self::SystemService,
            Self::Absent,
        ]
    }
}

/// What the plan does with one component's service definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    /// Create the definition.
    Install,
    /// Replace an existing definition.
    Upgrade,
    /// Leave the service as it is.
    #[serde(rename = "none")]
    Absent,
}

impl ServiceAction {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Upgrade => "upgrade",
            Self::Absent => "none",
        }
    }

    /// Every accepted value, in the order [`SERVICE_ACTIONS`] reports them.
    #[must_use]
    pub const fn all() -> &'static [ServiceAction] {
        &[Self::Install, Self::Upgrade, Self::Absent]
    }
}

/// Capability token that says the caller asked for a plan and not an install.
///
/// The tuple field is private, so a token cannot be fabricated with a struct
/// literal; [`DryRun::new`] and `Default` are the only constructors. Passing one
/// to [`plan_install`] is how a caller states "produce the plan, change
/// nothing", which is why the plan document can only carry `dry_run: true`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DryRun(());

impl DryRun {
    /// The dry-run token.
    #[must_use]
    pub const fn new() -> Self {
        Self(())
    }
}

/// One component version the host already carries, observed by discovery.
///
/// Planning reads no state itself. It announces `noop` or `upgrade` only from
/// what the caller observed with `discovery`, so a plan cannot depend on a
/// filesystem the planner never touched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedComponent {
    /// Component name from [`COMPONENTS`].
    pub component: String,
    /// Version currently installed, if any.
    pub version: String,
}

/// Caller-supplied planner inputs.
///
/// Every value a plan depends on is injected here, including the identifier and
/// the timestamp, so two runs over the same bundle produce byte-identical plans
/// and the planner needs neither a clock nor a random source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanContext {
    /// Identifier of this plan; the caller owns generation and uniqueness.
    pub plan_id: String,
    /// RFC 3339 creation time, injected so planning is deterministic.
    pub created_at: String,
    /// Host the plan targets, from [`HOSTS`].
    pub host: String,
    /// Absolute install root the versions are created under.
    pub install_root: String,
    /// Scope of the install; [`InstallScope::PerUser`] is the default.
    pub scope: InstallScope,
    /// Explicit opt-in required before a system-scoped plan is produced.
    pub allow_system: bool,
    /// Working versions kept for rollback.
    pub keep_previous_versions: u64,
    /// Component versions discovery already observed on this host.
    #[serde(default)]
    pub observed: Vec<ObservedComponent>,
}

impl PlanContext {
    /// A per-user context for one host and install root.
    ///
    /// The default scope, the default rollback depth and the safe opt-in are
    /// all fixed here, so a caller cannot forget one of them by accident.
    #[must_use]
    pub fn per_user(
        plan_id: impl Into<String>,
        created_at: impl Into<String>,
        host: impl Into<String>,
        install_root: impl Into<String>,
    ) -> Self {
        Self {
            plan_id: plan_id.into(),
            created_at: created_at.into(),
            host: host.into(),
            install_root: install_root.into(),
            scope: InstallScope::PerUser,
            allow_system: false,
            keep_previous_versions: MIN_KEEP_PREVIOUS_VERSIONS,
            observed: Vec::new(),
        }
    }

    /// The version discovery observed for one component, if any.
    #[must_use]
    pub fn observed_version(&self, component: &str) -> Option<&str> {
        self.observed
            .iter()
            .find(|observed| observed.component == component)
            .map(|observed| observed.version.as_str())
    }
}

/// One artifact of a bundle, as the bundle manifest declares it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleComponent {
    /// Component name from [`COMPONENTS`].
    pub component: String,
    /// Version of this artifact.
    pub version: String,
    /// Host this artifact was built for, from [`HOSTS`].
    pub host: String,
    /// Forward-slash path of the payload inside the bundle directory.
    pub artifact: String,
    /// What the payload is, which decides how it is activated.
    pub kind: ArtifactKind,
    /// Declared lowercase 64-hex digest of the payload.
    pub sha256: String,
    /// Declared size of the payload in bytes.
    pub size_bytes: u64,
    /// Permission identifiers the component needs, from [`PERMISSIONS`].
    pub permissions: Vec<String>,
    /// Service definition the component installs, when it installs one.
    #[serde(default)]
    pub service: Option<BundleService>,
    /// Network locations the component is planned to contact.
    #[serde(default)]
    pub network_access: Vec<NetworkAccessDeclaration>,
}

/// Service change a bundle declares for one component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleService {
    /// How the service is installed on this host.
    pub mechanism: ServiceMechanism,
    /// What the plan does with the definition.
    pub action: ServiceAction,
    /// Whether the definition needs administrator rights.
    pub requires_elevation: bool,
}

/// One network location a component is planned to contact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAccessDeclaration {
    /// Location the component would contact.
    pub url: String,
    /// Why it would contact it, in reviewable prose.
    pub purpose: String,
}

/// The bundle manifest this module reads: one already-downloaded local bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    /// Manifest schema version; must equal [`BUNDLE_SCHEMA_VERSION`].
    pub schema_version: u64,
    /// Bundle identifier, a portable slug.
    pub bundle_id: String,
    /// Release channel this bundle was built for, from [`CHANNELS`].
    pub channel: String,
    /// RFC 3339 build time of the bundle, carried through for review.
    pub created_at: String,
    /// The artifacts, one or more per component.
    pub components: Vec<BundleComponent>,
}

impl BundleManifest {
    /// Validate the manifest against this build's vocabulary and the AC1 rules.
    ///
    /// These are the checks that need no host and no target: a manifest that
    /// cannot be planned is refused here, before planning starts.
    ///
    /// # Errors
    /// - [`ErrorCode::ValidationError`] for an unsupported schema version, an
    ///   unknown vocabulary value, an empty component list, a malformed digest,
    ///   a zero size or an artifact path that is not portable.
    pub fn validate(&self) -> Result<(), AxiomError> {
        if self.schema_version != BUNDLE_SCHEMA_VERSION {
            let observed = self.schema_version.to_string();
            return Err(refuse("schema_version", &observed));
        }
        if !graph_core::paths::is_portable_id(&self.bundle_id) {
            return Err(refuse("bundle_id", &self.bundle_id));
        }
        if !CHANNELS.contains(&self.channel.as_str()) {
            return Err(refuse("channel", &self.channel));
        }
        if self.created_at.trim().is_empty() {
            return Err(refuse("created_at", "empty"));
        }
        if self.components.is_empty() {
            return Err(refuse("components", "empty"));
        }
        for component in &self.components {
            component.validate()?;
        }
        Ok(())
    }
}

impl BundleComponent {
    /// Validate one artifact declaration.
    ///
    /// # Errors
    /// - [`ErrorCode::ValidationError`] for an unknown component, host, kind or
    ///   permission, a malformed digest, a zero size, a non-portable artifact
    ///   path, or a service that declares no action.
    /// - [`ErrorCode::UnsafePortablePath`] when the artifact path is not a
    ///   portable bundle-relative path, for example it escapes with `..`.
    pub fn validate(&self) -> Result<(), AxiomError> {
        if !COMPONENTS.contains(&self.component.as_str()) {
            return Err(refuse("component", &self.component));
        }
        if self.version.trim().is_empty() {
            return Err(refuse("version", "empty"));
        }
        if !HOSTS.contains(&self.host.as_str()) {
            return Err(refuse("host", &self.host));
        }
        validate_portable_relative_path(&self.artifact)?;
        if !is_digest(&self.sha256) {
            return Err(refuse("sha256", &self.sha256));
        }
        if self.size_bytes == 0 {
            return Err(refuse("size_bytes", "0"));
        }
        let mut seen = BTreeMap::new();
        for permission in &self.permissions {
            if !PERMISSIONS.contains(&permission.as_str()) {
                return Err(refuse("permissions", permission));
            }
            if seen
                .insert(permission.as_str(), permission.as_str())
                .is_some()
            {
                return Err(refuse("permissions", permission));
            }
        }
        if let Some(service) = &self.service {
            if matches!(service.action, ServiceAction::Absent)
                != matches!(service.mechanism, ServiceMechanism::Absent)
            {
                return Err(refuse("service", "mechanism and action disagree"));
            }
        }
        Ok(())
    }
}

/// Read and parse the manifest of a verified local bundle directory.
///
/// This is the only filesystem call in this module. It opens
/// `<bundle_root>/bundle.json` read-only, reads at most [`MAX_MANIFEST_BYTES`]
/// plus one byte, and returns the parsed manifest with the SHA-256 of the exact
/// bytes it read, so the plan can name the manifest it was built from.
///
/// # Errors
/// - [`ErrorCode::NotFound`] when the manifest file cannot be opened.
/// - [`ErrorCode::ValidationError`] when the file is larger than
///   [`MAX_MANIFEST_BYTES`], is not UTF-8, is not valid JSON, carries keys this
///   build does not know, or fails [`BundleManifest::validate`].
pub fn read_bundle_manifest(bundle_root: &Path) -> Result<(BundleManifest, String), AxiomError> {
    let path = bundle_root.join(BUNDLE_MANIFEST_FILE);
    let file = std::fs::File::open(&path).map_err(|error| {
        AxiomError::new(
            ErrorCode::NotFound,
            "the bundle manifest could not be opened",
        )
        .with_detail("rule", "bundle_manifest")
        .with_detail("observed", BUNDLE_MANIFEST_FILE)
        .with_detail("actual", error.kind().to_string())
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            AxiomError::new(
                ErrorCode::ValidationError,
                "the bundle manifest could not be read",
            )
            .with_detail("rule", "bundle_manifest")
            .with_detail("observed", error.kind().to_string())
        })?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        let observed = bytes.len().to_string();
        return Err(refuse("manifest_bytes", &observed)
            .with_detail("limit", MAX_MANIFEST_BYTES.to_string()));
    }
    let text = String::from_utf8(bytes).map_err(|_| {
        AxiomError::new(
            ErrorCode::ValidationError,
            "the bundle manifest is not valid UTF-8",
        )
        .with_detail("rule", "bundle_manifest_utf8")
        .with_detail("observed", "invalid utf-8")
    })?;
    let manifest: BundleManifest = serde_json::from_str(&text).map_err(|error| {
        AxiomError::new(
            ErrorCode::ValidationError,
            "the bundle manifest is not a valid manifest",
        )
        .with_detail("rule", "bundle_manifest_json")
        .with_detail("observed", error.to_string())
    })?;
    manifest.validate()?;
    Ok((manifest, graph_export::sha256_hex(text.as_bytes())))
}

/// Lowercase 64-hex digest check, matching the canonical plan digest form.
#[must_use]
pub fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The one refusal shape of this module.
///
/// Details use only keys of `graph-core`'s `redact::ALLOWED_DETAIL_KEYS`, so a
/// refusal cannot be silently emptied by the redactor: `rule` names the violated
/// rule and `observed` names what was seen.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the install plan input violates the install plan contract",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

/// Where one artifact comes from, as the plan reports it.
///
/// `executed` is always `false` in a plan: the dry run names the location and
/// the declared digest, and nobody has fetched anything yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadSource {
    /// Whether the artifact is a local bundle member or a release location.
    pub kind: SourceKind,
    /// Absolute path inside the bundle, or the release location.
    pub location: String,
    /// Declared lowercase 64-hex digest of the payload.
    pub sha256: String,
    /// Declared size of the payload in bytes.
    pub size_bytes: u64,
    /// Always `false`; a plan transfers nothing.
    pub executed: bool,
}

/// One component the plan places.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedComponent {
    /// Component name from [`COMPONENTS`].
    pub component: String,
    /// Version that will be activated.
    pub version: String,
    /// What the plan does with the installed component, if any.
    pub action: ComponentAction,
    /// What the payload is.
    pub kind: ArtifactKind,
    /// Bundle-relative path of the payload.
    pub artifact: String,
    /// Absolute path the payload is activated at.
    pub destination: String,
    /// Absolute path the verified payload is staged at, outside the active tree.
    pub staged_destination: String,
    /// Where the payload comes from.
    pub source: DownloadSource,
    /// Permission identifiers the component needs.
    pub permissions: Vec<String>,
}

/// What the plan targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallTarget {
    /// Host identifier from [`HOSTS`].
    pub host: String,
    /// Absolute install root.
    pub install_root: String,
    /// Scope the files are owned by.
    pub scope: InstallScope,
    /// Absolute directory holding one directory per version.
    pub versions_root: String,
    /// Absolute directory holding verified bytes that are not yet active.
    pub staging_root: String,
}

/// The bundle the plan was built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleReference {
    /// Bundle identifier.
    pub bundle_id: String,
    /// Release channel.
    pub channel: String,
    /// Build time carried through for review.
    pub created_at: String,
    /// SHA-256 of the exact manifest bytes the plan was built from.
    pub manifest_sha256: String,
    /// Absolute local bundle directory.
    pub location: String,
}

/// One service change the plan announces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedServiceChange {
    /// Component the definition belongs to.
    pub component: String,
    /// Mechanism that will own the definition.
    pub mechanism: ServiceMechanism,
    /// What the plan does with the definition.
    pub action: ServiceAction,
    /// Whether writing the definition needs administrator rights.
    pub requires_elevation: bool,
    /// Absolute definition path, when the platform fixes one.
    pub definition_path: Option<String>,
}

/// One permission the install needs, with the reason it is needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permission {
    /// Identifier from [`PERMISSIONS`].
    pub id: String,
    /// Scope the permission is requested in.
    pub scope: InstallScope,
    /// True only for the `elevated` permission.
    pub requires_elevation: bool,
    /// Why the permission is needed.
    pub reason: String,
}

/// One network location the install is planned to contact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAccess {
    /// Component that would contact it.
    pub component: String,
    /// Location that would be contacted.
    pub url: String,
    /// Why, in reviewable prose.
    pub purpose: String,
    /// Always `false`; a plan contacts nothing.
    pub executed: bool,
}

/// What the install keeps so a version can be rolled back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackPlan {
    /// Working versions kept beside the activated one.
    pub keeps_previous_versions: u64,
    /// Absolute pointer an activation moves.
    pub current_pointer: String,
    /// Absolute directory holding the per-install journal.
    pub journal_directory: String,
}

/// The reviewable, dry-run installation plan.
///
/// Serialise it with [`InstallPlan::to_json`], and seal it with [`sealed`] to
/// obtain the digest `install apply` must be approved against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallPlan {
    /// Document schema version; must equal [`INSTALL_PLAN_SCHEMA_VERSION`].
    pub schema_version: u64,
    /// Document kind; always [`PLAN_KIND`].
    pub plan_kind: String,
    /// Specification baseline the plan was produced under.
    pub spec_version: String,
    /// Identifier of this plan.
    pub plan_id: String,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// Always `true`; a document that is not a dry run is not a plan.
    pub dry_run: bool,
    /// The bundle the plan was built from.
    pub bundle: BundleReference,
    /// What the plan targets.
    pub target: InstallTarget,
    /// The components the plan places.
    pub components: Vec<PlannedComponent>,
    /// The service changes the plan announces.
    pub service_changes: Vec<PlannedServiceChange>,
    /// The permissions the install needs.
    pub permissions: Vec<Permission>,
    /// The network locations the install is planned to contact.
    pub network_access: Vec<NetworkAccess>,
    /// Bytes the install root must have free for staging plus activation.
    pub disk_headroom_bytes: u64,
    /// What is kept for rollback.
    pub rollback: RollbackPlan,
}

/// Plan one installation from a manifest the caller already read.
///
/// This function is the AC1 dry run: it is pure over its inputs, so it cannot
/// write, download, launch or observe anything. Everything a plan depends on --
/// the plan id, the timestamp, the target, the scope and the versions discovery
/// observed -- arrives through [`PlanContext`].
///
/// # Errors
/// - [`ErrorCode::ValidationError`] when the manifest or the context violates
///   the contract, when an artifact was built for another host, when the bundle
///   root is not an absolute path, or when the manifest digest is not a digest.
/// - [`ErrorCode::Forbidden`] when a per-user plan needs administrator rights,
///   when a system mechanism is planned outside a system scope, or when a
///   system-scoped plan has no explicit opt-in.
/// - [`ErrorCode::Conflict`] when two components plan the same destination.
pub fn plan_install(
    manifest: &BundleManifest,
    manifest_sha256: &str,
    bundle_root: &str,
    context: &PlanContext,
    _dry_run: DryRun,
) -> Result<InstallPlan, AxiomError> {
    manifest.validate()?;
    validate_context(context)?;
    if !is_digest(manifest_sha256) {
        return Err(refuse("manifest_sha256", manifest_sha256));
    }
    if !is_absolute_host_path(bundle_root) {
        return Err(refuse("bundle_root", bundle_root));
    }
    let bundle_root = trim_root(bundle_root);

    let install_root = trim_root(&context.install_root);
    let versions_root = under(&install_root, &[VERSIONS_DIRECTORY]);
    let staging_root = under(&install_root, &[STAGING_DIRECTORY]);
    let mut components: Vec<PlannedComponent> = Vec::new();
    let mut permissions: Vec<Permission> = Vec::new();
    let mut service_changes: Vec<PlannedServiceChange> = Vec::new();
    let mut network_access: Vec<NetworkAccess> = Vec::new();
    let mut destinations: BTreeMap<String, String> = BTreeMap::new();
    let mut disk_headroom_bytes = 0_u64;

    for declared in &manifest.components {
        if declared.host != context.host {
            return Err(refuse("host", &declared.host).with_detail("expected", &context.host));
        }
        if context.scope == InstallScope::PerUser
            && declared
                .permissions
                .iter()
                .any(|permission| permission == "elevated")
        {
            return Err(AxiomError::new(
                ErrorCode::Forbidden,
                "a per-user install may not require administrator rights",
            )
            .with_detail("rule", "elevated_permission")
            .with_detail("component", &declared.component)
            .with_detail("observed", "elevated"));
        }
        let artifact_segments: Vec<&str> = declared.artifact.split('/').collect();
        let version_directory = under(&versions_root, &[declared.version.as_str()]);
        let destination = under(&version_directory, &artifact_segments);
        let staging_directory = format!("{}-{}", declared.component, declared.version);
        let staged_destination = under(&staging_root, &[staging_directory.as_str()]);
        let staged_destination = under(&staged_destination, &artifact_segments);
        if let Some(previous) = destinations.insert(destination.clone(), declared.component.clone())
        {
            return Err(AxiomError::new(
                ErrorCode::Conflict,
                "two components plan the same destination",
            )
            .with_detail("rule", "destination_collision")
            .with_detail("component", &declared.component)
            .with_detail("observed", &destination)
            .with_detail("expected", &previous));
        }
        for permission in &declared.permissions {
            permissions.push(Permission {
                id: permission.clone(),
                scope: context.scope,
                requires_elevation: permission == "elevated",
                reason: format!("required by component {}", declared.component),
            });
        }
        if let Some(service) = &declared.service {
            if service.mechanism.is_system() && context.scope != InstallScope::System {
                return Err(AxiomError::new(
                    ErrorCode::Forbidden,
                    "a system service mechanism needs a system-scoped plan",
                )
                .with_detail("rule", "service_mechanism")
                .with_detail("component", &declared.component)
                .with_detail("observed", service.mechanism.as_str()));
            }
            service_changes.push(PlannedServiceChange {
                component: declared.component.clone(),
                mechanism: service.mechanism,
                action: service.action,
                requires_elevation: service.requires_elevation || service.mechanism.is_system(),
                definition_path: None,
            });
        }
        for declaration in &declared.network_access {
            network_access.push(NetworkAccess {
                component: declared.component.clone(),
                url: declaration.url.clone(),
                purpose: declaration.purpose.clone(),
                executed: false,
            });
        }
        disk_headroom_bytes =
            disk_headroom_bytes.saturating_add(declared.size_bytes.saturating_mul(2));
        components.push(PlannedComponent {
            component: declared.component.clone(),
            version: declared.version.clone(),
            action: action_for(context, declared),
            kind: declared.kind,
            artifact: declared.artifact.clone(),
            destination,
            staged_destination,
            source: DownloadSource {
                kind: SourceKind::LocalBundle,
                location: under(&bundle_root, &artifact_segments),
                sha256: declared.sha256.clone(),
                size_bytes: declared.size_bytes,
                executed: false,
            },
            permissions: declared.permissions.clone(),
        });
    }

    let plan = InstallPlan {
        schema_version: INSTALL_PLAN_SCHEMA_VERSION,
        plan_kind: PLAN_KIND.to_string(),
        spec_version: SPEC_VERSION.to_string(),
        plan_id: context.plan_id.clone(),
        created_at: context.created_at.clone(),
        dry_run: true,
        bundle: BundleReference {
            bundle_id: manifest.bundle_id.clone(),
            channel: manifest.channel.clone(),
            created_at: manifest.created_at.clone(),
            manifest_sha256: manifest_sha256.to_string(),
            location: bundle_root.clone(),
        },
        target: InstallTarget {
            host: context.host.clone(),
            install_root,
            scope: context.scope,
            versions_root,
            staging_root,
        },
        components,
        service_changes,
        permissions,
        network_access,
        disk_headroom_bytes,
        rollback: RollbackPlan {
            keeps_previous_versions: context.keep_previous_versions,
            current_pointer: under(&context.install_root, &["current"]),
            journal_directory: under(&context.install_root, &["journal"]),
        },
    };
    plan.validate()?;
    Ok(plan)
}

/// What the plan does with one component, from the versions discovery observed.
///
/// `reinstall` is in the vocabulary for an explicit later request; planning
/// never selects it, because no observed state justifies rewriting an identical
/// version during a first install.
fn action_for(context: &PlanContext, declared: &BundleComponent) -> ComponentAction {
    match context.observed_version(&declared.component) {
        None => ComponentAction::Install,
        Some(version) if version == declared.version => ComponentAction::Noop,
        Some(_) => ComponentAction::Upgrade,
    }
}

/// Validate the caller-supplied planner inputs.
fn validate_context(context: &PlanContext) -> Result<(), AxiomError> {
    if !graph_core::paths::is_portable_id(&context.plan_id) {
        return Err(refuse("plan_id", &context.plan_id));
    }
    if context.created_at.trim().is_empty() {
        return Err(refuse("created_at", "empty"));
    }
    if !HOSTS.contains(&context.host.as_str()) {
        return Err(refuse("host", &context.host));
    }
    if !is_absolute_host_path(&context.install_root) {
        return Err(refuse("install_root", &context.install_root));
    }
    if context.keep_previous_versions < MIN_KEEP_PREVIOUS_VERSIONS {
        let observed = context.keep_previous_versions.to_string();
        return Err(refuse("keep_previous_versions", &observed));
    }
    if context.scope == InstallScope::System && !context.allow_system {
        return Err(AxiomError::new(
            ErrorCode::Forbidden,
            "a system-scoped install requires explicit opt-in",
        )
        .with_detail("rule", "scope_system_opt_in")
        .with_detail("observed", InstallScope::System.as_str()));
    }
    for observed in &context.observed {
        if !COMPONENTS.contains(&observed.component.as_str()) {
            return Err(refuse("observed.component", &observed.component));
        }
        if !is_version_token(&observed.version) {
            return Err(refuse("observed.version", &observed.version));
        }
    }
    Ok(())
}

/// A version token that is safe as one path segment.
///
/// Versions are not portable slugs (`0.0.0-dev` starts with a digit), so they
/// are checked against the narrower rule that matters here: they must be safe to
/// append to the version directory and cannot traverse out of it.
#[must_use]
pub fn is_version_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

/// Strip a trailing separator so joining is not doubled.
fn trim_root(root: &str) -> String {
    let trimmed = root.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        String::from(root)
    } else {
        trimmed.to_string()
    }
}

/// Join path segments with the host separator.
///
/// Crate-visible so `install::credentials` builds its directory the same way
/// the planner builds the version and staging trees (one path builder).
pub(crate) fn under(root: &str, segments: &[&str]) -> String {
    let mut path = PathBuf::from(root);
    for segment in segments {
        path.push(segment);
    }
    path.to_string_lossy().into_owned()
}

impl InstallPlan {
    /// Validate the document against the install-plan contract it claims.
    ///
    /// The rules are the ones a reviewer would otherwise have to check by hand:
    /// the document is a dry run, every destination is inside the plan's own
    /// version tree, no two components collide, no per-user plan claims
    /// administrator rights, and nothing is reported as already executed.
    ///
    /// # Errors
    /// - [`ErrorCode::ValidationError`] for a malformed document.
    /// - [`ErrorCode::Forbidden`] when the document claims a permission or a
    ///   mechanism the declared scope cannot have.
    /// - [`ErrorCode::Conflict`] when two components share a destination.
    pub fn validate(&self) -> Result<(), AxiomError> {
        if self.schema_version != INSTALL_PLAN_SCHEMA_VERSION {
            let observed = self.schema_version.to_string();
            return Err(refuse("schema_version", &observed));
        }
        if self.plan_kind != PLAN_KIND {
            return Err(refuse("plan_kind", &self.plan_kind));
        }
        if self.spec_version != SPEC_VERSION {
            return Err(refuse("spec_version", &self.spec_version));
        }
        if !self.dry_run {
            return Err(refuse("dry_run", "false"));
        }
        if !graph_core::paths::is_portable_id(&self.plan_id) {
            return Err(refuse("plan_id", &self.plan_id));
        }
        if self.created_at.trim().is_empty() {
            return Err(refuse("created_at", "empty"));
        }
        if !HOSTS.contains(&self.target.host.as_str()) {
            return Err(refuse("target.host", &self.target.host));
        }
        for (field, path) in [
            ("target.install_root", &self.target.install_root),
            ("target.versions_root", &self.target.versions_root),
            ("target.staging_root", &self.target.staging_root),
            ("bundle.location", &self.bundle.location),
            ("rollback.current_pointer", &self.rollback.current_pointer),
            (
                "rollback.journal_directory",
                &self.rollback.journal_directory,
            ),
        ] {
            if !is_absolute_host_path(path) {
                return Err(refuse(field, path));
            }
        }
        if !is_digest(&self.bundle.manifest_sha256) {
            return Err(refuse(
                "bundle.manifest_sha256",
                &self.bundle.manifest_sha256,
            ));
        }
        if self.components.is_empty() {
            return Err(refuse("components", "empty"));
        }
        if self.disk_headroom_bytes == 0 {
            return Err(refuse("disk_headroom_bytes", "0"));
        }
        if self.rollback.keeps_previous_versions < MIN_KEEP_PREVIOUS_VERSIONS {
            let observed = self.rollback.keeps_previous_versions.to_string();
            return Err(refuse("rollback.keeps_previous_versions", &observed));
        }
        let mut destinations: BTreeMap<&str, &str> = BTreeMap::new();
        for component in &self.components {
            if !COMPONENTS.contains(&component.component.as_str()) {
                return Err(refuse("component", &component.component));
            }
            if !is_version_token(&component.version) {
                return Err(refuse("component.version", &component.version));
            }
            if !is_digest(&component.source.sha256) {
                return Err(refuse("component.source.sha256", &component.source.sha256));
            }
            if component.source.executed {
                return Err(refuse("component.source.executed", "true"));
            }
            if component.source.size_bytes == 0 {
                return Err(refuse("component.source.size_bytes", "0"));
            }
            if !is_absolute_host_path(&component.destination) {
                return Err(refuse("component.destination", &component.destination));
            }
            if !is_absolute_host_path(&component.staged_destination) {
                return Err(refuse(
                    "component.staged_destination",
                    &component.staged_destination,
                ));
            }
            if component.destination == component.staged_destination {
                return Err(refuse(
                    "component.staged_destination",
                    "same as destination",
                ));
            }
            for permission in &component.permissions {
                if !PERMISSIONS.contains(&permission.as_str()) {
                    return Err(refuse("component.permissions", permission));
                }
            }
            if component.permissions.iter().any(|id| id == "elevated")
                && self.target.scope != InstallScope::System
            {
                return Err(AxiomError::new(
                    ErrorCode::Forbidden,
                    "a per-user install may not require administrator rights",
                )
                .with_detail("rule", "elevated_permission")
                .with_detail("component", &component.component));
            }
            if let Some(previous) =
                destinations.insert(&component.destination, &component.component)
            {
                return Err(AxiomError::new(
                    ErrorCode::Conflict,
                    "two components plan the same destination",
                )
                .with_detail("rule", "destination_collision")
                .with_detail("component", &component.component)
                .with_detail("observed", &component.destination)
                .with_detail("expected", previous));
            }
        }
        for permission in &self.permissions {
            if !PERMISSIONS.contains(&permission.id.as_str()) {
                return Err(refuse("permissions", &permission.id));
            }
            if permission.requires_elevation != (permission.id == "elevated") {
                return Err(refuse("elevation_flag", &permission.id));
            }
            if permission.requires_elevation && self.target.scope != InstallScope::System {
                return Err(AxiomError::new(
                    ErrorCode::Forbidden,
                    "a per-user install may not require administrator rights",
                )
                .with_detail("rule", "elevated_permission")
                .with_detail("observed", &permission.id));
            }
        }
        for change in &self.service_changes {
            if !COMPONENTS.contains(&change.component.as_str()) {
                return Err(refuse("service_changes.component", &change.component));
            }
            if matches!(change.mechanism, ServiceMechanism::Absent)
                != matches!(change.action, ServiceAction::Absent)
            {
                return Err(refuse("service_changes", "mechanism and action disagree"));
            }
            if change.mechanism.is_system() && self.target.scope != InstallScope::System {
                return Err(AxiomError::new(
                    ErrorCode::Forbidden,
                    "a system service mechanism needs a system-scoped plan",
                )
                .with_detail("rule", "service_mechanism")
                .with_detail("component", &change.component)
                .with_detail("observed", change.mechanism.as_str()));
            }
        }
        for access in &self.network_access {
            if !COMPONENTS.contains(&access.component.as_str()) {
                return Err(refuse("network_access.component", &access.component));
            }
            if access.executed {
                return Err(refuse("network_access.executed", "true"));
            }
            if access.url.trim().is_empty() {
                return Err(refuse("network_access.url", "empty"));
            }
            if access.purpose.trim().is_empty() {
                return Err(refuse("network_access.purpose", "empty"));
            }
        }
        Ok(())
    }

    /// The document as one JSON object.
    ///
    /// # Errors
    /// Fails only if the document cannot be serialised, which is an Axiom
    /// defect; validation is a separate step so a caller cannot mistake a
    /// serialised plan for a valid one.
    pub fn to_value(&self) -> Result<Value, AxiomError> {
        serde_json::to_value(self).map_err(|error| {
            AxiomError::new(ErrorCode::Internal, "the install plan is not serialisable")
                .with_detail("observed", error.to_string())
        })
    }

    /// One canonical JSON line, after validation.
    ///
    /// # Errors
    /// Propagates [`InstallPlan::validate`] so an invalid plan never renders.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        self.validate()?;
        serde_json::to_string(self).map_err(|error| {
            AxiomError::new(ErrorCode::Internal, "the install plan is not serialisable")
                .with_detail("observed", error.to_string())
        })
    }

    /// The human-reviewable rendering section C asks a reviewer to read.
    #[must_use]
    pub fn text(&self) -> String {
        let mut text = String::new();
        text.push_str(&format!(
            "install plan {} (dry run) kind={} scope={} host={}\n",
            self.plan_id,
            self.plan_kind,
            self.target.scope.as_str(),
            self.target.host
        ));
        text.push_str(&format!(
            "bundle {} channel={} manifest_sha256={}\n",
            self.bundle.bundle_id, self.bundle.channel, self.bundle.manifest_sha256
        ));
        text.push_str(&format!(
            "install_root {} versions={} staging={}\n",
            self.target.install_root, self.target.versions_root, self.target.staging_root
        ));
        for component in &self.components {
            text.push_str(&format!(
                "component {} {} {} (kind {})\n",
                component.component,
                component.version,
                component.action.as_str(),
                component.kind.as_str()
            ));
            text.push_str(&format!(
                "  source {} {} sha256={} size={} executed={}\n",
                component.source.kind.as_str(),
                component.source.location,
                component.source.sha256,
                component.source.size_bytes,
                if component.source.executed {
                    "yes"
                } else {
                    "no"
                }
            ));
            text.push_str(&format!(
                "  destination {}\n  staged {}\n",
                component.destination, component.staged_destination
            ));
            text.push_str(&format!(
                "  permissions {}\n",
                component.permissions.join(", ")
            ));
        }
        for change in &self.service_changes {
            text.push_str(&format!(
                "service {} {} {} (elevation: {})\n",
                change.component,
                change.mechanism.as_str(),
                change.action.as_str(),
                if change.requires_elevation {
                    "yes"
                } else {
                    "no"
                }
            ));
        }
        for access in &self.network_access {
            text.push_str(&format!(
                "network {} {} ({}) executed={}\n",
                access.component,
                access.url,
                access.purpose,
                if access.executed { "yes" } else { "no" }
            ));
        }
        for permission in &self.permissions {
            text.push_str(&format!(
                "permission {} scope={} elevation={} ({})\n",
                permission.id,
                permission.scope.as_str(),
                if permission.requires_elevation {
                    "yes"
                } else {
                    "no"
                },
                permission.reason
            ));
        }
        text.push_str(&format!(
            "rollback keeps {} previous version(s) pointer={} journal={}\n",
            self.rollback.keeps_previous_versions,
            self.rollback.current_pointer,
            self.rollback.journal_directory
        ));
        text.push_str(&format!(
            "disk headroom {} bytes\n",
            self.disk_headroom_bytes
        ));
        text
    }
}

/// Seal a plan with the one canonical plan digest of this workspace.
///
/// The returned object is the plan plus its `plan_digest`; the digest covers
/// every planner input and excludes only the approval metadata, which is
/// [`crate::plan`]'s contract. `install apply` is approved against this digest,
/// so an approval of one plan can never activate a different one.
///
/// # Errors
/// Fails when the plan cannot be represented as a JSON object.
pub fn sealed(plan: &InstallPlan) -> Result<(Value, String), AxiomError> {
    let mut value = plan.to_value()?;
    let digest = crate::plan::seal_digest(&mut value)?;
    Ok((value, digest))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;

    /// A lowercase 64-hex digest built from one repeated byte.
    fn hex(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    /// One bundle manifest declaring two components for the Linux host.
    fn manifest() -> BundleManifest {
        BundleManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            bundle_id: "axiom-core".to_string(),
            channel: "stable".to_string(),
            created_at: "2026-09-19T00:00:00Z".to_string(),
            components: vec![
                BundleComponent {
                    component: "axiom-graphd".to_string(),
                    version: "0.0.0-dev".to_string(),
                    host: "linux-x64".to_string(),
                    artifact: "bin/axiom-graphd".to_string(),
                    kind: ArtifactKind::Binary,
                    sha256: hex(0xab),
                    size_bytes: 4096,
                    permissions: vec!["read".to_string(), "execute".to_string()],
                    service: Some(BundleService {
                        mechanism: ServiceMechanism::SystemdUserUnit,
                        action: ServiceAction::Install,
                        requires_elevation: false,
                    }),
                    network_access: vec![NetworkAccessDeclaration {
                        url: "http://127.0.0.1:8766/health".to_string(),
                        purpose: "loopback health probe".to_string(),
                    }],
                },
                BundleComponent {
                    component: "axiom-mcp".to_string(),
                    version: "0.0.0-dev".to_string(),
                    host: "linux-x64".to_string(),
                    artifact: "python/axiom_mcp-0.0.0.dev0-py3-none-any.whl".to_string(),
                    kind: ArtifactKind::Python,
                    sha256: hex(0xcd),
                    size_bytes: 2048,
                    permissions: vec!["read".to_string()],
                    service: None,
                    network_access: Vec::new(),
                },
            ],
        }
    }

    /// A per-user context on the Linux host.
    fn context() -> PlanContext {
        PlanContext::per_user(
            "install-20260919-0001",
            "2026-09-19T00:00:00Z",
            "linux-x64",
            "/tmp/axiom-home",
        )
    }

    /// One dry run over the fixture bundle.
    fn planned() -> InstallPlan {
        plan_install(
            &manifest(),
            &hex(0x11),
            "/tmp/bundle",
            &context(),
            DryRun::new(),
        )
        .expect("the fixture bundle plans")
    }

    /// Recursive `path -> (bytes, sha256)` snapshot of a directory tree.
    fn tree(root: &Path) -> BTreeMap<String, (u64, String)> {
        let mut out: BTreeMap<String, (u64, String)> = BTreeMap::new();
        let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
        while let Some(directory) = stack.pop() {
            for entry in std::fs::read_dir(&directory).expect("the fixture is readable") {
                let path = entry.expect("a fixture entry").path();
                let metadata = std::fs::symlink_metadata(&path).expect("fixture metadata");
                if metadata.is_dir() {
                    out.insert(format!("dir:{}", path.display()), (0, String::new()));
                    stack.push(path);
                } else {
                    let bytes = std::fs::read(&path).expect("a readable fixture file");
                    out.insert(
                        format!("file:{}", path.display()),
                        (metadata.len(), graph_export::sha256_hex(&bytes)),
                    );
                }
            }
        }
        out
    }

    #[test]
    fn a_dry_run_plan_reports_versions_destinations_sources_and_permissions() {
        let plan = planned();
        plan.validate().expect("the plan is valid");
        assert!(plan.dry_run);
        assert_eq!(plan.schema_version, INSTALL_PLAN_SCHEMA_VERSION);
        assert_eq!(plan.plan_kind, PLAN_KIND);
        assert_eq!(plan.spec_version, SPEC_VERSION);
        assert_eq!(plan.components.len(), 2);

        let graphd = &plan.components[0];
        assert_eq!(graphd.component, "axiom-graphd");
        assert_eq!(graphd.version, "0.0.0-dev");
        assert_eq!(graphd.action, ComponentAction::Install);
        assert_eq!(graphd.kind, ArtifactKind::Binary);
        assert_eq!(
            graphd.destination,
            under(
                "/tmp/axiom-home",
                &[VERSIONS_DIRECTORY, "0.0.0-dev", "bin", "axiom-graphd"]
            )
        );
        assert_eq!(
            graphd.staged_destination,
            under(
                "/tmp/axiom-home",
                &[
                    STAGING_DIRECTORY,
                    "axiom-graphd-0.0.0-dev",
                    "bin",
                    "axiom-graphd"
                ]
            )
        );
        assert_eq!(graphd.source.kind, SourceKind::LocalBundle);
        assert_eq!(
            graphd.source.location,
            under("/tmp/bundle", &["bin", "axiom-graphd"])
        );
        assert_eq!(graphd.source.sha256, hex(0xab));
        assert_eq!(graphd.source.size_bytes, 4096);
        assert!(!graphd.source.executed);
        assert_eq!(
            graphd.permissions,
            vec!["read".to_string(), "execute".to_string()]
        );

        assert_eq!(plan.bundle.bundle_id, "axiom-core");
        assert_eq!(plan.bundle.channel, "stable");
        assert_eq!(plan.bundle.manifest_sha256, hex(0x11));
        assert_eq!(plan.bundle.location, "/tmp/bundle");
        assert_eq!(plan.target.host, "linux-x64");
        assert_eq!(plan.target.scope, InstallScope::PerUser);
        assert_eq!(plan.rollback.keeps_previous_versions, 1);
        assert_eq!(plan.disk_headroom_bytes, (4096 + 2048) * 2);

        assert_eq!(plan.permissions.len(), 3);
        assert!(plan
            .permissions
            .iter()
            .all(|entry| !entry.requires_elevation));
        assert!(plan
            .permissions
            .iter()
            .all(|entry| entry.scope == InstallScope::PerUser));
        assert_eq!(plan.service_changes.len(), 1);
        assert_eq!(
            plan.service_changes[0].mechanism,
            ServiceMechanism::SystemdUserUnit
        );
        assert!(!plan.service_changes[0].requires_elevation);
        assert_eq!(plan.network_access.len(), 1);
        assert_eq!(plan.network_access[0].url, "http://127.0.0.1:8766/health");
        assert!(!plan.network_access[0].executed);

        let json = plan.to_json().expect("the plan renders");
        let decoded: InstallPlan = serde_json::from_str(&json).expect("the plan round trips");
        assert_eq!(decoded, plan);
        assert!(plan.text().contains("install plan install-20260919-0001"));
    }

    #[test]
    fn planning_reads_the_bundle_without_writing_or_downloading_anything() {
        let bundle = TempDir::new().expect("a temporary bundle");
        let manifest_bytes = serde_json::to_vec(&manifest()).expect("the manifest serialises");
        std::fs::write(bundle.path().join(BUNDLE_MANIFEST_FILE), &manifest_bytes)
            .expect("the fixture manifest is written");

        let before = tree(bundle.path());
        assert_eq!(before.len(), 1, "the fixture holds exactly one file");

        let (read_back, digest) =
            read_bundle_manifest(bundle.path()).expect("the fixture manifest parses");
        assert_eq!(read_back, manifest());
        assert_eq!(digest, graph_export::sha256_hex(&manifest_bytes));

        let bundle_root = bundle.path().to_string_lossy().into_owned();
        let plan = plan_install(&read_back, &digest, &bundle_root, &context(), DryRun::new())
            .expect("the fixture bundle plans");
        let (value, sealed_digest) = sealed(&plan).expect("the plan seals");
        assert_eq!(value["plan_digest"].as_str(), Some(sealed_digest.as_str()));
        assert!(plan.components.iter().all(|entry| !entry.source.executed));
        assert!(plan.network_access.iter().all(|entry| !entry.executed));

        let after = tree(bundle.path());
        assert_eq!(before, after, "a dry run must not touch the bundle");
    }

    #[test]
    fn a_per_user_plan_refuses_an_elevated_permission() {
        let mut manifest = manifest();
        manifest.components[0]
            .permissions
            .push("elevated".to_string());
        let error = plan_install(
            &manifest,
            &hex(0x11),
            "/tmp/bundle",
            &context(),
            DryRun::new(),
        )
        .expect_err("an elevated permission is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("elevated_permission")
        );
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("elevated")
        );
        assert_eq!(
            error.details().get("component").map(String::as_str),
            Some("axiom-graphd")
        );
    }

    #[test]
    fn a_system_scope_plan_requires_explicit_opt_in() {
        let mut context = context();
        context.scope = InstallScope::System;
        let error = plan_install(
            &manifest(),
            &hex(0x11),
            "/tmp/bundle",
            &context,
            DryRun::new(),
        )
        .expect_err("a system scope without opt-in is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);

        context.allow_system = true;
        let plan = plan_install(
            &manifest(),
            &hex(0x11),
            "/tmp/bundle",
            &context,
            DryRun::new(),
        )
        .expect("an opted-in system plan is produced");
        assert_eq!(plan.target.scope, InstallScope::System);
        assert!(plan
            .permissions
            .iter()
            .all(|entry| !entry.requires_elevation));
    }

    #[test]
    fn a_system_service_mechanism_is_refused_in_a_per_user_plan() {
        let mut manifest = manifest();
        manifest.components[0].service = Some(BundleService {
            mechanism: ServiceMechanism::SystemService,
            action: ServiceAction::Install,
            requires_elevation: true,
        });
        let error = plan_install(
            &manifest,
            &hex(0x11),
            "/tmp/bundle",
            &context(),
            DryRun::new(),
        )
        .expect_err("a system service mechanism is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
    }

    #[test]
    fn a_document_that_is_not_a_dry_run_is_refused() {
        let mut tampered = planned();
        tampered.dry_run = false;
        let error = tampered
            .validate()
            .expect_err("a non-dry-run document is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("dry_run")
        );
        assert!(tampered.to_json().is_err(), "an invalid plan never renders");
    }

    #[test]
    fn an_artifact_built_for_another_host_is_refused() {
        let mut manifest = manifest();
        manifest.components[1].host = "macos-arm64".to_string();
        let error = plan_install(
            &manifest,
            &hex(0x11),
            "/tmp/bundle",
            &context(),
            DryRun::new(),
        )
        .expect_err("a foreign-host artifact is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("host")
        );
        assert_eq!(
            error.details().get("expected").map(String::as_str),
            Some("linux-x64")
        );
    }

    #[test]
    fn an_empty_bundle_is_refused() {
        let mut manifest = manifest();
        manifest.components.clear();
        let error = plan_install(
            &manifest,
            &hex(0x11),
            "/tmp/bundle",
            &context(),
            DryRun::new(),
        )
        .expect_err("an empty bundle is refused");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("components")
        );
    }

    #[test]
    fn two_components_may_not_plan_the_same_destination() {
        let mut manifest = manifest();
        let mut duplicate = manifest.components[0].clone();
        duplicate.component = "axiom".to_string();
        manifest.components.push(duplicate);
        let error = plan_install(
            &manifest,
            &hex(0x11),
            "/tmp/bundle",
            &context(),
            DryRun::new(),
        )
        .expect_err("a destination collision is refused");
        assert_eq!(error.code(), ErrorCode::Conflict);
    }

    #[test]
    fn an_artifact_path_that_escapes_the_bundle_is_refused() {
        let mut manifest = manifest();
        manifest.components[0].artifact = "../escape/axiom-graphd".to_string();
        let error = plan_install(
            &manifest,
            &hex(0x11),
            "/tmp/bundle",
            &context(),
            DryRun::new(),
        )
        .expect_err("a traversing artifact path is refused");
        assert_eq!(error.code(), ErrorCode::UnsafePortablePath);
    }

    #[test]
    fn a_version_that_is_not_a_path_segment_is_refused() {
        let mut manifest = manifest();
        manifest.components[0].version = "../../etc".to_string();
        let error = plan_install(
            &manifest,
            &hex(0x11),
            "/tmp/bundle",
            &context(),
            DryRun::new(),
        )
        .expect_err("a traversing version is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("component.version")
        );
    }

    #[test]
    fn an_observed_version_decides_between_noop_and_upgrade() {
        let mut context = context();
        context.observed = vec![ObservedComponent {
            component: "axiom-graphd".to_string(),
            version: "0.0.0-dev".to_string(),
        }];
        let plan = plan_install(
            &manifest(),
            &hex(0x11),
            "/tmp/bundle",
            &context,
            DryRun::new(),
        )
        .expect("the fixture bundle plans");
        assert_eq!(plan.components[0].action, ComponentAction::Noop);
        assert_eq!(plan.components[1].action, ComponentAction::Install);

        context.observed[0].version = "0.0.0-old".to_string();
        let plan = plan_install(
            &manifest(),
            &hex(0x11),
            "/tmp/bundle",
            &context,
            DryRun::new(),
        )
        .expect("the fixture bundle plans");
        assert_eq!(plan.components[0].action, ComponentAction::Upgrade);
    }

    #[test]
    fn a_missing_bundle_manifest_is_not_found() {
        let error = read_bundle_manifest(Path::new("/no-such-axiom-bundle-directory"))
            .expect_err("a missing manifest is refused");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("bundle_manifest")
        );
        // `observed` names the file that was seen, `actual` the portable
        // `io::ErrorKind` reason, which reads the same on every host.
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some(BUNDLE_MANIFEST_FILE)
        );
        assert_eq!(
            error.details().get("actual").map(String::as_str),
            Some("entity not found")
        );
    }

    #[test]
    fn a_malformed_manifest_fails_closed() {
        let bundle = TempDir::new().expect("a temporary bundle");
        let path = bundle.path().join(BUNDLE_MANIFEST_FILE);

        std::fs::write(&path, b"not json at all").expect("the fixture is written");
        let error = read_bundle_manifest(bundle.path()).expect_err("invalid JSON is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);

        let mut tampered = manifest();
        tampered.components[0].sha256 = "abc".to_string();
        std::fs::write(
            &path,
            serde_json::to_vec(&tampered).expect("the tampered manifest serialises"),
        )
        .expect("the fixture is written");
        let error = read_bundle_manifest(bundle.path()).expect_err("a bad digest is refused");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("sha256")
        );

        std::fs::write(&path, vec![b' '; MAX_MANIFEST_BYTES as usize + 2])
            .expect("the oversized fixture is written");
        let error =
            read_bundle_manifest(bundle.path()).expect_err("an oversized manifest is refused");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("manifest_bytes")
        );
    }

    #[test]
    fn an_approval_of_one_plan_never_activates_another() {
        let plan = planned();
        let (mut value, digest) = sealed(&plan).expect("the plan seals");
        assert!(crate::plan::approval_reasons(&value, &digest).is_empty());

        value["components"][0]["version"] = Value::String("9.9.9".to_string());
        // An in-place edit still carries the old self-digest, so only the stale
        // approval fires; the body still claims to be the approved document.
        assert_eq!(
            crate::plan::approval_reasons(&value, &digest),
            vec!["approval_stale".to_string()]
        );
        // Re-sealing cannot resurrect the old approval: both reasons fire.
        let mut resealed = value.clone();
        crate::plan::seal_digest(&mut resealed).expect("the tampered plan re-seals");
        assert_eq!(
            crate::plan::approval_reasons(&resealed, &digest),
            vec![
                "approval_stale".to_string(),
                "plan_digest_not_approved".to_string()
            ]
        );
    }

    #[test]
    fn every_wire_spelling_matches_the_plan_vocabulary() {
        assert_eq!(
            COMPONENTS.to_vec(),
            crate::discovery::INSTALLABLE_COMPONENTS.to_vec()
        );

        let scopes: Vec<&str> = InstallScope::all()
            .iter()
            .map(|value| value.as_str())
            .collect();
        assert_eq!(scopes, SCOPES.to_vec());
        let actions: Vec<&str> = ComponentAction::all()
            .iter()
            .map(|value| value.as_str())
            .collect();
        assert_eq!(actions, ACTIONS.to_vec());
        let sources: Vec<&str> = SourceKind::all()
            .iter()
            .map(|value| value.as_str())
            .collect();
        assert_eq!(sources, SOURCE_KINDS.to_vec());
        let kinds: Vec<&str> = ArtifactKind::all()
            .iter()
            .map(|value| value.as_str())
            .collect();
        assert_eq!(kinds, ARTIFACT_KINDS.to_vec());
        let mechanisms: Vec<&str> = ServiceMechanism::all()
            .iter()
            .map(|value| value.as_str())
            .collect();
        assert_eq!(mechanisms, SERVICE_MECHANISMS.to_vec());
        let service_actions: Vec<&str> = ServiceAction::all()
            .iter()
            .map(|value| value.as_str())
            .collect();
        assert_eq!(service_actions, SERVICE_ACTIONS.to_vec());

        for scope in InstallScope::all() {
            let json = serde_json::to_string(scope).expect("serialisable");
            assert_eq!(json, format!("\"{}\"", scope.as_str()));
        }
        for action in ComponentAction::all() {
            let json = serde_json::to_string(action).expect("serialisable");
            assert_eq!(json, format!("\"{}\"", action.as_str()));
        }
        for mechanism in ServiceMechanism::all() {
            let json = serde_json::to_string(mechanism).expect("serialisable");
            assert_eq!(json, format!("\"{}\"", mechanism.as_str()));
        }
        assert!(ServiceMechanism::SystemService.is_system());
        assert!(!ServiceMechanism::PerUserStartup.is_system());
    }

    #[test]
    fn macos_host_depends_on_the_architecture_not_the_os() {
        // Regression: this used to answer `macos-arm64` for every macOS build,
        // so an x86_64 MacIntel binary planned for a host row the running
        // machine is not, and `plan_ecosystem` then refused a bundle it had
        // itself been built to accept.
        assert_eq!(host_identifier_for(Platform::MacOs, "x86_64"), "macos-x64");
        assert_eq!(
            host_identifier_for(Platform::MacOs, "aarch64"),
            "macos-arm64"
        );
        assert_ne!(
            host_identifier_for(Platform::MacOs, "x86_64"),
            host_identifier_for(Platform::MacOs, "aarch64")
        );
    }

    /// The combinations a release set can be built for, or refuse.
    const ARCHITECTURES: [&str; 4] = ["x86_64", "aarch64", "i686", "unknown"];
    const PLATFORMS: [Platform; 4] = [
        Platform::Windows,
        Platform::Linux,
        Platform::MacOs,
        Platform::Unknown,
    ];

    #[test]
    fn every_host_identifier_is_a_declared_row_or_unknown() {
        for platform in PLATFORMS {
            for architecture in ARCHITECTURES {
                let identifier = host_identifier_for(platform, architecture);
                assert!(
                    identifier == "unknown" || HOSTS.contains(&identifier),
                    "{} / {} produced undeclared host {identifier}",
                    platform.as_str(),
                    architecture
                );
            }
        }
    }

    #[test]
    fn every_declared_row_is_reachable() {
        // A row no platform/architecture pair can produce is a declaration the
        // planner can never satisfy, which is the drift this function exists to
        // prevent.
        let reachable: Vec<&str> = PLATFORMS
            .iter()
            .flat_map(|platform| {
                ARCHITECTURES
                    .iter()
                    .map(move |architecture| host_identifier_for(*platform, architecture))
            })
            .filter(|identifier| *identifier != "unknown")
            .collect();
        for host in HOSTS {
            assert!(reachable.contains(&host), "{host} is unreachable");
        }
    }

    #[test]
    fn this_build_names_the_host_it_was_compiled_for() {
        let identifier = host_identifier();
        assert!(
            HOSTS.contains(&identifier.as_str()) || identifier == "unknown",
            "this build names undeclared host {identifier}"
        );
        let architecture = if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else if cfg!(target_arch = "x86_64") {
            "x86_64"
        } else {
            "unknown"
        };
        assert_eq!(
            identifier,
            host_identifier_for(Platform::current(), architecture)
        );
        if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
            assert_eq!(identifier, "macos-x64");
        }
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            assert_eq!(identifier, "macos-arm64");
        }
    }
}
