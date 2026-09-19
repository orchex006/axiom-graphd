//! Install versioned skill bundles (task E-032).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 6 fixes how the skills
//! bundle moves between versions: it is acquired into a *versioned directory*
//! and activated by switching a reviewed manifest pointer, never by writing
//! over the bundle that is currently installed. `docs/16-CLI-AND-CONTROL-API.md`
//! section 4 gives the command surface (`axiom skills update apply --plan
//! <file>`), and task E-032 fixes the one rule this module exists for:
//!
//! > Only validated declared skill paths are installed; unexpected executable
//! > files require explicit capability review.
//!
//! That rule is enforced structurally, in three steps:
//!
//! 1. [`SkillBundle::validate`] validates the *declaration*: every entry path is
//!    a portable repository-relative path (the one portability policy of
//!    `graph_core::paths`, never a second copy), every digest and size is
//!    usable, no path is declared twice, and an entry that can run code
//!    (`kind = "script"` or an executable suffix) must carry a non-empty
//!    capability review drawn from [`CAPABILITIES`].
//! 2. [`plan_install`] validates the *payload* against the declaration before a
//!    single byte is written: a declared file that is missing, short or altered
//!    is named, a file the bundle did not declare is refused, and an undeclared
//!    *executable* is refused with the capability-review rule
//!    (`unexpected_executable_capability_review_required`) instead of being
//!    installed "like the others".
//! 3. [`install`] writes only the files of that plan into `skills/<version>/`,
//!    writes the reviewed manifest last inside the version directory, and only
//!    then moves the `skills/current` pointer. A crash before the pointer move
//!    therefore leaves the previous bundle active, and an existing version
//!    directory is refused because a built version is immutable.
//!
//! Nothing here downloads, spawns or executes anything: an entry declared as a
//! script is *installed*, never run, and the capabilities it was reviewed
//! against are recorded for the host adapter that will run it later.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::validate_portable_relative_path;
use graph_export::sha256_hex;

use crate::install::plan::is_digest;

/// Component name of the skills bundle in the ecosystem version vocabulary.
pub const COMPONENT: &str = "skills";

/// Directory under the install root that holds every staged bundle version.
pub const BUNDLES_DIR: &str = "skills";

/// Name of the reviewed bundle manifest inside one versioned bundle.
pub const MANIFEST_FILE: &str = "bundle.json";

/// Name of the pointer that names the activated bundle version.
pub const ACTIVE_POINTER: &str = "current";

/// Suffix of the temporary sibling used to replace the pointer atomically.
pub const POINTER_TEMP_SUFFIX: &str = ".next";

/// Schema version of the reviewed manifest this build installs.
pub const BUNDLE_SCHEMA_VERSION: u64 = 1;

/// Entry kinds a bundle may declare, in contract order.
pub const ENTRY_KINDS: [&str; 4] = ["instruction", "reference", "asset", "script"];

/// Capabilities an executable entry must be reviewed against.
///
/// The list is an allowlist, not a menu: a capability outside it is refused, so
/// a bundle cannot invent a capability the host adapter would then have to
/// interpret for itself.
pub const CAPABILITIES: [&str; 3] = ["read", "write", "execute"];

/// Suffixes that mean "this file can run code" when nothing declared it.
pub const EXECUTABLE_SUFFIXES: [&str; 8] = ["exe", "bat", "cmd", "ps1", "sh", "py", "js", "mjs"];

/// Longest accepted version string.
pub const MAX_VERSION_LEN: usize = 64;

/// Most entries one bundle may declare.
pub const MAX_ENTRIES: usize = 512;

/// Largest single bundle file, declared and observed.
pub const MAX_ENTRY_BYTES: u64 = 8 * 1024 * 1024;

/// Largest rendered manifest or pointer record.
pub const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

/// One file a bundle declares, with the review that authorises it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredEntry {
    /// Portable bundle-relative path, forward slashes only.
    pub path: String,
    /// Entry kind, from [`ENTRY_KINDS`].
    pub kind: String,
    /// Lowercase 64-hex digest of the expected bytes.
    pub sha256: String,
    /// Expected length in bytes.
    pub size_bytes: u64,
    /// Capabilities this entry was reviewed against. Empty for a non-executable
    /// entry, non-empty for an executable one.
    pub capabilities: Vec<String>,
}

impl DeclaredEntry {
    /// A declared file with no capability review yet.
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        kind: impl Into<String>,
        sha256: impl Into<String>,
        size_bytes: u64,
    ) -> Self {
        Self {
            path: path.into(),
            kind: kind.into(),
            sha256: sha256.into(),
            size_bytes,
            capabilities: Vec::new(),
        }
    }

    /// The same entry with an explicit capability review.
    #[must_use]
    pub fn reviewed(mut self, capabilities: &[&str]) -> Self {
        self.capabilities = capabilities
            .iter()
            .map(|value| String::from(*value))
            .collect();
        self
    }

    /// True when this entry can run code.
    ///
    /// A declared `script` is executable by definition; an executable suffix on
    /// any other kind counts too, so a bundle cannot smuggle a binary in under
    /// the `asset` label.
    #[must_use]
    pub fn is_executable(&self) -> bool {
        self.kind == "script" || is_executable_path(&self.path)
    }

    /// Refuse an entry outside the declaration contract.
    ///
    /// # Errors
    ///
    /// Fails closed with a named `rule`: `unsafe_skill_path`,
    /// `skill_path_shape_not_declared`, `unsupported_entry_kind`,
    /// `entry_digest_invalid`, `entry_too_large`, `executable_kind_required`,
    /// `capability_review_required` or `capability_not_reviewed`.
    pub fn validate(&self) -> Result<(), AxiomError> {
        if validate_portable_relative_path(&self.path).is_err() {
            return Err(refuse("unsafe_skill_path", &self.path));
        }
        if !has_declared_shape(&self.path) {
            return Err(refuse("skill_path_shape_not_declared", &self.path));
        }
        if !ENTRY_KINDS.contains(&self.kind.as_str()) {
            return Err(refuse("unsupported_entry_kind", &self.kind));
        }
        if !is_digest(&self.sha256) {
            return Err(refuse("entry_digest_invalid", &self.path));
        }
        if self.size_bytes > MAX_ENTRY_BYTES {
            return Err(refuse("entry_too_large", &self.path)
                .with_detail("limit", MAX_ENTRY_BYTES.to_string()));
        }
        if is_executable_path(&self.path) && self.kind != "script" {
            return Err(refuse("executable_kind_required", &self.path));
        }
        if self.is_executable() && self.capabilities.is_empty() {
            return Err(refuse("capability_review_required", &self.path));
        }
        for capability in &self.capabilities {
            if !CAPABILITIES.contains(&capability.as_str()) {
                return Err(refuse("capability_not_reviewed", capability)
                    .with_detail("observed", &self.path));
            }
        }
        Ok(())
    }
}

/// The declaration one skill bundle version publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillBundle {
    /// Manifest schema version.
    pub schema_version: u64,
    /// Owning component; the skills bundle is always [`COMPONENT`].
    pub component: String,
    /// Bundle version. One version directory, never mutated after it is built.
    pub version: String,
    /// Source revision the bundle was built from. Must be pinned.
    pub revision: String,
    /// Immutable `axiom-specs` revision the bundle was reviewed against.
    pub spec_revision: String,
    /// Declared files, in bundled order.
    pub entries: Vec<DeclaredEntry>,
}

impl SkillBundle {
    /// A bundle whose entries are the caller's declaration.
    #[must_use]
    pub fn new(
        version: impl Into<String>,
        revision: impl Into<String>,
        spec_revision: impl Into<String>,
        entries: Vec<DeclaredEntry>,
    ) -> Self {
        Self {
            schema_version: BUNDLE_SCHEMA_VERSION,
            component: String::from(COMPONENT),
            version: version.into(),
            revision: revision.into(),
            spec_revision: spec_revision.into(),
            entries,
        }
    }

    /// Refuse a declaration this installer will not install.
    ///
    /// # Errors
    ///
    /// Fails closed with a named `rule`: `manifest_schema_unsupported`,
    /// `unexpected_component`, `invalid_version`, `revision_not_pinned`,
    /// `spec_revision_not_pinned`, `bundle_empty`, `too_many_entries`,
    /// `duplicate_skill_path`, or the entry rules of [`DeclaredEntry::validate`].
    pub fn validate(&self) -> Result<(), AxiomError> {
        if self.schema_version != BUNDLE_SCHEMA_VERSION {
            return Err(refuse(
                "manifest_schema_unsupported",
                &self.schema_version.to_string(),
            )
            .with_detail("expected", BUNDLE_SCHEMA_VERSION.to_string()));
        }
        if self.component != COMPONENT {
            return Err(refuse("unexpected_component", &self.component));
        }
        validate_version(&self.version)?;
        require_pinned_revision(&self.revision, "revision_not_pinned")?;
        require_pinned_revision(&self.spec_revision, "spec_revision_not_pinned")?;
        if self.entries.is_empty() {
            return Err(refuse("bundle_empty", &self.version));
        }
        if self.entries.len() > MAX_ENTRIES {
            return Err(refuse("too_many_entries", &self.version)
                .with_detail("limit", MAX_ENTRIES.to_string()));
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            entry.validate()?;
            if seen.contains(&entry.path.as_str()) {
                return Err(refuse("duplicate_skill_path", &entry.path));
            }
            seen.push(&entry.path);
        }
        Ok(())
    }

    /// Every declared path, in declaration order.
    #[must_use]
    pub fn declared_paths(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect()
    }

    /// Every declared path that can run code, in declaration order.
    #[must_use]
    pub fn executable_paths(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| entry.is_executable())
            .map(|entry| entry.path.clone())
            .collect()
    }

    /// True when this declaration installs at least one executable entry.
    #[must_use]
    pub fn installs_executable(&self) -> bool {
        self.entries.iter().any(DeclaredEntry::is_executable)
    }

    /// Canonical manifest bytes: compact JSON plus one trailing newline.
    ///
    /// # Errors
    ///
    /// Fails closed when the declaration is not installable or cannot be
    /// encoded, so an unusable manifest is never written.
    pub fn manifest_bytes(&self) -> Result<Vec<u8>, AxiomError> {
        self.validate()?;
        let value = serde_json::to_value(self)
            .map_err(|_| refuse("manifest_not_serialisable", &self.version))?;
        let text = graph_export::canonical::canonical_value(&value).map_err(|error| {
            refuse("manifest_not_serialisable", &self.version)
                .with_detail("observed", error.to_string())
        })?;
        let mut bytes = text.into_bytes();
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(refuse("manifest_too_large", &self.version)
                .with_detail("limit", MAX_MANIFEST_BYTES.to_string()));
        }
        Ok(bytes)
    }
}

/// One file the caller staged as a candidate payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedFile {
    /// Portable bundle-relative path.
    pub path: String,
    /// Observed length in bytes.
    pub size_bytes: u64,
    /// Lowercase 64-hex digest of the observed bytes.
    pub sha256: String,
    /// Whether the staged file can run code.
    pub executable: bool,
}

/// The payload a caller wants installed.
///
/// The trait is read-only on purpose: it can list and read, and it has no way
/// to write, rename or remove anything, so [`plan_install`] cannot mutate the
/// payload it is judging.
pub trait PayloadSource {
    /// Every staged file, in a deterministic order.
    ///
    /// # Errors
    ///
    /// Fails when the payload cannot be listed or unambiguously described.
    fn files(&self) -> Result<Vec<StagedFile>, AxiomError>;

    /// The bytes of one staged file.
    ///
    /// # Errors
    ///
    /// Fails when the file is missing or unreadable.
    fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError>;
}

/// Read a staged bundle from a local directory.
pub struct LocalPayloadSource {
    root: PathBuf,
}

impl LocalPayloadSource {
    /// A payload rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The portable relative path of a staged file.
    fn relative(&self, path: &std::path::Path) -> Result<String, AxiomError> {
        let stripped = path
            .strip_prefix(&self.root)
            .map_err(|_| refuse("payload_unreadable", &path.display().to_string()))?;
        let mut relative = String::new();
        for component in stripped.components() {
            let segment = component
                .as_os_str()
                .to_str()
                .ok_or_else(|| refuse("payload_unreadable", &path.display().to_string()))?;
            if !relative.is_empty() {
                relative.push('/');
            }
            relative.push_str(segment);
        }
        Ok(relative)
    }
}

impl PayloadSource for LocalPayloadSource {
    fn files(&self) -> Result<Vec<StagedFile>, AxiomError> {
        if !self.root.is_dir() {
            return Err(refuse(
                "payload_unreadable",
                &self.root.display().to_string(),
            ));
        }
        let mut staged = Vec::new();
        let mut pending = vec![self.root.clone()];
        while let Some(directory) = pending.pop() {
            let listing = std::fs::read_dir(&directory).map_err(|error| {
                refuse("payload_unreadable", &directory.display().to_string())
                    .with_detail("observed", error.to_string())
            })?;
            for entry in listing {
                let entry = entry.map_err(|error| {
                    refuse("payload_unreadable", &directory.display().to_string())
                        .with_detail("observed", error.to_string())
                })?;
                let path = entry.path();
                let relative = self.relative(&path)?;
                let file_type = entry.file_type().map_err(|error| {
                    refuse("payload_unreadable", &relative)
                        .with_detail("observed", error.to_string())
                })?;
                if file_type.is_symlink() {
                    return Err(refuse("payload_symlink_not_allowed", &relative));
                }
                if file_type.is_dir() {
                    pending.push(path);
                    continue;
                }
                let bytes = std::fs::read(&path).map_err(|error| {
                    refuse("payload_unreadable", &relative)
                        .with_detail("observed", error.to_string())
                })?;
                staged.push(StagedFile {
                    size_bytes: bytes.len() as u64,
                    sha256: sha256_hex(&bytes),
                    executable: is_executable_path(&relative),
                    path: relative,
                });
            }
        }
        staged.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(staged)
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
        let mut native = self.root.clone();
        for segment in path.split('/') {
            native.push(segment);
        }
        std::fs::read(&native).map_err(|error| {
            refuse("payload_unreadable", path).with_detail("observed", error.to_string())
        })
    }
}

/// One file an install plan will write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallStep {
    /// Portable bundle-relative path.
    pub path: String,
    /// Verified digest of the bytes to write.
    pub sha256: String,
    /// Verified length of the bytes to write.
    pub size_bytes: u64,
}

/// A validated, not-yet-written install: the declaration plus one step per file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    /// The declaration every step was checked against.
    pub bundle: SkillBundle,
    /// One step per declared file, in declaration order.
    pub steps: Vec<InstallStep>,
    /// Version directory the steps are written into, under the install root.
    pub directory: String,
}

impl InstallPlan {
    /// Every path this plan will write, in write order.
    #[must_use]
    pub fn paths(&self) -> Vec<String> {
        self.steps.iter().map(|step| step.path.clone()).collect()
    }

    /// True when the plan installs at least one file that can run code.
    #[must_use]
    pub fn installs_executable(&self) -> bool {
        self.bundle.installs_executable()
    }
}

/// Validate a payload against its declaration without writing anything.
///
/// # Errors
///
/// Fails closed with a named `rule`: the declaration rules of
/// [`SkillBundle::validate`], `payload_unreadable` for a listing failure,
/// `declared_file_missing` for a declared file the payload does not contain,
/// `declared_file_size_mismatch` / `declared_file_hash_mismatch` for bytes that
/// are not the declared bytes, `executable_not_declared` for an entry declared
/// as a non-executable that arrived executable, `undeclared_file` for a file the
/// bundle did not declare, and
/// `unexpected_executable_capability_review_required` for an undeclared
/// executable file.
pub fn plan_install(
    bundle: &SkillBundle,
    source: &dyn PayloadSource,
) -> Result<InstallPlan, AxiomError> {
    bundle.validate()?;
    let staged = source.files()?;
    let mut steps = Vec::with_capacity(bundle.entries.len());
    for entry in &bundle.entries {
        let Some(file) = staged.iter().find(|file| file.path == entry.path) else {
            return Err(
                refuse("declared_file_missing", &entry.path).with_detail("expected", &entry.sha256)
            );
        };
        if file.size_bytes != entry.size_bytes {
            return Err(refuse("declared_file_size_mismatch", &entry.path)
                .with_detail("expected", entry.size_bytes.to_string())
                .with_detail("actual", file.size_bytes.to_string()));
        }
        if file.sha256 != entry.sha256 {
            return Err(refuse("declared_file_hash_mismatch", &entry.path)
                .with_detail("expected", &entry.sha256)
                .with_detail("actual", &file.sha256));
        }
        if file.executable && !entry.is_executable() {
            return Err(refuse("executable_not_declared", &entry.path));
        }
        steps.push(InstallStep {
            path: entry.path.clone(),
            sha256: entry.sha256.clone(),
            size_bytes: entry.size_bytes,
        });
    }
    for file in &staged {
        if bundle.entries.iter().any(|entry| entry.path == file.path) {
            continue;
        }
        if file.executable {
            return Err(refuse(
                "unexpected_executable_capability_review_required",
                &file.path,
            )
            .with_detail(
                "expected",
                "a declared script entry with a reviewed capability set",
            ));
        }
        return Err(refuse("undeclared_file", &file.path));
    }
    Ok(InstallPlan {
        directory: format!("{BUNDLES_DIR}/{}", bundle.version),
        steps,
        bundle: bundle.clone(),
    })
}

/// The mutation surface of one install root.
pub trait InstallFs {
    /// True when the path exists, whatever its type.
    fn exists(&self, path: &str) -> bool;
    /// Read a file.
    ///
    /// # Errors
    ///
    /// Fails when the path is missing or unreadable.
    fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError>;
    /// Write a file, creating its parent directories when needed.
    ///
    /// # Errors
    ///
    /// Fails when the path cannot be written.
    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError>;
    /// Rename `from` over `to`, replacing `to`.
    ///
    /// # Errors
    ///
    /// Fails when either path is unusable or `from` is missing.
    fn rename(&self, from: &str, to: &str) -> Result<(), AxiomError>;
}

/// The one implementation that touches a real filesystem.
///
/// It is rooted: every path it is handed is a portable install-root-relative
/// path, validated again here so a caller-supplied path can never escape the
/// root the host was built with.
pub struct LocalInstallFs {
    root: PathBuf,
}

impl LocalInstallFs {
    /// A host rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The native path of one install-root-relative path.
    fn native(&self, path: &str) -> Result<PathBuf, AxiomError> {
        if validate_portable_relative_path(path).is_err() {
            return Err(refuse("unsafe_install_path", path));
        }
        let mut native = self.root.clone();
        for segment in path.split('/') {
            native.push(segment);
        }
        Ok(native)
    }
}

impl InstallFs for LocalInstallFs {
    fn exists(&self, path: &str) -> bool {
        self.native(path).is_ok_and(|native| native.exists())
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
        std::fs::read(self.native(path)?).map_err(|error| {
            refuse("bundle_unreadable", path).with_detail("observed", error.to_string())
        })
    }

    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError> {
        let target = self.native(path)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                refuse("install_write_failed", path).with_detail("observed", error.to_string())
            })?;
        }
        std::fs::write(&target, bytes).map_err(|error| {
            refuse("install_write_failed", path).with_detail("observed", error.to_string())
        })
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), AxiomError> {
        let source = self.native(from)?;
        let target = self.native(to)?;
        // A pointer is replaced, not merged: removing the previous pointer file
        // first is what makes the move work on every supported platform.
        if target.exists() {
            std::fs::remove_file(&target).map_err(|error| {
                refuse("pointer_write_failed", to).with_detail("observed", error.to_string())
            })?;
        }
        std::fs::rename(&source, &target).map_err(|error| {
            refuse("pointer_write_failed", to).with_detail("observed", error.to_string())
        })
    }
}

/// What one install did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallReport {
    /// Version that was installed.
    pub version: String,
    /// Version directory, relative to the install root.
    pub directory: String,
    /// Paths written, in write order, excluding the manifest and the pointer.
    pub installed: Vec<String>,
    /// Digest of the reviewed manifest that was written.
    pub manifest_sha256: String,
    /// Pointer path that was moved last.
    pub pointer: String,
    /// Whether the installed bundle holds an executable entry.
    pub installs_executable: bool,
}

/// Write a validated plan into a versioned directory and activate it.
///
/// Order is the safety property: every declared file, then the reviewed
/// manifest, then the pointer. A failure before the pointer leaves the previous
/// bundle active.
///
/// The staged bytes come from `source`, never from the install root: `fs` is
/// the one mutation surface and it is only ever handed a path under
/// `plan.directory` or the activation pointer.
///
/// # Errors
///
/// Fails closed with a named `rule`: the [`SkillBundle::validate`] rules,
/// `version_directory_exists` when the version was already built,
/// `staged_file_changed_since_plan` when a staged byte moved between planning
/// and writing, and the read refusals of [`PayloadSource`] plus the filesystem
/// failures of [`InstallFs`].
pub fn install(
    plan: &InstallPlan,
    source: &dyn PayloadSource,
    fs: &dyn InstallFs,
) -> Result<InstallReport, AxiomError> {
    plan.bundle.validate()?;
    if fs.exists(&plan.directory) {
        return Err(refuse("version_directory_exists", &plan.directory));
    }
    let mut installed = Vec::with_capacity(plan.steps.len());
    for step in &plan.steps {
        let bytes = source.read(&step.path)?;
        if bytes.len() as u64 != step.size_bytes || sha256_hex(&bytes) != step.sha256 {
            return Err(refuse("staged_file_changed_since_plan", &step.path));
        }
        fs.write(&format!("{}/{}", plan.directory, step.path), &bytes)?;
        installed.push(step.path.clone());
    }
    let manifest = plan.bundle.manifest_bytes()?;
    fs.write(&format!("{}/{}", plan.directory, MANIFEST_FILE), &manifest)?;

    let pointer_path = format!("{BUNDLES_DIR}/{ACTIVE_POINTER}");
    let temp = format!("{pointer_path}{POINTER_TEMP_SUFFIX}");
    fs.write(&temp, pointer_record(plan, &manifest).as_bytes())?;
    fs.rename(&temp, &pointer_path)?;

    Ok(InstallReport {
        version: plan.bundle.version.clone(),
        directory: plan.directory.clone(),
        installed,
        manifest_sha256: sha256_hex(&manifest),
        pointer: pointer_path,
        installs_executable: plan.installs_executable(),
    })
}

/// The activation pointer record for one installed bundle.
fn pointer_record(plan: &InstallPlan, manifest: &[u8]) -> String {
    format!(
        "{{\"schema_version\":{BUNDLE_SCHEMA_VERSION},\"component\":\"{COMPONENT}\",\"version\":\"{}\",\"revision\":\"{}\",\"spec_revision\":\"{}\",\"directory\":\"{}\",\"entries\":{},\"installs_executable\":{},\"manifest_sha256\":\"{}\"}}\n",
        plan.bundle.version,
        plan.bundle.revision,
        plan.bundle.spec_revision,
        plan.directory,
        plan.steps.len(),
        plan.installs_executable(),
        sha256_hex(manifest)
    )
}

/// True when a path names something that can run code.
#[must_use]
pub fn is_executable_path(path: &str) -> bool {
    match path.rsplit_once('.') {
        Some((_, suffix)) => EXECUTABLE_SUFFIXES
            .iter()
            .any(|known| suffix.eq_ignore_ascii_case(known)),
        None => false,
    }
}

/// Accept only a version that is one safe path segment.
fn validate_version(version: &str) -> Result<(), AxiomError> {
    if version.is_empty() || version.len() > MAX_VERSION_LEN {
        return Err(
            refuse("invalid_version", version).with_detail("limit", MAX_VERSION_LEN.to_string())
        );
    }
    if validate_portable_relative_path(version).is_err() {
        return Err(refuse("invalid_version", version));
    }
    Ok(())
}

/// Require a pinned 40-hex revision.
fn require_pinned_revision(revision: &str, rule: &str) -> Result<(), AxiomError> {
    let pinned = revision.len() == 40
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !pinned {
        return Err(refuse(rule, revision));
    }
    Ok(())
}

/// True when a declared path has the shape of a file inside a named skill.
fn has_declared_shape(path: &str) -> bool {
    let mut segments = path.split('/');
    let Some(root) = segments.next() else {
        return false;
    };
    let rest: Vec<&str> = segments.collect();
    if root.is_empty() || rest.is_empty() {
        return false;
    }
    let Some(name) = rest.last() else {
        return false;
    };
    match name.rsplit_once('.') {
        Some((stem, extension)) => !stem.is_empty() && !extension.is_empty(),
        None => false,
    }
}

/// The one refusal shape of this module.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the skill bundle violates the versioned skill-bundle contract",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use super::*;

    const REVISION: &str = "1111111111111111111111111111111111111111";
    const SPEC_REVISION: &str = "2222222222222222222222222222222222222222";
    const SKILL_MD: &[u8] = b"# axiom-analyze\n\nread the graph, never guess.\n";
    const SCRIPT: &[u8] = b"#!/bin/sh\necho bounded\n";

    fn digest(bytes: &[u8]) -> String {
        sha256_hex(bytes)
    }

    fn instruction() -> DeclaredEntry {
        DeclaredEntry::new(
            "axiom-analyze/SKILL.md",
            "instruction",
            digest(SKILL_MD),
            SKILL_MD.len() as u64,
        )
    }

    fn script() -> DeclaredEntry {
        DeclaredEntry::new(
            "axiom-analyze/scripts/check.sh",
            "script",
            digest(SCRIPT),
            SCRIPT.len() as u64,
        )
        .reviewed(&["read", "execute"])
    }

    fn bundle(entries: Vec<DeclaredEntry>) -> SkillBundle {
        SkillBundle::new("0.1.0", REVISION, SPEC_REVISION, entries)
    }

    #[derive(Default)]
    struct MemoryPayload {
        files: Vec<StagedFile>,
        reads: RefCell<u32>,
    }

    impl MemoryPayload {
        fn with(files: &[(&str, &[u8])]) -> Self {
            Self {
                files: files
                    .iter()
                    .map(|(path, bytes)| StagedFile {
                        path: String::from(*path),
                        size_bytes: bytes.len() as u64,
                        sha256: digest(bytes),
                        executable: is_executable_path(path),
                    })
                    .collect(),
                reads: RefCell::new(0),
            }
        }
    }

    impl PayloadSource for MemoryPayload {
        fn files(&self) -> Result<Vec<StagedFile>, AxiomError> {
            Ok(self.files.clone())
        }

        fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
            *self.reads.borrow_mut() += 1;
            match path {
                "axiom-analyze/SKILL.md" => Ok(SKILL_MD.to_vec()),
                "axiom-analyze/scripts/check.sh" => Ok(SCRIPT.to_vec()),
                other => Err(refuse("payload_unreadable", other)),
            }
        }
    }

    /// A payload whose bytes can move between planning and installing.
    struct RewrittenPayload {
        files: Vec<StagedFile>,
        bytes: RefCell<Vec<u8>>,
        reads: RefCell<u32>,
    }

    impl RewrittenPayload {
        fn with(path: &str, bytes: &[u8]) -> Self {
            Self {
                files: vec![StagedFile {
                    path: String::from(path),
                    size_bytes: bytes.len() as u64,
                    sha256: digest(bytes),
                    executable: is_executable_path(path),
                }],
                bytes: RefCell::new(bytes.to_vec()),
                reads: RefCell::new(0),
            }
        }

        fn rewrite(&self, bytes: &[u8]) {
            *self.bytes.borrow_mut() = bytes.to_vec();
        }
    }

    impl PayloadSource for RewrittenPayload {
        fn files(&self) -> Result<Vec<StagedFile>, AxiomError> {
            Ok(self.files.clone())
        }

        fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
            *self.reads.borrow_mut() += 1;
            if self.files.iter().any(|file| file.path == path) {
                return Ok(self.bytes.borrow().clone());
            }
            Err(refuse("payload_unreadable", path))
        }
    }
    #[derive(Default)]
    struct MemoryFs {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        writes: RefCell<Vec<String>>,
    }

    impl MemoryFs {
        fn get(&self, path: &str) -> Option<Vec<u8>> {
            self.files.borrow().get(path).cloned()
        }

        fn written(&self) -> Vec<String> {
            self.writes.borrow().clone()
        }
    }

    impl InstallFs for MemoryFs {
        fn exists(&self, path: &str) -> bool {
            let files = self.files.borrow();
            files.contains_key(path)
                || files
                    .keys()
                    .any(|known| known.starts_with(&format!("{path}/")))
        }

        fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
            self.get(path)
                .ok_or_else(|| refuse("payload_unreadable", path))
        }

        fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError> {
            self.writes.borrow_mut().push(String::from(path));
            self.files
                .borrow_mut()
                .insert(String::from(path), bytes.to_vec());
            Ok(())
        }

        fn rename(&self, from: &str, to: &str) -> Result<(), AxiomError> {
            let bytes = self
                .get(from)
                .ok_or_else(|| refuse("pointer_write_failed", from))?;
            let mut files = self.files.borrow_mut();
            files.remove(from);
            files.insert(String::from(to), bytes);
            Ok(())
        }
    }

    fn rule_of(error: &AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    #[test]
    fn a_declared_bundle_plans_and_installs_in_declaration_order() {
        let payload = MemoryPayload::with(&[
            ("axiom-analyze/SKILL.md", SKILL_MD),
            ("axiom-analyze/scripts/check.sh", SCRIPT),
        ]);
        let declared = bundle(vec![instruction(), script()]);
        let plan = plan_install(&declared, &payload).expect("a declared payload plans");
        assert_eq!(
            plan.paths(),
            vec![
                "axiom-analyze/SKILL.md".to_string(),
                "axiom-analyze/scripts/check.sh".to_string()
            ]
        );
        assert!(plan.installs_executable());
        assert_eq!(plan.directory, "skills/0.1.0");
        assert_eq!(*payload.reads.borrow(), 0, "planning reads no bytes");

        let fs = MemoryFs::default();
        let report = install(&plan, &payload, &fs).expect("install");
        assert_eq!(report.version, "0.1.0");
        assert!(report.installs_executable);
        assert_eq!(report.pointer, "skills/current");
        assert_eq!(
            report.manifest_sha256,
            digest(&declared.manifest_bytes().expect("manifest"))
        );
        assert_eq!(
            fs.written(),
            vec![
                "skills/0.1.0/axiom-analyze/SKILL.md".to_string(),
                "skills/0.1.0/axiom-analyze/scripts/check.sh".to_string(),
                "skills/0.1.0/bundle.json".to_string(),
                "skills/current.next".to_string(),
            ],
            "files, then the manifest, then the pointer"
        );
        assert!(
            fs.get("skills/current.next").is_none(),
            "the temporary sibling is consumed by the move, never left behind"
        );
        assert!(
            fs.get("skills/current").is_some(),
            "the pointer names the version that was just installed"
        );
        let pointer = String::from_utf8(fs.get("skills/current").expect("pointer")).expect("utf8");
        assert!(
            pointer.contains("\"installs_executable\":true"),
            "{pointer}"
        );
        assert!(
            pointer.contains(&format!("\"revision\":\"{REVISION}\"")),
            "{pointer}"
        );
    }

    #[test]
    fn an_undeclared_executable_requires_a_capability_review() {
        // The acceptance rule of E-032: an undeclared file is refused, and when
        // it can run code the refusal names the missing capability review.
        let payload = MemoryPayload::with(&[
            ("axiom-analyze/SKILL.md", SKILL_MD),
            (
                "axiom-analyze/scripts/telemetry.sh",
                b"#!/bin/sh\ncurl example.invalid\n",
            ),
        ]);
        let error = plan_install(&bundle(vec![instruction()]), &payload)
            .expect_err("an undeclared executable must not be planned");
        assert_eq!(
            rule_of(&error),
            Some("unexpected_executable_capability_review_required")
        );
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("axiom-analyze/scripts/telemetry.sh")
        );
    }

    #[test]
    fn an_undeclared_instruction_is_refused_with_its_own_rule() {
        let payload = MemoryPayload::with(&[
            ("axiom-analyze/SKILL.md", SKILL_MD),
            ("axiom-analyze/EXTRA.md", b"# extra\n"),
        ]);
        let error = plan_install(&bundle(vec![instruction()]), &payload)
            .expect_err("an undeclared file must not be installed");
        assert_eq!(rule_of(&error), Some("undeclared_file"));
    }

    #[test]
    fn a_declared_script_without_a_capability_review_is_refused() {
        let unreviewed = DeclaredEntry::new(
            "axiom-analyze/scripts/check.sh",
            "script",
            digest(SCRIPT),
            SCRIPT.len() as u64,
        );
        let error = bundle(vec![unreviewed])
            .validate()
            .expect_err("an executable without a review must fail");
        assert_eq!(rule_of(&error), Some("capability_review_required"));
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("axiom-analyze/scripts/check.sh")
        );
    }

    #[test]
    fn a_capability_outside_the_allowlist_is_refused() {
        let invented = DeclaredEntry::new(
            "axiom-analyze/scripts/check.sh",
            "script",
            digest(SCRIPT),
            SCRIPT.len() as u64,
        )
        .reviewed(&["network"]);
        let error = bundle(vec![invented])
            .validate()
            .expect_err("an invented capability must fail");
        assert_eq!(rule_of(&error), Some("capability_not_reviewed"));
    }

    #[test]
    fn an_executable_suffix_may_not_be_declared_as_a_non_script() {
        let disguised = DeclaredEntry::new(
            "axiom-analyze/tools/check.exe",
            "asset",
            digest(SCRIPT),
            SCRIPT.len() as u64,
        );
        let error = bundle(vec![disguised])
            .validate()
            .expect_err("an executable asset must fail");
        assert_eq!(rule_of(&error), Some("executable_kind_required"));
    }

    #[test]
    fn declared_bytes_that_changed_are_named_before_anything_is_written() {
        let shorter = MemoryPayload::with(&[("axiom-analyze/SKILL.md", b"# edited\n")]);
        let error = plan_install(&bundle(vec![instruction()]), &shorter)
            .expect_err("a changed file must not be planned");
        assert_eq!(rule_of(&error), Some("declared_file_size_mismatch"));

        // Same length, one different byte: only the digest can catch this.
        let same_length = MemoryPayload::with(&[(
            "axiom-analyze/SKILL.md",
            b"# axiom-analyze\n\nread the graph, never GUESS.\n",
        )]);
        let error = plan_install(&bundle(vec![instruction()]), &same_length)
            .expect_err("a rewritten file of the same length must not be planned");
        assert_eq!(rule_of(&error), Some("declared_file_hash_mismatch"));
    }

    #[test]
    fn staged_bytes_that_moved_after_planning_are_refused_before_any_write() {
        // The plan's digest is the promise the installer keeps: a staged byte
        // that moves between planning and writing is refused, and the same
        // length is not enough to pass.
        let payload = RewrittenPayload::with("axiom-analyze/SKILL.md", SKILL_MD);
        let plan = plan_install(&bundle(vec![instruction()]), &payload).expect("plan");
        payload.rewrite(b"# axiom-analyze\n\nread the graph, never GUESS.\n");
        let fs = MemoryFs::default();
        let error = install(&plan, &payload, &fs)
            .expect_err("a staged byte that moved must not be installed");
        assert_eq!(rule_of(&error), Some("staged_file_changed_since_plan"));
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("axiom-analyze/SKILL.md")
        );
        assert!(
            fs.written().is_empty(),
            "nothing is written for a payload that no longer matches its plan"
        );
        assert_eq!(*payload.reads.borrow(), 1, "the staged bytes are read once");
    }
    #[test]
    fn a_declared_file_the_payload_does_not_contain_is_refused() {
        let payload = MemoryPayload::with(&[("axiom-analyze/README.md", b"# readme\n")]);
        let error = plan_install(&bundle(vec![instruction()]), &payload)
            .expect_err("a missing declared file must fail");
        assert_eq!(rule_of(&error), Some("declared_file_missing"));
    }

    #[test]
    fn a_version_directory_is_never_rebuilt() {
        let payload = MemoryPayload::with(&[("axiom-analyze/SKILL.md", SKILL_MD)]);
        let plan = plan_install(&bundle(vec![instruction()]), &payload).expect("plan");
        let fs = MemoryFs::default();
        install(&plan, &payload, &fs).expect("first install");
        let error = install(&plan, &payload, &fs).expect_err("a built version is immutable");
        assert_eq!(rule_of(&error), Some("version_directory_exists"));
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("skills/0.1.0")
        );
    }

    #[test]
    fn a_non_portable_or_misshaped_declared_path_is_refused() {
        for path in [
            "../axiom-analyze/SKILL.md",
            "C:\\skills/SKILL.md",
            "/axiom-analyze/SKILL.md",
            "axiom-analyze/../SKILL.md",
        ] {
            let entry = DeclaredEntry::new(path, "instruction", digest(SKILL_MD), 1);
            let error = bundle(vec![entry])
                .validate()
                .expect_err("an unsafe path must fail");
            assert_eq!(rule_of(&error), Some("unsafe_skill_path"), "{path}");
        }
        // A portable path that is not `skill/<file>` is misshapen; a path the
        // one portability policy already refuses is reported as unsafe instead,
        // so a trailing separator never masquerades as a shape problem.
        for (path, expected) in [
            ("axiom-analyze", "skill_path_shape_not_declared"),
            ("SKILL.md", "skill_path_shape_not_declared"),
            ("axiom-analyze/dir", "skill_path_shape_not_declared"),
            ("axiom-analyze/dir/", "unsafe_skill_path"),
        ] {
            let entry = DeclaredEntry::new(path, "instruction", digest(SKILL_MD), 1);
            let error = bundle(vec![entry])
                .validate()
                .expect_err("a path without a declared shape must fail");
            assert_eq!(rule_of(&error), Some(expected), "{path}");
        }
    }

    #[test]
    fn an_unpinned_revision_duplicate_path_or_unknown_kind_is_refused() {
        let mut unpinned = bundle(vec![instruction()]);
        unpinned.revision = String::from("main");
        assert_eq!(
            rule_of(&unpinned.validate().expect_err("unpinned")).expect("rule"),
            "revision_not_pinned"
        );

        let mut unpinned_spec = bundle(vec![instruction()]);
        unpinned_spec.spec_revision = String::from("latest");
        assert_eq!(
            rule_of(&unpinned_spec.validate().expect_err("unpinned spec")).expect("rule"),
            "spec_revision_not_pinned"
        );

        assert_eq!(
            rule_of(
                &bundle(vec![instruction(), instruction()])
                    .validate()
                    .expect_err("dup")
            )
            .expect("rule"),
            "duplicate_skill_path"
        );

        let unknown = DeclaredEntry::new("axiom-analyze/notes.md", "hook", digest(SKILL_MD), 3);
        assert_eq!(
            rule_of(&bundle(vec![unknown]).validate().expect_err("kind")).expect("rule"),
            "unsupported_entry_kind"
        );

        assert_eq!(
            rule_of(&bundle(Vec::new()).validate().expect_err("empty")).expect("rule"),
            "bundle_empty"
        );

        let mut other_component = bundle(vec![instruction()]);
        other_component.component = String::from("axiom-mcp");
        assert_eq!(
            rule_of(&other_component.validate().expect_err("component")).expect("rule"),
            "unexpected_component"
        );
    }

    #[test]
    fn a_real_payload_directory_installs_through_the_production_host() {
        let staging = tempfile::tempdir().expect("staging");
        let root = tempfile::tempdir().expect("install root");
        let scripts = staging.path().join("axiom-analyze").join("scripts");
        std::fs::create_dir_all(&scripts).expect("staging tree");
        std::fs::write(
            staging.path().join("axiom-analyze").join("SKILL.md"),
            SKILL_MD,
        )
        .expect("write skill");
        std::fs::write(scripts.join("check.sh"), SCRIPT).expect("write script");

        let source = LocalPayloadSource::new(staging.path());
        let plan = plan_install(&bundle(vec![instruction(), script()]), &source).expect("plan");
        let host = LocalInstallFs::new(root.path());
        let report = install(&plan, &source, &host)
            .expect("the production host installs a declared payload");
        assert_eq!(report.installed.len(), 2);

        let bundles = root.path().join(BUNDLES_DIR);
        let pointer = std::fs::read_to_string(bundles.join(ACTIVE_POINTER)).expect("pointer");
        assert!(pointer.contains("\"version\":\"0.1.0\""), "{pointer}");
        assert!(
            pointer.contains(&format!("\"spec_revision\":\"{SPEC_REVISION}\"")),
            "{pointer}"
        );
        let manifest =
            std::fs::read_to_string(bundles.join("0.1.0").join(MANIFEST_FILE)).expect("manifest");
        assert!(
            manifest.starts_with("{\"component\":\"skills\""),
            "{manifest}"
        );
        assert!(manifest.ends_with("}\n"), "one trailing newline");
        assert!(bundles
            .join("0.1.0")
            .join("axiom-analyze")
            .join("scripts")
            .join("check.sh")
            .is_file());

        let second = install(&plan, &source, &host).expect_err("the version is now built");
        assert_eq!(rule_of(&second), Some("version_directory_exists"));
        let escape = LocalInstallFs::new(root.path())
            .write("../outside.txt", b"nope")
            .expect_err("an escaping path must be refused");
        assert_eq!(rule_of(&escape), Some("unsafe_install_path"));
    }
}
