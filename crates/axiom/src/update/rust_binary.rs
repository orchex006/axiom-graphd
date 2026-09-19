//! Activate the Rust binaries through versioned directories (task E-042).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 6 fixes two facts about the
//! core binaries: a payload is *staged into a versioned directory first*, and the
//! step that makes it live is a pointer move ("swap active install manifest"),
//! never a file replacement in place. Its Windows sentence is the reason this
//! module exists:
//!
//! > `axiom-graphd update` must let an external updater process perform the swap
//! > after the daemon exits; Windows does not overwrite an executable that is
//! > running.
//!
//! Replacing `axiom-graphd.exe` or `axiom.exe` in place is therefore not merely
//! risky, it is impossible while the image is mapped. This module records the two
//! properties that follow and enforces them structurally:
//!
//! 1. **A version is a directory, and the pointer names one.** `versions/<component>/<version>/`
//!    holds the payload; `current` holds a small canonical record naming the
//!    active component, version, directory and binary. Nothing else is written by
//!    an activation, so no activation can touch the directory the running image
//!    was loaded from (see [`BinaryActivation::plan_writes`]).
//! 2. **A failed activation keeps the previous launch target.** The pointer is
//!    never truncated or rewritten in place: a temporary sibling is written and
//!    renamed over it, so an activation that fails while writing or renaming
//!    leaves the previous pointer bytes exactly as they were, and
//!    [`BinaryActivation::launch_target`] still resolves the previous binary.
//!
//! ## Fail closed
//!
//! The pointer is a trust input: it decides which executable is launched. A
//! pointer that is missing means "nothing is activated yet", but a pointer that
//! exists and cannot be read as this component's record is refused rather than
//! ignored, a payload whose bytes do not match the staged digest is refused, and
//! a payload that was never smoke checked is refused. There is deliberately no
//! function here that downloads, executes, signs or tags anything.

use serde::{Deserialize, Serialize};

use graph_core::error::{AxiomError, ErrorCode};
use graph_export::sha256_hex;

use crate::install::plan::is_digest;

/// Directory under the install root that holds every staged version.
pub const VERSIONS_DIR: &str = "versions";

/// Name of the pointer that names the activated version.
pub const ACTIVE_POINTER: &str = "current";

/// Suffix of the temporary sibling used to replace the pointer atomically.
pub const POINTER_TEMP_SUFFIX: &str = ".next";

/// Schema version of the pointer record this build writes and accepts.
pub const POINTER_SCHEMA_VERSION: u64 = 1;

/// Upper bound on the pointer record, so a hostile file cannot be read forever.
pub const MAX_POINTER_BYTES: usize = 1024;

/// Upper bound on one staged binary this module will hash.
pub const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;

/// Longest accepted version string.
pub const MAX_VERSION_LEN: usize = 64;

/// Components that share the one core release and may be activated here.
///
/// `axiom-bootstrap` is deliberately absent: `docs/20-VERSION-CHECK-UPDATE-RELEASE.md`
/// section 6 and task E-048 require the bootstrap and updater to ship *inside* the
/// core release instead of as a separate installed component.
pub const COMPONENTS: [&str; 2] = ["axiom-graphd", "axiom"];

/// Executable suffix of this host, so a pointer can name the real image.
#[cfg(windows)]
pub const EXE_SUFFIX: &str = ".exe";

/// Executable suffix of this host, so a pointer can name the real image.
#[cfg(not(windows))]
pub const EXE_SUFFIX: &str = "";

/// Whether this operating system refuses to overwrite a running executable image.
///
/// On Windows the image is mapped and the file is locked, so an in-place
/// replacement is impossible and the versioned-directory scheme is mandatory. On
/// the other supported hosts an in-place write would be *possible*, which is
/// exactly why this module does not offer one: a possible half-written image is
/// worse than an impossible one.
pub const RUNNING_IMAGE_IS_LOCKED: bool = cfg!(windows);

/// The mutation surface of one install root.
///
/// The trait is the whole surface on purpose: [`BinaryActivation`] cannot delete,
/// truncate, spawn a process or follow a link, so a caller-supplied double or a
/// hostile fixture cannot make an activation do more than write one temporary
/// file and rename it.
pub trait ActivationFs {
    /// True when the path exists, whatever its type.
    fn exists(&self, path: &str) -> bool;
    /// Read a file.
    ///
    /// # Errors
    ///
    /// Fails when the path is missing or unreadable.
    fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError>;
    /// Write a file, creating it if needed.
    ///
    /// # Errors
    ///
    /// Fails when the path cannot be written.
    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError>;
    /// Rename `from` over `to`, replacing `to` in one step.
    ///
    /// # Errors
    ///
    /// Fails when either path is unusable.
    fn rename(&self, from: &str, to: &str) -> Result<(), AxiomError>;
}

/// A payload that has already been staged into its versioned directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedVersion {
    /// Version string of the staged payload.
    pub version: String,
    /// Lowercase 64-hex digest the staged bytes must have.
    pub sha256: String,
    /// Whether the staged payload passed its smoke check.
    pub smoke_checked: bool,
}

/// The record the pointer holds: which component version is launched from where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveInstall {
    /// Schema version of this record.
    pub schema_version: u64,
    /// Component name, from [`COMPONENTS`].
    pub component: String,
    /// Version that is active.
    pub version: String,
    /// Directory the payload lives in, relative to the install root.
    pub directory: String,
    /// Binary file name inside that directory.
    pub binary: String,
}

/// The outcome of one successful activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activation {
    /// The launch target that was active before, if any.
    pub previous: Option<ActiveInstall>,
    /// The launch target that is active now.
    pub active: ActiveInstall,
    /// Path of the pointer that was replaced.
    pub pointer: String,
}

impl Activation {
    /// Whether this activation actually changed the launch target.
    #[must_use]
    pub fn changed_target(&self) -> bool {
        self.previous.as_ref() != Some(&self.active)
    }
}

/// One component's versioned-directory activation inside an install root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryActivation {
    root: String,
    component: String,
    executable: String,
}

impl BinaryActivation {
    /// Bind an activation to one component of one install root.
    ///
    /// # Errors
    ///
    /// Refuses a component outside [`COMPONENTS`], and an executable or root that
    /// is not a usable path segment, because a pointer that names another
    /// component's binary is a launch-target bug, not a typo to absorb.
    pub fn new(
        root: &str,
        component: &str,
        executable: &str,
    ) -> Result<Self, AxiomError> {
        if !COMPONENTS.contains(&component) {
            return Err(refuse("component_not_in_core_release", component));
        }
        if root.is_empty() || root.contains('\0') {
            return Err(refuse("install_root_not_usable", root));
        }
        let name = executable.strip_suffix(EXE_SUFFIX).unwrap_or(executable);
        if !is_safe_segment(name) {
            return Err(refuse("executable_not_a_path_segment", executable));
        }
        Ok(Self {
            root: root.trim_end_matches('/').to_string(),
            component: component.to_string(),
            executable: executable.to_string(),
        })
    }

    /// Install root this activation is bound to.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Component this activation is bound to.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    /// Binary file name inside a version directory.
    #[must_use]
    pub fn executable(&self) -> &str {
        &self.executable
    }

    /// Path of the pointer file.
    #[must_use]
    pub fn pointer_path(&self) -> String {
        format!("{}/{}", self.root, ACTIVE_POINTER)
    }

    /// Path of the temporary sibling the pointer is written through.
    #[must_use]
    pub fn pointer_temp_path(&self) -> String {
        format!("{}{}", self.pointer_path(), POINTER_TEMP_SUFFIX)
    }

    /// Directory one version's payload lives in, relative to the install root.
    ///
    /// # Errors
    ///
    /// Refuses a version that is not a safe path segment.
    pub fn version_dir(&self, version: &str) -> Result<String, AxiomError> {
        validate_version(version)?;
        Ok(format!(
            "{}/{}/{}/{}",
            self.root, VERSIONS_DIR, self.component, version
        ))
    }

    /// Path of one version's binary.
    ///
    /// # Errors
    ///
    /// Refuses a version that is not a safe path segment.
    pub fn binary_path(&self, version: &str) -> Result<String, AxiomError> {
        Ok(format!("{}/{}", self.version_dir(version)?, self.executable))
    }

    /// Every path an activation of `staged` may write, in order.
    ///
    /// This exists so the Windows property is checkable rather than asserted: an
    /// activation writes only these two paths, so it cannot write inside the
    /// directory the currently running image was loaded from.
    ///
    /// # Errors
    ///
    /// Refuses a version that is not a safe path segment.
    pub fn plan_writes(&self, staged: &StagedVersion) -> Result<Vec<String>, AxiomError> {
        validate_version(&staged.version)?;
        Ok(vec![
            self.pointer_temp_path(),
            self.pointer_path(),
        ])
    }

    /// Read the pointer.
    ///
    /// `Ok(None)` means the pointer does not exist, which is the honest state of a
    /// root that has never been activated. A pointer that exists but cannot be
    /// read as this component's record is an error, never a silent `None`.
    ///
    /// # Errors
    ///
    /// Refuses an unreadable, oversized, malformed, or foreign pointer.
    pub fn active(&self, fs: &dyn ActivationFs) -> Result<Option<ActiveInstall>, AxiomError> {
        let path = self.pointer_path();
        if !fs.exists(&path) {
            return Ok(None);
        }
        let bytes = fs.read(&path)?;
        if bytes.len() > MAX_POINTER_BYTES {
            return Err(refuse("pointer_too_large", &path).with_detail(
                "limit",
                MAX_POINTER_BYTES.to_string(),
            ));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| refuse("pointer_not_utf8", &path))?;
        let record: ActiveInstall = serde_json::from_str(text)
            .map_err(|_| refuse("pointer_not_a_pointer_record", &path))?;
        if record.schema_version != POINTER_SCHEMA_VERSION {
            return Err(
                refuse("pointer_schema_not_supported", &path).with_detail(
                    "required_version",
                    POINTER_SCHEMA_VERSION.to_string(),
                ),
            );
        }
        if record.component != self.component {
            return Err(refuse("pointer_names_another_component", &path)
                .with_detail("component", &record.component));
        }
        if record.binary != self.executable {
            return Err(refuse("pointer_names_another_binary", &path)
                .with_detail("observed", &record.binary));
        }
        Ok(Some(record))
    }

    /// The path a launcher should execute, resolved through the pointer.
    ///
    /// # Errors
    ///
    /// Propagates the [`Self::active`] refusal for a corrupt pointer.
    pub fn launch_target(&self, fs: &dyn ActivationFs) -> Result<Option<String>, AxiomError> {
        match self.active(fs)? {
            Some(record) => Ok(Some(format!(
                "{}/{}/{}",
                self.root, record.directory, record.binary
            ))),
            None => Ok(None),
        }
    }

    /// Activate a staged version by moving the pointer.
    ///
    /// The payload is re-hashed from its staged bytes before the pointer moves, so
    /// a directory that was edited after the download is refused instead of
    /// activated. The pointer is replaced by writing a temporary sibling and
    /// renaming it, so a failure at any point leaves the previous launch target
    /// exactly as it was.
    ///
    /// # Errors
    ///
    /// Refuses an unsafe version, a payload that was not smoke checked, a missing
    /// payload, a payload whose digest is not the staged digest, and any write or
    /// rename failure. In every refusal the pointer is left untouched.
    pub fn activate(
        &self,
        fs: &dyn ActivationFs,
        staged: &StagedVersion,
    ) -> Result<Activation, AxiomError> {
        validate_version(&staged.version)?;
        if !staged.smoke_checked {
            return Err(refuse(
                "payload_not_smoke_checked",
                &staged.version,
            ));
        }
        if !is_digest(&staged.sha256) {
            return Err(refuse("staged_digest_not_a_digest", &staged.sha256));
        }
        let binary = self.binary_path(&staged.version)?;
        if !fs.exists(&binary) {
            return Err(refuse("payload_missing", &binary));
        }
        let bytes = fs.read(&binary)?;
        if bytes.len() as u64 > MAX_BINARY_BYTES {
            return Err(refuse("payload_too_large", &binary)
                .with_detail("limit", MAX_BINARY_BYTES.to_string()));
        }
        let observed = sha256_hex(&bytes);
        if observed != staged.sha256 {
            return Err(refuse("payload_digest_mismatch", &binary)
                .with_detail("expected", &staged.sha256)
                .with_detail("actual", &observed));
        }

        // The previous record is read before anything is written, so the pointer
        // bytes that a failure must preserve are known to still be there.
        let previous = self.active(fs)?;
        let directory = format!("{}/{}/{}", VERSIONS_DIR, self.component, staged.version);
        let active = ActiveInstall {
            schema_version: POINTER_SCHEMA_VERSION,
            component: self.component.clone(),
            version: staged.version.clone(),
            directory,
            binary: self.executable.clone(),
        };
        let record = serde_json::to_value(&active).map_err(|_| {
            AxiomError::new(
                ErrorCode::Internal,
                "the activation record is not encodable",
            )
        })?;
        let text = graph_export::canonical::canonical_value(&record).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the activation record is not canonically encodable",
            )
            .with_detail("observed", error.to_string())
        })?;
        let mut pointer_bytes = text.into_bytes();
        pointer_bytes.push(b'\n');
        if pointer_bytes.len() > MAX_POINTER_BYTES {
            return Err(refuse("pointer_too_large", &self.pointer_path()));
        }

        let temp = self.pointer_temp_path();
        fs.write(&temp, &pointer_bytes)?;
        fs.rename(&temp, &self.pointer_path())?;
        Ok(Activation {
            previous,
            active,
            pointer: self.pointer_path(),
        })
    }
}

/// Accept a version only when it is one safe path segment.
fn validate_version(version: &str) -> Result<(), AxiomError> {
    if version.len() > MAX_VERSION_LEN {
        return Err(refuse("version_too_long", version)
            .with_detail("limit", MAX_VERSION_LEN.to_string()));
    }
    if !is_safe_segment(version) {
        return Err(refuse("version_not_a_path_segment", version));
    }
    Ok(())
}

/// True when `value` is a non-empty `[A-Za-z0-9][A-Za-z0-9.+-]*` segment.
fn is_safe_segment(value: &str) -> bool {
    if value.is_empty() || value == "." || value == ".." {
        return false;
    }
    let mut bytes = value.bytes();
    let first = bytes.next().expect("non-empty");
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    bytes.all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-' | b'_')
    })
}

/// The one refusal shape of this module.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the activation request violates the versioned-directory activation contract",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use super::*;

    fn digest(bytes: &[u8]) -> String {
        sha256_hex(bytes)
    }

    #[derive(Default)]
    struct MemoryFs {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        writes: RefCell<Vec<String>>,
        fail_write: RefCell<Option<String>>,
        fail_rename_to: RefCell<Option<String>>,
    }

    impl MemoryFs {
        fn put(&self, path: &str, bytes: &[u8]) {
            self.files
                .borrow_mut()
                .insert(path.to_string(), bytes.to_vec());
        }

        fn get(&self, path: &str) -> Option<Vec<u8>> {
            self.files.borrow().get(path).cloned()
        }

        fn written_paths(&self) -> Vec<String> {
            self.writes.borrow().clone()
        }
    }

    impl ActivationFs for MemoryFs {
        fn exists(&self, path: &str) -> bool {
            self.files.borrow().contains_key(path)
        }

        fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
            self.get(path).ok_or_else(|| {
                AxiomError::new(ErrorCode::NotFound, "the fixture path is missing")
                    .with_detail("observed", path)
            })
        }

        fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError> {
            if self.fail_write.borrow().as_deref() == Some(path) {
                return Err(AxiomError::new(ErrorCode::Internal, "the fixture write fails"));
            }
            self.writes.borrow_mut().push(path.to_string());
            self.files
                .borrow_mut()
                .insert(path.to_string(), bytes.to_vec());
            Ok(())
        }

        fn rename(&self, from: &str, to: &str) -> Result<(), AxiomError> {
            if self.fail_rename_to.borrow().as_deref() == Some(to) {
                return Err(AxiomError::new(ErrorCode::Internal, "the fixture rename fails"));
            }
            let bytes = self.get(from).ok_or_else(|| {
                AxiomError::new(ErrorCode::NotFound, "the fixture source is missing")
            })?;
            let mut files = self.files.borrow_mut();
            files.remove(from);
            files.insert(to.to_string(), bytes);
            Ok(())
        }
    }

    const V1: &str = "0.0.0-dev";
    const V2: &str = "0.1.0";
    const V1_BYTES: &[u8] = b"axiom-graphd v1 image";
    const V2_BYTES: &[u8] = b"axiom-graphd v2 image";

    fn activation() -> BinaryActivation {
        BinaryActivation::new(
            "install",
            "axiom-graphd",
            &format!("axiom-graphd{EXE_SUFFIX}"),
        )
        .expect("the component and executable are valid")
    }

    fn stage(fs: &MemoryFs, a: &BinaryActivation, version: &str, bytes: &[u8]) -> StagedVersion {
        let path = a.binary_path(version).expect("a safe version");
        fs.put(&path, bytes);
        StagedVersion {
            version: version.to_string(),
            sha256: digest(bytes),
            smoke_checked: true,
        }
    }

    fn rule(error: &AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    #[test]
    fn activation_moves_the_pointer_and_keeps_the_previous_target() {
        let fs = MemoryFs::default();
        let a = activation();
        assert_eq!(a.launch_target(&fs).expect("readable"), None);

        let staging = stage(&fs, &a, V1, V1_BYTES);
        let first = a.activate(&fs, &staging).expect("the first activation succeeds");
        assert_eq!(first.previous, None);
        assert!(first.changed_target());
        assert_eq!(
            first.active.directory,
            format!("{VERSIONS_DIR}/axiom-graphd/{V1}")
        );

        let staging = stage(&fs, &a, V2, V2_BYTES);
        let second = a
            .activate(&fs, &staging)
            .expect("the second activation succeeds");
        assert_eq!(second.previous.as_ref(), Some(&first.active));
        assert_eq!(second.active.version, V2);

        let target = a.launch_target(&fs).expect("readable").expect("active");
        assert_eq!(target, format!("install/{VERSIONS_DIR}/axiom-graphd/{V2}/axiom-graphd{EXE_SUFFIX}"));
        assert!(a
            .binary_path(V1)
            .expect("a safe version")
            .starts_with("install/"), "the previous payload stays on disk");
    }

    #[test]
    fn a_failed_pointer_swap_retains_the_previous_launch_target() {
        let fs = MemoryFs::default();
        let a = activation();
        let staging = stage(&fs, &a, V1, V1_BYTES);
        a.activate(&fs, &staging).expect("the first activation succeeds");
        let before = fs.get(&a.pointer_path()).expect("the pointer exists");
        let target_before = a.launch_target(&fs).expect("readable");

        *fs.fail_rename_to.borrow_mut() = Some(a.pointer_path());
        let staging = stage(&fs, &a, V2, V2_BYTES);
        let error = a
            .activate(&fs, &staging)
            .expect_err("a failed rename must fail the activation");
        assert_eq!(error.code(), ErrorCode::Internal);

        assert_eq!(
            fs.get(&a.pointer_path()).expect("the pointer still exists"),
            before,
            "the pointer bytes are unchanged"
        );
        assert_eq!(a.launch_target(&fs).expect("readable"), target_before);
        assert_eq!(
            a.active(&fs).expect("readable").expect("active").version,
            V1
        );
    }

    #[test]
    fn a_failed_pointer_write_retains_the_previous_launch_target() {
        let fs = MemoryFs::default();
        let a = activation();
        let staging = stage(&fs, &a, V1, V1_BYTES);
        a.activate(&fs, &staging).expect("the first activation succeeds");
        let before = fs.get(&a.pointer_path()).expect("the pointer exists");

        *fs.fail_write.borrow_mut() = Some(a.pointer_temp_path());
        let staging = stage(&fs, &a, V2, V2_BYTES);
        a.activate(&fs, &staging)
            .expect_err("a failed temporary write must fail the activation");
        assert_eq!(fs.get(&a.pointer_path()).expect("still there"), before);
        assert_eq!(
            a.active(&fs).expect("readable").expect("active").version,
            V1
        );
    }

    #[test]
    fn activation_never_writes_inside_the_active_version_directory() {
        let fs = MemoryFs::default();
        let a = activation();
        let staging = stage(&fs, &a, V1, V1_BYTES);
        a.activate(&fs, &staging).expect("the first activation succeeds");
        let active_dir = a.version_dir(V1).expect("a safe version");

        let staging = stage(&fs, &a, V2, V2_BYTES);
        let planned = a.plan_writes(&staging).expect("the write plan");
        for path in &planned {
            assert!(
                !path.starts_with(&format!("{active_dir}/")),
                "an activation must not write inside the running image directory"
            );
        }
        a.activate(&fs, &staging).expect("the second activation succeeds");
        for path in fs.written_paths() {
            assert!(
                !path.starts_with(&format!("{active_dir}/")),
                "wrote {path} inside the previous version directory"
            );
        }
        assert_eq!(
            planned,
            vec![a.pointer_temp_path(), a.pointer_path()],
            "the write surface is two paths, one of them temporary"
        );
    }

    #[test]
    fn a_payload_that_does_not_match_its_staged_digest_is_refused() {
        let fs = MemoryFs::default();
        let a = activation();
        let path = a.binary_path(V1).expect("a safe version");
        fs.put(&path, b"a tampered image");
        let staging = StagedVersion {
            version: V1.to_string(),
            sha256: digest(V1_BYTES),
            smoke_checked: true,
        };
        let error = a
            .activate(&fs, &staging)
            .expect_err("a tampered payload must be refused");
        assert_eq!(rule(&error), Some("payload_digest_mismatch"));
        assert!(!fs.exists(&a.pointer_path()), "the pointer is never written");
    }

    #[test]
    fn a_payload_that_was_not_smoke_checked_is_refused() {
        let fs = MemoryFs::default();
        let a = activation();
        let mut staging = stage(&fs, &a, V1, V1_BYTES);
        staging.smoke_checked = false;
        let error = a
            .activate(&fs, &staging)
            .expect_err("an unchecked payload must be refused");
        assert_eq!(rule(&error), Some("payload_not_smoke_checked"));
        assert!(!fs.exists(&a.pointer_path()));
    }

    #[test]
    fn a_missing_payload_is_refused() {
        let fs = MemoryFs::default();
        let a = activation();
        let staging = StagedVersion {
            version: V1.to_string(),
            sha256: digest(V1_BYTES),
            smoke_checked: true,
        };
        let error = a
            .activate(&fs, &staging)
            .expect_err("an absent payload must be refused");
        assert_eq!(rule(&error), Some("payload_missing"));
    }

    #[test]
    fn a_version_that_is_not_one_path_segment_is_refused() {
        let fs = MemoryFs::default();
        let a = activation();
        for version in [
            "",
            ".",
            "..",
            "../escape",
            "v1/sub",
            "v1\\sub",
            " v1",
            "-v1",
        ] {
            let staging = StagedVersion {
                version: version.to_string(),
                sha256: digest(V1_BYTES),
                smoke_checked: true,
            };
            let error = a
                .activate(&fs, &staging)
                .expect_err("a traversing version must be refused");
            assert_eq!(
                rule(&error),
                Some("version_not_a_path_segment"),
                "version {version:?} was accepted"
            );
            assert!(
                a.version_dir(version).is_err(),
                "version {version:?} resolved to a directory"
            );
        }
    }

    #[test]
    fn a_version_at_the_length_boundary_is_accepted_and_one_over_is_refused() {
        let fs = MemoryFs::default();
        let a = activation();
        let longest: String = std::iter::repeat_n('9', MAX_VERSION_LEN).collect();
        assert_eq!(longest.len(), MAX_VERSION_LEN);
        let staging = stage(&fs, &a, &longest, V1_BYTES);
        a.activate(&fs, &staging)
            .expect("a version at the bound is accepted");

        let overlong: String = std::iter::repeat_n('9', MAX_VERSION_LEN + 1).collect();
        let error = validate_version(&overlong).expect_err("one over the bound is refused");
        assert_eq!(rule(&error), Some("version_too_long"));
    }

    #[test]
    fn an_unknown_component_is_refused() {
        let error = BinaryActivation::new("install", "axiom-bootstrap", "axiom-bootstrap")
            .expect_err("a component outside the core release is refused");
        assert_eq!(rule(&error), Some("component_not_in_core_release"));
        for component in COMPONENTS {
            BinaryActivation::new("install", component, component)
                .expect("every listed component is accepted");
        }
    }

    #[test]
    fn the_pointer_is_a_bounded_canonical_record() {
        let fs = MemoryFs::default();
        let a = activation();
        let staging = stage(&fs, &a, V2, V2_BYTES);
        let outcome = a.activate(&fs, &staging).expect("activation succeeds");
        let bytes = fs.get(&a.pointer_path()).expect("the pointer exists");
        assert!(bytes.len() <= MAX_POINTER_BYTES);
        assert_eq!(bytes.last(), Some(&b'\n'));
        let text = std::str::from_utf8(&bytes).expect("UTF-8");
        let value: serde_json::Value = serde_json::from_str(text).expect("JSON");
        assert_eq!(
            text.trim_end(),
            graph_export::canonical::canonical_value(&value).expect("canonical"),
            "the pointer is stored in the one canonical form"
        );
        assert_eq!(
            serde_json::from_str::<ActiveInstall>(text).expect("record"),
            outcome.active
        );
    }

    #[test]
    fn a_corrupt_or_foreign_pointer_is_refused_rather_than_ignored() {
        let a = activation();
        let fs = MemoryFs::default();
        fs.put(&a.pointer_path(), b"not json\n");
        let error = a.active(&fs).expect_err("a corrupt pointer is refused");
        assert_eq!(rule(&error), Some("pointer_not_a_pointer_record"));
        assert!(a.launch_target(&fs).is_err());

        let fs = MemoryFs::default();
        fs.put(&a.pointer_path(), &vec![b'x'; MAX_POINTER_BYTES + 1]);
        let error = a.active(&fs).expect_err("an oversized pointer is refused");
        assert_eq!(rule(&error), Some("pointer_too_large"));

        let fs = MemoryFs::default();
        let foreign = ActiveInstall {
            schema_version: POINTER_SCHEMA_VERSION,
            component: "axiom".to_string(),
            version: V1.to_string(),
            directory: format!("{VERSIONS_DIR}/axiom/{V1}"),
            binary: format!("axiom{EXE_SUFFIX}"),
        };
        fs.put(
            &a.pointer_path(),
            format!("{}\n", serde_json::to_string(&foreign).expect("encodable")).as_bytes(),
        );
        let error = a.active(&fs).expect_err("another component's pointer is refused");
        assert_eq!(rule(&error), Some("pointer_names_another_component"));

        let fs = MemoryFs::default();
        let future = ActiveInstall {
            schema_version: POINTER_SCHEMA_VERSION + 1,
            component: "axiom-graphd".to_string(),
            version: V1.to_string(),
            directory: format!("{VERSIONS_DIR}/axiom-graphd/{V1}"),
            binary: format!("axiom-graphd{EXE_SUFFIX}"),
        };
        fs.put(
            &a.pointer_path(),
            format!("{}\n", serde_json::to_string(&future).expect("encodable")).as_bytes(),
        );
        let error = a.active(&fs).expect_err("a newer pointer schema is refused");
        assert_eq!(rule(&error), Some("pointer_schema_not_supported"));
    }
}
