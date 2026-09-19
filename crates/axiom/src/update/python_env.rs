//! Activate a versioned, locked Python MCP environment (task E-043).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 6 states the rule this module
//! implements:
//!
//! > The Python package lives in a versioned virtual environment; it does not
//! > `pip install` over the environment that is currently active.
//!
//! Installing into the live interpreter is the failure this module removes
//! structurally rather than by policy: there is no function here that writes a
//! package into the environment the pointer names. The lifecycle is
//!
//! 1. [`PythonEnv::prepare`] declares one locked environment at one version and
//!    lands its lock file in `pyenv/<component>/<version>/`. A version directory
//!    that already exists is refused, so a version can never be mutated after it
//!    was built.
//! 2. The caller builds that directory with a hash-checked install
//!    (`pip install --require-hashes --requirement`), which is what writes
//!    `installed.json`.
//! 3. [`PythonEnv::smoke_test`] reads the directory back and proves the built
//!    environment *is* the locked one: the lock file on disk still has the locked
//!    digest, the interpreter is the locked interpreter, every locked distribution
//!    is installed at exactly the locked version, and nothing unlocked is present.
//! 4. [`PythonEnv::activate`] moves the pointer, and only accepts a verdict that
//!    was produced for *this* version and *this* lock digest, so a stale passing
//!    verdict cannot activate a different environment.
//!
//! A lock is pinned or it is refused: `>=`, `~=`, `*` and a missing hash are all
//! refusals, because an environment that can drift is not a locked environment and
//! a drifted MCP environment is invisible until a query fails in production.

use serde::{Deserialize, Serialize};

use graph_core::error::{AxiomError, ErrorCode};
use graph_export::sha256_hex;

/// Directory under the install root that holds every staged interpreter env.
pub const ENVS_DIR: &str = "pyenv";

/// Name of the pointer that names the activated environment.
pub const ACTIVE_POINTER: &str = "current";

/// Suffix of the temporary sibling used to replace the pointer atomically.
pub const POINTER_TEMP_SUFFIX: &str = ".next";

/// Schema version of the environment pointer record.
pub const POINTER_SCHEMA_VERSION: u64 = 1;

/// Name of the lock file inside one versioned environment.
pub const LOCK_FILE: &str = "requirements.lock";

/// Name of the record the build writes next to the lock, naming what it installed.
pub const INSTALLED_FILE: &str = "installed.json";

/// Name of the site-packages directory inside one versioned environment.
pub const SITE_PACKAGES_DIR: &str = "site-packages";

/// Components that own a Python environment in the core release.
///
/// Only the MCP server is a Python distribution; `axiom-graphd` and `axiom` are
/// native binaries activated by [`crate::update::rust_binary`].
pub const ENV_COMPONENTS: [&str; 1] = ["axiom-mcp"];

/// Longest accepted version string.
pub const MAX_VERSION_LEN: usize = 64;

/// Upper bound on one lock file.
pub const MAX_LOCK_BYTES: usize = 64 * 1024;

/// Upper bound on the number of locked distributions.
pub const MAX_REQUIREMENTS: usize = 512;

/// Upper bound on the pointer record.
pub const MAX_POINTER_BYTES: usize = 1024;

/// The mutation surface of one install root (see the module documentation).
pub trait EnvFs {
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

/// One pinned distribution of a locked environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedRequirement {
    /// Distribution name, normalised to lower case.
    pub name: String,
    /// Exact version this environment must contain.
    pub version: String,
    /// Lowercase 64-hex artifact digest the install must verify.
    pub sha256: String,
}

/// One distribution the build reports as installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledPackage {
    /// Distribution name, normalised to lower case.
    pub name: String,
    /// Version the build installed.
    pub version: String,
}

/// The build's record of what one environment actually contains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledEnv {
    /// Interpreter the environment was built against.
    pub interpreter: String,
    /// Distributions the build installed, in the order it reports them.
    pub packages: Vec<InstalledPackage>,
}

/// A parsed, fully pinned environment lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequirementLock {
    /// Interpreter the environment is built against.
    pub python: String,
    /// Every pinned distribution, in lock order.
    pub requirements: Vec<LockedRequirement>,
    /// Lowercase 64-hex digest of the exact lock text.
    pub digest: String,
}

impl RequirementLock {
    /// The exact lock text this digest was computed over.
    #[must_use]
    pub fn canonical_text(&self) -> String {
        let mut text = String::new();
        text.push_str(&format!("python=={}\n", self.python));
        for requirement in &self.requirements {
            text.push_str(&format!(
                "{}=={} --hash=sha256:{}\n",
                requirement.name, requirement.version, requirement.sha256
            ));
        }
        text
    }
}

/// A locked environment that has been declared and staged but not activated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedEnv {
    /// Version of the environment.
    pub version: String,
    /// Parsed lock the environment must be built from.
    pub lock: RequirementLock,
}

/// The record the pointer holds: which environment version is active.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveEnv {
    /// Schema version of this record.
    pub schema_version: u64,
    /// Component name, from [`ENV_COMPONENTS`].
    pub component: String,
    /// Version that is active.
    pub version: String,
    /// Directory the environment lives in, relative to the install root.
    pub directory: String,
    /// Digest of the lock the active environment was built from.
    pub lock_digest: String,
}

/// The proof that one staged environment *is* its lock and may be activated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVerdict {
    /// Component the verdict was produced for.
    pub component: String,
    /// Version the verdict was produced for.
    pub version: String,
    /// Lock digest the verdict was produced for.
    pub lock_digest: String,
    /// Interpreter that was found.
    pub interpreter: String,
    /// Number of locked distributions that were verified present.
    pub requirements_checked: usize,
}

/// The outcome of one successful environment activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvActivation {
    /// The environment that was active before, if any.
    pub previous: Option<ActiveEnv>,
    /// The environment that is active now.
    pub active: ActiveEnv,
    /// Path of the pointer that was replaced.
    pub pointer: String,
}

/// One component's versioned Python environment inside an install root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonEnv {
    root: String,
    component: String,
}

impl PythonEnv {
    /// Bind an environment to one component of one install root.
    ///
    /// # Errors
    ///
    /// Refuses a component that has no Python environment in this release.
    pub fn new(root: &str, component: &str) -> Result<Self, AxiomError> {
        if !ENV_COMPONENTS.contains(&component) {
            return Err(refuse("component_has_no_python_environment", component));
        }
        if root.is_empty() || root.contains('\0') {
            return Err(refuse("install_root_not_usable", root));
        }
        Ok(Self {
            root: root.trim_end_matches('/').to_string(),
            component: component.to_string(),
        })
    }

    /// Install root this environment is bound to.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Component this environment is bound to.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
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

    /// Directory one version's environment lives in.
    ///
    /// # Errors
    ///
    /// Refuses a version that is not a safe path segment.
    pub fn env_dir(&self, version: &str) -> Result<String, AxiomError> {
        validate_version(version)?;
        Ok(format!(
            "{}/{}/{}/{}",
            self.root, ENVS_DIR, self.component, version
        ))
    }

    /// Directory the interpreter installed into, which a build may write.
    ///
    /// # Errors
    ///
    /// Refuses a version that is not a safe path segment.
    pub fn site_packages(&self, version: &str) -> Result<String, AxiomError> {
        Ok(format!("{}/{}", self.env_dir(version)?, SITE_PACKAGES_DIR))
    }

    /// Path of one version's lock file.
    ///
    /// # Errors
    ///
    /// Refuses a version that is not a safe path segment.
    pub fn lock_path(&self, version: &str) -> Result<String, AxiomError> {
        Ok(format!("{}/{}", self.env_dir(version)?, LOCK_FILE))
    }

    /// Path of one version's installed record.
    ///
    /// # Errors
    ///
    /// Refuses a version that is not a safe path segment.
    pub fn installed_path(&self, version: &str) -> Result<String, AxiomError> {
        Ok(format!("{}/{}", self.env_dir(version)?, INSTALLED_FILE))
    }
    /// Read the pointer, refusing anything that is not this component's record.
    ///
    /// # Errors
    ///
    /// Refuses an unreadable, oversized, malformed, foreign or newer pointer.
    pub fn active(&self, fs: &dyn EnvFs) -> Result<Option<ActiveEnv>, AxiomError> {
        let path = self.pointer_path();
        if !fs.exists(&path) {
            return Ok(None);
        }
        let bytes = fs.read(&path)?;
        if bytes.len() > MAX_POINTER_BYTES {
            return Err(refuse("pointer_too_large", &path)
                .with_detail("limit", MAX_POINTER_BYTES.to_string()));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| refuse("pointer_not_utf8", &path))?;
        let record: ActiveEnv = serde_json::from_str(text)
            .map_err(|_| refuse("pointer_not_a_pointer_record", &path))?;
        if record.schema_version != POINTER_SCHEMA_VERSION {
            return Err(refuse("pointer_schema_not_supported", &path)
                .with_detail("required_version", POINTER_SCHEMA_VERSION.to_string()));
        }
        if record.component != self.component {
            return Err(refuse("pointer_names_another_component", &path)
                .with_detail("component", &record.component));
        }
        Ok(Some(record))
    }

    /// Declare one versioned environment and land its lock in a fresh directory.
    ///
    /// A version directory that already exists is refused, and so is a version the
    /// pointer already names. That is the whole in-place-mutation guarantee: a
    /// built environment is immutable, so the active environment is never written
    /// by a later build.
    ///
    /// # Errors
    ///
    /// Refuses an unsafe version, an environment version that already exists or is
    /// already active, a lock whose digest does not match its text, an empty or
    /// over-large requirement set, and an over-long lock.
    pub fn prepare(&self, fs: &dyn EnvFs, staged: &StagedEnv) -> Result<(), AxiomError> {
        validate_version(&staged.version)?;
        if staged.lock.requirements.is_empty() {
            return Err(refuse("lock_has_no_requirements", &staged.version));
        }
        if staged.lock.requirements.len() > MAX_REQUIREMENTS {
            return Err(refuse("lock_has_too_many_requirements", &staged.version)
                .with_detail("limit", MAX_REQUIREMENTS.to_string()));
        }
        if let Some(active) = self.active(fs)? {
            if active.version == staged.version {
                return Err(refuse(
                    "environment_version_already_active",
                    &staged.version,
                ));
            }
        }
        let directory = self.env_dir(&staged.version)?;
        if fs.exists(&directory) {
            return Err(refuse("environment_directory_already_exists", &directory));
        }
        let text = staged.lock.canonical_text();
        let observed = sha256_hex(text.as_bytes());
        if observed != staged.lock.digest {
            return Err(refuse("lock_digest_mismatch", &staged.version)
                .with_detail("expected", &staged.lock.digest)
                .with_detail("actual", &observed));
        }
        if text.len() > MAX_LOCK_BYTES {
            return Err(refuse("lock_too_large", &staged.version)
                .with_detail("limit", MAX_LOCK_BYTES.to_string()));
        }
        let lock_path = self.lock_path(&staged.version)?;
        fs.write(&lock_path, text.as_bytes())?;
        Ok(())
    }

    /// Read a built environment back and prove it is the locked one.
    ///
    /// # Errors
    ///
    /// Refuses a missing or tampered lock, an unbuilt environment, an interpreter
    /// that is not the locked interpreter, a locked distribution that is missing or
    /// installed at another version, and an installed distribution the lock does
    /// not contain.
    pub fn smoke_test(&self, fs: &dyn EnvFs, staged: &StagedEnv) -> Result<EnvVerdict, AxiomError> {
        validate_version(&staged.version)?;
        let lock_path = self.lock_path(&staged.version)?;
        if !fs.exists(&lock_path) {
            return Err(refuse("environment_not_staged", &lock_path));
        }
        let bytes = fs.read(&lock_path)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| refuse("lock_not_utf8", &lock_path))?;
        let observed = sha256_hex(text.as_bytes());
        if observed != staged.lock.digest {
            return Err(refuse("lock_file_tampered", &lock_path)
                .with_detail("expected", &staged.lock.digest)
                .with_detail("actual", &observed));
        }
        let installed_path = self.installed_path(&staged.version)?;
        if !fs.exists(&installed_path) {
            return Err(refuse("environment_not_built", &installed_path));
        }
        let installed_bytes = fs.read(&installed_path)?;
        let installed_text = std::str::from_utf8(&installed_bytes)
            .map_err(|_| refuse("installed_record_not_utf8", &installed_path))?;
        let installed: InstalledEnv = serde_json::from_str(installed_text)
            .map_err(|_| refuse("installed_record_not_a_record", &installed_path))?;

        if installed.interpreter != staged.lock.python {
            return Err(refuse("interpreter_mismatch", &installed_path)
                .with_detail("expected", &staged.lock.python)
                .with_detail("actual", &installed.interpreter));
        }
        for requirement in &staged.lock.requirements {
            match installed
                .packages
                .iter()
                .find(|package| package.name == requirement.name)
            {
                Some(package) if package.version == requirement.version => {}
                Some(package) => {
                    return Err(refuse("locked_version_not_installed", &requirement.name)
                        .with_detail("expected", &requirement.version)
                        .with_detail("actual", &package.version))
                }
                None => {
                    return Err(refuse("locked_requirement_missing", &requirement.name)
                        .with_detail("expected", &requirement.version))
                }
            }
        }
        for package in &installed.packages {
            if !staged
                .lock
                .requirements
                .iter()
                .any(|requirement| requirement.name == package.name)
            {
                return Err(refuse("unlocked_package_installed", &package.name)
                    .with_detail("observed", &package.version));
            }
        }
        Ok(EnvVerdict {
            component: self.component.clone(),
            version: staged.version.clone(),
            lock_digest: staged.lock.digest.clone(),
            interpreter: installed.interpreter,
            requirements_checked: staged.lock.requirements.len(),
        })
    }
    /// Activate a smoke-tested environment by moving the pointer.
    ///
    /// The verdict must have been produced for this component, this version and
    /// this lock digest; a verdict for another environment is refused rather than
    /// reused, which is what stops a passing test of one build from activating a
    /// different one.
    ///
    /// # Errors
    ///
    /// Refuses a verdict that does not belong to this staged environment, an
    /// unsafe version, and any pointer write or rename failure.
    pub fn activate(
        &self,
        fs: &dyn EnvFs,
        staged: &StagedEnv,
        verdict: &EnvVerdict,
    ) -> Result<EnvActivation, AxiomError> {
        validate_version(&staged.version)?;
        if verdict.component != self.component
            || verdict.version != staged.version
            || verdict.lock_digest != staged.lock.digest
        {
            return Err(refuse("verdict_not_for_this_environment", &staged.version)
                .with_detail("expected", &staged.lock.digest)
                .with_detail("actual", &verdict.lock_digest));
        }
        if verdict.requirements_checked != staged.lock.requirements.len() {
            return Err(
                refuse("verdict_checked_another_requirement_set", &staged.version)
                    .with_detail("expected", staged.lock.requirements.len().to_string())
                    .with_detail("actual", verdict.requirements_checked.to_string()),
            );
        }
        let previous = self.active(fs)?;
        let directory = format!("{}/{}/{}", ENVS_DIR, self.component, staged.version);
        let active = ActiveEnv {
            schema_version: POINTER_SCHEMA_VERSION,
            component: self.component.clone(),
            version: staged.version.clone(),
            directory,
            lock_digest: staged.lock.digest.clone(),
        };
        let record = serde_json::to_value(&active).map_err(|_| {
            AxiomError::new(
                ErrorCode::Internal,
                "the environment pointer is not encodable",
            )
        })?;
        let text = graph_export::canonical::canonical_value(&record).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the environment pointer is not canonically encodable",
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
        Ok(EnvActivation {
            previous,
            active,
            pointer: self.pointer_path(),
        })
    }
}

/// Parse a fully pinned environment lock.
///
/// # Errors
///
/// Refuses a lock that is over [`MAX_LOCK_BYTES`], has no interpreter line, has no
/// requirements, has more than [`MAX_REQUIREMENTS`] distributions, repeats a name,
/// is not pinned with `==`, is missing a `sha256:` hash, or names a version or
/// digest that is not a single token.
pub fn parse_lock(text: &str) -> Result<RequirementLock, AxiomError> {
    if text.len() > MAX_LOCK_BYTES {
        return Err(refuse("lock_too_large", "requirements.lock")
            .with_detail("limit", MAX_LOCK_BYTES.to_string()));
    }
    let mut python: Option<String> = None;
    let mut requirements: Vec<LockedRequirement> = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let number = (index + 1).to_string();
        let (head, hashes) = match line.split_once(" --hash=") {
            Some((head, rest)) => (head.trim(), Some(rest.trim())),
            None => (line, None),
        };
        let (name, version) = head.split_once("==").ok_or_else(|| {
            refuse("requirement_not_pinned", &number).with_detail("observed", head)
        })?;
        let name = name.trim();
        let version = version.trim();
        if !is_distribution_name(name) {
            return Err(refuse("requirement_name_not_a_distribution", &number)
                .with_detail("observed", name));
        }
        if name == "python" {
            if hashes.is_some() {
                return Err(refuse("interpreter_line_has_a_hash", &number));
            }
            if python.is_some() {
                return Err(refuse("interpreter_declared_twice", &number));
            }
            if !is_single_version_token(version) {
                return Err(
                    refuse("interpreter_not_pinned", &number).with_detail("observed", version)
                );
            }
            python = Some(version.to_string());
            continue;
        }
        if !is_single_version_token(version) {
            return Err(refuse("requirement_not_pinned", &number).with_detail("observed", version));
        }
        let digest = hashes.ok_or_else(|| {
            refuse("requirement_has_no_hash", &number).with_detail("observed", name)
        })?;
        let digest = digest.strip_prefix("sha256:").ok_or_else(|| {
            refuse("requirement_hash_is_not_sha256", &number).with_detail("observed", digest)
        })?;
        if !is_digest_text(digest) {
            return Err(
                refuse("requirement_hash_not_a_digest", &number).with_detail("observed", digest)
            );
        }
        let name = name.to_ascii_lowercase();
        if requirements.iter().any(|existing| existing.name == name) {
            return Err(
                refuse("requirement_declared_twice", &number).with_detail("observed", &name)
            );
        }
        if requirements.len() == MAX_REQUIREMENTS {
            return Err(refuse("lock_has_too_many_requirements", &number)
                .with_detail("limit", MAX_REQUIREMENTS.to_string()));
        }
        requirements.push(LockedRequirement {
            name,
            version: version.to_string(),
            sha256: digest.to_string(),
        });
    }
    let python =
        python.ok_or_else(|| refuse("lock_declares_no_interpreter", "requirements.lock"))?;
    if requirements.is_empty() {
        return Err(refuse("lock_has_no_requirements", "requirements.lock"));
    }
    Ok(RequirementLock {
        python,
        requirements,
        digest: sha256_hex(text.as_bytes()),
    })
}

/// Accept a version only when it is one safe path segment.
fn validate_version(version: &str) -> Result<(), AxiomError> {
    if version.len() > MAX_VERSION_LEN {
        return Err(
            refuse("version_too_long", version).with_detail("limit", MAX_VERSION_LEN.to_string())
        );
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
    bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-' | b'_'))
}

/// True when `value` is a PEP 503 distribution name.
fn is_distribution_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

/// True when `value` is a single version token with no range operator.
fn is_single_version_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_VERSION_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'!'))
        && value.bytes().any(|byte| byte.is_ascii_digit())
}

/// Lowercase 64-hex digest check, matching the one digest form in this workspace.
fn is_digest_text(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The one refusal shape of this module.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the environment request violates the locked-environment contract",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use super::*;

    const V1: &str = "0.0.0-dev";
    const V2: &str = "0.1.0";

    const LOCK_V1: &str = "python==3.12.7\nmcp==1.2.3 --hash=sha256:1111111111111111111111111111111111111111111111111111111111111111\n";

    fn digest(bytes: &[u8]) -> String {
        sha256_hex(bytes)
    }

    #[derive(Default)]
    struct MemoryFs {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        writes: RefCell<Vec<String>>,
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
    }

    impl EnvFs for MemoryFs {
        fn exists(&self, path: &str) -> bool {
            let prefix = format!("{path}/");
            let files = self.files.borrow();
            files.contains_key(path) || files.keys().any(|key| key.starts_with(&prefix))
        }
        fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
            self.get(path).ok_or_else(|| {
                AxiomError::new(ErrorCode::NotFound, "the fixture path is missing")
                    .with_detail("observed", path)
            })
        }
        fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError> {
            self.writes.borrow_mut().push(path.to_string());
            self.files
                .borrow_mut()
                .insert(path.to_string(), bytes.to_vec());
            Ok(())
        }
        fn rename(&self, from: &str, to: &str) -> Result<(), AxiomError> {
            if self.fail_rename_to.borrow().as_deref() == Some(to) {
                return Err(AxiomError::new(
                    ErrorCode::Internal,
                    "the fixture rename fails",
                ));
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

    fn env() -> PythonEnv {
        PythonEnv::new("install", "axiom-mcp").expect("the component owns an environment")
    }

    fn staged(text: &str, version: &str) -> StagedEnv {
        StagedEnv {
            version: version.to_string(),
            lock: parse_lock(text).expect("the fixture lock is pinned"),
        }
    }

    /// Simulate the caller's hash-checked build writing its installed record.
    fn build(fs: &MemoryFs, e: &PythonEnv, staged: &StagedEnv, packages: &[(&str, &str)]) {
        let installed = InstalledEnv {
            interpreter: staged.lock.python.clone(),
            packages: packages
                .iter()
                .map(|(name, version)| InstalledPackage {
                    name: (*name).to_string(),
                    version: (*version).to_string(),
                })
                .collect(),
        };
        let path = e.installed_path(&staged.version).expect("a safe version");
        fs.put(
            &path,
            format!(
                "{}\n",
                serde_json::to_string(&installed).expect("encodable")
            )
            .as_bytes(),
        );
    }

    fn rule(error: &AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    #[test]
    fn a_pinned_lock_parses_and_its_digest_covers_its_text() {
        let lock = parse_lock(LOCK_V1).expect("the lock is valid");
        assert_eq!(lock.python, "3.12.7");
        assert_eq!(lock.requirements.len(), 1);
        assert_eq!(lock.requirements[0].name, "mcp");
        assert_eq!(lock.requirements[0].version, "1.2.3");
        assert_eq!(lock.digest, digest(LOCK_V1.as_bytes()));
        let render = parse_lock(&lock.canonical_text()).expect("the rendered form re-parses");
        assert_eq!(render.digest, lock.digest);
        assert_eq!(render.canonical_text(), LOCK_V1);
    }

    #[test]
    fn a_lock_that_is_not_fully_pinned_is_refused() {
        let hash = "1111111111111111111111111111111111111111111111111111111111111111";
        let cases = [
            (format!("python==3.12.7\nmcp>=1.2.3 --hash=sha256:{hash}\n"), "requirement_not_pinned"),
            ("python==3.12.7\nmcp==1.2.3\n".to_string(), "requirement_has_no_hash"),
            (format!("python==3.12.7\nmcp==1.2.3 --hash=sha512:{hash}\n"), "requirement_hash_is_not_sha256"),
            ("python==3.12.7\nmcp==1.2.3 --hash=sha256:abcd\n".to_string(), "requirement_hash_not_a_digest"),
            ("python==3.12.7\n".to_string(), "lock_has_no_requirements"),
            (format!("mcp==1.2.3 --hash=sha256:{hash}\n"), "lock_declares_no_interpreter"),
            (format!("python==3.12.*\nmcp==1.2.3 --hash=sha256:{hash}\n"), "interpreter_not_pinned"),
            (format!("python==3.12.7\nMcp==1.2.3 --hash=sha256:{hash}\n"), "requirement_name_not_a_distribution"),
            (format!("python==3.12.7\nmcp==1.2.3 --hash=sha256:{hash}\nmcp==1.2.4 --hash=sha256:{hash}\n"), "requirement_declared_twice"),
            (format!("python==3.12.7\npython==3.12.8\nmcp==1.2.3 --hash=sha256:{hash}\n"), "interpreter_declared_twice"),
        ];
        for (text, expected) in cases {
            let error = parse_lock(&text).expect_err("the lock must be refused");
            assert_eq!(rule(&error), Some(expected), "for {text:?}");
        }
    }

    #[test]
    fn the_lifecycle_prepares_tests_and_then_activates() {
        let fs = MemoryFs::default();
        let e = env();
        let one = staged(LOCK_V1, V1);
        e.prepare(&fs, &one).expect("prepare lands the lock");
        assert_eq!(
            fs.get(&e.lock_path(V1).expect("a safe version")),
            Some(LOCK_V1.as_bytes().to_vec())
        );
        assert_eq!(e.active(&fs).expect("readable"), None);

        build(&fs, &e, &one, &[("mcp", "1.2.3")]);
        let verdict = e
            .smoke_test(&fs, &one)
            .expect("the built environment is locked");
        assert_eq!(verdict.requirements_checked, 1);
        assert_eq!(verdict.interpreter, "3.12.7");

        let first = e
            .activate(&fs, &one, &verdict)
            .expect("activation succeeds");
        assert_eq!(first.previous, None);
        assert_eq!(first.active.version, V1);

        let two = staged(LOCK_V1, V2);
        e.prepare(&fs, &two)
            .expect("prepare the second environment");
        build(&fs, &e, &two, &[("mcp", "1.2.3")]);
        let verdict = e.smoke_test(&fs, &two).expect("the second build is locked");
        let second = e
            .activate(&fs, &two, &verdict)
            .expect("the second activation succeeds");
        assert_eq!(second.previous.as_ref(), Some(&first.active));
        assert_eq!(second.active.version, V2);
        assert!(
            fs.exists(&e.env_dir(V1).expect("a safe version")),
            "the previous environment is still on disk"
        );
    }
    #[test]
    fn activation_is_refused_without_a_verdict_for_this_environment() {
        let fs = MemoryFs::default();
        let e = env();
        let one = staged(LOCK_V1, V1);
        e.prepare(&fs, &one).expect("prepare");
        build(&fs, &e, &one, &[("mcp", "1.2.3")]);
        let verdict = e.smoke_test(&fs, &one).expect("locked");

        let two = staged(LOCK_V1, V2);
        e.prepare(&fs, &two)
            .expect("prepare the second environment");
        let error = e
            .activate(&fs, &two, &verdict)
            .expect_err("a verdict for another version must be refused");
        assert_eq!(rule(&error), Some("verdict_not_for_this_environment"));
        assert_eq!(e.active(&fs).expect("readable"), None);

        let mut stale = verdict.clone();
        stale.lock_digest = digest(b"another lock");
        let error = e
            .activate(&fs, &one, &stale)
            .expect_err("a verdict for another lock must be refused");
        assert_eq!(rule(&error), Some("verdict_not_for_this_environment"));

        let mut short = verdict;
        short.requirements_checked = 0;
        let error = e
            .activate(&fs, &one, &short)
            .expect_err("a verdict for another requirement set must be refused");
        assert_eq!(
            rule(&error),
            Some("verdict_checked_another_requirement_set")
        );
    }

    #[test]
    fn an_existing_or_active_environment_directory_is_never_written_again() {
        let fs = MemoryFs::default();
        let e = env();
        let one = staged(LOCK_V1, V1);
        e.prepare(&fs, &one).expect("prepare");
        build(&fs, &e, &one, &[("mcp", "1.2.3")]);
        let verdict = e.smoke_test(&fs, &one).expect("locked");
        e.activate(&fs, &one, &verdict)
            .expect("activation succeeds");

        let error = e
            .prepare(&fs, &one)
            .expect_err("re-preparing the active environment must be refused");
        assert_eq!(rule(&error), Some("environment_version_already_active"));

        let two = staged(LOCK_V1, V2);
        e.prepare(&fs, &two)
            .expect("prepare the second environment");
        let error = e
            .prepare(&fs, &two)
            .expect_err("re-preparing an existing directory must be refused");
        assert_eq!(rule(&error), Some("environment_directory_already_exists"));

        let lock_path = e.lock_path(V1).expect("a safe version");
        assert_eq!(
            fs.get(&lock_path),
            Some(LOCK_V1.as_bytes().to_vec()),
            "the active environment's lock was not rewritten"
        );
        assert_eq!(
            fs.writes
                .borrow()
                .iter()
                .filter(|p| **p == lock_path)
                .count(),
            1,
            "the active lock was written exactly once, at prepare time"
        );
    }

    #[test]
    fn a_drifted_or_extra_installed_distribution_is_refused() {
        let fs = MemoryFs::default();
        let e = env();
        let one = staged(LOCK_V1, V1);
        e.prepare(&fs, &one).expect("prepare");

        build(&fs, &e, &one, &[("mcp", "1.2.4")]);
        let error = e
            .smoke_test(&fs, &one)
            .expect_err("a drifted version must be refused");
        assert_eq!(rule(&error), Some("locked_version_not_installed"));

        build(&fs, &e, &one, &[]);
        let error = e
            .smoke_test(&fs, &one)
            .expect_err("a missing distribution must be refused");
        assert_eq!(rule(&error), Some("locked_requirement_missing"));

        build(&fs, &e, &one, &[("mcp", "1.2.3"), ("whatever", "9.9.9")]);
        let error = e
            .smoke_test(&fs, &one)
            .expect_err("an unlocked distribution must be refused");
        assert_eq!(rule(&error), Some("unlocked_package_installed"));

        let installed = InstalledEnv {
            interpreter: "3.11.9".to_string(),
            packages: vec![InstalledPackage {
                name: "mcp".to_string(),
                version: "1.2.3".to_string(),
            }],
        };
        fs.put(
            &e.installed_path(V1).expect("a safe version"),
            format!(
                "{}\n",
                serde_json::to_string(&installed).expect("encodable")
            )
            .as_bytes(),
        );
        let error = e
            .smoke_test(&fs, &one)
            .expect_err("another interpreter must be refused");
        assert_eq!(rule(&error), Some("interpreter_mismatch"));
    }

    #[test]
    fn an_unbuilt_or_tampered_environment_is_refused() {
        let fs = MemoryFs::default();
        let e = env();
        let one = staged(LOCK_V1, V1);
        let error = e
            .smoke_test(&fs, &one)
            .expect_err("an unstaged environment must be refused");
        assert_eq!(rule(&error), Some("environment_not_staged"));

        e.prepare(&fs, &one).expect("prepare");
        let error = e
            .smoke_test(&fs, &one)
            .expect_err("an unbuilt environment must be refused");
        assert_eq!(rule(&error), Some("environment_not_built"));

        build(&fs, &e, &one, &[("mcp", "1.2.3")]);
        fs.put(
            &e.lock_path(V1).expect("a safe version"),
            b"python==3.12.7\nmcp==1.2.4 --hash=sha256:2222222222222222222222222222222222222222222222222222222222222222\n",
        );
        let error = e
            .smoke_test(&fs, &one)
            .expect_err("a tampered lock must be refused");
        assert_eq!(rule(&error), Some("lock_file_tampered"));
    }

    #[test]
    fn prepare_refuses_a_lock_whose_digest_does_not_cover_its_text() {
        let fs = MemoryFs::default();
        let e = env();
        let mut one = staged(LOCK_V1, V1);
        one.lock.digest = digest(b"a different lock");
        let error = e
            .prepare(&fs, &one)
            .expect_err("a mismatched lock digest must be refused");
        assert_eq!(rule(&error), Some("lock_digest_mismatch"));
        assert!(!fs.exists(&e.lock_path(V1).expect("a safe version")));
    }

    #[test]
    fn a_failed_pointer_swap_retains_the_previous_environment() {
        let fs = MemoryFs::default();
        let e = env();
        let one = staged(LOCK_V1, V1);
        e.prepare(&fs, &one).expect("prepare");
        build(&fs, &e, &one, &[("mcp", "1.2.3")]);
        let verdict = e.smoke_test(&fs, &one).expect("locked");
        e.activate(&fs, &one, &verdict)
            .expect("activation succeeds");
        let before = fs.get(&e.pointer_path()).expect("the pointer exists");

        let two = staged(LOCK_V1, V2);
        e.prepare(&fs, &two)
            .expect("prepare the second environment");
        build(&fs, &e, &two, &[("mcp", "1.2.3")]);
        let verdict = e.smoke_test(&fs, &two).expect("locked");
        *fs.fail_rename_to.borrow_mut() = Some(e.pointer_path());
        e.activate(&fs, &two, &verdict)
            .expect_err("a failed rename fails the activation");
        assert_eq!(fs.get(&e.pointer_path()).expect("still there"), before);
        assert_eq!(
            e.active(&fs).expect("readable").expect("active").version,
            V1
        );
    }

    #[test]
    fn the_pointer_is_bounded_and_a_foreign_pointer_is_refused() {
        let fs = MemoryFs::default();
        let e = env();
        let one = staged(LOCK_V1, V1);
        e.prepare(&fs, &one).expect("prepare");
        build(&fs, &e, &one, &[("mcp", "1.2.3")]);
        let verdict = e.smoke_test(&fs, &one).expect("locked");
        e.activate(&fs, &one, &verdict)
            .expect("activation succeeds");
        let bytes = fs.get(&e.pointer_path()).expect("the pointer exists");
        assert!(bytes.len() <= MAX_POINTER_BYTES);
        assert_eq!(bytes.last(), Some(&b'\n'));

        let foreign = ActiveEnv {
            schema_version: POINTER_SCHEMA_VERSION,
            component: "axiom-graphd".to_string(),
            version: V1.to_string(),
            directory: format!("{ENVS_DIR}/axiom-graphd/{V1}"),
            lock_digest: digest(b"x"),
        };
        fs.put(
            &e.pointer_path(),
            format!("{}\n", serde_json::to_string(&foreign).expect("encodable")).as_bytes(),
        );
        let error = e.active(&fs).expect_err("a foreign pointer is refused");
        assert_eq!(rule(&error), Some("pointer_names_another_component"));

        fs.put(&e.pointer_path(), b"junk\n");
        assert_eq!(
            rule(&e.active(&fs).expect_err("corrupt")),
            Some("pointer_not_a_pointer_record")
        );
    }

    #[test]
    fn a_component_without_a_python_environment_is_refused() {
        for component in ["axiom-graphd", "axiom", "axiom-bootstrap"] {
            let error = PythonEnv::new("install", component)
                .expect_err("only the MCP server owns a Python environment");
            assert_eq!(rule(&error), Some("component_has_no_python_environment"));
        }
        for component in ENV_COMPONENTS {
            PythonEnv::new("install", component).expect("the listed component is accepted");
        }
    }

    #[test]
    fn a_version_that_is_not_one_path_segment_is_refused() {
        let e = env();
        for version in ["", "..", "../escape", "v1/sub", "-v1"] {
            assert_eq!(
                rule(&e.env_dir(version).expect_err("refused")),
                Some("version_not_a_path_segment"),
                "version {version:?} resolved"
            );
        }
        let longest: String = std::iter::repeat_n('7', MAX_VERSION_LEN).collect();
        e.env_dir(&longest)
            .expect("a version at the bound is accepted");
        let overlong: String = std::iter::repeat_n('7', MAX_VERSION_LEN + 1).collect();
        assert_eq!(
            rule(&e.env_dir(&overlong).expect_err("refused")),
            Some("version_too_long")
        );
    }
}
