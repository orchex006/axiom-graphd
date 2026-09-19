//! Per-user state-root resolution and bootstrap (V2-006, CP-04).
//!
//! `graph-core::paths::AxiomHome::resolve` already owns the *lexical* policy:
//! `AXIOM_HOME` must be absolute, local and free of control characters, and the
//! Windows/Linux/macOS defaults come from `%LOCALAPPDATA%`, `XDG_STATE_HOME` (or
//! `$HOME/.local/state`) and `$HOME/Library/Application Support` respectively.
//!
//! What this module adds is everything that needs the real filesystem, through
//! one narrow injectable probe (CP-02):
//!
//! - the platform **default** is storage-class checked too, so a `%LOCALAPPDATA%`
//!   that points at a share or a cloud-sync folder fails as clearly as an
//!   `AXIOM_HOME` override does;
//! - the destination must be a real directory, never a symbolic link or reparse
//!   point (CP-03: bootstrap destinations reject symlink/reparse-point escapes);
//! - the resolved root is canonicalized once it exists, so the path recorded in
//!   state is the native resolved identity rather than the caller's spelling;
//! - bootstrap creation is private to the owner (`0700` on POSIX, created by the
//!   process that owns it), and the observation is recorded rather than assumed.
//!
//! A host that cannot observe ownership records that fact instead of claiming a
//! verified private root; `resolve_state_root` therefore reports what it actually
//! checked.

use std::path::{Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{classify_storage_lexically, AxiomHome, StorageClass};

/// Host facts needed to resolve the state home.
///
/// This is `graph-core`'s environment type: the policy is shared, so there is
/// exactly one definition of which variables feed resolution.
pub use graph_core::paths::PathEnvironment as StateEnvironment;
/// Platform vocabulary used by resolution.
pub use graph_core::paths::Platform as StatePlatform;

/// State-root resolution reports the shared typed error: an unsafe or relative
/// root is [`ErrorCode::UnsafeHomePath`], a missing platform fact or a
/// non-private root is [`ErrorCode::ConfigInvalid`].
pub type StateRootError = AxiomError;

/// Which authority produced the resolved root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateRootSource {
    /// The operator set `AXIOM_HOME`.
    Override,
    /// The root came from the platform default for the current OS.
    PlatformDefault,
}

impl StateRootSource {
    /// Stable name used in diagnostics and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Override => "override",
            Self::PlatformDefault => "platform-default",
        }
    }
}

/// What the native probe observed at the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryStatus {
    /// Nothing exists at the path yet.
    Missing,
    /// A real directory.
    Directory,
    /// Something exists but is not a directory (regular file, device, ...).
    NotADirectory,
    /// A symbolic link, junction or other name-surrogate reparse point.
    Link,
}

impl DirectoryStatus {
    /// Stable name used in diagnostics and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Directory => "directory",
            Self::NotADirectory => "not-a-directory",
            Self::Link => "link-or-reparse-point",
        }
    }
}

/// Native ownership/permission facts for the destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ownership {
    /// True when only the owner can read, write or traverse the directory.
    pub owner_only: bool,
    /// What the probe actually observed (for evidence, never a secret).
    pub detail: String,
}

/// The narrow native boundary state-root resolution needs.
///
/// Every method is observation or bootstrap of one caller-provided path; the
/// trait exists so the policy above it is testable without a privileged host.
pub trait StateRootProbe {
    /// Observe the destination without following links.
    fn status(&self, path: &Path) -> DirectoryStatus;

    /// Create the directory tree, private to the owner, bootstrapping the root.
    ///
    /// # Errors
    /// Returns a human-readable reason when the tree cannot be created.
    fn create_private_dir_all(&self, path: &Path) -> Result<(), String>;

    /// Observe ownership/permissions, or `None` when this host cannot.
    fn ownership(&self, path: &Path) -> Option<Ownership>;

    /// Resolve the path to its native identity, or `None` when it does not exist.
    fn canonicalize(&self, path: &Path) -> Option<PathBuf>;
}

/// The real host: `std::fs` plus the POSIX mode bits this crate may read.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeStateRootProbe;

impl StateRootProbe for NativeStateRootProbe {
    fn status(&self, path: &Path) -> DirectoryStatus {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => DirectoryStatus::Link,
            Ok(metadata) if metadata.is_dir() => DirectoryStatus::Directory,
            Ok(_) => DirectoryStatus::NotADirectory,
            Err(_) => DirectoryStatus::Missing,
        }
    }

    fn create_private_dir_all(&self, path: &Path) -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(path).map_err(|error| error.to_string())
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(path).map_err(|error| error.to_string())
        }
    }

    fn ownership(&self, path: &Path) -> Option<Ownership> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(path).ok()?;
            let mode = metadata.permissions().mode() & 0o777;
            Some(Ownership {
                owner_only: mode & 0o077 == 0,
                detail: format!("mode 0{mode:o}"),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            // Windows ACLs are not observable through `std::fs`; the adapter
            // records the gap instead of claiming a private root.
            None
        }
    }

    fn canonicalize(&self, path: &Path) -> Option<PathBuf> {
        std::fs::canonicalize(path).ok()
    }
}

/// A resolved state root, with the facts that were actually observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedStateRoot {
    root: PathBuf,
    source: StateRootSource,
    storage_class: StorageClass,
    status: DirectoryStatus,
    canonicalized: bool,
    bootstrap_created: bool,
    ownership: Option<Ownership>,
}

impl ResolvedStateRoot {
    /// The resolved state root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Which authority produced it.
    #[must_use]
    pub const fn source(&self) -> StateRootSource {
        self.source
    }

    /// The lexical storage class of the resolved root.
    #[must_use]
    pub const fn storage_class(&self) -> StorageClass {
        self.storage_class
    }

    /// What the probe observed at the destination.
    #[must_use]
    pub const fn status(&self) -> DirectoryStatus {
        self.status
    }

    /// True when the recorded root is the native canonical identity.
    #[must_use]
    pub const fn canonicalized(&self) -> bool {
        self.canonicalized
    }

    /// True when this resolution created the root (first-run bootstrap).
    #[must_use]
    pub const fn bootstrap_created(&self) -> bool {
        self.bootstrap_created
    }

    /// The observed ownership, or `None` when the host cannot observe it.
    #[must_use]
    pub fn ownership(&self) -> Option<&Ownership> {
        self.ownership.as_ref()
    }

    /// The standard state-home layout over this root.
    ///
    /// # Errors
    /// Returns [`ErrorCode::UnsafeHomePath`] only if the recorded root is no
    /// longer usable as a state home.
    pub fn home(&self) -> Result<AxiomHome, AxiomError> {
        let environment = StateEnvironment {
            axiom_home: Some(self.root.display().to_string()),
            ..StateEnvironment::default()
        };
        AxiomHome::resolve(&environment)
    }

    /// `<AXIOM_HOME>/instances/<instance>/solution.guard` (guard ABI section 1).
    ///
    /// # Errors
    /// Returns [`ErrorCode::ValidationError`] for a non-portable instance id.
    pub fn solution_guard_dir(&self, instance_id: &str) -> Result<PathBuf, AxiomError> {
        self.home()?.instance_guard(instance_id)
    }
}

fn refuse(reason: &str, detail_key: &str, detail_value: &str) -> AxiomError {
    AxiomError::new(ErrorCode::UnsafeHomePath, reason)
        .with_detail("config_key", "AXIOM_HOME")
        .with_detail(detail_key, detail_value)
}

fn check_destination(
    path: &Path,
    probe: &dyn StateRootProbe,
) -> Result<(DirectoryStatus, Option<Ownership>), AxiomError> {
    match probe.status(path) {
        DirectoryStatus::Directory => {}
        DirectoryStatus::Missing => {
            return Err(refuse(
                "AXIOM_HOME does not exist yet; create it with the bootstrap path",
                "actual",
                DirectoryStatus::Missing.as_str(),
            ));
        }
        DirectoryStatus::NotADirectory => {
            return Err(refuse(
                "AXIOM_HOME exists but is not a directory",
                "actual",
                DirectoryStatus::NotADirectory.as_str(),
            ));
        }
        DirectoryStatus::Link => {
            return Err(refuse(
                "AXIOM_HOME must not be a symbolic link or reparse point",
                "actual",
                DirectoryStatus::Link.as_str(),
            ));
        }
    }
    let ownership = probe.ownership(path);
    if let Some(observed) = &ownership {
        if !observed.owner_only {
            return Err(AxiomError::new(
                ErrorCode::ConfigInvalid,
                "AXIOM_HOME is not private to its owner; mutable state must not be shared",
            )
            .with_detail("config_key", "AXIOM_HOME")
            .with_detail("actual", observed.detail.clone()));
        }
    }
    Ok((DirectoryStatus::Directory, ownership))
}

/// Resolve the state root and verify the destination without creating anything.
///
/// The returned path is the canonical native identity when the destination
/// exists and the host can canonicalize it.
///
/// # Errors
/// - [`ErrorCode::UnsafeHomePath`] for a relative, remote, cloud-synchronised,
///   device or link destination, and for a root that resolves to the filesystem
///   root.
/// - [`ErrorCode::ConfigInvalid`] when the required platform fact is missing or
///   the destination is not private to its owner.
pub fn resolve_state_root(
    environment: &StateEnvironment,
    probe: &dyn StateRootProbe,
) -> Result<ResolvedStateRoot, AxiomError> {
    let source = match environment.axiom_home.as_deref() {
        Some(value) if !value.trim().is_empty() => StateRootSource::Override,
        _ => StateRootSource::PlatformDefault,
    };
    let lexical = AxiomHome::resolve(environment)?;
    // The override branch already refused unsafe storage; the platform default
    // has not been classified yet, so a `%LOCALAPPDATA%` on a share fails here.
    let storage_class = classify_storage_lexically(&lexical.root().display().to_string());
    if storage_class.is_unsafe_for_mutable_state() {
        return Err(refuse(
            "AXIOM_HOME must not be shared, remote or cloud-synchronised storage",
            "storage_class",
            storage_class.as_str(),
        ));
    }

    let (root, canonicalized) = match probe.canonicalize(lexical.root()) {
        Some(canonical) => (canonical, true),
        None => (lexical.root().to_path_buf(), false),
    };
    let (status, ownership) = check_destination(&root, probe)?;
    Ok(ResolvedStateRoot {
        root,
        source,
        storage_class,
        status,
        canonicalized,
        bootstrap_created: false,
        ownership,
    })
}

/// Resolve the state root, bootstrapping it when it does not exist yet.
///
/// Creation is the native oracle for CP-04: a root that appears only after
/// `create_private_dir_all` must still be a real, owner-private directory, and a
/// link or a non-directory is refused after creation just as before it.
///
/// # Errors
/// Adds to [`resolve_state_root`] a serde-free [`ErrorCode::UnsafeHomePath`] when
/// bootstrap cannot create a real directory, or [`ErrorCode::ConfigInvalid`] when
/// the created root is not private to its owner.
pub fn ensure_state_root(
    environment: &StateEnvironment,
    probe: &dyn StateRootProbe,
) -> Result<ResolvedStateRoot, AxiomError> {
    // Resolve lexically first: an unsafe or relative override must fail before
    // anything is created.
    let preliminary = match resolve_state_root(environment, probe) {
        Ok(resolved) => return Ok(resolved),
        Err(error) => error,
    };
    if preliminary.code() != ErrorCode::UnsafeHomePath
        || preliminary.details().get("actual").map(String::as_str)
            != Some(DirectoryStatus::Missing.as_str())
    {
        return Err(preliminary);
    }

    let lexical = AxiomHome::resolve(environment)?;
    if let Err(reason) = probe.create_private_dir_all(lexical.root()) {
        return Err(refuse("AXIOM_HOME could not be created", "actual", &reason));
    }
    let mut resolved = resolve_state_root(environment, probe)?;
    if resolved.status != DirectoryStatus::Directory {
        return Err(refuse(
            "AXIOM_HOME bootstrap did not produce a real directory",
            "actual",
            resolved.status.as_str(),
        ));
    }
    resolved.bootstrap_created = true;
    Ok(resolved)
}
