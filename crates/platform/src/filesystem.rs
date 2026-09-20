//! Native filesystem boundaries for staged replacement (V2-015, CP-03).
//!
//! A staged write is only safe when every native boundary around it was checked
//! rather than assumed:
//!
//! * a **link** (symbolic link or Windows junction) must not carry the write out
//!   of the bound project root, and a link whose target cannot be resolved must
//!   not be treated as if it had none;
//! * the staging area must be on the **same filesystem** as the destination, or
//!   the replacement is a copy across devices instead of an atomic rename;
//! * a **long path** must be refused rather than silently truncated to the
//!   native limit;
//! * a destination another process holds **open** must produce a conflict, not a
//!   half-written file;
//! * the staged bytes must be **byte-identical** to the source, so a CRLF file
//!   is not silently rewritten to LF (or the reverse) on a platform that
//!   normalizes line endings.
//!
//! Every native observation goes through [`FilesystemProbe`], so the policy is
//! exercised for real on any host (CP-02). The native Windows/macOS legs - real
//! junctions, drive-type classification, open-handle enumeration and long-path
//! opt-in - cannot be observed from `std` and are recorded as unverified instead
//! of being claimed.

use std::path::Path;

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::validate_portable_relative_path;

/// Native path limit in code units when long-path support is not in effect.
///
/// On Windows this is `MAX_PATH`; the limit is enforced with a refusal, never a
/// silent truncation.
pub const MAX_NATIVE_PATH_UNITS: usize = 260;

/// Flavour of a link that redirects a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymlinkKind {
    /// A symbolic link.
    Symlink,
    /// A Windows directory junction (or another name-surrogate reparse point).
    Junction,
}

impl SymlinkKind {
    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Symlink => "symlink",
            Self::Junction => "junction",
        }
    }
}

/// The storage class of one path, as far as the host could observe it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageLocation {
    /// A local, writable volume, identified by its native device number.
    Local {
        /// Native device identifier used to test "same filesystem".
        volume_id: u64,
    },
    /// A network share or cloud-synced location.
    Network,
    /// A read-only location.
    ReadOnly,
    /// The host could not classify the location.
    Unknown,
}

impl StorageLocation {
    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local { .. } => "local",
            Self::Network => "network",
            Self::ReadOnly => "read-only",
            Self::Unknown => "unknown",
        }
    }

    /// Whether the location is a local volume.
    #[must_use]
    pub const fn is_local(self) -> bool {
        matches!(self, Self::Local { .. })
    }

    /// The native device identifier, when the location is a local volume.
    #[must_use]
    pub const fn volume_id(self) -> Option<u64> {
        match self {
            Self::Local { volume_id } => Some(volume_id),
            Self::Network | Self::ReadOnly | Self::Unknown => None,
        }
    }
}

/// Native facts observed about one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryFacts {
    link: Option<SymlinkKind>,
    resolved_target: Option<String>,
    open_handles: Option<u32>,
    storage: StorageLocation,
}

impl EntryFacts {
    /// Facts for a regular file or directory.
    #[must_use]
    pub const fn regular(storage: StorageLocation) -> Self {
        Self {
            link: None,
            resolved_target: None,
            open_handles: None,
            storage,
        }
    }

    /// Facts for a link, with its resolved target when resolution succeeded.
    #[must_use]
    pub fn link(
        kind: SymlinkKind,
        resolved_target: Option<String>,
        storage: StorageLocation,
    ) -> Self {
        Self {
            link: Some(kind),
            resolved_target,
            open_handles: None,
            storage,
        }
    }

    /// Record the number of open handles the host observed.
    #[must_use]
    pub const fn with_open_handles(mut self, handles: u32) -> Self {
        self.open_handles = Some(handles);
        self
    }

    /// Link flavour, when the path is a link.
    #[must_use]
    pub const fn link_kind(&self) -> Option<SymlinkKind> {
        self.link
    }

    /// Resolved absolute target of the link, when one was observed.
    #[must_use]
    pub fn resolved_target(&self) -> Option<&str> {
        self.resolved_target.as_deref()
    }

    /// Open handles observed on the path, or `None` when the host cannot count
    /// them.
    #[must_use]
    pub const fn open_handles(&self) -> Option<u32> {
        self.open_handles
    }

    /// Storage class the path lives on.
    #[must_use]
    pub const fn storage(&self) -> StorageLocation {
        self.storage
    }
}

/// The narrow native boundary this module needs.
pub trait FilesystemProbe {
    /// Observe `path` without following links.
    ///
    /// # Errors
    /// [`ErrorCode::NotFound`] when the path does not exist.
    fn entry_facts(&self, path: &Path) -> Result<EntryFacts, AxiomError>;

    /// Classify the storage `path` lives on.
    fn storage_location(&self, path: &Path) -> StorageLocation;

    /// Native path limit in code units, or `None` when the platform has none.
    fn max_path_units(&self) -> Option<usize>;

    /// Length of `path` in native code units.
    fn path_units(&self, path: &Path) -> usize;

    /// Whether long-path support is in effect for this specific path.
    fn long_paths_enabled(&self, path: &Path) -> bool;
}

/// The real host: `std::fs`, with the gaps recorded rather than guessed.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeFilesystemProbe;

impl FilesystemProbe for NativeFilesystemProbe {
    fn entry_facts(&self, path: &Path) -> Result<EntryFacts, AxiomError> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            AxiomError::new(
                ErrorCode::NotFound,
                format!("the path could not be observed: {error}"),
            )
            .with_detail("path", path.display().to_string())
        })?;
        let storage = self.storage_location(path);
        if !metadata.file_type().is_symlink() {
            return Ok(EntryFacts::regular(storage));
        }
        // A junction and a symbolic link are both name surrogates; `std` exposes
        // the fact that the entry redirects but not which reparse tag it uses,
        // so the flavour that can be observed on every platform is reported.
        let kind = SymlinkKind::Symlink;
        let resolved = std::fs::canonicalize(path)
            .ok()
            .map(|target| target.display().to_string());
        Ok(EntryFacts::link(kind, resolved, storage))
    }

    fn storage_location(&self, path: &Path) -> StorageLocation {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            match std::fs::metadata(path) {
                Ok(metadata) => StorageLocation::Local {
                    volume_id: metadata.dev(),
                },
                Err(_) => StorageLocation::Unknown,
            }
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            // Drive type (`GetDriveTypeW`) and remote-filesystem detection are
            // not available through `std`; the adapter records the gap instead
            // of claiming a local volume.
            StorageLocation::Unknown
        }
    }

    fn max_path_units(&self) -> Option<usize> {
        if cfg!(windows) {
            Some(MAX_NATIVE_PATH_UNITS)
        } else {
            None
        }
    }

    fn path_units(&self, path: &Path) -> usize {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            path.as_os_str().encode_wide().count()
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::ffi::OsStrExt;
            path.as_os_str().as_bytes().len()
        }
    }

    fn long_paths_enabled(&self, path: &Path) -> bool {
        if !cfg!(windows) {
            return true;
        }
        // The verbatim (`\\?\`) forms bypass the legacy limit, so a path already
        // spelled that way is not subject to it.
        let spelling = path.to_string_lossy();
        spelling.starts_with(r"\\?\")
    }
}

/// Whether an absolute local path is the root itself or lives under it.
#[must_use]
pub fn is_within_root(root: &str, candidate: &str) -> bool {
    let root = root.replace('\\', "/");
    let candidate = candidate.replace('\\', "/");
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return false;
    }
    let equals = |lhs: &str, rhs: &str| {
        if cfg!(windows) {
            lhs.eq_ignore_ascii_case(rhs)
        } else {
            lhs == rhs
        }
    };
    if candidate.len() <= root.len() {
        return equals(&candidate, root);
    }
    let (prefix, rest) = candidate.split_at(root.len());
    equals(prefix, root) && rest.starts_with('/')
}

/// Outcome of the open-handle check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandleCheck {
    /// No conflicting handle was observed; the replacement may proceed.
    Clear,
    /// The host cannot enumerate open handles, so the native atomic rename is
    /// what prevents a corrupt result if a handle exists.
    Unobservable,
}

impl HandleCheck {
    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Unobservable => "unobservable",
        }
    }
}

/// Line-ending class of a byte sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LineEndings {
    /// No line terminator was present.
    None,
    /// Only bare LF terminators.
    Lf,
    /// Only CRLF terminators.
    CrLf,
    /// Only bare CR terminators.
    Cr,
    /// More than one class is present, which a rewrite hazard hides behind.
    Mixed,
}

impl LineEndings {
    /// Classify `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut crlf = 0usize;
        let mut lone_lf = 0usize;
        let mut lone_cr = 0usize;
        let mut index = 0usize;
        while index < bytes.len() {
            match bytes[index] {
                b'\r' if bytes.get(index + 1) == Some(&b'\n') => {
                    crlf += 1;
                    index += 2;
                }
                b'\r' => {
                    lone_cr += 1;
                    index += 1;
                }
                b'\n' => {
                    lone_lf += 1;
                    index += 1;
                }
                _ => index += 1,
            }
        }
        match (crlf > 0, lone_lf > 0, lone_cr > 0) {
            (false, false, false) => Self::None,
            (true, false, false) => Self::CrLf,
            (false, true, false) => Self::Lf,
            (false, false, true) => Self::Cr,
            _ => Self::Mixed,
        }
    }

    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Lf => "lf",
            Self::CrLf => "crlf",
            Self::Cr => "cr",
            Self::Mixed => "mixed",
        }
    }

    /// Whether a staged byte sequence keeps this class exactly.
    #[must_use]
    pub const fn is_preserved_by(self, staged: Self) -> bool {
        matches!(
            (self, staged),
            (Self::None, Self::None)
                | (Self::Lf, Self::Lf)
                | (Self::CrLf, Self::CrLf)
                | (Self::Cr, Self::Cr)
                | (Self::Mixed, Self::Mixed)
        )
    }
}

/// Whether the staged bytes are exactly the source bytes.
#[must_use]
pub fn preserves_bytes(source: &[u8], staged: &[u8]) -> bool {
    source == staged
}

/// Refuse a path that redirects out of the bound project root through a link.
///
/// # Errors
/// * [`ErrorCode::UnsafePortablePath`] when `path` is not a canonical portable
///   relative path (the shared `validate_portable_relative_path` policy).
/// * [`ErrorCode::NotReady`] when the path is a link whose target could not be
///   resolved, because its identity is then unknown rather than harmless.
/// * [`ErrorCode::UnsafePortablePath`] when the resolved target leaves `root`.
pub fn check_link_boundary(root: &str, path: &str, facts: &EntryFacts) -> Result<(), AxiomError> {
    validate_portable_relative_path(path)?;
    let Some(kind) = facts.link_kind() else {
        return Ok(());
    };
    match facts.resolved_target() {
        None => Err(AxiomError::new(
            ErrorCode::NotReady,
            "a link target could not be resolved, so the path identity is unknown",
        )
        .with_detail("portable_path", path)
        .with_detail("link_kind", kind.as_str())
        .with_detail("root", root)),
        Some(target) => {
            if is_within_root(root, target) {
                Ok(())
            } else {
                Err(AxiomError::new(
                    ErrorCode::UnsafePortablePath,
                    "a link target leaves the bound project root",
                )
                .with_detail("portable_path", path)
                .with_detail("link_kind", kind.as_str())
                .with_detail("target", target)
                .with_detail("root", root))
            }
        }
    }
}

/// Require that staging and destination are the same local filesystem.
///
/// A cross-device replacement is a copy, not an atomic rename, so it is refused
/// instead of performed. An unclassifiable location is refused too: "fail
/// safely" means refuse, not assume.
///
/// # Errors
/// [`ErrorCode::IncompatibleInput`] when either side is not a local volume or the
/// two sides are different volumes.
pub fn check_same_filesystem_staging(
    source: StorageLocation,
    destination: StorageLocation,
) -> Result<(), AxiomError> {
    let refused = |rule: &str| {
        AxiomError::new(
            ErrorCode::IncompatibleInput,
            "the staging area is not on the destination filesystem",
        )
        .with_detail("rule", rule)
        .with_detail("source", source.as_str())
        .with_detail("destination", destination.as_str())
    };
    match (source, destination) {
        (
            StorageLocation::Local { volume_id: left },
            StorageLocation::Local { volume_id: right },
        ) => {
            if left == right {
                Ok(())
            } else {
                Err(refused("same-volume"))
            }
        }
        (StorageLocation::Network, _) | (_, StorageLocation::Network) => {
            Err(refused("local-volume"))
        }
        (StorageLocation::ReadOnly, _) | (_, StorageLocation::ReadOnly) => {
            Err(refused("writable-volume"))
        }
        _ => Err(refused("classifiable-volume")),
    }
}

/// Refuse a path that exceeds the native limit without long-path support.
///
/// Returns the observed length in native code units, or `None` when the platform
/// imposes no limit.
///
/// # Errors
/// [`ErrorCode::ValidationError`] when the path is longer than the native limit
/// and long-path support is not in effect for it.
pub fn check_path_length(
    path: &Path,
    probe: &dyn FilesystemProbe,
) -> Result<Option<usize>, AxiomError> {
    let Some(max) = probe.max_path_units() else {
        return Ok(None);
    };
    let units = probe.path_units(path);
    if units <= max || probe.long_paths_enabled(path) {
        return Ok(Some(units));
    }
    Err(AxiomError::new(
        ErrorCode::ValidationError,
        "the path exceeds the native path limit",
    )
    .with_detail("path", path.display().to_string())
    .with_detail("units", units.to_string())
    .with_detail("limit", max.to_string()))
}

/// Refuse a replacement while another process holds the destination open.
///
/// # Errors
/// [`ErrorCode::Conflict`] when an open handle was observed: a conflict the
/// caller may retry, never a half-written file.
pub fn check_open_handle_replacement(facts: &EntryFacts) -> Result<HandleCheck, AxiomError> {
    match facts.open_handles() {
        None => Ok(HandleCheck::Unobservable),
        Some(0) => Ok(HandleCheck::Clear),
        Some(handles) => Err(AxiomError::new(
            ErrorCode::Conflict,
            "the destination is held open by another process",
        )
        .with_detail("open_handles", handles.to_string())),
    }
}

/// Refuse a staged byte sequence that is not exactly the source bytes.
///
/// Returns the source's line-ending class when the bytes are preserved.
///
/// # Errors
/// [`ErrorCode::ValidationError`] when the bytes differ. The error names both
/// line-ending classes, because a silent CRLF/LF rewrite is the usual cause.
pub fn check_staged_bytes(source: &[u8], staged: &[u8]) -> Result<LineEndings, AxiomError> {
    let endings = LineEndings::of(source);
    if preserves_bytes(source, staged) {
        return Ok(endings);
    }
    Err(AxiomError::new(
        ErrorCode::ValidationError,
        "the staged bytes differ from the source bytes",
    )
    .with_detail("source_len", source.len().to_string())
    .with_detail("staged_len", staged.len().to_string())
    .with_detail("source_line_endings", endings.as_str())
    .with_detail("staged_line_endings", LineEndings::of(staged).as_str()))
}

/// One staged replacement to check.
#[derive(Debug, Clone, Copy)]
pub struct ReplacementRequest<'a> {
    source_path: &'a Path,
    destination_path: &'a Path,
    destination_root: &'a str,
    portable_path: &'a str,
    source_bytes: &'a [u8],
    staged_bytes: &'a [u8],
}

impl<'a> ReplacementRequest<'a> {
    /// A replacement of `destination_path` - spelled `portable_path` relative to
    /// `destination_root` - whose staged bytes must equal `source_bytes`.
    #[must_use]
    pub const fn new(
        source_path: &'a Path,
        destination_path: &'a Path,
        destination_root: &'a str,
        portable_path: &'a str,
        source_bytes: &'a [u8],
        staged_bytes: &'a [u8],
    ) -> Self {
        Self {
            source_path,
            destination_path,
            destination_root,
            portable_path,
            source_bytes,
            staged_bytes,
        }
    }

    /// Where the bytes come from.
    #[must_use]
    pub const fn source_path(&self) -> &'a Path {
        self.source_path
    }

    /// The file being replaced.
    #[must_use]
    pub const fn destination_path(&self) -> &'a Path {
        self.destination_path
    }

    /// Absolute root the destination must stay inside.
    #[must_use]
    pub const fn destination_root(&self) -> &'a str {
        self.destination_root
    }

    /// Portable relative spelling of the destination.
    #[must_use]
    pub const fn portable_path(&self) -> &'a str {
        self.portable_path
    }

    /// Bytes the file currently contains.
    #[must_use]
    pub const fn source_bytes(&self) -> &'a [u8] {
        self.source_bytes
    }

    /// Bytes that would be written.
    #[must_use]
    pub const fn staged_bytes(&self) -> &'a [u8] {
        self.staged_bytes
    }
}

/// The native boundaries that were actually checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplacementApproval {
    line_endings: LineEndings,
    path_units: Option<usize>,
    source_storage: StorageLocation,
    destination_storage: StorageLocation,
    handles: HandleCheck,
    link: Option<SymlinkKind>,
}

impl ReplacementApproval {
    /// Line-ending class of the preserved bytes.
    #[must_use]
    pub const fn line_endings(&self) -> LineEndings {
        self.line_endings
    }

    /// Destination length in native code units, or `None` when unlimited.
    #[must_use]
    pub const fn path_units(&self) -> Option<usize> {
        self.path_units
    }

    /// Storage class of the source.
    #[must_use]
    pub const fn source_storage(&self) -> StorageLocation {
        self.source_storage
    }

    /// Storage class of the destination.
    #[must_use]
    pub const fn destination_storage(&self) -> StorageLocation {
        self.destination_storage
    }

    /// What the open-handle check could observe.
    #[must_use]
    pub const fn handles(&self) -> HandleCheck {
        self.handles
    }

    /// Link flavour of the destination, when it is a link.
    #[must_use]
    pub const fn link(&self) -> Option<SymlinkKind> {
        self.link
    }

    /// Whether source and destination share one local volume.
    #[must_use]
    pub fn is_same_volume(&self) -> bool {
        match (
            self.source_storage.volume_id(),
            self.destination_storage.volume_id(),
        ) {
            (Some(left), Some(right)) => left == right,
            _ => false,
        }
    }
}

/// Check every native boundary of one staged replacement.
///
/// # Errors
/// The typed error of the first boundary that refused the replacement: an
/// escaping link, a long path, an unobservable identity, an open handle, a
/// byte-level difference or a cross-filesystem staging area.
pub fn check_replacement(
    request: &ReplacementRequest<'_>,
    probe: &dyn FilesystemProbe,
) -> Result<ReplacementApproval, AxiomError> {
    let facts = probe.entry_facts(request.destination_path())?;
    check_link_boundary(request.destination_root(), request.portable_path(), &facts)?;
    let handles = check_open_handle_replacement(&facts)?;
    let line_endings = check_staged_bytes(request.source_bytes(), request.staged_bytes())?;
    let path_units = check_path_length(request.destination_path(), probe)?;
    let source_storage = probe.storage_location(request.source_path());
    let destination_storage = facts.storage();
    check_same_filesystem_staging(source_storage, destination_storage)?;
    Ok(ReplacementApproval {
        line_endings,
        path_units,
        source_storage,
        destination_storage,
        handles,
        link: facts.link_kind(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        check_link_boundary, check_open_handle_replacement, check_path_length, check_replacement,
        check_same_filesystem_staging, check_staged_bytes, is_within_root, preserves_bytes,
        EntryFacts, FilesystemProbe, HandleCheck, LineEndings, ReplacementRequest, StorageLocation,
        SymlinkKind,
    };
    use graph_core::error::{AxiomError, ErrorCode};
    use std::path::Path;

    const ROOT: &str = "D:/repo/Project";

    #[derive(Debug)]
    struct Probe {
        facts: EntryFacts,
        source_storage: StorageLocation,
        max_units: Option<usize>,
        units: usize,
        long_paths: bool,
    }

    impl Probe {
        fn of(facts: EntryFacts) -> Self {
            Self {
                facts,
                source_storage: StorageLocation::Local { volume_id: 1 },
                max_units: None,
                units: 0,
                long_paths: true,
            }
        }

        fn with_length(mut self, max: usize, units: usize, long_paths: bool) -> Self {
            self.max_units = Some(max);
            self.units = units;
            self.long_paths = long_paths;
            self
        }

        fn with_source_storage(mut self, storage: StorageLocation) -> Self {
            self.source_storage = storage;
            self
        }
    }

    impl FilesystemProbe for Probe {
        fn entry_facts(&self, _path: &Path) -> Result<EntryFacts, AxiomError> {
            Ok(self.facts.clone())
        }

        fn storage_location(&self, _path: &Path) -> StorageLocation {
            self.source_storage
        }

        fn max_path_units(&self) -> Option<usize> {
            self.max_units
        }

        fn path_units(&self, _path: &Path) -> usize {
            self.units
        }

        fn long_paths_enabled(&self, _path: &Path) -> bool {
            self.long_paths
        }
    }

    fn local(volume_id: u64) -> StorageLocation {
        StorageLocation::Local { volume_id }
    }

    fn error_code(result: Result<(), AxiomError>) -> ErrorCode {
        result.expect_err("the boundary must refuse").code()
    }

    #[test]
    fn link_escapes_and_unresolved_targets_are_refused_while_inside_targets_are_allowed() {
        let escaping = EntryFacts::link(
            SymlinkKind::Symlink,
            Some("D:/other/secret.cs".to_string()),
            local(1),
        );
        assert_eq!(
            error_code(check_link_boundary(ROOT, "src/link.cs", &escaping)),
            ErrorCode::UnsafePortablePath
        );

        let junction = EntryFacts::link(
            SymlinkKind::Junction,
            Some("D:/repo/Project-other/x.cs".to_string()),
            local(1),
        );
        assert_eq!(
            error_code(check_link_boundary(ROOT, "src/link.cs", &junction)),
            ErrorCode::UnsafePortablePath,
            "a sibling with a shared prefix is still outside the root"
        );

        let inside = EntryFacts::link(
            SymlinkKind::Junction,
            Some("D:/repo/Project/src/real.cs".to_string()),
            local(1),
        );
        assert_eq!(check_link_boundary(ROOT, "src/link.cs", &inside), Ok(()));

        let unresolved = EntryFacts::link(SymlinkKind::Symlink, None, local(1));
        assert_eq!(
            error_code(check_link_boundary(ROOT, "src/link.cs", &unresolved)),
            ErrorCode::NotReady
        );

        let regular = EntryFacts::regular(local(1));
        assert_eq!(check_link_boundary(ROOT, "src/App.cs", &regular), Ok(()));

        assert_eq!(
            error_code(check_link_boundary(ROOT, "C:/outside/App.cs", &regular)),
            ErrorCode::UnsafePortablePath,
            "a boundary check still refuses a non-portable spelling"
        );

        assert!(is_within_root(ROOT, "D:/repo/Project/src/App.cs"));
        assert!(is_within_root(ROOT, "D:/repo/Project"));
        assert!(!is_within_root(ROOT, "D:/repo/Project-other/App.cs"));
        assert!(!is_within_root("", "D:/repo/Project/src/App.cs"));
    }

    #[test]
    fn staging_must_share_the_destination_volume_and_refuse_what_it_cannot_classify() {
        assert_eq!(check_same_filesystem_staging(local(7), local(7)), Ok(()));
        assert_eq!(
            error_code(check_same_filesystem_staging(local(7), local(8))),
            ErrorCode::IncompatibleInput
        );
        assert_eq!(
            error_code(check_same_filesystem_staging(
                StorageLocation::Network,
                local(7)
            )),
            ErrorCode::IncompatibleInput
        );
        assert_eq!(
            error_code(check_same_filesystem_staging(
                local(7),
                StorageLocation::ReadOnly
            )),
            ErrorCode::IncompatibleInput
        );
        assert_eq!(
            error_code(check_same_filesystem_staging(
                local(7),
                StorageLocation::Unknown
            )),
            ErrorCode::IncompatibleInput,
            "an unclassifiable destination is refused rather than assumed usable"
        );
        assert!(StorageLocation::Network.volume_id().is_none());
        assert!(local(7).is_local());
    }

    #[test]
    fn a_long_path_is_refused_unless_long_path_support_is_in_effect() {
        let path = Path::new("D:/repo/Project/src/App.cs");
        let limited = Probe::of(EntryFacts::regular(local(1))).with_length(260, 300, false);
        assert_eq!(
            error_code(check_path_length(path, &limited).map(|_| ())),
            ErrorCode::ValidationError
        );

        let verbatim = Probe::of(EntryFacts::regular(local(1))).with_length(260, 300, true);
        assert_eq!(check_path_length(path, &verbatim), Ok(Some(300)));

        let unlimited = Probe::of(EntryFacts::regular(local(1)));
        assert_eq!(check_path_length(path, &unlimited), Ok(None));
    }

    #[test]
    fn an_open_handle_is_a_retryable_conflict_and_an_unobservable_host_says_so() {
        let clear = EntryFacts::regular(local(1)).with_open_handles(0);
        assert_eq!(
            check_open_handle_replacement(&clear),
            Ok(HandleCheck::Clear)
        );

        let held = EntryFacts::regular(local(1)).with_open_handles(3);
        assert_eq!(
            error_code(check_open_handle_replacement(&held).map(|_| ())),
            ErrorCode::Conflict
        );

        let silent = EntryFacts::regular(local(1));
        assert_eq!(
            check_open_handle_replacement(&silent),
            Ok(HandleCheck::Unobservable)
        );
        assert_eq!(HandleCheck::Unobservable.as_str(), "unobservable");
    }

    #[test]
    fn crlf_bytes_are_preserved_exactly_and_a_normalizing_rewrite_is_refused() {
        let crlf: &[u8] = b"alpha\r\nbeta\r\n";
        let lf: &[u8] = b"alpha\nbeta\n";
        assert!(preserves_bytes(crlf, crlf));
        assert!(!preserves_bytes(crlf, lf));
        assert_eq!(check_staged_bytes(crlf, crlf), Ok(LineEndings::CrLf));
        assert_eq!(
            error_code(check_staged_bytes(crlf, lf).map(|_| ())),
            ErrorCode::ValidationError,
            "a silent CRLF-to-LF rewrite is refused"
        );
        assert_eq!(
            error_code(check_staged_bytes(lf, crlf).map(|_| ())),
            ErrorCode::ValidationError
        );

        assert_eq!(LineEndings::of(b""), LineEndings::None);
        assert_eq!(LineEndings::of(b"one line"), LineEndings::None);
        assert_eq!(LineEndings::of(lf), LineEndings::Lf);
        assert_eq!(LineEndings::of(crlf), LineEndings::CrLf);
        assert_eq!(LineEndings::of(b"a\rb\r"), LineEndings::Cr);
        assert_eq!(LineEndings::of(b"a\r\nb\n"), LineEndings::Mixed);
        assert_eq!(LineEndings::of(b"a\rb\n"), LineEndings::Mixed);
        assert!(LineEndings::CrLf.is_preserved_by(LineEndings::CrLf));
        assert!(!LineEndings::CrLf.is_preserved_by(LineEndings::Lf));
        assert_eq!(LineEndings::Mixed.as_str(), "mixed");
    }

    #[test]
    fn a_whole_replacement_is_approved_or_refused_by_its_first_native_boundary() {
        let path = Path::new("D:/repo/Project/src/App.cs");
        let bytes: &[u8] = b"line\r\n";
        let request = || ReplacementRequest::new(path, path, ROOT, "src/App.cs", bytes, bytes);

        let approved = Probe::of(EntryFacts::regular(local(4))).with_source_storage(local(4));
        let approval = check_replacement(&request(), &approved).expect("approved");
        assert_eq!(approval.line_endings(), LineEndings::CrLf);
        assert_eq!(approval.handles(), HandleCheck::Unobservable);
        assert_eq!(approval.link(), None);
        assert!(approval.is_same_volume());
        assert_eq!(approval.path_units(), None);

        let cross_device = Probe::of(EntryFacts::regular(local(9))).with_source_storage(local(4));
        assert_eq!(
            error_code(check_replacement(&request(), &cross_device).map(|_| ())),
            ErrorCode::IncompatibleInput
        );

        let escaping = Probe::of(EntryFacts::link(
            SymlinkKind::Symlink,
            Some("D:/other/App.cs".to_string()),
            local(4),
        ));
        assert_eq!(
            error_code(check_replacement(&request(), &escaping).map(|_| ())),
            ErrorCode::UnsafePortablePath
        );
    }

    /// The Linux legs are real: a real file, real CRLF bytes and a real symlink.
    ///
    /// The Windows/macOS legs of this card - a real junction, drive-type
    /// classification, open-handle enumeration and long-path opt-in - cannot be
    /// observed from `std` on this host and are recorded as unverified.
    #[cfg(unix)]
    #[test]
    fn the_native_probe_observes_a_real_file_and_a_real_symlink() {
        use super::NativeFilesystemProbe;
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temp dir");
        let root = directory.path();
        let source = root.join("App.cs");
        let bytes: &[u8] = b"alpha\r\nbeta\r\n";
        std::fs::write(&source, bytes).expect("write");

        let probe = NativeFilesystemProbe;
        let facts = probe.entry_facts(&source).expect("observed");
        assert_eq!(facts.link_kind(), None);
        assert!(
            facts.storage().is_local(),
            "a real local file must be classified local: {:?}",
            facts.storage()
        );
        assert!(probe.max_path_units().is_none(), "POSIX has no path limit");
        assert_eq!(
            probe.path_units(&source),
            source.as_os_str().len(),
            "bytes are the native code unit on POSIX"
        );

        let root_spelling = root.display().to_string().replace('\\', "/");
        let request =
            ReplacementRequest::new(&source, &source, &root_spelling, "src/App.cs", bytes, bytes);
        let approval = check_replacement(&request, &probe).expect("a real replacement is approved");
        assert_eq!(approval.line_endings(), LineEndings::CrLf);
        assert!(approval.is_same_volume());

        let normalized: &[u8] = b"alpha\nbeta\n";
        let rewritten = ReplacementRequest::new(
            &source,
            &source,
            &root_spelling,
            "src/App.cs",
            bytes,
            normalized,
        );
        assert_eq!(
            error_code(check_replacement(&rewritten, &probe).map(|_| ())),
            ErrorCode::ValidationError
        );

        let link = root.join("Link.cs");
        symlink(&source, &link).expect("symlink");
        let link_facts = probe.entry_facts(&link).expect("observed");
        assert_eq!(link_facts.link_kind(), Some(SymlinkKind::Symlink));
        let target = link_facts.resolved_target().expect("resolved");
        assert!(
            super::is_within_root(&root_spelling, target),
            "a link to a file inside the root must resolve inside it: {target}"
        );
        assert_eq!(
            check_link_boundary(&root_spelling, "src/Link.cs", &link_facts),
            Ok(())
        );
    }
}
