//! Before-hash verification and the per-repository apply lock (task E-019).
//!
//! Approving a plan is not the same as still being allowed to apply it. The
//! operations guide fixes the order an apply must follow: take the
//! per-repository bootstrap lock, then re-check the before-hashes, and only then
//! write. This module owns the first two steps so [`super::apply`] can start at
//! "back up the affected bytes".
//!
//! Two properties make the step trustworthy:
//!
//! * **A changed target invalidates a stale plan.** [`verify_repository`]
//!   re-reads every file the plan would write and compares its current SHA-256
//!   with the `before_sha256` the plan recorded, and it recomputes the managed
//!   block from the current `AGENTS.md` and compares that with
//!   [`RepositoryPlan::before_block_sha256`]. The block check catches an edit
//!   even for a plan that writes nothing (an `unchanged` repository), so an
//!   approved plan can never overwrite a human edit made after approval. A
//!   mismatch is refused with the stable rule [`RULE_PLAN_STALE`] before any
//!   write.
//!
//! * **Cooperating applies cannot interleave.** [`ApplyLock::acquire`] creates
//!   one lock file per repository under `AXIOM_HOME` with an exclusive
//!   create-only write, so two processes racing for the same repository resolve
//!   to exactly one winner and the loser is refused with the stable rule
//!   [`RULE_LOCK_HELD`]. The lock records its holder and is removed only while
//!   it still records the token this holder wrote, so a cooperating process
//!   never deletes a lock it did not take.
//!
//! The policy half is host-free: [`PreconditionHost`] is the only place a
//! filesystem is touched, and the in-memory double lets every refusal be tested
//! without a disk.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use graph_core::error::{AxiomError, ErrorCode};
use graph_export::sha256_hex;

use super::markers;
use super::plan::{RepositoryPlan, RepositoryReader, AGENTS_PATH};
use super::refuse;
use super::text::SourceText;

/// Stable rule code: the repository changed since the plan was approved.
pub const RULE_PLAN_STALE: &str = "plan-stale";

/// Stable rule code: the bound repository root is no longer a directory.
pub const RULE_PLAN_ROOT: &str = "precondition-root";

/// Stable rule code: this repository already has a plan bootstrap refuses.
pub const RULE_PLAN_CONFLICT: &str = "plan-repository-conflict";

/// Stable rule code: another cooperating apply holds this repository's lock.
pub const RULE_LOCK_HELD: &str = "apply-lock-held";

/// Stable rule code: a repository identifier would escape the lock directory.
pub const RULE_LOCK_ID: &str = "apply-lock-id-unsafe";

/// Stable rule code: the lock file could not be created, read or removed.
pub const RULE_LOCK_IO: &str = "apply-lock-io";

/// Directory under `AXIOM_HOME` that holds the per-repository apply locks.
pub const LOCK_DIR: &str = "bootstrap-locks";

/// Extension of a lock file. One file per repository id.
pub const LOCK_EXTENSION: &str = "lock";

/// The filesystem operations the precondition step needs, and nothing else.
///
/// Only [`LocalPreconditionHost`] implements this over a real disk; the policy
/// below is decided by the free functions and never branches on the platform.
pub trait PreconditionHost: std::fmt::Debug {
    /// Whether `path` currently resolves to a directory.
    fn is_directory(&self, path: &Path) -> bool;

    /// Create `path` with `contents` only if it does not already exist.
    ///
    /// Returns `Ok(true)` when this caller created the file - and therefore
    /// owns the lock - and `Ok(false)` when it already existed. The
    /// create-only semantics are what makes the lock exclusive.
    ///
    /// # Errors
    ///
    /// Returns [`RULE_LOCK_IO`] when the file cannot be created or written.
    fn create_exclusive(&self, path: &Path, contents: &[u8]) -> Result<bool, AxiomError>;

    /// Read a lock file, or `None` when it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`RULE_LOCK_IO`] when the file exists but cannot be read.
    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, AxiomError>;

    /// Remove a lock file. Removing an absent file is not an error.
    ///
    /// # Errors
    ///
    /// Returns [`RULE_LOCK_IO`] when the file exists but cannot be removed.
    fn remove(&self, path: &Path) -> Result<(), AxiomError>;
}

/// The production host: `std::fs`, and only the calls the lock needs.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalPreconditionHost;

impl LocalPreconditionHost {
    /// The production filesystem host.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl PreconditionHost for LocalPreconditionHost {
    fn is_directory(&self, path: &Path) -> bool {
        path.is_dir()
    }

    fn create_exclusive(&self, path: &Path, contents: &[u8]) -> Result<bool, AxiomError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| lock_io(path, "create the lock directory", &error))?;
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(mut file) => {
                use std::io::Write as _;
                file.write_all(contents)
                    .map_err(|error| lock_io(path, "write the lock", &error))?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(lock_io(path, "create the lock", &error)),
        }
    }

    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, AxiomError> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(lock_io(path, "read the lock", &error)),
        }
    }

    fn remove(&self, path: &Path) -> Result<(), AxiomError> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(lock_io(path, "remove the lock", &error)),
        }
    }
}

/// An in-memory host for the refusal tests. It never touches a disk.
#[derive(Debug, Default)]
pub struct MemoryPreconditionHost {
    directories: Mutex<BTreeSet<PathBuf>>,
    files: Mutex<BTreeMap<PathBuf, Vec<u8>>>,
}

impl MemoryPreconditionHost {
    /// An empty host: no directory exists and no lock is held.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `path` as an existing directory.
    pub fn add_directory(&self, path: impl Into<PathBuf>) {
        self.directories
            .lock()
            .expect("the directory set is never poisoned")
            .insert(path.into());
    }

    /// Register `path` as an existing file, replacing any earlier contents.
    pub fn add_file(&self, path: impl Into<PathBuf>, contents: impl Into<Vec<u8>>) {
        self.files
            .lock()
            .expect("the file map is never poisoned")
            .insert(path.into(), contents.into());
    }

    /// Whether `path` currently exists in this host.
    #[must_use]
    pub fn contains(&self, path: &Path) -> bool {
        self.files
            .lock()
            .expect("the file map is never poisoned")
            .contains_key(path)
    }

    /// The current bytes of `path`, if any.
    #[must_use]
    pub fn file(&self, path: &Path) -> Option<Vec<u8>> {
        self.files
            .lock()
            .expect("the file map is never poisoned")
            .get(path)
            .cloned()
    }
}

impl PreconditionHost for MemoryPreconditionHost {
    fn is_directory(&self, path: &Path) -> bool {
        self.directories
            .lock()
            .expect("the directory set is never poisoned")
            .contains(path)
    }

    fn create_exclusive(&self, path: &Path, contents: &[u8]) -> Result<bool, AxiomError> {
        let mut files = self.files.lock().expect("the file map is never poisoned");
        if files.contains_key(path) {
            return Ok(false);
        }
        files.insert(path.to_path_buf(), contents.to_vec());
        Ok(true)
    }

    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, AxiomError> {
        Ok(self
            .files
            .lock()
            .expect("the file map is never poisoned")
            .get(path)
            .cloned())
    }

    fn remove(&self, path: &Path) -> Result<(), AxiomError> {
        self.files
            .lock()
            .expect("the file map is never poisoned")
            .remove(path);
        Ok(())
    }
}

/// The lock file path for one repository, under `AXIOM_HOME`.
///
/// # Errors
///
/// Returns [`RULE_LOCK_ID`] when the identifier could escape the lock directory
/// (an absolute or separator-bearing id, `..`, or an empty id).
pub fn lock_path(home: &Path, repository_id: &str) -> Result<PathBuf, AxiomError> {
    if !is_safe_repository_id(repository_id) {
        return Err(refuse(
            RULE_LOCK_ID,
            format!("unsafe repository identifier {repository_id:?}"),
        )
        .with_detail("portable_path", repository_id));
    }
    Ok(home
        .join(LOCK_DIR)
        .join(format!("{repository_id}.{LOCK_EXTENSION}")))
}

/// Whether a repository id can name one lock file inside the lock directory.
#[must_use]
fn is_safe_repository_id(repository_id: &str) -> bool {
    !repository_id.is_empty()
        && !repository_id.starts_with('.')
        && !repository_id.contains(['/', '\\', ':'])
}

/// A held per-repository apply lock.
///
/// Dropping the value releases the lock, so a failed apply cannot leave the
/// repository locked for the cooperating processes that respect this file.
#[derive(Debug)]
pub struct ApplyLock<'a> {
    host: &'a dyn PreconditionHost,
    path: PathBuf,
    token: Vec<u8>,
    held: bool,
}

impl<'a> ApplyLock<'a> {
    /// Take the per-repository apply lock.
    ///
    /// `root` and `plan_digest` are recorded in the lock so a refused
    /// cooperating apply can report who holds the repository.
    ///
    /// # Errors
    ///
    /// Returns [`RULE_LOCK_HELD`] (`WorktreeBusy`) when the lock already exists,
    /// [`RULE_LOCK_ID`] for an unsafe identifier, and [`RULE_LOCK_IO`] when the
    /// lock cannot be written.
    pub fn acquire(
        host: &'a dyn PreconditionHost,
        home: &Path,
        repository_id: &str,
        root: &str,
        plan_digest: &str,
    ) -> Result<Self, AxiomError> {
        let path = lock_path(home, repository_id)?;
        let token =
            format!("repository_id={repository_id}\nroot={root}\nplan_digest={plan_digest}\n")
                .into_bytes();
        if !host.create_exclusive(&path, &token)? {
            let owner = host.read(&path)?;
            return Err(lock_held(repository_id, &path, owner.as_deref()));
        }
        Ok(Self {
            host,
            path,
            token,
            held: true,
        })
    }

    /// The lock file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Release the lock explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`RULE_LOCK_IO`] when the lock file cannot be removed.
    pub fn release(mut self) -> Result<(), AxiomError> {
        self.held = false;
        self.remove_if_ours()
    }

    /// Remove the lock file only while it still records this holder's token.
    fn remove_if_ours(&self) -> Result<(), AxiomError> {
        match self.host.read(&self.path)? {
            Some(current) if current == self.token => self.host.remove(&self.path),
            _ => Ok(()),
        }
    }
}

impl Drop for ApplyLock<'_> {
    fn drop(&mut self) {
        if self.held {
            let _ = self.remove_if_ours();
        }
    }
}

/// Re-verify a planned repository against its current bytes.
///
/// # Errors
///
/// Returns [`RULE_PLAN_CONFLICT`] when the plan already refuses the repository,
/// [`RULE_PLAN_ROOT`] when the bound root is no longer a directory, and
/// [`RULE_PLAN_STALE`] when any recorded before-hash no longer matches.
pub fn verify_repository(
    repository: &RepositoryPlan,
    reader: &dyn RepositoryReader,
    host: &dyn PreconditionHost,
) -> Result<(), AxiomError> {
    if repository.is_conflict() {
        return Err(refuse(
            RULE_PLAN_CONFLICT,
            format!("the plan refuses repository {}", repository.repository_id),
        )
        .with_detail("component", &repository.repository_id));
    }
    if !host.is_directory(Path::new(&repository.root)) {
        return Err(refuse(
            RULE_PLAN_ROOT,
            format!("bound root {} is not a directory", repository.root),
        )
        .with_detail("portable_path", &repository.root));
    }
    for file in &repository.files {
        let current = reader.read(&file.path)?.map(|bytes| sha256_hex(&bytes));
        if current != file.before_sha256 {
            return Err(stale(
                &file.path,
                file.before_sha256.as_deref(),
                current.as_deref(),
            ));
        }
    }
    let current_block = observed_block_sha256(reader)?;
    if current_block != repository.before_block_sha256 {
        return Err(stale(
            AGENTS_PATH,
            repository.before_block_sha256.as_deref(),
            current_block.as_deref(),
        ));
    }
    Ok(())
}

/// Take a repository's apply lock and then re-verify it, the order the guide
/// fixes: a cooperating apply is excluded before the before-hashes are read.
///
/// # Errors
///
/// Returns the [`ApplyLock::acquire`] refusal when the lock is held, and the
/// [`verify_repository`] refusal - with the lock already released - when the
/// repository is stale, unbound or refused.
pub fn begin_apply<'a>(
    host: &'a dyn PreconditionHost,
    home: &Path,
    repository: &RepositoryPlan,
    reader: &dyn RepositoryReader,
    plan_digest: &str,
) -> Result<ApplyLock<'a>, AxiomError> {
    let lock = ApplyLock::acquire(
        host,
        home,
        &repository.repository_id,
        &repository.root,
        plan_digest,
    )?;
    if let Err(error) = verify_repository(repository, reader, host) {
        drop(lock);
        return Err(error);
    }
    Ok(lock)
}

/// The SHA-256 of the managed block as it exists in `reader` right now.
fn observed_block_sha256(reader: &dyn RepositoryReader) -> Result<Option<String>, AxiomError> {
    let Some(raw) = reader.read(AGENTS_PATH)? else {
        return Ok(None);
    };
    let Ok(text) = SourceText::decode(&raw) else {
        return Ok(None);
    };
    match markers::managed_span(text.document()) {
        Ok(Some(span)) => Ok(span
            .slice(text.document())
            .map(|block| sha256_hex(block.as_bytes()))),
        Ok(None) | Err(_) => Ok(None),
    }
}

/// Build the refusal for a before-hash that no longer matches.
fn stale(path: &str, expected: Option<&str>, observed: Option<&str>) -> AxiomError {
    refuse(
        RULE_PLAN_STALE,
        format!("{path} changed after the plan was approved"),
    )
    .with_detail("portable_path", path)
    .with_detail("expected", expected.unwrap_or("absent"))
    .with_detail("observed", observed.unwrap_or("absent"))
}

/// Build the refusal for a lock another cooperating apply already holds.
fn lock_held(repository_id: &str, path: &Path, owner: Option<&[u8]>) -> AxiomError {
    AxiomError::new(
        ErrorCode::WorktreeBusy,
        format!("another bootstrap apply holds the lock for {repository_id}"),
    )
    .with_detail("rule", RULE_LOCK_HELD)
    .with_detail("portable_path", path.display().to_string())
    .with_detail(
        "observed",
        owner.map_or_else(String::new, |bytes| {
            String::from_utf8_lossy(bytes).trim().to_owned()
        }),
    )
}

/// Label a lock-file I/O failure with its stable rule.
fn lock_io(path: &Path, action: impl std::fmt::Display, error: &std::io::Error) -> AxiomError {
    AxiomError::new(
        ErrorCode::Internal,
        format!("cannot {action} at {}: {error}", path.display()),
    )
    .with_detail("rule", RULE_LOCK_IO)
    .with_detail("portable_path", path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::plan::{
        plan_repository, ChangeClass, MapRepositoryReader, RepositoryTarget, Templates,
    };
    use crate::bootstrap::TEMPLATE_VERSION;

    fn corpus_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("bootstrap")
    }

    fn templates() -> Templates {
        let root = corpus_root();
        Templates::new(
            std::fs::read_to_string(root.join("templates").join("AGENTS.block.md"))
                .expect("block template"),
            std::fs::read(root.join("templates").join("POLICY.md")).expect("policy template"),
            TEMPLATE_VERSION,
        )
    }

    fn plan_for(reader: &dyn RepositoryReader, root: &str) -> RepositoryPlan {
        plan_repository(&RepositoryTarget::new("demo", root, reader), &templates())
            .expect("planning one repository")
    }

    fn home() -> PathBuf {
        PathBuf::from("/axiom-home")
    }

    fn rule(error: &AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    /// AC1 positive: a repository that still matches the plan verifies, and the
    /// lock it takes is released again.
    #[test]
    fn a_current_plan_verifies_and_takes_its_lock() {
        let host = MemoryPreconditionHost::new();
        host.add_directory("/repos/demo");
        let mut reader = MapRepositoryReader::new();
        reader.insert(AGENTS_PATH, "# Human\n");
        let plan = plan_for(&reader, "/repos/demo");
        assert_eq!(plan.change, ChangeClass::Append);

        let lock =
            begin_apply(&host, &home(), &plan, &reader, "digest-1").expect("preconditions hold");
        let path = lock_path(&home(), "demo").expect("lock path");
        assert!(host.contains(&path), "the lock is held");
        assert!(
            String::from_utf8_lossy(&host.file(&path).expect("lock bytes"))
                .contains("plan_digest=digest-1")
        );
        lock.release().expect("release");
        assert!(!host.contains(&path), "release removes the lock");
    }

    /// AC1 negative/boundary: a repository that changed after approval is
    /// refused as stale and the lock it briefly took is released, so nothing is
    /// written and no other apply is blocked.
    #[test]
    fn a_changed_target_is_refused_as_stale_before_any_write() {
        let host = MemoryPreconditionHost::new();
        host.add_directory("/repos/demo");
        let mut planned_from = MapRepositoryReader::new();
        planned_from.insert(AGENTS_PATH, "# Human\n");
        let plan = plan_for(&planned_from, "/repos/demo");

        let mut changed = MapRepositoryReader::new();
        changed.insert(AGENTS_PATH, "# Human\n\nedited after approval\n");
        let error = begin_apply(&host, &home(), &plan, &changed, "digest-1")
            .expect_err("a changed target is stale");
        assert_eq!(rule(&error), Some(RULE_PLAN_STALE));
        assert_eq!(
            error.details().get("portable_path").map(String::as_str),
            Some(AGENTS_PATH)
        );
        assert!(
            !host.contains(&lock_path(&home(), "demo").expect("lock path")),
            "a refused precondition does not leave the lock held"
        );
    }

    /// AC1 negative/boundary: a second cooperating apply cannot interleave with
    /// the first, and it succeeds once the first releases.
    #[test]
    fn a_second_apply_cannot_interleave_with_the_first() {
        let host = MemoryPreconditionHost::new();
        host.add_directory("/repos/demo");
        let mut reader = MapRepositoryReader::new();
        reader.insert(AGENTS_PATH, "# Human\n");
        let plan = plan_for(&reader, "/repos/demo");

        let first = begin_apply(&host, &home(), &plan, &reader, "digest-1").expect("first");
        let error = begin_apply(&host, &home(), &plan, &reader, "digest-2")
            .expect_err("the second apply must not interleave");
        assert_eq!(rule(&error), Some(RULE_LOCK_HELD));
        assert_eq!(error.code(), ErrorCode::WorktreeBusy);
        let lock = lock_path(&home(), "demo").expect("lock path");
        assert!(
            String::from_utf8_lossy(&host.file(&lock).expect("lock bytes")).contains("digest-1"),
            "the holder is reported, not overwritten"
        );

        drop(first);
        let second = begin_apply(&host, &home(), &plan, &reader, "digest-2")
            .expect("after release the repository is free");
        drop(second);
    }

    /// AC1 boundary: a lock that no longer records this holder is not deleted,
    /// so a cooperating process never removes someone else's lock.
    #[test]
    fn a_lock_is_removed_only_while_it_is_ours() {
        let host = MemoryPreconditionHost::new();
        let lock =
            ApplyLock::acquire(&host, &home(), "demo", "/repos/demo", "digest-1").expect("acquire");
        let path = lock.path().to_path_buf();
        host.add_file(path.clone(), b"repository_id=other\n".to_vec());
        drop(lock);
        assert!(host.contains(&path), "a foreign lock stays");
        assert_eq!(host.file(&path), Some(b"repository_id=other\n".to_vec()));
    }

    /// AC1 boundary: an identifier that could escape the lock directory is
    /// refused before any file is created.
    #[test]
    fn an_unsafe_repository_id_is_refused() {
        let host = MemoryPreconditionHost::new();
        for id in ["", "..", "a/b", "a\\b", ".hidden", "C:drive"] {
            let error = ApplyLock::acquire(&host, &home(), id, "/repos/demo", "digest-1")
                .expect_err("an unsafe id is refused");
            assert_eq!(rule(&error), Some(RULE_LOCK_ID), "id {id:?}");
        }
    }

    /// AC1 boundary: an unbound root and a plan that already refuses the
    /// repository are both refused before a lock is even considered.
    #[test]
    fn a_missing_root_and_a_conflict_plan_are_refused() {
        let host = MemoryPreconditionHost::new();
        let mut reader = MapRepositoryReader::new();
        reader.insert(AGENTS_PATH, "# Human\n");
        let plan = plan_for(&reader, "/repos/demo");
        let error = verify_repository(&plan, &reader, &host).expect_err("root absent");
        assert_eq!(rule(&error), Some(RULE_PLAN_ROOT));

        host.add_directory("/repos/demo");
        let mut broken = MapRepositoryReader::new();
        broken.insert(
            AGENTS_PATH,
            format!("{}\nunterminated\n", markers::BEGIN_MARKER),
        );
        let conflict = plan_for(&broken, "/repos/demo");
        assert!(conflict.is_conflict(), "an unbalanced marker is a conflict");
        let error =
            verify_repository(&conflict, &broken, &host).expect_err("a conflict is refused");
        assert_eq!(rule(&error), Some(RULE_PLAN_CONFLICT));
    }

    /// AC1 positive against the real adapter: the production host creates one
    /// lock file under `AXIOM_HOME` and removes only that file.
    #[test]
    fn the_local_host_holds_a_real_lock() {
        let dir = tempfile::tempdir().expect("temp dir");
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).expect("repository directory");
        let home = dir.path().join("home");
        let root = repo.display().to_string();
        let mut reader = MapRepositoryReader::new();
        reader.insert(AGENTS_PATH, "# Human\n");
        let plan = plan_for(&reader, root.as_str());

        let host = LocalPreconditionHost::new();
        let first = begin_apply(&host, &home, &plan, &reader, "digest-1").expect("real lock");
        let path = first.path().to_path_buf();
        assert!(path.is_file(), "the lock file is real");
        let error = ApplyLock::acquire(&host, &home, "demo", root.as_str(), "digest-2")
            .expect_err("the real lock is exclusive");
        assert_eq!(rule(&error), Some(RULE_LOCK_HELD));
        first.release().expect("release");
        assert!(!path.exists(), "the lock file is removed");
        assert!(home.join(LOCK_DIR).is_dir(), "the lock directory stays");
    }
}
