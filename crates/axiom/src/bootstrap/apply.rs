//! Journaled, backup-protected application of an approved plan (task E-020).
//!
//! Apply is the only half of bootstrap that writes, so it is built to fail
//! safely rather than to succeed quickly. Per repository it takes the apply lock
//! and re-verifies the before-hashes (E-019), backs the affected bytes up under
//! `AXIOM_HOME`, writes a journal *intent* before touching a single owned file,
//! writes the owned files with the ownership manifest last, verifies both the
//! written hashes and the bytes outside the owned block, and only then marks the
//! journal complete. Nothing is written before the backup and the intent exist,
//! so a half-finished run is recoverable instead of lost.
//!
//! When a write fails, [`rollback`] restores every file this run already wrote
//! from its backup, and it refuses to restore a file whose current hash no
//! longer equals the after-hash this run wrote - a newer human edit is preserved
//! and reported, never discarded. A rollback that had to refuse any file is
//! reported as [`ApplyOutcome::RollbackRefused`] rather than as a clean restore.
//!
//! A multi-repository plan is applied per repository, never as one transaction:
//! every repository gets its own outcome, one repository's refusal or failure
//! never hides another's result, and the aggregate exits
//! [`ExitCode::PartialOperation`] (20) when some repositories were updated and
//! others were not - bootstrap never claims all repositories were updated when
//! only some were.
//!
//! Only [`LocalBootstrapHost`] touches a filesystem; [`MemoryBootstrapHost`] is
//! the double that lets a failing write and a refused rollback be tested without
//! a disk.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use graph_core::error::{exit_code_for, AxiomError, ErrorCode, ExitCode};
use graph_export::sha256_hex;
use serde::{Deserialize, Serialize};

use super::markers;
use super::plan::{FileChange, Refusal, RepositoryPlan, RepositoryReader, AGENTS_PATH};
use super::preconditions::{self, PreconditionHost};
use super::text::{self, SourceText};
use super::{ownership, refuse};

/// Stable rule code: an owned file could not be written.
pub const RULE_APPLY_WRITE: &str = "apply-write-failed";

/// Stable rule code: a written file does not hash to the after-hash the plan
/// promised.
pub const RULE_APPLY_VERIFY: &str = "apply-verify-failed";

/// Stable rule code: bytes outside the owned block changed during the write.
pub const RULE_APPLY_OUTSIDE: &str = "apply-outside-content-changed";

/// Stable rule code: no reader was bound to a planned repository.
pub const RULE_APPLY_READER: &str = "apply-reader-absent";

/// Stable rule code: the journal could not be written.
pub const RULE_APPLY_JOURNAL: &str = "apply-journal-io";

/// Stable rule code: the backup for an affected file is missing at rollback.
pub const RULE_APPLY_BACKUP: &str = "apply-backup-missing";

/// Directory under `AXIOM_HOME` that holds the per-repository journals.
pub const JOURNAL_DIR: &str = "bootstrap-journal";

/// Directory under `AXIOM_HOME` that holds the affected-bytes backups.
pub const BACKUP_DIR: &str = "bootstrap-backups";

/// Schema version of the journal document this build writes.
pub const JOURNAL_SCHEMA_VERSION: u32 = 1;

/// The filesystem operations an apply needs, and nothing else.
pub trait BootstrapHost: std::fmt::Debug {
    /// Read a file, or `None` when it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`RULE_APPLY_WRITE`] when the path exists but cannot be read.
    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, AxiomError>;

    /// Create `path` and its parents if they do not exist.
    ///
    /// # Errors
    ///
    /// Returns [`RULE_APPLY_WRITE`] when the directory cannot be created.
    fn create_dir_all(&self, path: &Path) -> Result<(), AxiomError>;

    /// Replace `path` with `bytes` in one step.
    ///
    /// # Errors
    ///
    /// Returns [`RULE_APPLY_WRITE`] when the bytes cannot be written.
    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), AxiomError>;

    /// Remove `path`. Removing an absent file is not an error.
    ///
    /// # Errors
    ///
    /// Returns [`RULE_APPLY_WRITE`] when the file exists but cannot be removed.
    fn remove_file(&self, path: &Path) -> Result<(), AxiomError>;
}

/// The production host: `std::fs` with a temp-file-and-rename write.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalBootstrapHost;

impl LocalBootstrapHost {
    /// The production filesystem host.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl BootstrapHost for LocalBootstrapHost {
    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, AxiomError> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(apply_io(path, "read", &error)),
        }
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), AxiomError> {
        std::fs::create_dir_all(path).map_err(|error| apply_io(path, "create a directory", &error))
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), AxiomError> {
        let temporary = path.with_extension(format!("axiom-{}.tmp", std::process::id()));
        std::fs::write(&temporary, bytes).map_err(|error| apply_io(path, "write", &error))?;
        match std::fs::rename(&temporary, path) {
            Ok(()) => Ok(()),
            // A platform that refuses to rename onto an existing destination is
            // completed by removing the file this run is replacing; the bytes
            // were already backed up before any write.
            Err(_) if path.exists() => {
                std::fs::remove_file(path).map_err(|error| apply_io(path, "replace", &error))?;
                std::fs::rename(&temporary, path).map_err(|error| apply_io(path, "write", &error))
            }
            Err(error) => Err(apply_io(path, "write", &error)),
        }
    }

    fn remove_file(&self, path: &Path) -> Result<(), AxiomError> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(apply_io(path, "remove", &error)),
        }
    }
}

/// An in-memory host. A write can be made to fail so rollback is exercised.
#[derive(Debug, Default)]
pub struct MemoryBootstrapHost {
    files: Mutex<BTreeMap<PathBuf, Vec<u8>>>,
    directories: Mutex<BTreeSet<PathBuf>>,
    fail_write: Mutex<Option<PathBuf>>,
}

impl MemoryBootstrapHost {
    /// An empty host.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an existing file.
    pub fn add_file(&self, path: impl Into<PathBuf>, bytes: impl Into<Vec<u8>>) {
        self.files
            .lock()
            .expect("the file map is never poisoned")
            .insert(path.into(), bytes.into());
    }

    /// Register an existing directory.
    pub fn add_directory(&self, path: impl Into<PathBuf>) {
        self.directories
            .lock()
            .expect("the directory set is never poisoned")
            .insert(path.into());
    }

    /// Make the next write to exactly `path` fail.
    pub fn fail_write(&self, path: impl Into<PathBuf>) {
        *self
            .fail_write
            .lock()
            .expect("the failure slot is never poisoned") = Some(path.into());
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

    /// Whether `path` currently exists.
    #[must_use]
    pub fn contains(&self, path: &Path) -> bool {
        self.files
            .lock()
            .expect("the file map is never poisoned")
            .contains_key(path)
    }
}

impl BootstrapHost for MemoryBootstrapHost {
    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>, AxiomError> {
        Ok(self.file(path))
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), AxiomError> {
        self.directories
            .lock()
            .expect("the directory set is never poisoned")
            .insert(path.to_path_buf());
        Ok(())
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), AxiomError> {
        if self
            .fail_write
            .lock()
            .expect("the failure slot is never poisoned")
            .as_deref()
            == Some(path)
        {
            return Err(refuse(
                RULE_APPLY_WRITE,
                format!("injected write failure at {}", path.display()),
            ));
        }
        self.files
            .lock()
            .expect("the file map is never poisoned")
            .insert(path.to_path_buf(), bytes.to_vec());
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<(), AxiomError> {
        self.files
            .lock()
            .expect("the file map is never poisoned")
            .remove(path);
        Ok(())
    }
}

/// The state a per-repository journal records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JournalState {
    /// The affected bytes are backed up and the writes are about to start.
    Intent,
    /// Every owned file was written and verified.
    Complete,
    /// A write failed and the already-written files were restored.
    RolledBack,
}

/// One file the apply backed up and wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Repository-relative path.
    pub path: String,
    /// SHA-256 of the file before the write, or `None` when it did not exist.
    pub before_sha256: Option<String>,
    /// SHA-256 of the bytes this run wrote.
    pub after_sha256: String,
    /// Absolute path of the backup holding the before-bytes, or `None` when the
    /// file did not exist before.
    pub backup: Option<String>,
}

/// The per-repository journal document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    /// Schema version of this document.
    pub schema_version: u32,
    /// Stable identifier of the repository.
    pub repository_id: String,
    /// Display root of the repository.
    pub root: String,
    /// Digest of the whole plan this apply came from.
    pub plan_digest: String,
    /// Where the apply is.
    pub state: JournalState,
    /// One entry per affected file.
    pub entries: Vec<JournalEntry>,
}

/// What an apply did for one repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The owned files were written and verified.
    Applied {
        /// Repository-relative paths that were written, in write order.
        files: Vec<String>,
    },
    /// The plan proposed no writes for this repository.
    Unchanged,
    /// A precondition refused the repository and nothing was written.
    Refused {
        /// Stable rule code.
        rule: String,
        /// Operator-facing explanation.
        message: String,
    },
    /// A write failed and every file already written was restored.
    RolledBack {
        /// Stable rule code of the original failure.
        rule: String,
        /// Operator-facing explanation.
        message: String,
    },
    /// A write failed and at least one file could not be restored because it
    /// changed since the write.
    RollbackRefused {
        /// Stable rule code of the original failure.
        rule: String,
        /// Operator-facing explanation.
        message: String,
    },
}

impl ApplyOutcome {
    /// Whether the repository is now in the state the plan wanted.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Applied { .. } | Self::Unchanged)
    }

    /// The stable rule code, when this outcome is not a success.
    #[must_use]
    pub fn rule(&self) -> Option<&str> {
        match self {
            Self::Applied { .. } | Self::Unchanged => None,
            Self::Refused { rule, .. }
            | Self::RolledBack { rule, .. }
            | Self::RollbackRefused { rule, .. } => Some(rule),
        }
    }

    /// The failure code this outcome maps to, for the exit status.
    #[must_use]
    pub fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Applied { .. } | Self::Unchanged => None,
            Self::Refused { rule, .. } if rule == preconditions::RULE_LOCK_HELD => {
                Some(ErrorCode::WorktreeBusy)
            }
            Self::Refused { rule, .. } if rule == preconditions::RULE_PLAN_STALE => {
                Some(ErrorCode::NotReady)
            }
            Self::Refused { .. } | Self::RolledBack { .. } | Self::RollbackRefused { .. } => {
                Some(ErrorCode::Conflict)
            }
        }
    }
}

/// One repository's outcome in the aggregate report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryReport {
    /// Stable identifier of the repository.
    pub repository_id: String,
    /// What the apply did.
    pub outcome: ApplyOutcome,
}

/// The aggregate outcome of applying a whole plan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApplyReport {
    /// One entry per planned repository, in plan order.
    pub repositories: Vec<RepositoryReport>,
}

impl ApplyReport {
    /// How many repositories ended in the state the plan wanted.
    #[must_use]
    pub fn successes(&self) -> usize {
        self.repositories
            .iter()
            .filter(|report| report.outcome.is_success())
            .count()
    }

    /// The repositories that were not updated.
    #[must_use]
    pub fn failures(&self) -> Vec<&RepositoryReport> {
        self.repositories
            .iter()
            .filter(|report| !report.outcome.is_success())
            .collect()
    }

    /// The process exit status for this aggregate.
    ///
    /// A run in which every repository succeeded is [`ExitCode::Success`]; a run
    /// in which some succeeded and some did not is
    /// [`ExitCode::PartialOperation`]; a run in which none succeeded reports the
    /// first failure's own code.
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        let successes = self.successes();
        if successes == self.repositories.len() {
            return ExitCode::Success;
        }
        if successes > 0 {
            return ExitCode::PartialOperation;
        }
        self.repositories
            .iter()
            .find_map(|report| report.outcome.error_code())
            .map_or(ExitCode::Success, exit_code_for)
    }
}

/// Binds one planned repository to the reader that observes its host.
#[derive(Clone, Copy)]
pub struct ReaderBinding<'a> {
    /// Stable identifier matching a repository in the plan.
    pub repository_id: &'a str,
    /// Read-only access to that repository.
    pub reader: &'a dyn RepositoryReader,
}

impl<'a> ReaderBinding<'a> {
    /// Bind one repository identifier to its reader.
    #[must_use]
    pub const fn new(repository_id: &'a str, reader: &'a dyn RepositoryReader) -> Self {
        Self {
            repository_id,
            reader,
        }
    }
}

/// Apply a whole plan, one repository at a time.
///
/// Every repository is attempted independently, so one refusal or failure never
/// hides another repository's outcome.
#[must_use]
pub fn apply_plan(
    plan: &super::plan::BootstrapPlan,
    readers: &[ReaderBinding<'_>],
    host: &dyn BootstrapHost,
    locks: &dyn PreconditionHost,
    home: &Path,
) -> ApplyReport {
    let mut repositories = Vec::with_capacity(plan.repositories.len());
    for repository in &plan.repositories {
        let outcome = match readers
            .iter()
            .find(|binding| binding.repository_id == repository.repository_id)
        {
            Some(binding) => {
                apply_repository(repository, binding.reader, host, locks, home, &plan.digest)
            }
            None => ApplyOutcome::Refused {
                rule: RULE_APPLY_READER.to_owned(),
                message: format!(
                    "no reader is bound to repository {}",
                    repository.repository_id
                ),
            },
        };
        repositories.push(RepositoryReport {
            repository_id: repository.repository_id.clone(),
            outcome,
        });
    }
    ApplyReport { repositories }
}

/// Apply one planned repository.
///
/// A refused plan, a repository the plan leaves unchanged, a precondition
/// refusal and a write failure are four distinct outcomes, so a caller can
/// report them independently.
#[must_use]
pub fn apply_repository(
    plan: &RepositoryPlan,
    reader: &dyn RepositoryReader,
    host: &dyn BootstrapHost,
    locks: &dyn PreconditionHost,
    home: &Path,
    plan_digest: &str,
) -> ApplyOutcome {
    if plan.is_conflict() {
        let refusal = plan.refusal.clone().unwrap_or(Refusal {
            rule: preconditions::RULE_PLAN_CONFLICT.to_owned(),
            message: "the plan refuses this repository".to_owned(),
        });
        return ApplyOutcome::Refused {
            rule: refusal.rule,
            message: refusal.message,
        };
    }
    if !plan.would_write() {
        return ApplyOutcome::Unchanged;
    }
    let lock = match preconditions::begin_apply(locks, home, plan, reader, plan_digest) {
        Ok(lock) => lock,
        Err(error) => {
            return ApplyOutcome::Refused {
                rule: rule_of(&error),
                message: error.message().to_owned(),
            }
        }
    };
    let outcome = write_repository(plan, reader, host, home, plan_digest);
    drop(lock);
    outcome
}

/// Back up, journal, write and verify one repository.
fn write_repository(
    plan: &RepositoryPlan,
    reader: &dyn RepositoryReader,
    host: &dyn BootstrapHost,
    home: &Path,
    plan_digest: &str,
) -> ApplyOutcome {
    let root = Path::new(&plan.root);
    let journal_path = journal_path(home, &plan.repository_id);

    // 1. Back up the affected bytes before any write. `entries` is the intent
    //    the journal records, so recovery knows how to undo each file.
    let mut entries = Vec::with_capacity(plan.files.len());
    let before: BTreeMap<String, Option<Vec<u8>>> = plan
        .files
        .iter()
        .map(|file| (file.path.clone(), reader.read(&file.path).ok().flatten()))
        .collect();
    for file in &plan.files {
        let backup = match before.get(&file.path).and_then(Option::as_ref) {
            Some(bytes) => {
                let backup_path = backup_path(home, &plan.repository_id, &file.path);
                if let Some(parent) = backup_path.parent() {
                    if let Err(error) = host.create_dir_all(parent) {
                        return ApplyOutcome::RolledBack {
                            rule: rule_of(&error),
                            message: error.message().to_owned(),
                        };
                    }
                }
                if let Err(error) = host.write_atomic(&backup_path, bytes) {
                    return ApplyOutcome::RolledBack {
                        rule: rule_of(&error),
                        message: error.message().to_owned(),
                    };
                }
                Some(backup_path.display().to_string())
            }
            None => None,
        };
        entries.push(JournalEntry {
            path: file.path.clone(),
            before_sha256: file.before_sha256.clone(),
            after_sha256: file.after_sha256.clone(),
            backup,
        });
    }

    // 2. Journal the intent before the first owned byte is written.
    let mut journal = Journal {
        schema_version: JOURNAL_SCHEMA_VERSION,
        repository_id: plan.repository_id.clone(),
        root: plan.root.clone(),
        plan_digest: plan_digest.to_owned(),
        state: JournalState::Intent,
        entries: entries.clone(),
    };
    if let Err(error) = write_journal(host, &journal_path, &journal) {
        return ApplyOutcome::RolledBack {
            rule: rule_of(&error),
            message: error.message().to_owned(),
        };
    }

    // 3. Write the owned files, the ownership manifest last.
    let mut written: Vec<JournalEntry> = Vec::new();
    for file in ordered_files(plan) {
        match write_owned_file(
            file,
            before.get(&file.path).and_then(Option::as_ref),
            root,
            host,
        ) {
            Ok(()) => written.push(
                entries
                    .iter()
                    .find(|entry| entry.path == file.path)
                    .cloned()
                    .unwrap_or(JournalEntry {
                        path: file.path.clone(),
                        before_sha256: file.before_sha256.clone(),
                        after_sha256: file.after_sha256.clone(),
                        backup: None,
                    }),
            ),
            Err(error) => {
                let rollback = rollback(host, root, &written);
                journal.state = JournalState::RolledBack;
                let _ = write_journal(host, &journal_path, &journal);
                return match rollback {
                    Ok(rollback) if rollback.refused.is_empty() => ApplyOutcome::RolledBack {
                        rule: rule_of(&error),
                        message: format!(
                            "{}; restored {} file(s) from backup",
                            error.message(),
                            rollback.restored
                        ),
                    },
                    Ok(rollback) => ApplyOutcome::RollbackRefused {
                        rule: rule_of(&error),
                        message: format!(
                            "{}; restored {} file(s), refused {} ({} changed since the write)",
                            error.message(),
                            rollback.restored,
                            rollback.refused.len(),
                            rollback
                                .refused
                                .iter()
                                .map(|(path, _)| path.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    },
                    Err(rollback_error) => ApplyOutcome::RollbackRefused {
                        rule: rule_of(&error),
                        message: format!(
                            "{}; rollback failed: {}",
                            error.message(),
                            rollback_error.message()
                        ),
                    },
                };
            }
        }
    }

    // 4. Mark the journal complete. The repository is written and verified.
    journal.state = JournalState::Complete;
    let _ = write_journal(host, &journal_path, &journal);
    ApplyOutcome::Applied {
        files: written.into_iter().map(|entry| entry.path).collect(),
    }
}

/// Write one owned file, then verify it against the plan.
fn write_owned_file(
    file: &FileChange,
    before: Option<&Vec<u8>>,
    root: &Path,
    host: &dyn BootstrapHost,
) -> Result<(), AxiomError> {
    let path = root.join(&file.path);
    if let Some(parent) = path.parent() {
        host.create_dir_all(parent)?;
    }
    host.write_atomic(&path, &file.bytes)?;

    let written = host.read(&path)?.ok_or_else(|| {
        refuse(
            RULE_APPLY_VERIFY,
            format!("{} vanished after it was written", file.path),
        )
    })?;
    let observed = sha256_hex(&written);
    if observed != file.after_sha256 {
        return Err(refuse(
            RULE_APPLY_VERIFY,
            format!("{} does not match the approved after-hash", file.path),
        )
        .with_detail("portable_path", &file.path)
        .with_detail("expected", &file.after_sha256)
        .with_detail("observed", observed));
    }
    if file.path == AGENTS_PATH {
        verify_outside_content(before.map(Vec::as_slice), &written, &file.path)?;
    }
    Ok(())
}

/// Refuse a write that changed bytes outside the owned block.
fn verify_outside_content(
    before: Option<&[u8]>,
    after: &[u8],
    path: &str,
) -> Result<(), AxiomError> {
    let Some(before) = before else {
        // A file that did not exist has no outside content to preserve.
        return Ok(());
    };
    let before_text = SourceText::decode(before)?;
    let after_text = SourceText::decode(after)?;
    let preserved = match markers::managed_span(before_text.document()) {
        // A re-apply must be exactly the owned span replaced, nothing else.
        Ok(Some(span)) => {
            let replacement = markers::managed_span(after_text.document())
                .ok()
                .flatten()
                .and_then(|after_span| after_span.slice(after_text.document()))
                .unwrap_or_default();
            text::replaces_only_span(
                before_text.document(),
                after_text.document(),
                span,
                replacement,
            )
        }
        // An append must keep the whole original document as an exact prefix.
        _ => after_text.document().starts_with(before_text.document()),
    };
    if !preserved {
        return Err(refuse(
            RULE_APPLY_OUTSIDE,
            format!("{path} changed bytes outside the owned block"),
        )
        .with_detail("portable_path", path)
        .with_detail("expected", sha256_hex(before))
        .with_detail("observed", sha256_hex(after)));
    }
    Ok(())
}

/// The result of restoring the files written by a failed apply.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RollbackReport {
    /// How many files were restored from their backup.
    pub restored: usize,
    /// The files that could not be restored, with the reason.
    pub refused: Vec<(String, String)>,
}

/// Restore the files a failed apply already wrote, in reverse write order.
///
/// A file is restored only while its current hash still equals the after-hash
/// this run wrote; a file that changed since is left untouched and reported.
///
/// # Errors
///
/// Returns [`RULE_APPLY_WRITE`] when a restore cannot be attempted, and
/// [`RULE_APPLY_BACKUP`] when a needed backup is missing.
fn rollback(
    host: &dyn BootstrapHost,
    root: &Path,
    written: &[JournalEntry],
) -> Result<RollbackReport, AxiomError> {
    let mut report = RollbackReport::default();
    for entry in written.iter().rev() {
        let path = root.join(&entry.path);
        let current = host.read(&path)?;
        let current_sha256 = current.as_deref().map(sha256_hex);
        if current_sha256.as_deref() != Some(entry.after_sha256.as_str()) {
            report.refused.push((
                entry.path.clone(),
                "changed since the write; refusing to discard it".to_owned(),
            ));
            continue;
        }
        match &entry.backup {
            Some(backup) => {
                let backup = Path::new(backup);
                let bytes = host.read(backup)?.ok_or_else(|| {
                    refuse(
                        RULE_APPLY_BACKUP,
                        format!("the backup for {} is missing", entry.path),
                    )
                    .with_detail("portable_path", &entry.path)
                })?;
                host.write_atomic(&path, &bytes)?;
            }
            None => host.remove_file(&path)?,
        }
        report.restored += 1;
    }
    Ok(report)
}

/// The plan's files with the ownership manifest written last.
fn ordered_files(plan: &RepositoryPlan) -> Vec<&FileChange> {
    let (manifest, others): (Vec<_>, Vec<_>) = plan
        .files
        .iter()
        .partition(|file| file.path == ownership::OWNERSHIP_PATH);
    others.into_iter().chain(manifest).collect()
}

/// The journal path for one repository.
#[must_use]
pub fn journal_path(home: &Path, repository_id: &str) -> PathBuf {
    home.join(JOURNAL_DIR)
        .join(format!("{}.json", sanitize(repository_id)))
}

/// The backup path for one affected file.
#[must_use]
pub fn backup_path(home: &Path, repository_id: &str, relative_path: &str) -> PathBuf {
    home.join(BACKUP_DIR)
        .join(sanitize(repository_id))
        .join(sanitize(relative_path))
}

/// Fold a repository id or a relative path into one safe file name component.
#[must_use]
fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '/' | '\\' | ':' => '_',
            other => other,
        })
        .collect()
}

/// Write the journal document.
fn write_journal(
    host: &dyn BootstrapHost,
    path: &Path,
    journal: &Journal,
) -> Result<(), AxiomError> {
    let bytes = serde_json::to_vec(journal).map_err(|error| {
        refuse(
            RULE_APPLY_JOURNAL,
            format!("cannot encode the journal: {error}"),
        )
    })?;
    if let Some(parent) = path.parent() {
        host.create_dir_all(parent)?;
    }
    host.write_atomic(path, &bytes)
}

/// The stable rule code of an error, defaulting to the apply write rule.
fn rule_of(error: &AxiomError) -> String {
    error
        .details()
        .get("rule")
        .cloned()
        .unwrap_or_else(|| RULE_APPLY_WRITE.to_owned())
}

/// Label a host I/O failure with its stable rule.
fn apply_io(path: &Path, action: impl std::fmt::Display, error: &std::io::Error) -> AxiomError {
    AxiomError::new(
        ErrorCode::Internal,
        format!("cannot {action} {}: {error}", path.display()),
    )
    .with_detail("rule", RULE_APPLY_WRITE)
    .with_detail("portable_path", path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::plan::{
        plan_all, plan_repository, LocalRepositoryReader, MapRepositoryReader, RepositoryTarget,
        Templates,
    };
    use crate::bootstrap::preconditions::MemoryPreconditionHost;
    use crate::bootstrap::{markers, policy, TEMPLATE_VERSION};

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

    fn append_plan(reader: &dyn RepositoryReader, root: &str) -> RepositoryPlan {
        plan_repository(&RepositoryTarget::new("demo", root, reader), &templates())
            .expect("planning one repository")
    }

    fn home() -> PathBuf {
        PathBuf::from("/axiom-home")
    }

    /// AC1 positive: an apply writes every owned file, leaves the human bytes
    /// outside the block untouched and completes its journal.
    #[test]
    fn an_apply_writes_every_owned_file_and_completes_the_journal() {
        let host = MemoryBootstrapHost::new();
        let locks = MemoryPreconditionHost::new();
        locks.add_directory("/repos/demo");
        let mut reader = MapRepositoryReader::new();
        reader.insert(AGENTS_PATH, "# Human\n");
        let plan = append_plan(&reader, "/repos/demo");

        let outcome = apply_repository(&plan, &reader, &host, &locks, &home(), "digest-1");
        let ApplyOutcome::Applied { files } = &outcome else {
            panic!("expected an applied repository, got {outcome:?}");
        };
        assert_eq!(files.len(), 3);
        assert_eq!(
            files.last().map(String::as_str),
            Some(ownership::OWNERSHIP_PATH),
            "the ownership manifest is written last"
        );
        assert_eq!(files.first().map(String::as_str), Some(AGENTS_PATH));

        let root = Path::new("/repos/demo");
        let agents = host.file(&root.join(AGENTS_PATH)).expect("AGENTS.md");
        assert!(String::from_utf8_lossy(&agents).starts_with("# Human\n"));
        assert!(String::from_utf8_lossy(&agents).contains(markers::BEGIN_MARKER));
        assert!(host.contains(&root.join(policy::POLICY_PATH)));
        assert!(host.contains(&root.join(ownership::OWNERSHIP_PATH)));

        let journal = read_journal(&host, &journal_path(&home(), "demo")).expect("journal");
        assert_eq!(journal.state, JournalState::Complete);
        assert_eq!(journal.plan_digest, "digest-1");
        assert_eq!(journal.entries.len(), 3);
    }

    /// AC1 positive: a write that fails after an earlier file was written
    /// restores that file from its verified backup and leaves the failing file
    /// untouched.
    #[test]
    fn a_failed_write_restores_the_files_it_already_wrote() {
        let host = MemoryBootstrapHost::new();
        let locks = MemoryPreconditionHost::new();
        locks.add_directory("/repos/demo");
        let mut reader = MapRepositoryReader::new();
        reader.insert(AGENTS_PATH, "# Human\n");
        let plan = append_plan(&reader, "/repos/demo");

        let root = Path::new("/repos/demo");
        host.fail_write(root.join(policy::POLICY_PATH));
        let outcome = apply_repository(&plan, &reader, &host, &locks, &home(), "digest-1");
        let ApplyOutcome::RolledBack { rule, .. } = &outcome else {
            panic!("expected a rolled-back repository, got {outcome:?}");
        };
        assert_eq!(rule, RULE_APPLY_WRITE);
        assert_eq!(
            host.file(&root.join(AGENTS_PATH)),
            Some(b"# Human\n".to_vec()),
            "the already-written file is restored from its backup"
        );
        assert!(!host.contains(&root.join(policy::POLICY_PATH)));
        assert!(!host.contains(&root.join(ownership::OWNERSHIP_PATH)));
        let journal = read_journal(&host, &journal_path(&home(), "demo")).expect("journal");
        assert_eq!(journal.state, JournalState::RolledBack);
    }

    /// AC1 boundary: a rollback refuses to discard a file that changed since
    /// this run wrote it, and reports the divergence.
    #[test]
    fn a_rollback_refuses_to_discard_a_newer_edit() {
        let host = MemoryBootstrapHost::new();
        let root = Path::new("/repos/demo");
        let entry = JournalEntry {
            path: AGENTS_PATH.to_owned(),
            before_sha256: Some(sha256_hex(b"original")),
            after_sha256: sha256_hex(b"written by the run"),
            backup: Some("/axiom-home/bootstrap-backups/demo/AGENTS.md".to_owned()),
        };
        host.add_file(root.join(AGENTS_PATH), b"a newer human edit\n".to_vec());
        host.add_file(
            Path::new("/axiom-home/bootstrap-backups/demo/AGENTS.md"),
            b"original".to_vec(),
        );

        let report = rollback(&host, root, std::slice::from_ref(&entry)).expect("rollback runs");
        assert_eq!(report.restored, 0);
        assert_eq!(report.refused.len(), 1);
        assert_eq!(
            host.file(&root.join(AGENTS_PATH)),
            Some(b"a newer human edit\n".to_vec()),
            "the newer edit is preserved"
        );
    }

    /// AC1 negative/boundary: a multi-repository run reports every repository
    /// independently and exits 20 when only some were updated.
    #[test]
    fn a_partial_multi_repo_run_reports_each_outcome_and_exit_20() {
        let host = MemoryBootstrapHost::new();
        let locks = MemoryPreconditionHost::new();
        locks.add_directory("/repos/stale");
        locks.add_directory("/repos/clean");

        let mut planned_from = MapRepositoryReader::new();
        planned_from.insert(AGENTS_PATH, "# Human\n");
        let mut clean = MapRepositoryReader::new();
        clean.insert(AGENTS_PATH, "# Clean\n");
        let plan = plan_all(
            &[
                RepositoryTarget::new("stale", "/repos/stale", &planned_from),
                RepositoryTarget::new("clean", "/repos/clean", &clean),
            ],
            &templates(),
        )
        .expect("planning two repositories");

        let mut changed = MapRepositoryReader::new();
        changed.insert(AGENTS_PATH, "# Human\n\nedited after approval\n");
        let report = apply_plan(
            &plan,
            &[
                ReaderBinding::new("stale", &changed),
                ReaderBinding::new("clean", &clean),
            ],
            &host,
            &locks,
            &home(),
        );

        assert_eq!(report.successes(), 1);
        let failures = report.failures();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].repository_id, "stale");
        assert_eq!(
            failures[0].outcome.rule(),
            Some(preconditions::RULE_PLAN_STALE)
        );
        assert_eq!(report.exit_code(), ExitCode::PartialOperation);
        assert_eq!(report.exit_code().as_i32(), 20);
        assert!(host.contains(&Path::new("/repos/clean").join(AGENTS_PATH)));
        assert!(!host.contains(&Path::new("/repos/stale").join(AGENTS_PATH)));
    }

    /// AC1 boundary: a plan that already refuses a repository is reported as a
    /// refusal without taking a lock or writing anything.
    #[test]
    fn a_conflict_plan_is_refused_without_writing() {
        let host = MemoryBootstrapHost::new();
        let locks = MemoryPreconditionHost::new();
        locks.add_directory("/repos/demo");
        let mut broken = MapRepositoryReader::new();
        broken.insert(
            AGENTS_PATH,
            format!("{}\nunterminated\n", markers::BEGIN_MARKER),
        );
        let plan = append_plan(&broken, "/repos/demo");
        assert!(plan.is_conflict());

        let outcome = apply_repository(&plan, &broken, &host, &locks, &home(), "digest-1");
        let ApplyOutcome::Refused { rule, .. } = outcome else {
            panic!("a conflict plan is refused");
        };
        assert_eq!(rule, "markers-unbalanced");
        assert!(!host.contains(&Path::new("/repos/demo").join(AGENTS_PATH)));
    }

    /// The outside-content check bounds exactly what a write may touch: a block
    /// replacement and an append are accepted, an edit outside the block is not.
    #[test]
    fn the_outside_content_check_bounds_what_a_write_may_touch() {
        let begin = markers::BEGIN_MARKER;
        let end = markers::END_MARKER;
        let before = format!("# Head\n\n{begin}\nbody\n{end}\n# Tail\n");
        let replaced = format!("# Head\n\n{begin}\nnew body\n{end}\n# Tail\n");
        assert!(
            verify_outside_content(Some(before.as_bytes()), replaced.as_bytes(), AGENTS_PATH)
                .is_ok(),
            "a replacement that only swaps the owned block is accepted"
        );
        let plain = "# Head\n\n# Tail\n";
        let appended = format!("{plain}\n{begin}\nmore\n{end}\n");
        assert!(
            verify_outside_content(Some(plain.as_bytes()), appended.as_bytes(), AGENTS_PATH)
                .is_ok(),
            "an append keeps the original document as an exact prefix"
        );
        let tampered = replaced.replace("# Tail", "# Tail edited");
        assert!(
            verify_outside_content(Some(before.as_bytes()), tampered.as_bytes(), AGENTS_PATH)
                .is_err(),
            "an edit outside the block is refused"
        );
        let from_scratch = format!("# Human\n\n{begin}\nbody\n{end}\n");
        assert!(
            verify_outside_content(Some(b"# Human\n"), from_scratch.as_bytes(), AGENTS_PATH)
                .is_ok(),
            "a first append to a document with no block is accepted"
        );
    }

    /// The production host writes real owned files and a real journal.
    #[test]
    fn the_local_host_writes_owned_files_and_a_journal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).expect("repository directory");
        std::fs::write(repo.join(AGENTS_PATH), "# Human\n").expect("human AGENTS.md");
        let home = dir.path().join("home");
        let root = repo.display().to_string();

        let reader = LocalRepositoryReader::new(&repo);
        let plan = append_plan(&reader, root.as_str());
        let host = LocalBootstrapHost::new();
        let locks = crate::bootstrap::preconditions::LocalPreconditionHost::new();

        let outcome = apply_repository(&plan, &reader, &host, &locks, &home, "digest-1");
        assert!(
            matches!(outcome, ApplyOutcome::Applied { .. }),
            "expected an applied repository, got {outcome:?}"
        );
        let agents = std::fs::read_to_string(repo.join(AGENTS_PATH)).expect("AGENTS.md");
        assert!(agents.starts_with("# Human\n"));
        assert!(agents.contains(markers::BEGIN_MARKER));
        assert!(repo.join(policy::POLICY_PATH).is_file());
        assert!(repo.join(ownership::OWNERSHIP_PATH).is_file());

        let journal_bytes = std::fs::read(journal_path(&home, "demo")).expect("journal");
        let journal: Journal = serde_json::from_slice(&journal_bytes).expect("parse journal");
        assert_eq!(journal.state, JournalState::Complete);
    }

    /// Read the journal a host holds, for the in-memory assertions.
    fn read_journal(host: &dyn BootstrapHost, path: &Path) -> Option<Journal> {
        let bytes = host.read(path).ok().flatten()?;
        serde_json::from_slice(&bytes).ok()
    }
}
