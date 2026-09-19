//! Roll a managed bootstrap change back to the content it replaced (task E-025).
//!
//! `docs/18-BOOTSTRAP-AND-MANAGED-INSTRUCTIONS.md` section 5 fixes the rule this
//! module implements: *rollback restores only while the current hash still
//! equals the after-hash the installer wrote; if the user edited afterwards
//! that is a conflict, the backup is kept and the user's work is never
//! overwritten to force the rollback.*
//!
//! The record of a change is the per-repository journal the apply path already
//! writes ([`super::apply::Journal`]): one entry per affected file with its
//! before-hash, its after-hash and the backup that holds the before-bytes. This
//! module is the inverse operation over that document, and it adds exactly the
//! three guarantees the card asks for:
//!
//! 1. **approval binding** - a rollback only runs for the digest of the plan it
//!    undoes, so an operator cannot roll back a change nobody approved
//!    ([`RULE_ROLLBACK_DIGEST`]);
//! 2. **ownership-hash checking** - every file is judged against the hash the
//!    installer wrote *at rollback time*, and the ownership manifest
//!    (`.axiom/agent/bootstrap.lock.json`) is checked like any other owned file
//!    but reported with its own rule ([`RULE_ROLLBACK_OWNERSHIP`]) because it is
//!    the document that records what bootstrap last wrote;
//! 3. **later human edits win** - a file whose current bytes are neither the
//!    before-state nor the after-state is refused ([`RULE_ROLLBACK_LATER_EDIT`])
//!    and left exactly as the human left it, at plan time and again immediately
//!    before each write.
//!
//! The backup itself is verified, not trusted: a backup that is missing or whose
//! bytes no longer hash to the recorded before-hash is refused
//! ([`RULE_ROLLBACK_BACKUP_MISSING`], [`RULE_ROLLBACK_BACKUP`]), so rollback
//! never writes a state it cannot prove was the previous one. Nothing here
//! recurses: only the paths in the journal are considered, and a file that was
//! already restored (its current hash *is* its before-hash) is reported as
//! `already-before` instead of being written again, which makes a repeated
//! rollback of the same journal a no-op.

use std::path::{Path, PathBuf};

use graph_core::error::AxiomError;
use graph_export::sha256_hex;
use serde::{Deserialize, Serialize};

use super::apply::{self, BootstrapHost, Journal, JournalState};
use super::ownership;
use super::refuse;

/// Stable rule code: the caller did not approve the digest being rolled back.
pub const RULE_ROLLBACK_DIGEST: &str = "rollback-digest-mismatch";

/// Stable rule code: the journal document cannot be read or judged.
pub const RULE_ROLLBACK_JOURNAL: &str = "rollback-journal-malformed";

/// Stable rule code: a file changed after the installer wrote it.
pub const RULE_ROLLBACK_LATER_EDIT: &str = "rollback-later-edit";

/// Stable rule code: the ownership manifest changed after the installer wrote it.
pub const RULE_ROLLBACK_OWNERSHIP: &str = "rollback-ownership-drift";

/// Stable rule code: the backup for a file is missing.
pub const RULE_ROLLBACK_BACKUP_MISSING: &str = "rollback-backup-missing";

/// Stable rule code: a backup does not hash to the recorded before-hash.
pub const RULE_ROLLBACK_BACKUP: &str = "rollback-backup-mismatch";

/// What a rollback would do to one owned file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RollbackAction {
    /// The recorded before-bytes are put back from their verified backup.
    Restore,
    /// The file did not exist before the change and is removed.
    Remove,
    /// The file already carries its before-bytes; nothing is written.
    AlreadyBefore,
}

impl RollbackAction {
    /// Stable string form for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Restore => "restore",
            Self::Remove => "remove",
            Self::AlreadyBefore => "already-before",
        }
    }
}

/// One file's row in a rollback plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackEntry {
    /// Repository-relative path.
    pub path: String,
    /// What the rollback would do to it.
    pub action: RollbackAction,
    /// SHA-256 the file had before the change, or `None` when it did not exist.
    pub before_sha256: Option<String>,
    /// SHA-256 the installer wrote.
    pub after_sha256: String,
    /// Backup holding the before-bytes, when there was a before-state.
    pub backup: Option<String>,
}

impl RollbackEntry {
    /// Whether this entry names the ownership manifest.
    #[must_use]
    pub fn is_ownership(&self) -> bool {
        self.path == ownership::OWNERSHIP_PATH
    }
}

/// The reviewed, digest-bound decision to restore one repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackPlan {
    /// Stable identifier of the repository.
    pub repository_id: String,
    /// Display root of the repository.
    pub root: String,
    /// The plan digest the caller approved; it equals the journal's digest.
    pub approved_digest: String,
    /// One row per journal entry, in journal order.
    pub entries: Vec<RollbackEntry>,
}

impl RollbackPlan {
    /// How many files the rollback would write (restore or remove).
    #[must_use]
    pub fn writes(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.action != RollbackAction::AlreadyBefore)
            .count()
    }

    /// How many files already carry their before-bytes.
    #[must_use]
    pub fn already_before(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.action == RollbackAction::AlreadyBefore)
            .count()
    }

    /// The ownership manifest's row, when the journal recorded one.
    #[must_use]
    pub fn ownership_entry(&self) -> Option<&RollbackEntry> {
        self.entries.iter().find(|entry| entry.is_ownership())
    }

    /// A human-readable review document.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!(
            "bootstrap rollback {} ({}) for plan {}\n",
            self.repository_id, self.root, self.approved_digest
        );
        for entry in &self.entries {
            out.push_str(&format!("   {} {}\n", entry.action.as_str(), entry.path));
        }
        out
    }
}

/// What a rollback did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackReport {
    /// Stable identifier of the repository.
    pub repository_id: String,
    /// How many files were put back from their backup.
    pub restored: usize,
    /// How many files that did not exist before the change were removed.
    pub removed: usize,
    /// How many files were already at their before-state.
    pub already_before: usize,
    /// The journal state after the rollback.
    pub state: JournalState,
}

impl RollbackReport {
    /// Whether anything was written.
    #[must_use]
    pub const fn changed(&self) -> bool {
        self.restored > 0 || self.removed > 0
    }
}

/// Read a journal document and refuse one this build cannot judge.
///
/// # Errors
///
/// Returns a conflict carrying [`RULE_ROLLBACK_JOURNAL`] for a document that is
/// not UTF-8, not a journal of this schema, has no entries, or names a path that
/// could escape the repository root.
pub fn parse_journal(bytes: &[u8]) -> Result<Journal, AxiomError> {
    let malformed = |observed: String| {
        refuse(
            RULE_ROLLBACK_JOURNAL,
            "the rollback journal is not readable",
        )
        .with_detail("field", "journal")
        .with_detail("observed", observed)
    };
    let text = std::str::from_utf8(bytes).map_err(|error| malformed(error.to_string()))?;
    let journal: Journal =
        serde_json::from_str(text).map_err(|error| malformed(error.to_string()))?;
    if journal.schema_version != apply::JOURNAL_SCHEMA_VERSION {
        return Err(malformed(format!(
            "schema_version={}",
            journal.schema_version
        )));
    }
    if journal.entries.is_empty() {
        return Err(malformed("entries=0".to_owned()));
    }
    for entry in &journal.entries {
        if !is_safe_relative(&entry.path) {
            return Err(malformed(format!("path={}", entry.path)));
        }
    }
    Ok(journal)
}

/// Decide what rolling `journal` back would do, without writing anything.
///
/// The approved digest must equal the journal's own plan digest. Each file is
/// then judged against the bytes on the host *now*: the before-state means it is
/// already restored, the after-state means it may be restored (with its backup
/// verified first), and anything else is a later edit that rollback refuses to
/// discard.
///
/// # Errors
///
/// Returns [`RULE_ROLLBACK_DIGEST`] for an unapproved digest,
/// [`RULE_ROLLBACK_JOURNAL`] for a path that escapes the repository root,
/// [`RULE_ROLLBACK_LATER_EDIT`] or [`RULE_ROLLBACK_OWNERSHIP`] for a file that
/// changed after the write, [`RULE_ROLLBACK_BACKUP_MISSING`] for an absent
/// backup and [`RULE_ROLLBACK_BACKUP`] for a backup that no longer matches.
pub fn plan_rollback(
    journal: &Journal,
    approved_digest: &str,
    host: &dyn BootstrapHost,
) -> Result<RollbackPlan, AxiomError> {
    if approved_digest.is_empty() || approved_digest != journal.plan_digest {
        return Err(refuse(
            RULE_ROLLBACK_DIGEST,
            "a rollback requires the digest of the plan it undoes",
        )
        .with_detail("field", "plan_digest")
        .with_detail("observed", approved_digest));
    }

    let mut entries = Vec::with_capacity(journal.entries.len());
    for entry in &journal.entries {
        let path = resolve(&journal.root, &entry.path)?;
        let current = host.read(&path)?;
        let current_hash = current.as_deref().map(sha256_hex);
        let action = if current_hash == entry.before_sha256 {
            RollbackAction::AlreadyBefore
        } else if current_hash.as_deref() != Some(entry.after_sha256.as_str()) {
            return Err(later_edit(entry, current_hash.as_deref()));
        } else if entry.before_sha256.is_none() {
            RollbackAction::Remove
        } else {
            let bytes = backup_bytes(host, &entry.path, entry.backup.as_deref())?;
            let observed = sha256_hex(&bytes);
            if Some(observed.as_str()) != entry.before_sha256.as_deref() {
                return Err(backup_mismatch(
                    &entry.path,
                    entry.before_sha256.as_deref(),
                    &observed,
                ));
            }
            RollbackAction::Restore
        };
        entries.push(RollbackEntry {
            path: entry.path.clone(),
            action,
            before_sha256: entry.before_sha256.clone(),
            after_sha256: entry.after_sha256.clone(),
            backup: entry.backup.clone(),
        });
    }

    Ok(RollbackPlan {
        repository_id: journal.repository_id.clone(),
        root: journal.root.clone(),
        approved_digest: approved_digest.to_owned(),
        entries,
    })
}

/// Carry out an approved rollback plan and mark the journal `rolled_back`.
///
/// Every entry is re-checked immediately before it is written, so a human edit
/// that lands between planning and writing is still refused rather than
/// overwritten. Files are written in reverse journal order - the ownership
/// manifest, written last by apply, is restored first - and the journal is left
/// recording that this change was undone.
///
/// # Errors
///
/// Returns the same refusals as [`plan_rollback`] plus the write failure of the
/// host, and [`RULE_ROLLBACK_JOURNAL`] when the journal cannot be updated.
pub fn rollback_repository(
    host: &dyn BootstrapHost,
    journal_path: &Path,
    journal: &Journal,
    plan: &RollbackPlan,
) -> Result<RollbackReport, AxiomError> {
    let mut report = RollbackReport {
        repository_id: plan.repository_id.clone(),
        restored: 0,
        removed: 0,
        already_before: plan.already_before(),
        state: JournalState::RolledBack,
    };

    let writes: Vec<&RollbackEntry> = plan
        .entries
        .iter()
        .filter(|entry| entry.action != RollbackAction::AlreadyBefore)
        .collect();
    for entry in writes.iter().rev() {
        let path = resolve(&plan.root, &entry.path)?;
        let current = host.read(&path)?;
        let observed = current.as_deref().map(sha256_hex);
        if observed.as_deref() != Some(entry.after_sha256.as_str()) {
            return Err(later_edit_at(observed.as_deref(), entry));
        }
        match entry.action {
            RollbackAction::Restore => {
                let bytes = backup_bytes(host, &entry.path, entry.backup.as_deref())?;
                let observed = sha256_hex(&bytes);
                if Some(observed.as_str()) != entry.before_sha256.as_deref() {
                    return Err(backup_mismatch(
                        &entry.path,
                        entry.before_sha256.as_deref(),
                        &observed,
                    ));
                }
                host.write_atomic(&path, &bytes)?;
                report.restored += 1;
            }
            RollbackAction::Remove => {
                host.remove_file(&path)?;
                report.removed += 1;
            }
            RollbackAction::AlreadyBefore => {}
        }
    }

    let mut updated = journal.clone();
    updated.state = JournalState::RolledBack;
    // The same `serde_json` encoding `apply` writes with, so a journal
    // re-encoded here is byte-identical to the one apply wrote.
    let bytes = serde_json::to_vec(&updated).map_err(|error| {
        refuse(
            RULE_ROLLBACK_JOURNAL,
            format!("cannot encode the journal: {error}"),
        )
    })?;
    if let Some(parent) = journal_path.parent() {
        host.create_dir_all(parent)?;
    }
    host.write_atomic(journal_path, &bytes)?;

    Ok(report)
}

/// The verified before-bytes of one entry.
fn backup_bytes(
    host: &dyn BootstrapHost,
    path: &str,
    backup: Option<&str>,
) -> Result<Vec<u8>, AxiomError> {
    let Some(backup) = backup else {
        return Err(backup_missing(path));
    };
    host.read(Path::new(backup))?
        .ok_or_else(|| backup_missing(path))
}

/// Resolve a journal path against the repository root, refusing an escape.
fn resolve(root: &str, relative: &str) -> Result<PathBuf, AxiomError> {
    if !is_safe_relative(relative) {
        return Err(refuse(
            RULE_ROLLBACK_JOURNAL,
            format!("refusing the unsafe journal path {relative}"),
        )
        .with_detail("field", "path")
        .with_detail("observed", relative));
    }
    Ok(Path::new(root).join(relative))
}

/// Whether `path` is a repository-relative path with no escape.
#[must_use]
pub fn is_safe_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains(['\\', ':'])
        && !path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

/// The refusal for a file that moved after the installer wrote it.
fn later_edit(entry: &super::apply::JournalEntry, observed: Option<&str>) -> AxiomError {
    let rule = if entry.path == ownership::OWNERSHIP_PATH {
        RULE_ROLLBACK_OWNERSHIP
    } else {
        RULE_ROLLBACK_LATER_EDIT
    };
    refuse(
        rule,
        format!(
            "{} changed after the write; refusing to overwrite it with the backup",
            entry.path
        ),
    )
    .with_detail("portable_path", &entry.path)
    .with_detail("expected", entry.after_sha256.as_str())
    .with_detail("observed", observed.unwrap_or("absent"))
}

/// The refusal for a file that moved between planning and writing.
fn later_edit_at(observed: Option<&str>, entry: &RollbackEntry) -> AxiomError {
    let rule = if entry.is_ownership() {
        RULE_ROLLBACK_OWNERSHIP
    } else {
        RULE_ROLLBACK_LATER_EDIT
    };
    refuse(
        rule,
        format!(
            "{} changed during the rollback; refusing to overwrite it",
            entry.path
        ),
    )
    .with_detail("portable_path", &entry.path)
    .with_detail("expected", entry.after_sha256.as_str())
    .with_detail("observed", observed.unwrap_or("absent"))
}

/// The refusal for a backup that is absent.
fn backup_missing(path: &str) -> AxiomError {
    refuse(
        RULE_ROLLBACK_BACKUP_MISSING,
        format!("the backup for {path} is missing"),
    )
    .with_detail("portable_path", path)
}

/// The refusal for a backup that no longer matches the recorded before-hash.
fn backup_mismatch(path: &str, expected: Option<&str>, observed: &str) -> AxiomError {
    refuse(
        RULE_ROLLBACK_BACKUP,
        format!("the backup for {path} no longer matches the recorded before-state"),
    )
    .with_detail("portable_path", path)
    .with_detail("expected", expected.unwrap_or("absent"))
    .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::apply::{JournalEntry, MemoryBootstrapHost, JOURNAL_SCHEMA_VERSION};
    use crate::bootstrap::plan::AGENTS_PATH;
    use crate::bootstrap::policy::POLICY_PATH;
    use std::path::{Path, PathBuf};

    fn root() -> &'static str {
        "/repos/demo"
    }

    fn backup(name: &str) -> String {
        format!("/backups/demo/{name}")
    }

    fn journal_of(entries: Vec<JournalEntry>) -> Journal {
        Journal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            repository_id: "demo".to_owned(),
            root: root().to_owned(),
            plan_digest: "plan-digest".to_owned(),
            state: JournalState::Complete,
            entries,
        }
    }

    fn write_current(host: &MemoryBootstrapHost, path: &str, bytes: &[u8]) {
        host.add_file(Path::new(root()).join(path), bytes.to_vec());
    }

    fn current(host: &MemoryBootstrapHost, path: &str) -> Option<Vec<u8>> {
        host.file(&Path::new(root()).join(path))
    }

    fn rule_of(error: &AxiomError) -> Option<String> {
        error.details().get("rule").cloned()
    }

    /// AC1 positive: every file whose current hash still equals the after-hash
    /// is put back from its verified backup (or removed when it did not exist
    /// before), the journal records the rollback, and rolling the same journal
    /// back again is a no-op.
    #[test]
    fn a_rollback_restores_the_after_state_and_marks_the_journal() {
        let host = MemoryBootstrapHost::new();
        let agents_before = b"# Human\n";
        let agents_after = b"# Human\n<!-- axiom-graph:begin -->\n";
        let policy_after = b"# Managed policy\n";
        let lock_before = b"{\"template_version\":\"1.0.0\"}\n";
        let lock_after = b"{\"template_version\":\"2.0.0-draft.1\"}\n";

        write_current(&host, AGENTS_PATH, agents_after);
        write_current(&host, POLICY_PATH, policy_after);
        write_current(&host, ownership::OWNERSHIP_PATH, lock_after);
        host.add_file(PathBuf::from(backup("AGENTS.md")), agents_before.to_vec());
        host.add_file(
            PathBuf::from(backup("bootstrap.lock.json")),
            lock_before.to_vec(),
        );

        let journal = journal_of(vec![
            JournalEntry {
                path: AGENTS_PATH.to_owned(),
                before_sha256: Some(sha256_hex(agents_before)),
                after_sha256: sha256_hex(agents_after),
                backup: Some(backup("AGENTS.md")),
            },
            JournalEntry {
                path: POLICY_PATH.to_owned(),
                before_sha256: None,
                after_sha256: sha256_hex(policy_after),
                backup: None,
            },
            JournalEntry {
                path: ownership::OWNERSHIP_PATH.to_owned(),
                before_sha256: Some(sha256_hex(lock_before)),
                after_sha256: sha256_hex(lock_after),
                backup: Some(backup("bootstrap.lock.json")),
            },
        ]);

        let plan = plan_rollback(&journal, "plan-digest", &host).expect("rollback plans");
        assert_eq!(plan.writes(), 3);
        assert_eq!(plan.already_before(), 0);
        assert_eq!(plan.entries[0].action, RollbackAction::Restore);
        assert_eq!(plan.entries[1].action, RollbackAction::Remove);
        assert_eq!(plan.entries[1].action.as_str(), "remove");
        assert_eq!(plan.entries[2].action, RollbackAction::Restore);
        assert_eq!(
            plan.ownership_entry().map(|entry| entry.path.as_str()),
            Some(ownership::OWNERSHIP_PATH)
        );
        assert!(plan.render().contains("remove .axiom/agent/POLICY.md"));

        let home = Path::new("/axiom-home");
        let path = apply::journal_path(home, "demo");
        let report = rollback_repository(&host, &path, &journal, &plan).expect("rollback runs");
        assert_eq!(report.restored, 2);
        assert_eq!(report.removed, 1);
        assert_eq!(report.already_before, 0);
        assert!(report.changed());
        assert_eq!(report.state, JournalState::RolledBack);

        assert_eq!(current(&host, AGENTS_PATH), Some(agents_before.to_vec()));
        assert_eq!(
            current(&host, ownership::OWNERSHIP_PATH),
            Some(lock_before.to_vec()),
            "the manifest is restored from its backup"
        );
        assert_eq!(
            current(&host, POLICY_PATH),
            None,
            "a created file is removed because it has no before-state"
        );

        let bytes = host
            .file(&path)
            .expect("the rolled-back journal is written");
        let written = parse_journal(&bytes).expect("the journal is still readable");
        assert_eq!(written.state, JournalState::RolledBack);
        assert_eq!(written.entries.len(), 3);
        assert_eq!(written.plan_digest, "plan-digest");

        // Boundary: the same journal rolled back twice changes nothing.
        let again = plan_rollback(&journal, "plan-digest", &host).expect("replans");
        assert_eq!(again.writes(), 0);
        assert_eq!(again.already_before(), 3);
        let report = rollback_repository(&host, &path, &journal, &again).expect("no-op rollback");
        assert!(!report.changed());
        assert_eq!(report.restored, 0);
        assert_eq!(report.removed, 0);
        assert_eq!(current(&host, POLICY_PATH), None);
    }

    /// AC1 negative: a file a human changed after the write is refused, left
    /// exactly as the human left it, and never replaced by the backup. The
    /// ownership manifest is judged the same way under its own rule.
    #[test]
    fn a_later_human_edit_is_refused_and_preserved() {
        let after = b"written by the installer\n";
        let human = b"the human edited this afterwards\n";
        let before = b"before\n";

        let host = MemoryBootstrapHost::new();
        write_current(&host, AGENTS_PATH, human);
        host.add_file(PathBuf::from(backup("AGENTS.md")), before.to_vec());
        let journal = journal_of(vec![JournalEntry {
            path: AGENTS_PATH.to_owned(),
            before_sha256: Some(sha256_hex(before)),
            after_sha256: sha256_hex(after),
            backup: Some(backup("AGENTS.md")),
        }]);
        let error = plan_rollback(&journal, "plan-digest", &host).expect_err("refused");
        assert_eq!(rule_of(&error).as_deref(), Some(RULE_ROLLBACK_LATER_EDIT));
        assert_eq!(current(&host, AGENTS_PATH), Some(human.to_vec()));

        let host = MemoryBootstrapHost::new();
        write_current(&host, ownership::OWNERSHIP_PATH, human);
        host.add_file(
            PathBuf::from(backup("bootstrap.lock.json")),
            before.to_vec(),
        );
        let journal = journal_of(vec![JournalEntry {
            path: ownership::OWNERSHIP_PATH.to_owned(),
            before_sha256: Some(sha256_hex(before)),
            after_sha256: sha256_hex(after),
            backup: Some(backup("bootstrap.lock.json")),
        }]);
        let error = plan_rollback(&journal, "plan-digest", &host).expect_err("refused");
        assert_eq!(
            rule_of(&error).as_deref(),
            Some(RULE_ROLLBACK_OWNERSHIP),
            "the ownership manifest reports drift under its own rule"
        );
        assert_eq!(
            current(&host, ownership::OWNERSHIP_PATH),
            Some(human.to_vec())
        );
    }

    /// AC2 negative: an edit that lands between planning and writing is caught
    /// again immediately before the write, and the journal is not rewritten.
    #[test]
    fn an_edit_between_planning_and_writing_is_still_refused() {
        let before = b"before\n";
        let after = b"after\n";
        let human = b"edited between plan and write\n";

        let host = MemoryBootstrapHost::new();
        write_current(&host, AGENTS_PATH, after);
        host.add_file(PathBuf::from(backup("AGENTS.md")), before.to_vec());
        let journal = journal_of(vec![JournalEntry {
            path: AGENTS_PATH.to_owned(),
            before_sha256: Some(sha256_hex(before)),
            after_sha256: sha256_hex(after),
            backup: Some(backup("AGENTS.md")),
        }]);

        let plan = plan_rollback(&journal, "plan-digest", &host).expect("rollback plans");
        // The human edits the file after the plan was reviewed and approved.
        write_current(&host, AGENTS_PATH, human);

        let path = apply::journal_path(Path::new("/axiom-home"), "demo");
        let error = rollback_repository(&host, &path, &journal, &plan).expect_err("refused");
        assert_eq!(rule_of(&error).as_deref(), Some(RULE_ROLLBACK_LATER_EDIT));
        assert_eq!(current(&host, AGENTS_PATH), Some(human.to_vec()));
        assert!(
            !host.contains(&path),
            "the journal is not rewritten when a write is refused"
        );
    }

    /// AC2 negative/boundary: an unapproved digest, a missing backup and a
    /// backup that no longer matches the recorded before-state are each refused
    /// before anything is written.
    #[test]
    fn an_unapproved_digest_and_a_broken_backup_are_refused() {
        let before = b"before\n";
        let after = b"after\n";

        let host = MemoryBootstrapHost::new();
        write_current(&host, AGENTS_PATH, after);
        host.add_file(PathBuf::from(backup("AGENTS.md")), before.to_vec());
        let journal = journal_of(vec![JournalEntry {
            path: AGENTS_PATH.to_owned(),
            before_sha256: Some(sha256_hex(before)),
            after_sha256: sha256_hex(after),
            backup: Some(backup("AGENTS.md")),
        }]);

        let error = plan_rollback(&journal, "not-the-approved-digest", &host).expect_err("refused");
        assert_eq!(rule_of(&error).as_deref(), Some(RULE_ROLLBACK_DIGEST));
        let error = plan_rollback(&journal, "", &host).expect_err("refused");
        assert_eq!(rule_of(&error).as_deref(), Some(RULE_ROLLBACK_DIGEST));

        // A backup that is absent.
        let host = MemoryBootstrapHost::new();
        write_current(&host, AGENTS_PATH, after);
        let error = plan_rollback(&journal, "plan-digest", &host).expect_err("refused");
        assert_eq!(
            rule_of(&error).as_deref(),
            Some(RULE_ROLLBACK_BACKUP_MISSING)
        );

        // A backup that no longer hashes to the recorded before-state.
        let host = MemoryBootstrapHost::new();
        write_current(&host, AGENTS_PATH, after);
        host.add_file(
            PathBuf::from(backup("AGENTS.md")),
            b"tampered backup\n".to_vec(),
        );
        let error = plan_rollback(&journal, "plan-digest", &host).expect_err("refused");
        assert_eq!(rule_of(&error).as_deref(), Some(RULE_ROLLBACK_BACKUP));

        // Nothing was written by any of the refusals.
        assert_eq!(current(&host, AGENTS_PATH), Some(after.to_vec()));
    }

    /// AC2 boundary: a journal this build cannot judge is refused outright.
    #[test]
    fn a_journal_this_build_cannot_judge_is_refused() {
        let good = journal_of(vec![JournalEntry {
            path: AGENTS_PATH.to_owned(),
            before_sha256: None,
            after_sha256: sha256_hex(b"x"),
            backup: None,
        }]);
        assert_eq!(
            parse_journal(&serde_json::to_vec(&good).expect("encode"))
                .expect("a journal of this schema parses")
                .entries
                .len(),
            1
        );

        let mut wrong = good.clone();
        wrong.schema_version = JOURNAL_SCHEMA_VERSION + 1;
        let bytes = serde_json::to_vec(&wrong).expect("encode");
        assert_eq!(
            rule_of(&parse_journal(&bytes).expect_err("refused")).as_deref(),
            Some(RULE_ROLLBACK_JOURNAL)
        );

        let mut empty = good.clone();
        empty.entries.clear();
        let bytes = serde_json::to_vec(&empty).expect("encode");
        assert_eq!(
            rule_of(&parse_journal(&bytes).expect_err("refused")).as_deref(),
            Some(RULE_ROLLBACK_JOURNAL)
        );

        let mut escape = good.clone();
        escape.entries[0].path = "../escape.md".to_owned();
        let bytes = serde_json::to_vec(&escape).expect("encode");
        assert_eq!(
            rule_of(&parse_journal(&bytes).expect_err("refused")).as_deref(),
            Some(RULE_ROLLBACK_JOURNAL)
        );

        assert_eq!(
            rule_of(&parse_journal(b"not a journal").expect_err("refused")).as_deref(),
            Some(RULE_ROLLBACK_JOURNAL)
        );

        assert!(is_safe_relative("AGENTS.md"));
        assert!(is_safe_relative(".axiom/agent/POLICY.md"));
        assert!(!is_safe_relative(""));
        assert!(!is_safe_relative("/absolute"));
        assert!(!is_safe_relative("trailing/"));
        assert!(!is_safe_relative("a/../b"));
        assert!(!is_safe_relative("a//b"));
        assert!(!is_safe_relative("C:/windows"));
        assert!(!is_safe_relative("a\\b"));
    }
}
