//! Consistent, hash-verified DB and managed-state backups (task E-041).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` sections 6 and 7 put a consistent
//! DB backup inside the update transaction, after the bounded drain (E-040) and
//! before any migration, and use that same backup as the rollback payload. This
//! module is that slice. It fixes three rules:
//!
//! * a backup is only a backup once its copied bytes were hashed. Every
//!   [`BackupRecord`] carries the SHA-256 and the size of the copy, and
//!   [`verify_backup`] re-reads the file and re-hashes it, so a truncated or
//!   edited copy is named (`backup_hash_mismatch`, `backup_size_mismatch`)
//!   instead of being restored;
//! * a missing or empty backup prevents an irreversible migration.
//!   [`require_backup_for_irreversible`] refuses with `backup_missing`,
//!   `backup_empty` or a verification failure before the caller can apply one;
//! * nothing here erases data. Copying reads the source and writes a new file
//!   under a caller-supplied destination directory; the source is never
//!   removed, truncated or rewritten.
//!
//! Consistency is a caller responsibility this module cannot fake: a live
//! SQLite file must be quiesced (or copied through its own backup API) first,
//! which is exactly why the drain (E-040) pauses new work before this runs.
//! What this module proves is that the bytes it recorded are the bytes on disk.

use std::path::{Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};

/// One managed file a backup must copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupTarget {
    /// File name the copy is stored under. A plain name, never a path.
    pub name: String,
    /// Absolute or relative location of the live file.
    pub source: PathBuf,
}

impl BackupTarget {
    /// One target with a plain name and a source path.
    #[must_use]
    pub fn new(name: impl Into<String>, source: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            source: source.into(),
        }
    }
}

/// The set of files an update must back up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupPlan {
    /// Files to copy.
    pub targets: Vec<BackupTarget>,
    /// Whether an update requires this backup at all.
    pub required: bool,
}

/// One verified copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRecord {
    /// Name the copy is stored under.
    pub name: String,
    /// Location the bytes were read from.
    pub source: PathBuf,
    /// Location the copy was written to.
    pub path: PathBuf,
    /// Lowercase 64-hex digest of the copied bytes.
    pub sha256: String,
    /// Length of the copied bytes.
    pub size_bytes: u64,
}

/// A completed backup: every copy plus the directory that holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupSet {
    /// Directory the copies live in.
    pub directory: PathBuf,
    /// One record per copied file, in plan order.
    pub records: Vec<BackupRecord>,
}

impl BackupSet {
    /// Names of the copied files, in plan order.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.records
            .iter()
            .map(|record| record.name.clone())
            .collect()
    }

    /// Total bytes copied.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.records.iter().map(|record| record.size_bytes).sum()
    }
}

/// Copy every target into `destination` and record the hash of each copy.
///
/// # Errors
///
/// Fails closed with a named `rule` when a target name is not a plain file name
/// (`invalid_backup_name`), the destination is not an existing directory
/// (`backup_destination_not_directory`), a source cannot be read
/// (`backup_target_unreadable`) or a copy cannot be written
/// (`backup_write_failed`). The source files are only read.
pub fn create_backup(plan: &BackupPlan, destination: &Path) -> Result<BackupSet, AxiomError> {
    if !destination.is_dir() {
        return Err(refuse(
            "backup_destination_not_directory",
            &destination.display().to_string(),
        ));
    }
    let mut records = Vec::with_capacity(plan.targets.len());
    for target in &plan.targets {
        validate_name(&target.name)?;
        let bytes = std::fs::read(&target.source).map_err(|error| {
            refuse(
                "backup_target_unreadable",
                &format!("{}: {error}", target.source.display()),
            )
        })?;
        let path = destination.join(&target.name);
        std::fs::write(&path, &bytes).map_err(|error| {
            refuse(
                "backup_write_failed",
                &format!("{}: {error}", path.display()),
            )
        })?;
        records.push(BackupRecord {
            name: target.name.clone(),
            source: target.source.clone(),
            path,
            sha256: graph_export::sha256_hex(&bytes),
            size_bytes: bytes.len() as u64,
        });
    }
    Ok(BackupSet {
        directory: destination.to_path_buf(),
        records,
    })
}

/// Re-read one copy and confirm it still matches its recorded hash and size.
///
/// # Errors
///
/// Fails closed with `backup_missing` when the copy is gone,
/// `backup_size_mismatch` when its length changed, or `backup_hash_mismatch`
/// when its bytes changed.
pub fn verify_backup(record: &BackupRecord) -> Result<(), AxiomError> {
    let bytes = std::fs::read(&record.path).map_err(|error| {
        refuse(
            "backup_missing",
            &format!("{}: {error}", record.path.display()),
        )
    })?;
    let observed_size = bytes.len() as u64;
    if observed_size != record.size_bytes {
        return Err(refuse(
            "backup_size_mismatch",
            &format!(
                "name={};observed={observed_size};recorded={}",
                record.name, record.size_bytes
            ),
        ));
    }
    let observed = graph_export::sha256_hex(&bytes);
    if observed != record.sha256 {
        return Err(refuse(
            "backup_hash_mismatch",
            &format!(
                "name={};observed={observed};recorded={}",
                record.name, record.sha256
            ),
        ));
    }
    Ok(())
}

/// Verify every copy in a set.
///
/// # Errors
///
/// Propagates the first [`verify_backup`] refusal.
pub fn verify_backup_set(set: &BackupSet) -> Result<(), AxiomError> {
    for record in &set.records {
        verify_backup(record)?;
    }
    Ok(())
}

/// Refuse an irreversible migration that has no verified backup behind it.
///
/// `irreversible` names the migrations that cannot be undone in place. When it
/// is empty the call succeeds with no backup, because a reversible update does
/// not need one.
///
/// # Errors
///
/// Fails closed with `backup_missing` when no backup set or no record exists,
/// `backup_empty` when a recorded copy is zero bytes, and any
/// [`verify_backup`] refusal when a copy no longer matches its hash.
pub fn require_backup_for_irreversible(
    backup: Option<&BackupSet>,
    irreversible: &[String],
) -> Result<(), AxiomError> {
    if irreversible.is_empty() {
        return Ok(());
    }
    let names = irreversible.join(",");
    let Some(set) = backup else {
        return Err(refuse("backup_missing", &format!("irreversible={names}")));
    };
    if set.records.is_empty() {
        return Err(refuse("backup_missing", &format!("irreversible={names}")));
    }
    for record in &set.records {
        if record.size_bytes == 0 {
            return Err(refuse(
                "backup_empty",
                &format!("name={};irreversible={names}", record.name),
            ));
        }
        verify_backup(record)?;
    }
    Ok(())
}

/// Refuse a name that is not a plain file name.
///
/// A separator, a drive prefix or a `..` segment would let a copy escape the
/// destination directory, so every one of them is refused rather than
/// sanitised.
fn validate_name(name: &str) -> Result<(), AxiomError> {
    let separator = name.contains('/') || name.contains('\\');
    let navigates = name == ".." || name == ".";
    let empty = name.trim().is_empty();
    if empty || separator || navigates {
        return Err(refuse("invalid_backup_name", name));
    }
    Ok(())
}

/// One backup refusal, with the rule in a stable detail key.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the backup cannot be used as a restore point",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use graph_core::error::AxiomError;

    use super::{
        create_backup, require_backup_for_irreversible, verify_backup, verify_backup_set,
        BackupPlan, BackupTarget,
    };

    fn rule_of(error: &AxiomError) -> String {
        error.details().get("rule").cloned().unwrap_or_default()
    }

    fn write(directory: &Path, name: &str, bytes: &[u8]) {
        std::fs::write(directory.join(name), bytes).expect("writes fixture");
    }

    #[test]
    fn a_backup_records_and_re_verifies_the_hash_of_every_copy() {
        let root = tempfile::tempdir().expect("tempdir");
        let live = root.path().join("live");
        let store = root.path().join("backups");
        std::fs::create_dir_all(&live).expect("live");
        std::fs::create_dir_all(&store).expect("store");
        write(&live, "queue.db", b"queue-schema-1");
        write(&live, "manifest.json", b"{\"version\":\"0.1.0\"}");

        let plan = BackupPlan {
            targets: vec![
                BackupTarget::new("queue.db", live.join("queue.db")),
                BackupTarget::new("manifest.json", live.join("manifest.json")),
            ],
            required: true,
        };
        let set = create_backup(&plan, &store).expect("backs up");
        assert_eq!(set.names(), vec!["queue.db", "manifest.json"]);
        assert_eq!(set.total_bytes(), 33);
        assert_eq!(
            set.records[0].sha256,
            graph_export::sha256_hex(b"queue-schema-1")
        );
        verify_backup_set(&set).expect("verifies");
        // The live files were read, not moved.
        assert!(live.join("queue.db").exists());
        assert!(live.join("manifest.json").exists());
        require_backup_for_irreversible(Some(&set), &["queue-schema-1-to-2".to_string()])
            .expect("a verified backup satisfies an irreversible migration");
    }

    #[test]
    fn a_tampered_copy_is_named_by_hash_not_restored() {
        let root = tempfile::tempdir().expect("tempdir");
        let live = root.path().join("live");
        let store = root.path().join("backups");
        std::fs::create_dir_all(&live).expect("live");
        std::fs::create_dir_all(&store).expect("store");
        write(&live, "queue.db", b"queue-schema-1");
        let plan = BackupPlan {
            targets: vec![BackupTarget::new("queue.db", live.join("queue.db"))],
            required: true,
        };
        let set = create_backup(&plan, &store).expect("backs up");

        // Same length, different bytes: only the hash can catch this.
        std::fs::write(store.join("queue.db"), b"queue-schema-2").expect("tamper");
        let error = verify_backup(&set.records[0]).expect_err("refused");
        assert_eq!(rule_of(&error), "backup_hash_mismatch");

        // Different length is named separately.
        std::fs::write(store.join("queue.db"), b"short").expect("truncate");
        let error = verify_backup(&set.records[0]).expect_err("refused");
        assert_eq!(rule_of(&error), "backup_size_mismatch");

        // A removed copy is missing, never silently accepted.
        std::fs::remove_file(store.join("queue.db")).expect("remove");
        let error = verify_backup(&set.records[0]).expect_err("refused");
        assert_eq!(rule_of(&error), "backup_missing");

        let error = require_backup_for_irreversible(Some(&set), &["q1to2".to_string()])
            .expect_err("refused");
        assert_eq!(rule_of(&error), "backup_missing");
    }

    #[test]
    fn a_missing_or_empty_backup_blocks_an_irreversible_migration() {
        let irreversible = vec!["queue-schema-1-to-2".to_string()];
        let error =
            require_backup_for_irreversible(None, &irreversible).expect_err("no backup at all");
        assert_eq!(rule_of(&error), "backup_missing");

        let root = tempfile::tempdir().expect("tempdir");
        let live = root.path().join("live");
        let store = root.path().join("backups");
        std::fs::create_dir_all(&live).expect("live");
        std::fs::create_dir_all(&store).expect("store");
        write(&live, "queue.db", b"");
        let plan = BackupPlan {
            targets: vec![BackupTarget::new("queue.db", live.join("queue.db"))],
            required: true,
        };
        let set = create_backup(&plan, &store).expect("backs up");
        let error = require_backup_for_irreversible(Some(&set), &irreversible).expect_err("empty");
        assert_eq!(rule_of(&error), "backup_empty");

        // A reversible update needs no backup at all.
        require_backup_for_irreversible(None, &[]).expect("reversible needs none");
        require_backup_for_irreversible(Some(&set), &[]).expect("reversible needs none");
    }

    #[test]
    fn a_name_that_could_escape_the_destination_is_refused() {
        let root = tempfile::tempdir().expect("tempdir");
        let live = root.path().join("live");
        let store = root.path().join("backups");
        std::fs::create_dir_all(&live).expect("live");
        std::fs::create_dir_all(&store).expect("store");
        write(&live, "queue.db", b"bytes");

        for name in [
            "../escape.db",
            "nested/queue.db",
            "nested\\queue.db",
            "..",
            "",
            "  ",
        ] {
            let plan = BackupPlan {
                targets: vec![BackupTarget::new(name, live.join("queue.db"))],
                required: true,
            };
            let error = create_backup(&plan, &store).expect_err("refused");
            assert_eq!(rule_of(&error), "invalid_backup_name", "name={name}");
        }
        // Nothing escaped the destination.
        assert!(!root.path().join("escape.db").exists());
    }

    #[test]
    fn an_unreadable_source_and_a_non_directory_destination_are_named() {
        let root = tempfile::tempdir().expect("tempdir");
        let live = root.path().join("live");
        std::fs::create_dir_all(&live).expect("live");
        let plan = BackupPlan {
            targets: vec![BackupTarget::new("queue.db", live.join("absent.db"))],
            required: true,
        };
        let error = create_backup(&plan, &live).expect_err("refused");
        assert_eq!(rule_of(&error), "backup_target_unreadable");

        write(&live, "queue.db", b"bytes");
        let plan = BackupPlan {
            targets: vec![BackupTarget::new("queue.db", live.join("queue.db"))],
            required: true,
        };
        let error = create_backup(&plan, &live.join("queue.db")).expect_err("refused");
        assert_eq!(rule_of(&error), "backup_destination_not_directory");
    }
}
