//! Journaled migration application with writer fencing (V2-011) and rollback
//! with coexistence rejection (V2-012).
//!
//! [crate::plan] decides *what* one reviewed V1 to V2 migration may write and
//! refuses to authorise a plan whose inputs moved underneath it. This module
//! performs those writes through the staged cutover that migrations/V1-TO-V2.md
//! section 3 requires, and records every step in a journal so an interrupted run
//! is resumable instead of mysterious:
//!
//! 1. **fence** - the old publisher must be stopped and proven quiescent before
//!    a single destination byte is touched, because the destination and the old
//!    writer may never publish concurrently;
//! 2. **backup** - the owned bytes at each destination are copied aside, and the
//!    copy is verified against the hash the plan recorded before it is accepted
//!    as a rollback point;
//! 3. **stage** - the new bytes are written beside the destination and read back
//!    byte-for-byte;
//! 4. **verify** - the staged bytes and the destination precondition are checked
//!    a second time, immediately before cutover;
//! 5. **cutover** - each destination is replaced, one file at a time, with the
//!    journal recorded after each file;
//! 6. **complete** - the journal is closed.
//!
//! Every phase boundary is persisted, so a failure at any boundary leaves a
//! journal that says exactly how far the run got, and a later run resumes from
//! that journal instead of re-deciding. A file that is already cut over is
//! recognised by its hash, so a resume never rewrites it; a failure during
//! cutover restores the pre-cutover bytes from the verified backups. A
//! destination that a human changed after cutover is never overwritten by that
//! restore: the run reports the blocking path and asks for a human instead.
//!
//! [check_coexistence] refuses the plan before the fence when any destination
//! would keep the legacy and the V2 layout both live, and [rollback_journaled]
//! undoes a completed or an interrupted cutover from the same journal, restoring
//! each verified backup and discarding each staged copy while leaving a
//! destination that a human changed after cutover exactly as it is.
//!
//! As in the plan half, this module performs no filesystem access of its own.
//! The writer fence, the bytes and the journal are injected ([WriterFence],
//! [ApplyIo], [JournalStore]), so the policy is exercised for real in tests and
//! the native host stays the caller's choice.

use std::fmt;

use axiom_platform::PathKey;
use graph_core::error::{AxiomError, ErrorCode};

use crate::discover::{AXIOM_GRAPH_DIR, LEGACY_GRAPH_DIR, LEGACY_MISSPELLED_GRAPH_DIR};
use crate::plan::{
    is_portable_id, write_field, ChangeAction, ContentHash, CurrentSources, DestinationOwnership,
    MigrationPlan, PlanError, PlannedWrite,
};

/// The newline that terminates every encoded journal field.
const FIELD_NEWLINE: u8 = 10;

/// Schema version of the journal this module writes.
pub const APPLY_SCHEMA_VERSION: u32 = 1;

/// The journal's own first field, so a foreign document is refused, not parsed.
pub const JOURNAL_MAGIC: &str = "axiom-migration-apply-journal";

/// Stable code: the old writer could not be fenced, so nothing was written.
pub const ERR_FENCE_REFUSED: &str = "MIGRATION_WRITER_STILL_PUBLISHING";
/// Stable code: the bytes at a destination or in the staging area are not the
/// bytes the plan recorded.
pub const ERR_APPLY_HASH: &str = "MIGRATION_APPLY_HASH_MISMATCH";
/// Stable code: the destination state is not the state this cutover may start
/// from, and no destructive fallback was taken.
pub const ERR_APPLY_CONFLICT: &str = "MIGRATION_APPLY_CONFLICT";
/// Stable code: the journal could not be read, or does not describe this run.
pub const ERR_JOURNAL_INVALID: &str = "MIGRATION_JOURNAL_INVALID";
/// Stable code: recovery could not restore every file, so the run reports the
/// blocking paths instead of claiming an atomic undo.
pub const ERR_APPLY_INCOMPLETE: &str = "MIGRATION_APPLY_INCOMPLETE";
/// Stable code: the plan would leave the legacy and the V2 layout both live, so
/// applying it would dual-write one logical output.
pub const ERR_COEXISTENCE: &str = "MIGRATION_COEXISTENCE_REFUSED";
/// Stable code: the journal does not describe a cutover this run may undo.
pub const ERR_ROLLBACK: &str = "MIGRATION_ROLLBACK_REFUSED";
/// Stable code: a rollback could not restore every file, so the run reports the
/// blocking paths instead of claiming an atomic undo.
pub const ERR_ROLLBACK_BLOCKED: &str = "MIGRATION_ROLLBACK_BLOCKED";

/// One phase of the staged cutover, in the order it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ApplyPhase {
    /// The old publisher is stopped and proven quiescent.
    Fence,
    /// Existing owned bytes are copied aside and the copy is verified.
    Backup,
    /// New bytes are written beside the destination and read back.
    Stage,
    /// Staged bytes and destination preconditions are checked again.
    Verify,
    /// Destinations are replaced, one file at a time.
    Cutover,
    /// The journal is closed.
    Complete,
    /// The cutover was undone from its journal.
    Rollback,
}

impl ApplyPhase {
    /// Every phase, in order.
    pub const ORDER: [ApplyPhase; 7] = [
        ApplyPhase::Fence,
        ApplyPhase::Backup,
        ApplyPhase::Stage,
        ApplyPhase::Verify,
        ApplyPhase::Cutover,
        ApplyPhase::Complete,
        ApplyPhase::Rollback,
    ];

    /// Stable spelling used in journals and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fence => "fence",
            Self::Backup => "backup",
            Self::Stage => "stage",
            Self::Verify => "verify",
            Self::Cutover => "cutover",
            Self::Complete => "complete",
            Self::Rollback => "rollback",
        }
    }

    /// Parse the stable spelling, refusing anything else.
    ///
    /// # Errors
    /// [ApplyError::Journal] with rule unknown-phase when the spelling is not
    /// one of [ApplyPhase::ORDER].
    pub fn parse(value: &str) -> Result<Self, ApplyError> {
        Self::ORDER
            .into_iter()
            .find(|phase| phase.as_str() == value)
            .ok_or_else(|| ApplyError::journal("unknown-phase", value))
    }
}

impl fmt::Display for ApplyPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What the fence learned about the old publisher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceOutcome {
    quiescent: bool,
    publishers: Vec<String>,
}

impl FenceOutcome {
    /// The old publisher is stopped and quiescence is proven.
    #[must_use]
    pub const fn quiescent() -> Self {
        Self {
            quiescent: true,
            publishers: Vec::new(),
        }
    }

    /// The old publisher is still publishing; publishers names it.
    #[must_use]
    pub const fn still_publishing(publishers: Vec<String>) -> Self {
        Self {
            quiescent: false,
            publishers,
        }
    }

    /// Whether the cutover may proceed.
    #[must_use]
    pub const fn is_quiescent(&self) -> bool {
        self.quiescent
    }

    /// The participants that were still publishing, when any were.
    #[must_use]
    pub fn publishers(&self) -> &[String] {
        &self.publishers
    }
}

/// How far one destination file got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FileState {
    /// Nothing has been written for this file yet.
    Pending,
    /// The new bytes are staged beside the destination and read back.
    Staged,
    /// The staged bytes and the destination precondition were verified.
    Verified,
    /// The destination now holds the new bytes.
    Cutover,
}

impl FileState {
    /// Stable spelling used in journals.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Staged => "staged",
            Self::Verified => "verified",
            Self::Cutover => "cutover",
        }
    }

    /// Parse the stable spelling, refusing anything else.
    ///
    /// # Errors
    /// [ApplyError::Journal] with rule unknown-file-state for any other value.
    pub fn parse(value: &str) -> Result<Self, ApplyError> {
        match value {
            "pending" => Ok(Self::Pending),
            "staged" => Ok(Self::Staged),
            "verified" => Ok(Self::Verified),
            "cutover" => Ok(Self::Cutover),
            other => Err(ApplyError::journal("unknown-file-state", other)),
        }
    }
}

/// One destination file the journal tracks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalFile {
    repo_id: String,
    path: String,
    action: ChangeAction,
    source: Option<String>,
    staged: Option<String>,
    backup: Option<String>,
    expected_sha256: Option<ContentHash>,
    previous_sha256: Option<ContentHash>,
    state: FileState,
}

impl JournalFile {
    /// The repository this file belongs to.
    #[must_use]
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    /// The exact destination spelling.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// What the plan does to the destination.
    #[must_use]
    pub const fn action(&self) -> ChangeAction {
        self.action
    }

    /// The source the new bytes come from, when they come from a file.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }

    /// Where the new bytes were staged, once they were.
    #[must_use]
    pub fn staged(&self) -> Option<&str> {
        self.staged.as_deref()
    }

    /// Where the previous bytes were copied, once they were.
    #[must_use]
    pub fn backup(&self) -> Option<&str> {
        self.backup.as_deref()
    }

    /// The hash the new bytes must have, when the plan supplies bytes at all.
    #[must_use]
    pub const fn expected_sha256(&self) -> Option<&ContentHash> {
        match &self.expected_sha256 {
            Some(hash) => Some(hash),
            None => None,
        }
    }

    /// The hash of the bytes the destination held before this cutover.
    #[must_use]
    pub const fn previous_sha256(&self) -> Option<&ContentHash> {
        match &self.previous_sha256 {
            Some(hash) => Some(hash),
            None => None,
        }
    }

    /// How far this file got.
    #[must_use]
    pub const fn state(&self) -> FileState {
        self.state
    }
}

/// The resumable record of one application of one reviewed plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyJournal {
    schema_version: u32,
    solution_id: String,
    plan_digest: ContentHash,
    namespace: String,
    phase: ApplyPhase,
    fenced: bool,
    files: Vec<JournalFile>,
}

impl ApplyJournal {
    /// The journal a fresh run of this request starts from.
    ///
    /// # Errors
    /// [ApplyError::Plan] when the plan refuses authorisation, and whatever
    /// [ApplyJournal::for_authorized] refuses.
    pub fn for_plan(request: &ApplyRequest<'_>) -> Result<Self, ApplyError> {
        let authorized = request.plan.apply(
            request.reviewed_digest,
            request.current,
            request.now_seconds,
        )?;
        Self::for_authorized(request, &authorized)
    }

    /// The journal for an explicit set of authorised writes.
    ///
    /// # Errors
    /// [ApplyError::Refused] with code [ERR_APPLY_CONFLICT] when the namespace is
    /// not a portable id or a derived root is empty, and [ApplyError::Journal]
    /// when an authorised write cannot be traced back to the plan's inventory.
    pub fn for_authorized(
        request: &ApplyRequest<'_>,
        authorized: &[PlannedWrite],
    ) -> Result<Self, ApplyError> {
        if !is_portable_id(request.namespace) {
            return Err(ApplyError::refused(
                ERR_APPLY_CONFLICT,
                "namespace",
                None,
                format!("{:?} is not a portable output namespace", request.namespace),
            ));
        }
        if request.backup_root.is_empty() || request.staging_root.is_empty() {
            return Err(ApplyError::refused(
                ERR_APPLY_CONFLICT,
                "derived-root",
                None,
                "the backup and staging roots must be portable relative paths".to_string(),
            ));
        }
        let mut files = Vec::with_capacity(authorized.len());
        for write in authorized {
            let previous = previous_hash(request.plan, write.repo_id(), write.path())?;
            let expected = match write.source() {
                Some(source) => Some(source_hash(request.plan, write.repo_id(), source)?),
                None => None,
            };
            files.push(JournalFile {
                repo_id: write.repo_id().to_string(),
                path: write.path().to_string(),
                action: write.action(),
                source: write.source().map(str::to_string),
                staged: None,
                backup: None,
                expected_sha256: expected,
                previous_sha256: previous,
                state: FileState::Pending,
            });
        }
        Ok(Self {
            schema_version: APPLY_SCHEMA_VERSION,
            solution_id: request.plan.solution_id().to_string(),
            plan_digest: request.plan.digest().clone(),
            namespace: request.namespace.to_string(),
            phase: ApplyPhase::Fence,
            fenced: false,
            files,
        })
    }

    /// The schema version this journal was written with.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// The solution the journal belongs to.
    #[must_use]
    pub fn solution_id(&self) -> &str {
        &self.solution_id
    }

    /// The digest of the plan this journal applies.
    #[must_use]
    pub fn plan_digest(&self) -> &ContentHash {
        &self.plan_digest
    }

    /// The output namespace that was fenced.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The phase the run reached.
    #[must_use]
    pub const fn phase(&self) -> ApplyPhase {
        self.phase
    }

    /// Whether the old publisher was proven quiescent.
    #[must_use]
    pub const fn fenced(&self) -> bool {
        self.fenced
    }

    /// Every tracked destination file, in plan order.
    #[must_use]
    pub fn files(&self) -> &[JournalFile] {
        &self.files
    }

    /// How many tracked files are derived artifacts the caller regenerates.
    #[must_use]
    pub fn deferred_count(&self) -> usize {
        self.files
            .iter()
            .filter(|file| file.action == ChangeAction::Regenerate)
            .count()
    }

    /// Record whether the fence was established.
    pub fn set_fenced(&mut self, fenced: bool) {
        self.fenced = fenced;
    }

    /// Record the phase the run has reached.
    pub fn set_phase(&mut self, phase: ApplyPhase) {
        self.phase = phase;
    }

    /// Record where a file's previous bytes were copied.
    ///
    /// # Errors
    /// [ApplyError::Journal] with rule unknown-file when the path is not one of
    /// this journal's files.
    pub fn record_backup(&mut self, path: &str, backup: String) -> Result<(), ApplyError> {
        let index = self.index_of(path)?;
        self.files[index].backup = Some(backup);
        Ok(())
    }

    /// Record that a file's new bytes are staged.
    ///
    /// # Errors
    /// [ApplyError::Journal] with rule unknown-file when the path is not one of
    /// this journal's files.
    pub fn record_staged(&mut self, path: &str, staged: String) -> Result<(), ApplyError> {
        let index = self.index_of(path)?;
        self.files[index].staged = Some(staged);
        self.files[index].state = FileState::Staged;
        Ok(())
    }

    /// Record that a file's destination precondition was verified.
    ///
    /// # Errors
    /// [ApplyError::Journal] with rule unknown-file when the path is not one of
    /// this journal's files.
    pub fn record_verified(&mut self, path: &str) -> Result<(), ApplyError> {
        let index = self.index_of(path)?;
        if self.files[index].state < FileState::Verified {
            self.files[index].state = FileState::Verified;
        }
        Ok(())
    }

    /// Record that a file has been cut over.
    ///
    /// # Errors
    /// [ApplyError::Journal] with rule unknown-file when the path is not one of
    /// this journal's files.
    pub fn mark_cutover(&mut self, path: &str) -> Result<(), ApplyError> {
        let index = self.index_of(path)?;
        self.files[index].state = FileState::Cutover;
        Ok(())
    }

    /// Record that a file was restored to its pre-cutover state.
    ///
    /// # Errors
    /// [ApplyError::Journal] with rule unknown-file when the path is not one of
    /// this journal's files.
    pub fn mark_restored(&mut self, path: &str) -> Result<(), ApplyError> {
        let index = self.index_of(path)?;
        self.files[index].state = FileState::Verified;
        Ok(())
    }

    fn index_of(&self, path: &str) -> Result<usize, ApplyError> {
        self.files
            .iter()
            .position(|file| file.path == path)
            .ok_or_else(|| ApplyError::journal("unknown-file", path))
    }

    /// Confirm this journal describes this request.
    ///
    /// # Errors
    /// [ApplyError::Journal] with rule unsupported-schema when the document was
    /// written by another schema, and with rule foreign-journal when it belongs
    /// to another solution, plan or namespace.
    pub fn check_belongs_to(&self, request: &ApplyRequest<'_>) -> Result<(), ApplyError> {
        if self.schema_version != APPLY_SCHEMA_VERSION {
            return Err(ApplyError::journal(
                "unsupported-schema",
                &self.schema_version.to_string(),
            ));
        }
        if self.solution_id != request.plan.solution_id()
            || self.plan_digest != *request.plan.digest()
            || self.namespace != request.namespace
        {
            return Err(ApplyError::journal(
                "foreign-journal",
                &format!("{}/{}", self.solution_id, self.plan_digest.as_str()),
            ));
        }
        Ok(())
    }

    /// Confirm the journal tracks exactly the writes the plan authorises now.
    ///
    /// # Errors
    /// [ApplyError::Plan] when the plan no longer authorises the run, and
    /// [ApplyError::Journal] with rule journal-plan-drift when the plan the
    /// journal belongs to no longer authorises the same files.
    pub fn check_tracks(&self, request: &ApplyRequest<'_>) -> Result<(), ApplyError> {
        let authorized = request.plan.apply(
            request.reviewed_digest,
            request.current,
            request.now_seconds,
        )?;
        let expected = Self::for_authorized(request, &authorized)?;
        if expected.files.len() != self.files.len() {
            return Err(ApplyError::journal(
                "journal-plan-drift",
                "the authorised write count changed",
            ));
        }
        for (recorded, current) in self.files.iter().zip(expected.files.iter()) {
            if recorded.path != current.path
                || recorded.action != current.action
                || recorded.source != current.source
                || recorded.expected_sha256 != current.expected_sha256
                || recorded.previous_sha256 != current.previous_sha256
            {
                return Err(ApplyError::journal("journal-plan-drift", &recorded.path));
            }
        }
        Ok(())
    }

    /// The canonical encoding of this journal.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut out = String::new();
        write_field(&mut out, JOURNAL_MAGIC);
        write_field(&mut out, &self.schema_version.to_string());
        write_field(&mut out, &self.solution_id);
        write_field(&mut out, self.plan_digest.as_str());
        write_field(&mut out, &self.namespace);
        write_field(&mut out, self.phase.as_str());
        write_field(&mut out, if self.fenced { "1" } else { "0" });
        write_field(&mut out, &self.files.len().to_string());
        for file in &self.files {
            write_field(&mut out, &file.repo_id);
            write_field(&mut out, &file.path);
            write_field(&mut out, file.action.as_str());
            write_field(&mut out, file.source.as_deref().unwrap_or(""));
            write_field(&mut out, file.staged.as_deref().unwrap_or(""));
            write_field(&mut out, file.backup.as_deref().unwrap_or(""));
            write_field(
                &mut out,
                file.expected_sha256
                    .as_ref()
                    .map_or("", ContentHash::as_str),
            );
            write_field(
                &mut out,
                file.previous_sha256
                    .as_ref()
                    .map_or("", ContentHash::as_str),
            );
            write_field(&mut out, file.state.as_str());
        }
        out
    }

    /// Parse a journal produced by [ApplyJournal::encode].
    ///
    /// # Errors
    /// [ApplyError::Journal] for any document that is not exactly this journal's
    /// encoding: a magic mismatch, a malformed field, an unknown phase or action,
    /// a rejected hash, or trailing bytes after the last field.
    pub fn parse(text: &str) -> Result<Self, ApplyError> {
        let bytes = text.as_bytes();
        let mut cursor = 0usize;
        let magic = read_field(bytes, &mut cursor)?;
        if magic != JOURNAL_MAGIC {
            return Err(ApplyError::journal("unknown-document", &magic));
        }
        let schema_version: u32 = read_field(bytes, &mut cursor)?
            .parse()
            .map_err(|_| ApplyError::journal("malformed-field", "schema version"))?;
        if schema_version != APPLY_SCHEMA_VERSION {
            return Err(ApplyError::journal(
                "unsupported-schema",
                &schema_version.to_string(),
            ));
        }
        let solution_id = read_field(bytes, &mut cursor)?;
        let digest_text = read_field(bytes, &mut cursor)?;
        let plan_digest = ContentHash::parse(&digest_text)
            .map_err(|_| ApplyError::journal("rejected-hash", &digest_text))?;
        let namespace = read_field(bytes, &mut cursor)?;
        let phase = ApplyPhase::parse(&read_field(bytes, &mut cursor)?)?;
        let fenced = match read_field(bytes, &mut cursor)?.as_str() {
            "1" => true,
            "0" => false,
            other => return Err(ApplyError::journal("malformed-field", other)),
        };
        let count: usize = read_field(bytes, &mut cursor)?
            .parse()
            .map_err(|_| ApplyError::journal("malformed-field", "file count"))?;
        let mut files = Vec::with_capacity(count);
        for _ in 0..count {
            let repo_id = read_field(bytes, &mut cursor)?;
            let path = read_field(bytes, &mut cursor)?;
            let action = match read_field(bytes, &mut cursor)?.as_str() {
                "create" => ChangeAction::Create,
                "replace" => ChangeAction::Replace,
                "regenerate" => ChangeAction::Regenerate,
                other => return Err(ApplyError::journal("unknown-action", other)),
            };
            let source = optional_field(read_field(bytes, &mut cursor)?);
            let staged = optional_field(read_field(bytes, &mut cursor)?);
            let backup = optional_field(read_field(bytes, &mut cursor)?);
            let expected_text = read_field(bytes, &mut cursor)?;
            let expected_sha256 = if expected_text.is_empty() {
                None
            } else {
                Some(
                    ContentHash::parse(&expected_text)
                        .map_err(|_| ApplyError::journal("rejected-hash", &expected_text))?,
                )
            };
            let previous_text = read_field(bytes, &mut cursor)?;
            let previous_sha256 = if previous_text.is_empty() {
                None
            } else {
                Some(
                    ContentHash::parse(&previous_text)
                        .map_err(|_| ApplyError::journal("rejected-hash", &previous_text))?,
                )
            };
            let state = FileState::parse(&read_field(bytes, &mut cursor)?)?;
            files.push(JournalFile {
                repo_id,
                path,
                action,
                source,
                staged,
                backup,
                expected_sha256,
                previous_sha256,
                state,
            });
        }
        if cursor != bytes.len() {
            return Err(ApplyError::journal(
                "trailing-bytes",
                "the document continues after the last file",
            ));
        }
        Ok(Self {
            schema_version,
            solution_id,
            plan_digest,
            namespace,
            phase,
            fenced,
            files,
        })
    }
}

/// An empty encoded field is the encoding of "no value".
fn optional_field(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Read one len:value field, advancing cursor past its terminator.
fn read_field(bytes: &[u8], cursor: &mut usize) -> Result<String, ApplyError> {
    let rest = &bytes[*cursor..];
    let colon = rest
        .iter()
        .position(|byte| *byte == b':')
        .ok_or_else(|| ApplyError::journal("malformed-field", "a field has no length prefix"))?;
    let length_text = std::str::from_utf8(&rest[..colon])
        .map_err(|_| ApplyError::journal("malformed-field", "a field length is not text"))?;
    let length: usize = length_text
        .parse()
        .map_err(|_| ApplyError::journal("malformed-field", length_text))?;
    let value_start = *cursor + colon + 1;
    let value_end = value_start.saturating_add(length);
    if value_end >= bytes.len() {
        return Err(ApplyError::journal(
            "malformed-field",
            "a field is longer than the document",
        ));
    }
    if bytes[value_end] != FIELD_NEWLINE {
        return Err(ApplyError::journal(
            "malformed-field",
            "a field is not terminated by a newline",
        ));
    }
    let value = std::str::from_utf8(&bytes[value_start..value_end])
        .map_err(|_| ApplyError::journal("malformed-field", "a field value is not UTF-8"))?
        .to_string();
    *cursor = value_end + 1;
    Ok(value)
}

/// The previous bytes the plan recorded for one destination.
fn previous_hash(
    plan: &MigrationPlan,
    repo_id: &str,
    path: &str,
) -> Result<Option<ContentHash>, ApplyError> {
    let repo = plan
        .repositories()
        .iter()
        .find(|repo| repo.repo_id() == repo_id)
        .ok_or_else(|| ApplyError::journal("unknown-repository", repo_id))?;
    let change = repo
        .changes()
        .iter()
        .find(|change| change.path() == path)
        .ok_or_else(|| ApplyError::journal("unknown-file", path))?;
    Ok(match change.ownership() {
        DestinationOwnership::Managed { previous_sha256 } => previous_sha256.clone(),
        DestinationOwnership::HumanOwned => None,
    })
}

/// The hash of the source artifact one authorised write copies from.
fn source_hash(
    plan: &MigrationPlan,
    repo_id: &str,
    source: &str,
) -> Result<ContentHash, ApplyError> {
    let repo = plan
        .repositories()
        .iter()
        .find(|repo| repo.repo_id() == repo_id)
        .ok_or_else(|| ApplyError::journal("unknown-repository", repo_id))?;
    repo.sources()
        .iter()
        .find(|artifact| artifact.path() == source)
        .map(|artifact| artifact.sha256().clone())
        .ok_or_else(|| ApplyError::journal("source-not-inventoried", source))
}

/// One reviewed application to perform.
#[derive(Debug, Clone, Copy)]
pub struct ApplyRequest<'a> {
    /// The plan being applied.
    pub plan: &'a MigrationPlan,
    /// The digest the human reviewed.
    pub reviewed_digest: &'a str,
    /// The hashes the adapter observed for the plan's sources right now.
    pub current: &'a CurrentSources,
    /// The instant the apply starts, in seconds since the Unix epoch.
    pub now_seconds: i64,
    /// The output namespace the old publisher is fenced on.
    pub namespace: &'a str,
    /// Portable root the previous bytes are copied under.
    pub backup_root: &'a str,
    /// Portable root the new bytes are staged under.
    pub staging_root: &'a str,
}

/// The narrow boundary the cutover needs from the bytes on disk.
///
/// Paths are portable repository-relative spellings, exactly as the plan records
/// them, plus the derived backup and staging spellings. A native adapter maps
/// them onto one project root.
pub trait ApplyIo {
    /// Read one file's exact bytes.
    ///
    /// # Errors
    /// Whatever the adapter reports; a missing file must be an error rather than
    /// an empty byte sequence.
    fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError>;

    /// Write one file's exact bytes.
    ///
    /// # Errors
    /// Whatever the adapter reports.
    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError>;

    /// Remove one file.
    ///
    /// # Errors
    /// Whatever the adapter reports; removing a file that is not there is an
    /// error, because the cutover asserts what it is deleting.
    fn remove(&self, path: &str) -> Result<(), AxiomError>;

    /// Whether the path exists right now.
    fn exists(&self, path: &str) -> bool;
}

/// The boundary that stops the old publisher and proves it quiescent.
pub trait WriterFence {
    /// Fence the output namespace and report whether the old writer is gone.
    ///
    /// # Errors
    /// Whatever the adapter reports. An adapter that cannot prove quiescence
    /// returns [FenceOutcome::still_publishing] rather than an error, because the
    /// policy answer is "refuse", not "the fence broke".
    fn establish(&self, namespace: &str) -> Result<FenceOutcome, AxiomError>;
}

/// The boundary that persists the journal across a crash.
pub trait JournalStore {
    /// The journal this workspace holds, when it holds one.
    ///
    /// # Errors
    /// Whatever the adapter reports.
    fn load(&self) -> Result<Option<ApplyJournal>, AxiomError>;

    /// Persist the journal, replacing any earlier revision.
    ///
    /// # Errors
    /// Whatever the adapter reports.
    fn save(&self, journal: &ApplyJournal) -> Result<(), AxiomError>;
}

/// How one apply run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplyStatus {
    /// The plan was applied from a clean start.
    Applied,
    /// The plan was applied by resuming an interrupted journal.
    Resumed,
    /// The journal already recorded the plan as applied, so nothing ran.
    AlreadyComplete,
}

impl ApplyStatus {
    /// Stable spelling used in evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Resumed => "resumed",
            Self::AlreadyComplete => "already-complete",
        }
    }
}

/// What one apply run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    status: ApplyStatus,
    files: usize,
    deferred: usize,
    phases: Vec<ApplyPhase>,
}

impl ApplyOutcome {
    /// How the run ended.
    #[must_use]
    pub const fn status(&self) -> ApplyStatus {
        self.status
    }

    /// How many destination files the plan authorises.
    #[must_use]
    pub const fn files(&self) -> usize {
        self.files
    }

    /// How many of them are derived artifacts the caller regenerates.
    #[must_use]
    pub const fn deferred(&self) -> usize {
        self.deferred
    }

    /// The phases this run executed, in order.
    #[must_use]
    pub fn phases(&self) -> &[ApplyPhase] {
        &self.phases
    }
}

/// Apply one reviewed plan, resuming its journal when one exists.
///
/// The plan is authorised first, so a stale, expired, blocked or unapproved plan
/// never reaches the fence. The writer fence is established before any byte is
/// written, and every phase boundary is persisted.
///
/// # Errors
/// [ApplyError::Plan] when the plan refuses authorisation; [ApplyError::Refused]
/// with code [ERR_FENCE_REFUSED] when the old writer could not be proven
/// quiescent; with code [ERR_APPLY_HASH] when a destination, a source, a backup or
/// a staged file is not the bytes the plan recorded; with code
/// [ERR_APPLY_INCOMPLETE] when recovery could not restore every file; and with
/// code [ERR_APPLY_CONFLICT] when a destination is not in the state this cutover
/// may start from.
pub fn apply_journaled(
    request: &ApplyRequest<'_>,
    fence: &dyn WriterFence,
    io: &dyn ApplyIo,
    journals: &dyn JournalStore,
) -> Result<ApplyOutcome, ApplyError> {
    // 1. Authorise against the plan and the bytes on disk right now, and refuse
    //    a plan that would keep the legacy and the V2 layout both live.
    let authorized = request.plan.apply(
        request.reviewed_digest,
        request.current,
        request.now_seconds,
    )?;
    check_coexistence(request.plan, &authorized)?;

    // 2. Load or build the journal, and refuse a journal for another run.
    let stored = journals.load()?;
    let had_journal = stored.is_some();
    let mut journal = match stored {
        Some(existing) => {
            existing.check_belongs_to(request)?;
            existing.check_tracks(request)?;
            existing
        }
        None => ApplyJournal::for_plan(request)?,
    };
    // A rolled-back journal is a clean start: the previous bytes were restored,
    // so this is a fresh application rather than a resume.
    let resuming = had_journal && journal.phase != ApplyPhase::Rollback;
    if journal.phase == ApplyPhase::Rollback {
        journal = ApplyJournal::for_plan(request)?;
    }

    if journal.phase == ApplyPhase::Complete {
        return Ok(ApplyOutcome {
            status: ApplyStatus::AlreadyComplete,
            files: journal.files.len(),
            deferred: journal.deferred_count(),
            phases: Vec::new(),
        });
    }
    let resume_at_cutover = journal.phase == ApplyPhase::Cutover;

    // 3. Fence the old publisher before touching a single owned byte.
    let outcome = fence.establish(request.namespace)?;
    if !outcome.is_quiescent() {
        journal.set_phase(ApplyPhase::Fence);
        journal.set_fenced(false);
        save_quietly(journals, &journal);
        return Err(ApplyError::refused(
            ERR_FENCE_REFUSED,
            "writer-still-publishing",
            None,
            format!(
                "the old writer is still publishing on {}: {}",
                request.namespace,
                outcome.publishers().join(", ")
            ),
        ));
    }
    journal.set_fenced(true);
    journal.set_phase(ApplyPhase::Fence);
    journals.save(&journal)?;
    let mut phases = vec![ApplyPhase::Fence];

    if !resume_at_cutover {
        journal.set_phase(ApplyPhase::Backup);
        journals.save(&journal)?;
        phases.push(ApplyPhase::Backup);
        for index in 0..journal.files.len() {
            if let Err(error) = backup_one(request, io, &mut journal, index) {
                save_quietly(journals, &journal);
                return Err(error);
            }
        }
        journals.save(&journal)?;

        journal.set_phase(ApplyPhase::Stage);
        journals.save(&journal)?;
        phases.push(ApplyPhase::Stage);
        for index in 0..journal.files.len() {
            if let Err(error) = stage_one(request, io, &mut journal, index) {
                save_quietly(journals, &journal);
                return Err(error);
            }
        }
        journals.save(&journal)?;

        journal.set_phase(ApplyPhase::Verify);
        journals.save(&journal)?;
        phases.push(ApplyPhase::Verify);
        for index in 0..journal.files.len() {
            if let Err(error) = verify_one(io, &mut journal, index) {
                save_quietly(journals, &journal);
                return Err(error);
            }
        }
        journals.save(&journal)?;
    }

    journal.set_phase(ApplyPhase::Cutover);
    journals.save(&journal)?;
    phases.push(ApplyPhase::Cutover);
    cutover(io, journals, &mut journal)?;

    journal.set_phase(ApplyPhase::Complete);
    journals.save(&journal)?;
    phases.push(ApplyPhase::Complete);

    Ok(ApplyOutcome {
        status: if resuming {
            ApplyStatus::Resumed
        } else {
            ApplyStatus::Applied
        },
        files: journal.files.len(),
        deferred: journal.deferred_count(),
        phases,
    })
}

/// Copy one destination's previous bytes aside and verify the copy.
fn backup_one(
    request: &ApplyRequest<'_>,
    io: &dyn ApplyIo,
    journal: &mut ApplyJournal,
    index: usize,
) -> Result<(), ApplyError> {
    let file = &journal.files[index];
    if file.state >= FileState::Cutover {
        return Ok(());
    }
    let Some(previous) = file.previous_sha256.clone() else {
        return Ok(());
    };
    let path = file.path.clone();
    let repo_id = file.repo_id.clone();
    let observed = read_hash(io, &path)?;
    if observed != previous {
        return Err(ApplyError::refused(
            ERR_APPLY_HASH,
            "destination-drifted",
            Some(path.clone()),
            format!("{path} holds {observed} but the plan recorded {previous}"),
        ));
    }
    let target = derived_path(request.backup_root, &repo_id, &path)?;
    let bytes = io.read(&path)?;
    io.write(&target, &bytes)?;
    let verified = read_hash(io, &target)?;
    if verified != previous {
        return Err(ApplyError::refused(
            ERR_APPLY_HASH,
            "backup-verify",
            Some(target.clone()),
            format!("the backup of {path} is {verified}, not {previous}"),
        ));
    }
    journal.files[index].backup = Some(target);
    Ok(())
}

/// Stage one file's new bytes beside the destination and read them back.
fn stage_one(
    request: &ApplyRequest<'_>,
    io: &dyn ApplyIo,
    journal: &mut ApplyJournal,
    index: usize,
) -> Result<(), ApplyError> {
    let file = &journal.files[index];
    if file.state >= FileState::Cutover {
        return Ok(());
    }
    let (Some(source), Some(expected)) = (file.source.clone(), file.expected_sha256.clone()) else {
        return Ok(());
    };
    let bytes = io.read(&source)?;
    let observed = ContentHash::of_bytes(&bytes);
    if observed != expected {
        return Err(ApplyError::refused(
            ERR_APPLY_HASH,
            "source-drifted",
            Some(source.clone()),
            format!("{source} is {observed} but the plan recorded {expected}"),
        ));
    }
    let repo_id = file.repo_id.clone();
    let path = file.path.clone();
    let target = derived_path(request.staging_root, &repo_id, &path)?;
    io.write(&target, &bytes)?;
    let readback = io.read(&target)?;
    if readback != bytes {
        return Err(ApplyError::refused(
            ERR_APPLY_HASH,
            "stage-verify",
            Some(target.clone()),
            format!("the staged bytes of {path} do not read back"),
        ));
    }
    journal.files[index].staged = Some(target);
    journal.files[index].state = FileState::Staged;
    Ok(())
}

/// Re-check the staged bytes and the destination precondition.
fn verify_one(
    io: &dyn ApplyIo,
    journal: &mut ApplyJournal,
    index: usize,
) -> Result<(), ApplyError> {
    let file = &journal.files[index];
    if file.action == ChangeAction::Regenerate || file.state >= FileState::Cutover {
        return Ok(());
    }
    let path = file.path.clone();
    let Some(staged) = file.staged.clone() else {
        return Err(ApplyError::journal("missing-staged-bytes", &path));
    };
    let Some(expected) = file.expected_sha256.clone() else {
        return Err(ApplyError::journal("missing-expected-bytes", &path));
    };
    let bytes = io.read(&staged)?;
    let observed = ContentHash::of_bytes(&bytes);
    if observed != expected {
        return Err(ApplyError::refused(
            ERR_APPLY_HASH,
            "staged-hash",
            Some(path.clone()),
            format!("the staged bytes of {path} are {observed}, not {expected}"),
        ));
    }
    match file.previous_sha256.clone() {
        Some(previous) => {
            let observed = read_hash(io, &path)?;
            if observed != previous {
                return Err(ApplyError::refused(
                    ERR_APPLY_HASH,
                    "destination-drifted",
                    Some(path.clone()),
                    format!("{path} holds {observed} but the plan recorded {previous}"),
                ));
            }
        }
        None => {
            if io.exists(&path) {
                return Err(ApplyError::refused(
                    ERR_APPLY_CONFLICT,
                    "destination-appeared",
                    Some(path.clone()),
                    format!("{path} did not exist when the plan was built"),
                ));
            }
        }
    }
    if journal.files[index].state < FileState::Verified {
        journal.files[index].state = FileState::Verified;
    }
    Ok(())
}

/// Replace every destination, restoring the pre-cutover state on any failure.
fn cutover(
    io: &dyn ApplyIo,
    journals: &dyn JournalStore,
    journal: &mut ApplyJournal,
) -> Result<(), ApplyError> {
    for index in 0..journal.files.len() {
        match cutover_one(io, journal, index) {
            Ok(()) => journals.save(journal)?,
            Err(error) => {
                let blocked = restore(io, journal)?;
                save_quietly(journals, journal);
                if blocked.is_empty() {
                    return Err(error);
                }
                return Err(ApplyError::refused(
                    ERR_APPLY_INCOMPLETE,
                    "restore-blocked",
                    blocked.first().cloned(),
                    format!(
                        "recovery could not restore {} file(s); the first is {}",
                        blocked.len(),
                        blocked.join(", ")
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Cut one destination over, idempotently.
fn cutover_one(
    io: &dyn ApplyIo,
    journal: &mut ApplyJournal,
    index: usize,
) -> Result<(), ApplyError> {
    let file = &journal.files[index];
    if file.action == ChangeAction::Regenerate {
        return Ok(());
    }
    let path = file.path.clone();
    let Some(expected) = file.expected_sha256.clone() else {
        return Err(ApplyError::journal("missing-expected-bytes", &path));
    };
    if file.state >= FileState::Cutover {
        // A resume: the destination must still be exactly what we wrote.
        let observed = read_hash(io, &path)?;
        if observed != expected {
            return Err(ApplyError::refused(
                ERR_APPLY_CONFLICT,
                "cutover-drifted",
                Some(path.clone()),
                format!("{path} is {observed} but this cutover wrote {expected}"),
            ));
        }
        return Ok(());
    }
    if io.exists(&path) {
        let observed = read_hash(io, &path)?;
        if observed == expected {
            // The bytes are already in place, so the journal write was lost.
            journal.files[index].state = FileState::Cutover;
            return Ok(());
        }
        match file.previous_sha256.clone() {
            Some(previous) if observed == previous => {}
            Some(previous) => {
                return Err(ApplyError::refused(
                    ERR_APPLY_CONFLICT,
                    "destination-drifted",
                    Some(path.clone()),
                    format!("{path} holds {observed}, not the recorded {previous}"),
                ))
            }
            None => {
                return Err(ApplyError::refused(
                    ERR_APPLY_CONFLICT,
                    "destination-appeared",
                    Some(path.clone()),
                    format!("{path} appeared after the plan was built"),
                ))
            }
        }
    } else if file.previous_sha256.is_some() {
        return Err(ApplyError::refused(
            ERR_APPLY_CONFLICT,
            "destination-missing",
            Some(path.clone()),
            format!("{path} disappeared after the plan was built"),
        ));
    }
    let Some(staged) = file.staged.clone() else {
        return Err(ApplyError::journal("missing-staged-bytes", &path));
    };
    let bytes = io.read(&staged)?;
    let observed = ContentHash::of_bytes(&bytes);
    if observed != expected {
        return Err(ApplyError::refused(
            ERR_APPLY_HASH,
            "staged-hash",
            Some(path.clone()),
            format!("the staged bytes of {path} are {observed}, not {expected}"),
        ));
    }
    io.write(&path, &bytes)?;
    let written = read_hash(io, &path)?;
    if written != expected {
        return Err(ApplyError::refused(
            ERR_APPLY_HASH,
            "cutover-verify",
            Some(path.clone()),
            format!("{path} reads back as {written}, not {expected}"),
        ));
    }
    journal.files[index].state = FileState::Cutover;
    Ok(())
}

/// Restore every cut-over file to its pre-cutover bytes.
///
/// A destination whose bytes are no longer the bytes this cutover wrote is left
/// exactly as it is: a human edit made after the cutover is never erased to make
/// a rollback look atomic. Its path is returned so the caller can report it.
fn restore(io: &dyn ApplyIo, journal: &mut ApplyJournal) -> Result<Vec<String>, ApplyError> {
    let mut blocked = Vec::new();
    for index in 0..journal.files.len() {
        if journal.files[index].state != FileState::Cutover {
            continue;
        }
        let path = journal.files[index].path.clone();
        let Some(expected) = journal.files[index].expected_sha256.clone() else {
            blocked.push(path);
            continue;
        };
        if io.exists(&path) {
            let observed = read_hash(io, &path)?;
            if observed != expected {
                blocked.push(path);
                continue;
            }
        }
        if let Some(backup) = journal.files[index].backup.clone() {
            let previous = journal.files[index].previous_sha256.clone();
            let bytes = io.read(&backup)?;
            if let Some(previous) = previous {
                if ContentHash::of_bytes(&bytes) != previous {
                    blocked.push(path);
                    continue;
                }
            }
            io.write(&path, &bytes)?;
        } else if io.exists(&path) {
            io.remove(&path)?;
        }
        if let Some(staged) = journal.files[index].staged.clone() {
            if io.exists(&staged) {
                io.remove(&staged)?;
            }
        }
        journal.files[index].state = FileState::Verified;
    }
    if blocked.is_empty() {
        journal.set_phase(ApplyPhase::Verify);
    }
    Ok(blocked)
}

/// True when `path` is `root` itself or sits underneath it.
///
/// The comparison is on the portable spellings the plan and the discovery half
/// share, so a destination is only treated as a legacy path when it really is
/// under the legacy root rather than in a directory that merely shares a prefix.
fn is_under(root: &str, path: &str) -> bool {
    path == root || path.starts_with(&format!("{root}/"))
}

/// Refuse a plan that would leave the legacy and the V2 layout both live.
///
/// The legacy tree and the V2 tree are two spellings of the same logical output,
/// so a cutover may only ever write one of them. A destination under a legacy
/// root, a destination rewritten in place from itself, and a destination that is
/// also an inventoried source are all the same defect: after the run two live
/// copies would exist and neither could be trusted. Nothing is written when this
/// refuses.
///
/// # Errors
/// [ApplyError::Refused] with code [ERR_COEXISTENCE] and rule
/// `legacy-destination`, `in-place-legacy-source` or `destination-is-a-source`.
pub fn check_coexistence(
    plan: &MigrationPlan,
    authorized: &[PlannedWrite],
) -> Result<(), ApplyError> {
    let legacy_roots = [LEGACY_GRAPH_DIR, LEGACY_MISSPELLED_GRAPH_DIR];
    for write in authorized {
        for root in legacy_roots {
            if is_under(root, write.path()) {
                return Err(ApplyError::refused(
                    ERR_COEXISTENCE,
                    "legacy-destination",
                    Some(write.path().to_string()),
                    format!(
                        "{} is a legacy output path; the V2 destination must be under {}",
                        write.path(),
                        AXIOM_GRAPH_DIR
                    ),
                ));
            }
        }
        if write.source() == Some(write.path()) {
            return Err(ApplyError::refused(
                ERR_COEXISTENCE,
                "in-place-legacy-source",
                Some(write.path().to_string()),
                format!(
                    "{} would be rewritten in place, leaving the legacy and the V2 layout both live",
                    write.path()
                ),
            ));
        }
        for repo in plan.repositories() {
            for artifact in repo.sources() {
                if artifact.path() == write.path() {
                    return Err(ApplyError::refused(
                        ERR_COEXISTENCE,
                        "destination-is-a-source",
                        Some(write.path().to_string()),
                        format!(
                            "{} is both an inventoried source and a destination, so a cutover would dual-write it",
                            write.path()
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// How one rollback ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RollbackStatus {
    /// The cutover was undone.
    RolledBack,
    /// The journal already recorded a completed rollback.
    AlreadyRolledBack,
}

impl RollbackStatus {
    /// Stable spelling used in evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RolledBack => "rolled-back",
            Self::AlreadyRolledBack => "already-rolled-back",
        }
    }
}

/// What one rollback did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackOutcome {
    status: RollbackStatus,
    restored: usize,
    removed: usize,
    staged_removed: usize,
}

impl RollbackOutcome {
    /// How the rollback ended.
    #[must_use]
    pub const fn status(&self) -> RollbackStatus {
        self.status
    }

    /// How many destinations were restored from their verified backup.
    #[must_use]
    pub const fn restored(&self) -> usize {
        self.restored
    }

    /// How many created destinations were removed again.
    #[must_use]
    pub const fn removed(&self) -> usize {
        self.removed
    }

    /// How many staged copies were discarded.
    #[must_use]
    pub const fn staged_removed(&self) -> usize {
        self.staged_removed
    }
}

/// Undo a cutover from its journal, preserving every byte the run did not write.
///
/// The journal must belong to this plan's solution, digest and namespace, but the
/// current sources are deliberately not re-observed: a rollback restores the
/// bytes a cutover replaced, and it must still work after the legacy sources were
/// moved aside. Both a completed cutover and an interrupted one are undone: a
/// destination the run cut over is restored from its verified backup (or removed
/// again when the cutover created it), a destination the run never reached is left
/// alone, and every staged copy is discarded. A destination whose bytes are no
/// longer the bytes this cutover wrote, or a backup whose bytes are no longer the
/// recorded previous bytes, is never overwritten: the run reports
/// [ERR_ROLLBACK_BLOCKED] with the blocking paths and leaves those bytes as they
/// are, so a human edit made after the cutover survives. Files outside the
/// journal are never touched.
///
/// # Errors
/// [ApplyError::Journal] when a stored journal does not belong to this run;
/// [ApplyError::Refused] with code [ERR_ROLLBACK] and rule `no-journal` or
/// `cutover-not-started`, and with code [ERR_ROLLBACK_BLOCKED] and rule
/// `rollback-blocked`; and [ApplyError::Io] when the injected boundary fails.
pub fn rollback_journaled(
    request: &ApplyRequest<'_>,
    io: &dyn ApplyIo,
    journals: &dyn JournalStore,
) -> Result<RollbackOutcome, ApplyError> {
    let Some(mut journal) = journals.load()? else {
        return Err(ApplyError::refused(
            ERR_ROLLBACK,
            "no-journal",
            None,
            format!(
                "no apply journal records a cutover of {} on {}",
                request.plan.solution_id(),
                request.namespace
            ),
        ));
    };
    journal.check_belongs_to(request)?;
    if journal.phase() == ApplyPhase::Rollback {
        return Ok(RollbackOutcome {
            status: RollbackStatus::AlreadyRolledBack,
            restored: 0,
            removed: 0,
            staged_removed: 0,
        });
    }
    if journal.phase() != ApplyPhase::Complete && journal.phase() != ApplyPhase::Cutover {
        return Err(ApplyError::refused(
            ERR_ROLLBACK,
            "cutover-not-started",
            None,
            format!(
                "the journal is at phase {}; there is no cutover to undo",
                journal.phase()
            ),
        ));
    }

    let mut restored = 0usize;
    let mut removed = 0usize;
    let mut staged_removed = 0usize;
    let mut blocked: Vec<String> = Vec::new();
    for index in 0..journal.files.len() {
        let path = journal.files[index].path.clone();
        if let Some(staged) = journal.files[index].staged.clone() {
            if io.exists(&staged) {
                io.remove(&staged)?;
                staged_removed += 1;
            }
            journal.files[index].staged = None;
        }
        let was_cut_over = journal.files[index].state == FileState::Cutover;
        let expected = journal.files[index].expected_sha256.clone();
        let holds_our_bytes = match (&expected, io.exists(&path)) {
            (Some(expected), true) => read_hash(io, &path)? == *expected,
            _ => false,
        };
        // A destination the journal does not call cut over, but which already
        // holds exactly the bytes this cutover would have written, is a cutover
        // whose journal write was lost; it is undone as well.
        if !was_cut_over && !holds_our_bytes {
            continue;
        }
        if was_cut_over {
            match (&expected, io.exists(&path)) {
                (Some(expected), true) if read_hash(io, &path)? != *expected => {
                    blocked.push(path.clone());
                    continue;
                }
                (None, true) => {
                    blocked.push(path.clone());
                    continue;
                }
                (Some(_), false) if journal.files[index].previous_sha256.is_some() => {
                    blocked.push(path.clone());
                    continue;
                }
                _ => {}
            }
        }
        match journal.files[index].backup.clone() {
            Some(backup) => {
                let bytes = io.read(&backup)?;
                if let Some(previous) = journal.files[index].previous_sha256.clone() {
                    if ContentHash::of_bytes(&bytes) != previous {
                        blocked.push(path.clone());
                        continue;
                    }
                }
                io.write(&path, &bytes)?;
                restored += 1;
            }
            None => {
                if io.exists(&path) {
                    io.remove(&path)?;
                    removed += 1;
                }
            }
        }
        journal.files[index].state = FileState::Pending;
    }
    if blocked.is_empty() {
        journal.set_phase(ApplyPhase::Rollback);
    }
    save_quietly(journals, &journal);
    if !blocked.is_empty() {
        return Err(ApplyError::refused(
            ERR_ROLLBACK_BLOCKED,
            "rollback-blocked",
            blocked.first().cloned(),
            format!(
                "{} file(s) were changed after the cutover and are left as they are; the first is {}",
                blocked.len(),
                blocked.join(", ")
            ),
        ));
    }
    Ok(RollbackOutcome {
        status: RollbackStatus::RolledBack,
        restored,
        removed,
        staged_removed,
    })
}

/// Read one file and hash it.
fn read_hash(io: &dyn ApplyIo, path: &str) -> Result<ContentHash, ApplyError> {
    let bytes = io.read(path)?;
    Ok(ContentHash::of_bytes(&bytes))
}

/// The portable spelling of one derived path under root.
fn derived_path(root: &str, repo_id: &str, path: &str) -> Result<String, ApplyError> {
    let root = root.trim_end_matches('/');
    let candidate = format!("{root}/{repo_id}/{path}");
    let key = PathKey::new(&candidate).map_err(|error| {
        ApplyError::journal(
            "derived-path-not-portable",
            &format!("{candidate}: {error}"),
        )
    })?;
    Ok(key.into_string())
}

/// Persist the journal, ignoring a secondary failure on an error path.
fn save_quietly(journals: &dyn JournalStore, journal: &ApplyJournal) {
    let _ = journals.save(journal);
}

/// Why one application could not be performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyError {
    /// The plan itself refused authorisation.
    Plan(PlanError),
    /// The cutover refused to continue, and took no destructive fallback.
    Refused {
        /// Stable wire code.
        code: &'static str,
        /// Stable rule that refused it.
        rule: &'static str,
        /// The destination the refusal is about, when it is about one.
        path: Option<String>,
        /// What was observed.
        detail: String,
    },
    /// The journal could not be read, or does not describe this run.
    Journal {
        /// Stable rule that refused the document.
        rule: &'static str,
        /// What was observed.
        detail: String,
    },
    /// The injected byte or journal boundary failed.
    Io(AxiomError),
}

impl ApplyError {
    /// Build a refusal.
    #[must_use]
    pub fn refused(
        code: &'static str,
        rule: &'static str,
        path: Option<String>,
        detail: String,
    ) -> Self {
        Self::Refused {
            code,
            rule,
            path,
            detail,
        }
    }

    /// Build a journal refusal.
    #[must_use]
    pub fn journal(rule: &'static str, detail: &str) -> Self {
        Self::Journal {
            rule,
            detail: detail.to_string(),
        }
    }

    /// The stable wire code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Plan(error) => error.code(),
            Self::Refused { code, .. } => code,
            Self::Journal { .. } => ERR_JOURNAL_INVALID,
            Self::Io(_) => "MIGRATION_APPLY_IO",
        }
    }

    /// The shared typed error.
    #[must_use]
    pub fn to_axiom_error(&self) -> AxiomError {
        match self {
            Self::Plan(error) => error.to_axiom_error(),
            Self::Refused {
                code,
                rule,
                path,
                detail,
            } => {
                let error = AxiomError::new(
                    refused_error_code(code),
                    format!("{code}: the migration did not apply"),
                )
                .with_detail("rule", *rule)
                .with_detail("observed", detail.clone());
                match path {
                    Some(path) => error.with_detail("portable_path", path),
                    None => error,
                }
            }
            Self::Journal { rule, detail } => AxiomError::new(
                ErrorCode::ValidationError,
                format!("{ERR_JOURNAL_INVALID}: the apply journal is not usable"),
            )
            .with_detail("rule", *rule)
            .with_detail("observed", detail.clone()),
            Self::Io(error) => error.clone(),
        }
    }
}

/// The shared error code one refusal code maps onto.
fn refused_error_code(code: &str) -> ErrorCode {
    match code {
        ERR_FENCE_REFUSED => ErrorCode::WriterAlreadyRunning,
        ERR_APPLY_HASH => ErrorCode::MigrationChecksumMismatch,
        ERR_APPLY_INCOMPLETE => ErrorCode::Conflict,
        _ => ErrorCode::Conflict,
    }
}

impl From<AxiomError> for ApplyError {
    fn from(error: AxiomError) -> Self {
        Self::Io(error)
    }
}

impl From<PlanError> for ApplyError {
    fn from(error: PlanError) -> Self {
        Self::Plan(error)
    }
}

impl fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(error) => write!(formatter, "{error}"),
            Self::Refused {
                code, rule, detail, ..
            } => write!(formatter, "{code}: {rule}: {detail}"),
            Self::Journal { rule, detail } => {
                write!(formatter, "{ERR_JOURNAL_INVALID}: {rule}: {detail}")
            }
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ApplyError {}
