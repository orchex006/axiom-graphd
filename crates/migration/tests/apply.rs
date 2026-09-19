//! V2-011 acceptance tests: one reviewed plan is applied through the fence,
//! backup, stage, verify and cutover sequence, journalling every phase so an
//! interrupted run resumes or restores instead of guessing.
//!
//! Positive, negative and failure-boundary checks:
//! - positive: a clean run fences, backs up, stages, verifies and cuts over, and
//!   the journal records the run as complete;
//! - negative: a non-quiescent fence refuses before a single byte is written, a
//!   drifted destination and a corrupted backup refuse with a hash mismatch, an
//!   unreviewed digest never reaches the fence, and a foreign journal is refused;
//! - boundary: a crash at every journal boundary resumes to exactly the applied
//!   state, a failure during cutover restores the pre-cutover bytes, and a human
//!   edit made after cutover is never overwritten by recovery.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use axiom_migration::apply::{
    apply_journaled, ApplyError, ApplyIo, ApplyJournal, ApplyOutcome, ApplyPhase, ApplyRequest,
    ApplyStatus, FenceOutcome, FileState, JournalStore, WriterFence, ERR_APPLY_HASH,
    ERR_APPLY_INCOMPLETE, ERR_FENCE_REFUSED, ERR_JOURNAL_INVALID,
};
use axiom_migration::{
    build_plan, ChangeAction, ContentHash, CurrentSources, DestinationChange, DestinationOwnership,
    DiscoveryDecision, MigrationPlan, RepoPlan, SourceArtifact, ERR_PLAN_APPROVAL,
};
use graph_core::error::{AxiomError, ErrorCode};

const NAMESPACE: &str = "sample-publisher";
const BACKUP_ROOT: &str = ".axiom/backups";
const STAGING_ROOT: &str = ".axiom/staging";
const DEST_A: &str = ".axiom/graph/a.json";
const DEST_B: &str = ".axiom/graph/b.json";
const SRC_A: &str = ".axiom/graph/legacy-a.json";
const SRC_B: &str = ".axiom/graph/legacy-b.json";

fn hash_of(bytes: &[u8]) -> String {
    ContentHash::of_bytes(bytes).as_str().to_string()
}

fn backup_path(dest: &str) -> String {
    format!("{BACKUP_ROOT}/sample-repo/{dest}")
}

fn staging_path(dest: &str) -> String {
    format!("{STAGING_ROOT}/sample-repo/{dest}")
}

/// A plan and the observed sources that describe the same two replacements.
struct Fixture {
    plan: MigrationPlan,
    current: CurrentSources,
}

fn fixture(solution_id: &str) -> Fixture {
    let mut repo = RepoPlan::new("sample-repo", DiscoveryDecision::Fresh).expect("portable id");
    repo.add_source(SourceArtifact::new(SRC_A, &hash_of(b"new-a"), 5).expect("source a"))
        .expect("unique source a");
    repo.add_source(SourceArtifact::new(SRC_B, &hash_of(b"new-b"), 5).expect("source b"))
        .expect("unique source b");
    repo.add_change(
        DestinationChange::new(
            DEST_A,
            ChangeAction::Replace,
            Some(SRC_A),
            DestinationOwnership::Managed {
                previous_sha256: Some(ContentHash::of_bytes(b"old-a")),
            },
        )
        .expect("replace a"),
    )
    .expect("unique destination a");
    repo.add_change(
        DestinationChange::new(
            DEST_B,
            ChangeAction::Replace,
            Some(SRC_B),
            DestinationOwnership::Managed {
                previous_sha256: Some(ContentHash::of_bytes(b"old-b")),
            },
        )
        .expect("replace b"),
    )
    .expect("unique destination b");
    let plan = build_plan(solution_id, 1_000, 3_600, vec![repo]).expect("plan builds");

    let mut current = CurrentSources::new();
    current
        .observe("sample-repo", SRC_A, &hash_of(b"new-a"))
        .expect("observe a");
    current
        .observe("sample-repo", SRC_B, &hash_of(b"new-b"))
        .expect("observe b");

    Fixture { plan, current }
}

/// The bytes the destination and source tree holds before any run.
fn starting_io() -> MemIo {
    MemIo::new(&[
        (DEST_A, b"old-a".as_slice()),
        (DEST_B, b"old-b".as_slice()),
        (SRC_A, b"new-a".as_slice()),
        (SRC_B, b"new-b".as_slice()),
    ])
}

fn run(
    fixture: &Fixture,
    io: &MemIo,
    fence: &dyn WriterFence,
    journals: &MemJournals,
) -> Result<ApplyOutcome, ApplyError> {
    let request = ApplyRequest {
        plan: &fixture.plan,
        reviewed_digest: fixture.plan.digest().as_str(),
        current: &fixture.current,
        now_seconds: 1_100,
        namespace: NAMESPACE,
        backup_root: BACKUP_ROOT,
        staging_root: STAGING_ROOT,
    };
    apply_journaled(&request, fence, io, journals)
}

/// A fence that always answers the same way.
struct FixedFence(FenceOutcome);

impl WriterFence for FixedFence {
    fn establish(&self, _namespace: &str) -> Result<FenceOutcome, AxiomError> {
        Ok(self.0.clone())
    }
}

fn quiescent() -> FixedFence {
    FixedFence(FenceOutcome::quiescent())
}

/// An in-memory byte store with injectable write faults.
#[derive(Default)]
struct MemIo {
    files: RefCell<BTreeMap<String, Vec<u8>>>,
    fail_exact: RefCell<BTreeSet<String>>,
    corrupt_exact: RefCell<BTreeSet<String>>,
    writes: Cell<usize>,
}

impl MemIo {
    fn new(entries: &[(&str, &[u8])]) -> Self {
        let io = Self::default();
        {
            let mut files = io.files.borrow_mut();
            for (path, bytes) in entries {
                files.insert((*path).to_string(), bytes.to_vec());
            }
        }
        io
    }

    fn put(&self, path: &str, bytes: &[u8]) {
        self.files
            .borrow_mut()
            .insert(path.to_string(), bytes.to_vec());
    }

    fn get(&self, path: &str) -> Option<Vec<u8>> {
        self.files.borrow().get(path).cloned()
    }

    fn fail_writes_to(&self, path: &str) {
        self.fail_exact.borrow_mut().insert(path.to_string());
    }

    fn corrupt_writes_to(&self, path: &str) {
        self.corrupt_exact.borrow_mut().insert(path.to_string());
    }

    fn write_count(&self) -> usize {
        self.writes.get()
    }
}

impl ApplyIo for MemIo {
    fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
        self.get(path)
            .ok_or_else(|| AxiomError::new(ErrorCode::NotFound, format!("missing {path}")))
    }

    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError> {
        self.writes.set(self.writes.get() + 1);
        if self.fail_exact.borrow().contains(path) {
            return Err(AxiomError::new(
                ErrorCode::Internal,
                format!("injected write failure at {path}"),
            ));
        }
        let stored = if self.corrupt_exact.borrow().contains(path) {
            b"corrupted".to_vec()
        } else {
            bytes.to_vec()
        };
        self.files.borrow_mut().insert(path.to_string(), stored);
        Ok(())
    }

    fn remove(&self, path: &str) -> Result<(), AxiomError> {
        if self.files.borrow_mut().remove(path).is_some() {
            Ok(())
        } else {
            Err(AxiomError::new(
                ErrorCode::NotFound,
                format!("nothing to remove at {path}"),
            ))
        }
    }

    fn exists(&self, path: &str) -> bool {
        self.files.borrow().contains_key(path)
    }
}

/// A journal store that can be made to fail on a chosen save.
#[derive(Default)]
struct MemJournals {
    journal: RefCell<Option<ApplyJournal>>,
    fail_after: Cell<Option<usize>>,
    saves: Cell<usize>,
}

impl MemJournals {
    fn seeded(journal: ApplyJournal) -> Self {
        let store = Self::default();
        *store.journal.borrow_mut() = Some(journal);
        store
    }

    fn crash_after(&self, limit: usize) {
        self.fail_after.set(Some(limit));
    }

    fn stored(&self) -> Option<ApplyJournal> {
        self.journal.borrow().clone()
    }
}

impl JournalStore for MemJournals {
    fn load(&self) -> Result<Option<ApplyJournal>, AxiomError> {
        Ok(self.stored())
    }

    fn save(&self, journal: &ApplyJournal) -> Result<(), AxiomError> {
        let attempt = self.saves.get() + 1;
        if let Some(limit) = self.fail_after.get() {
            if attempt > limit {
                return Err(AxiomError::new(
                    ErrorCode::Internal,
                    "injected journal crash",
                ));
            }
        }
        self.saves.set(attempt);
        *self.journal.borrow_mut() = Some(journal.clone());
        Ok(())
    }
}
#[test]
fn a_clean_run_fences_backs_up_stages_verifies_and_cuts_over() {
    let scenario = fixture("sample-solution");
    let io = starting_io();
    let journals = MemJournals::default();

    let outcome = run(&scenario, &io, &quiescent(), &journals).expect("a clean apply");
    assert_eq!(outcome.status(), ApplyStatus::Applied);
    assert_eq!(outcome.files(), 2);
    assert_eq!(outcome.deferred(), 0);
    assert_eq!(
        outcome.phases(),
        &[
            ApplyPhase::Fence,
            ApplyPhase::Backup,
            ApplyPhase::Stage,
            ApplyPhase::Verify,
            ApplyPhase::Cutover,
            ApplyPhase::Complete,
        ][..]
    );

    // The destinations hold the new bytes.
    assert_eq!(io.get(DEST_A).as_deref(), Some(b"new-a".as_slice()));
    assert_eq!(io.get(DEST_B).as_deref(), Some(b"new-b".as_slice()));
    // The previous bytes are kept, verified, under the backup root.
    assert_eq!(
        io.get(&backup_path(DEST_A)).as_deref(),
        Some(b"old-a".as_slice())
    );
    assert_eq!(
        io.get(&backup_path(DEST_B)).as_deref(),
        Some(b"old-b".as_slice())
    );
    // The new bytes are staged beside the destination, not in place.
    assert_eq!(
        io.get(&staging_path(DEST_A)).as_deref(),
        Some(b"new-a".as_slice())
    );
    // A destination is only ever written from the staged copy.
    assert_eq!(
        io.get(DEST_A).as_deref(),
        io.get(&staging_path(DEST_A)).as_deref()
    );

    let stored = journals.stored().expect("the completed journal");
    assert_eq!(stored.phase(), ApplyPhase::Complete);
    assert!(stored.fenced());
    assert_eq!(stored.namespace(), NAMESPACE);
    assert_eq!(stored.plan_digest(), scenario.plan.digest());
    assert!(stored
        .files()
        .iter()
        .all(|file| file.state() == FileState::Cutover));
    assert!(stored.files().iter().all(|file| file.backup().is_some()));

    // Re-running a completed journal is a no-op, not a second cutover.
    let again = run(&scenario, &io, &quiescent(), &journals).expect("a re-run");
    assert_eq!(again.status(), ApplyStatus::AlreadyComplete);
    assert!(again.phases().is_empty());
}

#[test]
fn a_non_quiescent_fence_refuses_before_a_single_byte_is_written() {
    let scenario = fixture("sample-solution");
    let io = starting_io();
    let journals = MemJournals::default();
    let fence = FixedFence(FenceOutcome::still_publishing(vec![String::from(
        "legacy-publisher",
    )]));

    let error = run(&scenario, &io, &fence, &journals).expect_err("a live publisher is refused");
    assert_eq!(error.code(), ERR_FENCE_REFUSED);
    assert_eq!(
        error.to_axiom_error().code(),
        ErrorCode::WriterAlreadyRunning
    );
    assert_eq!(
        io.write_count(),
        0,
        "no byte may be written before the fence"
    );
    assert_eq!(io.get(DEST_A).as_deref(), Some(b"old-a".as_slice()));
    assert_eq!(io.get(SRC_A).as_deref(), Some(b"new-a".as_slice()));

    let stored = journals.stored().expect("the refusal is journalled");
    assert_eq!(stored.phase(), ApplyPhase::Fence);
    assert!(!stored.fenced());
}

#[test]
fn a_destination_that_drifted_after_review_refuses_with_a_hash_mismatch() {
    let scenario = fixture("sample-solution");
    let io = starting_io();
    io.put(DEST_A, b"drifted");
    let journals = MemJournals::default();

    let error = run(&scenario, &io, &quiescent(), &journals).expect_err("a drift is refused");
    assert_eq!(error.code(), ERR_APPLY_HASH);
    assert!(error.to_string().contains("destination-drifted"), "{error}");
    assert_eq!(io.write_count(), 0, "a drift is caught before any write");
    assert_eq!(io.get(DEST_A).as_deref(), Some(b"drifted".as_slice()));
    assert_eq!(io.get(DEST_B).as_deref(), Some(b"old-b".as_slice()));
}

#[test]
fn a_backup_that_does_not_read_back_is_refused_before_cutover() {
    let scenario = fixture("sample-solution");
    let io = starting_io();
    io.corrupt_writes_to(&backup_path(DEST_A));
    let journals = MemJournals::default();

    let error = run(&scenario, &io, &quiescent(), &journals).expect_err("a bad copy is refused");
    assert_eq!(error.code(), ERR_APPLY_HASH);
    assert!(error.to_string().contains("backup-verify"), "{error}");
    // Nothing was cut over.
    assert_eq!(io.get(DEST_A).as_deref(), Some(b"old-a".as_slice()));
    assert_eq!(io.get(DEST_B).as_deref(), Some(b"old-b".as_slice()));
    assert!(io.get(&staging_path(DEST_A)).is_none());
}

#[test]
fn a_failure_during_cutover_restores_the_pre_cutover_bytes() {
    let scenario = fixture("sample-solution");
    let io = starting_io();
    io.fail_writes_to(DEST_B);
    let journals = MemJournals::default();

    let error = run(&scenario, &io, &quiescent(), &journals).expect_err("the write fails");
    assert_eq!(error.code(), "MIGRATION_APPLY_IO");
    // The file that was already cut over is put back exactly as it was.
    assert_eq!(io.get(DEST_A).as_deref(), Some(b"old-a".as_slice()));
    assert_eq!(io.get(DEST_B).as_deref(), Some(b"old-b".as_slice()));
    let stored = journals.stored().expect("the restored journal");
    assert_eq!(stored.phase(), ApplyPhase::Verify);
    assert_eq!(stored.files()[0].state(), FileState::Verified);
    assert_eq!(stored.files()[1].state(), FileState::Verified);
}

#[test]
fn a_crash_at_every_journal_boundary_resumes_to_the_applied_state() {
    // Eleven saves happen on a clean run, so a partial crash exists for every
    // prefix of them.
    for limit in 0..11usize {
        let scenario = fixture("sample-solution");
        let io = starting_io();
        let crashing = MemJournals::default();
        crashing.crash_after(limit);

        let first = run(&scenario, &io, &quiescent(), &crashing);
        assert!(
            first.is_err(),
            "a crash at save {limit} must surface as an error, got {first:?}"
        );

        let resumed = match crashing.stored() {
            Some(journal) => MemJournals::seeded(journal),
            None => MemJournals::default(),
        };
        let existed = resumed.stored().is_some();
        let outcome = run(&scenario, &io, &quiescent(), &resumed).unwrap_or_else(|error| {
            panic!("a resume after a crash at save {limit} failed: {error}")
        });
        let expected = if existed {
            ApplyStatus::Resumed
        } else {
            ApplyStatus::Applied
        };
        assert_eq!(outcome.status(), expected, "at save {limit}");
        assert_eq!(
            io.get(DEST_A).as_deref(),
            Some(b"new-a".as_slice()),
            "at save {limit}"
        );
        assert_eq!(
            io.get(DEST_B).as_deref(),
            Some(b"new-b".as_slice()),
            "at save {limit}"
        );

        let stored = resumed.stored().expect("a completed journal");
        assert_eq!(stored.phase(), ApplyPhase::Complete, "at save {limit}");
        assert!(stored.fenced(), "at save {limit}");
        assert!(stored
            .files()
            .iter()
            .all(|file| file.state() == FileState::Cutover));

        let again = run(&scenario, &io, &quiescent(), &resumed).expect("the third run");
        assert_eq!(
            again.status(),
            ApplyStatus::AlreadyComplete,
            "at save {limit}"
        );
    }
}

#[test]
fn a_human_edit_after_cutover_is_never_overwritten_by_recovery() {
    let scenario = fixture("sample-solution");
    let io = starting_io();
    let crashing = MemJournals::default();
    // Save nine is the checkpoint written just after the first destination is
    // cut over, so the journal records it as cut over while the second is not.
    crashing.crash_after(9);
    let _ = run(&scenario, &io, &quiescent(), &crashing).expect_err("the crash surfaces");
    let stored = crashing
        .stored()
        .expect("the journal at the cutover checkpoint");
    assert_eq!(stored.phase(), ApplyPhase::Cutover);
    assert_eq!(stored.files()[0].state(), FileState::Cutover);
    assert_eq!(io.get(DEST_A).as_deref(), Some(b"new-a".as_slice()));

    // A human edits the destination this cutover had already replaced.
    io.put(DEST_A, b"human-edit");
    let journals = MemJournals::seeded(stored);
    let error = run(&scenario, &io, &quiescent(), &journals)
        .expect_err("recovery may not erase a human edit");
    assert_eq!(error.code(), ERR_APPLY_INCOMPLETE);
    assert!(error.to_string().contains(DEST_A), "{error}");
    assert_eq!(io.get(DEST_A).as_deref(), Some(b"human-edit".as_slice()));
    assert_eq!(io.get(DEST_B).as_deref(), Some(b"new-b".as_slice()));
}

#[test]
fn the_journal_round_trips_and_refuses_a_foreign_document() {
    let scenario = fixture("sample-solution");
    let io = starting_io();
    let journals = MemJournals::default();
    run(&scenario, &io, &quiescent(), &journals).expect("a clean apply");
    let stored = journals.stored().expect("the completed journal");

    let encoded = stored.encode();
    let parsed = ApplyJournal::parse(&encoded).expect("the journal round trips");
    assert_eq!(parsed, stored);
    assert_eq!(parsed.encode(), encoded);

    let mut trailing = encoded.clone();
    trailing.push('x');
    let error = ApplyJournal::parse(&trailing).expect_err("trailing bytes are refused");
    assert_eq!(error.code(), ERR_JOURNAL_INVALID);
    assert!(error.to_string().contains("trailing-bytes"), "{error}");

    let error = ApplyJournal::parse("5:magic\n").expect_err("a foreign document is refused");
    assert_eq!(error.code(), ERR_JOURNAL_INVALID);
    assert!(error.to_string().contains("unknown-document"), "{error}");

    let error = ApplyJournal::parse("not-a-journal").expect_err("a malformed document is refused");
    assert_eq!(error.code(), ERR_JOURNAL_INVALID);
    assert!(error.to_string().contains("malformed-field"), "{error}");

    let truncated = &encoded[..encoded.len() / 2];
    assert!(
        ApplyJournal::parse(truncated).is_err(),
        "a truncated journal must not be accepted"
    );
}

#[test]
fn a_journal_for_another_solution_is_refused() {
    let first = fixture("sample-solution");
    let io = starting_io();
    let journals = MemJournals::default();
    run(&first, &io, &quiescent(), &journals).expect("a clean apply");
    let foreign = journals.stored().expect("the completed journal");

    let second = fixture("other-solution");
    let seeded = MemJournals::seeded(foreign);
    let error = run(&second, &io, &quiescent(), &seeded).expect_err("a foreign journal is refused");
    assert_eq!(error.code(), ERR_JOURNAL_INVALID);
    assert!(error.to_string().contains("foreign-journal"), "{error}");
}

#[test]
fn an_unreviewed_digest_never_reaches_the_fence() {
    let scenario = fixture("sample-solution");
    let io = starting_io();
    let journals = MemJournals::default();
    let digest = "f".repeat(64);
    let request = ApplyRequest {
        plan: &scenario.plan,
        reviewed_digest: &digest,
        current: &scenario.current,
        now_seconds: 1_100,
        namespace: NAMESPACE,
        backup_root: BACKUP_ROOT,
        staging_root: STAGING_ROOT,
    };
    let error = apply_journaled(&request, &quiescent(), &io, &journals)
        .expect_err("an unapproved plan is refused");
    assert_eq!(error.code(), ERR_PLAN_APPROVAL);
    assert_eq!(io.write_count(), 0);
    assert!(
        journals.stored().is_none(),
        "no journal is written for a refusal"
    );
}
