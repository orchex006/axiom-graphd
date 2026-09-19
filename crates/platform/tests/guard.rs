//! V2-018 - OS-specific publisher and GC guards: positive, negative and
//! failure-boundary legs against the frozen reader/writer guard ABI.
//!
//! Three kinds of leg are here:
//!
//! * ABI parity, so the crate cannot drift from the frozen contract values.
//! * Behavioural legs on a real temporary guard directory: a second holder is
//!   refused instead of blocking, a reader releases admission before reading
//!   while its data guard stays held, and a dropped guard is released by the OS.
//! * A real cross-process leg: a child test process takes both exclusive guards
//!   and is killed with `std::process::exit`, and the parent then proves the OS
//!   released them. That is the "process crash releases ownership" clause.
//!
//! POSIX has no share mode, so the ABI share-mode pin is only asserted as a
//! host-dependent requirement here; the Windows-only pin refusal is recorded as
//! `not_run` in the task evidence rather than faked.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use axiom_platform::guard::{
    plan_gc, AcquireError, BoundedWait, CancelFlag, CancelToken, Clock, GcProtection, GcRefusal,
    GuardDir, GuardObservation, GuardRole, NeverCancelled, Participant, RealClock, RealSleeper,
    RecordingSleeper, ACQUISITION_ORDER, ADMISSION_LOCK_NAME, CANCEL_SUPPORTED, CONTRACT_ID,
    CONTRACT_VERSION, CRASH_RELEASE_MECHANISM, DATA_LOCK_NAME, DEFAULT_TIMEOUT_MS,
    ERR_GUARD_CANCELLED, ERR_GUARD_DIR, ERR_GUARD_PIN, ERR_GUARD_TIMEOUT, GC_NEVER_FOLLOWS_LINKS,
    GC_PROTECTS_REFERENCED_GENERATIONS, GUARD_DIR_NAME, INTEROP_DISTINCT_PROCESSES,
    INTEROP_LANGUAGES, LOCK_FILE_CONTENT_IS_OWNERSHIP, MAX_TIMEOUT_MS, NO_RECURSIVE_ACQUIRE,
    NO_UPGRADE, ON_TIMEOUT, PID_FILE_IS_OWNERSHIP, POSIX_PRIMITIVE, PROTOCOL_DIGEST, RELEASE_ORDER,
    REMOVAL_REQUIRES_ALL_STOPPED, RETRY_INITIAL_MS, RETRY_MAX_MS, SINGLE_GUARD_DEFAULT,
    SPEC_VERSION, STABLE_EMPTY_FILES_MAY_PERSIST, STALE_PID_IS_LIVE_HOLDER,
    UNBOUNDED_BLOCKING_ALLOWED, WINDOWS_PRIMITIVE, WINDOWS_SHARE_EXCLUDES, WINDOWS_SHARE_MODE,
};
use axiom_platform::LockMode;

/// Set in the child process of the crash leg; holds the guard directory to use.
const CHILD_GUARD_DIR_ENV: &str = "AXIOM_L16_GUARD_CHILD_DIR";
/// The exit code the child uses after taking the guards without releasing them.
const CHILD_EXIT_CODE: i32 = 9;
/// The test the child process re-enters by name.
const CRASH_TEST_NAME: &str = "a_crashed_process_releases_its_guards";

/// A clock frozen at a fixed elapsed value, so bounded-wait legs are exact.
struct FrozenClock(u64);

impl Clock for FrozenClock {
    fn elapsed_ms(&self) -> u64 {
        self.0
    }
}

fn guard_dir(temp: &tempfile::TempDir) -> GuardDir {
    GuardDir::at(temp.path().join(GUARD_DIR_NAME))
}

/// Assert a frozen ABI constant. `black_box` keeps the value opaque to
/// `clippy::assertions_on_constants`, which would otherwise treat the check as
/// dead code; flipping one of these constants must still fail the test.
fn assert_abi(flag: bool, name: &str) {
    assert!(std::hint::black_box(flag), "ABI constant {name} must hold");
}

// ------------------------------------------------------------- ABI parity

#[test]
fn the_guard_directory_and_lock_files_match_the_frozen_contract() {
    assert_eq!(CONTRACT_ID, "axiom-native-reader-writer-guards");
    assert_eq!(CONTRACT_VERSION, 1);
    assert_eq!(SPEC_VERSION, "2.0.0-draft.1");
    assert_eq!(GUARD_DIR_NAME, "solution.guard");
    assert_eq!(ADMISSION_LOCK_NAME, "admission.lock");
    assert_eq!(DATA_LOCK_NAME, "data.lock");
    assert_eq!(ACQUISITION_ORDER, [ADMISSION_LOCK_NAME, DATA_LOCK_NAME]);
    assert_eq!(RELEASE_ORDER, [DATA_LOCK_NAME, ADMISSION_LOCK_NAME]);
    assert_eq!(POSIX_PRIMITIVE, "flock");
    assert_eq!(WINDOWS_PRIMITIVE, "LockFileEx");
    assert_eq!(WINDOWS_SHARE_MODE, "FILE_SHARE_READ | FILE_SHARE_WRITE");
    assert_eq!(WINDOWS_SHARE_EXCLUDES, "FILE_SHARE_DELETE");
    assert_eq!(
        PROTOCOL_DIGEST,
        "06fadbdcd8ef4fba9573b10f838f060bc23652286ba757061249737b1d717f8a"
    );
}

#[test]
fn the_lock_paths_are_the_two_frozen_names_inside_the_guard_directory() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let dir = guard_dir(&temp);
    assert_eq!(dir.path(), temp.path().join(GUARD_DIR_NAME));
    assert_eq!(
        dir.lock_path(GuardRole::Admission),
        dir.path().join(ADMISSION_LOCK_NAME)
    );
    assert_eq!(
        dir.lock_path(GuardRole::Data),
        dir.path().join(DATA_LOCK_NAME)
    );
    assert_eq!(
        dir.lock_paths(),
        [
            dir.path().join(ADMISSION_LOCK_NAME),
            dir.path().join(DATA_LOCK_NAME)
        ]
    );
}

#[test]
fn participant_plans_follow_the_one_normative_order_and_never_upgrade() {
    for participant in [Participant::Publisher, Participant::Collector] {
        let plan = participant.plan();
        assert_eq!(plan[0].role, GuardRole::Admission);
        assert_eq!(plan[1].role, GuardRole::Data);
        assert_eq!(plan[0].mode, LockMode::Exclusive);
        assert_eq!(plan[1].mode, LockMode::Exclusive);
    }
    let reader = Participant::Reader.plan();
    assert_eq!(reader[0].role, GuardRole::Admission);
    assert_eq!(reader[1].role, GuardRole::Data);
    assert_eq!(reader[0].mode, LockMode::Shared);
    assert_eq!(reader[1].mode, LockMode::Shared);
    assert!(Participant::Reader.releases_admission_before_payload());
    assert!(!Participant::Publisher.releases_admission_before_payload());

    assert_eq!(Participant::Publisher.as_str(), "publisher");
    assert_eq!(Participant::Collector.as_str(), "collector");
    assert_eq!(Participant::Reader.as_str(), "reader");
    assert_eq!(GuardRole::Admission.file_name(), ADMISSION_LOCK_NAME);
    assert_eq!(GuardRole::Data.file_name(), DATA_LOCK_NAME);
    assert_eq!(GuardRole::ALL, [GuardRole::Admission, GuardRole::Data]);

    assert_abi(NO_UPGRADE, "NO_UPGRADE");
    assert_abi(NO_RECURSIVE_ACQUIRE, "NO_RECURSIVE_ACQUIRE");
    assert_abi(SINGLE_GUARD_DEFAULT, "SINGLE_GUARD_DEFAULT");
    assert_abi(!UNBOUNDED_BLOCKING_ALLOWED, "UNBOUNDED_BLOCKING_ALLOWED");
    assert_abi(CANCEL_SUPPORTED, "CANCEL_SUPPORTED");
}

#[test]
fn crash_release_and_removal_facts_match_the_frozen_contract() {
    assert_abi(!PID_FILE_IS_OWNERSHIP, "PID_FILE_IS_OWNERSHIP");
    assert_abi(
        !LOCK_FILE_CONTENT_IS_OWNERSHIP,
        "LOCK_FILE_CONTENT_IS_OWNERSHIP",
    );
    assert_abi(!STALE_PID_IS_LIVE_HOLDER, "STALE_PID_IS_LIVE_HOLDER");
    assert_abi(
        STABLE_EMPTY_FILES_MAY_PERSIST,
        "STABLE_EMPTY_FILES_MAY_PERSIST",
    );
    assert_abi(REMOVAL_REQUIRES_ALL_STOPPED, "REMOVAL_REQUIRES_ALL_STOPPED");
    assert!(CRASH_RELEASE_MECHANISM.contains("process termination"));
    assert!(ON_TIMEOUT.contains("reverse acquisition order"));
    assert_eq!(INTEROP_LANGUAGES, ["rust", "python"]);
    assert_abi(INTEROP_DISTINCT_PROCESSES, "INTEROP_DISTINCT_PROCESSES");
    assert_abi(
        GC_PROTECTS_REFERENCED_GENERATIONS,
        "GC_PROTECTS_REFERENCED_GENERATIONS",
    );
    assert_abi(GC_NEVER_FOLLOWS_LINKS, "GC_NEVER_FOLLOWS_LINKS");
    assert_eq!(ERR_GUARD_TIMEOUT, "guard-lock-timeout");
    assert_eq!(ERR_GUARD_CANCELLED, "guard-cancelled");
    assert_eq!(ERR_GUARD_DIR, "guard-directory");
    assert_eq!(ERR_GUARD_PIN, "guard-share-mode-pin");
}

// -------------------------------------------------------- the bounded wait

#[test]
fn the_bounded_wait_uses_the_frozen_bounds_and_refuses_unbounded_values() {
    assert_eq!(DEFAULT_TIMEOUT_MS, 5_000);
    assert_eq!(MAX_TIMEOUT_MS, 60_000);
    assert_eq!(RETRY_INITIAL_MS, 25);
    assert_eq!(RETRY_MAX_MS, 250);
    assert_eq!(BoundedWait::standard().timeout_ms(), DEFAULT_TIMEOUT_MS);
    assert_eq!(BoundedWait::default().timeout_ms(), DEFAULT_TIMEOUT_MS);
    assert_eq!(
        BoundedWait::new(MAX_TIMEOUT_MS)
            .expect("at the ceiling")
            .timeout_ms(),
        60_000
    );

    for rejected in [0, MAX_TIMEOUT_MS + 1] {
        match BoundedWait::new(rejected) {
            Err(error) => {
                assert_eq!(error.code(), ERR_GUARD_TIMEOUT);
                assert!(
                    matches!(error, AcquireError::TimeoutOutOfRange { timeout_ms } if timeout_ms == rejected)
                );
            }
            Ok(wait) => panic!("expected {rejected} to be refused, got {wait:?}"),
        }
    }
}

#[test]
fn retry_delays_start_at_25ms_double_then_cap_at_250ms() {
    let delays: Vec<u64> = BoundedWait::standard().retry_delays().take(7).collect();
    assert_eq!(delays, vec![25, 50, 100, 200, 250, 250, 250]);
}

// ------------------------------------------------------ native guard legs

#[test]
fn a_second_exclusive_holder_is_refused_rather_than_blocking() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let dir = guard_dir(&temp);
    let held = dir
        .try_acquire(GuardRole::Admission, LockMode::Exclusive)
        .expect("first holder");
    assert_eq!(held.role(), GuardRole::Admission);
    assert_eq!(held.mode(), LockMode::Exclusive);
    assert_eq!(held.path(), dir.lock_path(GuardRole::Admission));
    assert_eq!(held.share_mode_pinned(), cfg!(windows));
    assert_eq!(
        axiom_platform::guard::HeldGuard::share_mode_pin_required(),
        cfg!(windows)
    );

    let error = dir
        .try_acquire(GuardRole::Admission, LockMode::Exclusive)
        .expect_err("contended");
    assert_eq!(error.code(), "solution-guard-locked");
    assert_eq!(error.role(), Some(GuardRole::Admission));

    held.release().expect("release");
    dir.try_acquire(GuardRole::Admission, LockMode::Exclusive)
        .expect("free again");
}

#[test]
fn an_exclusive_holder_still_permits_a_shared_reader_of_the_other_file() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let dir = guard_dir(&temp);
    let admission = dir
        .try_acquire(GuardRole::Admission, LockMode::Exclusive)
        .expect("exclusive");
    // A different lock file in the same directory is unaffected.
    let data = dir
        .try_acquire(GuardRole::Data, LockMode::Shared)
        .expect("shared data");
    // The same file in exclusive mode cannot also be taken shared.
    let error = dir
        .try_acquire(GuardRole::Admission, LockMode::Shared)
        .expect_err("same file");
    assert_eq!(error.code(), "solution-guard-locked");
    data.release().expect("release data");
    admission.release().expect("release admission");
}

#[test]
fn dropping_a_guard_releases_it_because_the_os_owns_the_lock() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let dir = guard_dir(&temp);
    {
        let _held = dir
            .try_acquire(GuardRole::Data, LockMode::Exclusive)
            .expect("held");
    }
    dir.try_acquire(GuardRole::Data, LockMode::Exclusive)
        .expect("released by drop");
}

#[test]
fn the_publisher_set_holds_both_guards_exclusively_and_releases_fully() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let dir = guard_dir(&temp);
    let set = dir
        .acquire_exclusive(
            BoundedWait::standard(),
            &RealClock::new(),
            &mut RealSleeper,
            &NeverCancelled,
        )
        .expect("publisher acquires");
    assert_eq!(set.roles(), vec![GuardRole::Admission, GuardRole::Data]);
    assert!(set.holds_both_exclusive());
    assert_eq!(set.data().role(), GuardRole::Data);
    assert_eq!(set.data().mode(), LockMode::Exclusive);
    set.release();

    // Nothing is left held: the same plan can run again immediately.
    dir.acquire_exclusive(
        BoundedWait::standard(),
        &RealClock::new(),
        &mut RealSleeper,
        &NeverCancelled,
    )
    .expect("reacquire after release")
    .release();
}

#[test]
fn a_reader_releases_admission_before_the_payload_and_keeps_its_data_guard() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let dir = guard_dir(&temp);
    let mut reader = dir
        .acquire_reader(
            BoundedWait::standard(),
            &RealClock::new(),
            &mut RealSleeper,
            &NeverCancelled,
        )
        .expect("reader acquires");
    assert_eq!(reader.admission_mode(), Some(LockMode::Shared));
    assert_eq!(reader.data().role(), GuardRole::Data);

    reader.release_admission().expect("early release");
    assert_eq!(reader.admission_mode(), None);

    // Admission is provably free while the reader still pins its generation.
    let admission = dir
        .try_acquire(GuardRole::Admission, LockMode::Exclusive)
        .expect("admission is free after the early release");
    let blocked = dir
        .try_acquire(GuardRole::Data, LockMode::Exclusive)
        .expect_err("the reader still pins data");
    assert_eq!(blocked.code(), "solution-guard-locked");
    assert_eq!(blocked.role(), Some(GuardRole::Data));

    admission.release().expect("release admission");
    reader.release().expect("release reader");
    dir.try_acquire(GuardRole::Data, LockMode::Exclusive)
        .expect("data is free after the reader releases");
}

#[test]
fn an_expired_bound_reports_the_timeout_and_leaves_nothing_held() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let dir = guard_dir(&temp);
    let publisher = dir
        .acquire_exclusive(
            BoundedWait::standard(),
            &RealClock::new(),
            &mut RealSleeper,
            &NeverCancelled,
        )
        .expect("publisher holds everything");
    // The clock is already past the bound, so the wait must not sleep once.
    let mut sleeper = RecordingSleeper::default();
    let error = dir
        .acquire_reader(
            BoundedWait::new(1).expect("a bounded wait"),
            &FrozenClock(MAX_TIMEOUT_MS),
            &mut sleeper,
            &NeverCancelled,
        )
        .expect_err("bound expired");
    assert_eq!(error.code(), ERR_GUARD_TIMEOUT);
    assert_eq!(error.role(), Some(GuardRole::Admission));
    assert!(
        matches!(error, AcquireError::LayerTimedOut { timeout_ms: 1, .. }),
        "unexpected: {error:?}"
    );
    assert!(
        sleeper.waits.is_empty(),
        "the bound is checked before sleeping"
    );
    assert_eq!(sleeper.total_ms, 0);

    publisher.release();
    dir.acquire_reader(
        BoundedWait::standard(),
        &RealClock::new(),
        &mut RealSleeper,
        &NeverCancelled,
    )
    .expect("free after the publisher releases")
    .release()
    .expect("release");
}

#[test]
fn a_cancelled_wait_stops_without_taking_anything() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let dir = guard_dir(&temp);
    let cancel = CancelFlag::new();
    cancel.cancel();
    assert!(cancel.is_cancelled());
    let mut sleeper = RecordingSleeper::default();
    let error = dir
        .acquire_bounded(
            GuardRole::Data,
            LockMode::Exclusive,
            BoundedWait::standard(),
            &FrozenClock(0),
            &mut sleeper,
            &cancel,
        )
        .expect_err("cancelled");
    assert_eq!(error.code(), ERR_GUARD_CANCELLED);
    assert_eq!(error.role(), Some(GuardRole::Data));
    assert_eq!(error.to_string(), "guard-cancelled: data wait cancelled");
    assert!(sleeper.waits.is_empty());
    assert!(
        !dir.lock_path(GuardRole::Data).exists(),
        "nothing was created"
    );

    // `NeverCancelled` is the explicit no-op token.
    assert!(!NeverCancelled.is_cancelled());
}

#[test]
fn a_guard_path_that_is_not_a_directory_is_reported_as_a_guard_directory_error() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let occupied = temp.path().join(GUARD_DIR_NAME);
    std::fs::write(&occupied, b"not a directory").expect("write file");
    let dir = GuardDir::at(occupied.as_path());
    let error = dir
        .try_acquire(GuardRole::Admission, LockMode::Exclusive)
        .expect_err("refused");
    assert_eq!(error.code(), ERR_GUARD_DIR);
    assert!(error.to_string().contains("guard-directory"));
    assert!(error.role().is_none());
}

// ------------------------------------------------------------ retention GC

#[test]
fn gc_requires_the_exclusive_guard_set_and_refuses_a_partially_exposed_pointer() {
    let candidates = ["g1", "g2", "g3"].map(str::to_string);
    let protection = GcProtection {
        current_pointer: Some("g2".to_string()),
        reader_pinned: vec!["g3".to_string()],
        partially_exposed: Vec::new(),
    };

    assert_eq!(
        plan_gc(GuardObservation::default(), &protection, &candidates).expect_err("no guard"),
        GcRefusal::NoGuard
    );
    let shared = GuardObservation {
        admission: Some(LockMode::Exclusive),
        data: Some(LockMode::Shared),
    };
    assert_eq!(
        plan_gc(shared, &protection, &candidates).expect_err("not exclusive"),
        GcRefusal::NotExclusive
    );
    let exposed = GuardObservation::exclusive();
    let mut unsafe_protection = protection.clone();
    unsafe_protection.partially_exposed.push("g1".to_string());
    assert_eq!(
        plan_gc(exposed, &unsafe_protection, &candidates).expect_err("partial pointer"),
        GcRefusal::PointerPartiallyExposed
    );
    assert_eq!(GcRefusal::NoGuard.as_str(), "gc-without-guard");
    assert_eq!(GcRefusal::NotExclusive.as_str(), "gc-guard-not-exclusive");
    assert_eq!(
        GcRefusal::PointerPartiallyExposed.as_str(),
        "gc-pointer-partially-exposed"
    );
    assert!(exposed.is_exclusive_on_both());
}

#[test]
fn gc_keeps_the_current_pointer_and_every_reader_pinned_generation() {
    let plan = plan_gc(
        GuardObservation::exclusive(),
        &GcProtection {
            current_pointer: Some("g2".to_string()),
            reader_pinned: vec!["g1".to_string(), "g3".to_string()],
            partially_exposed: Vec::new(),
        },
        &["g1", "g2", "g3", "g4"].map(str::to_string),
    )
    .expect("a legal retention plan");
    assert_eq!(plan.deletable, vec!["g4".to_string()]);
    assert_eq!(
        plan.retained,
        vec!["g1".to_string(), "g2".to_string(), "g3".to_string()]
    );
}

// ------------------------------------------------- crash release, in earnest

#[test]
fn a_crashed_process_releases_its_guards() {
    // Child mode: take both exclusive guards, then die without releasing.
    if let Ok(raw) = std::env::var(CHILD_GUARD_DIR_ENV) {
        let dir = GuardDir::at(PathBuf::from(raw));
        let set = dir
            .acquire_exclusive(
                BoundedWait::standard(),
                &RealClock::new(),
                &mut RealSleeper,
                &NeverCancelled,
            )
            .expect("the child takes both guards");
        assert!(set.holds_both_exclusive());
        std::mem::forget(set);
        std::process::exit(CHILD_EXIT_CODE);
    }

    let temp = tempfile::tempdir().expect("temporary directory");
    let dir = guard_dir(&temp);
    let executable = std::env::current_exe().expect("the test binary");
    let status = Command::new(executable)
        .args([CRASH_TEST_NAME, "--exact", "--nocapture"])
        .env(CHILD_GUARD_DIR_ENV, dir.path().display().to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn the child");
    assert_eq!(
        status.code(),
        Some(CHILD_EXIT_CODE),
        "the child died holding the guards"
    );

    // The OS released the dead process's locks: the parent takes both now.
    let set = dir
        .acquire_exclusive(
            BoundedWait::standard(),
            &RealClock::new(),
            &mut RealSleeper,
            &NeverCancelled,
        )
        .expect("the parent acquires after the crash");
    assert!(set.holds_both_exclusive());
    set.release();
}
