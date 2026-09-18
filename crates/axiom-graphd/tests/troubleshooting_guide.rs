//! Regression test for the troubleshooting guide (task D-016).
//!
//! `docs/guides/troubleshooting.md` separates five recoverable conditions that
//! an operator easily confuses: a missing daemon, a stale graph, a corrupt
//! shard, a queue delay and an unsupported host. The guide is compiled into this
//! test binary and replayed through the real surfaces, so the document cannot
//! drift from the product alone:
//!
//! * the doctor report and the `status` report (`axiom_graphd::commands::doctor`),
//! * the generation validator (`graph_export::validate`),
//! * the queue retry classifier (`graph_queue::retry`),
//! * the store opener and its storage-class refusal (`graph_store::open`).
//!
//! The positive path proves each condition is detected by the surface the guide
//! names. The negative and boundary paths prove the conditions stay distinct:
//! only the stale graph and the queue delay are retryable, the codes that exist
//! are pairwise different, an unsupported host is never handed a queue delay,
//! and the backoff is bounded so a transient failure is eventually given up.

use axiom_graphd::commands::doctor::{
    self, HealthState, WatcherHealth, WatcherMode, REASON_QUEUE_RETRY_WAIT, REASON_WATCHER_DEGRADED,
};
use graph_core::config::JournalMode;
use graph_core::error::{exit_code_for, ErrorCode};
use graph_core::paths::StorageClass;
use graph_export::canonical::canonical_document;
use graph_export::manifest::{self, ManifestEntry};
use graph_export::validate::{validate_generation, ERR_NOT_CANONICAL};
use graph_export::{GraphRecord, ERR_INTEGRITY, ERR_MISSING};
use graph_queue::retry::{
    classify_error_code, decide, BackoffPolicy, FailureClass, RetryDecision, MAX_TRANSIENT_ATTEMPTS,
};
use graph_store::{LexicalVolumeProbe, OpenOptions, VolumeProbe};
use rusqlite::Connection;
use serde_json::Value;
use std::fs;
use std::path::Path;

/// The guide document, compiled in so the documentation cannot drift alone.
const TROUBLESHOOTING_GUIDE: &str = include_str!("../../../docs/guides/troubleshooting.md");

const BEGIN: &str = "<!-- BEGIN TROUBLESHOOTING EXAMPLE -->";
const END: &str = "<!-- END TROUBLESHOOTING EXAMPLE -->";
const JSON_FENCE: &str = "```json";

/// The fenced `json` example between the guide's sentinel markers.
fn example_json() -> String {
    let after_begin = TROUBLESHOOTING_GUIDE
        .split_once(BEGIN)
        .expect("the guide must keep its BEGIN marker")
        .1;
    let block = after_begin
        .split_once(END)
        .expect("the guide must keep its END marker")
        .0;
    let start = block
        .find(JSON_FENCE)
        .expect("the example must be a fenced json block")
        + JSON_FENCE.len();
    let rest = &block[start..];
    let end = rest.find("```").expect("the json fence must be closed");
    rest[..end].trim().to_owned()
}

fn example() -> Value {
    serde_json::from_str(&example_json()).expect("the documented example must be valid JSON")
}

fn field<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("example field {key}"))
}

/// The `conditions[]` entry with the requested id.
fn condition(value: &Value, id: &str) -> Value {
    value
        .get("conditions")
        .and_then(Value::as_array)
        .expect("example field conditions")
        .iter()
        .find(|entry| entry.get("condition").and_then(Value::as_str) == Some(id))
        .cloned()
        .unwrap_or_else(|| panic!("the example must describe the {id} condition"))
}

/// A storage probe fixed to one class, so a share can be modelled without one.
struct FixedProbe(StorageClass);

impl VolumeProbe for FixedProbe {
    fn classify(&self, _path: &Path) -> StorageClass {
        self.0
    }
}

/// The shipped schema on a private in-memory database.
fn open_connection() -> Connection {
    let connection = Connection::open_in_memory().expect("in-memory sqlite");
    connection
        .execute_batch(graph_store::SCHEMA_V1_SQL)
        .expect("shipped schema");
    connection
}

/// One registered solution with one project, as the doctor probes expect.
fn seed_solution(connection: &Connection, id: &str) {
    connection
        .execute(
            "INSERT INTO solutions (id, workspace_instance_id, profile, config_hash) \
             VALUES (?1, ?2, 'default', 'hash')",
            rusqlite::params![id, format!("wi-{id}")],
        )
        .expect("solution");
    connection
        .execute(
            "INSERT INTO projects (id, solution_id, repo_id, relative_path) \
             VALUES (?1, ?2, 'repo-main', 'src')",
            rusqlite::params![format!("{id}-project"), id],
        )
        .expect("project");
}

/// Write one generation directory holding one shard plus its manifest.
fn write_generation(directory: &Path, shard: &[u8], records: usize) {
    fs::create_dir_all(directory).expect("mkdir");
    let manifest = manifest::build(vec![ManifestEntry::from_bytes(
        "bucket-000",
        shard,
        records,
    )])
    .expect("manifest");
    fs::write(directory.join("bucket-000"), shard).expect("shard");
    fs::write(
        directory.join("manifest.json"),
        serde_json::to_vec(&manifest).expect("json"),
    )
    .expect("manifest file");
}

fn shard_of_a_small_graph() -> Vec<u8> {
    canonical_document(&[GraphRecord::new(
        "edge:a->b",
        "edge",
        serde_json::json!({"from": "a", "to": "b"}),
    )])
    .expect("canonical shard")
}

/// AC1: a daemon that is not running is a *disabled* watcher, which is degraded
/// rather than unavailable, and it raises no error code at all.
#[test]
fn troubleshooting_guide_missing_daemon_is_a_disabled_watcher() {
    let value = example();
    let entry = condition(&value, "missing-daemon");
    assert_eq!(field(&entry, "first_signal"), "watcher-disabled");
    assert!(
        entry["error_code"].is_null(),
        "a missing daemon raises no error code"
    );
    assert!(entry["exit_code"].is_null());
    assert_eq!(entry["retryable"].as_bool(), Some(false));

    let solution = field(&value, "solution_id");
    let connection = open_connection();
    seed_solution(&connection, solution);
    let watcher = WatcherHealth::degraded(
        WatcherMode::Disabled,
        "no daemon is watching; only explicit hints are honored",
    );
    let report = doctor::report(&connection, solution, watcher).expect("doctor report");
    assert_eq!(report.watcher.mode.wire(), "disabled");
    assert!(!report.watcher.healthy);
    assert_eq!(report.overall_label(), "degraded");
    assert_eq!(WatcherMode::parse("disabled"), Some(WatcherMode::Disabled));
    assert!(report
        .diagnostics
        .iter()
        .any(|reason| reason == REASON_WATCHER_DEGRADED));

    // Boundary: a degraded component is separable from an unavailable one, so a
    // stopped daemon is not reported as a broken database.
    assert!(HealthState::Healthy < HealthState::Degraded);
    assert!(HealthState::Degraded < HealthState::Unavailable);
}

/// AC1: a stale graph is reported honestly by `status` and its bounded-query
/// refusal is the retryable `NOT_READY` at exit code 4.
#[test]
fn troubleshooting_guide_stale_graph_is_a_retryable_not_ready() {
    let value = example();
    let entry = condition(&value, "stale-graph");
    assert_eq!(field(&entry, "first_signal"), "full-scan-required");
    assert_eq!(field(&entry, "error_code"), "NOT_READY");
    assert_eq!(entry["exit_code"].as_i64(), Some(4));
    assert_eq!(entry["retryable"].as_bool(), Some(true));

    let solution = field(&value, "solution_id");
    let connection = open_connection();
    seed_solution(&connection, solution);
    connection
        .execute(
            "INSERT INTO files (id, project_id, path, desired_generation, indexed_generation) \
             VALUES (1, ?1, 'src/a.rs', 1, 0)",
            rusqlite::params![format!("{solution}-project")],
        )
        .expect("file");
    connection
        .execute(
            "INSERT INTO dirty_files (file_id, target_generation, first_seen, last_seen, reason) \
             VALUES (1, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'edit')",
            [],
        )
        .expect("dirty file");

    let status = doctor::status(&connection, solution).expect("status report");
    assert!(
        status.full_scan_required,
        "a fresh solution still needs a scan"
    );
    assert_eq!(status.dirty_files, 1, "the dirty file is counted");
    assert_eq!(status.event_seq, 0);

    let code = ErrorCode::NotReady;
    assert_eq!(exit_code_for(code).as_i32(), 4);
    assert_eq!(code.as_str(), "NOT_READY");
    assert!(code.default_retryable());
}

/// AC1: a corrupt shard is an integrity fault of generation validation, and it
/// is neither a missing generation nor a non-canonical one.
#[test]
fn troubleshooting_guide_corrupt_shard_is_an_integrity_fault() {
    let value = example();
    let entry = condition(&value, "corrupt-shard");
    assert_eq!(field(&entry, "first_signal"), "export-integrity");
    assert_eq!(field(&entry, "error_code"), ERR_INTEGRITY);
    assert!(entry["exit_code"].is_null());
    assert_eq!(entry["retryable"].as_bool(), Some(false));

    let directory = tempfile::tempdir().expect("temp dir");
    let generation = directory.path().join("generations").join("gid-0000");
    write_generation(&generation, &shard_of_a_small_graph(), 1);

    // Boundary: the untouched generation validates, so a fault is a change.
    let report = validate_generation(&generation).expect("a clean generation validates");
    assert_eq!(report.records, 1);
    assert_eq!(report.files, 1);

    let mut shard = fs::read(generation.join("bucket-000")).expect("read shard");
    shard[5] = b'X';
    fs::write(generation.join("bucket-000"), &shard).expect("write shard");
    let corrupt = validate_generation(&generation).expect_err("corruption must be refused");
    assert_eq!(corrupt.code, ERR_INTEGRITY);
    assert_ne!(
        corrupt.code, ERR_MISSING,
        "corruption is not a missing file"
    );
    assert_ne!(
        corrupt.code, ERR_NOT_CANONICAL,
        "corruption is not a formatting fault"
    );

    // A generation whose manifest is gone is the *other* condition.
    let missing = directory.path().join("generations").join("gid-none");
    fs::create_dir_all(&missing).expect("mkdir");
    assert_eq!(
        validate_generation(&missing)
            .expect_err("missing manifest")
            .code,
        ERR_MISSING
    );
}

/// AC1: a queue delay is a bounded, retryable backoff, and the doctor report
/// says a job is waiting rather than failed.
#[test]
fn troubleshooting_guide_queue_delay_is_a_bounded_retryable_backoff() {
    let value = example();
    let entry = condition(&value, "queue-delay");
    assert_eq!(field(&entry, "first_signal"), "queue-retry-wait");
    assert_eq!(field(&entry, "error_code"), "RATE_LIMITED");
    assert_eq!(entry["exit_code"].as_i64(), Some(7));
    assert_eq!(entry["retryable"].as_bool(), Some(true));

    let solution = field(&value, "solution_id");
    let connection = open_connection();
    seed_solution(&connection, solution);
    connection
        .execute(
            "INSERT INTO jobs (id, solution_id, kind, scope_key, state, target_event_seq, \
             ready_at, created_at) \
             VALUES ('job-retry', ?1, 'reconcile', 'dirty', 'RETRY_WAIT', 3, \
             '2026-01-01T00:00:05Z', '2026-01-01T00:00:00Z')",
            rusqlite::params![solution],
        )
        .expect("retry-wait job");

    let health = doctor::read_queue_health(&connection, solution).expect("queue health");
    assert_eq!(health.retry_wait, 1);
    assert_eq!(health.failed, 0, "a delay is not a failure");
    let report =
        doctor::report(&connection, solution, WatcherHealth::native()).expect("doctor report");
    assert_eq!(report.overall_label(), "degraded");
    assert!(report
        .diagnostics
        .iter()
        .any(|reason| reason == REASON_QUEUE_RETRY_WAIT));

    let code = ErrorCode::RateLimited;
    assert_eq!(exit_code_for(code).as_i32(), 7);
    assert!(code.default_retryable());
    let policy = BackoffPolicy::documented_default();
    let decision = decide(classify_error_code(code), 1, &policy, 11);
    assert!(decision.is_retry(), "a transient failure is requeued");
    let delay = decision.delay_ms().expect("a retry carries a delay");
    assert!(delay >= 1, "the delay is positive");
    assert!(delay <= policy.cap_ms(), "the delay is bounded");
}

/// AC1: an unsupported host is refused by storage class and is not retried.
#[test]
fn troubleshooting_guide_unsupported_host_is_refused_and_not_retried() {
    let value = example();
    let entry = condition(&value, "unsupported-host");
    assert_eq!(
        field(&entry, "first_signal"),
        "sqlite-network-storage-unsupported"
    );
    let code = ErrorCode::SqliteNetworkStorageUnsupported;
    assert_eq!(field(&entry, "error_code"), code.as_str());
    assert_eq!(entry["exit_code"].as_i64(), Some(9));
    assert_eq!(entry["retryable"].as_bool(), Some(false));
    assert_eq!(exit_code_for(code).as_i32(), 9);
    assert!(!code.default_retryable());

    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("AXIOM_HOME").join("index.sqlite");
    let share = FixedProbe(StorageClass::NetworkShare);
    let refused = graph_store::open::open(&OpenOptions::file(&path), &share)
        .expect_err("mutable state on a share must be refused");
    assert_eq!(refused.code(), code);
    assert_eq!(
        refused.details().get("rule").map(String::as_str),
        Some("mutable-state-local-storage-only")
    );
    assert_eq!(
        refused.details().get("storage_class").map(String::as_str),
        Some("network_share")
    );

    // Boundary: the refusal is about the storage class, not only about the flag.
    let degraded = graph_store::open::open(
        &OpenOptions::file(&path).with_require_local_storage(false),
        &share,
    )
    .expect_err("WAL on a share must be refused even when degradation was requested");
    assert_eq!(degraded.code(), code);
    assert_eq!(
        degraded.details().get("rule").map(String::as_str),
        Some("wal-local-storage-only")
    );

    // The probe is what decides: the same explicit degradation is accepted on
    // local disk, and the degradation is also allowed on the share, so the
    // earlier refusals came from the storage class rather than from the path.
    // The explicit DELETE mode is used because this host's SQLite runtime is
    // below the WAL baseline, which is a separate, unrelated condition.
    let local = directory.path().join("local.sqlite");
    graph_store::open::open(
        &OpenOptions::file(&local)
            .with_journal_mode(JournalMode::Delete)
            .with_require_local_storage(false),
        &LexicalVolumeProbe,
    )
    .expect("local storage opens");
    graph_store::open::open(
        &OpenOptions::file(&path)
            .with_journal_mode(JournalMode::Delete)
            .with_require_local_storage(false),
        &share,
    )
    .expect("explicit degradation is allowed on a share");
}

/// AC2 negative/boundary: the five conditions stay distinguishable, and a fault
/// the operator must repair is never treated as a queue delay.
#[test]
fn troubleshooting_guide_keeps_the_five_conditions_distinct() {
    let value = example();
    let conditions = value
        .get("conditions")
        .and_then(Value::as_array)
        .expect("example field conditions");
    assert_eq!(conditions.len(), 5, "the guide separates exactly five");

    let mut names: Vec<&str> = conditions
        .iter()
        .map(|entry| field(entry, "condition"))
        .collect();
    let mut signals: Vec<&str> = conditions
        .iter()
        .map(|entry| field(entry, "first_signal"))
        .collect();
    names.sort_unstable();
    signals.sort_unstable();
    names.dedup();
    signals.dedup();
    assert_eq!(names.len(), 5, "every condition has a distinct name");
    assert_eq!(
        signals.len(),
        5,
        "every condition has a distinct first signal"
    );

    // Exactly the stale graph and the queue delay are retryable.
    let retryable: Vec<&str> = conditions
        .iter()
        .filter(|entry| entry["retryable"].as_bool() == Some(true))
        .map(|entry| field(entry, "condition"))
        .collect();
    assert_eq!(retryable, vec!["stale-graph", "queue-delay"]);

    // The exit codes that exist are pairwise distinct.
    let mut exits: Vec<i64> = conditions
        .iter()
        .filter_map(|entry| entry["exit_code"].as_i64())
        .collect();
    assert_eq!(
        exits.len(),
        3,
        "three of the five conditions carry an exit code"
    );
    exits.sort_unstable();
    exits.dedup();
    assert_eq!(exits.len(), 3, "the exit codes must not collide");

    // The unsupported host is permanent, so it must never be handed a delay.
    let policy = BackoffPolicy::documented_default();
    let host = classify_error_code(ErrorCode::SqliteNetworkStorageUnsupported);
    assert_eq!(host, FailureClass::Permanent);
    assert!(!host.is_transient());
    let decision = decide(host, 1, &policy, 11);
    assert!(
        !decision.is_retry(),
        "an unsupported host must not be retried"
    );
    assert_eq!(decision.delay_ms(), None);

    // The corrupt-shard fault is permanent for the same reason.
    assert_eq!(
        decide(FailureClass::Permanent, 1, &policy, 11).delay_ms(),
        None
    );
    assert!(matches!(
        decide(FailureClass::Permanent, 1, &policy, 11),
        RetryDecision::GiveUp { .. }
    ));

    // ...while the same call is correct for the two transient conditions.
    assert!(classify_error_code(ErrorCode::NotReady).is_transient());
    assert!(decide(classify_error_code(ErrorCode::NotReady), 1, &policy, 11).is_retry());
    assert!(decide(classify_error_code(ErrorCode::RateLimited), 1, &policy, 11).is_retry());

    // Boundary: the backoff is bounded, so even a transient failure is given up.
    assert!(
        !decide(
            FailureClass::TransientIo,
            MAX_TRANSIENT_ATTEMPTS,
            &policy,
            11
        )
        .is_retry(),
        "the retry budget is finite"
    );
    assert!(decide(FailureClass::TransientIo, 0, &policy, 11)
        .delay_ms()
        .is_none());
}
