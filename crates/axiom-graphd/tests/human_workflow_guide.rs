//! Regression test for the human editing and reconciliation guide (task D-009).
//!
//! `docs/guides/human-workflow.md` is part of the product, not a copy of it.
//! The worked example is compiled into this test binary and replayed through the
//! real watcher surfaces: the debouncer that coalesces an editor's save burst
//! (`graph_watch::debounce`), the normalizer that pairs a rename's two sides
//! (`graph_watch::normalize`), the ignore policy that excludes formatter and
//! generated output (`graph_watch::ignore`), the startup inventory planner that
//! finds offline edits (`graph_watch::inventory`), the snapshot-diffing polling
//! watcher (`graph_watch::poll`) and the declared backend selector.
//!
//! The point of the guide is that a human never submits a file by hand, so the
//! positive path proves that several saves become one batch, a rename becomes
//! one removal plus one upsert, and offline edits are found without touching
//! them. The negative and boundary paths prove a non-portable reported path is
//! refused rather than rewritten, that the polling watcher's first poll claims
//! no change, and that `require_native` on a host without native events refuses
//! to start.

use graph_core::error::{AxiomError, ErrorCode};
use graph_watch::debounce::{DebouncePolicy, Debouncer, FlushTrigger};
use graph_watch::ignore::{IgnoreDecision, IgnorePolicy, IgnoreReason};
use graph_watch::input_policy::InputPolicy;
use graph_watch::inventory::{
    plan_inventory, DirentSource, InventoryEvent, KnownInventory, ScannedEntry, ScannedKind,
    WalkReport,
};
use graph_watch::native::NativeSupport;
use graph_watch::normalize::{normalize, FileAction, RawHint, RawKind};
use graph_watch::poll::{
    select_backend, BackendKind, BackendPolicy, FileStamp, PollingWatcher, SnapshotSource,
};
use graph_watch::same_path;
use serde_json::Value;
use std::cell::RefCell;
use std::path::Path;
use std::time::{Duration, Instant};

/// The guide document, compiled in so the documentation cannot drift alone.
const HUMAN_WORKFLOW_GUIDE: &str = include_str!("../../../docs/guides/human-workflow.md");

const BEGIN: &str = "<!-- BEGIN HUMAN WORKFLOW EXAMPLE -->";
const END: &str = "<!-- END HUMAN WORKFLOW EXAMPLE -->";
const JSON_FENCE: &str = "```json";

/// The fenced `json` example between the guide's sentinel markers.
fn example_json() -> String {
    let after_begin = HUMAN_WORKFLOW_GUIDE
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

fn string_list(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("example field {key}"))
        .iter()
        .map(|item| item.as_str().expect("string entry").to_owned())
        .collect()
}

fn field<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("example field {key}"))
}

/// AC1: an editor's save burst becomes one batch of distinct paths, so the
/// human saves and stops rather than submitting every changed file.
#[test]
fn human_workflow_guide_saves_coalesce_without_manual_submission() {
    let value = example();
    let policy = DebouncePolicy::new(
        value["debounce_ms"].as_u64().expect("debounce_ms"),
        value["max_wait_ms"].as_u64().expect("max_wait_ms"),
    )
    .expect("the guide's debounce bounds are valid");
    let mut debouncer = Debouncer::new(policy);
    let start = Instant::now();
    let burst = string_list(&value, "save_burst");
    assert!(burst.len() > 2, "the example must show repeated saves");

    for (index, path) in burst.iter().enumerate() {
        let now = start + Duration::from_millis(index as u64 * 10);
        debouncer.note(path, now).expect("a portable save path");
    }

    // Nothing is released before the quiet period elapses.
    assert!(
        debouncer.take(start + Duration::from_millis(10)).is_none(),
        "the debouncer must hold the burst"
    );

    let batch = debouncer
        .take(start + Duration::from_millis(1000))
        .expect("the burst must be released");
    let paths = batch.paths().to_vec();
    assert_eq!(
        paths,
        vec!["src/App.cs".to_string(), "src/Widget.cs".to_string()],
        "repeated saves collapse to one entry per distinct path, in stable order"
    );
    assert!(
        paths.len() < burst.len(),
        "five saves must not become five entries"
    );
    assert_eq!(batch.trigger(), FlushTrigger::QuietPeriod);
    assert_eq!(
        value["manual_file_submissions_required"].as_u64(),
        Some(0),
        "the guide must state that no per-file submission is required"
    );
}

/// AC1: a rename is one removal plus one upsert carrying the origin, and a
/// case-only rename is classified the way the host filesystem compares paths.
#[test]
fn human_workflow_guide_rename_pairs_both_sides() {
    let value = example();
    let rename = value.get("rename").expect("rename");
    let from = field(rename, "from");
    let to = field(rename, "to");

    let outcome = normalize(&[
        RawHint::new(from, RawKind::RenamedFrom),
        RawHint::new(to, RawKind::RenamedTo),
    ])
    .expect("a rename normalizes");
    let actions: Vec<(FileAction, &str)> = outcome
        .hints()
        .iter()
        .map(|hint| (hint.action(), hint.path()))
        .collect();
    assert_eq!(
        actions,
        vec![(FileAction::Remove, from), (FileAction::Upsert, to)]
    );
    let upsert = outcome
        .hints()
        .iter()
        .find(|hint| hint.action() == FileAction::Upsert)
        .expect("upsert");
    assert_eq!(upsert.origin(), Some(from));
    assert!(!upsert.is_case_only_rename());
    assert!(outcome.unmatched_renames_from().is_empty());

    let case = value.get("case_only_rename").expect("case_only_rename");
    let case_from = field(case, "from");
    let case_to = field(case, "to");
    let outcome = normalize(&[
        RawHint::new(case_from, RawKind::RenamedFrom),
        RawHint::new(case_to, RawKind::RenamedTo),
    ])
    .expect("a case-only rename normalizes");
    let upsert = outcome
        .hints()
        .iter()
        .find(|hint| hint.action() == FileAction::Upsert)
        .expect("upsert");
    assert_eq!(upsert.path(), case_to);
    assert_eq!(upsert.origin(), Some(case_from));
    assert_eq!(
        upsert.is_case_only_rename(),
        same_path(case_from, case_to),
        "case-only detection must follow the host filesystem comparison"
    );
}

/// AC1: a formatter's write under the generated output root is excluded while
/// its write to a source path stays tracked, so a formatter run never requeues
/// the graph data it just wrote.
#[test]
fn human_workflow_guide_formatter_output_is_ignored_but_source_is_tracked() {
    let value = example();
    let policy = IgnorePolicy::new(field(&value, "generated_output_root"));
    let writes = string_list(&value, "formatter_writes");
    assert_eq!(writes.len(), 2, "the example names two formatter writes");

    let generated = policy
        .classify(&writes[0])
        .expect("the generated path is classified");
    assert_eq!(generated.reason(), Some(IgnoreReason::GeneratedGraphData));
    match generated {
        IgnoreDecision::Ignored { rule, .. } => assert_eq!(rule, "policy.graph-output-root"),
        IgnoreDecision::Tracked => panic!("generated graph data must be excluded"),
    }

    let source = policy
        .classify(&writes[1])
        .expect("the source path is classified");
    assert!(source.is_tracked(), "a source write must stay tracked");
}

/// A canned complete walk, so the offline case is deterministic.
#[derive(Debug)]
struct CannedWalk {
    report: WalkReport,
}

impl DirentSource for CannedWalk {
    fn walk(&self, _root: &Path) -> Result<WalkReport, AxiomError> {
        Ok(self.report.clone())
    }
}

fn file(path: &str, digest: &str) -> ScannedEntry {
    ScannedEntry::new(path, ScannedKind::File, 16, Some(digest.to_owned()))
}

/// AC1: edits made while the daemon was stopped are found by comparing a fresh
/// walk against the stored inventory, with no manual re-save or `git add`.
#[test]
fn human_workflow_guide_offline_edits_are_found_by_the_inventory() {
    let value = example();
    let offline = value.get("offline_edits").expect("offline_edits");
    let modified = string_list(offline, "modified");
    let created = string_list(offline, "created");
    let removed = string_list(offline, "removed");
    assert_eq!(modified.len(), 1);
    assert_eq!(created.len(), 1);
    assert_eq!(removed.len(), 1);

    // The stored inventory still holds the pre-edit digest for the modified
    // path and the vanished path; both were recorded before the daemon stopped.
    let known = KnownInventory::from_pairs([
        (modified[0].clone(), "digest-before-the-edit".to_owned()),
        (removed[0].clone(), "digest-of-the-deleted-file".to_owned()),
    ]);
    let walk = CannedWalk {
        report: WalkReport::new(
            vec![
                file(&modified[0], "digest-after-the-offline-edit"),
                file(&created[0], "digest-of-the-new-file"),
                file("live/generations/shard-0000.json", "generated"),
            ],
            Vec::new(),
            false,
        ),
    };
    let policy = IgnorePolicy::new(field(&value, "generated_output_root"));
    let input = InputPolicy::new("C:/work/proj");
    let plan = plan_inventory(&walk, Path::new("."), &known, &policy, &input)
        .expect("the inventory plan is produced");

    let described: Vec<(&str, &str)> = plan
        .events()
        .iter()
        .map(|event| {
            let kind = match event {
                InventoryEvent::Added { .. } => "added",
                InventoryEvent::Modified { .. } => "modified",
                InventoryEvent::Deleted { .. } => "deleted",
            };
            (kind, event.path())
        })
        .collect();
    assert_eq!(
        described,
        vec![
            ("deleted", removed[0].as_str()),
            ("added", created[0].as_str()),
            ("modified", modified[0].as_str()),
        ],
        "deletions precede additions precede modifications"
    );
    assert_eq!(plan.unchanged(), 0);
    assert!(!plan.requires_full_scan());
    assert!(
        plan.excluded()
            .iter()
            .any(|entry| entry.path() == "live/generations/shard-0000.json"
                && entry.reason() == IgnoreReason::GeneratedGraphData),
        "formatter output must not appear as an offline edit"
    );
}

/// A canned sequence of snapshots for the polling watcher.
#[derive(Debug)]
struct CannedSnapshots {
    snapshots: RefCell<Vec<Vec<(String, FileStamp)>>>,
}

impl SnapshotSource for CannedSnapshots {
    fn snapshot(&self, _root: &Path) -> Result<Vec<(String, FileStamp)>, AxiomError> {
        let mut snapshots = self.snapshots.borrow_mut();
        if snapshots.is_empty() {
            return Ok(Vec::new());
        }
        Ok(snapshots.remove(0))
    }
}

/// AC1: the polling fallback establishes a baseline on its first poll and only
/// reports real differences afterwards, so a restart cannot invent changes.
#[test]
fn human_workflow_guide_polling_baseline_then_diff() {
    let value = example();
    let offline = value.get("offline_edits").expect("offline_edits");
    let modified = string_list(offline, "modified");
    let created = string_list(offline, "created");
    let removed = string_list(offline, "removed");
    let stamp = |size: u64| FileStamp::new(size, 1_700_000_000_000_000_000);

    let source = CannedSnapshots {
        snapshots: RefCell::new(vec![
            vec![
                (modified[0].clone(), stamp(10)),
                (removed[0].clone(), stamp(20)),
            ],
            vec![
                (modified[0].clone(), stamp(11)),
                (created[0].clone(), stamp(30)),
            ],
        ]),
    };
    let mut watcher = PollingWatcher::new();

    let first = watcher
        .poll(&source, Path::new("."))
        .expect("the first poll succeeds");
    assert!(first.is_first_scan());
    assert!(
        first.is_empty(),
        "a first poll must not claim a change it never observed"
    );
    assert_eq!(watcher.known_count(), 2);

    let second = watcher
        .poll(&source, Path::new("."))
        .expect("the second poll succeeds");
    assert!(!second.is_first_scan());
    let described: Vec<(RawKind, &str)> = second
        .hints()
        .iter()
        .map(|hint| (hint.kind(), hint.path()))
        .collect();
    assert_eq!(
        described,
        vec![
            (RawKind::Created, created[0].as_str()),
            (RawKind::Modified, modified[0].as_str()),
            (RawKind::Removed, removed[0].as_str()),
        ],
        "changes to the current snapshot come first in path order, then removals"
    );
}

/// AC1: the polling backend is the declared fallback, not an error, and the
/// example's configured preference parses.
#[test]
fn human_workflow_guide_polling_is_the_declared_fallback() {
    let value = example();
    let preference = BackendPolicy::parse(field(&value, "backend_preference"))
        .expect("the example's backend preference is a known policy");
    assert_eq!(preference, BackendPolicy::PreferNative);

    let native =
        select_backend(preference, &NativeSupport::Supported).expect("native is available");
    assert_eq!(native.kind(), BackendKind::Native);
    assert!(native.reason().is_none());

    let forced = select_backend(BackendPolicy::ForcePolling, &NativeSupport::Supported)
        .expect("polling may always be forced");
    assert_eq!(forced.kind(), BackendKind::Polling);
    assert!(forced.reason().is_some());

    let unsupported = NativeSupport::Unsupported {
        reason: "no recursive backend on this host".to_owned(),
    };
    let fallback = select_backend(BackendPolicy::PreferNative, &unsupported)
        .expect("preferring native falls back instead of failing");
    assert_eq!(fallback.kind(), BackendKind::Polling);
    assert_eq!(fallback.reason(), Some("no recursive backend on this host"));
}

/// Negative and boundary: a reported path that is absolute or escapes the root
/// is refused and never rewritten, and `require_native` on a host without
/// native events refuses to start.
#[test]
fn human_workflow_guide_refuses_non_portable_paths_and_missing_native() {
    let start = Instant::now();
    let mut debouncer = Debouncer::new(DebouncePolicy::default());
    let error = debouncer
        .note("C:/work/repo/src/App.cs", start)
        .expect_err("an absolute reported path must be refused");
    assert_eq!(error.code(), ErrorCode::ValidationError);
    assert!(debouncer.is_idle(), "a refused hint must not be buffered");

    let error = normalize(&[RawHint::new("../escape.cs", RawKind::Created)])
        .expect_err("a traversal path must be refused");
    assert_eq!(error.code(), ErrorCode::ValidationError);

    let policy = IgnorePolicy::new("live");
    assert_eq!(
        policy
            .classify("/tmp/App.cs")
            .expect_err("an absolute path is not classifiable")
            .code(),
        ErrorCode::ValidationError
    );

    let error = select_backend(
        BackendPolicy::RequireNative,
        &NativeSupport::Unsupported {
            reason: "no recursive backend on this host".to_owned(),
        },
    )
    .expect_err("requiring native events on a host without them must refuse to start");
    assert_eq!(error.code(), ErrorCode::NotReady);
}
