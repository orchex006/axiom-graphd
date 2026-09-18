//! Fixture-driven regression test for update and migration safe refusal
//! (task F-010).
//!
//! Every vector in `fixtures/update/` is replayed through the real
//! [`axiom_graphd::update_guard::admit`] admission surface, the real
//! [`axiom_graphd::commands::update::delegate`] argv delegation, the real
//! [`graph_store::migrations`] schema ceiling and the real
//! [`graph_store::backup`] verification.
//!
//! Safety is asserted twice per vector: the declared refusal reason must be
//! reached, and the target tree must be byte-identical afterwards, so a refusal
//! can never be a write.
//!
//! No process is launched, so no Bash, WSL, Docker or administrator rights are
//! involved.

use std::path::{Path, PathBuf};

use axiom_graphd::commands::update::{delegate, TrustRoot, UpdatePlan, UpdateTrust, AXIOM_PROGRAM};
use axiom_graphd::update_guard::{
    admit, Admission, AdmitRequest, REASON_BACKUP_MISSING, REASON_SCHEMA_NEWER_THAN_BINARY,
    REASON_SIGNATURE_EXPIRED, REASON_SIGNER_UNTRUSTED, REFUSAL_REASONS,
};
use graph_core::error::ErrorCode;
use graph_store::backup::{restore_into, verify_backup};
use graph_store::migrations::{verify, CURRENT_SCHEMA_VERSION};
use rusqlite::Connection;
use tempfile::TempDir;

#[derive(serde::Deserialize)]
struct Manifest {
    refusal_reasons: Vec<String>,
    scenarios: Vec<Scenario>,
}

#[derive(serde::Deserialize)]
struct Scenario {
    id: String,
    class: String,
    kind: String,
    vector: String,
    must_distinguish: Vec<String>,
    expected: Expectation,
}

#[derive(serde::Deserialize, Clone, PartialEq, Eq, Debug)]
struct Expectation {
    decision: String,
    reason: Option<String>,
}

#[derive(serde::Deserialize)]
struct Vector {
    vector_id: String,
    class: String,
    kind: String,
    spec_contract: SpecContract,
    request: Request,
    expected: Expectation,
}

#[derive(serde::Deserialize)]
struct SpecContract {
    reference_path: String,
    reference_sha256: String,
}

#[derive(serde::Deserialize)]
struct Request {
    plan_path: String,
    component: String,
    target_version: String,
    canonical_digest: String,
    approve_digest: Option<String>,
    plan_created_at: String,
    trust_metadata_expiry: String,
    trust_root: String,
    allowed_components: Vec<String>,
    signature_present: bool,
    candidate_schema_version: u32,
    backup_required: bool,
    backup_relative_path: String,
    backup_present: bool,
}

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/update")
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn manifest() -> Manifest {
    read_json(&fixtures_dir().join("manifest.json"))
}

fn vector_for(scenario: &Scenario) -> Vector {
    read_json(&fixtures_dir().join(&scenario.vector))
}

fn trust_for(request: &Request) -> UpdateTrust {
    if request.trust_root.is_empty() || request.allowed_components.is_empty() {
        return UpdateTrust::Unconfigured;
    }
    UpdateTrust::Configured(TrustRoot::new(
        request.trust_root.clone(),
        request.allowed_components.clone(),
    ))
}

fn admission_request(request: &Request, tree: &Path) -> AdmitRequest {
    AdmitRequest {
        plan_path: request.plan_path.clone(),
        component: request.component.clone(),
        target_version: request.target_version.clone(),
        canonical_digest: request.canonical_digest.clone(),
        approve_digest: request.approve_digest.clone(),
        plan_created_at: request.plan_created_at.clone(),
        trust_metadata_expiry: request.trust_metadata_expiry.clone(),
        signature_present: request.signature_present,
        candidate_schema_version: request.candidate_schema_version,
        backup_required: request.backup_required,
        backup_path: Some(
            tree.join(&request.backup_relative_path)
                .to_string_lossy()
                .into_owned(),
        ),
    }
}

fn create_backup(path: &Path) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("backup directory");
    }
    let connection = Connection::open(path).expect("open the backup database");
    connection
        .execute_batch(
            "CREATE TABLE probe(value TEXT); \
             INSERT INTO probe(value) VALUES('pre-upgrade');",
        )
        .expect("seed the backup database");
    drop(connection);
}

/// One throwaway installation tree a vector is replayed against.
struct TargetTree {
    dir: TempDir,
}

impl TargetTree {
    fn build(request: &Request) -> Self {
        let tree = Self {
            dir: TempDir::new().expect("target tree"),
        };
        let root = tree.dir.path();
        std::fs::create_dir_all(root.join("state")).expect("state directory");
        std::fs::write(
            root.join("inventory.json"),
            b"{\"installed\":\"0.1.0\",\"generation\":7}\n",
        )
        .expect("inventory");
        std::fs::write(root.join("state/queue.db"), b"live-queue-state\n").expect("queue state");
        if request.backup_present {
            create_backup(&root.join(&request.backup_relative_path));
        }
        tree
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn fingerprint(&self) -> String {
        tree_fingerprint(self.dir.path())
    }
}

fn collect_entries(root: &Path, directory: &Path, entries: &mut Vec<String>) {
    let mut children: Vec<PathBuf> = std::fs::read_dir(directory)
        .expect("read the target tree")
        .map(|entry| entry.expect("target tree entry").path())
        .collect();
    children.sort();
    for child in children {
        if child.is_dir() {
            collect_entries(root, &child, entries);
        } else {
            let relative = child
                .strip_prefix(root)
                .expect("relative path")
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = std::fs::read(&child).expect("read a target file");
            entries.push(format!("{relative}={}", graph_export::sha256_hex(&bytes)));
        }
    }
}

/// A byte-level fingerprint of every file under `root`: a refusal that writes,
/// truncates or creates anything changes it.
fn tree_fingerprint(root: &Path) -> String {
    let mut entries = Vec::new();
    collect_entries(root, root, &mut entries);
    graph_export::sha256_hex(entries.join("\n").as_bytes())
}

fn declared_reason(expected: &Expectation) -> &str {
    expected
        .reason
        .as_deref()
        .expect("a refusing vector must declare a reason")
}

#[test]
fn every_update_vector_reaches_its_declared_decision_through_the_real_guard() {
    let manifest = manifest();
    for scenario in &manifest.scenarios {
        let vector = vector_for(scenario);

        // The corpus cannot drift from the manifest it is listed in.
        assert_eq!(vector.vector_id, scenario.id, "vector id");
        assert_eq!(vector.class, scenario.class, "vector class {}", scenario.id);
        assert_eq!(vector.kind, scenario.kind, "vector kind {}", scenario.id);
        assert_eq!(
            vector.expected, scenario.expected,
            "expectation {}",
            scenario.id
        );
        assert_eq!(
            scenario.must_distinguish,
            vec![vector.class.clone()],
            "distinguished class {}",
            scenario.id
        );
        assert!(
            ["hazard", "control", "boundary"].contains(&scenario.kind.as_str()),
            "unknown scenario kind {}",
            scenario.kind
        );
        assert!(
            !vector.spec_contract.reference_path.is_empty()
                && vector.spec_contract.reference_sha256.len() == 64,
            "provenance {}",
            scenario.id
        );

        let tree = TargetTree::build(&vector.request);
        let before = tree.fingerprint();
        let trust = trust_for(&vector.request);
        let admission = admit(&admission_request(&vector.request, tree.path()), &trust);

        assert_eq!(
            tree.fingerprint(),
            before,
            "admission must not write for {}",
            scenario.id
        );

        match scenario.expected.decision.as_str() {
            "admit" => {
                assert!(
                    admission.is_admitted(),
                    "{} must be admitted, saw {:?}",
                    scenario.id,
                    admission.reason()
                );
                assert_eq!(admission.reason(), None);
                let Admission::Admitted { program, args } = &admission else {
                    panic!("admitted variant for {}", scenario.id);
                };
                assert_eq!(program, AXIOM_PROGRAM);

                // The real delegation must agree with the admitted argv.
                let plan = UpdatePlan::new(
                    vector.request.plan_path.clone(),
                    vector.request.component.clone(),
                    vector.request.target_version.clone(),
                    vector.request.canonical_digest.clone(),
                );
                let delegation = delegate(&plan, &trust, vector.request.approve_digest.as_deref())
                    .expect("an admitted plan delegates");
                assert_eq!(delegation.program_and_args().0, program);
                assert_eq!(delegation.program_and_args().1, args.as_slice());
                assert_eq!(delegation.program_and_args().1[3], vector.request.plan_path);
                assert!(!delegation.contains_shell_metacharacters());
            }
            "refuse" => {
                assert!(!admission.is_admitted(), "{} must be refused", scenario.id);
                assert_eq!(
                    admission.reason(),
                    Some(declared_reason(&scenario.expected)),
                    "refusal reason for {}",
                    scenario.id
                );
            }
            other => panic!("unknown decision {other} for {}", scenario.id),
        }

        assert!(
            admission
                .reason()
                .is_none_or(|reason| REFUSAL_REASONS.contains(&reason)),
            "every refusal is a declared reason for {}",
            scenario.id
        );
    }
}

#[test]
fn a_refusal_leaves_the_target_tree_byte_identical_and_creates_nothing() {
    let manifest = manifest();
    let mut refusals = 0_usize;
    for scenario in &manifest.scenarios {
        if scenario.expected.decision != "refuse" {
            continue;
        }
        refusals += 1;
        let vector = vector_for(scenario);
        let tree = TargetTree::build(&vector.request);
        let before = tree.fingerprint();
        let trust = trust_for(&vector.request);
        let request = admission_request(&vector.request, tree.path());

        // Refusal is stable: repeated attempts reach the same reason and never
        // accumulate state.
        for attempt in 0..3 {
            let admission = admit(&request, &trust);
            assert!(
                !admission.is_admitted(),
                "{} attempt {attempt}",
                scenario.id
            );
            assert_eq!(
                admission.reason(),
                Some(declared_reason(&scenario.expected)),
                "{} attempt {attempt}",
                scenario.id
            );
            assert_eq!(
                tree.fingerprint(),
                before,
                "{} attempt {attempt} changed the target tree",
                scenario.id
            );
        }

        if vector.request.backup_required && !vector.request.backup_present {
            // The missing backup is still missing: the guard verifies, it never
            // creates the file it needs.
            assert!(
                !tree
                    .path()
                    .join(&vector.request.backup_relative_path)
                    .exists(),
                "{} must not create the missing backup",
                scenario.id
            );
        }
    }
    assert_eq!(refusals, 6, "the corpus must carry six refusing vectors");
}

#[test]
fn the_real_migration_and_backup_paths_refuse_incompatible_and_missing_state() {
    // CF-026 boundary: a database whose schema is newer than the binary is
    // refused explicitly and is never migrated downwards.
    let connection = Connection::open_in_memory().expect("in-memory store");
    connection
        .execute_batch(&format!(
            "PRAGMA user_version = {};",
            CURRENT_SCHEMA_VERSION + 1
        ))
        .expect("future schema version");
    let error = verify(&connection).expect_err("a newer database must be refused");
    assert_eq!(error.code(), ErrorCode::SchemaNewerThanBinary);
    assert_eq!(error.code().as_str(), "SCHEMA_NEWER_THAN_BINARY");
    let observed: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("read the schema version");
    assert_eq!(
        u32::try_from(observed).expect("version"),
        CURRENT_SCHEMA_VERSION + 1,
        "a refusal never downgrades the database"
    );
    drop(connection);

    // A missing backup is refused as not-found, and the target keeps its bytes.
    let tree = TempDir::new().expect("target tree");
    std::fs::create_dir_all(tree.path().join("state")).expect("state directory");
    let mut target = Connection::open(tree.path().join("state/queue.db")).expect("target database");
    target
        .execute_batch(
            "CREATE TABLE kept(value TEXT); \
             INSERT INTO kept(value) VALUES('human state');",
        )
        .expect("seed the target database");
    let before = tree_fingerprint(tree.path());
    let missing = tree.path().join("state/queue.db.bak");

    assert_eq!(
        verify_backup(&missing).expect_err("missing").code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        restore_into(&mut target, &missing)
            .expect_err("missing")
            .code(),
        ErrorCode::NotFound
    );
    let kept: String = target
        .query_row("SELECT value FROM kept", [], |row| row.get(0))
        .expect("the target still answers");
    assert_eq!(kept, "human state");
    drop(target);
    assert_eq!(
        tree_fingerprint(tree.path()),
        before,
        "a refused restore leaves the target byte-identical"
    );

    // Negative: an untrusted or absent signer is refused by the real delegation,
    // not by the fixture guard alone.
    let digest = "b1938dd0652de5cd76d1a4934fd39d5a7d83012eb3a8e8c0c6139e1bc1d77b00";
    let unconfigured = delegate(
        &UpdatePlan::new("plan.json", "axiom-graphd", "0.2.0", digest),
        &UpdateTrust::Unconfigured,
        Some(digest),
    )
    .expect_err("unconfigured trust must refuse");
    assert_eq!(error_rule(&unconfigured), Some("trust-not-configured"));
    assert_eq!(unconfigured.exit_code().as_i32(), 2);

    let mut unsigned = trust_request();
    unsigned.signature_present = false;
    let trust = trust_for(&unsigned);
    assert_eq!(
        admit(&admission_request(&unsigned, tree.path()), &trust).reason(),
        Some(REASON_SIGNER_UNTRUSTED)
    );
}

fn trust_request() -> Request {
    Request {
        plan_path: "plan.json".to_owned(),
        component: "axiom-graphd".to_owned(),
        target_version: "0.2.0".to_owned(),
        canonical_digest: "b1938dd0652de5cd76d1a4934fd39d5a7d83012eb3a8e8c0c6139e1bc1d77b00"
            .to_owned(),
        approve_digest: None,
        plan_created_at: "2026-09-18T02:00:00Z".to_owned(),
        trust_metadata_expiry: "2026-09-25T02:00:00Z".to_owned(),
        trust_root: "9f2c4a1b".to_owned(),
        allowed_components: vec!["axiom-graphd".to_owned()],
        signature_present: true,
        candidate_schema_version: CURRENT_SCHEMA_VERSION,
        backup_required: false,
        backup_relative_path: "state/queue.db.bak".to_owned(),
        backup_present: false,
    }
}

fn error_rule(error: &graph_core::error::AxiomError) -> Option<&str> {
    error.details().get("rule").map(String::as_str)
}

#[test]
fn the_guard_reason_vocabulary_matches_the_manifest() {
    let manifest = manifest();
    let mut declared: Vec<&str> = manifest
        .refusal_reasons
        .iter()
        .map(String::as_str)
        .collect();
    declared.sort_unstable();
    let mut guard: Vec<&str> = REFUSAL_REASONS.to_vec();
    guard.sort_unstable();
    assert_eq!(
        guard, declared,
        "the manifest must declare every guard reason"
    );
    for reason in [
        REASON_SIGNATURE_EXPIRED,
        REASON_SIGNER_UNTRUSTED,
        REASON_SCHEMA_NEWER_THAN_BINARY,
        REASON_BACKUP_MISSING,
    ] {
        assert!(REFUSAL_REASONS.contains(&reason), "{reason}");
    }
}
