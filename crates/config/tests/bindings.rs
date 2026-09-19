//! V2-007 acceptance tests: a logical repository id survives a checkout move,
//! the machine-local absolute root never reaches a portable artifact, and two
//! active writers that would publish the same output are refused before work.
//!
//! Positive, negative and failure-boundary checks:
//! - positive: a distinct pair of active writers is accepted and resolves;
//! - negative: duplicate/alias/overlap roots and non-portable ids are refused;
//! - boundary: the binding table accepts exactly `MAX_BINDINGS` and refuses one more.

use axiom_config::bindings::{
    ERR_DUPLICATE_WRITER, ERR_OUTPUT_NAMESPACE_OVERLAP, ERR_PRIVATE_BINDING, ERR_ROOT_ALIAS,
    ERR_WRITER_ALIAS,
};
use axiom_config::{
    resolve_binding, validate_active_writers, PortableBindings, RepoBinding, RepositoryBindings,
    MAX_BINDINGS,
};
use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::is_absolute_host_path;

const WIN_A: &str = r"C:\work\checkout-a";
const WIN_B: &str = r"D:\moved\checkout-b";
const UNIX_A: &str = "/home/dev/axiom-a";

fn binding(repo: &str, solution: &str, root: &str, active: bool) -> RepoBinding {
    RepoBinding::new(repo, solution, root, active).expect("binding should be valid")
}

fn code(error: &AxiomError) -> &'static str {
    error.envelope().code.as_str()
}

fn rule(error: &AxiomError) -> String {
    error.details().get("rule").cloned().unwrap_or_default()
}

#[test]
fn logical_identity_survives_a_checkout_move() {
    let before = RepositoryBindings::new(vec![binding("acme-app", "main", WIN_A, true)]).unwrap();
    let after = RepositoryBindings::new(vec![binding("acme-app", "main", WIN_B, true)]).unwrap();

    let before_entry = before.entries().first().unwrap();
    let after_entry = after.entries().first().unwrap();
    assert_eq!(before_entry.logical_id(), "acme-app/main");
    assert_eq!(before_entry.logical_id(), after_entry.logical_id());
    assert_ne!(before_entry.root(), after_entry.root());

    let portable_before = PortableBindings::from_private(&before);
    let portable_after = PortableBindings::from_private(&after);
    assert_eq!(
        portable_before, portable_after,
        "the publishable table is checkout-independent"
    );
    assert_eq!(portable_before.entries().len(), 1);
    assert_eq!(portable_before.entries()[0].storage_class, "local_disk");
}

#[test]
fn portable_view_carries_no_absolute_path() {
    let table = RepositoryBindings::new(vec![
        binding("acme-app", "main", WIN_A, true),
        binding("other-repo", "release", UNIX_A, false),
    ])
    .unwrap();
    let portable = PortableBindings::from_private(&table);
    assert!(portable.contains_no_absolute_path());
    for entry in portable.entries() {
        assert!(!is_absolute_host_path(&entry.repo_id));
        assert!(!is_absolute_host_path(&entry.solution_id));
        assert!(!is_absolute_host_path(&entry.storage_class));
    }
    // Only the private table holds the roots.
    assert_eq!(table.entries()[0].root(), WIN_A);
}

#[test]
fn distinct_active_writers_are_accepted() {
    let table = RepositoryBindings::new(vec![
        binding("acme-app", "main", WIN_A, true),
        binding("other-repo", "release", WIN_B, true),
    ])
    .unwrap();
    assert_eq!(table.active().len(), 2);
}

#[test]
fn duplicate_active_writer_on_one_root_is_refused() {
    let first = binding("acme-app", "main", WIN_A, true);
    let second = binding("acme-app", "main", WIN_A, true);
    let error = validate_active_writers(&[first, second]).unwrap_err();
    assert_eq!(code(&error), ErrorCode::Conflict.as_str());
    assert_eq!(rule(&error), ERR_DUPLICATE_WRITER);
}

#[test]
fn one_logical_writer_from_two_roots_is_refused() {
    let error = RepositoryBindings::new(vec![
        binding("acme-app", "main", WIN_A, true),
        binding("acme-app", "main", WIN_B, true),
    ])
    .unwrap_err();
    assert_eq!(code(&error), ErrorCode::Conflict.as_str());
    assert_eq!(rule(&error), ERR_WRITER_ALIAS);
}

#[test]
fn two_logical_repositories_on_one_root_are_refused() {
    let error = RepositoryBindings::new(vec![
        binding("acme-app", "main", WIN_A, true),
        binding("other-repo", "main", WIN_A, true),
    ])
    .unwrap_err();
    assert_eq!(code(&error), ErrorCode::Conflict.as_str());
    assert_eq!(rule(&error), ERR_ROOT_ALIAS);
}

#[test]
fn overlapping_output_namespace_is_refused() {
    let error = RepositoryBindings::new(vec![
        binding("acme-app", "main", WIN_A, true),
        binding("acme-app", "release", WIN_B, true),
    ])
    .unwrap_err();
    assert_eq!(code(&error), ErrorCode::Conflict.as_str());
    assert_eq!(rule(&error), ERR_OUTPUT_NAMESPACE_OVERLAP);
}

#[test]
fn inactive_bindings_do_not_claim_output() {
    let table = RepositoryBindings::new(vec![
        binding("acme-app", "main", WIN_A, false),
        binding("acme-app", "main", WIN_B, false),
    ])
    .expect("inactive duplicates do not contend for the output");
    assert!(table.active().is_empty());
    assert_eq!(table.entries().len(), 2);
}

#[test]
fn relative_root_is_refused() {
    let error = RepoBinding::new("acme-app", "main", "axiom/checkout", true).unwrap_err();
    assert_eq!(code(&error), ErrorCode::ConfigInvalid.as_str());
    assert_eq!(rule(&error), ERR_PRIVATE_BINDING);
}

#[test]
fn remote_device_and_cloud_roots_are_refused() {
    for root in [
        r"\\server\share\axiom",
        r"\\?\C:\axiom",
        r"\\.\C:\axiom",
        r"C:\Users\me\OneDrive\axiom",
    ] {
        let error = RepoBinding::new("acme-app", "main", root, true).unwrap_err();
        assert_eq!(
            code(&error),
            ErrorCode::ConfigInvalid.as_str(),
            "root {root} must be refused as non-private storage"
        );
        assert_eq!(rule(&error), ERR_PRIVATE_BINDING);
    }
}

#[test]
fn control_characters_in_a_root_are_refused() {
    let root = "C:\\axiom\u{0}bad";
    let error = RepoBinding::new("acme-app", "main", root, true).unwrap_err();
    assert_eq!(code(&error), ErrorCode::ConfigInvalid.as_str());
}

#[test]
fn non_portable_logical_ids_are_refused() {
    for (repo, solution) in [
        ("Acme App", "main"),
        ("acme_app", "main"),
        ("acme-app", "Main/Main"),
        ("acme-app", "1-solution"),
    ] {
        let error = RepoBinding::new(repo, solution, WIN_A, true).unwrap_err();
        assert_eq!(
            code(&error),
            ErrorCode::ValidationError.as_str(),
            "({repo}, {solution}) must not be accepted as a portable id pair"
        );
    }
}

#[test]
fn resolve_binding_is_exact_and_reports_not_found() {
    let table = RepositoryBindings::new(vec![
        binding("acme-app", "main", WIN_A, true),
        binding("other-repo", "release", WIN_B, true),
    ])
    .unwrap();
    let found = resolve_binding(&table, "other-repo", "release").unwrap();
    assert_eq!(found.root(), WIN_B);

    let error = resolve_binding(&table, "acme-app", "release").unwrap_err();
    assert_eq!(code(&error), ErrorCode::NotFound.as_str());
}

#[test]
fn binding_table_bound_is_enforced() {
    let at_limit: Vec<RepoBinding> = (0..MAX_BINDINGS)
        .map(|index| {
            binding(
                &format!("repo-{index}"),
                "main",
                &format!("/srv/checkout/{index}"),
                false,
            )
        })
        .collect();
    assert!(
        RepositoryBindings::new(at_limit).is_ok(),
        "exactly MAX_BINDINGS entries are accepted"
    );

    let over_limit: Vec<RepoBinding> = (0..=MAX_BINDINGS)
        .map(|index| {
            binding(
                &format!("repo-{index}"),
                "main",
                &format!("/srv/checkout/{index}"),
                false,
            )
        })
        .collect();
    let error = RepositoryBindings::new(over_limit).unwrap_err();
    assert_eq!(code(&error), ErrorCode::ValidationError.as_str());
    assert_eq!(
        error.details().get("limit").map(String::as_str),
        Some("1024")
    );
}
