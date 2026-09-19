//! V2-002 acceptance tests: one core revision owns bootstrap application and the
//! daemon lifecycle, so no separately versioned installer process is required.
//!
//! The witness is re-derived from the real workspace manifests on every run, so
//! a change that introduced a separately versioned installer package or a second
//! core version fails this test instead of passing silently.
//!
//! Positive, negative and failure-boundary checks:
//! - positive: the real workspace reports one version and an in-core engine;
//! - negative: no member or binary looks like a separately shipped installer,
//!   and the marker check itself rejects a synthetic installer package;
//! - boundary: a missing member/workspace is reported as an error, not guessed.

use axiom_bootstrap::{
    read_manifest, witness, workspace_members, workspace_root, workspace_version, ManifestFacts,
    ReleaseBoundaryWitness, BOOTSTRAP_ENGINE_CRATE, BOOTSTRAP_ENGINE_DIR, CLI_CRATE, DAEMON_CRATE,
    INSTALLER_NAME_MARKERS,
};

fn workspace_witness() -> ReleaseBoundaryWitness {
    witness(&workspace_root()).expect("the workspace manifests are readable")
}

#[test]
fn one_workspace_reports_one_core_version() {
    let witness = workspace_witness();
    assert!(!witness.workspace_version.is_empty());
    assert_eq!(
        witness.workspace_version,
        workspace_version(&workspace_root()).expect("root manifest is readable")
    );
    assert!(
        !witness.members.is_empty(),
        "the workspace declares members"
    );
    assert_eq!(
        witness.members.len(),
        workspace_members(&workspace_root())
            .expect("members are declared")
            .len()
    );
    assert!(witness.to_string().contains(&witness.workspace_version));
}

#[test]
fn bootstrap_engine_lives_inside_the_core_crate() {
    let witness = workspace_witness();
    assert!(
        witness.bootstrap_engine_dir_exists,
        "{BOOTSTRAP_ENGINE_DIR} must exist in {BOOTSTRAP_ENGINE_CRATE}"
    );
    assert!(workspace_root().join(BOOTSTRAP_ENGINE_DIR).is_dir());
    assert!(witness
        .members
        .iter()
        .any(|member| member.name == BOOTSTRAP_ENGINE_CRATE));
}

#[test]
fn every_member_inherits_the_one_workspace_version() {
    let witness = workspace_witness();
    assert!(
        witness.members_with_pinned_versions().is_empty(),
        "a pinned member version would break the one-core-version claim"
    );
    for member in &witness.members {
        assert!(
            member.inherits_workspace_version,
            "{member} must inherit version.workspace = true"
        );
    }
}

#[test]
fn no_member_is_a_separately_versioned_installer() {
    let witness = workspace_witness();
    assert!(witness.separate_installer_candidates().is_empty());
    for member in &witness.members {
        assert!(
            !member.looks_like_an_installer(),
            "{member} looks like a separately shipped installer"
        );
    }
}

#[test]
fn the_daemon_and_cli_share_the_release_boundary() {
    let witness = workspace_witness();
    let binaries = witness.binary_crates();
    assert!(
        binaries.contains(&DAEMON_CRATE),
        "expected the daemon binary, got {binaries:?}"
    );
    assert!(
        binaries.contains(&CLI_CRATE),
        "expected the CLI crate, got {binaries:?}"
    );
    assert!(!binaries
        .iter()
        .any(|name| name.to_ascii_lowercase().contains("installer")));
}

#[test]
fn the_installer_boundary_check_would_catch_a_regression() {
    assert_eq!(INSTALLER_NAME_MARKERS, ["installer", "setup"]);

    let by_name = ManifestFacts {
        member: "crates/axiom-installer".to_string(),
        name: "axiom-installer".to_string(),
        inherits_workspace_version: true,
        binaries: Vec::new(),
    };
    assert!(by_name.looks_like_an_installer());

    let by_binary = ManifestFacts {
        member: "crates/tool".to_string(),
        name: "tool".to_string(),
        inherits_workspace_version: true,
        binaries: vec!["setup".to_string()],
    };
    assert!(by_binary.looks_like_an_installer());

    let normal = ManifestFacts {
        member: "crates/graph-core".to_string(),
        name: "graph-core".to_string(),
        inherits_workspace_version: true,
        binaries: Vec::new(),
    };
    assert!(!normal.looks_like_an_installer());
}

#[test]
fn read_manifest_reports_version_inheritance_and_binaries() {
    let facts = read_manifest(&workspace_root(), "crates/graph-core").unwrap();
    assert_eq!(facts.member, "crates/graph-core");
    assert!(facts.inherits_workspace_version);
    assert!(facts.binaries.is_empty());

    let cli = read_manifest(&workspace_root(), "crates/axiom-cli").unwrap();
    assert!(cli.inherits_workspace_version);
    assert!(cli.binaries.contains(&"axiom".to_string()));
}

#[test]
fn unreadable_manifests_are_reported_instead_of_guessed() {
    let root = workspace_root();
    let error = read_manifest(&root, "crates/does-not-exist").unwrap_err();
    assert!(error.contains("does-not-exist"), "{error}");

    let missing = root.join("no-such-workspace");
    assert!(workspace_version(&missing).is_err());
    assert!(workspace_members(&missing).is_err());
    assert!(witness(&missing).is_err());
}
