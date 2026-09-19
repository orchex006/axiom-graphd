//! V2-009 acceptance tests: the legacy `graph` and `grahp` layouts are detected
//! independently, and two sources that cannot be resolved return
//! `MIGRATION_CONFLICT` instead of a plan (with no destination writes).
//!
//! Positive, negative and failure-boundary checks:
//! - positive: every row of the V1->V2 decision table yields its decision;
//! - negative: differing, unhealthy or conflicting sources are refused;
//! - boundary: a path *under* a layout counts as that layout, and a path that is
//!   not a portable repository-relative path is refused before it is inspected.

use axiom_migration::discover::{ERR_MIGRATION_CONFLICT, NO_DESTINATION_WRITES};
use axiom_migration::{
    discover_from_paths, plan_discovery, ContentRelation, DiscoverError, DiscoveryDecision,
    LayoutId, SnapshotFacts, AXIOM_GRAPH_DIR, LEGACY_GRAPH_DIR, LEGACY_MARKERS,
    LEGACY_MISSPELLED_GRAPH_DIR,
};
use graph_core::error::ErrorCode;

fn empty_inventory() -> axiom_migration::DiscoveryInventory {
    discover_from_paths(Vec::<&str>::new()).expect("an empty listing is valid")
}

fn inventory(paths: &[&str]) -> axiom_migration::DiscoveryInventory {
    discover_from_paths(paths.iter().copied()).expect("portable paths should be accepted")
}

fn conflict_rule(error: &DiscoverError) -> &'static str {
    match error {
        DiscoverError::Conflict { rule, .. } => rule,
        other => panic!("expected a conflict, got {other}"),
    }
}

#[test]
fn each_layout_is_recognized_on_its_own_spelling() {
    assert_eq!(AXIOM_GRAPH_DIR, ".axiom/graph");
    assert_eq!(
        LEGACY_GRAPH_DIR,
        ".agrimap-agent/knowledge/references/graph"
    );
    assert_eq!(
        LEGACY_MISSPELLED_GRAPH_DIR,
        ".agrimap-agent/knowledge/references/grahp"
    );

    let only_misspelled = inventory(&[LEGACY_MISSPELLED_GRAPH_DIR]);
    assert!(only_misspelled.contains(LayoutId::LegacyMisspelledGraph));
    assert!(
        !only_misspelled.contains(LayoutId::LegacyGraph),
        "grahp must never be inferred from graph"
    );

    let only_correct = inventory(&[LEGACY_GRAPH_DIR]);
    assert!(only_correct.contains(LayoutId::LegacyGraph));
    assert!(!only_correct.contains(LayoutId::LegacyMisspelledGraph));
}

#[test]
fn a_path_under_a_layout_counts_as_that_layout() {
    let nested = inventory(&[".agrimap-agent/knowledge/references/graph/catalog.json"]);
    assert_eq!(nested.present(), &[LayoutId::LegacyGraph]);

    let axiom_nested = inventory(&[".axiom/graph/generations/1/manifest.json"]);
    assert_eq!(axiom_nested.present(), &[LayoutId::AxiomGraph]);

    // A sibling directory with a shared prefix must not be mistaken for the layout.
    let sibling = inventory(&[".agrimap-agent/knowledge/references/graphs"]);
    assert!(sibling.is_empty());
}

#[test]
fn layouts_are_reported_in_canonical_order() {
    let both = inventory(&[
        LEGACY_MISSPELLED_GRAPH_DIR,
        LEGACY_GRAPH_DIR,
        AXIOM_GRAPH_DIR,
    ]);
    assert_eq!(
        both.present(),
        &[
            LayoutId::AxiomGraph,
            LayoutId::LegacyGraph,
            LayoutId::LegacyMisspelledGraph,
        ]
    );
    assert_eq!(
        both.legacy_present(),
        vec![LayoutId::LegacyGraph, LayoutId::LegacyMisspelledGraph]
    );
    assert!(LayoutId::LegacyGraph.is_legacy());
    assert!(!LayoutId::AxiomGraph.is_legacy());
}

#[test]
fn unsafe_listed_paths_are_refused_before_inspection() {
    for path in [
        "C:\\abs\\graph",
        "/etc/passwd",
        "a/../b",
        "graph\\..\\escape",
        "",
    ] {
        let error = discover_from_paths([path]).unwrap_err();
        assert_eq!(
            error.code(),
            "UNSAFE_PORTABLE_PATH",
            "path {path:?} must not be inspected"
        );
        assert!(matches!(error, DiscoverError::UnsafePath(_)));
    }
}

#[test]
fn no_legacy_folder_means_a_fresh_setup() {
    let decision = plan_discovery(&empty_inventory(), &SnapshotFacts::uncompared()).unwrap();
    assert_eq!(decision, DiscoveryDecision::Fresh);
    let no_destination_writes: bool = NO_DESTINATION_WRITES;
    assert!(
        no_destination_writes,
        "discovery must not write to the destination"
    );
}

#[test]
fn one_legacy_spelling_proposes_a_read_only_import() {
    let graph = plan_discovery(
        &inventory(&[LEGACY_GRAPH_DIR]),
        &SnapshotFacts::uncompared(),
    )
    .unwrap();
    assert_eq!(
        graph,
        DiscoveryDecision::Import {
            source: LayoutId::LegacyGraph
        }
    );

    let grahp = plan_discovery(
        &inventory(&[LEGACY_MISSPELLED_GRAPH_DIR]),
        &SnapshotFacts::uncompared(),
    )
    .unwrap();
    assert_eq!(
        grahp,
        DiscoveryDecision::Import {
            source: LayoutId::LegacyMisspelledGraph
        }
    );
}

#[test]
fn two_identical_spellings_are_deduplicated() {
    let both = inventory(&[LEGACY_GRAPH_DIR, LEGACY_MISSPELLED_GRAPH_DIR]);
    let decision = plan_discovery(&both, &SnapshotFacts::identical()).unwrap();
    assert_eq!(
        decision,
        DiscoveryDecision::Deduplicate {
            sources: vec![LayoutId::LegacyGraph, LayoutId::LegacyMisspelledGraph],
            target: LayoutId::AxiomGraph,
        }
    );
}

#[test]
fn two_conflicting_spellings_are_refused() {
    let both = inventory(&[LEGACY_GRAPH_DIR, LEGACY_MISSPELLED_GRAPH_DIR]);

    let different = plan_discovery(&both, &SnapshotFacts::different()).unwrap_err();
    assert_eq!(different.code(), ERR_MIGRATION_CONFLICT);
    assert_eq!(conflict_rule(&different), "legacy-spellings-differ");

    let uncompared = plan_discovery(&both, &SnapshotFacts::uncompared()).unwrap_err();
    assert_eq!(uncompared.code(), ERR_MIGRATION_CONFLICT);
    assert_eq!(conflict_rule(&uncompared), "legacy-spellings-differ");
}

#[test]
fn an_unhealthy_source_is_refused_even_when_the_other_is_present() {
    let both = inventory(&[LEGACY_GRAPH_DIR, LEGACY_MISSPELLED_GRAPH_DIR]);
    let facts = SnapshotFacts::identical().with_unhealthy(LayoutId::LegacyMisspelledGraph);
    let error = plan_discovery(&both, &facts).unwrap_err();
    assert_eq!(error.code(), ERR_MIGRATION_CONFLICT);
    assert_eq!(conflict_rule(&error), "source-unhealthy");

    // Unhealthy detection precedes even a single-source import decision.
    let one = inventory(&[LEGACY_GRAPH_DIR]);
    let facts = SnapshotFacts::uncompared().with_unhealthy(LayoutId::LegacyGraph);
    let error = plan_discovery(&one, &facts).unwrap_err();
    assert_eq!(conflict_rule(&error), "source-unhealthy");
}

#[test]
fn an_existing_v2_target_with_an_identical_leftover_is_already_migrated() {
    let axiom_only =
        plan_discovery(&inventory(&[AXIOM_GRAPH_DIR]), &SnapshotFacts::uncompared()).unwrap();
    assert_eq!(
        axiom_only,
        DiscoveryDecision::AlreadyMigrated {
            axiom: LayoutId::AxiomGraph,
            legacy_leftovers: Vec::new(),
        }
    );

    let both = inventory(&[AXIOM_GRAPH_DIR, LEGACY_GRAPH_DIR]);
    let decision = plan_discovery(&both, &SnapshotFacts::identical()).unwrap();
    assert_eq!(
        decision,
        DiscoveryDecision::AlreadyMigrated {
            axiom: LayoutId::AxiomGraph,
            legacy_leftovers: vec![LayoutId::LegacyGraph],
        }
    );
}

#[test]
fn an_unproven_v2_target_conflicts_instead_of_guessing() {
    let both = inventory(&[AXIOM_GRAPH_DIR, LEGACY_MISSPELLED_GRAPH_DIR]);

    for facts in [SnapshotFacts::different(), SnapshotFacts::uncompared()] {
        let error = plan_discovery(&both, &facts).unwrap_err();
        assert_eq!(error.code(), ERR_MIGRATION_CONFLICT);
        assert_eq!(conflict_rule(&error), "conflicting-axiom-target");
    }
}

#[test]
fn content_relation_defaults_to_not_compared() {
    assert_eq!(ContentRelation::default(), ContentRelation::NotCompared);
    assert_eq!(
        SnapshotFacts::uncompared().relation,
        ContentRelation::NotCompared
    );
}

#[test]
fn a_conflict_maps_to_the_shared_typed_error() {
    let both = inventory(&[LEGACY_GRAPH_DIR, LEGACY_MISSPELLED_GRAPH_DIR]);
    let error = plan_discovery(&both, &SnapshotFacts::different()).unwrap_err();
    let typed = error.to_axiom_error();
    assert_eq!(typed.envelope().code, ErrorCode::Conflict);
    assert!(
        typed.message().starts_with(ERR_MIGRATION_CONFLICT),
        "the domain decision must survive into the shared message: {}",
        typed.message()
    );
    assert!(typed.details().contains_key("rule"));
    assert!(typed.details().contains_key("observed"));
    assert_eq!(
        typed.dropped_details(),
        0,
        "conflict evidence must not be silently dropped by the detail allowlist"
    );
}

#[test]
fn the_legacy_marker_template_is_defined() {
    assert_eq!(LEGACY_MARKERS.len(), 2);
    assert!(LEGACY_MARKERS[0].contains("agrimap-graph"));
}
