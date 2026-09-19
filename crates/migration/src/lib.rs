//! Migration support for the Axiom core (V2-009).
//!
//! [`discover`] detects the legacy `graph` and `grahp` layouts independently and
//! returns `MIGRATION_CONFLICT` instead of a plan when the sources cannot be
//! resolved. It performs no filesystem access and no destination writes.

pub mod discover;

pub use discover::{
    discover_from_paths, plan_discovery, ContentRelation, DiscoverError, DiscoveryDecision,
    DiscoveryInventory, LayoutId, SnapshotFacts, AXIOM_GRAPH_DIR, AXIOM_GRAPH_DIR as V2_GRAPH_DIR,
    LEGACY_GRAPH_DIR, LEGACY_MARKERS, LEGACY_MISSPELLED_GRAPH_DIR,
};
