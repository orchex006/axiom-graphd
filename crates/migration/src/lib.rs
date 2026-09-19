//! Migration support for the Axiom core (V2-009, V2-010).
//!
//! [`discover`] detects the legacy `graph` and `grahp` layouts independently and
//! returns `MIGRATION_CONFLICT` instead of a plan when the sources cannot be
//! resolved. [`plan`] turns one discovery decision into a deterministic,
//! ownership-aware plan whose digest binds the bytes a human approved, and
//! refuses to apply a plan whose inputs moved underneath it. Both modules
//! perform no filesystem access and no destination writes.

pub mod discover;
pub mod plan;

pub use discover::{
    discover_from_paths, plan_discovery, ContentRelation, DiscoverError, DiscoveryDecision,
    DiscoveryInventory, LayoutId, SnapshotFacts, AXIOM_GRAPH_DIR, AXIOM_GRAPH_DIR as V2_GRAPH_DIR,
    LEGACY_GRAPH_DIR, LEGACY_MARKERS, LEGACY_MISSPELLED_GRAPH_DIR,
};
pub use plan::{
    build_plan, ChangeAction, ContentHash, CurrentSources, DestinationChange, DestinationOwnership,
    MigrationPlan, OwnershipProof, PlanConflict, PlanError, PlannedWrite, PreservedText, RepoPlan,
    SourceArtifact, ERR_PLAN_APPROVAL, ERR_PLAN_DUPLICATE, ERR_PLAN_EXPIRED, ERR_PLAN_HASH,
    ERR_PLAN_INVALID, ERR_PLAN_UNRESOLVED, ERR_STALE_PLAN, PLAN_SCHEMA_VERSION,
    PLAN_WRITES_NOTHING,
};
