//! Read-only discovery of the legacy graph layouts (V2-009).
//!
//! The V1->V2 decision table (migrations/V1-TO-V2.md, section 1) turns on which
//! old layout is present and whether the two old spellings agree:
//!
//! | present | required behaviour |
//! |---|---|
//! | nothing | fresh `.axiom` setup, no legacy folders created |
//! | only `.agrimap-agent/knowledge/references/grahp` | read-only discovery, propose import |
//! | only `.agrimap-agent/knowledge/references/graph` | same flow, never assume the typo variant must exist |
//! | both, identical validated snapshot content | deduplicate, after reporting both inputs |
//! | both differ, unhealthy, or a conflicting `.axiom` target | `MIGRATION_CONFLICT`, no destination writes |
//!
//! This module is the pure half: it takes the repo-relative paths that exist
//! (as a read-only listing produced it) plus the content facts the adapter
//! compared, and returns either a decision or [`MIGRATION_CONFLICT`]. It never
//! opens a file, so "without writes" is structural rather than a promise, and it
//! refuses paths that would escape the repository before it looks at them.
//!
//! [`MIGRATION_CONFLICT`]: ERR_MIGRATION_CONFLICT

use std::fmt;

use axiom_platform::PathKey;
use graph_core::error::{AxiomError, ErrorCode};

/// The correctly spelled legacy graph directory.
pub const LEGACY_GRAPH_DIR: &str = ".agrimap-agent/knowledge/references/graph";
/// The misspelled legacy graph directory that must be detected independently.
pub const LEGACY_MISSPELLED_GRAPH_DIR: &str = ".agrimap-agent/knowledge/references/grahp";
/// The V2 graph directory.
pub const AXIOM_GRAPH_DIR: &str = ".axiom/graph";
/// The legacy instruction-marker template pair.
pub const LEGACY_MARKERS: [&str; 2] =
    ["<!-- agrimap-graph:begin -->", "<!-- agrimap-graph:end -->"];
/// Stable code for the unresolved-source conflict.
pub const ERR_MIGRATION_CONFLICT: &str = "MIGRATION_CONFLICT";
/// Discovery performs no destination writes.
pub const NO_DESTINATION_WRITES: bool = true;

/// One recognizable graph layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LayoutId {
    /// `.axiom/graph`.
    AxiomGraph,
    /// `.agrimap-agent/knowledge/references/graph`.
    LegacyGraph,
    /// `.agrimap-agent/knowledge/references/grahp`.
    LegacyMisspelledGraph,
}

impl LayoutId {
    /// Every layout this module knows.
    pub const ALL: [LayoutId; 3] = [
        LayoutId::AxiomGraph,
        LayoutId::LegacyGraph,
        LayoutId::LegacyMisspelledGraph,
    ];

    /// The repo-relative directory of this layout.
    #[must_use]
    pub const fn relative_path(self) -> &'static str {
        match self {
            Self::AxiomGraph => AXIOM_GRAPH_DIR,
            Self::LegacyGraph => LEGACY_GRAPH_DIR,
            Self::LegacyMisspelledGraph => LEGACY_MISSPELLED_GRAPH_DIR,
        }
    }

    /// Stable name used in diagnostics, plans and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AxiomGraph => "axiom-graph",
            Self::LegacyGraph => "legacy-graph",
            Self::LegacyMisspelledGraph => "legacy-misspelled-graph",
        }
    }

    /// True for the two V1 spellings.
    #[must_use]
    pub const fn is_legacy(self) -> bool {
        !matches!(self, Self::AxiomGraph)
    }
}

impl fmt::Display for LayoutId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Which layout directories exist in the repository.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryInventory {
    present: Vec<LayoutId>,
}

impl DiscoveryInventory {
    /// The layouts observed, in [`LayoutId::ALL`] order.
    #[must_use]
    pub fn present(&self) -> &[LayoutId] {
        &self.present
    }

    /// True when this layout was observed.
    #[must_use]
    pub fn contains(&self, layout: LayoutId) -> bool {
        self.present.contains(&layout)
    }

    /// The legacy layouts observed, in order.
    #[must_use]
    pub fn legacy_present(&self) -> Vec<LayoutId> {
        self.present
            .iter()
            .copied()
            .filter(|layout| layout.is_legacy())
            .collect()
    }

    /// True when nothing recognizable exists yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.present.is_empty()
    }
}

/// Detect every layout independently from the repo-relative paths that exist.
///
/// A path *under* a layout directory (`.../graph/catalog.json`) counts as that
/// layout being present, because the adapter may have listed files rather than
/// the directory entry. Each layout is tested on its own segment sequence, so
/// the misspelled `grahp` variant is never inferred from `graph`.
///
/// # Errors
/// Returns [`DiscoverError::UnsafePath`] for a spelling that is not a portable
/// repository-relative path: discovery must not read outside the repository.
pub fn discover_from_paths<'a, I>(paths: I) -> Result<DiscoveryInventory, DiscoverError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut present: Vec<LayoutId> = Vec::new();
    for path in paths {
        let key = PathKey::new(path).map_err(DiscoverError::UnsafePath)?;
        for layout in LayoutId::ALL {
            if !present.contains(&layout) && is_under(&key, layout.relative_path()) {
                present.push(layout);
            }
        }
    }
    present.sort();
    Ok(DiscoveryInventory { present })
}

fn is_under(key: &PathKey, directory: &str) -> bool {
    let spelling = key.as_str();
    spelling == directory
        || (spelling.starts_with(directory) && spelling.as_bytes()[directory.len()] == b'/')
}

/// How the legacy snapshots compare with each other or with the V2 target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContentRelation {
    /// The adapter did not compare content; a decision that needs the comparison
    /// is then a conflict rather than a guess.
    #[default]
    NotCompared,
    /// The compared snapshots are identical and validated.
    Identical,
    /// The compared snapshots differ, or a generation or hash is invalid.
    Different,
}

/// Adapter facts that the pure decision needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SnapshotFacts {
    /// The result of comparing the inputs.
    pub relation: ContentRelation,
    /// Layouts whose snapshot failed validation (missing generation, invalid
    /// hash, unreadable shard).
    pub unhealthy: Vec<LayoutId>,
}

impl SnapshotFacts {
    /// Facts for a comparison that has not been made.
    #[must_use]
    pub fn uncompared() -> Self {
        Self::default()
    }

    /// Facts for two identical, validated snapshots.
    #[must_use]
    pub fn identical() -> Self {
        Self {
            relation: ContentRelation::Identical,
            unhealthy: Vec::new(),
        }
    }

    /// Facts for two snapshots that differ.
    #[must_use]
    pub fn different() -> Self {
        Self {
            relation: ContentRelation::Different,
            unhealthy: Vec::new(),
        }
    }

    /// Mark a layout as failing validation.
    #[must_use]
    pub fn with_unhealthy(mut self, layout: LayoutId) -> Self {
        self.unhealthy.push(layout);
        self
    }
}

/// The migration plan the discovery supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryDecision {
    /// No old installation: a fresh V2 setup, with no legacy folder created.
    Fresh,
    /// One legacy layout: read-only discovery, proposing import/regeneration.
    Import { source: LayoutId },
    /// Both legacy layouts agree: deduplicate, having reported both inputs.
    Deduplicate {
        sources: Vec<LayoutId>,
        target: LayoutId,
    },
    /// The V2 layout already holds the graph; legacy leftovers are reported and
    /// left untouched.
    AlreadyMigrated {
        axiom: LayoutId,
        legacy_leftovers: Vec<LayoutId>,
    },
}

/// Why discovery could not produce a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoverError {
    /// A listed path is not a portable repository-relative path.
    UnsafePath(axiom_platform::PathKeyError),
    /// The sources cannot be resolved without an explicit human decision.
    Conflict {
        /// Stable rule name for the conflict.
        rule: &'static str,
        /// What conflicted.
        detail: String,
    },
}

impl DiscoverError {
    /// The stable wire code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsafePath(error) => error.code(),
            Self::Conflict { .. } => ERR_MIGRATION_CONFLICT,
        }
    }

    /// The shared typed error.
    #[must_use]
    pub fn to_axiom_error(&self) -> AxiomError {
        match self {
            Self::UnsafePath(error) => error.to_axiom_error(),
            Self::Conflict { rule, detail } => AxiomError::new(
                ErrorCode::Conflict,
                format!(
                    "{ERR_MIGRATION_CONFLICT}: legacy graph sources conflict; \
                     resolve them before migration"
                ),
            )
            .with_detail("rule", *rule)
            .with_detail("observed", detail.clone()),
        }
    }
}

impl fmt::Display for DiscoverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafePath(error) => write!(formatter, "{error}"),
            Self::Conflict { rule, detail } => {
                write!(formatter, "{ERR_MIGRATION_CONFLICT}: {rule}: {detail}")
            }
        }
    }
}

impl std::error::Error for DiscoverError {}

/// Decide what the migration may do, refusing every ambiguous input.
///
/// # Errors
/// Returns [`DiscoverError::Conflict`] - never a decision - when two legacy
/// sources differ, when a present source failed validation, or when a legacy
/// source cannot be compared with an existing V2 target.
pub fn plan_discovery(
    inventory: &DiscoveryInventory,
    facts: &SnapshotFacts,
) -> Result<DiscoveryDecision, DiscoverError> {
    if let Some(layout) = inventory
        .present()
        .iter()
        .find(|layout| facts.unhealthy.contains(layout))
    {
        return Err(DiscoverError::Conflict {
            rule: "source-unhealthy",
            detail: format!(
                "{} failed snapshot validation (missing generation, invalid hash or unreadable shard)",
                layout.as_str()
            ),
        });
    }

    let legacy = inventory.legacy_present();
    match (inventory.contains(LayoutId::AxiomGraph), legacy.as_slice()) {
        (false, []) => Ok(DiscoveryDecision::Fresh),
        (false, [single]) => Ok(DiscoveryDecision::Import { source: *single }),
        (false, [first, second]) => match facts.relation {
            ContentRelation::Identical => Ok(DiscoveryDecision::Deduplicate {
                sources: vec![*first, *second],
                target: LayoutId::AxiomGraph,
            }),
            ContentRelation::Different | ContentRelation::NotCompared => {
                Err(DiscoverError::Conflict {
                    rule: "legacy-spellings-differ",
                    detail: format!(
                        "{} and {} are both present and were not proven identical",
                        first.as_str(),
                        second.as_str()
                    ),
                })
            }
        },
        // Only two legacy layouts exist, so a third source is impossible;
        // refusing is safer than guessing if the inventory type ever grows.
        (false, _) => Err(DiscoverError::Conflict {
            rule: "too-many-legacy-sources",
            detail: format!(
                "{} legacy layouts present; at most two are defined",
                legacy.len()
            ),
        }),
        (true, []) => Ok(DiscoveryDecision::AlreadyMigrated {
            axiom: LayoutId::AxiomGraph,
            legacy_leftovers: Vec::new(),
        }),
        (true, legacy) => match facts.relation {
            ContentRelation::Identical => Ok(DiscoveryDecision::AlreadyMigrated {
                axiom: LayoutId::AxiomGraph,
                legacy_leftovers: legacy.to_vec(),
            }),
            ContentRelation::Different | ContentRelation::NotCompared => {
                Err(DiscoverError::Conflict {
                    rule: "conflicting-axiom-target",
                    detail: format!(
                        "{} exists while {:?} is still present and was not proven identical",
                        LayoutId::AxiomGraph.as_str(),
                        legacy
                            .iter()
                            .map(|layout| layout.as_str())
                            .collect::<Vec<_>>()
                    ),
                })
            }
        },
    }
}
