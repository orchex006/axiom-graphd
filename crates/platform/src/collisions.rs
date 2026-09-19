//! Case-fold and Unicode-normalization collision detection (V2-013, CP-03).
//!
//! CP-03 requires A.ts/a.ts and NFC/NFD canonical-equivalent collisions to be
//! detected *before publication*, while the stored spelling is preserved. This
//! module therefore compares derived keys and reports the two original
//! spellings; it never returns, writes or publishes a folded/decomposed form.

use std::collections::BTreeMap;
use std::fmt;

use graph_core::error::{AxiomError, ErrorCode};

use crate::path_key::{PathKey, PathKeyError};

/// Which portability hazard two spellings share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollisionKind {
    /// The same spelling appeared twice.
    Duplicate,
    /// The spellings differ only by letter case (`A.ts` / `a.ts`).
    CaseOnly,
    /// The spellings are canonically equivalent (NFC/NFD), with or without a
    /// case difference, so casefolding alone does not separate them.
    Normalization,
}

impl CollisionKind {
    /// Stable name used in diagnostics and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Duplicate => "duplicate-identity",
            Self::CaseOnly => "case-only-collision",
            Self::Normalization => "normalization-collision",
        }
    }
}

/// Two paths that cannot both be published portably.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collision {
    kind: CollisionKind,
    first: String,
    second: String,
    case_difference: bool,
    normalization_difference: bool,
}

impl Collision {
    /// The hazard class.
    #[must_use]
    pub const fn kind(&self) -> CollisionKind {
        self.kind
    }

    /// Stable name of the hazard class.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        self.kind.as_str()
    }

    /// The spelling observed first, exactly as supplied.
    #[must_use]
    pub fn first(&self) -> &str {
        &self.first
    }

    /// The spelling that collided, exactly as supplied.
    #[must_use]
    pub fn second(&self) -> &str {
        &self.second
    }

    /// True when letter case takes part in the difference: at least one of the
    /// two spellings is changed by case folding.
    #[must_use]
    pub const fn case_difference(&self) -> bool {
        self.case_difference
    }

    /// True when case folding does not unify the two spellings, so canonical
    /// decomposition is required to see that they are the same path.
    #[must_use]
    pub const fn normalization_difference(&self) -> bool {
        self.normalization_difference
    }

    /// Map to the shared typed error, preserving both observed spellings.
    #[must_use]
    pub fn to_axiom_error(&self) -> AxiomError {
        AxiomError::new(
            ErrorCode::UnsafePortablePath,
            "path collision detected before publication",
        )
        .with_detail("portable_path", self.second.clone())
        .with_detail("observed", self.first.clone())
        .with_detail("rule", self.kind.as_str())
    }
}

impl fmt::Display for Collision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {} and {}",
            self.kind.as_str(),
            self.first,
            self.second
        )
    }
}

impl std::error::Error for Collision {}

/// Why a path set cannot be published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectError {
    /// One spelling violates the portable-path policy.
    Invalid(PathKeyError),
    /// Two spellings collide portably.
    Collision(Collision),
}

impl DetectError {
    /// The stable wire code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Invalid(error) => error.code(),
            Self::Collision(_) => crate::path_key::ERR_UNSAFE_PORTABLE_PATH,
        }
    }

    /// Map to the shared typed error.
    #[must_use]
    pub fn to_axiom_error(&self) -> AxiomError {
        match self {
            Self::Invalid(error) => error.to_axiom_error(),
            Self::Collision(collision) => collision.to_axiom_error(),
        }
    }
}

impl fmt::Display for DetectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(error) => write!(formatter, "{error}"),
            Self::Collision(collision) => write!(formatter, "{collision}"),
        }
    }
}

impl std::error::Error for DetectError {}

/// Validate every spelling and refuse case-only or canonical-equivalent
/// collisions between distinct spellings.
///
/// Exact duplicates are reported as [`CollisionKind::Duplicate`] rather than
/// silently deduplicated, because a published path list with two identical
/// entries is a caller defect.
///
/// # Errors
/// Returns [`DetectError::Invalid`] for the first non-portable spelling and
/// [`DetectError::Collision`] for the first colliding pair, in input order.
pub fn detect_portable_collisions<'a, I>(paths: I) -> Result<Vec<PathKey>, DetectError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen: BTreeMap<String, PathKey> = BTreeMap::new();
    let mut accepted = Vec::new();
    for path in paths {
        let key = PathKey::new(path).map_err(DetectError::Invalid)?;
        let collision_key = key.collision_key();
        if let Some(first) = seen.get(&collision_key) {
            return Err(DetectError::Collision(classify(first, &key)));
        }
        seen.insert(collision_key, key.clone());
        accepted.push(key);
    }
    Ok(accepted)
}

fn classify(first: &PathKey, second: &PathKey) -> Collision {
    // Two independent facts about *what* differs, then the summary class.
    // The pair collided on `collision_key`, so one of these holds:
    //   * the spellings are byte-identical            -> Duplicate
    //   * case folding alone unifies them             -> CaseOnly
    //   * canonical decomposition is needed as well   -> Normalization
    let identical = first.as_str() == second.as_str();
    let case_difference =
        first.casefold_key() != first.as_str() || second.casefold_key() != second.as_str();
    let normalization_difference = first.casefold_key() != second.casefold_key();
    let kind = if identical {
        CollisionKind::Duplicate
    } else if normalization_difference {
        CollisionKind::Normalization
    } else {
        CollisionKind::CaseOnly
    };
    Collision {
        kind,
        first: first.as_str().to_string(),
        second: second.as_str().to_string(),
        case_difference,
        normalization_difference,
    }
}
