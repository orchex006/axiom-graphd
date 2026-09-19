//! Portable path identity (V2-013, CP-03).
//!
//! A [`PathKey`] is a repository-relative path that passed the portable-path
//! policy **and** carries the exact spelling the caller supplied. The portability
//! policy itself is owned by `graph-core::paths::validate_portable_relative_path`
//! (absolute, drive, UNC/device, traversal, reserved-name, alternate-data-stream
//! and trailing dot/space rejection); this type does not copy that rule, it
//! makes the accepted spelling an identity that is never normalised in place.
//!
//! Two detection keys are derived on demand and never stored:
//!
//! - [`PathKey::casefold_key`] for case-only hazards,
//! - [`PathKey::normalization_key`] for canonical (NFC/NFD) equivalence.
//!
//! Storing a folded or decomposed spelling would silently rename a source path,
//! which CP-03 forbids.

use std::fmt;

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::validate_portable_relative_path;

use crate::unicode::{is_nfd, nfd};

/// The stable error code carried by [`PathKeyError`].
pub const ERR_UNSAFE_PORTABLE_PATH: &str = "UNSAFE_PORTABLE_PATH";

/// Why a spelling is not a portable path identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathKeyError {
    path: String,
    reason: String,
}

impl PathKeyError {
    fn new(path: &str, reason: impl Into<String>) -> Self {
        Self {
            path: path.to_string(),
            reason: reason.into(),
        }
    }

    /// The exact, unmodified spelling that was refused.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The portability rule that refused it.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The stable wire code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        ERR_UNSAFE_PORTABLE_PATH
    }

    /// Map to the shared typed error, preserving the observed spelling.
    #[must_use]
    pub fn to_axiom_error(&self) -> AxiomError {
        AxiomError::new(
            ErrorCode::UnsafePortablePath,
            format!("path rejected: {}", self.reason),
        )
        .with_detail("portable_path", self.path.clone())
        .with_detail("rule", "portable-identity")
    }
}

impl fmt::Display for PathKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {} ({})",
            self.code(),
            self.reason,
            self.path
        )
    }
}

impl std::error::Error for PathKeyError {}

/// A validated repository-relative path that preserves its exact spelling.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathKey(String);

impl PathKey {
    /// Validate `path` and keep its exact spelling.
    ///
    /// # Errors
    /// Returns [`PathKeyError`] when the spelling violates the portable-path
    /// policy. The error carries the original spelling, never a rewritten one.
    pub fn new(path: &str) -> Result<Self, PathKeyError> {
        validate_portable_relative_path(path)
            .map_err(|error| PathKeyError::new(path, error.message().to_string()))?;
        Ok(Self(path.to_string()))
    }

    /// The exact spelling, byte for byte, as the caller supplied it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the key and return the exact spelling.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }

    /// Case-folded detection key. Never stored, never published.
    #[must_use]
    pub fn casefold_key(&self) -> String {
        self.0.to_lowercase()
    }

    /// Canonical-decomposition detection key. Never stored, never published.
    #[must_use]
    pub fn normalization_key(&self) -> String {
        nfd(&self.0)
    }

    /// The combined detection key: canonical decomposition of the case-folded
    /// spelling. Equal keys mean the two spellings cannot coexist portably.
    #[must_use]
    pub fn collision_key(&self) -> String {
        nfd(&self.0.to_lowercase())
    }

    /// True when the stored spelling already equals its NFD form.
    #[must_use]
    pub fn is_in_nfd(&self) -> bool {
        is_nfd(&self.0)
    }
}

impl fmt::Display for PathKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::str::FromStr for PathKey {
    type Err = PathKeyError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        Self::new(path)
    }
}
