//! Monotonic desired/indexed dirty generations (task B-027).
//!
//! The watcher may report a second edit while the first edit is still being
//! analyzed. If the analyzer then acknowledged its result by clearing a boolean
//! dirty flag, the second edit would be lost. Instead every project carries a
//! monotonic `desired_generation` that only increases, and an analyzer result
//! names the generation it analyzed. A result is applied only while it is still
//! the desired generation; an older result is superseded and the project stays
//! dirty (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 3). The
//! `graph-store` file rows implement the same rule durably; this type is the
//! in-memory mirror used by the scheduler.

use graph_core::error::{AxiomError, ErrorCode};

/// Highest generation this process will hand out before refusing to guess.
pub const MAX_GENERATION: u64 = i64::MAX as u64;

/// Outcome of acknowledging an analyzed generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcome {
    /// The analyzed generation was still desired and is now indexed.
    Applied {
        /// Generation the project advanced to.
        indexed_generation: u64,
    },
    /// A newer generation arrived first, so the result was discarded and the
    /// project remains dirty.
    Superseded {
        /// Generation the project currently requires.
        desired_generation: u64,
        /// Generation the discarded result analyzed.
        target_generation: u64,
    },
}

impl AckOutcome {
    /// Whether the result was applied.
    #[must_use]
    pub const fn is_applied(self) -> bool {
        matches!(self, Self::Applied { .. })
    }
}

/// Monotonic dirty state of one project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DirtyGenerations {
    desired: u64,
    indexed: u64,
}

impl DirtyGenerations {
    /// A project with nothing dirty and nothing indexed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            desired: 0,
            indexed: 0,
        }
    }

    /// Generation the project currently requires.
    #[must_use]
    pub const fn desired_generation(&self) -> u64 {
        self.desired
    }

    /// Generation whose result is currently reflected in the graph.
    #[must_use]
    pub const fn indexed_generation(&self) -> u64 {
        self.indexed
    }

    /// Whether unreconciled input exists.
    #[must_use]
    pub const fn is_dirty(&self) -> bool {
        self.desired > self.indexed
    }

    /// Record one change and return the new desired generation.
    ///
    /// # Errors
    /// [`ErrorCode::Conflict`] when the counter would exceed
    /// [`MAX_GENERATION`]; the caller must re-seed from durable state instead of
    /// wrapping.
    pub fn mark_dirty(&mut self) -> Result<u64, AxiomError> {
        self.mark_dirty_many(1)
    }

    /// Record `count` changes and return the new desired generation.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] when `count` is zero; [`ErrorCode::Conflict`]
    /// when the counter would exceed [`MAX_GENERATION`].
    pub fn mark_dirty_many(&mut self, count: u64) -> Result<u64, AxiomError> {
        if count == 0 {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a dirty generation must advance by at least one",
            ));
        }
        let next = self
            .desired
            .checked_add(count)
            .filter(|next| *next <= MAX_GENERATION);
        match next {
            Some(next) => {
                self.desired = next;
                Ok(next)
            }
            None => Err(AxiomError::new(
                ErrorCode::Conflict,
                "the dirty generation counter is exhausted",
            )
            .with_detail("desired_generation", self.desired.to_string())),
        }
    }

    /// Acknowledge that generation `analyzed` was fully analyzed.
    ///
    /// The project advances only when `analyzed` is still the desired
    /// generation. An older result leaves the project dirty, so the newer edit
    /// is analyzed by a later job.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] when `analyzed` is zero or exceeds the
    /// desired generation, because no such generation was ever handed out.
    pub fn acknowledge(&mut self, analyzed: u64) -> Result<AckOutcome, AxiomError> {
        if analyzed == 0 || analyzed > self.desired {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "an acknowledged generation must be one this project issued",
            )
            .with_detail("analyzed_generation", analyzed.to_string())
            .with_detail("desired_generation", self.desired.to_string()));
        }
        if analyzed == self.desired {
            self.indexed = analyzed;
            Ok(AckOutcome::Applied {
                indexed_generation: analyzed,
            })
        } else {
            Ok(AckOutcome::Superseded {
                desired_generation: self.desired,
                target_generation: analyzed,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AckOutcome, DirtyGenerations, MAX_GENERATION};
    use graph_core::error::ErrorCode;

    #[test]
    fn a_second_edit_during_processing_raises_the_desired_generation() {
        let mut dirty = DirtyGenerations::new();
        assert!(!dirty.is_dirty());

        let first = dirty.mark_dirty().expect("first edit");
        assert_eq!(first, 1);
        assert!(dirty.is_dirty());

        let second = dirty.mark_dirty().expect("second edit during processing");
        assert_eq!(second, 2);
        assert_eq!(dirty.desired_generation(), 2);
        assert_eq!(dirty.indexed_generation(), 0);
    }

    #[test]
    fn acknowledging_an_old_generation_never_clears_new_work() {
        let mut dirty = DirtyGenerations::new();
        let analyzed = dirty.mark_dirty().expect("edit");
        dirty
            .mark_dirty()
            .expect("second edit arrives while analyzing");

        let outcome = dirty
            .acknowledge(analyzed)
            .expect("a handed-out generation");
        assert_eq!(
            outcome,
            AckOutcome::Superseded {
                desired_generation: 2,
                target_generation: 1,
            }
        );
        assert!(!outcome.is_applied());
        assert!(dirty.is_dirty(), "the newer edit must remain outstanding");

        let outcome = dirty.acknowledge(2).expect("current generation");
        assert!(outcome.is_applied());
        assert!(!dirty.is_dirty());
        assert_eq!(dirty.indexed_generation(), 2);
    }

    #[test]
    fn generations_are_monotonic_and_unguessable() {
        let mut dirty = DirtyGenerations::new();
        assert_eq!(
            dirty
                .mark_dirty_many(0)
                .expect_err("zero is not an advance")
                .code(),
            ErrorCode::ValidationError
        );
        assert_eq!(
            dirty
                .acknowledge(1)
                .expect_err("no generation was issued")
                .code(),
            ErrorCode::ValidationError
        );
        dirty.mark_dirty_many(MAX_GENERATION - 1).expect("bounded");
        assert_eq!(dirty.desired_generation(), MAX_GENERATION - 1);
        dirty.mark_dirty().expect("the last available generation");
        assert_eq!(dirty.desired_generation(), MAX_GENERATION);
        assert_eq!(
            dirty
                .mark_dirty()
                .expect_err("counter exhaustion is a conflict, not a wrap")
                .code(),
            ErrorCode::Conflict
        );
    }
}
