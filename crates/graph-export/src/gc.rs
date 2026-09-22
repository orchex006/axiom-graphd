//! Garbage collection of unreferenced generations (task B-080).
//!
//! Deletion is the only irreversible operation in the publication package, so
//! it is fenced twice: the plan only ever lists generations that nothing
//! retains, and the executor refuses to run under a shared guard. A budget
//! shortfall is never a reason to delete: that decision belongs to
//! [`crate::disk_budget`], which defers publication instead.

use crate::{ExportError, Result, ERR_INTEGRITY, ERR_LOCKED};
use graph_core::locks::SolutionGuard;
use std::fs;
use std::path::Path;

/// Reason recorded for the generation a reader would load.
pub const REASON_CURRENT: &str = "gc-retains-current-generation";
/// Reason recorded for a generation an active catalog pins.
pub const REASON_CATALOG: &str = "gc-retains-active-catalog";
/// Reason recorded for a generation some reader still holds.
pub const REASON_READER: &str = "gc-retains-open-reader";

/// A generation that must survive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedGeneration {
    /// The generation identity.
    pub generation_id: String,
    /// Why it is retained.
    pub reason: &'static str,
}

/// What a collection pass would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcPlan {
    /// Generation directories to delete, in ascending identity order.
    pub delete: Vec<String>,
    /// Generations that must survive, in ascending identity order.
    pub retain: Vec<RetainedGeneration>,
}

impl GcPlan {
    /// Whether a generation would be deleted.
    #[must_use]
    pub fn deletes(&self, generation_id: &str) -> bool {
        self.delete.iter().any(|entry| entry == generation_id)
    }

    /// Why a generation is retained, when it is.
    #[must_use]
    pub fn retained_reason(&self, generation_id: &str) -> Option<&'static str> {
        self.retain
            .iter()
            .find(|entry| entry.generation_id == generation_id)
            .map(|entry| entry.reason)
    }

    /// Total generations considered.
    #[must_use]
    pub fn considered(&self) -> usize {
        self.delete.len() + self.retain.len()
    }
}

/// Plan a collection pass.
#[must_use]
pub fn plan(
    current: &str,
    pinned: &[String],
    open_readers: &[String],
    present: &[String],
) -> GcPlan {
    let mut delete = Vec::new();
    let mut retain = Vec::new();
    for generation in present {
        let reason = if generation == current {
            Some(REASON_CURRENT)
        } else if pinned.iter().any(|entry| entry == generation) {
            Some(REASON_CATALOG)
        } else if open_readers.iter().any(|entry| entry == generation) {
            Some(REASON_READER)
        } else {
            None
        };
        match reason {
            Some(reason) => retain.push(RetainedGeneration {
                generation_id: generation.clone(),
                reason,
            }),
            None => delete.push(generation.clone()),
        }
    }
    delete.sort();
    retain.sort_by(|left, right| left.generation_id.cmp(&right.generation_id));
    GcPlan { delete, retain }
}

/// Delete the generations the plan lists, under the exclusive guard.
///
/// # Errors
///
/// * [`ERR_LOCKED`] when the guard is shared, because reading while deleting is
///   exactly the interleaving this fence exists to prevent;
/// * [`ERR_INTEGRITY`] when a delete target is actually retained;
/// * [`crate::ERR_IO`] when a directory cannot be removed.
pub fn execute(guard: &SolutionGuard, root: &Path, plan: &GcPlan) -> Result<usize> {
    if guard.is_shared() {
        return Err(ExportError::new(
            ERR_LOCKED,
            "garbage collection requires the exclusive guard, not a reader lock",
        ));
    }
    let mut removed = 0;
    for generation_id in &plan.delete {
        if let Some(reason) = plan.retained_reason(generation_id) {
            return Err(ExportError::new(
                ERR_INTEGRITY,
                format!("refusing to delete {generation_id}: {reason}"),
            ));
        }
        let dir = crate::staging::StagingLayout::new(root).generation_dir(generation_id);
        if dir.exists() {
            fs::remove_dir_all(&dir).map_err(|error| ExportError::io(&error))?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use graph_core::locks::LockMode;

    fn generation(seed: char) -> String {
        seed.to_string().repeat(64)
    }

    #[test]
    fn the_current_generation_is_retained_even_when_nothing_else_references_it() {
        let current = generation('a');
        let plan = plan(&current, &[], &[], std::slice::from_ref(&current));
        assert!(!plan.deletes(&current));
        assert_eq!(plan.retained_reason(&current), Some(REASON_CURRENT));
        assert!(plan.delete.is_empty());
    }

    #[test]
    fn an_active_catalog_and_open_readers_retain_their_generations() {
        let current = generation('a');
        let pinned = generation('b');
        let reading = generation('c');
        let stale = generation('d');
        let present = vec![
            current.clone(),
            pinned.clone(),
            reading.clone(),
            stale.clone(),
        ];
        let plan = plan(
            &current,
            std::slice::from_ref(&pinned),
            std::slice::from_ref(&reading),
            &present,
        );
        assert_eq!(plan.retained_reason(&pinned), Some(REASON_CATALOG));
        assert_eq!(plan.retained_reason(&reading), Some(REASON_READER));
        assert!(plan.deletes(&stale));
        assert_eq!(plan.delete, vec![stale]);
        assert_eq!(plan.considered(), 4);
    }

    #[test]
    fn collection_refuses_to_run_under_a_shared_guard() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("solution.lock");
        let reader = SolutionGuard::acquire(&path, LockMode::Shared).expect("reader");
        let stale = generation('e');
        let plan = plan(&generation('f'), &[], &[], std::slice::from_ref(&stale));
        let error = execute(&reader, dir.path(), &plan).expect_err("shared guard must be refused");
        assert_eq!(error.code, ERR_LOCKED);
        assert!(error.message.contains("exclusive guard"));
    }

    #[test]
    fn collection_deletes_only_the_unreferenced_generations() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = crate::staging::StagingLayout::new(dir.path());
        let current = generation('1');
        let stale = generation('2');
        for id in [&current, &stale] {
            fs::create_dir_all(layout.generation_dir(id)).expect("mkdir");
            fs::write(layout.generation_dir(id).join("bucket-000"), b"{}\n").expect("shard");
        }
        let path = dir.path().join("solution.lock");
        let guard = SolutionGuard::acquire(&path, LockMode::Exclusive).expect("writer");
        let plan = plan(&current, &[], &[], &[current.clone(), stale.clone()]);
        assert_eq!(execute(&guard, dir.path(), &plan).expect("gc"), 1);
        assert!(layout.generation_dir(&current).exists());
        assert!(!layout.generation_dir(&stale).exists());
    }
}
