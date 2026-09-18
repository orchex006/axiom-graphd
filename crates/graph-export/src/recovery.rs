//! Resuming a publication that a crash interrupted (task B-077).
//!
//! Recovery is a pure decision over observed state, so it can be replayed in a
//! test without a real crash. The rule that matters most: an incomplete staging
//! directory never becomes current, whatever else was true when the process
//! died.

use crate::manifest::GenerationManifest;
use crate::pointer::{pointer_path, CurrentPointer, PointerStrategy};
use crate::{ExportError, Result};
use std::fs;
use std::path::Path;

/// Reason recorded when a staging directory was never sealed.
pub const REASON_STAGING_INCOMPLETE: &str = "incomplete-staging-never-becomes-current";
/// Reason recorded when the pointer names a generation that is not on disk.
pub const REASON_CURRENT_GENERATION_MISSING: &str = "current-generation-is-missing";
/// Reason recorded when there is nothing to resume.
pub const REASON_CLEAN: &str = "publication-state-is-consistent";

/// A staging directory observed during recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingObservation {
    /// The generation identity the directory was staged for.
    pub generation_id: String,
    /// Whether the directory was sealed with a manifest whose bytes match.
    pub sealed: bool,
}

/// Everything recovery is allowed to look at.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecoveryState {
    /// The pointer currently on disk, if any.
    pub pointer: Option<CurrentPointer>,
    /// The generation the pointer names, when its directory exists and verifies.
    pub pointer_target_present: bool,
    /// The generation the active catalog pins, if any.
    pub pinned: Option<String>,
    /// Staging directories left behind.
    pub staging: Vec<StagingObservation>,
}

/// What recovery decided to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAction {
    /// The publication state is already consistent.
    Nothing,
    /// Move a sealed staged generation into place and point at it.
    InstallSealed {
        /// The generation to install.
        generation_id: String,
    },
    /// Delete a staging directory that was never sealed.
    DiscardStaging {
        /// The generation whose staging directory is discarded.
        generation_id: String,
        /// Why it is discarded.
        reason: &'static str,
    },
    /// Re-point at the generation the active catalog pins.
    RestorePinned {
        /// The pinned generation to restore.
        generation_id: String,
        /// Why the pointer had to move.
        reason: &'static str,
    },
    /// Report a state a human must resolve.
    Report {
        /// What is wrong.
        reason: &'static str,
    },
}

impl RecoveryAction {
    /// A short description suitable for a log line.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            RecoveryAction::Nothing => String::from("nothing to resume"),
            RecoveryAction::InstallSealed { generation_id } => {
                format!("install sealed generation {generation_id}")
            }
            RecoveryAction::DiscardStaging {
                generation_id,
                reason,
            } => format!("discard staging {generation_id}: {reason}"),
            RecoveryAction::RestorePinned {
                generation_id,
                reason,
            } => format!("restore pinned generation {generation_id}: {reason}"),
            RecoveryAction::Report { reason } => format!("report: {reason}"),
        }
    }
}

/// Decide how to resume from an observed state.
#[must_use]
pub fn plan(state: &RecoveryState) -> RecoveryAction {
    if let Some(pointer) = &state.pointer {
        if state.pointer_target_present {
            return RecoveryAction::Nothing;
        }
        return match &state.pinned {
            Some(pinned) if pinned != &pointer.generation_id => RecoveryAction::RestorePinned {
                generation_id: pinned.clone(),
                reason: REASON_CURRENT_GENERATION_MISSING,
            },
            _ => RecoveryAction::Report {
                reason: REASON_CURRENT_GENERATION_MISSING,
            },
        };
    }
    if let Some(sealed) = state.staging.iter().find(|entry| entry.sealed) {
        return RecoveryAction::InstallSealed {
            generation_id: sealed.generation_id.clone(),
        };
    }
    if let Some(incomplete) = state.staging.first() {
        return RecoveryAction::DiscardStaging {
            generation_id: incomplete.generation_id.clone(),
            reason: REASON_STAGING_INCOMPLETE,
        };
    }
    if let Some(pinned) = &state.pinned {
        return RecoveryAction::RestorePinned {
            generation_id: pinned.clone(),
            reason: REASON_CLEAN,
        };
    }
    RecoveryAction::Nothing
}

/// Observe the publication state of one export root.
///
/// # Errors
///
/// Returns the same errors as [`crate::pointer::read`] and [`crate::ERR_IO`].
pub fn observe(root: &Path, pinned: Option<String>) -> Result<RecoveryState> {
    let pointer = crate::pointer::read(root)?;
    let pointer_target_present = match &pointer {
        Some(pointer) => crate::validate::validate_generation(
            &crate::staging::StagingLayout::new(root).generation_dir(&pointer.generation_id),
        )
        .is_ok(),
        None => false,
    };
    let mut staging = Vec::new();
    let staging_root = root.join(crate::staging::STAGING_DIR);
    if staging_root.is_dir() {
        for entry in fs::read_dir(&staging_root).map_err(|error| ExportError::io(&error))? {
            let entry = entry.map_err(|error| ExportError::io(&error))?;
            let generation_id = entry.file_name().to_string_lossy().into_owned();
            let sealed = read_staged_manifest(&entry.path())
                .map(|manifest| manifest.identity_is_self_consistent())
                .unwrap_or(false);
            staging.push(StagingObservation {
                generation_id,
                sealed,
            });
        }
    }
    staging.sort_by(|left, right| left.generation_id.cmp(&right.generation_id));
    Ok(RecoveryState {
        pointer,
        pointer_target_present,
        pinned,
        staging,
    })
}

/// Finish the publication the crash interrupted.
///
/// # Errors
///
/// Returns the same errors as the install or pointer step it performs.
pub fn resume(root: &Path, pinned: Option<String>) -> Result<RecoveryAction> {
    let state = observe(root, pinned)?;
    let action = plan(&state);
    match &action {
        RecoveryAction::InstallSealed { generation_id } => {
            let staged = crate::staging::StagingLayout::new(root).staging_dir(generation_id);
            let manifest = read_staged_manifest(&staged)?;
            let target = crate::staging::StagingLayout::new(root).generation_dir(generation_id);
            if !target.exists() {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|error| ExportError::io(&error))?;
                }
                fs::rename(&staged, &target).map_err(|error| ExportError::io(&error))?;
            }
            crate::pointer::replace(
                root,
                &CurrentPointer::new(manifest.generation_id.clone()),
                PointerStrategy::AtomicReplace,
            )?;
        }
        RecoveryAction::DiscardStaging { generation_id, .. } => {
            let staged = crate::staging::StagingLayout::new(root).staging_dir(generation_id);
            if staged.exists() {
                fs::remove_dir_all(&staged).map_err(|error| ExportError::io(&error))?;
            }
        }
        _ => {}
    }
    Ok(action)
}

fn read_staged_manifest(dir: &Path) -> Result<GenerationManifest> {
    let path = dir.join("manifest.json");
    let bytes = fs::read(&path).map_err(|error| ExportError::io(&error))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        ExportError::new(crate::ERR_MISSING, format!("{}: {error}", path.display()))
    })
}

/// The pointer file a resumed publication writes.
#[must_use]
pub fn resumed_pointer_path(root: &Path) -> std::path::PathBuf {
    pointer_path(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn digest(seed: char) -> String {
        seed.to_string().repeat(64)
    }

    #[test]
    fn a_crash_after_the_immutable_rename_resumes_by_pointing_at_the_sealed_generation() {
        let state = RecoveryState {
            pointer: None,
            pointer_target_present: false,
            pinned: None,
            staging: vec![StagingObservation {
                generation_id: digest('a'),
                sealed: true,
            }],
        };
        assert_eq!(
            plan(&state),
            RecoveryAction::InstallSealed {
                generation_id: digest('a')
            }
        );
    }

    #[test]
    fn an_incomplete_staging_directory_never_becomes_current() {
        let state = RecoveryState {
            pointer: None,
            pointer_target_present: false,
            pinned: Some(digest('b')),
            staging: vec![StagingObservation {
                generation_id: digest('c'),
                sealed: false,
            }],
        };
        assert_eq!(
            plan(&state),
            RecoveryAction::DiscardStaging {
                generation_id: digest('c'),
                reason: REASON_STAGING_INCOMPLETE,
            }
        );
    }

    #[test]
    fn a_pointer_whose_generation_vanished_is_restored_from_the_pinned_catalog() {
        let state = RecoveryState {
            pointer: Some(CurrentPointer::new(digest('d'))),
            pointer_target_present: false,
            pinned: Some(digest('e')),
            staging: Vec::new(),
        };
        assert_eq!(
            plan(&state),
            RecoveryAction::RestorePinned {
                generation_id: digest('e'),
                reason: REASON_CURRENT_GENERATION_MISSING,
            }
        );
        let unresolved = RecoveryState {
            pinned: None,
            ..state
        };
        assert_eq!(
            plan(&unresolved),
            RecoveryAction::Report {
                reason: REASON_CURRENT_GENERATION_MISSING
            }
        );
    }

    #[test]
    fn a_consistent_publication_needs_no_recovery_action() {
        let state = RecoveryState {
            pointer: Some(CurrentPointer::new(digest('f'))),
            pointer_target_present: true,
            pinned: Some(digest('f')),
            staging: Vec::new(),
        };
        assert_eq!(plan(&state), RecoveryAction::Nothing);
        assert_eq!(plan(&RecoveryState::default()), RecoveryAction::Nothing);
    }

    #[test]
    fn resume_discards_unsealed_staging_and_never_points_at_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let staged = dir
            .path()
            .join(crate::staging::STAGING_DIR)
            .join(digest('9'));
        std::fs::create_dir_all(&staged).expect("mkdir");
        std::fs::write(staged.join("part-000"), b"{}\n").expect("part");
        let action = resume(dir.path(), None).expect("resume");
        assert!(matches!(action, RecoveryAction::DiscardStaging { .. }));
        assert!(!staged.exists());
        assert!(!resumed_pointer_path(dir.path()).exists());
    }
}
