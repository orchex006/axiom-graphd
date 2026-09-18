//! Checkpoint creation and verification (tasks B-088 - B-091).
//!
//! `docs/19-GIT-SNAPSHOTS-AND-MERGES.md` defines two lanes, three source
//! selections and one CI verification loop. The modules below own one slice
//! each and share the rule that a checkpoint is a *source* artifact: it is
//! materialized from the Git index, from a verified-stable worktree or from a
//! clean commit checkout, and it never mutates the user's index or working tree.
//!
//! * [`staged`] - B-088, materialize the Git index without touching it.
//! * [`worktree`] - B-089, certify an unchanged worktree or report `WORKTREE_BUSY`.
//! * [`export`] - B-090, write only into the checkpoint lane.
//! * [`verify`] - B-091, detect a stale snapshot after a textual merge.

pub mod export;
pub mod staged;
pub mod verify;
pub mod worktree;

/// Where a checkpoint is materialized from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckpointSource {
    /// The Git index (`--source staged`).
    Staged,
    /// The live working tree, verified stable before and after (`--source worktree`).
    Worktree,
    /// A clean commit checkout (`--source commit --ref <sha>`).
    Commit,
}

impl CheckpointSource {
    /// Stable wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Worktree => "worktree",
            Self::Commit => "commit",
        }
    }

    /// The stored `runtime_checkpoints.source_mode` value.
    #[must_use]
    pub const fn source_mode(self) -> &'static str {
        self.wire()
    }

    /// Whether this source must be certified stable before it is exported.
    #[must_use]
    pub const fn requires_stability_certificate(self) -> bool {
        matches!(self, Self::Worktree)
    }
}
