//! Write a checkpoint into the checkpoint lane (task B-090).
//!
//! `docs/19-GIT-SNAPSHOTS-AND-MERGES.md` section 1 splits the two lanes: the
//! **live** lane under a project is Git-ignored and rewritten on every debounce,
//! while the **checkpoint** lane is an explicit, tracked artifact a human chose
//! to publish. Section 2 adds that the checkpoint's outputs are not part of its
//! own input fingerprint.
//!
//! This module enforces both rules where they can be broken:
//!
//! * A live-lane write is refused ([`REASON_NOT_CHECKPOINT_LANE`]) and so is a
//!   checkpoint write the caller did not explicitly ask for
//!   ([`REASON_EXPLICIT_COMMAND_REQUIRED`]); a debounce can therefore never
//!   publish a tracked artifact by accident.
//! * A destination outside the checkpoint lane is refused
//!   ([`REASON_OUTPUT_OUTSIDE_LANE`]).
//! * Generated outputs are removed from the input fingerprint
//!   ([`REASON_GENERATED_OUTPUT_EXCLUDED`]) so the fingerprint describes the
//!   human source rather than the artifact it produced.

use graph_core::error::{AxiomError, ErrorCode};
use serde::Serialize;

/// The Git-ignored lane that is rewritten on every debounce.
pub const LIVE_LANE_DIR: &str = "live";
/// The tracked checkpoint lane.
pub const CHECKPOINT_LANE_DIR: &str = "checkpoint";
/// Reason recorded when a write targets the live lane.
pub const REASON_NOT_CHECKPOINT_LANE: &str = "not-checkpoint-lane";
/// Reason recorded when a checkpoint write was not explicitly requested.
pub const REASON_EXPLICIT_COMMAND_REQUIRED: &str = "explicit-command-required";
/// Reason recorded when an output path leaves the checkpoint lane.
pub const REASON_OUTPUT_OUTSIDE_LANE: &str = "output-outside-lane";
/// Reason recorded when a generated output is dropped from the fingerprint.
pub const REASON_GENERATED_OUTPUT_EXCLUDED: &str = "generated-output-excluded";
/// Reason recorded when no output was requested.
pub const REASON_NO_OUTPUTS: &str = "no-outputs";
/// Reason recorded when a path is not repository-relative.
pub const REASON_PATH_NOT_PORTABLE: &str = "path-not-portable";

/// The two publication lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lane {
    /// Git-ignored, rewritten on every debounce.
    Live,
    /// Tracked, written only by an explicit command.
    Checkpoint,
}

impl Lane {
    /// Stable wire spelling and on-disk directory name.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Live => LIVE_LANE_DIR,
            Self::Checkpoint => CHECKPOINT_LANE_DIR,
        }
    }

    /// Parse a wire spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "live" => Some(Self::Live),
            "checkpoint" => Some(Self::Checkpoint),
            _ => None,
        }
    }

    /// Whether this lane is tracked in Git.
    #[must_use]
    pub const fn is_tracked(self) -> bool {
        matches!(self, Self::Checkpoint)
    }
}

/// A `checkpoint create` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRequest {
    /// Requested lane.
    pub lane: Lane,
    /// Whether the caller ran the explicit checkpoint command rather than a
    /// debounced publication.
    pub explicit_command: bool,
    /// Repository-relative output paths.
    pub outputs: Vec<String>,
}

/// A validated checkpoint export plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportPlan {
    /// The lane, always `checkpoint`.
    pub lane: Lane,
    /// Validated output paths, in request order.
    pub outputs: Vec<String>,
    /// `runtime_checkpoints.source_mode` for the created checkpoint.
    pub lane_dir: &'static str,
    /// The lane is tracked and therefore reviewed in the diff.
    pub tracked: bool,
}

/// Plan a checkpoint export.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] with [`REASON_NOT_CHECKPOINT_LANE`] when the
///   lane is `live`.
/// - [`ErrorCode::ValidationError`] with
///   [`REASON_EXPLICIT_COMMAND_REQUIRED`] when the write was not explicit.
/// - [`ErrorCode::ValidationError`] with [`REASON_NO_OUTPUTS`] for an empty
///   output list, and [`REASON_OUTPUT_OUTSIDE_LANE`] /
///   [`REASON_PATH_NOT_PORTABLE`] for a destination outside the lane.
pub fn plan_export(request: &ExportRequest) -> Result<ExportPlan, AxiomError> {
    if request.lane != Lane::Checkpoint {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "a checkpoint is written only into the checkpoint lane",
        )
        .with_detail("rule", REASON_NOT_CHECKPOINT_LANE)
        .with_detail("lane", request.lane.wire()));
    }
    if !request.explicit_command {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "the checkpoint lane is written only by an explicit command",
        )
        .with_detail("rule", REASON_EXPLICIT_COMMAND_REQUIRED)
        .with_detail("lane", request.lane.wire()));
    }
    if request.outputs.is_empty() {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "a checkpoint export requires at least one output path",
        )
        .with_detail("rule", REASON_NO_OUTPUTS));
    }
    for output in &request.outputs {
        graph_core::paths::validate_portable_relative_path(output).map_err(|error| {
            AxiomError::new(
                ErrorCode::ValidationError,
                "a checkpoint output must be a repository-relative path",
            )
            .with_detail("rule", REASON_PATH_NOT_PORTABLE)
            .with_detail("path", output.clone())
            .with_detail("cause", error.message())
        })?;
        if !is_in_checkpoint_lane(output) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a checkpoint output must live under the checkpoint lane",
            )
            .with_detail("rule", REASON_OUTPUT_OUTSIDE_LANE)
            .with_detail("path", output.clone())
            .with_detail("lane_dir", CHECKPOINT_LANE_DIR));
        }
    }
    Ok(ExportPlan {
        lane: Lane::Checkpoint,
        outputs: request.outputs.clone(),
        lane_dir: CHECKPOINT_LANE_DIR,
        tracked: true,
    })
}

/// Whether a repository-relative path is inside the checkpoint lane.
#[must_use]
pub fn is_in_checkpoint_lane(path: &str) -> bool {
    path == CHECKPOINT_LANE_DIR
        || path
            .strip_prefix(CHECKPOINT_LANE_DIR)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Which inputs contribute to a checkpoint's source fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FingerprintPlan {
    /// Input paths that are fingerprinted.
    pub included: Vec<String>,
    /// Input paths dropped because they are generated outputs.
    pub excluded: Vec<String>,
    /// Stable reason for the exclusions.
    pub excluded_reason: &'static str,
}

/// Split input paths into fingerprinted inputs and generated outputs.
///
/// A path is generated when it equals a generated root or lies beneath it, so a
/// checkpoint never hashes the artifact it just produced.
#[must_use]
pub fn fingerprint_inputs(inputs: &[String], generated_roots: &[String]) -> FingerprintPlan {
    let mut included = Vec::new();
    let mut excluded = Vec::new();
    for input in inputs {
        let generated = generated_roots.iter().any(|root| {
            input == root
                || input
                    .strip_prefix(root)
                    .is_some_and(|rest| rest.starts_with('/'))
        });
        if generated {
            excluded.push(input.clone());
        } else {
            included.push(input.clone());
        }
    }
    FingerprintPlan {
        included,
        excluded,
        excluded_reason: REASON_GENERATED_OUTPUT_EXCLUDED,
    }
}

/// A destination the export writes through, so tests can prove no live-lane
/// write happened without touching a repository.
pub trait LaneWriter {
    /// Write `bytes` to the repository-relative `path`.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`] when the write fails.
    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError>;
}

/// The result of an executed checkpoint export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckpointExport {
    /// The lane that was written.
    pub lane: Lane,
    /// Paths actually written, in plan order.
    pub written: Vec<String>,
    /// The input fingerprint plan for this checkpoint.
    pub fingerprint: FingerprintPlan,
    /// SHA-256 over the written path/digest pairs.
    pub output_sha256: String,
}

/// Execute a checkpoint export plan.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] with [`REASON_OUTPUT_OUTSIDE_LANE`] when a
///   file to write is outside the checkpoint lane.
/// - [`ErrorCode::ValidationError`] with [`REASON_NO_OUTPUTS`] when a planned
///   output has no bytes.
pub fn execute(
    plan: &ExportPlan,
    writer: &dyn LaneWriter,
    files: &[(String, Vec<u8>)],
    input_paths: &[String],
    generated_roots: &[String],
) -> Result<CheckpointExport, AxiomError> {
    let mut written = Vec::new();
    let mut inventory = String::new();
    for (path, bytes) in files {
        if !is_in_checkpoint_lane(path) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a checkpoint output must live under the checkpoint lane",
            )
            .with_detail("rule", REASON_OUTPUT_OUTSIDE_LANE)
            .with_detail("path", path.clone()));
        }
        if !plan.outputs.iter().any(|planned| planned == path) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a checkpoint output was not part of the approved plan",
            )
            .with_detail("rule", REASON_NO_OUTPUTS)
            .with_detail("path", path.clone()));
        }
        writer.write(path, bytes)?;
        inventory.push_str(path);
        inventory.push('\u{1f}');
        inventory.push_str(&graph_export::sha256_hex(bytes));
        inventory.push('\n');
        written.push(path.clone());
    }
    Ok(CheckpointExport {
        lane: Lane::Checkpoint,
        written,
        fingerprint: fingerprint_inputs(input_paths, generated_roots),
        output_sha256: graph_export::sha256_hex(inventory.as_bytes()),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records every destination a checkpoint export writes through.
    struct Recorder {
        writes: RefCell<Vec<String>>,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                writes: RefCell::new(Vec::new()),
            }
        }
    }

    impl LaneWriter for Recorder {
        fn write(&self, path: &str, _bytes: &[u8]) -> Result<(), AxiomError> {
            self.writes.borrow_mut().push(path.to_owned());
            Ok(())
        }
    }

    fn request(lane: Lane, explicit: bool, outputs: &[&str]) -> ExportRequest {
        ExportRequest {
            lane,
            explicit_command: explicit,
            outputs: outputs.iter().map(|path| (*path).to_owned()).collect(),
        }
    }

    #[test]
    fn an_explicit_checkpoint_command_writes_only_into_the_checkpoint_lane() {
        let plan = plan_export(&request(
            Lane::Checkpoint,
            true,
            &[
                "checkpoint/current.json",
                "checkpoint/generations/gen-1/bucket-000",
            ],
        ))
        .expect("plan");
        assert_eq!(plan.lane, Lane::Checkpoint);
        assert!(plan.tracked);
        assert_eq!(plan.lane_dir, CHECKPOINT_LANE_DIR);

        let writer = Recorder::new();
        let files = vec![
            (
                "checkpoint/current.json".to_owned(),
                b"{\"generation\":\"gen-1\"}\n".to_vec(),
            ),
            (
                "checkpoint/generations/gen-1/bucket-000".to_owned(),
                b"{\"key\":\"edge:a->b\"}\n".to_vec(),
            ),
        ];
        let export = execute(
            &plan,
            &writer,
            &files,
            &["src/Auth.Api/AuthController.cs".to_owned()],
            &["checkpoint".to_owned()],
        )
        .expect("execute");
        assert_eq!(writer.writes.borrow().len(), 2);
        assert!(writer
            .writes
            .borrow()
            .iter()
            .all(|path| is_in_checkpoint_lane(path)));
        assert_eq!(export.written.len(), 2);
        assert_eq!(export.lane, Lane::Checkpoint);
        assert_eq!(export.output_sha256.len(), 64);
        assert!(is_in_checkpoint_lane("checkpoint/current.json"));
        assert!(is_in_checkpoint_lane("checkpoint"));
        assert!(!is_in_checkpoint_lane("checkpointed/current.json"));
        assert!(!is_in_checkpoint_lane("live/current.json"));
    }

    #[test]
    fn the_live_lane_and_an_implicit_write_are_both_refused() {
        let error =
            plan_export(&request(Lane::Live, true, &["live/current.json"])).expect_err("live lane");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_NOT_CHECKPOINT_LANE)
        );
        let error = plan_export(&request(
            Lane::Checkpoint,
            false,
            &["checkpoint/current.json"],
        ))
        .expect_err("implicit");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_EXPLICIT_COMMAND_REQUIRED)
        );
        assert_eq!(Lane::parse("checkpoint"), Some(Lane::Checkpoint));
        assert_eq!(Lane::parse("live"), Some(Lane::Live));
        assert_eq!(Lane::parse("other"), None);
        assert!(Lane::Checkpoint.is_tracked());
        assert!(!Lane::Live.is_tracked());
    }

    #[test]
    fn an_output_outside_the_checkpoint_lane_is_refused() {
        for path in [
            "live/current.json",
            "../checkpoint/current.json",
            "D:/repo/checkpoint/current.json",
        ] {
            let error =
                plan_export(&request(Lane::Checkpoint, true, &[path])).expect_err("outside lane");
            assert_eq!(error.code(), ErrorCode::ValidationError);
        }
        let error = plan_export(&request(Lane::Checkpoint, true, &[])).expect_err("no outputs");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_NO_OUTPUTS)
        );
        // A writer cannot smuggle a write outside the approved plan.
        let plan = plan_export(&request(
            Lane::Checkpoint,
            true,
            &["checkpoint/current.json"],
        ))
        .expect("plan");
        let writer = Recorder::new();
        let error = execute(
            &plan,
            &writer,
            &[("live/current.json".to_owned(), b"{}".to_vec())],
            &[],
            &[],
        )
        .expect_err("outside lane");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_OUTPUT_OUTSIDE_LANE)
        );
        assert!(writer.writes.borrow().is_empty());
    }

    #[test]
    fn generated_outputs_are_excluded_from_the_input_fingerprint() {
        let plan = plan_export(&request(
            Lane::Checkpoint,
            true,
            &["checkpoint/generations/gen-1/catalog.json"],
        ))
        .expect("plan");
        let writer = Recorder::new();
        let inputs = vec![
            "src/Auth.Api/AuthController.cs".to_owned(),
            "solution.yaml".to_owned(),
            "checkpoint/generations/gen-1/catalog.json".to_owned(),
            "checkpoint/current.json".to_owned(),
        ];
        let export = execute(
            &plan,
            &writer,
            &[(
                "checkpoint/generations/gen-1/catalog.json".to_owned(),
                b"{}\n".to_vec(),
            )],
            &inputs,
            &["checkpoint".to_owned()],
        )
        .expect("execute");
        assert_eq!(
            export.fingerprint.included,
            vec![
                "src/Auth.Api/AuthController.cs".to_owned(),
                "solution.yaml".to_owned()
            ]
        );
        assert_eq!(export.fingerprint.excluded.len(), 2);
        assert_eq!(
            export.fingerprint.excluded_reason,
            REASON_GENERATED_OUTPUT_EXCLUDED
        );
        // A root that is a prefix of another path is not a false positive.
        let plan = fingerprint_inputs(
            &[
                "generatedx/file.rs".to_owned(),
                "generated/file.rs".to_owned(),
            ],
            &["generated".to_owned()],
        );
        assert_eq!(plan.included, vec!["generatedx/file.rs".to_owned()]);
        assert_eq!(plan.excluded, vec!["generated/file.rs".to_owned()]);
    }
}
