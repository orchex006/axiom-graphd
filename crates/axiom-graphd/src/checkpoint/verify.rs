//! Verify a merged-source checkpoint in CI (task B-091).
//!
//! `docs/19-GIT-SNAPSHOTS-AND-MERGES.md` section 4 is explicit: "a successful
//! text merge does not mean the graph semantics are correct", and section 6
//! requires CI to check out the PR merge result, regenerate, and compare the
//! canonical payload against the tracked checkpoint, failing with regenerate
//! instructions. Section 4 also forbids `merge=union` on nodes and edges and
//! forbids choosing one side wholesale and claiming it matches the source.
//!
//! The module therefore never treats a clean textual merge as evidence. It
//! compares the regenerated canonical identity - per-project source
//! fingerprints plus the checkpoint digest - and, when a clean textual merge
//! produced a different payload, it records
//! [`REASON_TEXTUAL_MERGE_INSUFFICIENT`] alongside the stale verdict so the
//! failure mode is named rather than merely reported.

use std::collections::BTreeMap;

use graph_core::error::{AxiomError, ErrorCode};
use serde::Serialize;

/// Reason recorded when the regenerated payload no longer matches the checkpoint.
pub const REASON_STALE_SNAPSHOT: &str = "stale-snapshot";
/// Reason recorded when a human must regenerate the checkpoint.
pub const REASON_REGENERATE_REQUIRED: &str = "regenerate-required";
/// Reason recorded when a clean textual merge still produced a different graph.
pub const REASON_TEXTUAL_MERGE_INSUFFICIENT: &str = "textual-merge-insufficient";
/// Reason recorded when one project's source fingerprint moved.
pub const REASON_FINGERPRINT_MISMATCH: &str = "fingerprint-mismatch";
/// Reason recorded when no tracked checkpoint is available.
pub const REASON_CHECKPOINT_MISSING: &str = "checkpoint-missing";
/// Reason recorded when the merge left conflicts for a human.
pub const REASON_MERGE_CONFLICTED: &str = "merge-conflicted";

/// What the Git merge of the tested source reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeEvidence {
    /// Whether Git reported a clean textual merge.
    pub textual_merge_clean: bool,
    /// Paths Git left conflicted.
    pub conflicted_paths: Vec<String>,
    /// The ref or commit the regeneration ran against.
    pub tested_revision: String,
}

impl MergeEvidence {
    /// A clean textual merge of `revision`.
    #[must_use]
    pub fn clean(revision: impl Into<String>) -> Self {
        Self {
            textual_merge_clean: true,
            conflicted_paths: Vec::new(),
            tested_revision: revision.into(),
        }
    }

    /// A merge that left conflicts.
    #[must_use]
    pub fn conflicted(revision: impl Into<String>, paths: Vec<String>) -> Self {
        Self {
            textual_merge_clean: false,
            conflicted_paths: paths,
            tested_revision: revision.into(),
        }
    }

    /// Whether the merge evidence is usable at all.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.textual_merge_clean && self.conflicted_paths.is_empty()
    }
}

/// One regeneration of the merged source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Regeneration {
    /// The catalog generation the regeneration produced or expects.
    pub generation_id: String,
    /// Per-project source fingerprints, keyed by project id.
    pub project_fingerprints: BTreeMap<String, String>,
    /// SHA-256 of the canonical checkpoint payload.
    pub checkpoint_sha256: String,
}

impl Regeneration {
    /// Build a regeneration record.
    #[must_use]
    pub fn new(
        generation_id: impl Into<String>,
        project_fingerprints: BTreeMap<String, String>,
        checkpoint_sha256: impl Into<String>,
    ) -> Self {
        Self {
            generation_id: generation_id.into(),
            project_fingerprints,
            checkpoint_sha256: checkpoint_sha256.into(),
        }
    }
}

/// Whether the tested checkpoint is still current.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerifyStatus {
    /// The regenerated payload matches the tracked checkpoint.
    Current,
    /// The tracked checkpoint must be regenerated.
    Stale,
}

impl VerifyStatus {
    /// Stable wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Stale => "stale",
        }
    }
}

/// The verdict of one CI verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyOutcome {
    /// Current or stale.
    pub status: VerifyStatus,
    /// The revision the regeneration ran against.
    pub tested_revision: String,
    /// The generation the tracked checkpoint records.
    pub expected_generation_id: String,
    /// The generation the regeneration produced.
    pub regenerated_generation_id: String,
    /// Project ids whose source fingerprint moved.
    pub mismatched_projects: Vec<String>,
    /// Stable reasons for a stale verdict.
    pub reasons: Vec<&'static str>,
    /// The instructions CI fails with.
    pub required_actions: Vec<String>,
}

impl VerifyOutcome {
    /// Whether the checkpoint is current.
    #[must_use]
    pub fn is_current(&self) -> bool {
        matches!(self.status, VerifyStatus::Current)
    }
}
/// Compare a regenerated payload against the tracked checkpoint.
///
/// # Errors
/// [`ErrorCode::NotFound`] with [`REASON_CHECKPOINT_MISSING`] when the tracked
/// checkpoint has no recorded payload digest.
pub fn verify(
    expected: &Regeneration,
    regenerated: &Regeneration,
    merge: &MergeEvidence,
) -> Result<VerifyOutcome, AxiomError> {
    if expected.checkpoint_sha256.len() != 64 {
        return Err(AxiomError::new(
            ErrorCode::NotFound,
            "no tracked checkpoint payload is available to compare against",
        )
        .with_detail("rule", REASON_CHECKPOINT_MISSING)
        .with_detail("tested_revision", merge.tested_revision.clone()));
    }
    let mut mismatched_projects: Vec<String> = Vec::new();
    let mut project_ids: Vec<&String> = expected.project_fingerprints.keys().collect();
    for project in regenerated.project_fingerprints.keys() {
        if !expected.project_fingerprints.contains_key(project) {
            project_ids.push(project);
        }
    }
    project_ids.sort();
    project_ids.dedup();
    for project in project_ids {
        let left = expected.project_fingerprints.get(project);
        let right = regenerated.project_fingerprints.get(project);
        if left != right {
            mismatched_projects.push(project.clone());
        }
    }
    let payload_matches = expected.checkpoint_sha256 == regenerated.checkpoint_sha256
        && expected.generation_id == regenerated.generation_id;
    let mut reasons: Vec<&'static str> = Vec::new();
    if !payload_matches || !mismatched_projects.is_empty() {
        reasons.push(REASON_STALE_SNAPSHOT);
        reasons.push(REASON_REGENERATE_REQUIRED);
        if !mismatched_projects.is_empty() {
            reasons.push(REASON_FINGERPRINT_MISMATCH);
        }
        // The exact trap section 4 warns about: Git said the merge was clean,
        // yet the regenerated graph no longer matches the tracked checkpoint.
        if merge.is_usable() {
            reasons.push(REASON_TEXTUAL_MERGE_INSUFFICIENT);
        }
    }
    if !merge.is_usable() {
        reasons.push(REASON_MERGE_CONFLICTED);
    }
    reasons.sort_unstable();
    reasons.dedup();
    let stale = !payload_matches || !mismatched_projects.is_empty();
    let mut required_actions = Vec::new();
    if stale {
        required_actions.push(format!(
            "regenerate the checkpoint from {} and commit the result",
            merge.tested_revision
        ));
        required_actions.push(
            "review the regenerated diff; do not resolve graph conflicts by choosing one side"
                .to_owned(),
        );
    } else if !merge.is_usable() {
        required_actions.push("resolve the remaining merge conflicts before verifying".to_owned());
    }
    Ok(VerifyOutcome {
        status: if stale {
            VerifyStatus::Stale
        } else {
            VerifyStatus::Current
        },
        tested_revision: merge.tested_revision.clone(),
        expected_generation_id: expected.generation_id.clone(),
        regenerated_generation_id: regenerated.generation_id.clone(),
        mismatched_projects,
        reasons,
        required_actions,
    })
}

/// Fail a CI step when the checkpoint is stale.
///
/// # Errors
/// [`ErrorCode::NotReady`] with [`REASON_STALE_SNAPSHOT`] and the regenerate
/// instructions, so the step exits `not ready/stale` (exit 4).
pub fn require_current(outcome: &VerifyOutcome) -> Result<(), AxiomError> {
    if outcome.is_current() {
        return Ok(());
    }
    Err(AxiomError::new(
        ErrorCode::NotReady,
        "the tracked checkpoint is stale against the tested merged source",
    )
    .with_detail("rule", REASON_STALE_SNAPSHOT)
    .with_detail("tested_revision", outcome.tested_revision.clone())
    .with_detail(
        "expected_generation_id",
        outcome.expected_generation_id.clone(),
    )
    .with_detail(
        "regenerated_generation_id",
        outcome.regenerated_generation_id.clone(),
    )
    .with_detail("actions", outcome.required_actions.join("; "))
    .with_retryable(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprints(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(project, digest)| ((*project).to_owned(), (*digest).to_owned()))
            .collect()
    }

    fn digest(seed: &str) -> String {
        graph_export::sha256_hex(seed.as_bytes())
    }

    fn expected() -> Regeneration {
        Regeneration::new(
            "gen-tracked",
            fingerprints(&[("auth-api", &digest("a")), ("auth-tests", &digest("b"))]),
            digest("checkpoint"),
        )
    }

    #[test]
    fn a_regenerated_payload_matching_the_checkpoint_is_current() {
        let outcome =
            verify(&expected(), &expected(), &MergeEvidence::clean("merge-sha")).expect("verify");
        assert!(outcome.is_current());
        assert_eq!(outcome.status, VerifyStatus::Current);
        assert!(outcome.reasons.is_empty());
        assert!(outcome.required_actions.is_empty());
        assert!(require_current(&outcome).is_ok());
    }

    #[test]
    fn a_clean_textual_merge_with_a_different_graph_is_stale() {
        let regenerated = Regeneration::new(
            "gen-tracked",
            fingerprints(&[
                ("auth-api", &digest("a")),
                ("auth-tests", &digest("CHANGED")),
            ]),
            digest("checkpoint"),
        );
        let outcome = verify(
            &expected(),
            &regenerated,
            &MergeEvidence::clean("merge-sha"),
        )
        .expect("verify");
        assert!(!outcome.is_current());
        assert_eq!(outcome.status, VerifyStatus::Stale);
        assert_eq!(outcome.mismatched_projects, vec!["auth-tests".to_owned()]);
        assert!(outcome.reasons.contains(&REASON_STALE_SNAPSHOT));
        assert!(outcome.reasons.contains(&REASON_REGENERATE_REQUIRED));
        assert!(outcome.reasons.contains(&REASON_FINGERPRINT_MISMATCH));
        // The named failure mode: Git said clean, the graph disagreed.
        assert!(outcome.reasons.contains(&REASON_TEXTUAL_MERGE_INSUFFICIENT));
        assert!(outcome
            .required_actions
            .iter()
            .any(|action| action.contains("regenerate the checkpoint")));
        let error = require_current(&outcome).expect_err("stale");
        assert_eq!(error.code(), ErrorCode::NotReady);
        assert_eq!(error.exit_code().as_i32(), 4);
        assert!(!error.retryable());
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_STALE_SNAPSHOT)
        );
    }

    #[test]
    fn a_differing_payload_digest_or_generation_is_stale_even_with_equal_fingerprints() {
        let other_digest = Regeneration::new(
            "gen-tracked",
            expected().project_fingerprints,
            digest("other"),
        );
        let outcome = verify(
            &expected(),
            &other_digest,
            &MergeEvidence::clean("merge-sha"),
        )
        .expect("verify");
        assert!(!outcome.is_current());
        assert!(outcome.mismatched_projects.is_empty());
        assert!(outcome.reasons.contains(&REASON_STALE_SNAPSHOT));

        let other_generation = Regeneration::new(
            "gen-other",
            expected().project_fingerprints,
            digest("checkpoint"),
        );
        let outcome = verify(
            &expected(),
            &other_generation,
            &MergeEvidence::clean("merge-sha"),
        )
        .expect("verify");
        assert!(!outcome.is_current());
    }

    #[test]
    fn a_conflicted_merge_is_never_reported_as_usable() {
        let evidence = MergeEvidence::conflicted("merge-sha", vec!["src/graph.json".to_owned()]);
        assert!(!evidence.is_usable());
        // An otherwise identical payload still cannot certify through conflicts.
        let outcome = verify(&expected(), &expected(), &evidence).expect("verify");
        assert!(outcome.is_current());
        assert!(outcome.reasons.contains(&REASON_MERGE_CONFLICTED));
        assert!(outcome
            .required_actions
            .iter()
            .any(|action| action.contains("resolve the remaining merge conflicts")));
    }

    #[test]
    fn a_missing_tracked_checkpoint_is_not_found() {
        let missing = Regeneration::new("gen-tracked", BTreeMap::new(), "not-a-digest");
        let error = verify(&missing, &expected(), &MergeEvidence::clean("merge-sha"))
            .expect_err("missing checkpoint");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_CHECKPOINT_MISSING)
        );
    }

    #[test]
    fn a_project_only_present_in_the_regeneration_is_a_mismatch() {
        let mut regenerated = expected();
        regenerated
            .project_fingerprints
            .insert("auth-new".to_owned(), digest("new"));
        let outcome = verify(
            &expected(),
            &regenerated,
            &MergeEvidence::clean("merge-sha"),
        )
        .expect("verify");
        assert!(!outcome.is_current());
        assert!(outcome.mismatched_projects.contains(&"auth-new".to_owned()));
    }
}
