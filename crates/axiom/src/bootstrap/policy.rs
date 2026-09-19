//! The separate managed policy file (task E-016).
//!
//! The managed block inside `AGENTS.md` is a pointer, not a policy: it is small
//! enough to review in a diff and it exists to tell the agent to read
//! [`POLICY_PATH`] before it touches source. The policy itself is a second owned
//! artifact with its own path, its own digest and its own failure modes, which
//! is what this module fixes.
//!
//! Two properties decide the outcome:
//!
//! 1. The block must actually instruct the agent to read the policy. A block
//!    that never names [`POLICY_PATH`], or names it without asking for it to be
//!    read, is refused with [`RULE_BLOCK_POINTER`] rather than written, because
//!    a pointer that does not point is worse than no pointer.
//! 2. An existing policy file is only ever the *managed* policy file when an
//!    ownership manifest says so. A repository that already has its own
//!    `.axiom/agent/POLICY.md` is never adopted - not even when its bytes are
//!    byte-identical to the shipped template - and never overwritten; bootstrap
//!    refuses with [`RULE_UNOWNED`] and leaves the file alone. The human override
//!    path is [`POLICY_LOCAL_PATH`], which bootstrap does not own at all.
//!
//! `docs/guides/bootstrap.md` states the same rule from the operator's side:
//! `conflict` always means refuse and preserve, and a whole-file policy edit is a
//! conflict because the policy is owned as a whole file rather than as a span.

use graph_core::error::AxiomError;

use super::refuse;

/// Directory bootstrap owns inside a repository.
pub const POLICY_DIR: &str = ".axiom/agent";

/// The canonical managed policy file, relative to a repository root.
pub const POLICY_PATH: &str = ".axiom/agent/POLICY.md";

/// The human override path. Bootstrap reads nothing here and owns nothing here.
pub const POLICY_LOCAL_PATH: &str = ".axiom/agent/POLICY.local.md";

/// The exact pointer the managed block must carry.
pub const POLICY_POINTER: &str = POLICY_PATH;

/// Prefix of the version line inside the policy file.
pub const VERSION_PREFIX: &str = "Managed policy version:";

/// Stable rule code: the managed block does not instruct reading the policy.
pub const RULE_BLOCK_POINTER: &str = "policy-pointer-missing";

/// Stable rule code: an existing policy file is not recorded as managed.
pub const RULE_UNOWNED: &str = "policy-unowned";

/// Stable rule code: the managed policy file was edited by a human.
pub const RULE_EDITED: &str = "policy-edited";

/// Stable rule code: the managed policy file was removed.
pub const RULE_REMOVED: &str = "policy-missing";

/// What an observed policy file means for this plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyVerdict {
    /// No manifest and no file: the managed policy is created.
    Create,
    /// The manifest owns the file and its bytes still match the recorded digest.
    Unchanged,
    /// The manifest owns the file, but its bytes differ: refuse and preserve.
    Edited,
    /// A file exists that no manifest records: never adopted, never overwritten.
    Unowned,
    /// The manifest owns the file, but the file is gone: refuse to recreate it.
    Removed,
}

impl PolicyVerdict {
    /// Stable, greppable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "policy-create",
            Self::Unchanged => "policy-unchanged",
            Self::Edited => RULE_EDITED,
            Self::Unowned => RULE_UNOWNED,
            Self::Removed => RULE_REMOVED,
        }
    }

    /// Whether this verdict refuses the repository.
    #[must_use]
    pub const fn is_conflict(self) -> bool {
        matches!(self, Self::Edited | Self::Unowned | Self::Removed)
    }

    /// The refusal for a conflicting verdict.
    #[must_use]
    pub fn refusal(self) -> Option<AxiomError> {
        if !self.is_conflict() {
            return None;
        }
        Some(
            refuse(self.as_str(), self.message())
                .with_detail("field", "policy")
                .with_detail("observed", self.as_str()),
        )
    }

    /// Human-readable message used in the plan report.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Create => "the managed policy file is created",
            Self::Unchanged => "the managed policy file already matches",
            Self::Edited => "the managed policy file was edited; refusing to overwrite it",
            Self::Unowned => {
                "an existing policy file is unowned; refusing to adopt or overwrite it"
            }
            Self::Removed => {
                "the managed policy file is missing although ownership records it; refusing to recreate it"
            }
        }
    }
}

/// What bootstrap will do with the managed policy file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Write the shipped policy bytes.
    Write,
    /// Leave the file exactly as it is.
    Leave,
}

/// Decide the verdict for the managed policy file of one repository.
///
/// `owned_sha256` is the digest recorded in the ownership manifest, or `None`
/// when this repository has no manifest entry for the policy. `observed_sha256`
/// is the digest of the bytes on disk, or `None` when the file is absent.
///
/// The unowned case is decided before the digest is looked at: a file that no
/// manifest records is not managed, however familiar its bytes look.
#[must_use]
pub fn verdict(observed_sha256: Option<&str>, owned_sha256: Option<&str>) -> PolicyVerdict {
    match (observed_sha256, owned_sha256) {
        (Some(_), None) => PolicyVerdict::Unowned,
        (None, None) => PolicyVerdict::Create,
        (None, Some(_)) => PolicyVerdict::Removed,
        (Some(observed), Some(owned)) if observed == owned => PolicyVerdict::Unchanged,
        (Some(_), Some(_)) => PolicyVerdict::Edited,
    }
}

/// Plan the managed policy file for one repository.
///
/// # Errors
///
/// Returns the refusal for a conflicting verdict: an unowned, edited or removed
/// policy file is never written over.
pub fn plan_policy(
    observed_sha256: Option<&str>,
    owned_sha256: Option<&str>,
) -> Result<PolicyAction, AxiomError> {
    let verdict = verdict(observed_sha256, owned_sha256);
    match verdict.refusal() {
        Some(refusal) => Err(refusal),
        None => Ok(match verdict {
            PolicyVerdict::Create => PolicyAction::Write,
            _ => PolicyAction::Leave,
        }),
    }
}

/// Whether a managed block instructs the agent to read the policy.
///
/// The block must name [`POLICY_POINTER`] and must ask for it to be *read*, so a
/// block that merely mentions the path in prose, or says `readme`, is not
/// accepted.
#[must_use]
pub fn block_points_at_policy(block: &str) -> bool {
    let lowered = block.to_lowercase();
    lowered.contains(&POLICY_POINTER.to_lowercase()) && contains_word(&lowered, "read")
}

/// Refuse a managed block that does not point at the policy.
///
/// # Errors
///
/// Returns a conflict carrying [`RULE_BLOCK_POINTER`].
pub fn ensure_block_points_at_policy(block: &str) -> Result<(), AxiomError> {
    if block_points_at_policy(block) {
        Ok(())
    } else {
        Err(AxiomError::new(
            graph_core::error::ErrorCode::Conflict,
            format!("the managed block must instruct reading {POLICY_POINTER}"),
        )
        .with_detail("rule", RULE_BLOCK_POINTER)
        .with_detail("field", "block")
        .with_detail("observed", "missing-policy-pointer"))
    }
}

/// The template version the policy file declares on its version line.
///
/// The ownership manifest records the version it wrote, so reading the version
/// back out of the file is what lets a later plan notice that the file on disk
/// belongs to another template generation.
#[must_use]
pub fn declared_version(policy: &str) -> Option<&str> {
    policy.lines().find_map(|line| {
        line.trim()
            .strip_prefix(VERSION_PREFIX)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

/// Whether `haystack` contains `word` as a whole ASCII word.
fn contains_word(haystack: &str, word: &str) -> bool {
    haystack
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| token == word)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::TEMPLATE_VERSION;
    use graph_core::error::ErrorCode;
    use graph_export::sha256_hex;

    fn corpus_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("bootstrap")
    }

    fn policy_template() -> String {
        std::fs::read_to_string(corpus_root().join("templates").join("POLICY.md"))
            .expect("policy template")
    }

    fn block_template() -> String {
        std::fs::read_to_string(corpus_root().join("templates").join("AGENTS.block.md"))
            .expect("block template")
    }

    fn rule_of(error: &AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    /// AC1 positive: the shipped block names the policy and asks for it to be
    /// read, and the shipped policy declares the template version.
    #[test]
    fn the_managed_block_instructs_reading_the_policy() {
        let block = block_template();
        assert!(block_points_at_policy(&block));
        assert!(ensure_block_points_at_policy(&block).is_ok());
        assert!(block.contains(POLICY_POINTER));

        let policy = policy_template();
        assert_eq!(declared_version(&policy), Some(TEMPLATE_VERSION));

        let unnamed = "# Axiom\nFollow the graph workflow.\n";
        let error = ensure_block_points_at_policy(unnamed).expect_err("no pointer");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(rule_of(&error), Some(RULE_BLOCK_POINTER));

        let mentioned_only = format!("This repository has a {POLICY_POINTER} file.\n");
        assert!(!block_points_at_policy(&mentioned_only));

        let readme_only = format!("See the {POLICY_POINTER} readme.\n");
        assert!(!block_points_at_policy(&readme_only));

        let spelled_differently = "EXPLICITLY READ `.AXIOM/AGENT/POLICY.MD` first.\n";
        assert!(block_points_at_policy(spelled_differently));
    }

    /// AC1 boundary: an existing policy file is unowned unless a manifest
    /// records it - even when its bytes are identical to the shipped template.
    #[test]
    fn an_unowned_policy_is_never_adopted_or_overwritten() {
        let template = policy_template();
        let observed = sha256_hex(template.as_bytes());

        let decided = verdict(Some(&observed), None);
        assert_eq!(decided, PolicyVerdict::Unowned);
        assert!(decided.is_conflict());

        let error = plan_policy(Some(&observed), None).expect_err("unowned is refused");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(rule_of(&error), Some(RULE_UNOWNED));
        assert!(
            error.message().contains("unowned"),
            "the refusal says unowned: {}",
            error.message()
        );
        assert_eq!(plan_policy(None, None), Ok(PolicyAction::Write));
        assert_eq!(
            plan_policy(Some(&observed), Some(&observed)),
            Ok(PolicyAction::Leave)
        );
    }

    /// AC1 negative: an edited or removed managed policy is a conflict, and a
    /// policy that still matches is left alone.
    #[test]
    fn an_edited_or_removed_managed_policy_is_refused() {
        let owned = sha256_hex(policy_template().as_bytes());
        let edited = sha256_hex(b"# Axiom Graph Policy\n\nI rewrote this by hand.\n");

        let decided = verdict(Some(&edited), Some(&owned));
        assert_eq!(decided, PolicyVerdict::Edited);
        let error = plan_policy(Some(&edited), Some(&owned)).expect_err("edited");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(rule_of(&error), Some(RULE_EDITED));
        assert!(error.message().contains("policy"), "{}", error.message());

        let error = plan_policy(None, Some(&owned)).expect_err("removed");
        assert_eq!(rule_of(&error), Some(RULE_REMOVED));
        assert!(error.message().contains("policy"), "{}", error.message());

        assert_eq!(
            verdict(Some(&owned), Some(&owned)),
            PolicyVerdict::Unchanged
        );
        assert_eq!(
            plan_policy(Some(&owned), Some(&owned)),
            Ok(PolicyAction::Leave)
        );
        assert_eq!(PolicyVerdict::Unchanged.refusal(), None);
    }

    /// AC2: the corpus is replayed through this module. The only refusals are
    /// the vectors whose contract reason is `unowned` or `policy`, and every
    /// other before-state plans a create or an unchanged policy.
    #[test]
    fn the_bootstrap_corpus_policy_vectors_match_this_planner() {
        let root = corpus_root();
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(root.join("vectors.json")).expect("vectors.json"),
        )
        .expect("parse vectors");
        let vectors = manifest["vectors"].as_array().expect("vectors array");

        let mut created = 0usize;
        let mut unchanged = 0usize;
        let mut refused = 0usize;
        for vector in vectors {
            let id = vector["id"].as_str().expect("id");
            let before = root.join("vectors").join(id).join("before");
            let policy = std::fs::read(before.join(".axiom").join("agent").join("POLICY.md")).ok();
            let lock = std::fs::read(
                before
                    .join(".axiom")
                    .join("agent")
                    .join("bootstrap.lock.json"),
            )
            .ok();
            let owned: Option<String> = lock.and_then(|bytes| {
                let parsed: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
                Some(parsed["policy_sha256"].as_str()?.to_owned())
            });
            let observed = policy.as_deref().map(sha256_hex);

            let planned = plan_policy(observed.as_deref(), owned.as_deref());
            match vector["reason_contains"].as_str() {
                Some(needle @ ("unowned" | "policy")) => {
                    let error = planned.expect_err(&format!("{id} must be refused"));
                    assert!(
                        error.message().contains(needle),
                        "{id}: refusal {:?} does not mention {needle:?}",
                        error.message()
                    );
                    if needle == "unowned" {
                        assert_eq!(rule_of(&error), Some(RULE_UNOWNED), "{id}");
                    } else {
                        assert!(
                            matches!(rule_of(&error), Some(RULE_EDITED | RULE_REMOVED)),
                            "{id}: {}",
                            error.message()
                        );
                    }
                    refused += 1;
                }
                _ => match planned {
                    Ok(PolicyAction::Write) => created += 1,
                    Ok(PolicyAction::Leave) => unchanged += 1,
                    Err(error) => panic!("{id} must not be refused: {error}"),
                },
            }
        }

        assert_eq!(refused, 3, "three corpus vectors are policy conflicts");
        assert_eq!(created, 9, "nine corpus before-states create the policy");
        assert_eq!(unchanged, 4, "four corpus before-states already match");
        assert_eq!(
            created + unchanged + refused,
            vectors.len(),
            "every corpus vector is classified"
        );
    }
}
