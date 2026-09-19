//! Optional, scoped commit proposals for bootstrap-owned paths (task E-024).
//!
//! `docs/18-BOOTSTRAP-AND-MANAGED-INSTRUCTIONS.md` section 6 is explicit:
//! bootstrap does not commit or push by default, `--commit`/`--push` are
//! explicit options that must be authorized for a repository, a branch and a
//! remote in the plan, the commit stage covers only owned changed paths, and a
//! repository with unrelated dirty files is planned but never stashed or
//! cleaned. This module is that boundary expressed as types:
//!
//! * [`CommitProposal`] is a sealed document that names *only* paths from
//!   [`COMMITTABLE_PATHS`] - the three managed artifacts of the update path plus
//!   the managed `.gitignore` span (E-023). A proposal that names anything else
//!   cannot be built and cannot be parsed back, so a later stage can never stage
//!   a human file by accident;
//! * [`CommitGrant`] is the separate, explicit authority. Staging happens under
//!   the plan; a commit needs `commit`, and a push needs `push` *and* an
//!   authorized remote and branch. Without the grant the executor is never asked
//!   to commit or push - which the tests assert by reading the call log;
//! * [`apply_commit`] re-verifies the proposal digest, the owned paths, the
//!   staged content and the secret scan at the moment of use, and stages exactly
//!   the proposal's paths, so an unrelated dirty file is left alone.
//!
//! Nothing here runs Git. The Git operations are an injected
//! [`GitExecutor`] boundary - program and argv, never an interpolated shell
//! string - and the production implementation is deliberately not part of this
//! bounded task; [`MemoryGitExecutor`] records the calls so the grant boundary
//! is testable.

use std::collections::BTreeSet;
use std::sync::Mutex;

use graph_core::error::AxiomError;
use graph_export::canonical::canonical_value;
use graph_export::sha256_hex;
use serde::{Deserialize, Serialize};

use super::gitignore::GITIGNORE_PATH;
use super::plan::AGENTS_PATH;
use super::policy::POLICY_PATH;
use super::{ownership, refuse};

/// Every repository-relative path bootstrap may propose to commit.
///
/// The first three entries are the managed artifacts the update path writes
/// ([`super::update::OWNED_PATHS`]); the last is the managed `.gitignore` span
/// planned by [`super::gitignore`]. No other path is committable, so a generated
/// graph checkpoint, a portable solution config or a human annotation is never
/// swept into a bootstrap commit.
pub const COMMITTABLE_PATHS: [&str; 4] = [
    super::update::OWNED_PATHS[0],
    super::update::OWNED_PATHS[1],
    super::update::OWNED_PATHS[2],
    GITIGNORE_PATH,
];

/// Stable rule code: the proposal document is not readable.
pub const RULE_COMMIT_MALFORMED: &str = "commit-plan-malformed";

/// Stable rule code: the proposal body no longer matches its recorded digest.
pub const RULE_COMMIT_DIGEST: &str = "commit-plan-digest-mismatch";

/// Stable rule code: a path is not a safe repository-relative path, or is named
/// twice.
pub const RULE_COMMIT_PATH: &str = "commit-path-unsafe";

/// Stable rule code: a path is safe but bootstrap does not own it.
pub const RULE_COMMIT_UNOWNED_PATH: &str = "commit-unowned-path";

/// Stable rule code: there is nothing to propose.
pub const RULE_COMMIT_EMPTY: &str = "commit-nothing-to-plan";

/// Stable rule code: staging or committing was requested without a grant.
pub const RULE_COMMIT_GRANT: &str = "commit-grant-required";

/// Stable rule code: planned content was not supplied for the commit stage.
pub const RULE_COMMIT_CONTENT: &str = "commit-content-missing";

/// Stable rule code: the content to be committed looks like a credential.
pub const RULE_COMMIT_SECRET: &str = "commit-secret-detected";

/// What a commit stage is not allowed to contain.
///
/// The scan is deliberately small and literal: it is a last-resort check on the
/// bytes bootstrap itself wrote, not a replacement for the export-side redaction
/// `docs/19-GIT-SNAPSHOTS-AND-MERGES.md` section 7 requires.
const SECRET_MARKERS: [&str; 6] = [
    "-----BEGIN",
    "PRIVATE KEY",
    "password=",
    "passwd=",
    "api_key=",
    "AWS_SECRET_ACCESS_KEY",
];

/// A sealed proposal to commit exactly the bootstrap-owned paths of one
/// repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitProposal {
    /// Stable identifier of the repository.
    pub repository_id: String,
    /// Display root of the repository.
    pub root: String,
    /// The owned paths to stage, sorted and unique.
    pub paths: Vec<String>,
    /// The commit message to use when a commit grant is later presented.
    pub message: String,
    /// Digest of the bootstrap plan this proposal came from, so a commit can be
    /// traced to the reviewed plan.
    pub plan_digest: String,
    /// SHA-256 over the canonical bytes of this document with `digest` empty.
    pub digest: String,
}

impl CommitProposal {
    /// Build and seal a proposal.
    ///
    /// # Errors
    ///
    /// Returns a conflict carrying [`RULE_COMMIT_EMPTY`] for an empty path set,
    /// [`RULE_COMMIT_PATH`] for an unsafe or repeated path and
    /// [`RULE_COMMIT_UNOWNED_PATH`] for a safe path bootstrap does not own.
    pub fn new(
        repository_id: impl Into<String>,
        root: impl Into<String>,
        paths: &[String],
        message: impl Into<String>,
        plan_digest: impl Into<String>,
    ) -> Result<Self, AxiomError> {
        let paths = checked_paths(paths)?;
        let mut proposal = Self {
            repository_id: repository_id.into(),
            root: root.into(),
            paths,
            message: message.into(),
            plan_digest: plan_digest.into(),
            digest: String::new(),
        };
        proposal.digest = proposal.compute_digest()?;
        Ok(proposal)
    }

    /// The canonical bytes of this proposal, with a trailing newline.
    ///
    /// # Errors
    ///
    /// Returns a conflict when the document cannot be encoded.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, AxiomError> {
        let mut bytes = self.encode_body()?.into_bytes();
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Parse a proposal and refuse one whose body no longer matches its digest.
    ///
    /// The owned-path check is repeated here, so a proposal that was edited on
    /// disk cannot smuggle an unowned path into the commit stage.
    ///
    /// # Errors
    ///
    /// Returns [`RULE_COMMIT_MALFORMED`], [`RULE_COMMIT_DIGEST`],
    /// [`RULE_COMMIT_PATH`] or [`RULE_COMMIT_UNOWNED_PATH`].
    pub fn parse(bytes: &[u8]) -> Result<Self, AxiomError> {
        let text = std::str::from_utf8(bytes).map_err(|error| {
            refuse(
                RULE_COMMIT_MALFORMED,
                format!("the commit proposal is not UTF-8: {error}"),
            )
        })?;
        let parsed: Self = serde_json::from_str(text).map_err(|error| {
            refuse(
                RULE_COMMIT_MALFORMED,
                format!("the commit proposal is malformed: {error}"),
            )
        })?;
        parsed.verify()?;
        Ok(parsed)
    }

    /// Re-check the digest and the owned-path property.
    ///
    /// # Errors
    ///
    /// Same refusals as [`CommitProposal::parse`].
    pub fn verify(&self) -> Result<(), AxiomError> {
        let expected = self.compute_digest()?;
        if self.digest != expected {
            return Err(refuse(
                RULE_COMMIT_DIGEST,
                "the commit proposal body does not match its recorded digest",
            )
            .with_detail("field", "digest")
            .with_detail("observed", self.digest.clone()));
        }
        checked_paths(&self.paths)?;
        Ok(())
    }

    /// Whether this proposal has nothing to stage.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    fn encode_body(&self) -> Result<String, AxiomError> {
        let value = serde_json::to_value(self).map_err(|error| {
            refuse(
                RULE_COMMIT_MALFORMED,
                format!("the commit proposal cannot be encoded: {error}"),
            )
        })?;
        canonical_value(&value).map_err(|error| refuse(RULE_COMMIT_MALFORMED, error.message))
    }

    fn compute_digest(&self) -> Result<String, AxiomError> {
        let mut bare = self.clone();
        bare.digest = String::new();
        Ok(sha256_hex(bare.encode_body()?.as_bytes()))
    }
}

/// Validate a proposed path set and return it sorted.
fn checked_paths(paths: &[String]) -> Result<Vec<String>, AxiomError> {
    if paths.is_empty() {
        return Err(refuse(
            RULE_COMMIT_EMPTY,
            "there is no bootstrap-owned change to propose",
        ));
    }
    let mut seen = BTreeSet::new();
    for path in paths {
        if !is_safe_relative(path) {
            return Err(refuse(
                RULE_COMMIT_PATH,
                format!("refusing the unsafe commit path {path}"),
            )
            .with_detail("field", "path")
            .with_detail("observed", path.as_str()));
        }
        if !COMMITTABLE_PATHS.contains(&path.as_str()) {
            return Err(refuse(
                RULE_COMMIT_UNOWNED_PATH,
                format!("refusing to commit the unowned path {path}"),
            )
            .with_detail("field", "path")
            .with_detail("observed", path.as_str()));
        }
        if !seen.insert(path.clone()) {
            return Err(refuse(
                RULE_COMMIT_PATH,
                format!("the commit path {path} is named more than once"),
            )
            .with_detail("field", "path")
            .with_detail("observed", path.as_str()));
        }
    }
    Ok(seen.into_iter().collect())
}

/// Whether `path` is a repository-relative path with no escape and no
/// platform-specific spelling.
#[must_use]
pub fn is_safe_relative(path: &str) -> bool {
    if path.is_empty() || path.ends_with('/') || path.contains('\\') {
        return false;
    }
    if path.starts_with('/') || path.contains(':') {
        return false;
    }
    !path
        .split('/')
        .any(|part| part.is_empty() || part == ".." || part == ".")
}

/// The explicit authority a commit or push needs.
///
/// The default is [`CommitGrant::none`]: a plan may be staged and reviewed but
/// no commit and no push happen without a separate grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitGrant {
    /// The repository this grant is for.
    pub repository_id: String,
    /// Whether the commit stage is authorized.
    pub commit: bool,
    /// Whether the push stage is authorized.
    pub push: bool,
    /// The authorized remote, required when `push` is set.
    pub remote: Option<String>,
    /// The authorized branch, required when `push` is set.
    pub branch: Option<String>,
}

impl CommitGrant {
    /// A grant that authorizes neither a commit nor a push.
    #[must_use]
    pub fn none(repository_id: impl Into<String>) -> Self {
        Self {
            repository_id: repository_id.into(),
            commit: false,
            push: false,
            remote: None,
            branch: None,
        }
    }

    /// Authorize the commit stage.
    #[must_use]
    pub fn with_commit(mut self) -> Self {
        self.commit = true;
        self
    }

    /// Authorize the commit and push stages, for one remote and one branch.
    #[must_use]
    pub fn with_push(mut self, remote: impl Into<String>, branch: impl Into<String>) -> Self {
        self.commit = true;
        self.push = true;
        self.remote = Some(remote.into());
        self.branch = Some(branch.into());
        self
    }

    /// Refuse a grant that does not match the proposal or is incomplete.
    ///
    /// # Errors
    ///
    /// Returns a conflict carrying [`RULE_COMMIT_GRANT`] when the grant names
    /// another repository, when a push is authorized without a remote and a
    /// branch, or when a push is authorized without the commit it depends on.
    pub fn authorize(&self, proposal: &CommitProposal) -> Result<(), AxiomError> {
        if self.repository_id != proposal.repository_id {
            return Err(refuse(
                RULE_COMMIT_GRANT,
                format!(
                    "the grant is for {} but the proposal is for {}",
                    self.repository_id, proposal.repository_id
                ),
            )
            .with_detail("field", "repository_id")
            .with_detail("observed", self.repository_id.as_str()));
        }
        if self.push && (!self.commit || self.remote.is_none() || self.branch.is_none()) {
            return Err(refuse(
                RULE_COMMIT_GRANT,
                "a push needs an authorized branch and remote in the same grant as the commit",
            )
            .with_detail("field", "push")
            .with_detail("observed", "incomplete-grant"));
        }
        Ok(())
    }
}

/// One Git operation a commit stage may request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitCall {
    /// Stage exactly these repository-relative paths.
    Stage {
        /// The repository root.
        root: String,
        /// The paths to stage.
        paths: Vec<String>,
    },
    /// Commit the staged paths.
    Commit {
        /// The repository root.
        root: String,
        /// The commit message.
        message: String,
    },
    /// Push one branch to one remote.
    Push {
        /// The repository root.
        root: String,
        /// The authorized remote.
        remote: String,
        /// The authorized branch.
        branch: String,
    },
}

/// The Git boundary a commit stage runs against.
///
/// Implementations receive a program-and-argv description of one operation;
/// nothing in this crate builds a shell string.
pub trait GitExecutor: std::fmt::Debug {
    /// Stage exactly `paths`; unrelated dirty files must not be included.
    ///
    /// # Errors
    ///
    /// Returns a conflict when the staging operation fails.
    fn stage(&self, root: &str, paths: &[String]) -> Result<(), AxiomError>;

    /// Commit the staged paths and return the new commit id.
    ///
    /// # Errors
    ///
    /// Returns a conflict when the commit fails.
    fn commit(&self, root: &str, message: &str) -> Result<String, AxiomError>;

    /// Push `branch` to `remote`.
    ///
    /// # Errors
    ///
    /// Returns a conflict when the push fails.
    fn push(&self, root: &str, remote: &str, branch: &str) -> Result<(), AxiomError>;
}

/// A recording executor for tests and for a caller that only wants a dry run.
#[derive(Debug, Default)]
pub struct MemoryGitExecutor {
    calls: Mutex<Vec<GitCall>>,
    commit_id: String,
}

impl MemoryGitExecutor {
    /// A recorder that reports `0000000` as the commit id.
    #[must_use]
    pub fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            commit_id: "0000000".to_owned(),
        }
    }

    /// A recorder that reports `commit_id` as the commit id.
    #[must_use]
    pub fn with_commit_id(commit_id: impl Into<String>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            commit_id: commit_id.into(),
        }
    }

    /// Every operation this executor was asked to perform, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<GitCall> {
        self.calls
            .lock()
            .expect("the call log is never poisoned")
            .clone()
    }

    /// How many operations of each kind the executor saw.
    #[must_use]
    pub fn count(&self, kind: fn(&GitCall) -> bool) -> usize {
        self.calls().iter().filter(|call| kind(call)).count()
    }
}

impl GitExecutor for MemoryGitExecutor {
    fn stage(&self, root: &str, paths: &[String]) -> Result<(), AxiomError> {
        self.calls
            .lock()
            .expect("the call log is never poisoned")
            .push(GitCall::Stage {
                root: root.to_owned(),
                paths: paths.to_vec(),
            });
        Ok(())
    }

    fn commit(&self, root: &str, message: &str) -> Result<String, AxiomError> {
        self.calls
            .lock()
            .expect("the call log is never poisoned")
            .push(GitCall::Commit {
                root: root.to_owned(),
                message: message.to_owned(),
            });
        Ok(self.commit_id.clone())
    }

    fn push(&self, root: &str, remote: &str, branch: &str) -> Result<(), AxiomError> {
        self.calls
            .lock()
            .expect("the call log is never poisoned")
            .push(GitCall::Push {
                root: root.to_owned(),
                remote: remote.to_owned(),
                branch: branch.to_owned(),
            });
        Ok(())
    }
}

/// One planned file's bytes, handed to the commit stage for the secret scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedFile {
    /// Repository-relative path.
    pub path: String,
    /// The exact bytes that would be committed.
    pub bytes: Vec<u8>,
}

impl StagedFile {
    /// Bind one planned file's bytes.
    #[must_use]
    pub fn new(path: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            bytes: bytes.into(),
        }
    }
}

/// What the commit stage did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// The owned paths are staged; no commit was authorized.
    Staged {
        /// The staged paths.
        paths: Vec<String>,
    },
    /// The owned paths are staged and committed; no push was authorized.
    Committed {
        /// The new commit id.
        commit: String,
        /// The committed paths.
        paths: Vec<String>,
    },
    /// The commit was pushed to its authorized remote and branch.
    Pushed {
        /// The new commit id.
        commit: String,
        /// The remote the commit was pushed to.
        remote: String,
        /// The branch the commit was pushed to.
        branch: String,
    },
}

impl CommitOutcome {
    /// Whether a commit was actually made.
    #[must_use]
    pub fn committed(&self) -> bool {
        !matches!(self, Self::Staged { .. })
    }

    /// Whether the commit was pushed.
    #[must_use]
    pub fn pushed(&self) -> bool {
        matches!(self, Self::Pushed { .. })
    }
}

/// Stage, and only if separately granted commit and push, one proposal.
///
/// # Errors
///
/// Returns the proposal refusals, [`RULE_COMMIT_GRANT`] for an unmatched or
/// incomplete grant, [`RULE_COMMIT_CONTENT`] when planned content is missing and
/// [`RULE_COMMIT_SECRET`] when the content looks like a credential. The grant is
/// checked before any executor call, so a refused grant performs nothing.
pub fn apply_commit(
    proposal: &CommitProposal,
    grant: &CommitGrant,
    staged: &[StagedFile],
    executor: &dyn GitExecutor,
) -> Result<CommitOutcome, AxiomError> {
    proposal.verify()?;
    grant.authorize(proposal)?;
    checked_content(proposal, staged)?;
    executor.stage(&proposal.root, &proposal.paths)?;
    if !grant.commit {
        return Ok(CommitOutcome::Staged {
            paths: proposal.paths.clone(),
        });
    }
    let commit = executor.commit(&proposal.root, &proposal.message)?;
    if !grant.push {
        return Ok(CommitOutcome::Committed {
            commit,
            paths: proposal.paths.clone(),
        });
    }
    let remote = grant.remote.clone().unwrap_or_default();
    let branch = grant.branch.clone().unwrap_or_default();
    executor.push(&proposal.root, &remote, &branch)?;
    Ok(CommitOutcome::Pushed {
        commit,
        remote,
        branch,
    })
}

/// Check that every planned path has content and that none of it looks secret.
fn checked_content(proposal: &CommitProposal, staged: &[StagedFile]) -> Result<(), AxiomError> {
    for path in &proposal.paths {
        let file = staged
            .iter()
            .find(|file| file.path == *path)
            .ok_or_else(|| {
                refuse(
                    RULE_COMMIT_CONTENT,
                    format!("no planned content was supplied for {path}"),
                )
                .with_detail("field", "path")
                .with_detail("observed", path.as_str())
            })?;
        if let Some(marker) = scan_secrets(&file.bytes) {
            return Err(refuse(
                RULE_COMMIT_SECRET,
                format!("refusing to commit {path}: it looks like a credential"),
            )
            .with_detail("field", "path")
            .with_detail("observed", marker));
        }
    }
    Ok(())
}

/// Scan bytes for the literal credential markers bootstrap refuses to commit.
#[must_use]
pub fn scan_secrets(bytes: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(bytes).to_lowercase();
    SECRET_MARKERS
        .into_iter()
        .find(|marker| text.contains(&marker.to_lowercase()))
}

/// Refuse a set of files when any of them looks like a credential.
///
/// # Errors
///
/// Returns a conflict carrying [`RULE_COMMIT_SECRET`].
pub fn ensure_no_secrets(staged: &[StagedFile]) -> Result<(), AxiomError> {
    for file in staged {
        if let Some(marker) = scan_secrets(&file.bytes) {
            return Err(refuse(
                RULE_COMMIT_SECRET,
                format!(
                    "refusing to commit {}: it looks like a credential",
                    file.path
                ),
            )
            .with_detail("field", "path")
            .with_detail("observed", marker));
        }
    }
    Ok(())
}

/// The path set the managed `AGENTS.md` block, policy and manifest occupy.
///
/// Re-exported so a caller can name the owned set without importing the plan
/// module's path constants separately.
pub const MANAGED_PATHS: [&str; 3] = super::update::OWNED_PATHS;

/// The managed policy path, named here for the tests and for reports.
pub const POLICY_FILE: &str = POLICY_PATH;

/// The managed pointer file, named here for the tests and for reports.
pub const AGENTS_FILE: &str = AGENTS_PATH;

/// The ownership manifest path, named here for the tests and for reports.
pub const OWNERSHIP_FILE: &str = ownership::OWNERSHIP_PATH;

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|path| (*path).to_owned()).collect()
    }

    /// A sealed proposal for exactly the owned `paths` of one repository.
    fn proposal(paths: &[&str]) -> CommitProposal {
        CommitProposal::new(
            "demo",
            "/repo/demo",
            &owned(paths),
            "chore(bootstrap): refresh managed policy",
            "plan-digest",
        )
        .expect("the proposal seals")
    }

    /// One body per committable path, so a positive run has real content.
    fn content() -> Vec<StagedFile> {
        COMMITTABLE_PATHS
            .into_iter()
            .map(|path| {
                let bytes = match path {
                    AGENTS_FILE => {
                        b"# Demo\n\n<!-- axiom-graph:begin -->\n<!-- axiom-graph:end -->\n".to_vec()
                    }
                    POLICY_FILE => {
                        b"# Axiom managed policy\n\nManaged policy version: 2.0.0-draft.1\n"
                            .to_vec()
                    }
                    OWNERSHIP_FILE => b"{\"schema_version\":2}\n".to_vec(),
                    _ => b"# managed ignores\n".to_vec(),
                };
                StagedFile::new(path, bytes)
            })
            .collect()
    }

    /// The digest the sealed document records over its own body.
    fn seal(proposal: &CommitProposal) -> String {
        let mut bare = proposal.clone();
        bare.digest = String::new();
        let value = serde_json::to_value(&bare).expect("the body encodes");
        sha256_hex(
            canonical_value(&value)
                .expect("the body canonicalises")
                .as_bytes(),
        )
    }

    fn rule_of(error: &AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    /// AC1: a proposal names only bootstrap-owned paths and refuses every other
    /// path, so a later stage can never stage a human file by accident.
    #[test]
    fn a_proposal_lists_only_the_owned_paths() {
        let all = proposal(&COMMITTABLE_PATHS);
        assert!(!all.is_empty());
        assert_eq!(all.paths.len(), COMMITTABLE_PATHS.len());
        assert_eq!(all.digest.len(), 64);
        let mut sorted = all.paths.clone();
        sorted.sort();
        assert_eq!(all.paths, sorted, "the path set is sorted and unique");
        for path in &all.paths {
            assert!(
                MANAGED_PATHS.contains(&path.as_str()) || path == GITIGNORE_PATH,
                "unowned path in the proposal: {path}"
            );
        }

        let bytes = all.to_canonical_bytes().expect("the proposal encodes");
        assert!(bytes.ends_with(b"\n"));
        assert_eq!(CommitProposal::parse(&bytes).expect("round-trips"), all);

        // Negative: a legal repository path bootstrap does not own is refused.
        let error = CommitProposal::new("demo", "/repo/demo", &owned(&["src/main.rs"]), "m", "d")
            .expect_err("an unowned path is refused");
        assert_eq!(rule_of(&error), Some(RULE_COMMIT_UNOWNED_PATH));

        // Negative: escaping, absolute and repeated paths are refused, and an
        // empty path set has nothing to propose.
        for unsafe_path in ["../POLICY.md", "/etc/passwd", ".axiom\\agent\\POLICY.md"] {
            let error = CommitProposal::new("demo", "/repo/demo", &owned(&[unsafe_path]), "m", "d")
                .expect_err(unsafe_path);
            assert_eq!(rule_of(&error), Some(RULE_COMMIT_PATH), "{unsafe_path}");
        }
        let error = CommitProposal::new(
            "demo",
            "/repo/demo",
            &owned(&[POLICY_FILE, POLICY_FILE]),
            "m",
            "d",
        )
        .expect_err("a repeated path is refused");
        assert_eq!(rule_of(&error), Some(RULE_COMMIT_PATH));
        let error =
            CommitProposal::new("demo", "/repo/demo", &[], "m", "d").expect_err("nothing to plan");
        assert_eq!(rule_of(&error), Some(RULE_COMMIT_EMPTY));
    }

    /// AC1 boundary: staging is part of the plan, and without a separate grant
    /// the executor is never asked to commit or push, so a bootstrap apply
    /// cannot publish on its own.
    #[test]
    fn staging_needs_no_grant_but_commit_and_push_do() {
        let files = content();
        let proposal = proposal(&COMMITTABLE_PATHS);
        let executor = MemoryGitExecutor::new();
        let outcome = apply_commit(&proposal, &CommitGrant::none("demo"), &files, &executor)
            .expect("staging is allowed without a commit grant");

        assert_eq!(
            outcome,
            CommitOutcome::Staged {
                paths: proposal.paths.clone()
            }
        );
        assert!(!outcome.committed());
        assert!(!outcome.pushed());
        assert_eq!(
            executor.count(|call| matches!(call, GitCall::Stage { .. })),
            1
        );
        assert_eq!(
            executor.count(|call| matches!(call, GitCall::Commit { .. })),
            0
        );
        assert_eq!(
            executor.count(|call| matches!(call, GitCall::Push { .. })),
            0
        );

        // The staged set is exactly the proposal's owned paths: an unrelated
        // dirty file is never swept into a bootstrap commit.
        let calls = executor.calls();
        let GitCall::Stage { root, paths } = &calls[0] else {
            panic!("expected a stage call, got {:?}", calls[0]);
        };
        assert_eq!(root, "/repo/demo");
        assert_eq!(paths, &proposal.paths);
    }

    /// AC2: a commit grant commits but still pushes nothing, and a push needs a
    /// grant that names the authorized remote and branch.
    #[test]
    fn a_commit_grant_commits_and_a_push_grant_names_one_remote() {
        let files = content();
        let proposal = proposal(&COMMITTABLE_PATHS);

        let executor = MemoryGitExecutor::with_commit_id("abc1234");
        let outcome = apply_commit(
            &proposal,
            &CommitGrant::none("demo").with_commit(),
            &files,
            &executor,
        )
        .expect("a commit grant commits");
        assert_eq!(
            outcome,
            CommitOutcome::Committed {
                commit: "abc1234".to_owned(),
                paths: proposal.paths.clone(),
            }
        );
        assert!(outcome.committed());
        assert!(!outcome.pushed());
        assert_eq!(
            executor.count(|call| matches!(call, GitCall::Commit { .. })),
            1
        );
        assert_eq!(
            executor.count(|call| matches!(call, GitCall::Push { .. })),
            0,
            "a commit grant is not a push grant"
        );

        let executor = MemoryGitExecutor::with_commit_id("abc1234");
        let outcome = apply_commit(
            &proposal,
            &CommitGrant::none("demo").with_push("origin", "feature/bootstrap"),
            &files,
            &executor,
        )
        .expect("a push grant pushes");
        assert_eq!(
            outcome,
            CommitOutcome::Pushed {
                commit: "abc1234".to_owned(),
                remote: "origin".to_owned(),
                branch: "feature/bootstrap".to_owned(),
            }
        );
        let pushes: Vec<GitCall> = executor
            .calls()
            .into_iter()
            .filter(|call| matches!(call, GitCall::Push { .. }))
            .collect();
        assert_eq!(
            pushes,
            vec![GitCall::Push {
                root: "/repo/demo".to_owned(),
                remote: "origin".to_owned(),
                branch: "feature/bootstrap".to_owned(),
            }]
        );
    }

    /// AC2 negative: an incomplete or foreign grant is refused before any
    /// executor call, so a half-specified push can never reach Git.
    #[test]
    fn an_incomplete_or_foreign_grant_performs_nothing() {
        let files = content();
        let proposal = proposal(&COMMITTABLE_PATHS);

        let incomplete = CommitGrant {
            repository_id: "demo".to_owned(),
            commit: false,
            push: true,
            remote: Some("origin".to_owned()),
            branch: None,
        };
        let executor = MemoryGitExecutor::new();
        let error = apply_commit(&proposal, &incomplete, &files, &executor)
            .expect_err("a push without a branch is refused");
        assert_eq!(rule_of(&error), Some(RULE_COMMIT_GRANT));
        assert!(executor.calls().is_empty());

        let executor = MemoryGitExecutor::new();
        let error = apply_commit(
            &proposal,
            &CommitGrant::none("other-repository").with_commit(),
            &files,
            &executor,
        )
        .expect_err("a grant for another repository is refused");
        assert_eq!(rule_of(&error), Some(RULE_COMMIT_GRANT));
        assert!(executor.calls().is_empty());
    }

    /// AC2 negative: a proposal edited after it was sealed is refused, and an
    /// unowned path cannot be smuggled in even with a recomputed digest.
    #[test]
    fn a_tampered_proposal_is_refused() {
        let sealed = proposal(&COMMITTABLE_PATHS);
        let bytes = sealed.to_canonical_bytes().expect("the proposal encodes");
        let tampered = String::from_utf8(bytes)
            .expect("UTF-8")
            .replace("refresh managed policy", "refresh managedEDITED policy");
        let error = CommitProposal::parse(tampered.as_bytes()).expect_err("digest mismatch");
        assert_eq!(rule_of(&error), Some(RULE_COMMIT_DIGEST));

        let mut forged = sealed.clone();
        forged.paths = owned(&["src/main.rs"]);
        forged.digest = seal(&forged);
        let error = forged.verify().expect_err("an unowned path is refused");
        assert_eq!(rule_of(&error), Some(RULE_COMMIT_UNOWNED_PATH));
        let document = serde_json::to_vec(&forged).expect("the forged body encodes");
        let error = CommitProposal::parse(&document).expect_err("an unowned path is refused");
        assert_eq!(rule_of(&error), Some(RULE_COMMIT_UNOWNED_PATH));
    }

    /// AC2 boundary: a missing body or a credential-looking body is refused
    /// before any Git call, so the commit stage cannot publish a secret.
    #[test]
    fn missing_or_secret_content_is_refused_before_any_git_call() {
        let proposal = proposal(&COMMITTABLE_PATHS);
        let executor = MemoryGitExecutor::new();
        let missing: Vec<StagedFile> = content()
            .into_iter()
            .filter(|file| file.path != POLICY_FILE)
            .collect();
        let error = apply_commit(&proposal, &CommitGrant::none("demo"), &missing, &executor)
            .expect_err("missing content is refused");
        assert_eq!(rule_of(&error), Some(RULE_COMMIT_CONTENT));
        assert!(executor.calls().is_empty());

        let secret: Vec<StagedFile> = content()
            .into_iter()
            .map(|file| {
                if file.path == POLICY_FILE {
                    StagedFile::new(POLICY_FILE, b"api_key=abcd1234\n".to_vec())
                } else {
                    file
                }
            })
            .collect();
        let executor = MemoryGitExecutor::new();
        let error = apply_commit(&proposal, &CommitGrant::none("demo"), &secret, &executor)
            .expect_err("a secret is refused");
        assert_eq!(rule_of(&error), Some(RULE_COMMIT_SECRET));
        assert!(executor.calls().is_empty());

        assert_eq!(
            scan_secrets(b"-----BEGIN TEST MATERIAL-----"),
            Some("-----BEGIN")
        );
        assert_eq!(scan_secrets(b"# Axiom managed policy\n"), None);
        let error =
            ensure_no_secrets(&[StagedFile::new("AGENTS.md", b"password=hunter2".to_vec())])
                .expect_err("a secret is refused");
        assert_eq!(rule_of(&error), Some(RULE_COMMIT_SECRET));
    }

    /// Boundary: the relative-path predicate accepts the owned spellings and
    /// refuses escapes and platform-specific spellings.
    #[test]
    fn the_relative_path_predicate_is_strict() {
        for good in [
            AGENTS_FILE,
            POLICY_FILE,
            OWNERSHIP_FILE,
            GITIGNORE_PATH,
            "docs/guides/bootstrap.md",
        ] {
            assert!(is_safe_relative(good), "{good} must be a safe path");
        }
        for bad in [
            "",
            "/etc/passwd",
            "C:\\repo\\AGENTS.md",
            "../AGENTS.md",
            "a//b",
            "docs/",
            "./AGENTS.md",
        ] {
            assert!(!is_safe_relative(bad), "{bad} must be refused");
        }
    }
}
