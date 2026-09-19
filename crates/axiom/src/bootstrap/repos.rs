//! Discover the approved repository set of a solution (task E-013).
//!
//! Bootstrap rewrites `AGENTS.md` inside a repository, so the set of
//! repositories it may touch cannot be guessed. `docs/18-BOOTSTRAP-AND-MANAGED-
//! INSTRUCTIONS.md` section 3 states the rule this module implements: the plan
//! reads an *explicit registered solution*, and "no auto discovery rewrite all
//! HOME repositories". A catalog `repo_id` is not a path either
//! (`graph_core::bindings`), so the caller must supply the absolute root.
//!
//! This module is therefore an admission check over explicitly declared
//! bindings, and it is deliberately strict about substitution:
//!
//! * a declared binding whose root does not exist, is not a directory, or
//!   cannot be read is **rejected**, never quietly pointed at a neighbour;
//! * a root whose directory name is not the declared repository name is
//!   **rejected** even when it is a sibling of a correctly named checkout, so
//!   `axiom-graphd-old` can never stand in for `axiom-graphd`;
//! * a root whose Git origin is not the declared canonical remote is
//!   **rejected**, so a fork or an unrelated repository with the same name is
//!   not silently adopted;
//! * a relative root, a root containing `..`, a duplicated id or a duplicated
//!   root is **rejected** before anything is read.
//!
//! Observed state enters through [`RepoProbe`] so the policy is testable
//! without a host, and [`LocalRepoProbe`] is the one real adapter: it reads
//! metadata and `.git/config` and nothing else. It never writes.

use std::collections::BTreeMap;
use std::path::Path;

use graph_core::error::AxiomError;
use graph_core::paths::is_absolute_host_path;
use serde::{Deserialize, Serialize};

use super::{refuse, refuse_field};

/// Upper bound on declared repositories in one solution.
///
/// The installer binds at most a handful of repositories; a document that
/// claims thousands is a mistake or an attack, and refuse rather than read.
pub const MAX_BOUND_REPOSITORIES: usize = 1024;

/// Rule: the declared root does not exist.
pub const RULE_ABSENT: &str = "repository-absent";
/// Rule: the declared root exists but is not a directory.
pub const RULE_NOT_A_DIRECTORY: &str = "repository-not-a-directory";
/// Rule: the declared root could not be read (for example denied by ACL).
pub const RULE_INACCESSIBLE: &str = "repository-inaccessible";
/// Rule: the directory name differs from the declared repository name.
pub const RULE_NAME_MISMATCH: &str = "repository-name-mismatch";
/// Rule: the observed origin differs from the expected canonical remote.
pub const RULE_REMOTE_MISMATCH: &str = "repository-remote-mismatch";
/// Rule: the declared root is not an absolute, `..`-free path.
pub const RULE_UNSAFE_ROOT: &str = "repository-root-unsafe";
/// Rule: two declared bindings resolve to the same root.
pub const RULE_DUPLICATE_ROOT: &str = "repository-root-duplicate";
/// Rule: two declared bindings carry the same repository id.
pub const RULE_DUPLICATE_ID: &str = "repository-id-duplicate";
/// Rule: the solution declared no repository at all.
pub const RULE_EMPTY_SOLUTION: &str = "solution-has-no-repositories";
/// Rule: every declared repository was rejected, so there is nothing to plan.
pub const RULE_NOTHING_APPROVED: &str = "solution-has-no-approved-repository";

/// One explicitly declared repository of a solution.
///
/// `name` is the repository directory name the caller expects this root to be
/// (for example `axiom-graphd`), and `remote` is the canonical origin the
/// caller expects that repository to have. Both are admission criteria, not
/// hints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryBinding {
    /// Stable repository id from the solution document.
    pub repo_id: String,
    /// Expected repository directory name.
    pub name: String,
    /// Explicit absolute host root of the checkout.
    pub root: String,
    /// Expected canonical Git origin, when the solution pins one.
    #[serde(default)]
    pub remote: Option<String>,
}

impl RepositoryBinding {
    /// Bind `repo_id` to the absolute `root` named `name`.
    #[must_use]
    pub fn new(
        repo_id: impl Into<String>,
        name: impl Into<String>,
        root: impl Into<String>,
    ) -> Self {
        Self {
            repo_id: repo_id.into(),
            name: name.into(),
            root: root.into(),
            remote: None,
        }
    }

    /// Require the bound checkout to have this canonical origin.
    #[must_use]
    pub fn with_remote(mut self, remote: impl Into<String>) -> Self {
        self.remote = Some(remote.into());
        self
    }
}

/// A solution's explicit repository bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolutionRequest {
    /// Solution id the bindings belong to.
    pub solution_id: String,
    /// Explicitly declared repositories, in declaration order.
    pub bindings: Vec<RepositoryBinding>,
}

impl SolutionRequest {
    /// Build a request from explicit bindings.
    #[must_use]
    pub fn new(solution_id: impl Into<String>, bindings: Vec<RepositoryBinding>) -> Self {
        Self {
            solution_id: solution_id.into(),
            bindings,
        }
    }
}

/// What a probe observed about one declared root.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RepoObservation {
    /// Whether anything exists at the root path.
    pub exists: bool,
    /// Whether the root is a directory.
    pub is_dir: bool,
    /// Directory name observed at the root, when it could be read.
    pub directory_name: Option<String>,
    /// Canonical `origin` remote observed in the checkout, when present.
    pub remote: Option<String>,
    /// Why the root could not be read, when it could not.
    pub unreadable_reason: Option<String>,
}

impl RepoObservation {
    /// Nothing exists at the declared root.
    #[must_use]
    pub fn absent() -> Self {
        Self::default()
    }

    /// A readable directory named `name` with an optional origin.
    #[must_use]
    pub fn directory(name: impl Into<String>, remote: Option<String>) -> Self {
        Self {
            exists: true,
            is_dir: true,
            directory_name: Some(name.into()),
            remote,
            unreadable_reason: None,
        }
    }

    /// A root that exists but could not be read.
    #[must_use]
    pub fn inaccessible(reason: impl Into<String>) -> Self {
        Self {
            exists: true,
            is_dir: false,
            directory_name: None,
            remote: None,
            unreadable_reason: Some(reason.into()),
        }
    }
}

/// Host observation for one declared root, injected so the policy is testable.
pub trait RepoProbe {
    /// Observe the declared absolute `root` without changing anything.
    fn observe(&self, root: &str) -> RepoObservation;
}

/// An approved binding: the declared root passed every admission check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedRepository {
    /// Declared repository id.
    pub repo_id: String,
    /// Declared and observed directory name.
    pub name: String,
    /// Explicit absolute root.
    pub root: String,
    /// Observed canonical origin, when the checkout has one.
    pub remote: Option<String>,
}

impl ApprovedRepository {
    /// Declared repository id.
    #[must_use]
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    /// Approved absolute root.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }
}

/// A declared binding that was refused, with the rule that refused it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedRepository {
    /// Declared repository id.
    pub repo_id: String,
    /// Declared directory name.
    pub name: String,
    /// Declared root.
    pub root: String,
    /// Stable rule code for the refusal.
    pub rule: String,
    /// Human-readable reason.
    pub reason: String,
}

/// The approved and rejected halves of one discovery run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedSet {
    /// Solution the bindings were declared by.
    pub solution_id: String,
    /// Repositories that passed every admission check, in declaration order.
    pub approved: Vec<ApprovedRepository>,
    /// Repositories that were refused, in declaration order.
    pub rejected: Vec<RejectedRepository>,
}

impl ApprovedSet {
    /// Approved repositories.
    #[must_use]
    pub fn approved(&self) -> &[ApprovedRepository] {
        &self.approved
    }

    /// Rejected repositories.
    #[must_use]
    pub fn rejected(&self) -> &[RejectedRepository] {
        &self.rejected
    }

    /// Whether every declared repository was approved.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.rejected.is_empty()
    }

    /// Refuse a set that cannot be planned at all.
    ///
    /// A partial set is *not* an error: the unaffected repositories proceed and
    /// the rejected ones are reported, exactly like the per-repository apply
    /// outcome. A set with nothing approved has nothing to plan, so it is a
    /// refusal rather than an empty plan.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::Conflict`](graph_core::error::ErrorCode::Conflict)
    /// with rule [`RULE_NOTHING_APPROVED`] when no repository was approved.
    pub fn validate(&self) -> Result<(), AxiomError> {
        if self.approved.is_empty() {
            return Err(refuse(
                RULE_NOTHING_APPROVED,
                "no declared repository passed the admission checks",
            )
            .with_detail("solution_id", self.solution_id.clone())
            .with_detail("rejected", self.rejected.len().to_string()));
        }
        Ok(())
    }
}

/// Refuse a root that is not an absolute, `..`-free host path.
fn root_is_safe(root: &str) -> bool {
    if !is_absolute_host_path(root) {
        return false;
    }
    !root.split(['/', '\\']).any(|segment| segment == "..")
}

/// Normalize an origin for comparison: drop a trailing slash and a trailing
/// `.git`, and compare case-insensitively.
#[must_use]
pub fn normalize_remote(remote: &str) -> String {
    let trimmed = remote.trim().trim_end_matches('/');
    let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    trimmed.to_ascii_lowercase()
}

/// Whether an observed origin satisfies an expected canonical remote.
#[must_use]
pub fn remote_satisfies(expected: &str, observed: Option<&str>) -> bool {
    match observed {
        Some(observed) => normalize_remote(expected) == normalize_remote(observed),
        None => false,
    }
}

/// Decide one binding against the observation.
fn judge(binding: &RepositoryBinding, observed: &RepoObservation) -> Result<(), (String, String)> {
    if let Some(reason) = observed.unreadable_reason.as_deref() {
        return Err((
            RULE_INACCESSIBLE.to_owned(),
            format!("{} could not be read: {reason}", binding.root),
        ));
    }
    if !observed.exists {
        return Err((
            RULE_ABSENT.to_owned(),
            format!("the declared root {} does not exist", binding.root),
        ));
    }
    if !observed.is_dir {
        return Err((
            RULE_NOT_A_DIRECTORY.to_owned(),
            format!("the declared root {} is not a directory", binding.root),
        ));
    }
    match observed.directory_name.as_deref() {
        Some(name) if name == binding.name => {}
        Some(name) => {
            return Err((
                RULE_NAME_MISMATCH.to_owned(),
                format!(
                    "the declared root {} holds {name}, not {}; a similarly named repository is not substituted",
                    binding.root, binding.name
                ),
            ));
        }
        None => {
            return Err((
                RULE_NAME_MISMATCH.to_owned(),
                format!(
                    "the declared root {} has no readable directory name",
                    binding.root
                ),
            ));
        }
    }
    if let Some(expected) = binding.remote.as_deref() {
        if !remote_satisfies(expected, observed.remote.as_deref()) {
            return Err((
                RULE_REMOTE_MISMATCH.to_owned(),
                format!(
                    "{} does not have the canonical origin {expected}",
                    binding.root
                ),
            ));
        }
    }
    Ok(())
}

/// Discover the approved repository set of `request` through `probe`.
///
/// The result keeps the declaration order and reports every refusal with its
/// rule; it never substitutes a similar repository for a declared one.
///
/// # Errors
///
/// Returns a conflict when the solution declares no repository, when it
/// declares more than [`MAX_BOUND_REPOSITORIES`], or when a declared root, id
/// or repository name is unusable. Per-repository refusals are results, not
/// errors, so a partial set is reported rather than thrown away.
pub fn discover_approved_set(
    request: &SolutionRequest,
    probe: &dyn RepoProbe,
) -> Result<ApprovedSet, AxiomError> {
    if request.bindings.is_empty() {
        return Err(refuse(
            RULE_EMPTY_SOLUTION,
            "the solution declares no repository to bootstrap",
        )
        .with_detail("solution_id", request.solution_id.clone()));
    }
    if request.bindings.len() > MAX_BOUND_REPOSITORIES {
        return Err(refuse_field(
            RULE_UNSAFE_ROOT,
            "bindings",
            &request.bindings.len().to_string(),
        ));
    }

    let mut approved = Vec::new();
    let mut rejected = Vec::new();
    let mut seen_roots: BTreeMap<String, String> = BTreeMap::new();
    let mut seen_ids: BTreeMap<String, String> = BTreeMap::new();

    for binding in &request.bindings {
        let rule_reason = if let Some(previous) = seen_ids.get(&binding.repo_id) {
            Some((
                RULE_DUPLICATE_ID.to_owned(),
                format!("{} is declared twice (also as {previous})", binding.repo_id),
            ))
        } else if !root_is_safe(&binding.root) {
            Some((
                RULE_UNSAFE_ROOT.to_owned(),
                format!("{} is not an absolute, ..-free host path", binding.root),
            ))
        } else {
            seen_roots
                .get(&binding.root.to_ascii_lowercase())
                .map(|previous| {
                    (
                        RULE_DUPLICATE_ROOT.to_owned(),
                        format!("{} is already bound as {previous}", binding.root),
                    )
                })
        };
        if let Some((rule, reason)) = rule_reason {
            rejected.push(RejectedRepository {
                repo_id: binding.repo_id.clone(),
                name: binding.name.clone(),
                root: binding.root.clone(),
                rule,
                reason,
            });
            continue;
        }

        seen_ids.insert(binding.repo_id.clone(), binding.root.clone());
        seen_roots.insert(binding.root.to_ascii_lowercase(), binding.repo_id.clone());

        let observed = probe.observe(&binding.root);
        match judge(binding, &observed) {
            Ok(()) => approved.push(ApprovedRepository {
                repo_id: binding.repo_id.clone(),
                name: binding.name.clone(),
                root: binding.root.clone(),
                remote: observed.remote,
            }),
            Err((rule, reason)) => rejected.push(RejectedRepository {
                repo_id: binding.repo_id.clone(),
                name: binding.name.clone(),
                root: binding.root.clone(),
                rule,
                reason,
            }),
        }
    }

    Ok(ApprovedSet {
        solution_id: request.solution_id.clone(),
        approved,
        rejected,
    })
}

/// The one real probe: `symlink_metadata`/`metadata` plus a read of
/// `.git/config`. It never writes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocalRepoProbe;

impl RepoProbe for LocalRepoProbe {
    fn observe(&self, root: &str) -> RepoObservation {
        let path = Path::new(root);
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_dir() => {
                RepoObservation::directory(directory_name(path), read_origin_remote(path))
            }
            Ok(_) => RepoObservation {
                exists: true,
                is_dir: false,
                directory_name: path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned()),
                remote: None,
                unreadable_reason: None,
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => RepoObservation::absent(),
            Err(error) => RepoObservation::inaccessible(error.to_string()),
        }
    }
}

fn directory_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Read the canonical `origin` URL of a checkout, following a `.git` file
/// (worktree) as well as a `.git` directory.
///
/// Returns `None` when the checkout has no readable origin; an absent remote is
/// not an error here, because a solution that does not pin a remote does not
/// require one.
#[must_use]
pub fn read_origin_remote(root: &Path) -> Option<String> {
    let dot_git = root.join(".git");
    let config_path = if dot_git.is_dir() {
        dot_git.join("config")
    } else {
        let pointer = std::fs::read_to_string(&dot_git).ok()?;
        let gitdir = pointer
            .lines()
            .find_map(|line| line.trim().strip_prefix("gitdir:"))?
            .trim();
        let gitdir = if Path::new(gitdir).is_absolute() {
            std::path::PathBuf::from(gitdir)
        } else {
            root.join(gitdir)
        };
        let common = gitdir.join("commondir");
        match std::fs::read_to_string(&common) {
            Ok(text) => {
                let relative = text.trim();
                let common_dir = if Path::new(relative).is_absolute() {
                    std::path::PathBuf::from(relative)
                } else {
                    gitdir.join(relative)
                };
                common_dir.join("config")
            }
            Err(_) => gitdir.join("..").join("..").join("config"),
        }
    };
    parse_origin_remote(&std::fs::read_to_string(config_path).ok()?)
}

/// Parse the `origin` URL out of a Git config body.
#[must_use]
pub fn parse_origin_remote(config: &str) -> Option<String> {
    let mut in_origin = false;
    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_origin = trimmed == "[remote \"origin\"]";
            continue;
        }
        if !in_origin {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("url") {
            let value = rest.trim_start_matches([' ', '=', '\t']).trim();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn write_checkout(root: &Path, remote: &str) {
        fs::create_dir_all(root.join(".git")).expect("create .git");
        fs::write(
            root.join(".git").join("config"),
            format!("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = {remote}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"),
        )
        .expect("write config");
    }

    /// AC1 positive: explicitly bound, correctly named, accessible repositories
    /// with the expected origin are approved.
    #[test]
    fn explicit_bindings_with_matching_identity_are_approved() {
        let temp = tempfile::tempdir().expect("tempdir");
        let graphd = temp.path().join("axiom-graphd");
        let mcp = temp.path().join("axiom-mcp");
        write_checkout(&graphd, "https://github.com/orchex006/axiom-graphd.git");
        write_checkout(&mcp, "https://github.com/orchex006/axiom-mcp.git");

        let request = SolutionRequest::new(
            "axiom-main",
            vec![
                RepositoryBinding::new("graphd", "axiom-graphd", graphd.display().to_string())
                    .with_remote("https://github.com/orchex006/axiom-graphd.git"),
                RepositoryBinding::new("mcp", "axiom-mcp", mcp.display().to_string()),
            ],
        );
        let set = discover_approved_set(&request, &LocalRepoProbe).expect("discovery");
        set.validate().expect("a non-empty set is valid");
        assert!(set.is_complete());
        assert_eq!(set.approved().len(), 2);
        assert_eq!(set.approved()[0].repo_id(), "graphd");
        assert_eq!(set.approved()[0].name, "axiom-graphd");
        assert_eq!(
            set.approved()[0].remote.as_deref(),
            Some("https://github.com/orchex006/axiom-graphd.git")
        );
        assert!(set.rejected().is_empty());
    }

    /// AC1 negative: a similarly named checkout, an inaccessible root and a
    /// wrong origin are refused instead of being silently substituted.
    #[test]
    fn similarly_named_inaccessible_and_foreign_repositories_are_refused() {
        let temp = tempfile::tempdir().expect("tempdir");
        let similar = temp.path().join("axiom-graphd-old");
        write_checkout(&similar, "https://github.com/orchex006/axiom-graphd.git");
        let foreign = temp.path().join("axiom-mcp");
        write_checkout(&foreign, "https://github.com/orchex006/axiom-mcp-fork.git");
        let absent = temp.path().join("axiom-skills");

        let probe = LocalRepoProbe;
        let request = SolutionRequest::new(
            "axiom-main",
            vec![
                RepositoryBinding::new("graphd", "axiom-graphd", similar.display().to_string()),
                RepositoryBinding::new("mcp", "axiom-mcp", foreign.display().to_string())
                    .with_remote("https://github.com/orchex006/axiom-mcp.git"),
                RepositoryBinding::new("skills", "axiom-skills", absent.display().to_string()),
            ],
        );
        let set = discover_approved_set(&request, &probe).expect("discovery");
        assert!(set.approved().is_empty());
        assert_eq!(set.rejected().len(), 3);
        assert_eq!(set.rejected()[0].rule, RULE_NAME_MISMATCH);
        assert_eq!(set.rejected()[1].rule, RULE_REMOTE_MISMATCH);
        assert_eq!(set.rejected()[2].rule, RULE_ABSENT);
        let error = set.validate().expect_err("nothing approved");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(RULE_NOTHING_APPROVED)
        );
    }

    /// Boundary: an unreadable root is reported as inaccessible, and the probe
    /// itself is modelled rather than requiring an ACL the test cannot set.
    #[test]
    fn an_inaccessible_root_is_refused_with_its_own_rule() {
        struct Denied;
        impl RepoProbe for Denied {
            fn observe(&self, _root: &str) -> RepoObservation {
                RepoObservation::inaccessible("access is denied")
            }
        }
        let request = SolutionRequest::new(
            "axiom-main",
            vec![RepositoryBinding::new(
                "graphd",
                "axiom-graphd",
                "/home/dev/axiom-graphd",
            )],
        );
        let set = discover_approved_set(&request, &Denied).expect("discovery");
        assert_eq!(set.rejected()[0].rule, RULE_INACCESSIBLE);
    }

    /// Boundary: unsafe roots, duplicate ids and duplicate roots are refused
    /// before any host read happens.
    #[test]
    fn unsafe_and_duplicate_bindings_are_refused_without_substitution() {
        #[derive(Default)]
        struct Counting {
            calls: std::cell::Cell<usize>,
        }
        impl RepoProbe for Counting {
            fn observe(&self, _root: &str) -> RepoObservation {
                self.calls.set(self.calls.get() + 1);
                RepoObservation::absent()
            }
        }
        let request = SolutionRequest::new(
            "axiom-main",
            vec![
                RepositoryBinding::new("relative", "axiom-graphd", "axiom-graphd"),
                RepositoryBinding::new(
                    "escaping",
                    "axiom-graphd",
                    "/srv/repos/../repos/axiom-graphd",
                ),
                RepositoryBinding::new("dup-id", "axiom-graphd", "/srv/repos/axiom-graphd"),
                RepositoryBinding::new("dup-id", "axiom-mcp", "/srv/repos/axiom-mcp"),
                RepositoryBinding::new("dup-root", "axiom-mcp", "/srv/repos/Axiom-Graphd"),
            ],
        );
        let probe = Counting::default();
        let set = discover_approved_set(&request, &probe).expect("discovery");
        assert_eq!(set.rejected().len(), 5);
        assert_eq!(set.rejected()[0].rule, RULE_UNSAFE_ROOT);
        assert_eq!(set.rejected()[1].rule, RULE_UNSAFE_ROOT);
        assert_eq!(set.rejected()[2].rule, RULE_ABSENT);
        assert_eq!(set.rejected()[3].rule, RULE_DUPLICATE_ID);
        assert_eq!(set.rejected()[4].rule, RULE_DUPLICATE_ROOT);
        assert_eq!(
            probe.calls.get(),
            1,
            "the host is read once, only for the one structurally valid binding"
        );
    }

    /// Boundary: an empty solution is refused outright rather than planned as
    /// "nothing to do".
    #[test]
    fn a_solution_without_repositories_is_refused() {
        let request = SolutionRequest::new("axiom-main", Vec::new());
        let error = discover_approved_set(&request, &LocalRepoProbe).expect_err("empty solution");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(RULE_EMPTY_SOLUTION)
        );
    }

    /// The origin parser accepts only the `origin` remote and ignores the other
    /// sections of a real Git config.
    #[test]
    fn only_the_origin_remote_is_read_from_a_git_config() {
        let config = "[core]\n\tbare = false\n[remote \"upstream\"]\n\turl = https://example.invalid/upstream.git\n[remote \"origin\"]\n\turl = https://github.com/orchex006/axiom-graphd.git\n";
        assert_eq!(
            parse_origin_remote(config).as_deref(),
            Some("https://github.com/orchex006/axiom-graphd.git")
        );
        assert_eq!(parse_origin_remote("[core]\n\tbare = false\n"), None);
        assert!(remote_satisfies(
            "https://github.com/orchex006/axiom-graphd",
            Some("https://github.com/orchex006/axiom-graphd.git")
        ));
        assert!(!remote_satisfies(
            "https://github.com/orchex006/axiom-graphd",
            None
        ));
    }
}
