//! Project membership and root-overlap validation (task B-013).
//!
//! docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md section 2 gives one `projects`
//! table to a solution: every project claims a repository-relative source root
//! and, optionally, a repository-relative generated-output root. Two projects
//! may live in the same repository, but two owners must never claim the same or
//! a nested path. A duplicated id, a duplicated root or a generated-output
//! directory nested inside another project's claim would make graph ownership
//! ambiguous at publication time, so membership is validated before a row is
//! written and the caller can still tell a legitimate same-repository pair from
//! an ownership collision.
//!
//! Path comparisons are segment aware, never string prefixes: `src/App` and
//! `src/AppTests` are two different projects, while `src/App` and
//! `src/App/generated` are not.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{AxiomError, ErrorCode};
use crate::paths::{is_portable_id, validate_project_root_binding, WHOLE_REPO_BINDING};

/// Upper bound on projects in one solution.
///
/// A bounded membership check keeps a malformed or hostile document from
/// turning the quadratic overlap test into an unbounded denial of service.
pub const MAX_PROJECTS_PER_SOLUTION: usize = 4096;

/// One project of a solution, as it appears in membership validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectMembership {
    id: String,
    repo_id: String,
    relative_path: String,
    generated_output_root: Option<String>,
}

impl ProjectMembership {
    /// Build a project claim for `repo_id` rooted at `relative_path`.
    ///
    /// `relative_path` is `"."` for the whole repository or a portable
    /// repository-relative path; validation happens in
    /// [`validate_membership`].
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        repo_id: impl Into<String>,
        relative_path: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            repo_id: repo_id.into(),
            relative_path: relative_path.into(),
            generated_output_root: None,
        }
    }

    /// Attach the repository-relative generated-output root this project owns.
    #[must_use]
    pub fn with_generated_output_root(mut self, root: impl Into<String>) -> Self {
        self.generated_output_root = Some(root.into());
        self
    }

    /// Task project id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Repository this project belongs to.
    #[must_use]
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    /// Repository-relative source root or [`WHOLE_REPO_BINDING`].
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Repository-relative generated-output root, when declared.
    #[must_use]
    pub fn generated_output_root(&self) -> Option<&str> {
        self.generated_output_root.as_deref()
    }

    /// Every repository-relative path this project claims to own.
    #[must_use]
    pub fn claims(&self) -> Vec<&str> {
        let mut claims = vec![self.relative_path.as_str()];
        if let Some(root) = self.generated_output_root.as_deref() {
            claims.push(root);
        }
        claims
    }
}

/// A solution's project membership as submitted for validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolutionMembership {
    id: String,
    projects: Vec<ProjectMembership>,
}

impl SolutionMembership {
    /// Build a membership document for `id`.
    #[must_use]
    pub fn new(id: impl Into<String>, projects: Vec<ProjectMembership>) -> Self {
        Self {
            id: id.into(),
            projects,
        }
    }

    /// Solution id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Submitted projects, in order.
    #[must_use]
    pub fn projects(&self) -> &[ProjectMembership] {
        &self.projects
    }
}

/// Counts proven by a successful membership validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipReport {
    projects: usize,
    repos: usize,
}

impl MembershipReport {
    /// Validated project count.
    #[must_use]
    pub const fn projects(self) -> usize {
        self.projects
    }

    /// Distinct repositories referenced by the validated projects.
    #[must_use]
    pub const fn repos(self) -> usize {
        self.repos
    }
}

/// Whether two repository-relative claims overlap.
///
/// `.` (the whole repository) overlaps everything. Otherwise two paths overlap
/// only when they are equal or one is an ancestor of the other *by whole path
/// segment*, so `src/App` and `src/AppTests` do not overlap.
#[must_use]
pub fn paths_overlap(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    if left == WHOLE_REPO_BINDING || right == WHOLE_REPO_BINDING {
        return true;
    }
    let mut left_segments = left.split('/');
    let mut right_segments = right.split('/');
    loop {
        match (left_segments.next(), right_segments.next()) {
            (Some(a), Some(b)) if a == b => {}
            // Either side ending here means the other side continues the same
            // chain, so one claim is nested inside the other.
            (None, _) | (_, None) => return true,
            _ => return false,
        }
    }
}

/// Validate a solution's project membership and generated-output ownership.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] for a non-portable solution/project/repo
///   identifier, a path that violates the portable-path policy, or a membership
///   larger than [`MAX_PROJECTS_PER_SOLUTION`].
/// - [`ErrorCode::Conflict`] for a duplicated project id or for two projects of
///   the same repository whose source or generated-output claims overlap.
pub fn validate_membership(
    membership: &SolutionMembership,
) -> Result<MembershipReport, AxiomError> {
    if !is_portable_id(membership.id()) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "solution id must be a portable Axiom identifier",
        )
        .with_detail("solution_id", membership.id()));
    }
    if membership.projects().len() > MAX_PROJECTS_PER_SOLUTION {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "project membership exceeds the bounded solution size",
        )
        .with_detail("limit", MAX_PROJECTS_PER_SOLUTION.to_string())
        .with_detail("observed", membership.projects().len().to_string()));
    }

    let mut seen_ids: BTreeSet<&str> = BTreeSet::new();
    let mut repos: BTreeSet<&str> = BTreeSet::new();
    // repo id -> claim path -> owning project id, so a collision can name both
    // owners instead of only the path that lost.
    let mut claims: BTreeMap<&str, BTreeMap<&str, &str>> = BTreeMap::new();

    for project in membership.projects() {
        if !is_portable_id(project.id()) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "project id must be a portable Axiom identifier",
            )
            .with_detail("project_id", project.id())
            .with_detail("solution_id", membership.id()));
        }
        if !is_portable_id(project.repo_id()) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "repo id must be a portable Axiom identifier",
            )
            .with_detail("project_id", project.id()));
        }
        validate_project_root_binding(project.relative_path())?;
        if let Some(root) = project.generated_output_root() {
            validate_project_root_binding(root)?;
        }
        if !seen_ids.insert(project.id()) {
            return Err(AxiomError::new(
                ErrorCode::Conflict,
                "project id is duplicated in this solution",
            )
            .with_detail("rule", "duplicate-project-id")
            .with_detail("project_id", project.id())
            .with_detail("solution_id", membership.id()));
        }

        let repo_claims = claims.entry(project.repo_id()).or_default();
        for claim in project.claims() {
            if let Some(other) = repo_claims.get(claim) {
                return Err(overlap_error(membership.id(), project.id(), claim, other));
            }
            for (other_claim, other) in repo_claims.iter() {
                if paths_overlap(claim, other_claim) {
                    return Err(overlap_error(membership.id(), project.id(), claim, other));
                }
            }
        }
        for claim in project.claims() {
            repo_claims.insert(claim, project.id());
        }
        repos.insert(project.repo_id());
    }

    Ok(MembershipReport {
        projects: membership.projects().len(),
        repos: repos.len(),
    })
}

fn overlap_error(
    solution_id: &str,
    project_id: &str,
    claim: &str,
    other_project: &str,
) -> AxiomError {
    AxiomError::new(
        ErrorCode::Conflict,
        "project source or generated-output ownership overlaps another project",
    )
    .with_detail("rule", "root-overlap")
    .with_detail("solution_id", solution_id)
    .with_detail("project_id", project_id)
    .with_detail("observed", other_project)
    .with_detail("portable_path", claim)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: &str, path: &str) -> ProjectMembership {
        ProjectMembership::new(id, "repo-main", path)
    }

    #[test]
    fn two_projects_in_one_repo_are_supported_without_overlap() {
        let membership = SolutionMembership::new(
            "sol-main",
            vec![
                member("proj-app", "src/App"),
                member("proj-tests", "src/AppTests"),
            ],
        );
        let report = validate_membership(&membership).expect("same-repo pair is valid");
        assert_eq!(report.projects(), 2);
        assert_eq!(report.repos(), 1);
        assert!(!paths_overlap("src/App", "src/AppTests"));
        assert!(paths_overlap("src/App", "src/App/generated"));
    }

    #[test]
    fn duplicate_ids_and_overlapping_generated_output_are_refused() {
        let duplicate = SolutionMembership::new(
            "sol-main",
            vec![
                member("proj-app", "src/App"),
                member("proj-app", "src/Other"),
            ],
        );
        let error = validate_membership(&duplicate).expect_err("duplicate project id");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("duplicate-project-id")
        );

        let overlapping = SolutionMembership::new(
            "sol-main",
            vec![
                member("proj-app", "src/App").with_generated_output_root("src/App/generated"),
                member("proj-oracle", "src/App/generated"),
            ],
        );
        let error = validate_membership(&overlapping).expect_err("owned output overlap");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("root-overlap")
        );
    }
}
