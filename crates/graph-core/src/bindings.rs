//! Resolving catalog repository ids to trusted local bindings (task B-014).
//!
//! A published catalog names repositories by `repo_id`; those ids are not
//! paths. `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` and the V2 layout rules
//! require the daemon to map an id only through an operator-provided, absolute
//! binding. Guessing a path from an id, following `..`, or accepting a symlink
//! that leaves the bound root would let a catalog select files outside the
//! granted source roots, so every resolution is checked and refused loudly.
//!
//! Filesystem resolution is injected through [`SymlinkProbe`] so the policy is
//! testable on a host without the link being modelled.

use std::collections::BTreeMap;

use crate::error::{AxiomError, ErrorCode};
use crate::paths::{is_absolute_host_path, is_portable_id, validate_portable_relative_path};

/// Upper bound on configured local bindings.
pub const MAX_BINDINGS: usize = 1024;

/// One operator-provided mapping from a catalog repository id to a local root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalBinding {
    repo_id: String,
    root: String,
}

impl LocalBinding {
    /// Bind `repo_id` to the absolute local `root`.
    #[must_use]
    pub fn new(repo_id: impl Into<String>, root: impl Into<String>) -> Self {
        Self {
            repo_id: repo_id.into(),
            root: root.into(),
        }
    }

    /// Catalog repository id.
    #[must_use]
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    /// Absolute local root.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }
}

/// A repository id referenced by a catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogRepoReference {
    repo_id: String,
}

impl CatalogRepoReference {
    /// Reference `repo_id` from a catalog document.
    #[must_use]
    pub fn new(repo_id: impl Into<String>) -> Self {
        Self {
            repo_id: repo_id.into(),
        }
    }

    /// Referenced repository id.
    #[must_use]
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }
}

/// What a [`SymlinkProbe`] learned about a candidate path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The candidate resolves inside the bound root; carries the resolved path.
    Inside(String),
    /// The candidate resolves outside the bound root.
    Escape(String),
}

/// Host filesystem resolution, injected so the policy stays testable.
pub trait SymlinkProbe {
    /// Resolve `relative` under `binding_root`.
    fn resolve(&self, binding_root: &str, relative: &str) -> ProbeOutcome;
}

/// Probe for callers that have already canonicalized the bound root.
///
/// It joins paths lexically and never reports an escape, so it must only be
/// used where the caller owns that guarantee. Native canonicalization belongs
/// to the platform adapter, not to this policy module.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoSymlinkProbe;

impl SymlinkProbe for NoSymlinkProbe {
    fn resolve(&self, binding_root: &str, relative: &str) -> ProbeOutcome {
        ProbeOutcome::Inside(join(binding_root, relative))
    }
}

/// A catalog repository id resolved to a trusted local root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBinding {
    repo_id: String,
    root: String,
    resolved_root: String,
}

impl ResolvedBinding {
    /// Catalog repository id.
    #[must_use]
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    /// Configured absolute root.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// Root as the host resolved it (canonicalized when the probe can).
    #[must_use]
    pub fn resolved_root(&self) -> &str {
        &self.resolved_root
    }
}

/// Validate a full binding table before it is used for any resolution.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] for a non-portable repo id or a table larger
///   than [`MAX_BINDINGS`].
/// - [`ErrorCode::ConfigInvalid`] for a relative root, a control character or a
///   `.`/`..` traversal segment.
/// - [`ErrorCode::Conflict`] for two bindings of the same repo id.
pub fn validate_bindings(bindings: &[LocalBinding]) -> Result<(), AxiomError> {
    if bindings.len() > MAX_BINDINGS {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "binding table exceeds the bounded size",
        )
        .with_detail("limit", MAX_BINDINGS.to_string())
        .with_detail("observed", bindings.len().to_string()));
    }
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    for binding in bindings {
        if !is_portable_id(binding.repo_id()) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "binding repo id must be a portable Axiom identifier",
            )
            .with_detail("rule", "non-portable-repo-id"));
        }
        validate_root(binding.root())?;
        if seen.insert(binding.repo_id(), binding.root()).is_some() {
            return Err(
                AxiomError::new(ErrorCode::Conflict, "repo id is bound more than once")
                    .with_detail("rule", "duplicate-binding"),
            );
        }
    }
    Ok(())
}

/// Resolve one catalog repository id through the trusted binding table.
///
/// # Errors
/// - [`ErrorCode::NotFound`] when the catalog does not reference the id or the
///   id has no local binding; an id is never resolved by guessing a path.
/// - [`ErrorCode::Forbidden`] when the bound root resolves outside itself.
/// - The validation errors of [`validate_bindings`].
pub fn resolve_binding(
    bindings: &[LocalBinding],
    catalog: &[CatalogRepoReference],
    repo_id: &str,
    probe: &dyn SymlinkProbe,
) -> Result<ResolvedBinding, AxiomError> {
    validate_bindings(bindings)?;
    if !catalog.iter().any(|entry| entry.repo_id() == repo_id) {
        return Err(AxiomError::new(
            ErrorCode::NotFound,
            "repository id is not referenced by the catalog",
        )
        .with_detail("rule", "unknown-catalog-repo"));
    }
    let binding = bindings
        .iter()
        .find(|binding| binding.repo_id() == repo_id)
        .ok_or_else(|| {
            AxiomError::new(
                ErrorCode::NotFound,
                "repository id has no trusted local binding",
            )
            .with_detail("rule", "unbound-repo")
        })?;
    let root = normalise_root(binding.root());
    let resolved = match probe.resolve(&root, ".") {
        ProbeOutcome::Inside(resolved) => resolved,
        ProbeOutcome::Escape(resolved) => {
            return Err(
                AxiomError::new(ErrorCode::Forbidden, "bound root resolves outside itself")
                    .with_detail("rule", "symlink-escape")
                    .with_detail("observed", resolved),
            )
        }
    };
    if has_traversal(&resolved) {
        return Err(AxiomError::new(
            ErrorCode::Forbidden,
            "resolved root contains a relative traversal segment",
        )
        .with_detail("rule", "relative-traversal"));
    }
    Ok(ResolvedBinding {
        repo_id: binding.repo_id().to_string(),
        root,
        resolved_root: resolved,
    })
}

/// Resolve a project's repository-relative root under a resolved binding.
///
/// # Errors
/// - [`ErrorCode::UnsafePortablePath`] for a path that violates the portable
///   path policy (including `..` traversal).
/// - [`ErrorCode::Forbidden`] when the project root resolves outside the binding.
pub fn resolve_project_root(
    binding: &ResolvedBinding,
    relative: &str,
    probe: &dyn SymlinkProbe,
) -> Result<String, AxiomError> {
    validate_portable_relative_path(relative)?;
    match probe.resolve(binding.resolved_root(), relative) {
        ProbeOutcome::Inside(resolved) => Ok(resolved),
        ProbeOutcome::Escape(resolved) => Err(AxiomError::new(
            ErrorCode::Forbidden,
            "project root resolves outside the bound repository",
        )
        .with_detail("rule", "symlink-escape")
        .with_detail("observed", resolved)),
    }
}

fn validate_root(root: &str) -> Result<(), AxiomError> {
    if !is_absolute_host_path(root) {
        return Err(AxiomError::new(
            ErrorCode::ConfigInvalid,
            "binding root must be an absolute local path",
        )
        .with_detail("rule", "relative-binding-root"));
    }
    if root.chars().any(char::is_control) {
        return Err(AxiomError::new(
            ErrorCode::ConfigInvalid,
            "binding root contains control characters",
        )
        .with_detail("rule", "control-character"));
    }
    if has_traversal(root) {
        return Err(AxiomError::new(
            ErrorCode::ConfigInvalid,
            "binding root contains a relative traversal segment",
        )
        .with_detail("rule", "relative-traversal"));
    }
    Ok(())
}

fn has_traversal(path: &str) -> bool {
    path.split(['/', '\\']).any(|segment| segment == "..")
}

fn normalise_root(root: &str) -> String {
    let trimmed = root.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        root.to_string()
    } else {
        trimmed.replace('\\', "/")
    }
}

fn join(root: &str, relative: &str) -> String {
    let root = normalise_root(root);
    if relative == "." || relative.is_empty() {
        return root;
    }
    format!(
        "{}/{}",
        root.trim_end_matches('/'),
        relative.replace('\\', "/")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Probe that models a bound root which is itself a link out of the tree.
    struct EscapingProbe;

    impl SymlinkProbe for EscapingProbe {
        fn resolve(&self, binding_root: &str, relative: &str) -> ProbeOutcome {
            if binding_root.ends_with("/link") {
                ProbeOutcome::Escape("/outside/root".to_string())
            } else {
                ProbeOutcome::Inside(join(binding_root, relative))
            }
        }
    }

    #[test]
    fn catalog_repo_id_resolves_only_through_an_absolute_binding() {
        let bindings = vec![LocalBinding::new("repo-a", "/srv/axiom/repo-a")];
        let catalog = vec![CatalogRepoReference::new("repo-a")];
        let resolved = resolve_binding(&bindings, &catalog, "repo-a", &NoSymlinkProbe)
            .expect("bound catalog id resolves");
        assert_eq!(resolved.repo_id(), "repo-a");
        assert_eq!(resolved.resolved_root(), "/srv/axiom/repo-a");
        assert_eq!(
            resolve_project_root(&resolved, "src/App", &NoSymlinkProbe).expect("project root"),
            "/srv/axiom/repo-a/src/App"
        );
        assert_eq!(
            resolve_binding(&bindings, &catalog, "repo-b", &NoSymlinkProbe)
                .expect_err("unbound id is never guessed")
                .code(),
            ErrorCode::NotFound
        );
    }

    #[test]
    fn relative_traversal_and_symlink_escape_are_refused() {
        for root in ["repo-a", "/srv/axiom/../secrets", "/srv/axiom/\u{7}repo"] {
            let error = validate_bindings(&[LocalBinding::new("repo-a", root)])
                .expect_err("unsafe binding root");
            assert_eq!(error.code(), ErrorCode::ConfigInvalid, "root {root:?}");
        }

        let bindings = vec![LocalBinding::new("repo-a", "/srv/axiom/link")];
        let catalog = vec![CatalogRepoReference::new("repo-a")];
        assert_eq!(
            resolve_binding(&bindings, &catalog, "repo-a", &EscapingProbe)
                .expect_err("symlink escape")
                .code(),
            ErrorCode::Forbidden
        );
    }
}
