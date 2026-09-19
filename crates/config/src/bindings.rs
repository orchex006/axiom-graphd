//! Logical repository bindings whose absolute roots stay private (V2-007).
//!
//! The problem this module solves is the one CP-03 and the V1->V2 migration call
//! out: a *logical* repository id must survive a checkout move, while the
//! machine-local absolute root of that checkout must never be published in a
//! portable config, checkpoint or catalog.
//!
//! So a binding has two halves and they are kept apart by type:
//!
//! - [`RepoBinding`] is the **private** half. It carries the absolute root, is
//!   never serialized into a portable artifact, and refuses a root that is
//!   relative, remote, cloud-synchronised or a device path.
//! - [`PortableBindings`] is the **publishable** half. It carries only portable
//!   logical ids plus the lexical storage class, so two checkouts of the same
//!   logical repository at different paths produce the same portable table.
//!
//! The second rule is ownership: at most one active writer may publish a given
//! output namespace. A duplicate active writer, a logical writer reachable from
//! two roots, two logical repositories bound to one root, or two active
//! solutions publishing the same repository pointer are all refused before any
//! work starts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{
    classify_storage_lexically, is_absolute_host_path, is_portable_id, StorageClass,
};

/// Upper bound on configured bindings.
pub const MAX_BINDINGS: usize = 1024;

/// Stable rule name: two active bindings claim the same output owner.
pub const ERR_DUPLICATE_WRITER: &str = "duplicate-output-writer";
/// Stable rule name: one logical writer is reachable from two absolute roots.
pub const ERR_WRITER_ALIAS: &str = "duplicate-output-writer-alias";
/// Stable rule name: two logical repositories claim one absolute root.
pub const ERR_ROOT_ALIAS: &str = "binding-root-alias";
/// Stable rule name: two active solutions would publish one repository pointer.
pub const ERR_OUTPUT_NAMESPACE_OVERLAP: &str = "output-namespace-overlap";
/// Stable rule name: a private binding must hold an absolute local root.
pub const ERR_PRIVATE_BINDING: &str = "private-binding-required";

/// One operator-provided binding of a logical repository + solution to a local
/// checkout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoBinding {
    repo_id: String,
    solution_id: String,
    root: String,
    active: bool,
}

impl RepoBinding {
    /// Create a binding, validating both halves.
    ///
    /// # Errors
    /// - [`ErrorCode::ValidationError`] for a non-portable `repo_id` or
    ///   `solution_id`.
    /// - [`ErrorCode::ConfigInvalid`] for a root that is not absolute, is on
    ///   shared/remote/cloud-synchronised storage, is a device path or contains
    ///   a control character.
    pub fn new(
        repo_id: &str,
        solution_id: &str,
        root: &str,
        active: bool,
    ) -> Result<Self, AxiomError> {
        if !is_portable_id(repo_id) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "repository id is not a portable slug",
            )
            .with_detail("config_key", "repo_id")
            .with_detail("observed", repo_id));
        }
        if !is_portable_id(solution_id) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "solution id is not a portable slug",
            )
            .with_detail("config_key", "solution_id")
            .with_detail("observed", solution_id));
        }
        if root.chars().any(char::is_control) {
            return Err(private_binding_error(
                root,
                "root contains control characters",
            ));
        }
        if !is_absolute_host_path(root) {
            return Err(private_binding_error(
                root,
                "a private binding root must be an absolute host path",
            ));
        }
        let storage_class = classify_storage_lexically(root);
        if storage_class.is_unsafe_for_mutable_state() {
            return Err(private_binding_error(
                root,
                "a private binding root must be local storage",
            )
            .with_detail("storage_class", storage_class.as_str()));
        }
        Ok(Self {
            repo_id: repo_id.to_string(),
            solution_id: solution_id.to_string(),
            root: root.to_string(),
            active,
        })
    }

    /// The logical repository id.
    #[must_use]
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    /// The logical solution id.
    #[must_use]
    pub fn solution_id(&self) -> &str {
        &self.solution_id
    }

    /// The machine-local absolute root. Never published in a portable artifact.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }

    /// True when this binding is the active writer for its output namespace.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// The logical identity, which contains no local path and therefore survives
    /// a checkout move unchanged.
    #[must_use]
    pub fn logical_id(&self) -> String {
        format!("{}/{}", self.repo_id, self.solution_id)
    }

    /// The output-owner registration key a writer claims.
    #[must_use]
    pub fn output_owner_key(&self) -> String {
        format!("{}::{}", self.repo_id, self.solution_id)
    }

    /// The lexical storage class of the private root.
    #[must_use]
    pub fn storage_class(&self) -> StorageClass {
        classify_storage_lexically(&self.root)
    }
}

fn private_binding_error(root: &str, reason: &str) -> AxiomError {
    AxiomError::new(ErrorCode::ConfigInvalid, reason)
        .with_detail("config_key", "binding_root")
        .with_detail("observed", root)
        .with_detail("rule", ERR_PRIVATE_BINDING)
}

/// One publishable binding entry: logical ids and a storage class, no path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PortableBinding {
    /// Logical repository id.
    pub repo_id: String,
    /// Logical solution id.
    pub solution_id: String,
    /// Lexical storage class name of the private root.
    pub storage_class: String,
    /// Whether the binding is the active writer.
    pub active: bool,
}

/// The publishable view of a binding table.
///
/// It has no field that can hold an absolute path, so "paths are never
/// committed" is a property of the type rather than of a convention.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortableBindings {
    entries: Vec<PortableBinding>,
}

impl PortableBindings {
    /// Project a private table onto its publishable view, sorted by logical id.
    #[must_use]
    pub fn from_private(bindings: &RepositoryBindings) -> Self {
        let mut entries: Vec<PortableBinding> = bindings
            .entries()
            .iter()
            .map(|binding| PortableBinding {
                repo_id: binding.repo_id().to_string(),
                solution_id: binding.solution_id().to_string(),
                storage_class: binding.storage_class().as_str().to_string(),
                active: binding.is_active(),
            })
            .collect();
        entries.sort();
        Self { entries }
    }

    /// The publishable entries.
    #[must_use]
    pub fn entries(&self) -> &[PortableBinding] {
        &self.entries
    }

    /// True when no entry carries an absolute host path.
    #[must_use]
    pub fn contains_no_absolute_path(&self) -> bool {
        self.entries.iter().all(|entry| {
            !is_absolute_host_path(&entry.repo_id)
                && !is_absolute_host_path(&entry.solution_id)
                && !is_absolute_host_path(&entry.storage_class)
        })
    }
}

/// A validated private binding table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepositoryBindings {
    entries: Vec<RepoBinding>,
}

impl RepositoryBindings {
    /// Build a table, rejecting duplicates and overlapping active writers.
    ///
    /// # Errors
    /// Returns the first [`validate_active_writers`] refusal.
    pub fn new(entries: Vec<RepoBinding>) -> Result<Self, AxiomError> {
        let table = Self { entries };
        table.validate()?;
        Ok(table)
    }

    /// The bindings, in insertion order.
    #[must_use]
    pub fn entries(&self) -> &[RepoBinding] {
        &self.entries
    }

    /// The active writers only.
    #[must_use]
    pub fn active(&self) -> Vec<&RepoBinding> {
        self.entries
            .iter()
            .filter(|entry| entry.is_active())
            .collect()
    }

    /// Validate the table: size, then active-writer ownership.
    ///
    /// # Errors
    /// - [`ErrorCode::ValidationError`] when the table exceeds [`MAX_BINDINGS`].
    /// - [`ErrorCode::Conflict`] for a duplicate active writer, an aliased
    ///   logical writer, an aliased root or an overlapping output namespace.
    pub fn validate(&self) -> Result<(), AxiomError> {
        if self.entries.len() > MAX_BINDINGS {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "binding table exceeds the configured bound",
            )
            .with_detail("limit", MAX_BINDINGS.to_string())
            .with_detail("observed", self.entries.len().to_string()));
        }
        validate_active_writers(&self.entries)
    }
}

/// Reject every pair of active writers that would publish the same output.
///
/// # Errors
/// Returns [`ErrorCode::Conflict`] naming the rule that was violated.
pub fn validate_active_writers(bindings: &[RepoBinding]) -> Result<(), AxiomError> {
    let mut owners: BTreeMap<String, &RepoBinding> = BTreeMap::new();
    let mut roots: BTreeMap<&str, &RepoBinding> = BTreeMap::new();
    let mut repo_pointers: BTreeSet<&str> = BTreeSet::new();
    let mut repo_pointer_owner: BTreeMap<&str, &RepoBinding> = BTreeMap::new();

    for binding in bindings.iter().filter(|entry| entry.is_active()) {
        let key = binding.output_owner_key();
        if let Some(first) = owners.get(&key) {
            let rule = if first.root() == binding.root() {
                ERR_DUPLICATE_WRITER
            } else {
                ERR_WRITER_ALIAS
            };
            return Err(conflict_error(rule, binding, first));
        }
        owners.insert(key, binding);

        if let Some(first) = roots.get(binding.root()) {
            if first.logical_id() != binding.logical_id() {
                return Err(conflict_error(ERR_ROOT_ALIAS, binding, first));
            }
        }
        roots.insert(binding.root(), binding);

        if !repo_pointers.insert(binding.repo_id()) {
            let first = repo_pointer_owner
                .get(binding.repo_id())
                .copied()
                .unwrap_or(binding);
            return Err(conflict_error(ERR_OUTPUT_NAMESPACE_OVERLAP, binding, first));
        }
        repo_pointer_owner.insert(binding.repo_id(), binding);
    }
    Ok(())
}

fn conflict_error(rule: &str, second: &RepoBinding, first: &RepoBinding) -> AxiomError {
    AxiomError::new(
        ErrorCode::Conflict,
        "two active writers claim the same output ownership",
    )
    .with_detail("rule", rule)
    .with_detail("logical_id", second.logical_id())
    .with_detail("observed", first.logical_id())
}

/// Resolve a logical binding by id.
///
/// # Errors
/// Returns [`ErrorCode::NotFound`] when the logical id is not bound. A binding
/// is never resolved by guessing a path.
pub fn resolve_binding<'a>(
    bindings: &'a RepositoryBindings,
    repo_id: &str,
    solution_id: &str,
) -> Result<&'a RepoBinding, AxiomError> {
    bindings
        .entries()
        .iter()
        .find(|binding| binding.repo_id() == repo_id && binding.solution_id() == solution_id)
        .ok_or_else(|| {
            AxiomError::new(
                ErrorCode::NotFound,
                "no local binding for this logical repository and solution",
            )
            .with_detail("repo_id", repo_id)
            .with_detail("solution_id", solution_id)
        })
}

impl fmt::Display for RepoBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} [{}]",
            self.logical_id(),
            if self.active { "active" } else { "inactive" }
        )
    }
}
