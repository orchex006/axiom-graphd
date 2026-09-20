//! Publishable configuration for the Axiom core (V2-007).
//!
//! [`bindings`] keeps the logical identity of a bound repository separate from
//! the machine-local absolute root, and refuses duplicate active writers before
//! any work starts.

pub mod bindings;
pub mod solution;

pub use bindings::{
    resolve_binding, validate_active_writers, PortableBinding, PortableBindings, RepoBinding,
    RepositoryBindings, MAX_BINDINGS,
};
pub use solution::{
    normalize_service_key, read_registered_solution, AliasResolution, MembershipClaim,
    RegisteredSolution, ServiceAlias, ERR_ALIAS_AMBIGUOUS_HOST, ERR_ALIAS_UNRESOLVED_HOST,
    ERR_BINDING_KEY_DUPLICATE, ERR_BINDING_KEY_UNRESOLVED, ERR_LINK_ENDPOINT_NOT_MEMBER,
    ERR_PROJECT_PATH_NOT_REPOSITORY_RELATIVE, ERR_PROJECT_ROOT_ESCAPES_BINDING,
    ERR_ROUTE_PREFIX_NOT_PORTABLE_FREE_TEXT, ERR_ROUTE_PREFIX_REQUIRED,
};
