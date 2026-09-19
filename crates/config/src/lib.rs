//! Publishable configuration for the Axiom core (V2-007).
//!
//! [`bindings`] keeps the logical identity of a bound repository separate from
//! the machine-local absolute root, and refuses duplicate active writers before
//! any work starts.

pub mod bindings;

pub use bindings::{
    resolve_binding, validate_active_writers, PortableBinding, PortableBindings, RepoBinding,
    RepositoryBindings, MAX_BINDINGS,
};
