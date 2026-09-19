//! Native platform policy for the Axiom core (V2 layout and guards).
//!
//! This crate is the policy/adapter layer between `graph-core`'s pure rules and
//! the processes that touch a real filesystem. It owns three slices:
//!
//! - [`state_root`] (V2-006): resolve and bootstrap the per-user `AXIOM_HOME`,
//!   including the native "this is a real, owner-private directory, not a link"
//!   check and the platform-default storage-class check.
//! - [`path_key`] and [`collisions`] (V2-013): the portable path identity and the
//!   case-fold/Unicode-normalization collision detector that `graph-core`
//!   explicitly deferred to the portability task.
//! - [`guard`] (V2-018): the frozen reader/writer guard ABI - participant plans,
//!   acquisition/release order, bounded wait, crash release and retention GC.
//!
//! Nothing here invokes a shell, and every native probe or wait primitive is
//! injectable so the policy stays testable on any host (CP-02).

pub mod collisions;
pub mod guard;
pub mod path_key;
pub mod state_root;
pub mod unicode;
pub mod unicode_tables;

pub use collisions::{detect_portable_collisions, Collision, CollisionKind, DetectError};
// The guard ABI is expressed in the shared lock vocabulary, so consumers of
// [guard] need this type nameable from this crate.
pub use graph_core::locks::LockMode;
pub use path_key::{PathKey, PathKeyError};
pub use state_root::{
    ensure_state_root, resolve_state_root, DirectoryStatus, NativeStateRootProbe, Ownership,
    ResolvedStateRoot, StateEnvironment, StatePlatform, StateRootError, StateRootProbe,
    StateRootSource,
};
pub use unicode::{canonical_combining_class, nfd, UNICODE_DATA_VERSION};
