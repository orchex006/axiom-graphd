//! Filesystem observation, input policy and reconciliation scheduling for the
//! Axiom graph engine (`axiom-graphd`).
//!
//! This crate owns the watcher-and-input-inventory work package (B-021 - B-031).
//! A filesystem watcher is a *hint*, never the truth
//! (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 9): the modules here
//! turn backend events into normalized hints ([`normalize`]), decide which paths
//! are parseable inputs at all ([`ignore`], [`input_policy`]), coalesce the hint
//! storm into a bounded reconciliation batch ([`debounce`]), track monotonic
//! dirty generations ([`dirty`]), and perform the real inventory scans that
//! recovery depends on ([`inventory`], [`recovery`]).
//!
//! * B-021 ([`native`]) - the `notify`-backed native watcher adapter.
//! * B-022 ([`poll`]) - the polling fallback and the declared backend policy.
//! * B-023 ([`normalize`]) - create/write/rename/delete normalization.
//! * B-024 ([`ignore`]) - generated-output and build-directory exclusions.
//! * B-025 ([`input_policy`]) - secret handling and symlink escape policy.
//! * B-026 ([`debounce`]) - debounce with a hard maximum wait.
//! * B-027 ([`dirty`]) - monotonic desired/indexed dirty generations.
//! * B-028 ([`inventory`]) - the complete startup input inventory.
//! * B-029 ([`recovery`]) - full rescan after overflow or reconnect.
//! * B-030 ([`config_invalidation`]) - config/dependency fingerprints and scope.
//! * B-031 ([`git_observer`]) - safe Git worktree observation.
//! * V2-014 ([`reconcile`]) - bounded reconciliation that turns one observed
//!   batch into apply/bounded-rescan/full-scan, and degrades to polling when a
//!   target has no native backend.
//! * F-009 ([`checkpoint_inputs`]) - distinguish the Git input classes a
//!   checkpoint must keep apart.
//!
//! No module here executes a repository script, a build or a database query:
//! analysis never discovers graph facts by running the analysed project
//! (`docs/15-STATIC-ANALYSIS-COVERAGE.md` section 6).

pub mod checkpoint_inputs;
pub mod config_invalidation;
pub mod debounce;
pub mod dirty;
pub mod git_observer;
pub mod ignore;
pub mod input_policy;
pub mod inventory;
pub mod native;
pub mod normalize;
pub mod poll;
pub mod reconcile;
pub mod recovery;

use graph_core::error::{AxiomError, ErrorCode};

/// Convert a caller-supplied path into the canonical portable relative form.
///
/// The graph, the queue and every evidence record address a file by one
/// spelling: forward slashes, no leading separator, no drive or UNC prefix and
/// no `.` or `..` segment. Anything else is refused instead of being rewritten,
/// because a silently rewritten path can point at a different file than the
/// caller meant.
///
/// # Errors
/// [`ErrorCode::ValidationError`] when the value is empty, absolute, or contains
/// an empty, `.` or `..` segment.
pub fn portable_relative_path(value: &str) -> Result<String, AxiomError> {
    if value.is_empty() {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "a watched path must not be empty",
        ));
    }
    if value.contains('\0') {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "a watched path must not contain a NUL byte",
        )
        .with_detail("path", value));
    }
    let unified = value.replace('\\', "/");
    let bytes = unified.as_bytes();
    let absolute = unified.starts_with('/')
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':');
    if absolute {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "a watched path must be relative to the bound project root",
        )
        .with_detail("path", value));
    }
    let mut segments: Vec<&str> = Vec::new();
    for segment in unified.split('/') {
        match segment {
            "" => {
                return Err(AxiomError::new(
                    ErrorCode::ValidationError,
                    "a watched path must not contain an empty segment",
                )
                .with_detail("path", value));
            }
            "." | ".." => {
                return Err(AxiomError::new(
                    ErrorCode::ValidationError,
                    "a watched path must not contain a relative traversal segment",
                )
                .with_detail("path", value));
            }
            _ => segments.push(segment),
        }
    }
    Ok(segments.join("/"))
}

/// Whether a value is already a canonical portable relative path.
#[must_use]
pub fn is_portable_relative_path(value: &str) -> bool {
    portable_relative_path(value).is_ok()
}

/// Compare two portable paths the way the local filesystem does.
///
/// Windows compares case-insensitively, so a case-only rename must be detected
/// rather than reported as two unrelated paths. Other platforms compare exactly.
#[must_use]
pub fn same_path(lhs: &str, rhs: &str) -> bool {
    if cfg!(windows) {
        lhs.eq_ignore_ascii_case(rhs)
    } else {
        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::{is_portable_relative_path, portable_relative_path, same_path};
    use graph_core::error::ErrorCode;

    #[test]
    fn canonical_paths_are_accepted_and_unified() {
        assert_eq!(
            portable_relative_path("src\\App.cs").expect("windows spelling"),
            "src/App.cs"
        );
        assert_eq!(
            portable_relative_path("src/nested/App.cs").expect("portable"),
            "src/nested/App.cs"
        );
        assert!(is_portable_relative_path("Cargo.toml"));
    }

    #[test]
    fn absolute_traversal_and_empty_paths_are_refused() {
        for value in [
            "",
            "/etc/passwd",
            "C:/tmp/file.cs",
            "c:file.cs",
            "src/../secret.cs",
            "src//App.cs",
            "src/./App.cs",
        ] {
            let error = portable_relative_path(value).expect_err("must be refused");
            assert_eq!(error.code(), ErrorCode::ValidationError, "value {value:?}");
        }
    }

    #[test]
    fn case_comparison_follows_the_host_filesystem() {
        assert!(same_path("src/App.cs", "src/App.cs"));
        if cfg!(windows) {
            assert!(same_path("src/App.cs", "SRC/app.CS"));
        } else {
            assert!(!same_path("src/App.cs", "SRC/app.CS"));
        }
    }
}
