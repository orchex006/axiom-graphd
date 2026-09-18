//! Secret handling and symlink escape policy (task B-025).
//!
//! Reading a source tree is not the same as reading every file in it. A secret
//! store must not be parsed into the graph, where it would be indexed, exported
//! and possibly published; and a symlink whose target leaves the bound project
//! root is a request to read a file the project does not own
//! (`docs/19-GIT-SNAPSHOT-POLICY.md` section 7).
//!
//! Both decisions are made on the observed entry, not on a guess: the caller
//! reports whether the entry is a regular file or a symlink and, for a symlink,
//! the resolved target when resolution succeeded. Resolution itself is a
//! filesystem operation and therefore stays outside this pure module.

use crate::portable_relative_path;
use graph_core::error::AxiomError;

/// What the filesystem reported about one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchedEntry {
    /// A regular file.
    File,
    /// A symlink whose target resolved, given as an absolute local path.
    ResolvedSymlink {
        /// Resolved absolute target of the link.
        target: String,
    },
    /// A symlink whose target could not be resolved (dangling or denied).
    UnresolvedSymlink,
}

/// File-name patterns that hold credentials rather than analyzable source.
const SECRET_FILE_NAMES: &[&str] = &[
    ".env",
    "credentials",
    "credentials.json",
    "secrets.json",
    "id_rsa",
    "id_ed25519",
    ".npmrc",
    ".pypirc",
    ".netrc",
];

/// File extensions that hold credentials.
const SECRET_EXTENSIONS: &[&str] = &["pfx", "p12", "key", "pem", "kdbx"];

/// Directories whose whole subtree is a credential store.
const SECRET_DIRECTORIES: &[&str] = &[".secrets", "secrets", "credentials"];

/// Why an entry is not parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSkip {
    /// The path holds credentials.
    Secret {
        /// Name or extension pattern that matched.
        matched: String,
    },
    /// The entry is a symlink whose target escapes the project root.
    SymlinkEscape {
        /// Resolved target when one was available (for a diagnostic).
        target: Option<String>,
    },
    /// The entry is a symlink whose target could not be resolved.
    SymlinkUnresolved,
    /// Symbolic links are disabled by policy for this project.
    SymlinkDisallowed,
}

/// Whether an entry may be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputDecision {
    /// The entry is analyzable input.
    Parsable,
    /// The entry is deliberately not parsed.
    Skipped(InputSkip),
}

impl InputDecision {
    /// Whether the entry may be parsed.
    #[must_use]
    pub const fn is_parsable(&self) -> bool {
        matches!(self, Self::Parsable)
    }

    /// The skip reason, when the entry is not parsed.
    #[must_use]
    pub fn skip(&self) -> Option<&InputSkip> {
        match self {
            Self::Parsable => None,
            Self::Skipped(reason) => Some(reason),
        }
    }
}

/// Project-scoped input policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputPolicy {
    project_root: String,
    follow_symlinks: bool,
}

impl InputPolicy {
    /// Policy for a project rooted at the absolute local path `project_root`.
    ///
    /// Symbolic links are followed only when their resolved target stays inside
    /// the root; that is the safe default and matches the inventory contract
    /// (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 9).
    #[must_use]
    pub fn new(project_root: impl Into<String>) -> Self {
        Self {
            project_root: project_root.into(),
            follow_symlinks: true,
        }
    }

    /// Refuse every symbolic link, resolved or not.
    #[must_use]
    pub fn without_symlinks(mut self) -> Self {
        self.follow_symlinks = false;
        self
    }

    /// Absolute root every resolved target must stay inside.
    #[must_use]
    pub fn project_root(&self) -> &str {
        &self.project_root
    }

    /// Decide whether one observed entry may be parsed.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] when the path is not a canonical portable
    /// relative path.
    pub fn decide(&self, path: &str, entry: &WatchedEntry) -> Result<InputDecision, AxiomError> {
        let path = portable_relative_path(path)?;
        if let Some(skip) = self.secret_skip(&path) {
            return Ok(InputDecision::Skipped(skip));
        }
        match entry {
            WatchedEntry::File => Ok(InputDecision::Parsable),
            WatchedEntry::UnresolvedSymlink => {
                Ok(InputDecision::Skipped(InputSkip::SymlinkUnresolved))
            }
            WatchedEntry::ResolvedSymlink { target } => {
                if !self.follow_symlinks {
                    return Ok(InputDecision::Skipped(InputSkip::SymlinkDisallowed));
                }
                if is_within_root(&self.project_root, target) {
                    Ok(InputDecision::Parsable)
                } else {
                    Ok(InputDecision::Skipped(InputSkip::SymlinkEscape {
                        target: Some(target.clone()),
                    }))
                }
            }
        }
    }

    fn secret_skip(&self, path: &str) -> Option<InputSkip> {
        let segments: Vec<&str> = path.split('/').collect();
        for segment in &segments[..segments.len() - 1] {
            if SECRET_DIRECTORIES
                .iter()
                .any(|name| name.eq_ignore_ascii_case(segment))
            {
                return Some(InputSkip::Secret {
                    matched: (*segment).to_string(),
                });
            }
        }
        let last = segments[segments.len() - 1];
        for name in SECRET_FILE_NAMES {
            if last.eq_ignore_ascii_case(name) {
                return Some(InputSkip::Secret {
                    matched: (*name).to_string(),
                });
            }
        }
        if let Some((stem, extension)) = last.rsplit_once('.') {
            if SECRET_EXTENSIONS
                .iter()
                .any(|name| extension.eq_ignore_ascii_case(name))
            {
                return Some(InputSkip::Secret {
                    matched: extension.to_ascii_lowercase(),
                });
            }
            // `.env.production`, `.env.local` and similar per-environment files
            // carry the same secrets as `.env` itself.
            if stem.eq_ignore_ascii_case(".env") {
                return Some(InputSkip::Secret {
                    matched: ".env".to_string(),
                });
            }
        }
        None
    }
}

/// Whether an absolute local path is the root itself or lives under it.
#[must_use]
pub fn is_within_root(root: &str, candidate: &str) -> bool {
    let root = root.replace('\\', "/");
    let candidate = candidate.replace('\\', "/");
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return false;
    }
    if candidate.len() <= root.len() {
        return crate::same_path(&candidate, root);
    }
    let (prefix, rest) = candidate.split_at(root.len());
    crate::same_path(prefix, root) && rest.starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::{is_within_root, InputDecision, InputPolicy, InputSkip, WatchedEntry};
    use graph_core::error::ErrorCode;

    fn skipping(policy: &InputPolicy, path: &str, entry: &WatchedEntry) -> InputSkip {
        policy
            .decide(path, entry)
            .expect("portable path")
            .skip()
            .cloned()
            .expect("a skip reason")
    }

    #[test]
    fn secret_files_are_not_parsed_while_safe_sources_stay_visible() {
        let policy = InputPolicy::new("D:/repo/Project");
        for path in [
            ".env",
            ".env.local",
            "src/.env.production",
            "cfg/secrets.json",
            "keys/signing.pfx",
            "secrets/api.json",
        ] {
            let decision = policy
                .decide(path, &WatchedEntry::File)
                .expect("portable path");
            assert!(
                matches!(decision.skip(), Some(InputSkip::Secret { .. })),
                "path {path} must be withheld"
            );
        }
        for path in [
            "src/App.cs",
            "appsettings.json",
            "Program.cs",
            "docs/notes.md",
        ] {
            assert_eq!(
                policy
                    .decide(path, &WatchedEntry::File)
                    .expect("portable path"),
                InputDecision::Parsable,
                "path {path} must remain visible"
            );
        }
    }

    #[test]
    fn escaping_and_unresolved_symlinks_are_not_parsed() {
        let policy = InputPolicy::new("D:/repo/Project");
        assert_eq!(
            policy
                .decide(
                    "src/link.cs",
                    &WatchedEntry::ResolvedSymlink {
                        target: "D:/repo/Project/src/real.cs".to_string(),
                    }
                )
                .expect("portable path"),
            InputDecision::Parsable,
            "a target inside the root must not be reported as an escape"
        );
        let escaped = skipping(
            &policy,
            "src/link.cs",
            &WatchedEntry::ResolvedSymlink {
                target: "D:/other/secret.cs".to_string(),
            },
        );
        assert!(
            matches!(escaped, InputSkip::SymlinkEscape { .. }),
            "a target outside the root must be refused: {escaped:?}"
        );
        assert_eq!(
            skipping(&policy, "src/dangling.cs", &WatchedEntry::UnresolvedSymlink),
            InputSkip::SymlinkUnresolved
        );
        assert_eq!(
            skipping(
                &policy.without_symlinks(),
                "src/inside.cs",
                &WatchedEntry::ResolvedSymlink {
                    target: "D:/repo/Project/src/real.cs".to_string(),
                }
            ),
            InputSkip::SymlinkDisallowed
        );
    }

    #[test]
    fn root_containment_is_exact_and_rejects_sibling_prefixes() {
        assert!(is_within_root(
            "D:/repo/Project",
            "D:/repo/Project/src/App.cs"
        ));
        assert!(is_within_root("D:/repo/Project", "D:/repo/Project"));
        assert!(is_within_root(
            "D:/repo/Project/",
            "D:/repo/Project/src/App.cs"
        ));
        assert!(
            !is_within_root("D:/repo/Project", "D:/repo/Project-other/App.cs"),
            "a sibling with a shared prefix must not be treated as contained"
        );
        assert!(!is_within_root("D:/repo/Project", "D:/repo"));
        assert!(!is_within_root("", "D:/repo/Project/src/App.cs"));
        let error = InputPolicy::new("D:/repo")
            .decide("C:/tmp/x.cs", &WatchedEntry::File)
            .expect_err("absolute paths are refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
    }
}
