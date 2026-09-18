//! Generated-output and build-directory exclusions (task B-024).
//!
//! A watcher that reports the graph engine writing its own output will requeue
//! that write forever: the generated data lives inside the project folder, so
//! publishing one generation is itself a filesystem event for the next one.
//! Generation, staging, live JSON, database, WAL, log, backup and dependency
//! output paths are classified away before they reach the queue
//! (`docs/19-GIT-SNAPSHOT-POLICY.md` section 1;
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 4).
//!
//! Classification is a pure function of the canonical portable path, so the
//! inventory scan, the debouncer and the queue all make the same decision for
//! the same path.

use crate::portable_relative_path;
use graph_core::error::AxiomError;

/// Directory name excluded at any depth because it is a build or dependency
/// output rather than source.
const EXCLUDED_ANY_DEPTH: &[(&str, IgnoreReason)] = &[
    ("bin", IgnoreReason::BuildOutput),
    ("obj", IgnoreReason::BuildOutput),
    ("node_modules", IgnoreReason::DependencyCache),
    (".git", IgnoreReason::VersionControlMetadata),
];

/// Directory name excluded only directly under the project root, because the
/// graph engine and the queue own every file in it.
const EXCLUDED_PROJECT_ROOT: &[(&str, IgnoreReason)] = &[
    (".staging", IgnoreReason::StagingArea),
    ("queue", IgnoreReason::QueueState),
    ("leases", IgnoreReason::QueueState),
    ("locks", IgnoreReason::QueueState),
    ("logs", IgnoreReason::LogFile),
    ("backups", IgnoreReason::BackupArtifact),
    ("temp", IgnoreReason::StagingArea),
    ("credentials", IgnoreReason::CredentialStore),
];

/// File extensions that are never analyzable input.
const EXCLUDED_EXTENSIONS: &[(&str, IgnoreReason)] = &[
    ("db", IgnoreReason::DatabaseFile),
    ("db-wal", IgnoreReason::DatabaseFile),
    ("db-shm", IgnoreReason::DatabaseFile),
    ("sqlite", IgnoreReason::DatabaseFile),
    ("sqlite3", IgnoreReason::DatabaseFile),
    ("wal", IgnoreReason::DatabaseFile),
    ("shm", IgnoreReason::DatabaseFile),
    ("log", IgnoreReason::LogFile),
    ("swp", IgnoreReason::EditorTemporaryFile),
    ("tmp", IgnoreReason::EditorTemporaryFile),
    ("orig", IgnoreReason::EditorTemporaryFile),
    ("rej", IgnoreReason::EditorTemporaryFile),
];

/// Default project-relative root of the generated live graph data.
pub const DEFAULT_GRAPH_OUTPUT_ROOT: &str = "live";

/// Why a path is not analyzable input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IgnoreReason {
    /// Generated graph data the daemon writes itself.
    GeneratedGraphData,
    /// Compiler or MSBuild output (`bin/`, `obj/`).
    BuildOutput,
    /// Restored third-party dependencies (`node_modules/`).
    DependencyCache,
    /// Git metadata that Git owns, not the graph.
    VersionControlMetadata,
    /// Same-volume staging area of an in-progress generation.
    StagingArea,
    /// Durable queue state (jobs, leases, locks).
    QueueState,
    /// SQLite database plus WAL and SHM sidecars.
    DatabaseFile,
    /// Diagnostic log output.
    LogFile,
    /// Editor temporary or atomic-replace scratch file.
    EditorTemporaryFile,
    /// Backup artifact.
    BackupArtifact,
    /// Local credential store.
    CredentialStore,
}

impl IgnoreReason {
    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GeneratedGraphData => "generated_graph_data",
            Self::BuildOutput => "build_output",
            Self::DependencyCache => "dependency_cache",
            Self::VersionControlMetadata => "version_control_metadata",
            Self::StagingArea => "staging_area",
            Self::QueueState => "queue_state",
            Self::DatabaseFile => "database_file",
            Self::LogFile => "log_file",
            Self::EditorTemporaryFile => "editor_temporary_file",
            Self::BackupArtifact => "backup_artifact",
            Self::CredentialStore => "credential_store",
        }
    }
}

/// Whether a path is analyzed or excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreDecision {
    /// The path is a candidate input.
    Tracked,
    /// The path is excluded, with the rule that excluded it.
    Ignored {
        /// Category of the exclusion.
        reason: IgnoreReason,
        /// Stable identifier of the matching rule.
        rule: &'static str,
    },
}

impl IgnoreDecision {
    /// Whether the path is a candidate input.
    #[must_use]
    pub const fn is_tracked(self) -> bool {
        matches!(self, Self::Tracked)
    }

    /// The exclusion reason, when the path is excluded.
    #[must_use]
    pub const fn reason(self) -> Option<IgnoreReason> {
        match self {
            Self::Tracked => None,
            Self::Ignored { reason, .. } => Some(reason),
        }
    }
}

/// Project-scoped exclusion policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnorePolicy {
    graph_output_root: String,
    additional_roots: Vec<String>,
}

impl Default for IgnorePolicy {
    fn default() -> Self {
        Self::new(DEFAULT_GRAPH_OUTPUT_ROOT)
    }
}

impl IgnorePolicy {
    /// Policy whose generated graph data lives under `graph_output_root`.
    #[must_use]
    pub fn new(graph_output_root: impl Into<String>) -> Self {
        Self {
            graph_output_root: graph_output_root.into(),
            additional_roots: Vec::new(),
        }
    }

    /// Also exclude an operator-configured project-relative root.
    #[must_use]
    pub fn with_additional_root(mut self, root: impl Into<String>) -> Self {
        self.additional_roots.push(root.into());
        self
    }

    /// Project-relative root of the generated graph data.
    #[must_use]
    pub fn graph_output_root(&self) -> &str {
        &self.graph_output_root
    }

    /// Classify one project-relative path.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] when the path is not a canonical portable
    /// relative path.
    pub fn classify(&self, path: &str) -> Result<IgnoreDecision, AxiomError> {
        let path = portable_relative_path(path)?;
        let segments: Vec<&str> = path.split('/').collect();
        let first = segments[0];
        let last = segments[segments.len() - 1];

        if crate::same_path(first, &self.graph_output_root) {
            return Ok(IgnoreDecision::Ignored {
                reason: IgnoreReason::GeneratedGraphData,
                rule: "policy.graph-output-root",
            });
        }
        for root in &self.additional_roots {
            if crate::same_path(first, root) {
                return Ok(IgnoreDecision::Ignored {
                    reason: IgnoreReason::GeneratedGraphData,
                    rule: "policy.additional-root",
                });
            }
        }
        for (name, reason) in EXCLUDED_PROJECT_ROOT {
            if crate::same_path(first, name) {
                return Ok(IgnoreDecision::Ignored {
                    reason: *reason,
                    rule: "policy.project-root-directory",
                });
            }
        }
        if segments.len() > 1 {
            for segment in &segments[..segments.len() - 1] {
                for (name, reason) in EXCLUDED_ANY_DEPTH {
                    if crate::same_path(segment, name) {
                        return Ok(IgnoreDecision::Ignored {
                            reason: *reason,
                            rule: "policy.any-depth-directory",
                        });
                    }
                }
            }
        }
        if let Some(extension) = last.rsplit_once('.').map(|(_, extension)| extension) {
            for (name, reason) in EXCLUDED_EXTENSIONS {
                if extension.eq_ignore_ascii_case(name) {
                    return Ok(IgnoreDecision::Ignored {
                        reason: *reason,
                        rule: "policy.extension",
                    });
                }
            }
        }
        if last.starts_with("~$") || (last.starts_with('.') && last.ends_with(".swp")) {
            return Ok(IgnoreDecision::Ignored {
                reason: IgnoreReason::EditorTemporaryFile,
                rule: "policy.editor-temporary-name",
            });
        }
        if last.ends_with(".tmp") || last.contains(".tmp.") {
            return Ok(IgnoreDecision::Ignored {
                reason: IgnoreReason::EditorTemporaryFile,
                rule: "policy.atomic-replace-scratch",
            });
        }
        Ok(IgnoreDecision::Tracked)
    }
}

#[cfg(test)]
mod tests {
    use super::{IgnoreDecision, IgnorePolicy, IgnoreReason, DEFAULT_GRAPH_OUTPUT_ROOT};
    use graph_core::error::ErrorCode;

    fn reason(policy: &IgnorePolicy, path: &str) -> Option<IgnoreReason> {
        policy.classify(path).expect("portable path").reason()
    }

    #[test]
    fn writing_generated_graph_data_never_requeues_itself() {
        let policy = IgnorePolicy::default();
        assert_eq!(
            reason(&policy, "live/manifest.json"),
            Some(IgnoreReason::GeneratedGraphData)
        );
        assert_eq!(
            reason(&policy, "live/shards/0001.json"),
            Some(IgnoreReason::GeneratedGraphData)
        );
        assert_eq!(
            reason(&policy, ".staging/generation-7/index.json"),
            Some(IgnoreReason::StagingArea)
        );
        assert!(
            policy
                .classify("src/App.cs")
                .expect("portable")
                .is_tracked(),
            "the watcher must still observe real source"
        );
        assert_eq!(policy.graph_output_root(), DEFAULT_GRAPH_OUTPUT_ROOT);
    }

    #[test]
    fn bin_obj_and_node_modules_bursts_are_excluded_at_any_depth() {
        let policy = IgnorePolicy::default();
        for (path, expected) in [
            (
                "src/Server/bin/Debug/net8.0/Server.dll",
                IgnoreReason::BuildOutput,
            ),
            ("obj/project.assets.json", IgnoreReason::BuildOutput),
            (
                "src/api/obj/Release/net8.0/Program.cs",
                IgnoreReason::BuildOutput,
            ),
            (
                "app/node_modules/left-pad/index.js",
                IgnoreReason::DependencyCache,
            ),
            (".git/index", IgnoreReason::VersionControlMetadata),
            ("graph.db-wal", IgnoreReason::DatabaseFile),
            ("logs/daemon.log", IgnoreReason::LogFile),
            ("~$Report.docx", IgnoreReason::EditorTemporaryFile),
            ("src/App.cs.tmp", IgnoreReason::EditorTemporaryFile),
        ] {
            assert_eq!(reason(&policy, path), Some(expected), "path {path}");
        }
        assert_eq!(
            reason(&policy, "src/App.cs"),
            None,
            "a source file next to a build output stays visible"
        );
    }

    #[test]
    fn an_operator_configured_root_and_invalid_paths_are_handled() {
        let policy = IgnorePolicy::new("live").with_additional_root("generated");
        assert_eq!(
            reason(&policy, "generated/catalog.json"),
            Some(IgnoreReason::GeneratedGraphData)
        );
        let error = policy
            .classify("C:/outside/live/index.json")
            .expect_err("absolute paths are refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            policy.classify("").expect_err("empty path").code(),
            ErrorCode::ValidationError
        );
        assert_eq!(IgnoreDecision::Tracked.reason(), None);
    }
}
