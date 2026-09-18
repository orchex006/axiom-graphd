//! Materialize the Git index as an isolated input tree (task B-088).
//!
//! `docs/19-GIT-SNAPSHOTS-AND-MERGES.md` section 2 states the contract for
//! `--source staged`: materialize the Git **index** as an isolated input tree
//! and analyze from that tree, never resetting the working tree, stashing or
//! uncommitting, and never changing the user's index. Two failure modes follow
//! directly from that wording and are both refused rather than papered over:
//!
//! * A partially staged file must export the bytes the index holds, not the
//!   bytes the working tree holds. The index is the only byte source this module
//!   reads, so a working-tree copy cannot leak in.
//! * A path that is absent from the index is an error
//!   ([`REASON_NOT_IN_INDEX`]), never a silent fall back to the working tree.

use graph_core::error::{AxiomError, ErrorCode};

/// Reason recorded when a requested path is not present in the Git index.
pub const REASON_NOT_IN_INDEX: &str = "not-in-index";
/// Reason recorded when the index cannot be read.
pub const REASON_INDEX_UNREADABLE: &str = "index-unreadable";
/// Reason recorded when a materialization would mutate the user's index.
pub const REASON_INDEX_MUTATION: &str = "index-mutation";
/// Reason recorded when a requested path is not repository-relative.
pub const REASON_PATH_NOT_PORTABLE: &str = "path-not-portable";

/// The Git index as a byte source.
///
/// Production reads the index of a registered repository; tests provide a
/// scripted index, so the "staged bytes only" rule is provable without a
/// repository fixture.
pub trait IndexSource {
    /// The bytes the index holds for `path`, or `None` when the index does not
    /// contain that path.
    fn index_bytes(&self, path: &str) -> Option<Vec<u8>>;
    /// The bytes the working tree holds for `path`.
    ///
    /// Materialization deliberately never calls this; it exists so a test can
    /// prove the staged bytes differ from the working-tree bytes and that the
    /// exported result follows the index.
    fn worktree_bytes(&self, path: &str) -> Option<Vec<u8>>;
}

/// One file materialized out of the index.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MaterializedFile {
    /// Repository-relative forward-slash path.
    pub path: String,
    /// Bytes read from the index.
    pub bytes: Vec<u8>,
    /// SHA-256 of those bytes.
    pub sha256: String,
}

/// The complete isolated input tree for one checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StagedMaterialization {
    /// Materialized files, in index order.
    pub files: Vec<MaterializedFile>,
    /// Total materialized bytes.
    pub total_bytes: usize,
    /// The materialization was read-only with respect to the index.
    pub read_only: bool,
    /// Index writes performed. Always zero; a non-zero value is a defect.
    pub index_writes: usize,
    /// The index revision the bytes came from.
    pub index_revision: String,
}

impl StagedMaterialization {
    /// Number of materialized files.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether nothing was materialized.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The materialized bytes for `path`.
    #[must_use]
    pub fn file(&self, path: &str) -> Option<&MaterializedFile> {
        self.files.iter().find(|file| file.path == path)
    }

    /// Refuse a materialization that mutated the index.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`] with [`REASON_INDEX_MUTATION`].
    pub fn assert_read_only(&self) -> Result<(), AxiomError> {
        if self.index_writes == 0 && self.read_only {
            return Ok(());
        }
        Err(AxiomError::new(
            ErrorCode::Internal,
            "staged materialization must not modify the user's Git index",
        )
        .with_detail("rule", REASON_INDEX_MUTATION)
        .with_detail("index_writes", self.index_writes.to_string()))
    }

    /// The SHA-256 of the canonical inventory, so a checkpoint records exactly
    /// which index bytes it was built from.
    #[must_use]
    pub fn inventory_sha256(&self) -> String {
        let mut buffer = String::new();
        for file in &self.files {
            buffer.push_str(&file.path);
            buffer.push('\u{1f}');
            buffer.push_str(&file.sha256);
            buffer.push('\n');
        }
        graph_export::sha256_hex(buffer.as_bytes())
    }
}

/// Materialize `paths` from the Git index.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] with [`REASON_PATH_NOT_PORTABLE`] for an
///   absolute or traversing path.
/// - [`ErrorCode::NotFound`] with [`REASON_NOT_IN_INDEX`] for a path the index
///   does not hold. The working tree is never consulted as a fallback.
pub fn materialize(
    source: &dyn IndexSource,
    index_revision: &str,
    paths: &[String],
) -> Result<StagedMaterialization, AxiomError> {
    let mut files = Vec::with_capacity(paths.len());
    let mut total_bytes = 0usize;
    for path in paths {
        graph_core::paths::validate_portable_relative_path(path).map_err(|error| {
            AxiomError::new(
                ErrorCode::ValidationError,
                "a staged materialization path must be repository-relative",
            )
            .with_detail("rule", REASON_PATH_NOT_PORTABLE)
            .with_detail("path", path.clone())
            .with_detail("cause", error.message())
        })?;
        let bytes = source.index_bytes(path).ok_or_else(|| {
            AxiomError::new(
                ErrorCode::NotFound,
                "the requested path is not present in the Git index",
            )
            .with_detail("rule", REASON_NOT_IN_INDEX)
            .with_detail("path", path.clone())
        })?;
        total_bytes += bytes.len();
        files.push(MaterializedFile {
            path: path.clone(),
            sha256: graph_export::sha256_hex(&bytes),
            bytes,
        });
    }
    Ok(StagedMaterialization {
        files,
        total_bytes,
        read_only: true,
        index_writes: 0,
        index_revision: index_revision.to_owned(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::BTreeMap;

    /// A scripted index that counts how each byte source was consulted.
    struct ScriptedIndex {
        index: BTreeMap<String, Vec<u8>>,
        worktree: BTreeMap<String, Vec<u8>>,
        index_reads: Cell<usize>,
        worktree_reads: Cell<usize>,
    }

    impl ScriptedIndex {
        fn new() -> Self {
            Self {
                index: BTreeMap::new(),
                worktree: BTreeMap::new(),
                index_reads: Cell::new(0),
                worktree_reads: Cell::new(0),
            }
        }

        fn stage(mut self, path: &str, bytes: &str) -> Self {
            self.index
                .insert(path.to_owned(), bytes.as_bytes().to_vec());
            self
        }

        fn worktree(mut self, path: &str, bytes: &str) -> Self {
            self.worktree
                .insert(path.to_owned(), bytes.as_bytes().to_vec());
            self
        }
    }

    impl IndexSource for ScriptedIndex {
        fn index_bytes(&self, path: &str) -> Option<Vec<u8>> {
            self.index_reads.set(self.index_reads.get() + 1);
            self.index.get(path).cloned()
        }
        fn worktree_bytes(&self, path: &str) -> Option<Vec<u8>> {
            self.worktree_reads.set(self.worktree_reads.get() + 1);
            self.worktree.get(path).cloned()
        }
    }

    #[test]
    fn a_partially_staged_file_exports_the_index_bytes_not_the_worktree() {
        let index = ScriptedIndex::new()
            .stage("src/Auth.Api/AuthController.cs", "staged version\n")
            .worktree("src/Auth.Api/AuthController.cs", "unstaged edit\n")
            .stage("src/Auth.Api/appsettings.json", "{}\n");
        let materialized = materialize(
            &index,
            "index-rev-1",
            &[
                "src/Auth.Api/AuthController.cs".to_owned(),
                "src/Auth.Api/appsettings.json".to_owned(),
            ],
        )
        .expect("materialize");
        let file = materialized
            .file("src/Auth.Api/AuthController.cs")
            .expect("file");
        assert_eq!(file.bytes, b"staged version\n");
        assert_ne!(file.bytes, b"unstaged edit\n");
        assert_eq!(file.sha256, graph_export::sha256_hex(b"staged version\n"));
        // The working tree was never consulted, and the index was never written.
        assert_eq!(index.worktree_reads.get(), 0);
        assert_eq!(index.index_reads.get(), 2);
        assert_eq!(materialized.index_writes, 0);
        assert!(materialized.read_only);
        assert!(materialized.assert_read_only().is_ok());
        assert_eq!(materialized.index_revision, "index-rev-1");
        assert_eq!(materialized.len(), 2);
        assert!(!materialized.is_empty());
        assert!(materialized.total_bytes > 0);
        assert_eq!(materialized.inventory_sha256().len(), 64);
    }

    #[test]
    fn a_path_absent_from_the_index_is_refused_and_never_falls_back() {
        let index = ScriptedIndex::new()
            .stage("src/kept.rs", "kept\n")
            .worktree("src/untracked.rs", "untracked but present on disk\n");
        let error = materialize(&index, "index-rev-1", &["src/untracked.rs".to_owned()])
            .expect_err("not in index");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_NOT_IN_INDEX)
        );
        // The working-tree copy that does exist was still never read.
        assert_eq!(index.worktree_reads.get(), 0);
    }

    #[test]
    fn an_absolute_or_traversing_path_is_refused_before_the_index_is_read() {
        let index = ScriptedIndex::new().stage("src/kept.rs", "kept\n");
        for bad in ["D:/src/kept.rs", "../outside.rs", "/etc/passwd"] {
            let error = materialize(&index, "index-rev-1", &[bad.to_owned()])
                .expect_err("non-portable path");
            assert_eq!(error.code(), ErrorCode::ValidationError);
            assert_eq!(
                error.details().get("rule").map(String::as_str),
                Some(REASON_PATH_NOT_PORTABLE)
            );
        }
        assert_eq!(index.index_reads.get(), 0);
    }
}
