//! Same-volume staging that is never readable (task B-071).
//!
//! A generation is written under `<root>/.staging/<generation-id>/` and only
//! becomes readable after [`SealedGeneration::install`] moves it under
//! `<root>/generations/<generation-id>/`. Nothing in this module writes the
//! current pointer, so a failed or partial write cannot advance it.
//!
//! Only canonical JSON documents are staged. A shard is a single JSON array or
//! object, never a sequence of JSONL lines, and the record count a manifest
//! declares is the count the shipped reader recomputes: an array holds its
//! length, an object holds exactly one.

use crate::canonical;
use crate::manifest::{self, GenerationManifest, ManifestEntry, ManifestHeader};
use crate::{ExportError, Result, ERR_CANONICAL};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The directory a generation is staged in, relative to the export root.
pub const STAGING_DIR: &str = ".staging";
/// The directory readable generations live in, relative to the export root.
pub const GENERATIONS_DIR: &str = "generations";
/// Error code for a staged path that would become readable before publication.
pub const ERR_STAGING_PATH: &str = "export-staging-path";
/// Error code for sealing a staging directory that has no files.
pub const ERR_STAGING_INCOMPLETE: &str = "export-staging-incomplete";

/// Where a publication writes, and where a reader may look.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingLayout {
    root: PathBuf,
}

impl StagingLayout {
    /// A layout rooted at the export root.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The export root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The staging directory of one generation. Never readable.
    #[must_use]
    pub fn staging_dir(&self, generation_id: &str) -> PathBuf {
        self.root.join(STAGING_DIR).join(generation_id)
    }

    /// The readable directory of one generation.
    #[must_use]
    pub fn generation_dir(&self, generation_id: &str) -> PathBuf {
        self.root.join(GENERATIONS_DIR).join(generation_id)
    }

    /// Whether a generation-relative path is visible to a reader.
    #[must_use]
    pub fn is_reader_visible(&self, relative: &str) -> bool {
        let normalized = relative.replace('\\', "/");
        !normalized.starts_with(STAGING_DIR)
            && normalized.starts_with(GENERATIONS_DIR)
            && !normalized.contains("..")
    }

    /// Start staging a generation.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ERR_IO`] when the staging directory cannot be created.
    pub fn begin(&self, generation_id: &str) -> Result<StagedGeneration> {
        let dir = self.staging_dir(generation_id);
        fs::create_dir_all(&dir).map_err(|error| ExportError::io(&error))?;
        Ok(StagedGeneration {
            layout: self.clone(),
            generation_id: generation_id.to_owned(),
            dir,
            files: Vec::new(),
            sealed: false,
        })
    }

    /// Bytes already staged for a generation, used for the disk budget.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ERR_IO`] when a staged file cannot be inspected.
    pub fn staged_bytes(&self, generation_id: &str) -> Result<u64> {
        let dir = self.staging_dir(generation_id);
        if !dir.is_dir() {
            return Ok(0);
        }
        let mut total = 0_u64;
        for entry in fs::read_dir(&dir).map_err(|error| ExportError::io(&error))? {
            let entry = entry.map_err(|error| ExportError::io(&error))?;
            let metadata = entry.metadata().map_err(|error| ExportError::io(&error))?;
            if metadata.is_file() {
                total += metadata.len();
            }
        }
        Ok(total)
    }
}

/// One file staged for publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedFile {
    /// Path relative to the generation root, using `/` separators.
    pub path: String,
    /// The role that path plays.
    pub role: String,
    /// Exact byte length written.
    pub bytes: usize,
    /// Records the document holds.
    pub records: usize,
    /// SHA-256 of the written bytes.
    pub sha256: String,
}

/// A generation that is being written and is not yet readable.
#[derive(Debug)]
pub struct StagedGeneration {
    layout: StagingLayout,
    generation_id: String,
    dir: PathBuf,
    files: Vec<StagedFile>,
    sealed: bool,
}

impl StagedGeneration {
    /// The generation identity being staged.
    #[must_use]
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    /// The staging directory. It is not under a readable generation path.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Files staged so far.
    #[must_use]
    pub fn files(&self) -> &[StagedFile] {
        &self.files
    }

    /// Whether this generation has been sealed.
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Stage one already-encoded document under the role it plays.
    ///
    /// # Errors
    ///
    /// * [`ERR_STAGING_PATH`] when `relative_path` is absolute, escapes the
    ///   staging directory, or would be readable before publication;
    /// * [`crate::ERR_IO`] when the write fails, including a full volume. A full
    ///   volume cannot advance the current pointer because this module never
    ///   writes it.
    pub fn write(&mut self, relative_path: &str, role: &str, bytes: &[u8]) -> Result<StagedFile> {
        let target = self.target(relative_path)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| ExportError::io(&error))?;
        }
        let mut file = fs::File::create(&target).map_err(|error| ExportError::io(&error))?;
        file.write_all(bytes)
            .map_err(|error| ExportError::io(&error))?;
        file.sync_all().map_err(|error| ExportError::io(&error))?;
        let staged = StagedFile {
            path: relative_path.replace('\\', "/"),
            role: role.to_owned(),
            bytes: bytes.len(),
            records: count_records(bytes)?,
            sha256: crate::sha256_hex(bytes),
        };
        self.files.push(staged.clone());
        Ok(staged)
    }

    /// Stage one canonical JSON document under the role it plays.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::write`] plus [`ERR_CANONICAL`].
    pub fn write_document(
        &mut self,
        relative_path: &str,
        role: &str,
        value: &serde_json::Value,
    ) -> Result<StagedFile> {
        let bytes = canonical::canonical_document_value(value)?;
        self.write(relative_path, role, &bytes)
    }

    /// Stage one canonical document holding an array of records.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::write_document`].
    pub fn write_records(
        &mut self,
        relative_path: &str,
        role: &str,
        records: &[serde_json::Value],
    ) -> Result<StagedFile> {
        self.write_document(
            relative_path,
            role,
            &serde_json::Value::Array(records.to_vec()),
        )
    }

    /// Stage one shard through a caller-supplied sink, so a failing volume can
    /// be injected instead of filling a real disk.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ERR_IO`] with the sink's own error, and stages nothing.
    pub fn write_through<W: Write>(
        &mut self,
        sink: &mut W,
        relative_path: &str,
        role: &str,
        bytes: &[u8],
    ) -> Result<StagedFile> {
        self.target(relative_path)?;
        sink.write_all(bytes)
            .map_err(|error| ExportError::io(&error))?;
        sink.flush().map_err(|error| ExportError::io(&error))?;
        Ok(StagedFile {
            path: relative_path.replace('\\', "/"),
            role: role.to_owned(),
            bytes: bytes.len(),
            records: count_records(bytes)?,
            sha256: crate::sha256_hex(bytes),
        })
    }

    /// Re-read every staged file, record its hash and build the manifest.
    ///
    /// # Errors
    ///
    /// * [`ERR_STAGING_INCOMPLETE`] when nothing was staged;
    /// * [`crate::ERR_IO`] when a staged file cannot be re-read;
    /// * [`crate::ERR_INTEGRITY`] when the assembled manifest breaks the contract.
    pub fn seal(self, header: ManifestHeader) -> Result<SealedGeneration> {
        if self.files.is_empty() {
            return Err(ExportError::new(
                ERR_STAGING_INCOMPLETE,
                format!("generation {} staged no files", self.generation_id),
            ));
        }
        let mut entries = Vec::with_capacity(self.files.len());
        for staged in &self.files {
            let bytes = fs::read(self.dir.join(&staged.path))
                .map_err(|error| ExportError::io(&error))?;
            let records = count_records(&bytes)?;
            entries.push(ManifestEntry::from_bytes(
                staged.path.clone(),
                staged.role.clone(),
                &bytes,
                records,
            ));
        }
        let manifest = manifest::build(header, entries)?;
        let generation_id = manifest.generation_id()?;
        Ok(SealedGeneration {
            layout: self.layout,
            generation_id,
            dir: self.dir,
            manifest,
        })
    }

    fn target(&self, relative_path: &str) -> Result<PathBuf> {
        let normalized = relative_path.replace('\\', "/");
        let rejected =
            |why: &str| ExportError::new(ERR_STAGING_PATH, format!("{relative_path}: {why}"));
        if normalized.is_empty()
            || Path::new(&normalized).is_absolute()
            || graph_core::paths::is_absolute_host_path(&normalized)
        {
            return Err(rejected("a staged path must be relative"));
        }
        if normalized.split('/').any(|part| part == "..") {
            return Err(rejected("a staged path may not escape the staging root"));
        }
        if self.layout.is_reader_visible(&normalized) {
            return Err(rejected(
                "a staged path may not be readable before publication",
            ));
        }
        Ok(self.dir.join(&normalized))
    }
}

/// A staged generation whose bytes have been hashed and inventoried.
#[derive(Debug)]
pub struct SealedGeneration {
    layout: StagingLayout,
    generation_id: String,
    dir: PathBuf,
    manifest: GenerationManifest,
}

impl SealedGeneration {
    /// The verified manifest.
    #[must_use]
    pub const fn manifest(&self) -> &GenerationManifest {
        &self.manifest
    }

    /// The generation identity: `sha256` over the manifest's canonical bytes.
    ///
    /// The caller must publish exactly [`GenerationManifest::canonical_bytes`]
    /// as `manifest.json`, or the generation directory name would no longer
    /// name the bytes a reader hashes.
    ///
    /// # Errors
    ///
    /// [`ERR_CANONICAL`] when the manifest cannot be encoded.
    pub fn manifest_bytes(&self) -> Result<Vec<u8>> {
        self.manifest.canonical_bytes()
    }

    /// The generation identity the manifest computed.
    #[must_use]
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    /// Total records across every staged file.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.manifest.record_count()
    }

    /// Total bytes across every staged file.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.manifest.total_bytes()
    }

    /// Re-read the staged bytes and refuse any disagreement with the manifest.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ERR_MISSING`] or [`crate::ERR_INTEGRITY`] through
    /// [`GenerationManifest::verify`].
    pub fn verify(&self) -> Result<()> {
        let mut files = Vec::with_capacity(self.manifest.files.len());
        for entry in &self.manifest.files {
            let bytes =
                fs::read(self.dir.join(&entry.path)).map_err(|error| ExportError::io(&error))?;
            files.push((entry.path.clone(), bytes, entry.records));
        }
        self.manifest.verify(&files)
    }

    /// Move the staged generation into its readable directory.
    ///
    /// # Errors
    ///
    /// * [`crate::ERR_INTEGRITY`] when a staged byte changed after sealing;
    /// * [`crate::ERR_IO`] when the move fails.
    pub fn install(&self) -> Result<PathBuf> {
        self.verify()?;
        let target = self.layout.generation_dir(&self.generation_id);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| ExportError::io(&error))?;
        }
        if target.exists() {
            return Err(ExportError::new(
                crate::ERR_INTEGRITY,
                format!("generation {} is already installed", self.generation_id),
            ));
        }
        fs::rename(&self.dir, &target).map_err(|error| ExportError::io(&error))?;
        Ok(target)
    }
}

/// Number of records in one canonical document.
///
/// An array holds its length and an object holds exactly one, which is the rule
/// the shipped `axiom-mcp` reader recomputes from the same bytes. A document
/// that is neither is refused here rather than given a guessed count.
///
/// # Errors
///
/// [`ERR_CANONICAL`] when `bytes` are not a canonical JSON array or object.
pub fn count_records(bytes: &[u8]) -> Result<usize> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        ExportError::new(ERR_CANONICAL, format!("shard is not valid JSON: {error}"))
    })?;
    match value {
        serde_json::Value::Array(items) => Ok(items.len()),
        serde_json::Value::Object(_) => Ok(1),
        _ => Err(ExportError::new(
            ERR_CANONICAL,
            "a shard must be a JSON array or a JSON object",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Coverage;
    use serde_json::json;
    use std::io;

    #[derive(Default)]
    struct FullVolume {
        written: usize,
        limit: usize,
    }

    impl Write for FullVolume {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.written + buffer.len() > self.limit {
                return Err(io::Error::new(io::ErrorKind::StorageFull, "volume is full"));
            }
            self.written += buffer.len();
            Ok(buffer.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn header(project: &str) -> ManifestHeader {
        ManifestHeader {
            solution_id: "demo-solution".to_owned(),
            project_id: project.to_owned(),
            analysis_profile: "default".to_owned(),
            generator_version: "0.1.0".to_owned(),
            analyzer_set_hash: "a".repeat(64),
            source_fingerprint: "b".repeat(64),
            config_fingerprint: "c".repeat(64),
            dependency_fingerprint: "d".repeat(64),
            coverage: Coverage::complete_for_profile(1, 1, 0),
        }
    }

    fn records() -> Vec<serde_json::Value> {
        vec![json!({"from": "a", "to": "b", "relation": "calls"})]
    }

    #[test]
    fn staged_files_are_outside_every_readable_generation_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StagingLayout::new(dir.path());
        let mut staged = layout.begin("gid-1").expect("begin");
        staged
            .write_records("nodes/000000.json", "nodes", &records())
            .expect("write");
        let staged_path = staged.dir().join("nodes/000000.json");
        assert!(staged_path.is_file());
        assert!(!layout.is_reader_visible(&format!("{STAGING_DIR}/gid-1/nodes/000000.json")));
        assert!(!layout.generation_dir("gid-1").exists());
        assert!(!dir.path().join("current.json").exists());
        let sealed = staged.seal(header("demo-project")).expect("seal");
        assert_eq!(sealed.record_count(), 1);
        let install_root = sealed.install().expect("install");
        assert_eq!(install_root, layout.generation_dir(sealed.generation_id()));
        assert!(layout.is_reader_visible(&format!(
            "{GENERATIONS_DIR}/{}/nodes/000000.json",
            sealed.generation_id()
        )));
    }

    #[test]
    fn a_record_count_follows_the_array_and_object_rule() {
        assert_eq!(count_records(b"[{\"a\":1},{\"b\":2}]\n").expect("array"), 2);
        assert_eq!(count_records(b"[ ]\n").expect("empty array"), 0);
        assert_eq!(count_records(b"{\"a\":1}\n").expect("object"), 1);
        let error = count_records(b"{\"a\":1}\n{\"b\":2}\n").expect_err("jsonl must fail");
        assert_eq!(error.code, ERR_CANONICAL);
        let error = count_records(b"5\n").expect_err("scalar must fail");
        assert_eq!(error.code, ERR_CANONICAL);
    }

    #[test]
    fn a_staged_path_that_would_be_readable_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StagingLayout::new(dir.path());
        let mut staged = layout.begin("gid-2").expect("begin");
        for bad in [
            "../escape.json",
            "generations/gid-2/nodes/000000.json",
            "C:/tmp/x.json",
        ] {
            let error = staged
                .write(bad, "nodes", b"[{}]\n")
                .expect_err("must be rejected");
            assert_eq!(error.code, ERR_STAGING_PATH, "{bad}");
        }
        assert!(staged.files().is_empty());
        assert!(!layout.generation_dir("gid-2").exists());
    }

    #[test]
    fn a_disk_full_write_fails_and_never_advances_the_pointer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StagingLayout::new(dir.path());
        let mut staged = layout.begin("gid-3").expect("begin");
        let mut volume = FullVolume {
            written: 0,
            limit: 4,
        };
        let error = staged
            .write_through(&mut volume, "nodes/000000.json", "nodes", b"[{}]\n")
            .expect_err("a full volume must fail the write");
        assert_eq!(error.code, crate::ERR_IO);
        assert!(
            error.message.contains("volume is full"),
            "{}",
            error.message
        );
        assert!(staged.files().is_empty());
        assert!(staged.seal(header("demo-project")).is_err());
        assert!(!dir.path().join("current.json").exists());
        assert!(!layout.generation_dir("gid-3").exists());
    }

    #[test]
    fn sealing_requires_at_least_one_staged_shard() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StagingLayout::new(dir.path());
        let staged = layout.begin("gid-4").expect("begin");
        let error = staged
            .seal(header("demo-project"))
            .expect_err("empty staging cannot seal");
        assert_eq!(error.code, ERR_STAGING_INCOMPLETE);
    }

    #[test]
    fn the_generation_id_is_the_digest_of_the_manifest_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = StagingLayout::new(dir.path());
        let mut staged = layout.begin("pending").expect("begin");
        staged
            .write_records("nodes/000000.json", "nodes", &records())
            .expect("write");
        let sealed = staged.seal(header("demo-project")).expect("seal");
        let bytes = sealed.manifest_bytes().expect("bytes");
        assert_eq!(crate::sha256_hex(&bytes), sealed.generation_id());
        assert_eq!(
            crate::manifest::GenerationManifest::from_canonical_bytes(&bytes)
                .expect("parse")
                .generation_id()
                .expect("id"),
            sealed.generation_id()
        );
    }
}
