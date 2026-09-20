//! The gate a staged generation passes before publication (task B-072).
//!
//! Validation covers three separate claims: the manifest is a closed,
//! canonical document with no self-reference, every named file matches its
//! recorded bytes and record count, and every published document is still in
//! canonical form. A corrupt shard or a missing manifest fails here, which is
//! before the current pointer can change.

use crate::canonical;
use crate::manifest::GenerationManifest;
use crate::{ExportError, Result, ERR_MISSING};
use std::fs;
use std::path::Path;

/// Error code for a shard whose bytes are no longer canonical.
pub const ERR_NOT_CANONICAL: &str = "export-not-canonical";

/// What validation actually checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    /// The generation identity: `sha256` over the manifest's canonical bytes.
    pub generation_id: String,
    /// Files verified.
    pub files: usize,
    /// Records counted.
    pub records: usize,
    /// Bytes verified.
    pub bytes: usize,
}

/// Read and check the manifest of a generation directory.
///
/// # Errors
///
/// * [`ERR_MISSING`] when `manifest.json` does not exist or is not readable as
///   JSON;
/// * [`crate::ERR_CANONICAL`] when the bytes are not the canonical encoding of
///   their own value or carry a field outside the contract;
/// * [`ERR_INTEGRITY`] when the document fails structural validation.
pub fn read_manifest(generation_dir: &Path) -> Result<GenerationManifest> {
    let path = generation_dir.join("manifest.json");
    if !path.is_file() {
        return Err(ExportError::new(
            ERR_MISSING,
            format!("no manifest at {}", path.display()),
        ));
    }
    let bytes = fs::read(&path).map_err(|error| ExportError::io(&error))?;
    GenerationManifest::from_canonical_bytes(&bytes)
}

/// Validate already-loaded files against the manifest.
///
/// # Errors
///
/// * [`ERR_MISSING`] when the file set and the manifest disagree;
/// * [`ERR_INTEGRITY`] when bytes, length or record count disagree;
/// * [`ERR_NOT_CANONICAL`] when a published document is not canonical.
pub fn validate_files(
    files: &[(String, Vec<u8>, usize)],
    manifest: &GenerationManifest,
) -> Result<ValidationReport> {
    manifest.verify(files)?;
    let mut bytes_total = 0;
    for (path, bytes, _) in files {
        if !canonical::is_canonical_text(&String::from_utf8_lossy(bytes)) {
            return Err(ExportError::new(
                ERR_NOT_CANONICAL,
                format!("published shard {path} is not in canonical form"),
            ));
        }
        bytes_total += bytes.len();
    }
    Ok(ValidationReport {
        generation_id: manifest.generation_id()?,
        files: files.len(),
        records: manifest.record_count(),
        bytes: bytes_total,
    })
}

/// Read a generation directory and validate every shard in it.
///
/// # Errors
///
/// The same errors as [`read_manifest`] and [`validate_files`], plus
/// [`crate::ERR_IO`].
pub fn validate_generation(generation_dir: &Path) -> Result<ValidationReport> {
    let manifest = read_manifest(generation_dir)?;
    let mut files = Vec::with_capacity(manifest.files.len());
    for entry in &manifest.files {
        let path = generation_dir.join(&entry.path);
        let bytes = fs::read(&path).map_err(|error| {
            ExportError::new(ERR_MISSING, format!("{}: {error}", path.display()))
        })?;
        files.push((entry.path.clone(), bytes, entry.records));
    }
    validate_files(&files, &manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical;
    use crate::manifest::{self, Coverage, ManifestEntry, ManifestHeader};
    use crate::ERR_INTEGRITY;
    use std::fs;

    fn shard_bytes() -> Vec<u8> {
        canonical::canonical_document_value(&serde_json::json!([
            {"key": "edge:a->b", "kind": "edge", "body": {"from": "a", "to": "b"}}
        ]))
        .expect("canonical")
    }

    fn header() -> ManifestHeader {
        ManifestHeader {
            solution_id: "demo-solution".to_owned(),
            project_id: "demo-project".to_owned(),
            analysis_profile: "default".to_owned(),
            generator_version: "0.1.0".to_owned(),
            analyzer_set_hash: "a".repeat(64),
            source_fingerprint: "b".repeat(64),
            config_fingerprint: "c".repeat(64),
            dependency_fingerprint: "d".repeat(64),
            coverage: Coverage::complete_for_profile(1, 1, 0),
        }
    }

    fn write_generation(dir: &Path, shard: Vec<u8>) -> GenerationManifest {
        fs::create_dir_all(dir.join("nodes")).expect("mkdir");
        let manifest = manifest::build(
            header(),
            vec![ManifestEntry::from_bytes(
                "nodes/000000.json",
                "nodes",
                &shard,
                1,
            )],
        )
        .expect("manifest");
        fs::write(dir.join("nodes/000000.json"), &shard).expect("shard");
        fs::write(
            dir.join("manifest.json"),
            manifest.canonical_bytes().expect("bytes"),
        )
        .expect("manifest file");
        manifest
    }

    #[test]
    fn a_consistent_generation_validates_and_counts_its_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let generation = dir.path().join("generations/gid-ok");
        let manifest = write_generation(&generation, shard_bytes());
        let report = validate_generation(&generation).expect("valid");
        assert_eq!(report.generation_id, manifest.generation_id().expect("id"));
        assert_eq!(report.files, 1);
        assert_eq!(report.records, 1);
    }

    #[test]
    fn a_corrupt_shard_is_rejected_before_publication() {
        let dir = tempfile::tempdir().expect("tempdir");
        let generation = dir.path().join("generations/gid-bad");
        write_generation(&generation, shard_bytes());
        let mut shard = fs::read(generation.join("nodes/000000.json")).expect("read");
        shard[15] = b'X';
        fs::write(generation.join("nodes/000000.json"), &shard).expect("write");
        let error = validate_generation(&generation).expect_err("corrupt shard must fail");
        assert_eq!(error.code, ERR_INTEGRITY);
    }

    #[test]
    fn a_missing_manifest_is_reported_as_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let generation = dir.path().join("generations/gid-none");
        fs::create_dir_all(&generation).expect("mkdir");
        let error = validate_generation(&generation).expect_err("missing manifest must fail");
        assert_eq!(error.code, ERR_MISSING);
    }

    #[test]
    fn a_non_canonical_shard_body_is_rejected_even_when_its_hash_matches() {
        let dir = tempfile::tempdir().expect("tempdir");
        let generation = dir.path().join("generations/gid-space");
        let untidy = b"[{\"body\": {  }, \"key\": \"edge:a->b\", \"kind\": \"edge\"}]\n".to_vec();
        write_generation(&generation, untidy);
        let error = validate_generation(&generation).expect_err("non-canonical must fail");
        assert_eq!(error.code, ERR_NOT_CANONICAL);
    }

    #[test]
    fn a_manifest_that_is_not_canonical_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let generation = dir.path().join("generations/gid-pretty");
        write_generation(&generation, shard_bytes());
        let bytes = fs::read(generation.join("manifest.json")).expect("read");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let pretty = serde_json::to_vec_pretty(&value).expect("pretty");
        fs::write(generation.join("manifest.json"), pretty).expect("write");
        let error = validate_generation(&generation).expect_err("non-canonical manifest must fail");
        assert_eq!(error.code, crate::ERR_CANONICAL);
    }
}
