//! The generation manifest (task B-070).
//!
//! `docs/11-GRAPH-DATA-CONTRACT.md` section 5 fixes the document this module
//! writes, and the shipped `axiom-mcp` reader is the executable copy of that
//! contract. A manifest is the only place a reader learns what a generation
//! contains, so it describes the bytes exactly: every entry carries the shard's
//! generation-relative `path`, the `role` that path plays, the SHA-256 of the
//! bytes, the real byte length and the record count.
//!
//! The generation identity is `sha256` over the manifest's own canonical bytes,
//! so the identity cannot be a field of the document it hashes. A manifest that
//! carries `generation_id`, `manifest_sha256` or any other self-hash field is
//! refused here and by the reader, because such a field would make the digest
//! circular.
//!
//! The document is closed: `additionalProperties:false` in
//! `contracts/schemas/project-manifest.schema.json` means the eleven top-level
//! fields, the five entry fields and the five coverage fields are each an exact
//! set, and a document with an unknown or missing field is refused rather than
//! read as if the extra field did not exist.

use serde::{Deserialize, Serialize};

use crate::{ExportError, Result, ERR_CANONICAL, ERR_INTEGRITY, ERR_MISSING};

/// The manifest schema major this build writes and reads.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
/// The largest shard the contract allows, from section 6 (16 MiB hard cap).
pub const MAX_SHARD_BYTES: usize = 16_777_216;
/// Every role a manifest entry may declare, exactly once each.
pub const FILE_ROLES: [&str; 7] = [
    "nodes",
    "edges",
    "symbol_index",
    "outgoing_index",
    "incoming_index",
    "architecture_summary",
    "coverage",
];
/// The coverage statuses the contract allows.
pub const COVERAGE_STATUSES: [&str; 3] = ["complete_for_profile", "partial", "unsupported"];
/// The exact top-level field set of a manifest document.
pub const MANIFEST_FIELDS: [&str; 11] = [
    "schema_version",
    "solution_id",
    "project_id",
    "analysis_profile",
    "generator_version",
    "analyzer_set_hash",
    "source_fingerprint",
    "config_fingerprint",
    "dependency_fingerprint",
    "coverage",
    "files",
];
/// The exact field set of one manifest entry.
pub const ENTRY_FIELDS: [&str; 5] = ["path", "role", "sha256", "bytes", "records"];
/// The exact field set of the coverage block.
pub const COVERAGE_FIELDS: [&str; 5] = [
    "status",
    "input_files",
    "processed_files",
    "unresolved_references",
    "unsupported_patterns",
];
/// Field names that would make the generation identity circular.
pub const SELF_HASH_FIELDS: [&str; 4] = [
    "manifest_sha256",
    "generation_id",
    "manifest_id",
    "self_sha256",
];

/// Whether `candidate` is a lowercase SHA-256 digest.
#[must_use]
pub fn is_sha256_hex(candidate: &str) -> bool {
    candidate.len() == 64
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether `path` is a portable, generation-relative path.
///
/// Byte-identical to the reader's `PORTABLE_RELATIVE_RE`: not absolute, no
/// backslash, no `..` segment, no Windows drive prefix and not empty.
#[must_use]
pub fn is_portable_relative(path: &str) -> bool {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') {
        return false;
    }
    if path.as_bytes().get(1) == Some(&b':') {
        return false;
    }
    !path.split('/').any(|part| part == "..")
}

/// Whether `candidate` is a portable identifier (lowercase, digits, hyphens).
#[must_use]
pub fn is_identifier(candidate: &str) -> bool {
    let mut bytes = candidate.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    if candidate.len() > 63 {
        return false;
    }
    candidate
        .bytes()
        .skip(1)
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// One file the generation publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Path relative to the generation root, using `/` separators.
    pub path: String,
    /// The role that path plays, from [`FILE_ROLES`].
    pub role: String,
    /// SHA-256 of the file bytes.
    pub sha256: String,
    /// Exact byte length of the file.
    pub bytes: usize,
    /// Number of records in the file.
    pub records: usize,
}

impl ManifestEntry {
    /// Build an entry from the bytes it describes.
    #[must_use]
    pub fn from_bytes(
        path: impl Into<String>,
        role: impl Into<String>,
        bytes: &[u8],
        records: usize,
    ) -> Self {
        Self {
            path: path.into(),
            role: role.into(),
            sha256: crate::sha256_hex(bytes),
            bytes: bytes.len(),
            records,
        }
    }

    /// Whether these actual bytes match the entry.
    #[must_use]
    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.bytes == bytes.len() && self.sha256 == crate::sha256_hex(bytes)
    }
}

/// The coverage block of a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// One of [`COVERAGE_STATUSES`].
    pub status: String,
    /// Input files the profile declared for this project.
    pub input_files: usize,
    /// Input files the analyzers actually processed.
    pub processed_files: usize,
    /// References the generation could not resolve to a pinned node.
    pub unresolved_references: usize,
    /// Patterns the pinned analyzers deliberately do not model.
    pub unsupported_patterns: Vec<String>,
}

impl Coverage {
    /// A coverage block claiming every declared input was processed.
    #[must_use]
    pub fn complete_for_profile(
        input_files: usize,
        processed_files: usize,
        unresolved_references: usize,
    ) -> Self {
        Self {
            status: "complete_for_profile".to_owned(),
            input_files,
            processed_files,
            unresolved_references,
            unsupported_patterns: Vec::new(),
        }
    }
}

/// The content of one generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationManifest {
    /// The manifest schema major.
    pub schema_version: u32,
    /// The solution this generation belongs to.
    pub solution_id: String,
    /// The project this generation is of.
    pub project_id: String,
    /// The analysis profile the generation was produced under.
    pub analysis_profile: String,
    /// The producer version that wrote these bytes.
    pub generator_version: String,
    /// Digest of the pinned analyzer set.
    pub analyzer_set_hash: String,
    /// Digest of the analysed inputs, excluding graph outputs and absolute paths.
    pub source_fingerprint: String,
    /// Digest of the bound configuration inputs.
    pub config_fingerprint: String,
    /// Digest of the bound dependency inputs.
    pub dependency_fingerprint: String,
    /// How much of the profile's declared input this generation covers.
    pub coverage: Coverage,
    /// The shards this generation publishes, one per role at most.
    pub files: Vec<ManifestEntry>,
}

impl GenerationManifest {
    /// The canonical bytes the generation identity is defined over.
    ///
    /// Compact, lexicographic keys, one trailing LF, no BOM: exactly the form
    /// the shipped reader's canonical check accepts.
    ///
    /// # Errors
    ///
    /// [`ERR_CANONICAL`] when the document cannot be encoded.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self).map_err(|error| {
            ExportError::new(ERR_CANONICAL, format!("manifest cannot be encoded: {error}"))
        })?;
        crate::canonical::canonical_document_value(&value)
    }

    /// `sha256` over this manifest's canonical bytes.
    ///
    /// # Errors
    ///
    /// [`ERR_CANONICAL`] when the document cannot be encoded.
    pub fn generation_id(&self) -> Result<String> {
        Ok(crate::sha256_hex(&self.canonical_bytes()?))
    }

    /// Total records across every entry.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.files.iter().map(|entry| entry.records).sum()
    }

    /// Total bytes across every entry.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.files.iter().map(|entry| entry.bytes).sum()
    }

    /// Structural validation, mirroring the shipped reader's own checks.
    ///
    /// # Errors
    ///
    /// [`ERR_INTEGRITY`] when the field sets, the roles, the digests, the shard
    /// sizes or the coverage counts disagree with the contract.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(ExportError::new(
                ERR_INTEGRITY,
                format!(
                    "manifest schema major {} is not the supported major {}",
                    self.schema_version, MANIFEST_SCHEMA_VERSION
                ),
            ));
        }
        if !is_identifier(&self.solution_id) {
            return Err(ExportError::new(
                ERR_INTEGRITY,
                format!("manifest solution_id {} is not a portable identifier", self.solution_id),
            ));
        }
        if !is_identifier(&self.project_id) {
            return Err(ExportError::new(
                ERR_INTEGRITY,
                format!("manifest project_id {} is not a portable identifier", self.project_id),
            ));
        }
        for text in [
            &self.analysis_profile,
            &self.generator_version,
        ] {
            if text.is_empty() {
                return Err(ExportError::new(
                    ERR_INTEGRITY,
                    "manifest analysis_profile and generator_version must be non-empty",
                ));
            }
        }
        for digest in [
            &self.analyzer_set_hash,
            &self.source_fingerprint,
            &self.config_fingerprint,
            &self.dependency_fingerprint,
        ] {
            if !is_sha256_hex(digest) {
                return Err(ExportError::new(
                    ERR_INTEGRITY,
                    format!("manifest fingerprint {digest} is not a lowercase sha256 digest"),
                ));
            }
        }
        if !COVERAGE_STATUSES.contains(&self.coverage.status.as_str()) {
            return Err(ExportError::new(
                ERR_INTEGRITY,
                format!("manifest coverage status {} is not supported", self.coverage.status),
            ));
        }
        if self.coverage.processed_files > self.coverage.input_files {
            return Err(ExportError::new(
                ERR_INTEGRITY,
                format!(
                    "manifest coverage processed_files {} exceeds input_files {}",
                    self.coverage.processed_files, self.coverage.input_files
                ),
            ));
        }
        if self.files.is_empty() {
            return Err(ExportError::new(
                ERR_INTEGRITY,
                "manifest files must be a non-empty list",
            ));
        }
        let mut roles: Vec<&str> = Vec::new();
        for entry in &self.files {
            if !is_portable_relative(&entry.path) {
                return Err(ExportError::new(
                    ERR_INTEGRITY,
                    format!("manifest entry path {} is not a portable relative path", entry.path),
                ));
            }
            if !FILE_ROLES.contains(&entry.role.as_str()) {
                return Err(ExportError::new(
                    ERR_INTEGRITY,
                    format!("manifest entry role {} is not supported", entry.role),
                ));
            }
            if roles.contains(&entry.role.as_str()) {
                return Err(ExportError::new(
                    ERR_INTEGRITY,
                    format!("manifest declares duplicate file role {}", entry.role),
                ));
            }
            roles.push(&entry.role);
            if !is_sha256_hex(&entry.sha256) {
                return Err(ExportError::new(
                    ERR_INTEGRITY,
                    format!("manifest entry {} sha256 is not a lowercase digest", entry.path),
                ));
            }
            if entry.bytes < 1 || entry.bytes > MAX_SHARD_BYTES {
                return Err(ExportError::new(
                    ERR_INTEGRITY,
                    format!(
                        "manifest entry {} declares {} bytes, outside 1..={MAX_SHARD_BYTES}",
                        entry.path, entry.bytes
                    ),
                ));
            }
        }
        for (index, entry) in self.files.iter().enumerate() {
            if self.files[..index].iter().any(|seen| seen.path == entry.path) {
                return Err(ExportError::new(
                    ERR_INTEGRITY,
                    format!("manifest declares duplicate file path {}", entry.path),
                ));
            }
        }
        Ok(())
    }

    /// Re-read the actual files and refuse any disagreement.
    ///
    /// # Errors
    ///
    /// * [`ERR_MISSING`] when a file the manifest names was not read, or a file
    ///   was read that the manifest does not name;
    /// * [`ERR_INTEGRITY`] when a file's bytes, length or record count disagree.
    pub fn verify(&self, files: &[(String, Vec<u8>, usize)]) -> Result<()> {
        self.validate()?;
        for entry in &self.files {
            let Some((_, bytes, records)) = files.iter().find(|(path, _, _)| path == &entry.path)
            else {
                return Err(ExportError::new(
                    ERR_MISSING,
                    format!("generation is missing {}", entry.path),
                ));
            };
            if !entry.matches(bytes) {
                return Err(ExportError::new(
                    ERR_INTEGRITY,
                    format!(
                        "{} does not match its manifest entry ({} bytes vs {})",
                        entry.path,
                        bytes.len(),
                        entry.bytes
                    ),
                ));
            }
            if *records != entry.records {
                return Err(ExportError::new(
                    ERR_INTEGRITY,
                    format!(
                        "{} has {} records but the manifest says {}",
                        entry.path, records, entry.records
                    ),
                ));
            }
        }
        for (path, _, _) in files {
            if !self.files.iter().any(|entry| &entry.path == path) {
                return Err(ExportError::new(
                    ERR_MISSING,
                    format!("{path} is not named by the manifest"),
                ));
            }
        }
        Ok(())
    }

    /// Parse and validate a manifest from the exact bytes it was published as.
    ///
    /// # Errors
    ///
    /// * [`ERR_CANONICAL`] when the bytes are not the canonical encoding of
    ///   their own value, or carry a field outside the contract;
    /// * [`ERR_INTEGRITY`] when the document fails [`Self::validate`].
    pub fn from_canonical_bytes(raw: &[u8]) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_slice(raw).map_err(|error| {
            ExportError::new(ERR_CANONICAL, format!("manifest is not valid JSON: {error}"))
        })?;
        let rendered = crate::canonical::canonical_document_value(&value)?;
        if rendered != raw {
            return Err(ExportError::new(
                ERR_CANONICAL,
                "manifest is not in canonical form: it is not the compact, lexicographic, \
                 single-trailing-LF encoding of its own value",
            ));
        }
        let document = value.as_object().ok_or_else(|| {
            ExportError::new(ERR_CANONICAL, "manifest is not a JSON object")
        })?;
        for field in SELF_HASH_FIELDS {
            if document.contains_key(field) {
                return Err(ExportError::new(
                    ERR_CANONICAL,
                    format!(
                        "manifest carries its own hash field {field}; the generation identity \
                         is defined over these bytes and must not reference itself"
                    ),
                ));
            }
        }
        require_exact_keys(document.keys().map(String::as_str), &MANIFEST_FIELDS, "manifest")?;
        if let Some(coverage) = document.get("coverage").and_then(|value| value.as_object()) {
            require_exact_keys(coverage.keys().map(String::as_str), &COVERAGE_FIELDS, "coverage")?;
        }
        if let Some(entries) = document.get("files").and_then(|value| value.as_array()) {
            for entry in entries {
                if let Some(entry) = entry.as_object() {
                    require_exact_keys(
                        entry.keys().map(String::as_str),
                        &ENTRY_FIELDS,
                        "manifest entry",
                    )?;
                }
            }
        }
        let manifest: Self = serde_json::from_value(value).map_err(|error| {
            ExportError::new(ERR_INTEGRITY, format!("manifest fields are invalid: {error}"))
        })?;
        manifest.validate()?;
        Ok(manifest)
    }
}

fn require_exact_keys<'a>(
    actual: impl Iterator<Item = &'a str>,
    expected: &[&str],
    what: &str,
) -> Result<()> {
    let actual: Vec<&str> = actual.collect();
    let missing: Vec<&str> = expected
        .iter()
        .copied()
        .filter(|key| !actual.contains(key))
        .collect();
    let unknown: Vec<&str> = actual
        .iter()
        .copied()
        .filter(|key| !expected.contains(key))
        .collect();
    if !missing.is_empty() || !unknown.is_empty() {
        return Err(ExportError::new(
            ERR_CANONICAL,
            format!("{what} fields do not match the contract; missing={missing:?} unknown={unknown:?}"),
        ));
    }
    Ok(())
}

/// The header fields a manifest is assembled from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestHeader {
    /// The solution this generation belongs to.
    pub solution_id: String,
    /// The project this generation is of.
    pub project_id: String,
    /// The analysis profile the generation was produced under.
    pub analysis_profile: String,
    /// The producer version that wrote these bytes.
    pub generator_version: String,
    /// Digest of the pinned analyzer set.
    pub analyzer_set_hash: String,
    /// Digest of the analysed inputs.
    pub source_fingerprint: String,
    /// Digest of the bound configuration inputs.
    pub config_fingerprint: String,
    /// Digest of the bound dependency inputs.
    pub dependency_fingerprint: String,
    /// How much of the profile's declared input this generation covers.
    pub coverage: Coverage,
}

/// Assemble a manifest from its header and the shards it publishes.
///
/// # Errors
///
/// [`ERR_INTEGRITY`] when the assembled document fails [`GenerationManifest::validate`].
pub fn build(header: ManifestHeader, files: Vec<ManifestEntry>) -> Result<GenerationManifest> {
    let manifest = GenerationManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        solution_id: header.solution_id,
        project_id: header.project_id,
        analysis_profile: header.analysis_profile,
        generator_version: header.generator_version,
        analyzer_set_hash: header.analyzer_set_hash,
        source_fingerprint: header.source_fingerprint,
        config_fingerprint: header.config_fingerprint,
        dependency_fingerprint: header.dependency_fingerprint,
        coverage: header.coverage,
        files,
    };
    manifest.validate()?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::{
        build, Coverage, GenerationManifest, ManifestEntry, ManifestHeader, COVERAGE_FIELDS,
        MANIFEST_FIELDS,
    };
    use crate::{ERR_CANONICAL, ERR_INTEGRITY, ERR_MISSING};

    fn shard(bytes: &[u8]) -> Vec<u8> {
        crate::canonical::canonical_document_value(
            &serde_json::from_slice::<serde_json::Value>(bytes).expect("json"),
        )
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
            coverage: Coverage::complete_for_profile(2, 2, 0),
        }
    }

    fn files() -> Vec<(String, Vec<u8>, usize)> {
        vec![
            (
                "nodes/000000.json".to_owned(),
                shard(br#"[{"a":1},{"b":2}]"#),
                2,
            ),
            (
                "edges/000000.json".to_owned(),
                shard(br#"[{"c":3}]"#),
                1,
            ),
        ]
    }

    fn manifest_for(actual: &[(String, Vec<u8>, usize)]) -> GenerationManifest {
        let entries = actual
            .iter()
            .map(|(path, bytes, records)| {
                let role = path.split('/').next().expect("role");
                ManifestEntry::from_bytes(path.clone(), role, bytes, *records)
            })
            .collect();
        build(header(), entries).expect("manifest")
    }

    #[test]
    fn actual_bytes_counts_and_hashes_match_the_entries() {
        let actual = files();
        let manifest = manifest_for(&actual);
        assert_eq!(manifest.record_count(), 3);
        assert_eq!(
            manifest.total_bytes(),
            actual.iter().map(|(_, bytes, _)| bytes.len()).sum::<usize>()
        );
        manifest.verify(&actual).expect("verifies");
        let id = manifest.generation_id().expect("id");
        assert_eq!(id.len(), 64);
        assert_eq!(
            id,
            crate::sha256_hex(&manifest.canonical_bytes().expect("bytes"))
        );
    }

    #[test]
    fn a_tampered_byte_is_rejected() {
        let mut actual = files();
        let manifest = manifest_for(&actual);
        actual[0].1.push(b' ');
        let error = manifest.verify(&actual).expect_err("must refuse");
        assert_eq!(error.code, ERR_INTEGRITY);
    }

    #[test]
    fn a_file_the_manifest_does_not_name_is_rejected() {
        let mut actual = files();
        let manifest = manifest_for(&actual);
        actual.push(("coverage.json".to_owned(), shard(br#"{"x":1}"#), 1));
        let error = manifest.verify(&actual).expect_err("must refuse");
        assert_eq!(error.code, ERR_MISSING);
    }

    #[test]
    fn the_identity_hashes_the_canonical_bytes_without_self_reference() {
        let actual = files();
        let first = manifest_for(&actual);
        let second = manifest_for(&actual);
        assert_eq!(
            first.generation_id().expect("id"),
            second.generation_id().expect("id")
        );
        let mut changed = actual;
        changed[0].2 = 99;
        assert_ne!(
            first.generation_id().expect("id"),
            manifest_for(&changed).generation_id().expect("id")
        );
    }

    #[test]
    fn canonical_bytes_round_trip_through_from_canonical_bytes() {
        let manifest = manifest_for(&files());
        let bytes = manifest.canonical_bytes().expect("bytes");
        let parsed = GenerationManifest::from_canonical_bytes(&bytes).expect("parse");
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn a_manifest_carrying_a_self_hash_field_is_refused() {
        let manifest = manifest_for(&files());
        let mut value: serde_json::Value =
            serde_json::from_slice(&manifest.canonical_bytes().expect("bytes")).expect("json");
        value["generation_id"] = serde_json::Value::String("0".repeat(64));
        let bytes =
            crate::canonical::canonical_document_value(&value).expect("canonical");
        let error = GenerationManifest::from_canonical_bytes(&bytes).expect_err("must refuse");
        assert_eq!(error.code, ERR_CANONICAL, "{}", error.message);
    }

    #[test]
    fn a_manifest_with_an_unknown_field_is_refused() {
        let manifest = manifest_for(&files());
        let mut value: serde_json::Value =
            serde_json::from_slice(&manifest.canonical_bytes().expect("bytes")).expect("json");
        value["extra"] = serde_json::Value::from(1);
        let bytes = crate::canonical::canonical_document_value(&value).expect("canonical");
        let error = GenerationManifest::from_canonical_bytes(&bytes).expect_err("must refuse");
        assert_eq!(error.code, ERR_CANONICAL, "{}", error.message);
    }

    #[test]
    fn a_duplicate_role_is_refused() {
        let actual = files();
        let mut entries: Vec<ManifestEntry> = Vec::new();
        for (index, (path, bytes, records)) in actual.iter().enumerate() {
            let role = if index == 1 { "nodes" } else { "nodes" };
            entries.push(ManifestEntry::from_bytes(path.clone(), role, bytes, *records));
        }
        let error = build(header(), entries).expect_err("must refuse");
        assert_eq!(error.code, ERR_INTEGRITY, "{}", error.message);
    }

    #[test]
    fn a_non_portable_path_is_refused() {
        let actual = files();
        for bad in ["../escape.json", "nodes\\x.json", "C:/tmp/x.json", "/abs.json"] {
            let entries = vec![ManifestEntry::from_bytes(
                bad,
                "nodes",
                &actual[0].1,
                2,
            )];
            let error = build(header(), entries).expect_err("must refuse");
            assert_eq!(error.code, ERR_INTEGRITY, "{bad}: {}", error.message);
        }
    }

    #[test]
    fn an_oversized_shard_is_refused() {
        let actual = files();
        let mut entry = ManifestEntry::from_bytes("nodes/000000.json", "nodes", &actual[0].1, 2);
        entry.bytes = super::MAX_SHARD_BYTES + 1;
        let error = build(header(), vec![entry]).expect_err("must refuse");
        assert_eq!(error.code, ERR_INTEGRITY);
        let mut empty = ManifestEntry::from_bytes("nodes/000000.json", "nodes", &actual[0].1, 2);
        empty.bytes = 0;
        let error = build(header(), vec![empty]).expect_err("must refuse");
        assert_eq!(error.code, ERR_INTEGRITY);
    }

    #[test]
    fn a_non_canonical_byte_encoding_is_refused() {
        let manifest = manifest_for(&files());
        let pretty = serde_json::to_vec_pretty(
            &serde_json::from_slice::<serde_json::Value>(
                &manifest.canonical_bytes().expect("bytes"),
            )
            .expect("json"),
        )
        .expect("pretty");
        let error = GenerationManifest::from_canonical_bytes(&pretty).expect_err("must refuse");
        assert_eq!(error.code, ERR_CANONICAL);
    }

    #[test]
    fn an_unknown_schema_major_is_refused() {
        let manifest = manifest_for(&files());
        let mut value: serde_json::Value =
            serde_json::from_slice(&manifest.canonical_bytes().expect("bytes")).expect("json");
        value["schema_version"] = serde_json::Value::from(2);
        let bytes = crate::canonical::canonical_document_value(&value).expect("canonical");
        let error = GenerationManifest::from_canonical_bytes(&bytes).expect_err("must refuse");
        assert_eq!(error.code, ERR_INTEGRITY, "{}", error.message);
    }

    #[test]
    fn a_coverage_block_with_a_missing_field_is_refused() {
        let manifest = manifest_for(&files());
        let mut value: serde_json::Value =
            serde_json::from_slice(&manifest.canonical_bytes().expect("bytes")).expect("json");
        let coverage = value["coverage"].as_object_mut().expect("coverage");
        coverage.remove("unsupported_patterns");
        assert_eq!(COVERAGE_FIELDS.len(), 5);
        assert_eq!(MANIFEST_FIELDS.len(), 11);
        let bytes = crate::canonical::canonical_document_value(&value).expect("canonical");
        let error = GenerationManifest::from_canonical_bytes(&bytes).expect_err("must refuse");
        assert_eq!(error.code, ERR_CANONICAL);
    }
}

