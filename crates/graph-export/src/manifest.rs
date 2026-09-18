//! The generation manifest (task B-070).
//!
//! A manifest is the only place a reader learns what a generation contains, so
//! it must describe the bytes exactly. Every entry carries the real byte length,
//! the SHA-256 of those bytes and the record count, and [`GenerationManifest::verify`]
//! re-reads the actual files and refuses any disagreement.
//!
//! The generation identity is a digest of the manifest's content, so it cannot
//! be a field of the content it hashes. `generation_id` is computed over the
//! entries, record count and byte total, and the field holding it is excluded;
//! [`GenerationManifest::identity_is_self_consistent`] recomputes it and proves
//! there is no circular self-reference.

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_value;
use crate::{ExportError, Result, ERR_INTEGRITY, ERR_MISSING};

/// One file the generation publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Path relative to the generation root, using `/` separators.
    pub relative_path: String,
    /// Exact byte length of the file.
    pub byte_len: usize,
    /// SHA-256 of the file bytes.
    pub sha256: String,
    /// Number of records in the file.
    pub record_count: usize,
}

impl ManifestEntry {
    /// Build an entry from the bytes it describes.
    #[must_use]
    pub fn from_bytes(relative_path: impl Into<String>, bytes: &[u8], record_count: usize) -> Self {
        Self {
            relative_path: relative_path.into(),
            byte_len: bytes.len(),
            sha256: crate::sha256_hex(bytes),
            record_count,
        }
    }

    /// Whether these actual bytes match the entry.
    #[must_use]
    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.byte_len == bytes.len() && self.sha256 == crate::sha256_hex(bytes)
    }
}

/// The content of one generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationManifest {
    /// Digest of the manifest content, excluding this field.
    pub generation_id: String,
    /// Entries, in the order the producer published them.
    pub entries: Vec<ManifestEntry>,
    /// Total records across every entry.
    pub record_count: usize,
    /// Total bytes across every entry.
    pub total_bytes: usize,
}

impl GenerationManifest {
    /// The manifest content that the generation identity hashes.
    fn identity_content(&self) -> serde_json::Value {
        serde_json::json!({
            "entries": self.entries,
            "record_count": self.record_count,
            "total_bytes": self.total_bytes,
        })
    }

    /// Recompute the generation identity from the content.
    pub fn computed_generation_id(&self) -> Result<String> {
        Ok(crate::sha256_hex(
            canonical_value(&self.identity_content())?.as_bytes(),
        ))
    }

    /// Whether the recorded identity matches the content it describes.
    #[must_use]
    pub fn identity_is_self_consistent(&self) -> bool {
        self.computed_generation_id()
            .is_ok_and(|computed| computed == self.generation_id)
    }

    /// Re-read the actual files and refuse any disagreement.
    ///
    /// # Errors
    ///
    /// * [`ERR_MISSING`] when a file the manifest names was not read, or a file
    ///   was read that the manifest does not name;
    /// * [`ERR_INTEGRITY`] when a file's bytes, length or record count disagree.
    pub fn verify(&self, files: &[(String, Vec<u8>, usize)]) -> Result<()> {
        let mut seen: Vec<&str> = Vec::new();
        for entry in &self.entries {
            let Some((_, bytes, records)) = files
                .iter()
                .find(|(path, _, _)| path == &entry.relative_path)
            else {
                return Err(ExportError::new(
                    ERR_MISSING,
                    format!("generation is missing {}", entry.relative_path),
                ));
            };
            if !entry.matches(bytes) {
                return Err(ExportError::new(
                    ERR_INTEGRITY,
                    format!(
                        "{} does not match its manifest entry ({} bytes vs {})",
                        entry.relative_path,
                        bytes.len(),
                        entry.byte_len
                    ),
                ));
            }
            if *records != entry.record_count {
                return Err(ExportError::new(
                    ERR_INTEGRITY,
                    format!(
                        "{} has {} records but the manifest says {}",
                        entry.relative_path, records, entry.record_count
                    ),
                ));
            }
            seen.push(&entry.relative_path);
        }
        for (path, _, _) in files {
            if !seen.contains(&path.as_str()) {
                return Err(ExportError::new(
                    ERR_MISSING,
                    format!("{path} is not named by the manifest"),
                ));
            }
        }
        if !self.identity_is_self_consistent() {
            return Err(ExportError::new(
                ERR_INTEGRITY,
                "the generation identity does not match the manifest content",
            ));
        }
        Ok(())
    }
}

/// Build a manifest from the files a generation contains.
pub fn build(entries: Vec<ManifestEntry>) -> Result<GenerationManifest> {
    let record_count = entries.iter().map(|entry| entry.record_count).sum();
    let total_bytes = entries.iter().map(|entry| entry.byte_len).sum();
    let mut manifest = GenerationManifest {
        generation_id: String::new(),
        entries,
        record_count,
        total_bytes,
    };
    manifest.generation_id = manifest.computed_generation_id()?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{build, ManifestEntry};
    use crate::canonical::canonical_document;
    use crate::{GraphRecord, ERR_INTEGRITY, ERR_MISSING};

    fn files() -> Vec<(String, Vec<u8>, usize)> {
        let first = canonical_document(&[GraphRecord::new(
            "e1",
            "edge",
            json!({"from": "a", "to": "b"}),
        )])
        .expect("canonical");
        let second = canonical_document(&[GraphRecord::new(
            "e2",
            "edge",
            json!({"from": "b", "to": "c"}),
        )])
        .expect("canonical");
        vec![
            ("bucket-002".to_string(), first, 1),
            ("bucket-007".to_string(), second, 1),
        ]
    }

    #[test]
    fn actual_bytes_counts_and_hashes_match_the_entries() {
        let actual = files();
        let entries: Vec<ManifestEntry> = actual
            .iter()
            .map(|(path, bytes, records)| ManifestEntry::from_bytes(path.clone(), bytes, *records))
            .collect();
        let manifest = build(entries).expect("manifest");
        assert_eq!(manifest.record_count, 2);
        assert_eq!(
            manifest.total_bytes,
            actual
                .iter()
                .map(|(_, bytes, _)| bytes.len())
                .sum::<usize>()
        );
        assert!(manifest.identity_is_self_consistent());
        manifest.verify(&actual).expect("verifies");
    }

    #[test]
    fn a_tampered_byte_is_rejected() {
        let mut actual = files();
        let entries: Vec<ManifestEntry> = actual
            .iter()
            .map(|(path, bytes, records)| ManifestEntry::from_bytes(path.clone(), bytes, *records))
            .collect();
        let manifest = build(entries).expect("manifest");
        actual[0].1.push(b' ');
        let error = manifest.verify(&actual).expect_err("must refuse");
        assert_eq!(error.code, ERR_INTEGRITY);
    }

    #[test]
    fn a_file_the_manifest_does_not_name_is_rejected() {
        let mut actual = files();
        let entries: Vec<ManifestEntry> = actual
            .iter()
            .map(|(path, bytes, records)| ManifestEntry::from_bytes(path.clone(), bytes, *records))
            .collect();
        let manifest = build(entries).expect("manifest");
        actual.push(("bucket-099".to_string(), b"extra\n".to_vec(), 1));
        let error = manifest.verify(&actual).expect_err("must refuse");
        assert_eq!(error.code, ERR_MISSING);
    }

    #[test]
    fn the_generation_id_hashes_the_content_without_self_reference() {
        let actual = files();
        let entries: Vec<ManifestEntry> = actual
            .iter()
            .map(|(path, bytes, records)| ManifestEntry::from_bytes(path.clone(), bytes, *records))
            .collect();
        let first = build(entries.clone()).expect("manifest");
        let second = build(entries.clone()).expect("manifest");
        assert_eq!(first.generation_id, second.generation_id);
        assert_eq!(first.generation_id.len(), 64);

        // Changing the recorded identity cannot change the content digest, so a
        // forged id is detectable.
        let mut forged = first.clone();
        forged.generation_id = "0".repeat(64);
        assert!(!forged.identity_is_self_consistent());
        forged.generation_id = first.generation_id.clone();
        assert!(forged.identity_is_self_consistent());

        let mut changed = entries;
        changed[0].record_count = 99;
        let third = build(changed).expect("manifest");
        assert_ne!(first.generation_id, third.generation_id);
    }
}
