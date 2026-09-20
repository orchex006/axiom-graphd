//! Serving an archived checkpoint read-only (task B-082).
//!
//! An archive can prove that its bytes match the hashes it recorded. It cannot
//! prove that the analysed source is still what the archive was built from, so
//! freshness is reported as [`Freshness::Unknown`] and a request to verify
//! against live source is refused rather than answered with a guess.

use crate::validate;
use crate::{ExportError, Result, ERR_UNSUPPORTED};
use std::path::{Path, PathBuf};

/// Reason recorded for an archive whose freshness cannot be established.
pub const REASON_SNAPSHOT_ONLY: &str = "freshness-unknown-snapshot-only";
/// Reason recorded when live source was not supplied to the archive reader.
pub const REASON_LIVE_SOURCE_ABSENT: &str = "freshness-unknown-live-source-absent";

/// How an archive was opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveMode {
    /// The archive is all that exists; the analysed source is not available.
    SnapshotOnly,
    /// The caller supplied the live source and asked for a comparison.
    LiveSource,
}

/// What an archive can honestly say about freshness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// The archive was compared against live source by its caller.
    Current,
    /// Freshness cannot be established here.
    Unknown {
        /// Why it cannot be established.
        reason: &'static str,
    },
}

impl Freshness {
    /// Whether freshness was established.
    #[must_use]
    pub const fn is_current(self) -> bool {
        matches!(self, Freshness::Current)
    }

    /// The recorded reason, when freshness is unknown.
    #[must_use]
    pub const fn reason(self) -> Option<&'static str> {
        match self {
            Freshness::Current => None,
            Freshness::Unknown { reason } => Some(reason),
        }
    }
}

/// A read-only archive reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archive {
    root: PathBuf,
    mode: ArchiveMode,
}

/// What the caller asks the archive for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveRequest {
    /// Verify that the archived bytes match the recorded hashes.
    VerifyHashes,
    /// Verify that the archive still matches live source (needs live source).
    VerifyAgainstLiveSource,
}

/// The result of an archive request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveVerification {
    /// The generation verified.
    pub generation_id: String,
    /// Files verified.
    pub files: usize,
    /// Records counted.
    pub records: usize,
    /// What can be said about freshness.
    pub freshness: Freshness,
}

impl ArchiveVerification {
    /// Whether the archive claims the analysed source is still current.
    #[must_use]
    pub const fn claims_current_source_verification(&self) -> bool {
        self.freshness.is_current()
    }
}

/// Open an archive read-only.
#[must_use]
pub fn open(root: impl Into<PathBuf>, mode: ArchiveMode) -> Archive {
    Archive {
        root: root.into(),
        mode,
    }
}

impl Archive {
    /// How the archive was opened.
    #[must_use]
    pub const fn mode(&self) -> ArchiveMode {
        self.mode
    }

    /// The archive root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// What this archive can say about freshness, without reading anything.
    #[must_use]
    pub const fn freshness(&self) -> Freshness {
        match self.mode {
            ArchiveMode::SnapshotOnly => Freshness::Unknown {
                reason: REASON_SNAPSHOT_ONLY,
            },
            ArchiveMode::LiveSource => Freshness::Current,
        }
    }

    /// Whether this archive may claim the analysed source is still current.
    #[must_use]
    pub const fn claims_current_source_verification(&self) -> bool {
        self.freshness().is_current()
    }

    /// Serve one request.
    ///
    /// # Errors
    ///
    /// * [`ERR_UNSUPPORTED`] when a snapshot-only archive is asked to verify
    ///   against live source;
    /// * the same errors as [`validate::validate_generation`] when the archived
    ///   bytes do not match the manifest.
    pub fn serve(&self, request: ArchiveRequest) -> Result<ArchiveVerification> {
        if let (ArchiveMode::SnapshotOnly, ArchiveRequest::VerifyAgainstLiveSource) =
            (self.mode, request)
        {
            return Err(ExportError::new(ERR_UNSUPPORTED, REASON_SNAPSHOT_ONLY));
        }
        let pointer = crate::pointer::read(&self.root)?.ok_or_else(|| {
            ExportError::new(
                crate::ERR_MISSING,
                format!("no archived pointer under {}", self.root.display()),
            )
        })?;
        let generation_dir =
            crate::staging::StagingLayout::new(&self.root).generation_dir(&pointer.generation_id);
        let report = validate::validate_generation(&generation_dir)?;
        Ok(ArchiveVerification {
            generation_id: report.generation_id,
            files: report.files,
            records: report.records,
            freshness: self.freshness(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{self, Coverage, ManifestEntry, ManifestHeader};
    use crate::pointer::{self, CurrentPointer, PointerStrategy};
    use std::fs;

    fn archive_fixture() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let shard = crate::canonical::canonical_document_value(&serde_json::json!([
            {"body": {"from": "a", "to": "b"}, "key": "edge:a->b", "kind": "edge"}
        ]))
        .expect("canonical");
        let header = ManifestHeader {
            solution_id: "demo-solution".to_owned(),
            project_id: "demo-project".to_owned(),
            analysis_profile: "default".to_owned(),
            generator_version: "0.1.0".to_owned(),
            analyzer_set_hash: "a".repeat(64),
            source_fingerprint: "b".repeat(64),
            config_fingerprint: "c".repeat(64),
            dependency_fingerprint: "d".repeat(64),
            coverage: Coverage::complete_for_profile(1, 1, 0),
        };
        let manifest = manifest::build(
            header,
            vec![ManifestEntry::from_bytes(
                "nodes/000000.json",
                "nodes",
                &shard,
                1,
            )],
        )
        .expect("manifest");
        let generation_id = manifest.generation_id().expect("id");
        let generation_dir =
            crate::staging::StagingLayout::new(dir.path()).generation_dir(&generation_id);
        fs::create_dir_all(generation_dir.join("nodes")).expect("mkdir");
        fs::write(generation_dir.join("nodes/000000.json"), &shard).expect("shard");
        fs::write(
            generation_dir.join("manifest.json"),
            manifest.canonical_bytes().expect("bytes"),
        )
        .expect("manifest");
        pointer::replace(
            dir.path(),
            &CurrentPointer::new(generation_id.clone()),
            PointerStrategy::AtomicReplace,
        )
        .expect("pointer");
        (dir, generation_id)
    }

    #[test]
    fn a_snapshot_only_archive_validates_hashes_but_reports_unknown_freshness() {
        let (dir, generation_id) = archive_fixture();
        let archive = open(dir.path(), ArchiveMode::SnapshotOnly);
        let verification = archive.serve(ArchiveRequest::VerifyHashes).expect("verify");
        assert_eq!(verification.generation_id, generation_id);
        assert_eq!(verification.files, 1);
        assert_eq!(verification.records, 1);
        assert_eq!(
            verification.freshness,
            Freshness::Unknown {
                reason: REASON_SNAPSHOT_ONLY
            }
        );
        assert!(!verification.claims_current_source_verification());
        assert_eq!(archive.freshness().reason(), Some(REASON_SNAPSHOT_ONLY));
    }

    #[test]
    fn a_snapshot_only_archive_cannot_claim_current_source_verification() {
        let (dir, _) = archive_fixture();
        let archive = open(dir.path(), ArchiveMode::SnapshotOnly);
        let error = archive
            .serve(ArchiveRequest::VerifyAgainstLiveSource)
            .expect_err("snapshot-only must refuse a live comparison");
        assert_eq!(error.code, ERR_UNSUPPORTED);
        assert!(error.message.contains(REASON_SNAPSHOT_ONLY));
        assert!(!archive.claims_current_source_verification());
    }

    #[test]
    fn a_corrupt_archived_shard_is_rejected() {
        let (dir, _) = archive_fixture();
        let generation_dir = fs::read_dir(dir.path().join("generations"))
            .expect("generations")
            .next()
            .expect("entry")
            .expect("entry")
            .path();
        let mut shard = fs::read(generation_dir.join("nodes/000000.json")).expect("read");
        shard[1] = b'!';
        fs::write(generation_dir.join("nodes/000000.json"), &shard).expect("write");
        let archive = open(dir.path(), ArchiveMode::SnapshotOnly);
        let error = archive
            .serve(ArchiveRequest::VerifyHashes)
            .expect_err("corrupt shard must fail");
        assert_eq!(error.code, crate::ERR_INTEGRITY);
    }

    #[test]
    fn freshness_is_only_current_when_live_source_was_supplied() {
        let (dir, _) = archive_fixture();
        let archive = open(dir.path(), ArchiveMode::LiveSource);
        assert!(archive.claims_current_source_verification());
        let verification = archive
            .serve(ArchiveRequest::VerifyAgainstLiveSource)
            .expect("live comparison");
        assert!(verification.claims_current_source_verification());
        assert_eq!(Freshness::Current.reason(), None);
        assert!(!Freshness::Unknown {
            reason: REASON_LIVE_SOURCE_ABSENT
        }
        .is_current());
    }
}
