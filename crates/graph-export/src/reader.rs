//! Guarded reading of one generation into bounded memory (task B-079).
//!
//! The cross-process guard must cover the pointer, the manifest and every shard,
//! because those three reads are what a concurrent publisher could otherwise
//! replace halfway through. Parsing is explicitly outside that span: the loaded
//! [`Snapshot`] owns its bytes, so a parser or a network call can run after the
//! guard is released and never extends the shared lock.

use crate::manifest::GenerationManifest;
use crate::validate;
use crate::{ExportError, Result, ERR_MISSING};
use graph_core::locks::SolutionGuard;
use std::fs;
use std::path::Path;

/// Error code for a load that lost its guard before it finished.
pub const ERR_UNGUARDED: &str = "export-read-unguarded";

/// The phases a guarded load performs, in order.
pub const LOAD_PHASES: [&str; 3] = ["pointer", "manifest", "shards"];

/// What a guarded load needs to know about its guard.
pub trait LoadGuard {
    /// Whether the cross-process lock is held right now.
    fn is_held(&self) -> bool;
    /// Whether the holder is a reader.
    fn is_shared(&self) -> bool;
}

impl LoadGuard for SolutionGuard {
    fn is_held(&self) -> bool {
        true
    }
    fn is_shared(&self) -> bool {
        SolutionGuard::is_shared(self)
    }
}

/// One shard's bytes inside a loaded snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardBytes {
    /// Path relative to the generation root.
    pub relative_path: String,
    /// The shard's canonical bytes.
    pub bytes: Vec<u8>,
}

/// A complete generation, owned by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    generation_id: String,
    manifest: GenerationManifest,
    shards: Vec<ShardBytes>,
    guarded_checks: usize,
}

impl Snapshot {
    /// The generation this snapshot is of.
    #[must_use]
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }

    /// The verified manifest.
    #[must_use]
    pub const fn manifest(&self) -> &GenerationManifest {
        &self.manifest
    }

    /// The shards, in manifest order.
    #[must_use]
    pub fn shards(&self) -> &[ShardBytes] {
        &self.shards
    }

    /// The bytes of one shard.
    #[must_use]
    pub fn shard(&self, relative_path: &str) -> Option<&[u8]> {
        self.shards
            .iter()
            .find(|shard| shard.relative_path == relative_path)
            .map(|shard| shard.bytes.as_slice())
    }

    /// Total bytes held.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.shards.iter().map(|shard| shard.bytes.len()).sum()
    }

    /// How many times the load consulted its guard.
    #[must_use]
    pub const fn guarded_checks(&self) -> usize {
        self.guarded_checks
    }

    /// Parse one shard into records. This does not need the guard, because the
    /// bytes are already owned by the snapshot.
    ///
    /// A shard is one canonical JSON document, not a sequence of JSONL lines: an
    /// array yields its items and a single object yields itself, which is the
    /// record count the manifest declares.
    ///
    /// # Errors
    ///
    /// Returns [`ERR_MISSING`] for an unknown shard and
    /// [`crate::ERR_CANONICAL`] for a document that is neither an array nor an
    /// object.
    pub fn parse_shard(&self, relative_path: &str) -> Result<Vec<serde_json::Value>> {
        let bytes = self.shard(relative_path).ok_or_else(|| {
            ExportError::new(
                ERR_MISSING,
                format!(
                    "snapshot {} has no shard {relative_path}",
                    self.generation_id
                ),
            )
        })?;
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
            ExportError::new(crate::ERR_CANONICAL, format!("{relative_path}: {error}"))
        })?;
        match value {
            serde_json::Value::Array(items) => Ok(items),
            object @ serde_json::Value::Object(_) => Ok(vec![object]),
            _ => Err(ExportError::new(
                crate::ERR_CANONICAL,
                format!("{relative_path} is neither a JSON array nor a JSON object"),
            )),
        }
    }
}

/// Load the current generation under `guard`.
///
/// # Errors
///
/// * [`ERR_UNGUARDED`] when the guard reports it is not held at the start of a
///   phase, so a half-guarded read can never produce a snapshot;
/// * [`ERR_MISSING`] when the pointer, manifest or a shard is absent;
/// * [`crate::ERR_INTEGRITY`] when a shard does not match the manifest.
pub fn load<G: LoadGuard>(root: &Path, guard: &G) -> Result<Snapshot> {
    let mut checks = 0;
    let mut check = |phase: &str| -> Result<()> {
        checks += 1;
        if guard.is_held() {
            Ok(())
        } else {
            Err(ExportError::new(
                ERR_UNGUARDED,
                format!("guard was lost before reading the {phase}"),
            ))
        }
    };

    check(LOAD_PHASES[0])?;
    let pointer = crate::pointer::read(root)?.ok_or_else(|| {
        ExportError::new(
            ERR_MISSING,
            format!("no current pointer under {}", root.display()),
        )
    })?;
    let generation_dir =
        crate::staging::StagingLayout::new(root).generation_dir(&pointer.generation_id);

    check(LOAD_PHASES[1])?;
    let manifest = validate::read_manifest(&generation_dir)?;

    let mut shards = Vec::with_capacity(manifest.files.len());
    for entry in &manifest.files {
        check(LOAD_PHASES[2])?;
        let path = generation_dir.join(&entry.path);
        let bytes = fs::read(&path).map_err(|error| {
            ExportError::new(ERR_MISSING, format!("{}: {error}", path.display()))
        })?;
        shards.push(ShardBytes {
            relative_path: entry.path.clone(),
            bytes,
        });
    }

    Ok(Snapshot {
        generation_id: pointer.generation_id,
        manifest,
        shards,
        guarded_checks: checks,
    })
}

/// Load a generation and validate it while the guard is still held.
///
/// # Errors
///
/// The same errors as [`load`] plus [`crate::ERR_NOT_CANONICAL`].
pub fn load_verified<G: LoadGuard>(root: &Path, guard: &G) -> Result<Snapshot> {
    let snapshot = load(root, guard)?;
    let mut files: Vec<(String, Vec<u8>, usize)> = Vec::with_capacity(snapshot.shards.len());
    for shard in &snapshot.shards {
        let records = crate::staging::count_records(&shard.bytes)?;
        files.push((shard.relative_path.clone(), shard.bytes.clone(), records));
    }
    validate::validate_files(&files, snapshot.manifest())?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{self, Coverage, ManifestEntry, ManifestHeader};
    use crate::pointer::{self, CurrentPointer, PointerStrategy};
    use std::cell::Cell;

    /// A guard that reports held until `held_for` checks have happened.
    struct ScriptedGuard {
        held_for: usize,
        checks: Cell<usize>,
    }

    impl LoadGuard for ScriptedGuard {
        fn is_held(&self) -> bool {
            let seen = self.checks.get();
            self.checks.set(seen + 1);
            seen < self.held_for
        }
        fn is_shared(&self) -> bool {
            true
        }
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

    fn fixture() -> (tempfile::TempDir, String, usize) {
        let dir = tempfile::tempdir().expect("tempdir");
        let nodes = crate::canonical::canonical_document_value(&serde_json::json!([
            {"key": "node:a", "kind": "symbol", "body": {"name": "a"}},
            {"key": "node:b", "kind": "symbol", "body": {"name": "b"}}
        ]))
        .expect("canonical");
        let edges = crate::canonical::canonical_document_value(&serde_json::json!([
            {"key": "edge:a->b", "kind": "edge", "body": {"from": "a", "to": "b"}}
        ]))
        .expect("canonical");
        let entries = vec![
            ManifestEntry::from_bytes("nodes/000000.json", "nodes", &nodes, 2),
            ManifestEntry::from_bytes("edges/000000.json", "edges", &edges, 1),
        ];
        let manifest = manifest::build(header(), entries).expect("manifest");
        let generation_id = manifest.generation_id().expect("id");
        let generation_dir =
            crate::staging::StagingLayout::new(dir.path()).generation_dir(&generation_id);
        fs::create_dir_all(generation_dir.join("nodes")).expect("mkdir");
        fs::create_dir_all(generation_dir.join("edges")).expect("mkdir");
        fs::write(generation_dir.join("nodes/000000.json"), &nodes).expect("shard");
        fs::write(generation_dir.join("edges/000000.json"), &edges).expect("shard");
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
        let checks = 2 + 2;
        (dir, generation_id, checks)
    }

    #[test]
    fn the_guard_is_checked_before_the_pointer_the_manifest_and_every_shard() {
        let (dir, generation_id, expected) = fixture();
        let guard = ScriptedGuard {
            held_for: usize::MAX,
            checks: Cell::new(0),
        };
        let snapshot = load(dir.path(), &guard).expect("load");
        assert_eq!(snapshot.generation_id(), generation_id);
        assert_eq!(guard.checks.get(), expected);
        assert_eq!(snapshot.guarded_checks(), expected);
        assert_eq!(snapshot.shards().len(), 2);
    }

    #[test]
    fn a_reader_that_loses_its_guard_stops_before_reading_the_manifest() {
        let (dir, _, _) = fixture();
        let guard = ScriptedGuard {
            held_for: 1,
            checks: Cell::new(0),
        };
        let error = load(dir.path(), &guard).expect_err("a lost guard must stop the load");
        assert_eq!(error.code, ERR_UNGUARDED);
        assert!(error.message.contains("manifest"), "{}", error.message);
    }

    #[test]
    fn a_loaded_snapshot_stays_complete_after_the_guard_is_released() {
        let (dir, generation_id, _) = fixture();
        let snapshot = {
            let path = dir.path().join("solution.lock");
            let guard =
                SolutionGuard::acquire(&path, graph_core::locks::LockMode::Shared).expect("reader");
            assert!(guard.is_shared());
            load(dir.path(), &guard).expect("load")
        };
        // The guard is gone here; the snapshot still has everything it needs.
        assert_eq!(snapshot.generation_id(), generation_id);
        assert_eq!(snapshot.manifest().record_count(), 3);
        assert!(snapshot.total_bytes() > 0);
    }

    #[test]
    fn parsing_happens_outside_the_guard_span() {
        let (dir, _, _) = fixture();
        let snapshot = {
            let path = dir.path().join("solution.lock");
            let guard = SolutionGuard::acquire(&path, graph_core::locks::LockMode::Exclusive)
                .expect("writer");
            load(dir.path(), &guard).expect("load")
        };
        let records = snapshot.parse_shard("nodes/000000.json").expect("parse");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["key"], "node:a");
        let edges = snapshot.parse_shard("edges/000000.json").expect("parse");
        assert_eq!(edges.len(), 1);
        assert!(snapshot.parse_shard("nodes/999999.json").is_err());
    }
}
