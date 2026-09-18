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
    /// # Errors
    ///
    /// Returns [`ERR_MISSING`] for an unknown shard and
    /// [`crate::ERR_CANONICAL`] for a line that is not a JSON object.
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
        let text = String::from_utf8_lossy(bytes);
        let mut records = Vec::new();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            records.push(serde_json::from_str(line).map_err(|error| {
                ExportError::new(crate::ERR_CANONICAL, format!("{relative_path}: {error}"))
            })?);
        }
        Ok(records)
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

    let mut shards = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        check(LOAD_PHASES[2])?;
        let path = generation_dir.join(&entry.relative_path);
        let bytes = fs::read(&path).map_err(|error| {
            ExportError::new(ERR_MISSING, format!("{}: {error}", path.display()))
        })?;
        shards.push(ShardBytes {
            relative_path: entry.relative_path.clone(),
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
    let files: Vec<(String, Vec<u8>, usize)> = snapshot
        .shards
        .iter()
        .map(|shard| (shard.relative_path.clone(), shard.bytes.clone(), 0))
        .collect();
    validate::validate_files(&files, snapshot.manifest())?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{self, ManifestEntry};
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

    fn fixture() -> (tempfile::TempDir, String, usize) {
        let dir = tempfile::tempdir().expect("tempdir");
        let shards = [
            b"{\"key\":\"edge:a->b\",\"kind\":\"edge\",\"body\":{\"from\":\"a\",\"to\":\"b\"}}\n"
                .to_vec(),
            b"{\"key\":\"edge:b->c\",\"kind\":\"edge\",\"body\":{\"from\":\"b\",\"to\":\"c\"}}\n"
                .to_vec(),
        ];
        let entries: Vec<ManifestEntry> = shards
            .iter()
            .enumerate()
            .map(|(index, bytes)| ManifestEntry::from_bytes(format!("bucket-{index:03}"), bytes, 1))
            .collect();
        let manifest = manifest::build(entries).expect("manifest");
        let generation_dir =
            crate::staging::StagingLayout::new(dir.path()).generation_dir(&manifest.generation_id);
        fs::create_dir_all(&generation_dir).expect("mkdir");
        for (index, bytes) in shards.iter().enumerate() {
            fs::write(generation_dir.join(format!("bucket-{index:03}")), bytes).expect("shard");
        }
        fs::write(
            generation_dir.join("manifest.json"),
            serde_json::to_vec(&manifest).expect("json"),
        )
        .expect("manifest");
        pointer::replace(
            dir.path(),
            &CurrentPointer::new(manifest.generation_id.clone()),
            PointerStrategy::AtomicReplace,
        )
        .expect("pointer");
        let checks = 2 + shards.len();
        (dir, manifest.generation_id, checks)
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
        assert_eq!(snapshot.manifest().record_count, 2);
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
        let records = snapshot.parse_shard("bucket-000").expect("parse");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["key"], "edge:a->b");
        assert!(snapshot.parse_shard("bucket-999").is_err());
    }
}
