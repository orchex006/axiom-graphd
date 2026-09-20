//! Atomic current-generation pointer replacement (task B-075).
//!
//! A reader sees the old complete pointer or the new complete pointer, never a
//! truncated one and never a gap. The replacement is a same-directory temporary
//! file followed by a rename, which both supported platforms perform as a single
//! replacement. When a platform cannot do that, [`PointerStrategy::Unsupported`]
//! returns an error instead of falling back to remove-then-rename, because that
//! fallback has a window with no pointer at all.
//!
//! The wire document is fixed by `contracts/schemas/pointer.schema.json` and by
//! `docs/12-SNAPSHOT-READ-WRITE-PROTOCOL.md`: exactly
//! `{schema_version, generation_id, manifest_sha256}`, with
//! `additionalProperties: false`, `generation_id == manifest_sha256`, and
//! `schema_version` a required integer. The shipped `axiom-mcp` reader
//! additionally accepts a pointer only when its bytes are the compact,
//! lexicographic, single-trailing-LF encoding of their own value, so
//! [`canonical_bytes`] is the one writer form and [`replace`] writes it rather
//! than relying on struct field order.

use crate::{ExportError, Result, ERR_UNSUPPORTED};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The file name of the current pointer inside an export root.
pub const POINTER_FILE: &str = "current.json";
/// Error code for a pointer that is present but not a complete document.
pub const ERR_TORN_POINTER: &str = "export-pointer-torn";
/// The pointer schema major `pointer.schema.json` fixes at `1`.
pub const POINTER_SCHEMA_VERSION: u32 = 1;

/// A pointer written before `schema_version` existed is read as schema 1.
///
/// Pre-field pointers are regenerable artifacts, not human work, so refusing to
/// read them would turn a routine writer upgrade into an outage: a reader would
/// report `ERR_TORN_POINTER` for a lane that is in fact complete and consistent.
/// The value is still not trusted for anything that needs a version, because
/// [`read`] refuses any other major instead of guessing.
fn legacy_schema_version() -> u32 {
    POINTER_SCHEMA_VERSION
}

/// The pointer that names the current generation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CurrentPointer {
    /// The generation a reader must load.
    pub generation_id: String,
    /// The manifest digest, which must equal `generation_id`.
    pub manifest_sha256: String,
    /// The pointer schema major. Absent on a legacy document, then read as 1.
    #[serde(default = "legacy_schema_version")]
    pub schema_version: u32,
}

impl CurrentPointer {
    /// A pointer naming `generation_id`.
    #[must_use]
    pub fn new(generation_id: impl Into<String>) -> Self {
        let generation_id = generation_id.into();
        Self {
            manifest_sha256: generation_id.clone(),
            generation_id,
            schema_version: POINTER_SCHEMA_VERSION,
        }
    }

    /// Whether the pointer is internally consistent.
    #[must_use]
    pub fn is_self_consistent(&self) -> bool {
        self.generation_id.len() == 64
            && self.generation_id == self.manifest_sha256
            && self
                .generation_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }
}

/// The exact canonical bytes `pointer.schema.json` fixes for a pointer.
///
/// Keys are sorted, separators are `,`/`:`, there is no insignificant
/// whitespace and the document ends in exactly one LF, so the shipped
/// `axiom-mcp` reader's canonical-form check accepts these bytes unchanged.
///
/// # Errors
///
/// [`crate::ERR_CANONICAL`] when the document cannot be encoded.
pub fn canonical_bytes(pointer: &CurrentPointer) -> Result<Vec<u8>> {
    // A BTreeMap sorts the keys, so the encoding does not depend on the struct
    // field order or on serde_json's map feature.
    let mut document = std::collections::BTreeMap::new();
    document.insert(
        "schema_version",
        serde_json::Value::from(pointer.schema_version),
    );
    document.insert(
        "generation_id",
        serde_json::Value::from(pointer.generation_id.clone()),
    );
    document.insert(
        "manifest_sha256",
        serde_json::Value::from(pointer.manifest_sha256.clone()),
    );
    let mut bytes = serde_json::to_vec(&document)
        .map_err(|error| ExportError::new(crate::ERR_CANONICAL, format!("pointer: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// How a caller is allowed to replace the pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerStrategy {
    /// Same-directory temporary file plus rename.
    AtomicReplace,
    /// Any strategy that would remove the old pointer first is refused.
    Unsupported,
}

/// The pointer path inside an export root.
#[must_use]
pub fn pointer_path(root: &Path) -> PathBuf {
    root.join(POINTER_FILE)
}

/// Read the current pointer.
///
/// # Errors
///
/// * [`crate::ERR_IO`] when the file exists but cannot be read;
/// * [`ERR_TORN_POINTER`] when it is present but not a complete, consistent
///   document, so a reader is never handed a half-written pointer.
pub fn read(root: &Path) -> Result<Option<CurrentPointer>> {
    let path = pointer_path(root);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).map_err(|error| ExportError::io(&error))?;
    let pointer: CurrentPointer = serde_json::from_slice(&bytes).map_err(|error| {
        ExportError::new(
            ERR_TORN_POINTER,
            format!("{} is not a complete pointer: {error}", path.display()),
        )
    })?;
    // A pointer this writer did not produce may name a different schema; it is
    // refused rather than read as if it were this one.
    if pointer.schema_version != POINTER_SCHEMA_VERSION {
        return Err(ExportError::new(
            ERR_UNSUPPORTED,
            format!(
                "{} declares pointer schema_version {} but this reader implements {}",
                path.display(),
                pointer.schema_version,
                POINTER_SCHEMA_VERSION
            ),
        ));
    }
    if !pointer.is_self_consistent() {
        return Err(ExportError::new(
            ERR_TORN_POINTER,
            format!("{} is not self-consistent", path.display()),
        ));
    }
    Ok(Some(pointer))
}

/// Replace the current pointer.
///
/// # Errors
///
/// * [`ERR_UNSUPPORTED`] when the caller asks for a strategy this platform
///   cannot perform atomically. The previous pointer is left exactly as it was;
///   this function never removes it first.
/// * [`crate::ERR_IO`] when the temporary file or the rename fails.
pub fn replace(root: &Path, pointer: &CurrentPointer, strategy: PointerStrategy) -> Result<()> {
    if let PointerStrategy::Unsupported = strategy {
        return Err(ExportError::new(
            ERR_UNSUPPORTED,
            "refusing to remove the current pointer before renaming: that leaves a window with no pointer",
        ));
    }
    if !pointer.is_self_consistent() {
        return Err(ExportError::new(
            ERR_TORN_POINTER,
            "refusing to publish an inconsistent pointer",
        ));
    }
    fs::create_dir_all(root).map_err(|error| ExportError::io(&error))?;
    let target = pointer_path(root);
    let temporary = root.join(format!(".{POINTER_FILE}.{}.tmp", std::process::id()));
    {
        let mut file = fs::File::create(&temporary).map_err(|error| ExportError::io(&error))?;
        let body = canonical_bytes(pointer)?;
        file.write_all(&body)
            .map_err(|error| ExportError::io(&error))?;
        file.sync_all().map_err(|error| ExportError::io(&error))?;
    }
    fs::rename(&temporary, &target).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        ExportError::io(&error)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: char) -> String {
        seed.to_string().repeat(64)
    }

    #[test]
    fn a_reader_never_observes_a_torn_pointer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let old = CurrentPointer::new(digest('a'));
        let new = CurrentPointer::new(digest('b'));
        replace(dir.path(), &old, PointerStrategy::AtomicReplace).expect("first");
        assert_eq!(read(dir.path()).expect("read").as_ref(), Some(&old));
        replace(dir.path(), &new, PointerStrategy::AtomicReplace).expect("replace");
        assert_eq!(read(dir.path()).expect("read").as_ref(), Some(&new));

        // A truncated document is reported, not silently accepted as absent.
        fs::write(pointer_path(dir.path()), b"{\"generation_id\": \"aa").expect("torn");
        let error = read(dir.path()).expect_err("torn pointer must be reported");
        assert_eq!(error.code, ERR_TORN_POINTER);
    }

    #[test]
    fn an_unsupported_replacement_keeps_the_previous_pointer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let old = CurrentPointer::new(digest('c'));
        replace(dir.path(), &old, PointerStrategy::AtomicReplace).expect("first");
        let new = CurrentPointer::new(digest('d'));
        let error = replace(dir.path(), &new, PointerStrategy::Unsupported)
            .expect_err("unsupported replacement must fail");
        assert_eq!(error.code, ERR_UNSUPPORTED);
        assert!(error.message.contains("remove the current pointer"));
        assert_eq!(read(dir.path()).expect("read").as_ref(), Some(&old));
    }

    #[test]
    fn a_replacement_leaves_no_temporary_file_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        replace(
            dir.path(),
            &CurrentPointer::new(digest('e')),
            PointerStrategy::AtomicReplace,
        )
        .expect("replace");
        let leftovers: Vec<String> = fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name != POINTER_FILE)
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn an_inconsistent_pointer_is_never_written() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bad = CurrentPointer {
            generation_id: digest('f'),
            manifest_sha256: digest('0'),
            schema_version: POINTER_SCHEMA_VERSION,
        };
        let error = replace(dir.path(), &bad, PointerStrategy::AtomicReplace)
            .expect_err("inconsistent pointer must not be published");
        assert_eq!(error.code, ERR_TORN_POINTER);
        assert!(!pointer_path(dir.path()).exists());
    }

    #[test]
    fn the_written_pointer_is_the_exact_schema_document_the_reader_requires() {
        // The wire bytes are fixed by contracts/schemas/pointer.schema.json and by
        // the shipped axiom-mcp reader: three keys, no extra key, sorted,
        // compact, and exactly one trailing LF.
        let dir = tempfile::tempdir().expect("tempdir");
        let pointer = CurrentPointer::new(digest('a'));
        replace(dir.path(), &pointer, PointerStrategy::AtomicReplace).expect("replace");
        let written = fs::read(pointer_path(dir.path())).expect("read back");
        assert_eq!(
            String::from_utf8(written.clone()).expect("utf8"),
            format!(
                "{{\"generation_id\":\"{}\",\"manifest_sha256\":\"{}\",\"schema_version\":1}}\n",
                digest('a'),
                digest('a')
            )
        );
        assert_eq!(written, canonical_bytes(&pointer).expect("canonical"));
        assert!(written.ends_with(b"\n"));
        assert!(!written[..written.len() - 1].contains(&b'\n'));
        assert!(!written.contains(&b' '));
    }

    #[test]
    fn a_pointer_written_before_the_schema_field_existed_still_reads() {
        // An on-disk pointer from an earlier revision carries no schema_version.
        // It is complete and consistent, so it reads as schema 1 instead of being
        // reported torn; the writer emits the field from now on.
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            pointer_path(dir.path()),
            format!(
                "{{\"generation_id\":\"{}\",\"manifest_sha256\":\"{}\"}}",
                digest('a'),
                digest('a')
            ),
        )
        .expect("legacy write");
        let pointer = read(dir.path())
            .expect("legacy pointer must read")
            .expect("present");
        assert_eq!(pointer.schema_version, POINTER_SCHEMA_VERSION);
        assert_eq!(pointer.generation_id, digest('a'));
    }

    #[test]
    fn a_pointer_from_an_unknown_schema_major_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            pointer_path(dir.path()),
            format!(
                "{{\"generation_id\":\"{}\",\"manifest_sha256\":\"{}\",\"schema_version\":2}}",
                digest('b'),
                digest('b')
            ),
        )
        .expect("future write");
        let error = read(dir.path()).expect_err("an unknown major must be refused");
        assert_eq!(error.code, ERR_UNSUPPORTED);
        assert!(error.message.contains("schema_version 2"));
    }
}
