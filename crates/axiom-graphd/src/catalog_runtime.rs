//! Publication of the MCP-readable solution catalog.
//!
//! This module is deliberately downstream of analysis: callers provide only
//! sealed project generation metadata.  It never discovers a project's latest
//! pointer, because a catalog must pin one immutable generation per member.
//! The resulting `manifest.json` uses the frozen `catalog.schema.json` wire
//! shape read by `axiom-mcp`, not graph-export's internal B-078 catalog type.

use std::fs;
use std::path::{Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::locks::{LockMode, SolutionGuard};
use graph_export::canonical::canonical_document_value;
use graph_export::pointer::{self, CurrentPointer, PointerStrategy};
use graph_export::sha256_hex;
use graph_export::staging::StagingLayout;
use serde_json::json;

use crate::runtime;

const CATALOG_MANIFEST: &str = "manifest.json";
const CATALOG_SCHEMA_VERSION: u32 = 1;

/// One exact project generation that the catalog may name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogMember {
    pub project_id: String,
    pub generation_id: String,
    pub source_fingerprint: String,
    /// The sealed project manifest this member is allowed to pin. This path is
    /// local publication input only and never appears in the catalog wire form.
    pub manifest_path: PathBuf,
}

/// All metadata needed to publish one catalog lane.
///
/// `lane_root` is the trusted catalog-host path ending in `live` or
/// `checkpoint`. `guard_root` is the already verified solution guard domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogPublication {
    pub solution_id: String,
    pub analysis_profile: String,
    pub coverage: String,
    pub members: Vec<CatalogMember>,
    pub lane_root: PathBuf,
    pub guard_root: PathBuf,
}

/// The immutable catalog generation installed by [`publish_catalog`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogPublicationOutcome {
    pub generation_id: String,
    pub manifest_sha256: String,
}

/// Publish one canonical catalog generation and move its pointer last.
///
/// Work before the guard is limited to encoding and staging. Under the guard,
/// only an immutable directory install and atomic pointer replacement occur.
/// A validation or staging failure therefore leaves an old pointer unchanged.
pub fn publish_catalog(
    publication: &CatalogPublication,
) -> Result<CatalogPublicationOutcome, AxiomError> {
    let manifest = canonical_manifest(publication)?;
    let generation_id = sha256_hex(&manifest);
    let layout = StagingLayout::new(publication.lane_root.clone());
    let staged = layout.staging_dir(&generation_id);
    fs::create_dir_all(&staged)
        .map_err(|error| runtime::storage_error("catalog staging directory", &error))?;
    fs::write(staged.join(CATALOG_MANIFEST), &manifest)
        .map_err(|error| runtime::storage_error("catalog manifest write", &error))?;

    let guard = CatalogGuard::acquire(&publication.guard_root)?;
    install_generation(&layout, &generation_id, &staged)?;
    pointer::replace(
        &publication.lane_root,
        &CurrentPointer::new(generation_id.clone()),
        PointerStrategy::AtomicReplace,
    )
    .map_err(runtime::export_error)?;
    guard.release()?;

    Ok(CatalogPublicationOutcome {
        manifest_sha256: generation_id.clone(),
        generation_id,
    })
}

/// The native guard ABI for a bounded catalog pointer publication.
///
/// The two files and their order are fixed by
/// `native-reader-writer-guards.md`: admission first, then data; release data
/// before admission. Expensive manifest validation/staging completes before
/// either file is held.
struct CatalogGuard {
    admission: SolutionGuard,
    data: SolutionGuard,
}

impl CatalogGuard {
    fn acquire(root: &Path) -> Result<Self, AxiomError> {
        fs::create_dir_all(root)
            .map_err(|error| runtime::storage_error("catalog solution guard directory", &error))?;
        let admission = SolutionGuard::acquire(&root.join("admission.lock"), LockMode::Exclusive)
            .map_err(runtime::guard_error)?;
        let data = SolutionGuard::acquire(&root.join("data.lock"), LockMode::Exclusive)
            .map_err(runtime::guard_error)?;
        Ok(Self { admission, data })
    }

    fn release(self) -> Result<(), AxiomError> {
        self.data.release().map_err(runtime::guard_error)?;
        self.admission.release().map_err(runtime::guard_error)
    }
}

fn canonical_manifest(publication: &CatalogPublication) -> Result<Vec<u8>, AxiomError> {
    if !portable_id(&publication.solution_id) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "catalog solution_id is not a portable identifier",
        ));
    }
    if publication.analysis_profile.is_empty() {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "catalog analysis_profile must not be empty",
        ));
    }
    if !matches!(
        publication.coverage.as_str(),
        "complete_for_profile" | "partial" | "unsupported"
    ) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "catalog coverage is not supported",
        ));
    }
    if publication.members.is_empty() {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "catalog must pin at least one project generation",
        ));
    }

    let mut members = publication.members.clone();
    members.sort_by(|left, right| left.project_id.cmp(&right.project_id));
    if members
        .windows(2)
        .any(|pair| pair[0].project_id == pair[1].project_id)
    {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "catalog contains duplicate project_id",
        ));
    }
    for member in &members {
        if !portable_id(&member.project_id)
            || !sha256(&member.generation_id)
            || !sha256(&member.source_fingerprint)
        {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "catalog member does not pin portable project and sha256 generation metadata",
            ));
        }
        verify_member_manifest(member)?;
    }

    canonical_document_value(&json!({
        "schema_version": CATALOG_SCHEMA_VERSION,
        "solution_id": publication.solution_id,
        "analysis_profile": publication.analysis_profile,
        "projects": members.into_iter().map(|member| json!({
            "project_id": member.project_id,
            "generation_id": member.generation_id,
            "source_fingerprint": member.source_fingerprint,
        })).collect::<Vec<_>>(),
        "coverage": publication.coverage,
    }))
    .map_err(runtime::export_error)
}

fn verify_member_manifest(member: &CatalogMember) -> Result<(), AxiomError> {
    let bytes = fs::read(&member.manifest_path)
        .map_err(|error| runtime::storage_error("catalog member manifest read", &error))?;
    if sha256_hex(&bytes) != member.generation_id {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "catalog member manifest does not match its pinned generation",
        ));
    }
    let document: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| runtime::storage_error("catalog member manifest parse", &error))?;
    if document
        .get("source_fingerprint")
        .and_then(serde_json::Value::as_str)
        != Some(member.source_fingerprint.as_str())
    {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "catalog member manifest source fingerprint does not match its pin",
        ));
    }
    Ok(())
}

fn install_generation(
    layout: &StagingLayout,
    generation_id: &str,
    staged: &Path,
) -> Result<(), AxiomError> {
    let installed = layout.generation_dir(generation_id);
    if installed.is_dir() {
        fs::remove_dir_all(staged)
            .map_err(|error| runtime::storage_error("duplicate catalog staging cleanup", &error))?;
        return Ok(());
    }
    if let Some(parent) = installed.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| runtime::storage_error("catalog generation directory", &error))?;
    }
    fs::rename(staged, installed)
        .map_err(|error| runtime::storage_error("catalog generation install", &error))
}

fn portable_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !value.is_empty()
        && value.len() <= 63
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
}

#[cfg(test)]
mod tests {
    use super::{publish_catalog, CatalogMember, CatalogPublication};
    use graph_export::pointer;
    use serde_json::Value;
    use std::fs;

    fn member(root: &std::path::Path, project_id: &str, seed: char) -> CatalogMember {
        let source_fingerprint = if seed == 'a' { "b" } else { "a" }.repeat(64);
        let manifest_path = root.join(format!("{project_id}-{seed}.json"));
        fs::write(
            &manifest_path,
            format!(r#"{{"source_fingerprint":"{source_fingerprint}"}}"#),
        )
        .expect("sealed member manifest");
        let bytes = fs::read(&manifest_path).expect("member manifest bytes");
        CatalogMember {
            project_id: project_id.to_owned(),
            generation_id: graph_export::sha256_hex(&bytes),
            source_fingerprint,
            manifest_path,
        }
    }

    fn request(root: &std::path::Path, members: Vec<CatalogMember>) -> CatalogPublication {
        CatalogPublication {
            solution_id: "demo-solution".to_owned(),
            analysis_profile: "default".to_owned(),
            coverage: "complete_for_profile".to_owned(),
            members,
            lane_root: root.join("catalog-host/.axiom/graph/demo-solution/_catalog/live"),
            guard_root: root.join("guard"),
        }
    }

    #[test]
    fn publishes_the_mcp_catalog_shape_and_pointer_after_installing_generation() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let publication = request(
            temporary.path(),
            vec![
                member(temporary.path(), "zeta", 'a'),
                member(temporary.path(), "alpha", 'c'),
            ],
        );
        let outcome = publish_catalog(&publication).expect("catalog publication");

        let pointer = pointer::read(&publication.lane_root)
            .expect("pointer read")
            .expect("catalog pointer");
        assert_eq!(pointer.generation_id, outcome.generation_id);
        let manifest = publication
            .lane_root
            .join("generations")
            .join(&outcome.generation_id)
            .join("manifest.json");
        let bytes = fs::read(manifest).expect("catalog manifest");
        assert_eq!(graph_export::sha256_hex(&bytes), outcome.generation_id);
        let document: Value = serde_json::from_slice(&bytes).expect("catalog json");
        assert_eq!(document["schema_version"], 1);
        assert_eq!(document["solution_id"], "demo-solution");
        assert_eq!(document["projects"][0]["project_id"], "alpha");
        assert_eq!(document["projects"][1]["project_id"], "zeta");
        assert!(bytes.ends_with(b"\n"));
    }

    #[test]
    fn refuses_invalid_member_without_replacing_the_previous_pointer() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let valid = request(
            temporary.path(),
            vec![member(temporary.path(), "alpha", 'a')],
        );
        let previous = publish_catalog(&valid).expect("initial catalog");
        let invalid = request(
            temporary.path(),
            vec![CatalogMember {
                project_id: "alpha".to_owned(),
                generation_id: "bad".to_owned(),
                source_fingerprint: "a".repeat(64),
                manifest_path: temporary.path().join("missing.json"),
            }],
        );
        assert!(publish_catalog(&invalid).is_err());
        assert_eq!(
            pointer::read(&valid.lane_root)
                .expect("pointer read")
                .expect("previous pointer")
                .generation_id,
            previous.generation_id
        );
    }

    #[test]
    fn refuses_a_missing_or_corrupt_member_manifest_before_catalog_publication() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let valid = request(
            temporary.path(),
            vec![member(temporary.path(), "alpha", 'a')],
        );
        let previous = publish_catalog(&valid).expect("initial catalog");
        let missing = request(
            temporary.path(),
            vec![CatalogMember {
                project_id: "alpha".to_owned(),
                generation_id: "a".repeat(64),
                source_fingerprint: "b".repeat(64),
                manifest_path: temporary.path().join("gone.json"),
            }],
        );
        assert!(publish_catalog(&missing).is_err());

        let corrupt_path = temporary.path().join("corrupt.json");
        fs::write(&corrupt_path, b"not-json").expect("corrupt manifest");
        let corrupt = request(
            temporary.path(),
            vec![CatalogMember {
                project_id: "alpha".to_owned(),
                generation_id: graph_export::sha256_hex(b"not-json"),
                source_fingerprint: "b".repeat(64),
                manifest_path: corrupt_path,
            }],
        );
        assert!(publish_catalog(&corrupt).is_err());
        assert_eq!(
            pointer::read(&valid.lane_root)
                .expect("pointer read")
                .expect("previous pointer")
                .generation_id,
            previous.generation_id
        );
    }
}
