//! The pinned multi-project generation vector (task B-078).
//!
//! A solution is published as one catalog that names the exact generation of
//! every member project. A member that disappears from the inputs is an error,
//! not an invitation to take whatever the latest generation happens to be:
//! that substitution would silently mix two different analysis vintages.

use crate::sha256_hex;
use crate::{ExportError, Result, ERR_INTEGRITY, ERR_MISSING};
use std::fs;
use std::path::Path;

/// Error code for a member that vanished without an explicit drop.
pub const ERR_MEMBER_MISSING: &str = "export-catalog-member-missing";

/// One project's pinned generation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct CatalogMember {
    /// The project identity, which orders the vector.
    pub project_id: String,
    /// The generation the project is pinned to.
    pub generation_id: String,
    /// The source fingerprint that generation was built from.
    pub source_fingerprint: String,
}

/// A pinned generation vector.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Catalog {
    /// Digest of the member vector.
    pub catalog_id: String,
    /// Members, ordered by project identity.
    pub members: Vec<CatalogMember>,
}

impl Catalog {
    /// The member for a project.
    #[must_use]
    pub fn member(&self, project_id: &str) -> Option<&CatalogMember> {
        self.members
            .iter()
            .find(|member| member.project_id == project_id)
    }

    /// Whether the recorded identity matches the member vector.
    #[must_use]
    pub fn identity_is_self_consistent(&self) -> bool {
        computed_id(&self.members) == self.catalog_id
    }
}

fn computed_id(members: &[CatalogMember]) -> String {
    let mut text = String::new();
    for member in members {
        text.push_str(&member.project_id);
        text.push('\u{1f}');
        text.push_str(&member.generation_id);
        text.push('\u{1f}');
        text.push_str(&member.source_fingerprint);
        text.push('\n');
    }
    sha256_hex(text.as_bytes())
}

/// Build a catalog from a member vector.
///
/// # Errors
///
/// Returns [`ERR_INTEGRITY`] when two members name the same project, because a
/// duplicate would make the vector ambiguous.
pub fn build(mut members: Vec<CatalogMember>) -> Result<Catalog> {
    members.sort();
    if let Some(pair) = members
        .windows(2)
        .find(|pair| pair[0].project_id == pair[1].project_id)
    {
        return Err(ExportError::new(
            ERR_INTEGRITY,
            format!("project {} appears twice", pair[0].project_id),
        ));
    }
    let catalog_id = computed_id(&members);
    Ok(Catalog {
        catalog_id,
        members,
    })
}

/// Pin the latest vector, refusing to silently replace a member that vanished.
///
/// # Errors
///
/// * [`ERR_MEMBER_MISSING`] when a project pinned by `previous` is absent from
///   `latest` and is not named in `dropped`;
/// * [`ERR_INTEGRITY`] when `latest` is ambiguous.
pub fn pin(
    previous: Option<&Catalog>,
    latest: Vec<CatalogMember>,
    dropped: &[&str],
) -> Result<Catalog> {
    let catalog = build(latest)?;
    if let Some(previous) = previous {
        for member in &previous.members {
            let dropped_explicitly = dropped.contains(&member.project_id.as_str());
            if catalog.member(&member.project_id).is_none() && !dropped_explicitly {
                return Err(ExportError::new(
                    ERR_MEMBER_MISSING,
                    format!(
                        "project {} was pinned to generation {} and is absent from the new vector; it must not be silently replaced or dropped",
                        member.project_id, member.generation_id
                    ),
                ));
            }
        }
    }
    Ok(catalog)
}

/// Re-read every member generation and check it against the catalog.
///
/// # Errors
///
/// * [`ERR_MISSING`] when a member's generation directory or manifest is gone;
/// * [`ERR_INTEGRITY`] when a manifest digest or source fingerprint disagrees.
pub fn verify(solution_root: &Path, catalog: &Catalog) -> Result<()> {
    if !catalog.identity_is_self_consistent() {
        return Err(ExportError::new(
            ERR_INTEGRITY,
            "catalog does not hash to its recorded identity",
        ));
    }
    for member in &catalog.members {
        let manifest = member.project_root(solution_root).join("manifest.json");
        if !manifest.is_file() {
            return Err(ExportError::new(
                ERR_MISSING,
                format!("catalog member {} has no manifest", member.project_id),
            ));
        }
        let bytes = fs::read(&manifest).map_err(|error| ExportError::io(&error))?;
        if crate::sha256_hex(&bytes) != member.generation_id {
            return Err(ExportError::new(
                ERR_INTEGRITY,
                format!(
                    "catalog member {} manifest does not match its pinned generation",
                    member.project_id
                ),
            ));
        }
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            ExportError::new(ERR_MISSING, format!("{}: {error}", manifest.display()))
        })?;
        let fingerprint = parsed
            .get("source_fingerprint")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if fingerprint != member.source_fingerprint {
            return Err(ExportError::new(
                ERR_INTEGRITY,
                format!(
                    "catalog member {} fingerprint changed since it was pinned",
                    member.project_id
                ),
            ));
        }
    }
    Ok(())
}

impl CatalogMember {
    /// The generation directory of this member inside a solution root.
    #[must_use]
    pub fn project_root(&self, solution_root: &Path) -> std::path::PathBuf {
        solution_root
            .join(&self.project_id)
            .join("checkpoint")
            .join("generations")
            .join(&self.generation_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(project: &str, generation: char) -> CatalogMember {
        CatalogMember {
            project_id: project.to_owned(),
            generation_id: generation.to_string().repeat(64),
            source_fingerprint: format!("fp-{project}"),
        }
    }

    #[test]
    fn a_catalog_pins_the_verified_generation_vector() {
        let catalog = build(vec![member("b", 'b'), member("a", 'a')]).expect("catalog");
        assert_eq!(
            catalog
                .members
                .iter()
                .map(|member| member.project_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert!(catalog.identity_is_self_consistent());
        let rebuilt = build(catalog.members.clone()).expect("catalog");
        assert_eq!(catalog.catalog_id, rebuilt.catalog_id);
    }

    #[test]
    fn a_member_that_vanished_is_not_silently_replaced_by_another_generation() {
        let previous = build(vec![member("a", 'a'), member("b", 'b')]).expect("catalog");
        let error = pin(Some(&previous), vec![member("a", 'c')], &[])
            .expect_err("a vanished member must be refused");
        assert_eq!(error.code, ERR_MEMBER_MISSING);
        assert!(error.message.contains("project b"));
        let allowed = pin(Some(&previous), vec![member("a", 'c')], &["b"]).expect("explicit drop");
        assert!(allowed.member("b").is_none());
        assert_eq!(
            allowed.member("a").expect("a").generation_id,
            "c".repeat(64)
        );
    }

    #[test]
    fn a_member_whose_manifest_digest_differs_fails_verification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pinned = member("a", 'a');
        let generation_dir = pinned.project_root(dir.path());
        fs::create_dir_all(&generation_dir).expect("mkdir");
        fs::write(generation_dir.join("manifest.json"), b"{}").expect("manifest");
        let catalog = build(vec![pinned]).expect("catalog");
        let error = verify(dir.path(), &catalog).expect_err("digest must be checked");
        assert_eq!(error.code, ERR_INTEGRITY);
    }

    #[test]
    fn a_vanished_member_generation_is_missing_rather_than_replaced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let catalog = build(vec![member("a", 'a')]).expect("catalog");
        let error = verify(dir.path(), &catalog).expect_err("missing member");
        assert_eq!(error.code, ERR_MISSING);
    }
}
