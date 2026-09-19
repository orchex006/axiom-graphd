//! Activate a verified, staged installation (task E-006).
//!
//! `21-INSTALLATION.md` section C requires one versioned directory per install
//! and at least one previous working version kept for rollback, and
//! `docs/16-CLI-AND-CONTROL-API.md` section 7 requires `install apply` to bind
//! approval to the exact canonical plan digest. This module is the activation
//! half of the `install plan`/`install apply` pair that
//! [crate::install::plan] prepares.
//!
//! ## The three properties that matter
//!
//! 1. **Nothing replaces a working install by accident.** Every artifact is
//!    checked *before* anything moves: a missing, short or digest-mismatched
//!    staged payload refuses the whole transaction, so a partial download can
//!    never reach the activated tree. There is no code path that moves one
//!    artifact and then discovers the next one is bad.
//! 2. **Activation is a pointer move.** Payloads land in the versioned
//!    directory, and the single [InstallPlan::rollback] pointer is replaced by
//!    writing a sibling temporary and renaming it over the old one, so a
//!    reader either sees the previous install or the new one, never a torn
//!    combination.
//! 3. **Approval is not a formality.** The transaction only proceeds when the
//!    caller's approved digest is the digest of the very plan body it is
//!    installing, reusing [crate::plan::approval_reasons], so an approval of
//!    one plan can never activate another.
//!
//! ## Why the filesystem is a trait
//!
//! [InstallFs] is the whole mutation surface, so the tests exercise a complete
//! activation, a torn staging tree and a conflicting destination against an
//! in-memory double. No test and no probe touches a real install root, and the
//! production [LocalFs] is the only implementation that writes to disk.

use std::collections::BTreeSet;
use std::path::Path;

use graph_core::error::{AxiomError, ErrorCode};
use serde::{Deserialize, Serialize};

use crate::install::plan::{sealed, ComponentAction, InstallPlan};

/// `schema_version` of the activation journal this build writes.
pub const JOURNAL_SCHEMA_VERSION: u64 = 1;

/// Name of the pointer that names the activated install.
pub const POINTER_FILE: &str = "current";

/// Suffix of the temporary sibling used to replace the pointer atomically.
pub const POINTER_TEMP_SUFFIX: &str = ".next";

/// Suffix of the rollback record written beside the journal entry.
pub const ROLLBACK_SUFFIX: &str = ".rollback.json";

/// The mutation surface of one installation (see the module documentation).
pub trait InstallFs {
    /// True when the path exists, whatever its type.
    fn exists(&self, path: &str) -> bool;
    /// Read a file.
    ///
    /// # Errors
    /// [ErrorCode::NotFound] when the file is absent.
    fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError>;
    /// Create a directory and its parents.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the directory cannot be created.
    fn create_dir_all(&self, path: &str) -> Result<(), AxiomError>;
    /// Write a file, replacing any previous content.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the file cannot be written.
    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError>;
    /// Move a path, atomically where the host allows it.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the move cannot be completed.
    fn rename(&self, from: &str, to: &str) -> Result<(), AxiomError>;
}

/// The real filesystem, and the only implementation that touches a disk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocalFs;

impl InstallFs for LocalFs {
    fn exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
        std::fs::read(path).map_err(|error| {
            AxiomError::new(ErrorCode::NotFound, "the staged artifact could not be read")
                .with_detail("rule", "staged_read")
                .with_detail("observed", path)
                .with_detail("actual", error.kind().to_string())
        })
    }

    fn create_dir_all(&self, path: &str) -> Result<(), AxiomError> {
        std::fs::create_dir_all(path).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the install directory could not be created",
            )
            .with_detail("rule", "create_dir_all")
            .with_detail("observed", path)
            .with_detail("actual", error.kind().to_string())
        })
    }

    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError> {
        std::fs::write(path, bytes).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the install record could not be written",
            )
            .with_detail("rule", "write")
            .with_detail("observed", path)
            .with_detail("actual", error.kind().to_string())
        })
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), AxiomError> {
        std::fs::rename(from, to).map_err(|error| {
            AxiomError::new(ErrorCode::Internal, "the install could not be activated")
                .with_detail("rule", "rename")
                .with_detail("observed", from)
                .with_detail("expected", to)
                .with_detail("actual", error.kind().to_string())
        })
    }
}

/// The caller-supplied inputs of one activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyRequest {
    /// Identifier of this transaction; the caller owns generation.
    pub transaction_id: String,
    /// Digest the caller approved, from the reviewed plan document.
    pub approved_digest: String,
    /// RFC 3339 instant of the activation, injected for determinism.
    pub applied_at: String,
}

impl ApplyRequest {
    /// A request for one transaction over one approved digest.
    #[must_use]
    pub fn new(
        transaction_id: impl Into<String>,
        approved_digest: impl Into<String>,
        applied_at: impl Into<String>,
    ) -> Self {
        Self {
            transaction_id: transaction_id.into(),
            approved_digest: approved_digest.into(),
            applied_at: applied_at.into(),
        }
    }
}

/// One artifact this transaction placed, or found already in place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivatedArtifact {
    /// Component of the artifact.
    pub component: String,
    /// Version of the artifact.
    pub version: String,
    /// Bundle-relative location of the artifact.
    pub artifact: String,
    /// Digest of the bytes that were activated.
    pub sha256: String,
    /// Absolute destination that now holds the bytes.
    pub destination: String,
    /// True when identical bytes were already installed at the destination.
    pub already_present: bool,
}

/// The result of one activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedInstall {
    /// Schema baseline of this record.
    pub schema_version: u64,
    /// Transaction that performed the activation.
    pub transaction_id: String,
    /// Plan that was activated.
    pub plan_id: String,
    /// Digest the activation was approved against.
    pub plan_digest: String,
    /// RFC 3339 instant of the activation.
    pub applied_at: String,
    /// Artifacts that are now installed.
    pub activated: Vec<ActivatedArtifact>,
    /// Pointer that names the activated install.
    pub pointer_path: String,
    /// Journal entry describing the transaction.
    pub journal_path: String,
    /// Rollback record describing what the pointer replaced.
    pub rollback_path: String,
    /// Pointer content before this transaction, when one existed.
    pub previous_pointer: Option<String>,
    /// Previous versions the install keeps for rollback.
    pub keeps_previous_versions: u64,
}

impl AppliedInstall {
    /// The activation record as one JSON object.
    ///
    /// # Errors
    /// [ErrorCode::Internal] when the record cannot be serialised.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        serde_json::to_string(self).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the activation record is not serialisable",
            )
            .with_detail("observed", error.to_string())
        })
    }

    /// The human-reviewable rendering of one activation.
    #[must_use]
    pub fn text(&self) -> String {
        let mut text = format!(
            "install apply {} (transaction {}) plan={} digest={}\n",
            self.applied_at, self.transaction_id, self.plan_id, self.plan_digest
        );
        for artifact in &self.activated {
            text.push_str(&format!(
                "activated {} {} {} -> {} sha256={}{}\n",
                artifact.component,
                artifact.version,
                artifact.artifact,
                artifact.destination,
                artifact.sha256,
                if artifact.already_present {
                    " (already present)"
                } else {
                    ""
                }
            ));
        }
        text.push_str(&format!(
            "pointer {} previous={} keeps {} version(s)\n",
            self.pointer_path,
            self.previous_pointer.as_deref().unwrap_or("<none>"),
            self.keeps_previous_versions
        ));
        text.push_str(&format!(
            "journal {}\nrollback {}\n",
            self.journal_path, self.rollback_path
        ));
        text
    }
}

/// A refusal that leaves the install exactly as it was.
fn refuse(code: ErrorCode, rule: &str, observed: &str, message: &str) -> AxiomError {
    AxiomError::new(code, message)
        .with_detail("rule", rule)
        .with_detail("observed", observed)
}

/// The parent directory of a host path, when it has one.
fn parent_of(path: &str) -> Option<String> {
    Path::new(path)
        .parent()
        .map(|parent| parent.to_string_lossy().into_owned())
}

/// The pointer content for one activation.
fn pointer_document(
    plan: &InstallPlan,
    request: &ApplyRequest,
    activated: &[ActivatedArtifact],
) -> Result<Vec<u8>, AxiomError> {
    let document = serde_json::json!({
        "schema_version": JOURNAL_SCHEMA_VERSION,
        "plan_id": plan.plan_id,
        "plan_digest": request.approved_digest,
        "transaction_id": request.transaction_id,
        "applied_at": request.applied_at,
        "activated": activated,
    });
    let mut bytes = serde_json::to_vec_pretty(&document).map_err(|error| {
        AxiomError::new(ErrorCode::Internal, "the pointer is not serialisable")
            .with_detail("observed", error.to_string())
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Activate the payloads of one approved plan.
///
/// The whole transaction is planned and checked before the first write:
///
/// 1. the plan, the request and the approval digest are validated;
/// 2. every payload that needs activating is read from staging and must match
///    its declared digest and size;
/// 3. a destination that already holds *different* bytes refuses the
///    transaction instead of overwriting;
/// 4. only then are payloads moved and the pointer replaced atomically.
///
/// # Errors
/// [ErrorCode::ValidationError] when the plan or the request is malformed;
/// [ErrorCode::Forbidden] when the approved digest is not the digest of this
/// plan body; [ErrorCode::Conflict] when staging is incomplete, when a staged
/// payload disagrees with its declared digest or size, or when a destination
/// already holds different bytes.
pub fn apply_install(
    plan: &InstallPlan,
    request: &ApplyRequest,
    fs: &impl InstallFs,
) -> Result<AppliedInstall, AxiomError> {
    plan.validate()?;
    if !plan.dry_run {
        return Err(refuse(
            ErrorCode::ValidationError,
            "dry_run",
            "false",
            "only a dry-run plan may be applied",
        ));
    }
    if !crate::install::plan::is_digest(&request.approved_digest) {
        return Err(refuse(
            ErrorCode::ValidationError,
            "approved_digest",
            &request.approved_digest,
            "the approved digest is not a digest",
        ));
    }
    if request.transaction_id.trim().is_empty() || request.applied_at.trim().is_empty() {
        return Err(refuse(
            ErrorCode::ValidationError,
            "transaction_id",
            &request.transaction_id,
            "a transaction needs an identifier and an instant",
        ));
    }
    let (value, digest) = sealed(plan)?;
    let reasons = crate::plan::approval_reasons(&value, &request.approved_digest);
    if !reasons.is_empty() {
        return Err(AxiomError::new(
            ErrorCode::Forbidden,
            "the plan was not approved at the digest it is being installed at",
        )
        .with_detail("rule", "approval")
        .with_detail("observed", reasons.join(","))
        .with_detail("expected", &digest));
    }

    // Phase 1: check every payload. No mutation happens in this loop.
    let mut activated: Vec<ActivatedArtifact> = Vec::new();
    let mut to_move: Vec<(String, String)> = Vec::new();
    for component in &plan.components {
        if component.action == ComponentAction::Noop {
            continue;
        }
        let staged = component.staged_destination.clone();
        if !fs.exists(&staged) {
            return Err(refuse(
                ErrorCode::Conflict,
                "staging_incomplete",
                &staged,
                "a planned payload is not staged, so nothing is activated",
            )
            .with_detail("component", &component.component));
        }
        let bytes = fs.read(&staged)?;
        if bytes.len() as u64 != component.source.size_bytes {
            return Err(refuse(
                ErrorCode::Conflict,
                "staging_incomplete",
                &bytes.len().to_string(),
                "a staged payload does not have the size the plan declared",
            )
            .with_detail("component", &component.component)
            .with_detail("expected", component.source.size_bytes.to_string()));
        }
        let staged_digest = graph_export::sha256_hex(&bytes);
        if staged_digest != component.source.sha256 {
            return Err(refuse(
                ErrorCode::Conflict,
                "staging_incomplete",
                &staged_digest,
                "a staged payload does not match the digest the plan declared",
            )
            .with_detail("component", &component.component)
            .with_detail("expected", &component.source.sha256));
        }
        let mut already_present = false;
        if fs.exists(&component.destination) {
            let installed = fs.read(&component.destination)?;
            if graph_export::sha256_hex(&installed) == component.source.sha256 {
                already_present = true;
            } else {
                return Err(refuse(
                    ErrorCode::Conflict,
                    "destination_conflict",
                    &component.destination,
                    "the destination already holds different bytes",
                )
                .with_detail("component", &component.component));
            }
        }
        if !already_present {
            to_move.push((staged, component.destination.clone()));
        }
        activated.push(ActivatedArtifact {
            component: component.component.clone(),
            version: component.version.clone(),
            artifact: component.artifact.clone(),
            sha256: staged_digest,
            destination: component.destination.clone(),
            already_present,
        });
    }

    // Phase 2: the previous pointer, read before it is replaced.
    let pointer_path = plan.rollback.current_pointer.clone();
    let previous_pointer = if fs.exists(&pointer_path) {
        Some(String::from_utf8_lossy(&fs.read(&pointer_path)?).into_owned())
    } else {
        None
    };
    let journal_path = format!(
        "{}{}{}.json",
        if plan.rollback.journal_directory.ends_with('/') {
            plan.rollback.journal_directory.clone()
        } else {
            format!("{}/", plan.rollback.journal_directory)
        },
        "",
        request.transaction_id
    );
    let rollback_path = format!("{journal_path}{ROLLBACK_SUFFIX}");

    // Phase 3: activate. Every check has already passed.
    let mut created: BTreeSet<String> = BTreeSet::new();
    for (from, to) in &to_move {
        if let Some(parent) = parent_of(to) {
            if created.insert(parent.clone()) {
                fs.create_dir_all(&parent)?;
            }
        }
        let _ = from;
        fs.rename(from, to)?;
    }
    if let Some(parent) = parent_of(&pointer_path) {
        if created.insert(parent.clone()) {
            fs.create_dir_all(&parent)?;
        }
    }
    if let Some(parent) = parent_of(&journal_path) {
        if created.insert(parent.clone()) {
            fs.create_dir_all(&parent)?;
        }
    }

    let applied = AppliedInstall {
        schema_version: JOURNAL_SCHEMA_VERSION,
        transaction_id: request.transaction_id.clone(),
        plan_id: plan.plan_id.clone(),
        plan_digest: request.approved_digest.clone(),
        applied_at: request.applied_at.clone(),
        activated,
        pointer_path: pointer_path.clone(),
        journal_path: journal_path.clone(),
        rollback_path: rollback_path.clone(),
        previous_pointer: previous_pointer.clone(),
        keeps_previous_versions: plan.rollback.keeps_previous_versions,
    };

    // The pointer is replaced through a sibling temporary, so a reader never
    // observes a half-written pointer.
    let pointer_temp = format!("{pointer_path}{POINTER_TEMP_SUFFIX}");
    fs.write(
        &pointer_temp,
        &pointer_document(plan, request, &applied.activated)?,
    )?;
    fs.rename(&pointer_temp, &pointer_path)?;
    let mut record = applied.to_json()?.into_bytes();
    record.push(b'\n');
    fs.write(&journal_path, &record)?;
    let rollback = serde_json::json!({
        "schema_version": JOURNAL_SCHEMA_VERSION,
        "transaction_id": request.transaction_id,
        "plan_id": plan.plan_id,
        "previous_pointer": previous_pointer,
        "keeps_previous_versions": plan.rollback.keeps_previous_versions,
    });
    let mut rollback_bytes = serde_json::to_vec_pretty(&rollback).map_err(|error| {
        AxiomError::new(
            ErrorCode::Internal,
            "the rollback record is not serialisable",
        )
        .with_detail("observed", error.to_string())
    })?;
    rollback_bytes.push(b'\n');
    fs.write(&rollback_path, &rollback_bytes)?;
    Ok(applied)
}
#[cfg(test)]
mod tests {
    //! Activation tests (task E-006 AC2).
    //!
    //! The refusals are asserted against an in-memory [`InstallFs`] double so
    //! each one can also prove that *nothing* was mutated, and one test runs the
    //! production [`LocalFs`] under a temporary root so the real adapter that
    //! touches a disk is covered too.

    use std::cell::RefCell;
    use std::collections::{BTreeMap, BTreeSet};

    use graph_export::sha256_hex;
    use tempfile::TempDir;

    use super::*;
    use crate::install::plan::{
        plan_install, ArtifactKind, BundleComponent, BundleManifest, DryRun, PlanContext,
        BUNDLE_SCHEMA_VERSION,
    };

    /// The two fixture payloads; their digests are computed, not written down.
    const GRAPHD: &[u8] = b"the axiom-graphd binary payload";
    const MCP: &[u8] = b"the axiom-mcp wheel payload";

    /// One bundle whose declared digests describe the exact fixture payloads.
    fn manifest(graphd: &[u8], mcp: &[u8]) -> BundleManifest {
        BundleManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            bundle_id: "axiom-core".to_string(),
            channel: "stable".to_string(),
            created_at: "2026-09-19T00:00:00Z".to_string(),
            components: vec![
                BundleComponent {
                    component: "axiom-graphd".to_string(),
                    version: "0.0.0-dev".to_string(),
                    host: "linux-x64".to_string(),
                    artifact: "bin/axiom-graphd".to_string(),
                    kind: ArtifactKind::Binary,
                    sha256: sha256_hex(graphd),
                    size_bytes: graphd.len() as u64,
                    permissions: vec!["read".to_string(), "execute".to_string()],
                    service: None,
                    network_access: Vec::new(),
                },
                BundleComponent {
                    component: "axiom-mcp".to_string(),
                    version: "0.0.0-dev".to_string(),
                    host: "linux-x64".to_string(),
                    artifact: "python/axiom_mcp-0.0.0.dev0-py3-none-any.whl".to_string(),
                    kind: ArtifactKind::Python,
                    sha256: sha256_hex(mcp),
                    size_bytes: mcp.len() as u64,
                    permissions: vec!["read".to_string()],
                    service: None,
                    network_access: Vec::new(),
                },
            ],
        }
    }

    /// One dry-run plan for the fixture bundle at `install_root`.
    fn plan_for(install_root: &str, graphd: &[u8], mcp: &[u8]) -> InstallPlan {
        plan_install(
            &manifest(graphd, mcp),
            &sha256_hex(b"the exact manifest bytes"),
            "/tmp/axiom-bundle",
            &PlanContext::per_user(
                "install-20260919-0001",
                "2026-09-19T00:00:00Z",
                "linux-x64",
                install_root,
            ),
            DryRun::new(),
        )
        .expect("the fixture bundle plans")
    }

    /// Stage every component's declared payload, in plan order.
    fn stage(fs: &MemoryFs, plan: &InstallPlan, payloads: &[&[u8]]) {
        for (component, payload) in plan.components.iter().zip(payloads.iter()) {
            fs.put(&component.staged_destination, payload);
        }
    }

    /// The journal entry one transaction would write.
    fn journal_path(plan: &InstallPlan, transaction_id: &str) -> String {
        format!(
            "{}/{}.json",
            plan.rollback.journal_directory, transaction_id
        )
    }

    /// An in-memory [`InstallFs`] that records every mutation it is asked for.
    #[derive(Default)]
    struct MemoryFs {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        dirs: RefCell<BTreeSet<String>>,
        renames: RefCell<Vec<(String, String)>>,
    }

    impl MemoryFs {
        fn put(&self, path: &str, bytes: &[u8]) {
            self.files
                .borrow_mut()
                .insert(path.to_string(), bytes.to_vec());
        }

        fn get(&self, path: &str) -> Option<Vec<u8>> {
            self.files.borrow().get(path).cloned()
        }

        fn renames(&self) -> Vec<(String, String)> {
            self.renames.borrow().clone()
        }
    }

    impl InstallFs for MemoryFs {
        fn exists(&self, path: &str) -> bool {
            self.files.borrow().contains_key(path) || self.dirs.borrow().contains(path)
        }

        fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
            self.files.borrow().get(path).cloned().ok_or_else(|| {
                AxiomError::new(ErrorCode::NotFound, "the staged artifact could not be read")
                    .with_detail("rule", "staged_read")
                    .with_detail("observed", path)
            })
        }

        fn create_dir_all(&self, path: &str) -> Result<(), AxiomError> {
            let mut dirs = self.dirs.borrow_mut();
            let mut current = path.to_string();
            loop {
                dirs.insert(current.clone());
                match current.rfind('/') {
                    Some(0) => {
                        dirs.insert("/".to_string());
                        break;
                    }
                    Some(index) => current.truncate(index),
                    None => break,
                }
            }
            Ok(())
        }

        fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError> {
            self.put(path, bytes);
            Ok(())
        }

        fn rename(&self, from: &str, to: &str) -> Result<(), AxiomError> {
            let bytes = self.files.borrow_mut().remove(from).ok_or_else(|| {
                AxiomError::new(
                    ErrorCode::NotFound,
                    "the staged artifact could not be moved",
                )
                .with_detail("rule", "rename")
                .with_detail("observed", from)
            })?;
            self.files.borrow_mut().insert(to.to_string(), bytes);
            self.renames
                .borrow_mut()
                .push((from.to_string(), to.to_string()));
            Ok(())
        }
    }

    #[test]
    fn a_complete_staging_tree_activates_atomically_with_rollback_metadata() {
        let plan = plan_for("/tmp/axiom-home", GRAPHD, MCP);
        let fs = MemoryFs::default();
        stage(&fs, &plan, &[GRAPHD, MCP]);
        let (_, digest) = sealed(&plan).expect("the plan seals");

        let applied = apply_install(
            &plan,
            &ApplyRequest::new("tx-0001", &digest, "2026-09-19T00:05:00Z"),
            &fs,
        )
        .expect("a complete staging tree activates");

        assert_eq!(applied.activated.len(), 2);
        assert!(applied
            .activated
            .iter()
            .all(|artifact| !artifact.already_present));
        assert_eq!(applied.plan_digest, digest);
        assert_eq!(applied.previous_pointer, None);
        assert_eq!(applied.keeps_previous_versions, 1);
        for (component, payload) in plan.components.iter().zip([GRAPHD, MCP]) {
            assert_eq!(fs.get(&component.destination).as_deref(), Some(payload));
            assert!(!fs.exists(&component.staged_destination));
        }
        // The pointer moved through its temporary sibling, never in place.
        let pointer_temp = format!("{}{POINTER_TEMP_SUFFIX}", plan.rollback.current_pointer);
        assert!(fs
            .renames()
            .iter()
            .any(|(from, to)| from == &pointer_temp && to == &plan.rollback.current_pointer));
        let pointer = fs
            .get(&plan.rollback.current_pointer)
            .expect("the pointer exists");
        let pointer: serde_json::Value =
            serde_json::from_slice(&pointer).expect("the pointer is JSON");
        assert_eq!(pointer["plan_id"].as_str(), Some(plan.plan_id.as_str()));
        assert_eq!(pointer["plan_digest"].as_str(), Some(digest.as_str()));
        assert_eq!(pointer["transaction_id"].as_str(), Some("tx-0001"));
        let journal = fs.get(&applied.journal_path).expect("the journal exists");
        let journal: serde_json::Value =
            serde_json::from_slice(&journal).expect("the journal is JSON");
        assert_eq!(
            journal["schema_version"].as_u64(),
            Some(JOURNAL_SCHEMA_VERSION)
        );
        assert_eq!(journal["transaction_id"].as_str(), Some("tx-0001"));
        let rollback = fs
            .get(&applied.rollback_path)
            .expect("the rollback record exists");
        let rollback: serde_json::Value =
            serde_json::from_slice(&rollback).expect("the rollback record is JSON");
        assert!(rollback["previous_pointer"].is_null());
        assert_eq!(rollback["keeps_previous_versions"].as_u64(), Some(1));
    }

    #[test]
    fn a_partial_staging_tree_never_replaces_the_current_install() {
        let plan = plan_for("/tmp/axiom-home", GRAPHD, MCP);
        let fs = MemoryFs::default();
        // Only the first component finished downloading; the second is absent.
        fs.put(&plan.components[0].staged_destination, GRAPHD);
        let (_, digest) = sealed(&plan).expect("the plan seals");

        let error = apply_install(
            &plan,
            &ApplyRequest::new("tx-0002", &digest, "2026-09-19T00:05:00Z"),
            &fs,
        )
        .expect_err("an incomplete staging tree is refused");

        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("staging_incomplete")
        );
        assert!(fs.renames().is_empty());
        assert!(plan
            .components
            .iter()
            .all(|component| !fs.exists(&component.destination)));
        assert!(!fs.exists(&plan.rollback.current_pointer));
        assert!(!fs.exists(&journal_path(&plan, "tx-0002")));
        // Staging is untouched: the payload that was there is still there.
        assert_eq!(
            fs.get(&plan.components[0].staged_destination).as_deref(),
            Some(GRAPHD)
        );
        assert!(!fs.exists(&plan.components[1].staged_destination));
    }

    #[test]
    fn a_staged_payload_that_disagrees_with_its_digest_is_refused_without_mutation() {
        let plan = plan_for("/tmp/axiom-home", GRAPHD, MCP);
        let fs = MemoryFs::default();
        stage(&fs, &plan, &[GRAPHD, MCP]);
        // Same length, different bytes: the size check passes and the digest
        // check is the one that must refuse.
        let mut tampered = GRAPHD.to_vec();
        tampered[0] ^= 0xff;
        fs.put(&plan.components[0].staged_destination, &tampered);
        let (_, digest) = sealed(&plan).expect("the plan seals");

        let error = apply_install(
            &plan,
            &ApplyRequest::new("tx-0003", &digest, "2026-09-19T00:05:00Z"),
            &fs,
        )
        .expect_err("bytes that disagree with the trusted digest are refused");

        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("staging_incomplete")
        );
        assert!(fs.renames().is_empty());
        assert!(plan
            .components
            .iter()
            .all(|component| !fs.exists(&component.destination)));
        assert_eq!(
            fs.get(&plan.components[0].staged_destination).as_deref(),
            Some(tampered.as_slice())
        );
    }

    #[test]
    fn a_destination_holding_different_bytes_refuses_the_whole_transaction() {
        let plan = plan_for("/tmp/axiom-home", GRAPHD, MCP);
        let fs = MemoryFs::default();
        stage(&fs, &plan, &[GRAPHD, MCP]);
        fs.put(&plan.components[0].destination, b"an older unrelated build");
        let (_, digest) = sealed(&plan).expect("the plan seals");

        let error = apply_install(
            &plan,
            &ApplyRequest::new("tx-0004", &digest, "2026-09-19T00:05:00Z"),
            &fs,
        )
        .expect_err("a conflicting destination is refused");

        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("destination_conflict")
        );
        assert!(fs.renames().is_empty());
        assert!(!fs.exists(&journal_path(&plan, "tx-0004")));
        assert_eq!(
            fs.get(&plan.components[0].destination).as_deref(),
            Some(b"an older unrelated build".as_slice())
        );
        assert_eq!(
            fs.get(&plan.components[1].staged_destination).as_deref(),
            Some(MCP)
        );
    }

    #[test]
    fn a_destination_already_holding_the_same_bytes_is_reported_not_rewritten() {
        let plan = plan_for("/tmp/axiom-home", GRAPHD, MCP);
        let fs = MemoryFs::default();
        stage(&fs, &plan, &[GRAPHD, MCP]);
        fs.put(&plan.components[0].destination, GRAPHD);
        let (_, digest) = sealed(&plan).expect("the plan seals");

        let applied = apply_install(
            &plan,
            &ApplyRequest::new("tx-0005", &digest, "2026-09-19T00:05:00Z"),
            &fs,
        )
        .expect("an idempotent activation succeeds");

        assert!(applied.activated[0].already_present);
        assert!(!applied.activated[1].already_present);
        assert!(!fs
            .renames()
            .iter()
            .any(|(_, to)| to == &plan.components[0].destination));
        assert_eq!(
            fs.get(&plan.components[1].destination).as_deref(),
            Some(MCP)
        );
    }

    #[test]
    fn an_approval_for_another_plan_never_activates_this_one() {
        let plan = plan_for("/tmp/axiom-home", GRAPHD, MCP);
        let fs = MemoryFs::default();
        stage(&fs, &plan, &[GRAPHD, MCP]);
        let (_, digest) = sealed(&plan).expect("the plan seals");
        let other = "0".repeat(64);
        assert_ne!(other, digest);

        let error = apply_install(
            &plan,
            &ApplyRequest::new("tx-0006", &other, "2026-09-19T00:05:00Z"),
            &fs,
        )
        .expect_err("an approval of another plan is refused");

        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("approval")
        );
        assert!(fs.renames().is_empty());
        assert!(plan
            .components
            .iter()
            .all(|component| !fs.exists(&component.destination)));
        assert_eq!(
            fs.get(&plan.components[0].staged_destination).as_deref(),
            Some(GRAPHD)
        );
    }

    #[test]
    fn a_second_activation_records_the_pointer_it_replaced() {
        let plan = plan_for("/tmp/axiom-home", GRAPHD, MCP);
        let fs = MemoryFs::default();
        stage(&fs, &plan, &[GRAPHD, MCP]);
        let (_, digest) = sealed(&plan).expect("the plan seals");
        apply_install(
            &plan,
            &ApplyRequest::new("tx-0007", &digest, "2026-09-19T00:05:00Z"),
            &fs,
        )
        .expect("the first activation succeeds");
        let replaced = String::from_utf8(
            fs.get(&plan.rollback.current_pointer)
                .expect("the first pointer exists"),
        )
        .expect("the pointer is UTF-8");

        // Re-stage to represent a second install of the same version, then
        // activate again: the rollback record must name the pointer it replaced.
        stage(&fs, &plan, &[GRAPHD, MCP]);
        let second = apply_install(
            &plan,
            &ApplyRequest::new("tx-0008", &digest, "2026-09-19T00:06:00Z"),
            &fs,
        )
        .expect("the second activation succeeds");

        assert_eq!(second.previous_pointer.as_deref(), Some(replaced.as_str()));
        let now = fs
            .get(&plan.rollback.current_pointer)
            .expect("the second pointer exists");
        assert_ne!(now, replaced.into_bytes());
    }

    #[test]
    fn the_real_filesystem_adapter_activates_under_a_temporary_root() {
        let root = TempDir::new().expect("a temporary install root");
        let install_root = root.path().to_string_lossy().into_owned();
        let plan = plan_for(&install_root, GRAPHD, MCP);
        let (_, digest) = sealed(&plan).expect("the plan seals");
        for (component, payload) in plan.components.iter().zip([GRAPHD, MCP]) {
            let staged = std::path::Path::new(&component.staged_destination);
            std::fs::create_dir_all(staged.parent().expect("a staging parent"))
                .expect("the staging directory is created");
            std::fs::write(staged, payload).expect("the payload is staged");
        }

        let applied = apply_install(
            &plan,
            &ApplyRequest::new("tx-0009", &digest, "2026-09-19T00:05:00Z"),
            &LocalFs,
        )
        .expect("a complete staging tree activates on the real filesystem");

        assert_eq!(applied.activated.len(), 2);
        assert!(applied.previous_pointer.is_none());
        for (component, payload) in plan.components.iter().zip([GRAPHD, MCP]) {
            assert_eq!(
                std::fs::read(&component.destination).expect("the destination is readable"),
                payload
            );
        }
        for path in [
            &plan.rollback.current_pointer,
            &applied.journal_path,
            &applied.rollback_path,
        ] {
            assert!(std::path::Path::new(path).exists(), "{path} exists");
        }
    }
}
