//! Update and migration admission guard (task F-010).
//!
//! `fixtures/update/` declares the portable update and migration hazards a local
//! installation must refuse: an expired signature, an untrusted or absent
//! signer, a candidate schema whose major version is newer than this binary
//! understands, and a plan that requires a backup that is not present. This
//! module is the single admission surface those vectors assert against, so the
//! fixture corpus and the real refusal path cannot drift apart.
//!
//! Refusal is total and read-only: [`admit`] never writes, never creates a file
//! and never mutates the target tree, so a refused update leaves the
//! installation byte-identical. Every check that already exists in the shipping
//! code is reused rather than re-implemented:
//!
//! * the trust decision reuses [`crate::commands::update::UpdateTrust`] and
//!   [`crate::commands::update::TrustRoot::is_usable`],
//! * the schema ceiling reuses
//!   [`graph_store::migrations::CURRENT_SCHEMA_VERSION`],
//! * the backup presence check reuses [`graph_store::backup::verify_backup`],
//! * an admitted plan is delegated with the real, argv-only
//!   [`crate::commands::update::delegate`].

use std::path::Path;

use graph_store::backup::verify_backup;
use graph_store::migrations::CURRENT_SCHEMA_VERSION;

use crate::commands::update::{delegate, TrustRoot, UpdatePlan, UpdateTrust};

/// Reason recorded when the trust metadata expiry is not after the plan was
/// created, so the signature can no longer be trusted.
pub const REASON_SIGNATURE_EXPIRED: &str = "signature-expired";
/// Reason recorded when the plan carries no signature, or no usable trust root
/// is configured, so the signer is untrusted or absent.
pub const REASON_SIGNER_UNTRUSTED: &str = "signer-untrusted";
/// Reason recorded when the candidate schema major is newer than this binary
/// supports; the database is never migrated downwards.
pub const REASON_SCHEMA_NEWER_THAN_BINARY: &str = "schema-newer-than-binary";
/// Reason recorded when the plan requires a backup that is not present.
pub const REASON_BACKUP_MISSING: &str = "backup-missing";
/// Reason recorded when the real delegation refuses an otherwise plausible plan.
pub const REASON_DELEGATION_REFUSED: &str = "delegation-refused";

/// Every stable refusal reason this guard can record, in check order.
pub const REFUSAL_REASONS: [&str; 5] = [
    REASON_SIGNATURE_EXPIRED,
    REASON_SIGNER_UNTRUSTED,
    REASON_SCHEMA_NEWER_THAN_BINARY,
    REASON_BACKUP_MISSING,
    REASON_DELEGATION_REFUSED,
];

/// One admission request, built from a `fixtures/update/` vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitRequest {
    /// Repository-relative plan path handed to the delegation.
    pub plan_path: String,
    /// Component the plan installs.
    pub component: String,
    /// Target version.
    pub target_version: String,
    /// Canonical SHA-256 of the plan document.
    pub canonical_digest: String,
    /// The explicit approval digest, when the operator supplied one.
    pub approve_digest: Option<String>,
    /// Creation timestamp of the plan, `YYYY-MM-DDTHH:MM:SSZ`.
    pub plan_created_at: String,
    /// Expiry timestamp of the trust metadata, same format.
    pub trust_metadata_expiry: String,
    /// Whether the plan carries a signature at all.
    pub signature_present: bool,
    /// Schema major the plan would migrate to.
    pub candidate_schema_version: u32,
    /// Whether the plan declares a required backup.
    pub backup_required: bool,
    /// Path of the required backup, when the plan names one.
    pub backup_path: Option<String>,
}

/// The outcome of [`admit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// The plan may be applied; the real argv delegation is included so a
    /// caller cannot re-derive it from a shell string.
    Admitted {
        /// The delegated program, always the sibling `axiom` CLI.
        program: String,
        /// The delegated argv, in order.
        args: Vec<String>,
    },
    /// The plan is refused with a stable reason and no side effect.
    Refused {
        /// The stable reason code.
        reason: &'static str,
    },
}

impl Admission {
    /// Whether the plan was admitted.
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted { .. })
    }

    /// The refusal reason, when the plan was refused.
    #[must_use]
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            Self::Admitted { .. } => None,
            Self::Refused { reason } => Some(reason),
        }
    }
}

/// Admit or refuse one update plan.
///
/// This function is read-only. The only filesystem access is the read-only
/// backup verification behind [`REASON_BACKUP_MISSING`]; no check creates,
/// truncates or rewrites a file, so a refusal leaves the target tree
/// byte-identical.
#[must_use]
pub fn admit(request: &AdmitRequest, trust: &UpdateTrust) -> Admission {
    if request.trust_metadata_expiry <= request.plan_created_at {
        return refuse(REASON_SIGNATURE_EXPIRED);
    }
    if !request.signature_present || !trust.root().is_some_and(TrustRoot::is_usable) {
        return refuse(REASON_SIGNER_UNTRUSTED);
    }
    if request.candidate_schema_version > CURRENT_SCHEMA_VERSION {
        return refuse(REASON_SCHEMA_NEWER_THAN_BINARY);
    }
    if request.backup_required && !backup_present(request.backup_path.as_deref()) {
        return refuse(REASON_BACKUP_MISSING);
    }
    let plan = UpdatePlan::new(
        request.plan_path.clone(),
        request.component.clone(),
        request.target_version.clone(),
        request.canonical_digest.clone(),
    );
    match delegate(&plan, trust, request.approve_digest.as_deref()) {
        Ok(delegation) => {
            let (program, args) = delegation.program_and_args();
            Admission::Admitted {
                program: program.to_owned(),
                args: args.to_vec(),
            }
        }
        Err(_) => refuse(REASON_DELEGATION_REFUSED),
    }
}

/// Whether a required backup is present and readable as a consistent database.
fn backup_present(path: Option<&str>) -> bool {
    let Some(path) = path else {
        return false;
    };
    if path.is_empty() {
        return false;
    }
    verify_backup(Path::new(path)).is_ok()
}

const fn refuse(reason: &'static str) -> Admission {
    Admission::Refused { reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trust() -> UpdateTrust {
        UpdateTrust::Configured(TrustRoot::new("9f2c4a1b", vec!["axiom-graphd".to_owned()]))
    }

    fn request() -> AdmitRequest {
        AdmitRequest {
            plan_path: "plan.json".to_owned(),
            component: "axiom-graphd".to_owned(),
            target_version: "0.2.0".to_owned(),
            canonical_digest: "b1938dd0652de5cd76d1a4934fd39d5a7d83012eb3a8e8c0c6139e1bc1d77b00"
                .to_owned(),
            approve_digest: Some(
                "b1938dd0652de5cd76d1a4934fd39d5a7d83012eb3a8e8c0c6139e1bc1d77b00".to_owned(),
            ),
            plan_created_at: "2026-09-18T02:00:00Z".to_owned(),
            trust_metadata_expiry: "2026-09-25T02:00:00Z".to_owned(),
            signature_present: true,
            candidate_schema_version: CURRENT_SCHEMA_VERSION,
            backup_required: false,
            backup_path: None,
        }
    }

    #[test]
    fn a_plausible_plan_is_admitted_with_an_argv_delegation() {
        let admission = admit(&request(), &trust());
        assert!(admission.is_admitted());
        assert_eq!(admission.reason(), None);
        let Admission::Admitted { program, args } = admission else {
            panic!("admitted");
        };
        assert_eq!(program, crate::commands::update::AXIOM_PROGRAM);
        assert_eq!(args[0], "update");
        assert_eq!(args[1], "apply");
        assert!(!args.iter().any(|arg| arg.contains("--approve-digest=")));
    }

    #[test]
    fn every_declared_hazard_is_refused_with_its_own_reason() {
        let mut expired = request();
        expired.trust_metadata_expiry = "2026-09-01T00:00:00Z".to_owned();
        assert_eq!(
            admit(&expired, &trust()).reason(),
            Some(REASON_SIGNATURE_EXPIRED)
        );

        let mut unsigned = request();
        unsigned.signature_present = false;
        assert_eq!(
            admit(&unsigned, &trust()).reason(),
            Some(REASON_SIGNER_UNTRUSTED)
        );
        assert_eq!(
            admit(&request(), &UpdateTrust::Unconfigured).reason(),
            Some(REASON_SIGNER_UNTRUSTED)
        );

        let mut future = request();
        future.candidate_schema_version = CURRENT_SCHEMA_VERSION + 1;
        assert_eq!(
            admit(&future, &trust()).reason(),
            Some(REASON_SCHEMA_NEWER_THAN_BINARY)
        );

        let mut no_backup = request();
        no_backup.backup_required = true;
        assert_eq!(
            admit(&no_backup, &trust()).reason(),
            Some(REASON_BACKUP_MISSING)
        );
    }

    #[test]
    fn the_expiry_boundary_is_not_after_creation() {
        let mut equal = request();
        equal.trust_metadata_expiry = equal.plan_created_at.clone();
        assert_eq!(
            admit(&equal, &trust()).reason(),
            Some(REASON_SIGNATURE_EXPIRED)
        );
        let mut later = request();
        later.trust_metadata_expiry = "2026-09-18T02:00:01Z".to_owned();
        assert!(admit(&later, &trust()).is_admitted());
    }

    #[test]
    fn an_unsupported_approval_is_refused_rather_than_admitted() {
        let mut stale = request();
        stale.approve_digest =
            Some("0000000000000000000000000000000000000000000000000000000000000000".to_owned());
        assert_eq!(
            admit(&stale, &trust()).reason(),
            Some(REASON_DELEGATION_REFUSED)
        );
    }

    #[test]
    fn the_declared_reason_vocabulary_is_unique() {
        let mut sorted = REFUSAL_REASONS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), REFUSAL_REASONS.len());
    }
}
