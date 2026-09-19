//! State-aware rollback of one compatible version set (task E-045).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 7 does not describe "undo the
//! last change". It describes restoring *one compatible set*:
//!
//! > Before apply, keep the old install manifest, a consistent database backup and
//! > the owned configuration before-hashes. On a health failure, stop the new
//! > process, repoint the old versions, restore the compatible database backup,
//! > clear the new unpublished outbox/cache, and reconcile the inputs that changed
//! > during the upgrade.
//!
//! Two refusals make that set-restoring property enforceable rather than
//! aspirational, and both are in this module:
//!
//! 1. **A partial rollback is refused.** The binary, the database schema and the
//!    policy version move together, so `RollbackScope::FullSet` is the only
//!    accepted scope. Restoring the binary but keeping the migrated database is the
//!    one combination section 7 forbids outright:
//!    > if the new database schema cannot be rolled back, the old binary must not
//!    > run against the new database.
//! 2. **An unsupported downgrade is refused, not attempted.** A schema step the
//!    shipped code marks irreversible, a policy version below the supported floor,
//!    a snapshot whose binary does not speak its own schema, and a snapshot with no
//!    verified backup are each a refusal with its own rule.
//!
//! Nothing here restores anything: the module produces the plan and the refusal,
//! and the caller performs the steps. The compatibility facts it consults are the
//! ones the shipped code declares in [`Compatibility`], so a test can state them
//! explicitly rather than infer them from a version string.

use graph_core::error::{AxiomError, ErrorCode};

use crate::install::plan::is_digest;
use crate::update::verify::RollbackStep;

/// The three version axes that must move together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionSet {
    /// Active binary version.
    pub binary: String,
    /// Active database schema version.
    pub db_schema: u32,
    /// Active policy version.
    pub policy: u32,
}

/// The verified state captured before an update was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// The version set that was installed when the snapshot was taken.
    pub set: VersionSet,
    /// Lowercase 64-hex digest of the consistent database backup.
    pub backup_digest: String,
    /// Whether the backup was verified restorable, not merely written.
    pub backup_verified: bool,
}

/// Which axes a rollback proposes to restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackScope {
    /// Restore the binary, the database schema and the policy together.
    FullSet,
    /// Restore only the binary.
    BinaryOnly,
    /// Restore only the database schema.
    SchemaOnly,
    /// Restore only the policy version.
    PolicyOnly,
}

impl RollbackScope {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FullSet => "full_set",
            Self::BinaryOnly => "binary_only",
            Self::SchemaOnly => "schema_only",
            Self::PolicyOnly => "policy_only",
        }
    }

    /// Every scope, for contract tests.
    #[must_use]
    pub const fn all() -> &'static [RollbackScope] {
        &[
            Self::FullSet,
            Self::BinaryOnly,
            Self::SchemaOnly,
            Self::PolicyOnly,
        ]
    }
}

/// The database schema versions one binary release speaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryRelease {
    /// Release version.
    pub version: String,
    /// Lowest database schema this release reads.
    pub schema_min: u32,
    /// Highest database schema this release reads.
    pub schema_max: u32,
}

/// One schema migration the shipped code knows about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaMigration {
    /// Schema version the migration starts from.
    pub from: u32,
    /// Schema version the migration produces.
    pub to: u32,
    /// Whether the shipped code can walk this step backwards.
    pub reversible: bool,
}

/// What the shipped code declares about compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compatibility {
    /// Binary releases this build knows, and the schema range each speaks.
    pub releases: Vec<BinaryRelease>,
    /// Schema migrations this build knows, each with its reversibility.
    pub migrations: Vec<SchemaMigration>,
    /// The lowest policy version this build is willing to restore.
    pub policy_floor: u32,
    /// The policy version this build itself writes.
    pub policy_version: u32,
}

impl Compatibility {
    /// Whether `version` speaks `schema`.
    #[must_use]
    pub fn speaks(&self, version: &str, schema: u32) -> bool {
        self.releases.iter().any(|release| {
            release.version == version
                && schema >= release.schema_min
                && schema <= release.schema_max
        })
    }

    /// Whether every step from `to` down to `from` is a known reversible migration.
    ///
    /// A descending walk that finds no migration for a step is missing, not
    /// reversible-by-default, so a gap is reported as a missing path.
    fn downgrade_path(&self, from: u32, to: u32) -> DowngradePath {
        let mut current = from;
        while current > to {
            let step = self
                .migrations
                .iter()
                .find(|migration| migration.to == current && migration.from == current - 1);
            match step {
                Some(migration) if migration.reversible => current -= 1,
                Some(_) => return DowngradePath::Irreversible(current),
                None => return DowngradePath::Missing(current),
            }
        }
        DowngradePath::Reversible
    }
}

/// The result of walking a schema downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DowngradePath {
    /// Every step is reversible.
    Reversible,
    /// The migration out of this schema version cannot be reversed.
    Irreversible(u32),
    /// No migration out of this schema version is known.
    Missing(u32),
}

/// The plan a rollback must follow, or the reason it was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackPlan {
    /// The state being rolled back from.
    pub from: VersionSet,
    /// The compatible set that will be restored.
    pub target: VersionSet,
    /// The backup that must be restored, when the database axis moves.
    pub backup_digest: Option<String>,
    /// The steps, in the order section 7 applies them.
    pub steps: Vec<RollbackStep>,
    /// Whether inputs changed during the upgrade must be reconciled afterwards.
    pub reconcile_required: bool,
    /// Whether a journal replay must confirm the swap actually committed.
    pub verify_journal: bool,
}

impl RollbackPlan {
    /// True when every axis this plan moves is covered by a step of the plan.
    ///
    /// The binary and policy axes move with the pointer repoint, so the only axis
    /// that needs a step of its own is the database schema; a plan that moves the
    /// schema without a verified backup is not a set restore and is reported so.
    #[must_use]
    pub fn restores_one_set(&self) -> bool {
        let schema_moves = self.target.db_schema != self.from.db_schema;
        let has_restore = self.steps.contains(&RollbackStep::RestoreCompatibleBackup);
        schema_moves == has_restore && (!schema_moves || self.backup_digest.is_some())
    }
}

/// Plan a rollback of the whole version set.
///
/// # Errors
///
/// Refuses a scope that is not [`RollbackScope::FullSet`], an unverified backup, a
/// backup digest that is not a digest, a snapshot newer than the installed state, a
/// snapshot binary that does not speak the schema it is paired with, an installed
/// binary that does not speak its own schema, an irreversible schema step, a
/// missing schema downgrade path, and a policy version below the supported floor.
pub fn plan_rollback(
    current: &VersionSet,
    snapshot: &Snapshot,
    scope: RollbackScope,
    compatibility: &Compatibility,
) -> Result<RollbackPlan, AxiomError> {
    if scope != RollbackScope::FullSet {
        return Err(refuse("partial_rollback_refused", scope.as_str()));
    }
    if !snapshot.backup_verified {
        return Err(refuse("backup_not_verified", &snapshot.backup_digest));
    }
    if !is_digest(&snapshot.backup_digest) {
        return Err(refuse(
            "backup_digest_not_a_digest",
            &snapshot.backup_digest,
        ));
    }
    if snapshot.set.db_schema > current.db_schema {
        return Err(refuse(
            "snapshot_schema_newer_than_install",
            &snapshot.set.db_schema.to_string(),
        ));
    }
    if snapshot.set.policy > current.policy {
        return Err(refuse(
            "snapshot_policy_newer_than_install",
            &snapshot.set.policy.to_string(),
        )
        .with_detail("expected", current.policy.to_string())
        .with_detail("actual", snapshot.set.policy.to_string()));
    }
    if snapshot.set.policy < compatibility.policy_floor {
        return Err(refuse(
            "policy_downgrade_not_supported",
            &snapshot.set.policy.to_string(),
        )
        .with_detail("required_version", compatibility.policy_floor.to_string()));
    }
    if !compatibility.speaks(&snapshot.set.binary, snapshot.set.db_schema) {
        return Err(refuse(
            "snapshot_binary_and_schema_incompatible",
            &snapshot.set.binary,
        )
        .with_detail("schema", snapshot.set.db_schema.to_string()));
    }
    if !compatibility.speaks(&current.binary, current.db_schema) {
        return Err(
            refuse("installed_binary_and_schema_incompatible", &current.binary)
                .with_detail("schema", current.db_schema.to_string()),
        );
    }
    match compatibility.downgrade_path(current.db_schema, snapshot.set.db_schema) {
        DowngradePath::Reversible => {}
        DowngradePath::Irreversible(schema) => {
            return Err(refuse(
                "schema_downgrade_not_reversible",
                &schema.to_string(),
            ))
        }
        DowngradePath::Missing(schema) => {
            return Err(refuse("schema_downgrade_path_missing", &schema.to_string()))
        }
    }
    if compatibility.policy_version < current.policy {
        return Err(refuse(
            "installed_policy_newer_than_this_build",
            &current.policy.to_string(),
        )
        .with_detail("expected", compatibility.policy_version.to_string()));
    }

    let database_moves = current.db_schema != snapshot.set.db_schema;
    let mut steps = vec![RollbackStep::StopNewProcess, RollbackStep::RepointPrevious];
    if database_moves {
        steps.push(RollbackStep::RestoreCompatibleBackup);
        steps.push(RollbackStep::ClearUnpublishedOutbox);
    }
    Ok(RollbackPlan {
        from: current.clone(),
        target: snapshot.set.clone(),
        backup_digest: Some(snapshot.backup_digest.clone()),
        reconcile_required: database_moves
            || current.binary != snapshot.set.binary
            || current.policy != snapshot.set.policy,
        verify_journal: true,
        steps,
    })
}

/// The one refusal shape of this module.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the rollback request violates the state-aware rollback contract",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "0.0.0-dev";
    const NEW: &str = "0.1.0";
    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn compatibility() -> Compatibility {
        Compatibility {
            releases: vec![
                BinaryRelease {
                    version: OLD.to_string(),
                    schema_min: 1,
                    schema_max: 1,
                },
                BinaryRelease {
                    version: NEW.to_string(),
                    schema_min: 1,
                    schema_max: 2,
                },
            ],
            migrations: vec![SchemaMigration {
                from: 1,
                to: 2,
                reversible: true,
            }],
            policy_floor: 1,
            policy_version: 1,
        }
    }

    fn snapshot() -> Snapshot {
        Snapshot {
            set: VersionSet {
                binary: OLD.to_string(),
                db_schema: 1,
                policy: 1,
            },
            backup_digest: DIGEST.to_string(),
            backup_verified: true,
        }
    }

    fn installed() -> VersionSet {
        VersionSet {
            binary: NEW.to_string(),
            db_schema: 2,
            policy: 1,
        }
    }

    fn rule(error: &AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    #[test]
    fn a_reversible_upgrade_rolls_back_to_the_snapshot_set() {
        let plan = plan_rollback(
            &installed(),
            &snapshot(),
            RollbackScope::FullSet,
            &compatibility(),
        )
        .expect("a reversible migration rolls back");
        assert_eq!(plan.target, snapshot().set);
        assert_eq!(plan.from, installed());
        assert_eq!(plan.backup_digest.as_deref(), Some(DIGEST));
        assert_eq!(
            plan.steps,
            vec![
                RollbackStep::StopNewProcess,
                RollbackStep::RepointPrevious,
                RollbackStep::RestoreCompatibleBackup,
                RollbackStep::ClearUnpublishedOutbox,
            ]
        );
        assert!(plan.restores_one_set());
        assert!(plan.reconcile_required);
        assert!(plan.verify_journal);
    }

    #[test]
    fn a_rollback_that_moves_no_database_axis_needs_no_backup_restore() {
        let snapshot = Snapshot {
            set: VersionSet {
                binary: OLD.to_string(),
                db_schema: 2,
                policy: 1,
            },
            backup_digest: DIGEST.to_string(),
            backup_verified: true,
        };
        // The base fixture has the old binary read schema 1 only. A rollback that
        // keeps schema 2 is legal only when this release set says the old binary
        // speaks 2, so the fixture declares that rather than the plan weakening.
        let mut speaks_two = compatibility();
        speaks_two.releases[0].schema_max = 2;
        let plan = plan_rollback(&installed(), &snapshot, RollbackScope::FullSet, &speaks_two)
            .expect("a same-schema rollback is planned");
        assert_eq!(
            plan.steps,
            vec![RollbackStep::StopNewProcess, RollbackStep::RepointPrevious]
        );
        assert!(plan.restores_one_set());
        assert_eq!(plan.target.binary, OLD);
        assert_eq!(plan.target.db_schema, 2);
    }

    #[test]
    fn a_partial_rollback_is_refused_for_every_axis() {
        for scope in [
            RollbackScope::BinaryOnly,
            RollbackScope::SchemaOnly,
            RollbackScope::PolicyOnly,
        ] {
            let error = plan_rollback(&installed(), &snapshot(), scope, &compatibility())
                .expect_err("a partial rollback must be refused");
            assert_eq!(rule(&error), Some("partial_rollback_refused"), "{scope:?}");
            assert_eq!(
                error.details().get("observed").map(String::as_str),
                Some(scope.as_str())
            );
        }
        assert_eq!(RollbackScope::all().len(), 4);
    }

    #[test]
    fn an_irreversible_or_missing_schema_step_is_refused() {
        let mut irreversible = compatibility();
        irreversible.migrations[0].reversible = false;
        let error = plan_rollback(
            &installed(),
            &snapshot(),
            RollbackScope::FullSet,
            &irreversible,
        )
        .expect_err("an irreversible step must block the downgrade");
        assert_eq!(rule(&error), Some("schema_downgrade_not_reversible"));
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("2")
        );

        let mut missing = compatibility();
        missing.migrations.clear();
        let error = plan_rollback(&installed(), &snapshot(), RollbackScope::FullSet, &missing)
            .expect_err("a missing step must block the downgrade");
        assert_eq!(rule(&error), Some("schema_downgrade_path_missing"));

        let deep = VersionSet {
            binary: NEW.to_string(),
            db_schema: 4,
            policy: 1,
        };
        let mut four = compatibility();
        four.releases.push(BinaryRelease {
            version: NEW.to_string(),
            schema_min: 1,
            schema_max: 4,
        });
        four.migrations.push(SchemaMigration {
            from: 3,
            to: 4,
            reversible: true,
        });
        let error = plan_rollback(&deep, &snapshot(), RollbackScope::FullSet, &four)
            .expect_err("a gap in the path must block the downgrade");
        assert_eq!(rule(&error), Some("schema_downgrade_path_missing"));
    }

    #[test]
    fn an_old_binary_paired_with_a_schema_it_cannot_read_is_refused() {
        let mut narrow = compatibility();
        narrow.releases[0].schema_max = 1;
        let previous = Snapshot {
            set: VersionSet {
                binary: OLD.to_string(),
                db_schema: 2,
                policy: 1,
            },
            backup_digest: DIGEST.to_string(),
            backup_verified: true,
        };
        let error = plan_rollback(&installed(), &previous, RollbackScope::FullSet, &narrow)
            .expect_err("an old binary must not be paired with a schema it cannot read");
        assert_eq!(
            rule(&error),
            Some("snapshot_binary_and_schema_incompatible")
        );
        assert_eq!(error.details().get("schema").map(String::as_str), Some("2"));

        let mut broken = compatibility();
        broken.releases[1].schema_min = 3;
        let error = plan_rollback(&installed(), &snapshot(), RollbackScope::FullSet, &broken)
            .expect_err("an installed binary must speak its own schema");
        assert_eq!(
            rule(&error),
            Some("installed_binary_and_schema_incompatible")
        );
    }

    #[test]
    fn an_unsupported_policy_downgrade_is_refused() {
        let mut floor = compatibility();
        floor.policy_floor = 2;
        let error = plan_rollback(&installed(), &snapshot(), RollbackScope::FullSet, &floor)
            .expect_err("a policy below the floor must be refused");
        assert_eq!(rule(&error), Some("policy_downgrade_not_supported"));
        assert_eq!(
            error.details().get("required_version").map(String::as_str),
            Some("2")
        );

        let newer_policy = Snapshot {
            set: VersionSet {
                binary: OLD.to_string(),
                db_schema: 2,
                policy: 3,
            },
            backup_digest: DIGEST.to_string(),
            backup_verified: true,
        };
        let error = plan_rollback(
            &installed(),
            &newer_policy,
            RollbackScope::FullSet,
            &compatibility(),
        )
        .expect_err("a snapshot newer than the install is not a rollback");
        assert_eq!(rule(&error), Some("snapshot_policy_newer_than_install"));

        let mut behind = compatibility();
        behind.policy_version = 0;
        let error = plan_rollback(&installed(), &snapshot(), RollbackScope::FullSet, &behind)
            .expect_err("an installed policy newer than this build is refused");
        assert_eq!(rule(&error), Some("installed_policy_newer_than_this_build"));
    }

    #[test]
    fn an_unverified_or_newer_snapshot_is_refused() {
        let unverified = Snapshot {
            backup_verified: false,
            ..snapshot()
        };
        let error = plan_rollback(
            &installed(),
            &unverified,
            RollbackScope::FullSet,
            &compatibility(),
        )
        .expect_err("an unverified backup must be refused");
        assert_eq!(rule(&error), Some("backup_not_verified"));

        let malformed = Snapshot {
            backup_digest: "not-a-digest".to_string(),
            ..snapshot()
        };
        let error = plan_rollback(
            &installed(),
            &malformed,
            RollbackScope::FullSet,
            &compatibility(),
        )
        .expect_err("a malformed backup digest must be refused");
        assert_eq!(rule(&error), Some("backup_digest_not_a_digest"));

        let ahead = Snapshot {
            set: VersionSet {
                binary: NEW.to_string(),
                db_schema: 5,
                policy: 1,
            },
            ..snapshot()
        };
        let error = plan_rollback(
            &installed(),
            &ahead,
            RollbackScope::FullSet,
            &compatibility(),
        )
        .expect_err("a snapshot schema newer than the install is not a rollback");
        assert_eq!(rule(&error), Some("snapshot_schema_newer_than_install"));
    }

    #[test]
    fn a_plan_that_moved_the_schema_without_a_restore_is_not_a_set_restore() {
        let plan = RollbackPlan {
            from: installed(),
            target: snapshot().set,
            backup_digest: None,
            steps: vec![RollbackStep::StopNewProcess, RollbackStep::RepointPrevious],
            reconcile_required: true,
            verify_journal: true,
        };
        assert!(
            !plan.restores_one_set(),
            "a schema move without a backup restore is not a set restore"
        );
    }

    #[test]
    fn compatibility_answers_from_the_declared_releases_not_from_a_version_string() {
        let policy = compatibility();
        assert!(policy.speaks(OLD, 1));
        assert!(!policy.speaks(OLD, 2));
        assert!(policy.speaks(NEW, 1));
        assert!(policy.speaks(NEW, 2));
        assert!(
            !policy.speaks("0.2.0", 1),
            "an undeclared release speaks nothing"
        );
        assert_eq!(policy.downgrade_path(2, 1), DowngradePath::Reversible);
        assert_eq!(policy.downgrade_path(1, 1), DowngradePath::Reversible);
        assert_eq!(policy.downgrade_path(2, 0), DowngradePath::Missing(1));
    }
}
