//! The update policy that decides between auto-apply and approval (task E-046).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 4 fixes both halves of this
//! module:
//!
//! > Default auto-apply disabled. A user may enable compatible-patch auto-apply
//! > with an explicit policy; it requires an idle window, drain, a verified signed
//! > bundle, backup plus rollback and scope grants. A major version, schema
//! > migration, host config rewrite or trust root change requires explicit plan
//! > approval.
//!
//! The failure this module prevents is an updater that treats "the user enabled
//! auto-apply" as "the user approved this specific plan". So the decision is a
//! three-way one and only one of the three outcomes can be reached:
//!
//! * [`Decision::ApplyAutomatically`] -- reachable only in
//!   [`AutoApplyMode::CompatiblePatch`], only for a strictly newer **patch** on an
//!   allowed channel, only when no approval boundary is crossed, and only when
//!   every readiness condition section 4 requires actually holds.
//! * [`Decision::RequiresApproval`] -- the default outcome, and the outcome of every
//!   boundary crossing. Each gate that forced it is named, so an operator can see
//!   *why* the run stopped instead of guessing.
//! * [`Decision::Refused`] -- the candidate is not applicable at all: not newer,
//!   not a version this build can order, or on a channel the policy does not allow.
//!
//! The default policy is [`UpdatePolicy::default`], and it is
//! [`AutoApplyMode::ExplicitApproval`]: a plain compatible patch still requires
//! approval until an operator opts in, which is what "default auto-apply disabled"
//! means in code rather than in prose.

use graph_core::error::{AxiomError, ErrorCode};

/// How the updater treats a candidate it did not ask about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoApplyMode {
    /// Every candidate needs an approved plan. The default.
    ExplicitApproval,
    /// A compatible patch may apply itself when no boundary is crossed.
    CompatiblePatch,
}

impl AutoApplyMode {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitApproval => "explicit_approval",
            Self::CompatiblePatch => "compatible_patch",
        }
    }

    /// Every mode, for contract tests.
    #[must_use]
    pub const fn all() -> &'static [AutoApplyMode] {
        &[Self::ExplicitApproval, Self::CompatiblePatch]
    }
}

/// Release channels a policy accepts.
pub const CHANNELS: [&str; 2] = ["stable", "prerelease"];

/// Boundaries that always require explicit plan approval.
///
/// The list is closed: a boundary that is not here cannot stop an auto-apply, and a
/// boundary that is here can never be crossed automatically.
pub const APPROVAL_BOUNDARIES: [&str; 5] = [
    "minor_or_major_version",
    "schema_migration",
    "security_advisory",
    "trust_root_change",
    "host_config_rewrite",
];

/// Readiness conditions section 4 requires before an auto-apply may run.
pub const READINESS_GATES: [&str; 5] = [
    "host_not_idle",
    "queue_not_drained",
    "bundle_signature_not_verified",
    "backup_and_rollback_not_ready",
    "scope_grants_missing",
];

/// How large a version step a candidate is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Only the patch component moved.
    Patch,
    /// The minor component moved.
    Minor,
    /// The major component moved.
    Major,
}

impl Severity {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Patch => "patch",
            Self::Minor => "minor",
            Self::Major => "major",
        }
    }

    /// Every severity, for contract tests.
    #[must_use]
    pub const fn all() -> &'static [Severity] {
        &[Self::Patch, Self::Minor, Self::Major]
    }

    /// Whether this severity may auto-apply under a compatible-patch policy.
    #[must_use]
    pub const fn is_compatible_patch(self) -> bool {
        matches!(self, Self::Patch)
    }
}

/// One candidate release the updater is considering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Version currently installed.
    pub from_version: String,
    /// Version the candidate would install.
    pub to_version: String,
    /// Size of the version step.
    pub severity: Severity,
    /// Release channel the candidate comes from, from [`CHANNELS`].
    pub channel: String,
    /// Whether the candidate changes the graph or control schema.
    pub schema_change: bool,
    /// Whether the candidate carries a security advisory.
    pub security_advisory: bool,
    /// Whether the candidate rotates the update trust root.
    pub trust_root_change: bool,
    /// Whether the candidate rewrites host configuration.
    pub host_config_rewrite: bool,
}

/// The host and bundle conditions an auto-apply depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Readiness {
    /// The maintenance window is idle.
    pub idle_window: bool,
    /// In-flight work has drained.
    pub drained: bool,
    /// The bundle's signature verified against the pinned trust root.
    pub bundle_signature_verified: bool,
    /// A consistent backup and a rollback plan are ready.
    pub backup_and_rollback_ready: bool,
    /// The scoped grants the plan needs are present.
    pub scope_grants_present: bool,
}

impl Readiness {
    /// Everything section 4 requires, in one value.
    #[must_use]
    pub const fn complete() -> Self {
        Self {
            idle_window: true,
            drained: true,
            bundle_signature_verified: true,
            backup_and_rollback_ready: true,
            scope_grants_present: true,
        }
    }

    /// Every readiness condition that does not hold, as gate names.
    #[must_use]
    pub fn missing(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.idle_window {
            missing.push(READINESS_GATES[0]);
        }
        if !self.drained {
            missing.push(READINESS_GATES[1]);
        }
        if !self.bundle_signature_verified {
            missing.push(READINESS_GATES[2]);
        }
        if !self.backup_and_rollback_ready {
            missing.push(READINESS_GATES[3]);
        }
        if !self.scope_grants_present {
            missing.push(READINESS_GATES[4]);
        }
        missing
    }
}

/// What the updater will do with one candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Apply without asking, naming the conditions that permitted it.
    ApplyAutomatically {
        /// Conditions that had to hold and did.
        satisfied: Vec<&'static str>,
    },
    /// Stop and ask for an approved plan, naming every gate that forced it.
    RequiresApproval {
        /// Every gate that forced approval, in declaration order.
        gates: Vec<&'static str>,
    },
    /// The candidate is not applicable at all.
    Refused {
        /// Stable name of the refusal.
        rule: &'static str,
    },
}

impl Decision {
    /// Whether this decision applies without approval.
    #[must_use]
    pub const fn is_automatic(&self) -> bool {
        matches!(self, Self::ApplyAutomatically { .. })
    }

    /// Whether this decision refuses the candidate outright.
    #[must_use]
    pub const fn is_refused(&self) -> bool {
        matches!(self, Self::Refused { .. })
    }
}

/// One operator's update policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdatePolicy {
    /// How an unrequested candidate is treated.
    pub mode: AutoApplyMode,
    /// Whether a prerelease candidate is acceptable at all.
    pub allow_prerelease: bool,
}

impl Default for UpdatePolicy {
    /// The default policy: every candidate needs an approved plan.
    fn default() -> Self {
        Self {
            mode: AutoApplyMode::ExplicitApproval,
            allow_prerelease: false,
        }
    }
}

/// Decide what to do with one candidate under one policy.
///
/// # Errors
///
/// Refuses a candidate whose versions cannot be ordered as SemVer, or whose
/// channel is not one of [`CHANNELS`].
pub fn decide(
    policy: &UpdatePolicy,
    candidate: &Candidate,
    readiness: &Readiness,
) -> Result<Decision, AxiomError> {
    if !CHANNELS.contains(&candidate.channel.as_str()) {
        return Ok(Decision::Refused {
            rule: "channel_not_supported",
        });
    }
    let from = parse_semver(&candidate.from_version)
        .ok_or_else(|| refuse("installed_version_not_semver", &candidate.from_version))?;
    let to = parse_semver(&candidate.to_version)
        .ok_or_else(|| refuse("candidate_version_not_semver", &candidate.to_version))?;
    if to <= from {
        return Ok(Decision::Refused {
            rule: "candidate_not_newer",
        });
    }
    if candidate.channel == "prerelease" && !policy.allow_prerelease {
        return Ok(Decision::Refused {
            rule: "channel_not_allowed",
        });
    }

    let mut gates: Vec<&'static str> = Vec::new();
    if policy.mode == AutoApplyMode::ExplicitApproval {
        gates.push("auto_apply_disabled");
    }
    if !candidate.severity.is_compatible_patch() {
        gates.push(APPROVAL_BOUNDARIES[0]);
    }
    if candidate.schema_change {
        gates.push(APPROVAL_BOUNDARIES[1]);
    }
    if candidate.security_advisory {
        gates.push(APPROVAL_BOUNDARIES[2]);
    }
    if candidate.trust_root_change {
        gates.push(APPROVAL_BOUNDARIES[3]);
    }
    if candidate.host_config_rewrite {
        gates.push(APPROVAL_BOUNDARIES[4]);
    }
    gates.extend(readiness.missing());
    if candidate.channel == "prerelease" {
        gates.push("prerelease_never_auto_applies");
    }

    if !gates.is_empty() {
        return Ok(Decision::RequiresApproval { gates });
    }
    Ok(Decision::ApplyAutomatically {
        satisfied: READINESS_GATES.to_vec(),
    })
}

/// Parse `major.minor.patch`, ignoring a prerelease or build suffix.
fn parse_semver(value: &str) -> Option<(u64, u64, u64)> {
    let core = value.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// The one refusal shape of this module.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the update candidate violates the update policy contract",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A compatible patch candidate on `stable` that crosses no boundary.
    fn candidate() -> Candidate {
        Candidate {
            from_version: "1.2.3".to_string(),
            to_version: "1.2.4".to_string(),
            severity: Severity::Patch,
            channel: "stable".to_string(),
            schema_change: false,
            security_advisory: false,
            trust_root_change: false,
            host_config_rewrite: false,
        }
    }

    /// An operator that opted in to compatible-patch auto-apply.
    fn opted_in() -> UpdatePolicy {
        UpdatePolicy {
            mode: AutoApplyMode::CompatiblePatch,
            allow_prerelease: false,
        }
    }

    fn gates(
        policy: &UpdatePolicy,
        candidate: &Candidate,
        readiness: &Readiness,
    ) -> Vec<&'static str> {
        match decide(policy, candidate, readiness) {
            Ok(Decision::RequiresApproval { gates }) => gates,
            other => panic!("expected RequiresApproval, got {other:?}"),
        }
    }

    fn rule_of(error: &AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    #[test]
    fn default_policy_is_explicit_approval() {
        let policy = UpdatePolicy::default();
        assert_eq!(policy.mode, AutoApplyMode::ExplicitApproval);
        assert_eq!(policy.mode.as_str(), "explicit_approval");
        assert!(!policy.allow_prerelease);
    }

    #[test]
    fn default_policy_never_auto_applies_even_a_ready_patch() {
        let decision = decide(
            &UpdatePolicy::default(),
            &candidate(),
            &Readiness::complete(),
        )
        .expect("decide");
        assert_eq!(
            decision,
            Decision::RequiresApproval {
                gates: vec!["auto_apply_disabled"],
            }
        );
        assert!(!decision.is_automatic());
        assert!(!decision.is_refused());
    }

    #[test]
    fn opted_in_compatible_patch_applies_when_every_condition_holds() {
        let decision = decide(&opted_in(), &candidate(), &Readiness::complete()).expect("decide");
        assert_eq!(
            decision,
            Decision::ApplyAutomatically {
                satisfied: READINESS_GATES.to_vec(),
            }
        );
        assert!(decision.is_automatic());
        assert!(!decision.is_refused());
    }

    #[test]
    fn every_approval_boundary_stops_an_opted_in_patch() {
        let cases: [(Candidate, &'static str); 6] = [
            (
                Candidate {
                    severity: Severity::Minor,
                    ..candidate()
                },
                "minor_or_major_version",
            ),
            (
                Candidate {
                    severity: Severity::Major,
                    ..candidate()
                },
                "minor_or_major_version",
            ),
            (
                Candidate {
                    schema_change: true,
                    ..candidate()
                },
                "schema_migration",
            ),
            (
                Candidate {
                    security_advisory: true,
                    ..candidate()
                },
                "security_advisory",
            ),
            (
                Candidate {
                    trust_root_change: true,
                    ..candidate()
                },
                "trust_root_change",
            ),
            (
                Candidate {
                    host_config_rewrite: true,
                    ..candidate()
                },
                "host_config_rewrite",
            ),
        ];

        let mut covered: Vec<&'static str> = Vec::new();
        for (candidate, expected) in cases {
            let forced = gates(&opted_in(), &candidate, &Readiness::complete());
            assert!(
                forced.contains(&expected),
                "expected gate {expected} in {forced:?}"
            );
            if !covered.contains(&expected) {
                covered.push(expected);
            }
        }
        for boundary in APPROVAL_BOUNDARIES {
            assert!(covered.contains(&boundary), "uncovered boundary {boundary}");
        }
    }

    #[test]
    fn every_missing_readiness_condition_stops_an_opted_in_patch() {
        let cases: [(Readiness, &'static str); 5] = [
            (
                Readiness {
                    idle_window: false,
                    ..Readiness::complete()
                },
                READINESS_GATES[0],
            ),
            (
                Readiness {
                    drained: false,
                    ..Readiness::complete()
                },
                READINESS_GATES[1],
            ),
            (
                Readiness {
                    bundle_signature_verified: false,
                    ..Readiness::complete()
                },
                READINESS_GATES[2],
            ),
            (
                Readiness {
                    backup_and_rollback_ready: false,
                    ..Readiness::complete()
                },
                READINESS_GATES[3],
            ),
            (
                Readiness {
                    scope_grants_present: false,
                    ..Readiness::complete()
                },
                READINESS_GATES[4],
            ),
        ];

        for (readiness, expected) in cases {
            let forced = gates(&opted_in(), &candidate(), &readiness);
            assert_eq!(forced, vec![expected], "readiness gate {expected}");
        }
    }

    #[test]
    fn every_crossed_gate_is_named_in_declaration_order() {
        let candidate = Candidate {
            severity: Severity::Major,
            schema_change: true,
            security_advisory: true,
            trust_root_change: true,
            host_config_rewrite: true,
            ..candidate()
        };
        let readiness = Readiness {
            drained: false,
            ..Readiness::complete()
        };

        let forced = gates(&opted_in(), &candidate, &readiness);
        assert_eq!(
            forced,
            vec![
                "minor_or_major_version",
                "schema_migration",
                "security_advisory",
                "trust_root_change",
                "host_config_rewrite",
                "queue_not_drained",
            ]
        );
    }

    #[test]
    fn readiness_missing_reports_every_condition_and_none_when_complete() {
        assert!(Readiness::complete().missing().is_empty());
        let none_ready = Readiness::default();
        assert_eq!(none_ready.missing(), READINESS_GATES.to_vec());
    }

    #[test]
    fn prerelease_never_auto_applies_even_when_the_policy_allows_it() {
        let policy = UpdatePolicy {
            mode: AutoApplyMode::CompatiblePatch,
            allow_prerelease: true,
        };
        let candidate = Candidate {
            from_version: "1.2.3".to_string(),
            to_version: "1.2.4".to_string(),
            channel: "prerelease".to_string(),
            ..candidate()
        };

        let forced = gates(&policy, &candidate, &Readiness::complete());
        assert_eq!(forced, vec!["prerelease_never_auto_applies"]);
    }

    #[test]
    fn prerelease_is_refused_when_the_policy_does_not_allow_it() {
        let policy = UpdatePolicy {
            mode: AutoApplyMode::CompatiblePatch,
            allow_prerelease: false,
        };
        let candidate = Candidate {
            channel: "prerelease".to_string(),
            ..candidate()
        };

        let decision = decide(&policy, &candidate, &Readiness::complete()).expect("decide");
        assert_eq!(
            decision,
            Decision::Refused {
                rule: "channel_not_allowed",
            }
        );
        assert!(decision.is_refused());
    }

    #[test]
    fn a_candidate_that_is_not_newer_is_refused() {
        let same = Candidate {
            to_version: "1.2.3".to_string(),
            ..candidate()
        };
        assert_eq!(
            decide(&opted_in(), &same, &Readiness::complete()).expect("decide"),
            Decision::Refused {
                rule: "candidate_not_newer",
            }
        );

        let older = Candidate {
            to_version: "1.2.2".to_string(),
            ..candidate()
        };
        assert_eq!(
            decide(&opted_in(), &older, &Readiness::complete()).expect("decide"),
            Decision::Refused {
                rule: "candidate_not_newer",
            }
        );
    }

    #[test]
    fn an_unknown_channel_is_refused_not_errored() {
        let candidate = Candidate {
            channel: "nightly".to_string(),
            ..candidate()
        };
        let decision = decide(&opted_in(), &candidate, &Readiness::complete()).expect("decide");
        assert_eq!(
            decision,
            Decision::Refused {
                rule: "channel_not_supported",
            }
        );
    }

    #[test]
    fn versions_that_are_not_semver_are_contract_errors() {
        let installed = Candidate {
            from_version: "one.two.three".to_string(),
            ..candidate()
        };
        let error = decide(&opted_in(), &installed, &Readiness::complete()).expect_err("must fail");
        assert_eq!(rule_of(&error), Some("installed_version_not_semver"));
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("one.two.three")
        );

        let proposed = Candidate {
            to_version: "1.2.x.4".to_string(),
            ..candidate()
        };
        let error = decide(&opted_in(), &proposed, &Readiness::complete()).expect_err("must fail");
        assert_eq!(rule_of(&error), Some("candidate_version_not_semver"));
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("1.2.x.4")
        );
    }

    #[test]
    fn a_patch_with_build_metadata_is_still_a_compatible_patch() {
        let candidate = Candidate {
            to_version: "1.2.4+build.5".to_string(),
            ..candidate()
        };
        let decision = decide(&opted_in(), &candidate, &Readiness::complete()).expect("decide");
        assert!(decision.is_automatic(), "got {decision:?}");
    }

    #[test]
    fn a_patch_behind_a_prerelease_suffix_still_orders_by_its_core() {
        let candidate = Candidate {
            from_version: "1.2.3-rc.1".to_string(),
            to_version: "1.2.4".to_string(),
            ..candidate()
        };
        assert!(decide(&opted_in(), &candidate, &Readiness::complete())
            .expect("decide")
            .is_automatic());
    }

    #[test]
    fn wire_spellings_are_stable_and_closed() {
        assert_eq!(CHANNELS, ["stable", "prerelease"]);
        assert_eq!(APPROVAL_BOUNDARIES.len(), 5);
        assert_eq!(READINESS_GATES.len(), 5);

        assert_eq!(AutoApplyMode::all().len(), 2);
        assert_eq!(AutoApplyMode::CompatiblePatch.as_str(), "compatible_patch");

        assert_eq!(Severity::all().len(), 3);
        assert_eq!(Severity::Patch.as_str(), "patch");
        assert_eq!(Severity::Minor.as_str(), "minor");
        assert_eq!(Severity::Major.as_str(), "major");
        assert!(Severity::Patch.is_compatible_patch());
        assert!(!Severity::Minor.is_compatible_patch());
        assert!(!Severity::Major.is_compatible_patch());
    }
}
