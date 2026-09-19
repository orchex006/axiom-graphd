//! Ecosystem compatibility resolution (task E-038).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 5 step 2 requires the
//! planner to prefer the latest compatible **released stable SemVer**, explicitly
//! "not the latest commit or timestamp alone", and step 3 requires it to resolve
//! component dependency ranges and the graph/control/schema compatibility before
//! it locks exact artifact versions and hashes. Section 9's hazard table adds the
//! two failures this slice exists to prevent: a branch head that moved ahead of
//! the released version is not an update, and a candidate schema major newer than
//! the binary supports is refused rather than migrated downwards.
//!
//! This module resolves one component target from a candidate list. It is pure:
//! no network, no clock, no filesystem. It:
//!
//! * parses SemVer itself, with the contract's prerelease ordering, so the
//!   comparison never depends on a string sort;
//! * rejects every candidate that fails the graph/control/queue/spec constraints
//!   with a named rule, keeping the reasons so a report can show *why* the newest
//!   release was not chosen;
//! * selects the highest compatible version in the requested channel, never the
//!   newest publication time and never the newest revision;
//! * reports `noop` when the highest compatible release equals what is installed,
//!   and fails closed when nothing is compatible at all.

use graph_core::error::{AxiomError, ErrorCode};
use serde::{Deserialize, Serialize};

use crate::install::plan::is_digest;
use crate::update::source::CHANNELS;

/// Components the update-plan contract names, in schema order.
pub const COMPONENTS: [&str; 4] = ["axiom-graphd", "axiom-mcp", "axiom", "skills"];

/// The action an update plan records for one component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedAction {
    /// Nothing is installed yet.
    Install,
    /// A newer compatible release replaces the installed one.
    Upgrade,
    /// The highest compatible release is already installed.
    Noop,
}

impl ResolvedAction {
    /// Stable spelling, matching `contracts/schemas/update-plan.schema.json`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Upgrade => "upgrade",
            Self::Noop => "noop",
        }
    }
}

/// The compatibility constraints a candidate must satisfy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constraints {
    /// Component being updated.
    pub component: String,
    /// Channel the update follows.
    pub channel: String,
    /// Graph payload schema major this binary reads and writes.
    pub graph_schema_major: u32,
    /// Control API version this binary speaks.
    pub control_api: u32,
    /// Durable queue schema version this binary understands.
    pub queue_schema: u32,
    /// Specification baseline of this build.
    pub spec_version: String,
}

/// One published release candidate of one component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentRelease {
    /// Component the release belongs to.
    pub component: String,
    /// Released SemVer.
    pub version: String,
    /// Source revision the release was built from.
    pub revision: String,
    /// Channel the release was published on.
    pub channel: String,
    /// Specification baseline the release implements.
    pub spec_version: String,
    /// Graph payload schema major the release writes.
    pub graph_schema: u32,
    /// Control API version the release speaks.
    pub control_api: u32,
    /// Durable queue schema version the release understands.
    pub queue_schema: u32,
    /// Trusted lowercase 64-hex digest of the release artifact.
    pub artifact_sha256: String,
    /// RFC 3339 UTC publication time; recorded, never used to rank.
    pub published_at: String,
}

/// Why one candidate was not selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rejection {
    /// Version that was rejected.
    pub version: String,
    /// Named rule that rejected it.
    pub rule: String,
}

/// The one selected update target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedUpdate {
    /// Component being updated.
    pub component: String,
    /// Installed version, when one is recorded.
    pub installed_version: Option<String>,
    /// Selected target version.
    pub target_version: String,
    /// Selected target revision.
    pub target_revision: String,
    /// Selected target artifact digest.
    pub artifact_sha256: String,
    /// Action the plan records.
    pub action: ResolvedAction,
    /// Number of candidates that satisfied every constraint.
    pub compatible_candidates: usize,
    /// Every rejected candidate with its named rule.
    pub rejected: Vec<Rejection>,
}

/// Resolve the update target for one component.
///
/// # Errors
///
/// Fails closed with a named `rule` when the constraints are unusable, when the
/// installed component is unknown, or when no candidate satisfies the
/// constraints (`no_compatible_release`).
pub fn resolve(
    candidates: &[ComponentRelease],
    constraints: &Constraints,
    installed_version: Option<&str>,
) -> Result<ResolvedUpdate, AxiomError> {
    validate_constraints(constraints)?;
    let installed = installed_version.map(parse_version).transpose()?;

    let mut compatible: Vec<(Version, &ComponentRelease)> = Vec::new();
    let mut rejected: Vec<Rejection> = Vec::new();
    for candidate in candidates {
        match evaluate_candidate(candidate, constraints, installed.as_ref()) {
            Ok(version) => compatible.push((version, candidate)),
            Err(rule) => rejected.push(Rejection {
                version: candidate.version.clone(),
                rule,
            }),
        }
    }

    if compatible.is_empty() {
        return Err(refuse(
            "no_compatible_release",
            &format!(
                "component={};candidates={};rejected={}",
                constraints.component,
                candidates.len(),
                rejected.len()
            ),
        ));
    }
    rejected.sort_by(|left, right| left.version.cmp(&right.version));
    let compatible_candidates = compatible.len();
    // Highest compatible SemVer wins; ties are impossible because a duplicate
    // version would be a duplicate release and both keys compare equal.
    compatible.sort_by(|left, right| left.0.cmp(&right.0));
    let (selected_version, selected) = compatible.pop().expect("non-empty after the check above");

    let action = match &installed {
        None => ResolvedAction::Install,
        Some(current) if *current == selected_version => ResolvedAction::Noop,
        Some(_) => ResolvedAction::Upgrade,
    };
    Ok(ResolvedUpdate {
        component: selected.component.clone(),
        installed_version: installed_version.map(str::to_string),
        target_version: selected.version.clone(),
        target_revision: selected.revision.clone(),
        artifact_sha256: selected.artifact_sha256.clone(),
        action,
        compatible_candidates,
        rejected,
    })
}

/// Accept one candidate, or name the rule that rejects it.
fn evaluate_candidate(
    candidate: &ComponentRelease,
    constraints: &Constraints,
    installed: Option<&Version>,
) -> Result<Version, String> {
    if candidate.component != constraints.component {
        return Err("component_not_selected".to_string());
    }
    if candidate.channel != constraints.channel {
        return Err("channel_not_selected".to_string());
    }
    let version = Version::parse(&candidate.version).ok_or_else(|| "invalid_semver".to_string())?;
    if constraints.channel == "stable" && version.pre.is_some() {
        return Err("prerelease_not_on_stable".to_string());
    }
    if candidate.spec_version != constraints.spec_version {
        return Err("spec_version_pin_mismatch".to_string());
    }
    if candidate.graph_schema != constraints.graph_schema_major {
        return Err("graph_schema_incompatible".to_string());
    }
    if candidate.control_api > constraints.control_api {
        return Err("control_api_newer_than_binary".to_string());
    }
    if candidate.queue_schema > constraints.queue_schema {
        return Err("queue_schema_newer_than_binary".to_string());
    }
    if !is_revision(&candidate.revision) {
        return Err("invalid_revision".to_string());
    }
    if !is_digest(&candidate.artifact_sha256) {
        return Err("invalid_artifact_hash".to_string());
    }
    if installed.is_some_and(|current| version < *current) {
        return Err("older_than_installed".to_string());
    }
    Ok(version)
}

/// Validate the requested constraints before any candidate is considered.
fn validate_constraints(constraints: &Constraints) -> Result<(), AxiomError> {
    if !COMPONENTS.contains(&constraints.component.as_str()) {
        return Err(refuse(
            "unsupported_component",
            &format!("component={}", constraints.component),
        ));
    }
    if !CHANNELS.contains(&constraints.channel.as_str()) {
        return Err(refuse(
            "unsupported_channel",
            &format!("channel={}", constraints.channel),
        ));
    }
    if Version::parse(&constraints.spec_version).is_none() {
        return Err(refuse(
            "invalid_spec_version",
            &format!("spec_version={}", constraints.spec_version),
        ));
    }
    Ok(())
}

/// Parse an optional installed version string.
fn parse_version(text: &str) -> Result<Version, AxiomError> {
    Version::parse(text).ok_or_else(|| {
        refuse(
            "invalid_installed_version",
            &format!("installed_version={text}"),
        )
    })
}

/// True when `text` is a lowercase 40-hex revision.
fn is_revision(text: &str) -> bool {
    text.len() == 40
        && text
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// The one refusal shape of this module.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the candidate set violates the compatibility contract",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

/// A parsed SemVer version with the contract's ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Version {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Option<Vec<String>>,
}

impl Version {
    /// Parse `major.minor.patch[-prerelease][+build]`.
    ///
    /// Returns `None` for anything the contract would not accept: a missing
    /// component, a leading zero in a numeric identifier, or an empty
    /// prerelease/build identifier.
    fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let (core_and_pre, _build) = match text.split_once('+') {
            Some((left, build)) => {
                if build.is_empty() || build.split('.').any(|part| part.is_empty()) {
                    return None;
                }
                (left, Some(build))
            }
            None => (text, None),
        };
        let (core, pre) = match core_and_pre.split_once('-') {
            Some((core, pre)) => {
                let identifiers: Vec<String> = pre.split('.').map(str::to_string).collect();
                if identifiers.is_empty() || identifiers.iter().any(String::is_empty) {
                    return None;
                }
                (core, Some(identifiers))
            }
            None => (core_and_pre, None),
        };
        let mut parts = core.split('.');
        let major = numeric(parts.next()?)?;
        let minor = numeric(parts.next()?)?;
        let patch = numeric(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
            pre,
        })
    }
}

/// Parse one numeric SemVer component, refusing a leading zero.
fn numeric(text: &str) -> Option<u64> {
    if text.is_empty() || !text.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if text.len() > 1 && text.starts_with('0') {
        return None;
    }
    text.parse().ok()
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.major
            .cmp(&other.major)
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| self.patch.cmp(&other.patch))
            .then_with(|| compare_prerelease(self.pre.as_deref(), other.pre.as_deref()))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// SemVer prerelease ordering: a release is higher than its prereleases, a
/// numeric identifier is lower than an alphanumeric one, and a shorter list is
/// lower when all shared identifiers are equal.
fn compare_prerelease(left: Option<&[String]>, right: Option<&[String]>) -> std::cmp::Ordering {
    match (left, right) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(left), Some(right)) => {
            for (a, b) in left.iter().zip(right.iter()) {
                let ordering = compare_identifier(a, b);
                if ordering != std::cmp::Ordering::Equal {
                    return ordering;
                }
            }
            left.len().cmp(&right.len())
        }
    }
}

/// Compare one prerelease identifier.
fn compare_identifier(left: &str, right: &str) -> std::cmp::Ordering {
    let left_numeric = left.chars().all(|c| c.is_ascii_digit());
    let right_numeric = right.chars().all(|c| c.is_ascii_digit());
    match (left_numeric, right_numeric) {
        (true, true) => left.parse::<u64>().ok().cmp(&right.parse::<u64>().ok()),
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        (false, false) => left.cmp(right),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(
        version: &str,
        channel: &str,
        graph: u32,
        queue: u32,
        published: &str,
    ) -> ComponentRelease {
        ComponentRelease {
            component: "axiom-graphd".to_string(),
            version: version.to_string(),
            revision: "a".repeat(40),
            channel: channel.to_string(),
            spec_version: "2.0.0-draft.1".to_string(),
            graph_schema: graph,
            control_api: 1,
            queue_schema: queue,
            artifact_sha256: "b".repeat(64),
            published_at: published.to_string(),
        }
    }

    fn constraints() -> Constraints {
        Constraints {
            component: "axiom-graphd".to_string(),
            channel: "stable".to_string(),
            graph_schema_major: 1,
            control_api: 1,
            queue_schema: 1,
            spec_version: "2.0.0-draft.1".to_string(),
        }
    }

    fn rule_of(error: &AxiomError) -> String {
        error.details().get("rule").cloned().unwrap_or_default()
    }

    #[test]
    fn the_highest_compatible_release_wins_over_the_newest_publication() {
        // 0.4.0 writes a newer graph schema major and is refused; 0.2.0 is the
        // newest publication yet still loses to the higher 0.3.0; 0.0.9 is older
        // than the installed 0.1.0 and is refused for that reason.
        let candidates = vec![
            release("0.4.0", "stable", 2, 1, "2026-09-10T00:00:00Z"),
            release("0.3.0", "stable", 1, 1, "2026-09-01T00:00:00Z"),
            release("0.2.0", "stable", 1, 1, "2026-09-15T00:00:00Z"),
            release("0.0.9", "stable", 1, 1, "2026-09-20T00:00:00Z"),
        ];
        let resolved = resolve(&candidates, &constraints(), Some("0.1.0")).expect("resolves");
        assert_eq!(resolved.target_version, "0.3.0");
        assert_eq!(resolved.action, ResolvedAction::Upgrade);
        assert_eq!(resolved.compatible_candidates, 2);
        assert!(resolved
            .rejected
            .iter()
            .any(|rejection| rejection.version == "0.4.0"
                && rejection.rule == "graph_schema_incompatible"));
        assert!(resolved
            .rejected
            .iter()
            .any(|rejection| rejection.version == "0.0.9"
                && rejection.rule == "older_than_installed"));
        // The newest publication is compatible, yet it is not the target.
        assert!(!resolved
            .rejected
            .iter()
            .any(|rejection| rejection.version == "0.2.0"));
    }
    #[test]
    fn a_candidate_that_breaks_a_schema_constraint_is_named_not_selected() {
        let candidates = vec![
            release("0.5.0", "stable", 1, 2, "2026-09-10T00:00:00Z"),
            release("0.4.1", "stable", 1, 1, "2026-09-09T00:00:00Z"),
        ];
        let resolved = resolve(&candidates, &constraints(), Some("0.4.0")).expect("resolves");
        assert_eq!(resolved.target_version, "0.4.1");
        assert_eq!(resolved.action, ResolvedAction::Upgrade);
        assert!(resolved
            .rejected
            .iter()
            .any(|rejection| rejection.rule == "queue_schema_newer_than_binary"));

        // A control-API-newer candidate is rejected the same way.
        let mut newer_control = release("0.6.0", "stable", 1, 1, "2026-09-11T00:00:00Z");
        newer_control.control_api = 2;
        let resolved = resolve(
            &[
                newer_control,
                release("0.4.1", "stable", 1, 1, "2026-09-09T00:00:00Z"),
            ],
            &constraints(),
            Some("0.4.0"),
        )
        .expect("resolves");
        assert_eq!(resolved.target_version, "0.4.1");
        assert!(resolved
            .rejected
            .iter()
            .any(|rejection| rejection.rule == "control_api_newer_than_binary"));
    }
    #[test]
    fn a_prerelease_is_not_selected_on_the_stable_channel() {
        let candidates = vec![
            // A prerelease SemVer on the stable channel must be refused there.
            release("1.0.0-rc.1", "stable", 1, 1, "2026-09-12T00:00:00Z"),
            // The same release on the prerelease channel is not a stable target.
            release("1.0.0-rc.1", "prerelease", 1, 1, "2026-09-12T00:00:00Z"),
            release("0.9.0", "stable", 1, 1, "2026-09-01T00:00:00Z"),
        ];
        let resolved = resolve(&candidates, &constraints(), Some("0.8.0")).expect("resolves");
        assert_eq!(resolved.target_version, "0.9.0");
        assert!(resolved
            .rejected
            .iter()
            .any(|rejection| rejection.rule == "prerelease_not_on_stable"));

        // The same candidate is eligible on the prerelease channel.
        let mut alpha = constraints();
        alpha.channel = "prerelease".to_string();
        let resolved = resolve(&candidates, &alpha, Some("0.8.0")).expect("resolves");
        assert_eq!(resolved.target_version, "1.0.0-rc.1");
    }
    #[test]
    fn a_candidate_for_another_component_or_spec_pin_is_rejected() {
        let mut foreign = release("9.9.9", "stable", 1, 1, "2026-09-20T00:00:00Z");
        foreign.component = "axiom-mcp".to_string();
        let mut repinned = release("1.2.3", "stable", 1, 1, "2026-09-20T00:00:00Z");
        repinned.spec_version = "2.0.0-draft.2".to_string();
        let resolved = resolve(
            &[
                foreign,
                repinned,
                release("0.2.0", "stable", 1, 1, "2026-09-01T00:00:00Z"),
            ],
            &constraints(),
            Some("0.1.0"),
        )
        .expect("resolves");
        assert_eq!(resolved.target_version, "0.2.0");
        assert!(resolved
            .rejected
            .iter()
            .any(|rejection| rejection.rule == "component_not_selected"));
        assert!(resolved
            .rejected
            .iter()
            .any(|rejection| rejection.rule == "spec_version_pin_mismatch"));
    }

    #[test]
    fn an_installed_highest_release_is_a_noop_and_an_empty_set_is_an_error() {
        let candidates = vec![release("0.3.0", "stable", 1, 1, "2026-09-01T00:00:00Z")];
        let resolved = resolve(&candidates, &constraints(), Some("0.3.0")).expect("resolves");
        assert_eq!(resolved.action, ResolvedAction::Noop);
        assert_eq!(resolved.target_version, "0.3.0");

        // Nothing installed yet is an install, not an upgrade.
        let resolved = resolve(&candidates, &constraints(), None).expect("resolves");
        assert_eq!(resolved.action, ResolvedAction::Install);

        // No compatible candidate at all fails closed instead of guessing.
        let error = resolve(
            &[release("9.9.9", "stable", 7, 1, "2026-09-01T00:00:00Z")],
            &constraints(),
            Some("0.3.0"),
        )
        .expect_err("an incompatible set must fail");
        assert_eq!(rule_of(&error), "no_compatible_release");

        // An unusable constraint is refused before any candidate is considered.
        let mut bad = constraints();
        bad.channel = "nightly".to_string();
        let error = resolve(&candidates, &bad, None).expect_err("a bad channel must fail");
        assert_eq!(rule_of(&error), "unsupported_channel");
    }

    #[test]
    fn semver_parsing_and_ordering_follow_the_contract() {
        assert!(Version::parse("1.0.0").is_some());
        assert!(Version::parse("01.0.0").is_none(), "leading zero");
        assert!(Version::parse("1.0").is_none(), "missing patch");
        assert!(Version::parse("1.0.0-").is_none(), "empty prerelease");
        assert!(Version::parse("1.0.0+").is_none(), "empty build");
        assert!(Version::parse("1.0.0+build.1").is_some(), "build metadata");

        let ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ];
        for pair in ordered.windows(2) {
            let left = Version::parse(pair[0]).expect("parses");
            let right = Version::parse(pair[1]).expect("parses");
            assert!(left < right, "{} < {}", pair[0], pair[1]);
        }
        assert_eq!(COMPONENTS.len(), 4);
        assert_eq!(ResolvedAction::Noop.as_str(), "noop");
        assert_eq!(ResolvedAction::Upgrade.as_str(), "upgrade");
        assert_eq!(ResolvedAction::Install.as_str(), "install");
    }

    #[test]
    fn a_candidate_with_a_broken_revision_or_hash_is_rejected() {
        let mut bad_revision = release("0.2.0", "stable", 1, 1, "2026-09-01T00:00:00Z");
        bad_revision.revision = "not-a-revision".to_string();
        let mut bad_hash = release("0.3.0", "stable", 1, 1, "2026-09-01T00:00:00Z");
        bad_hash.artifact_sha256 = "zz".repeat(32);
        let mut uppercase = release("0.4.0", "stable", 1, 1, "2026-09-01T00:00:00Z");
        uppercase.revision = "A".repeat(40);
        let resolved = resolve(
            &[
                bad_revision,
                bad_hash,
                uppercase,
                release("0.1.0", "stable", 1, 1, "2026-09-01T00:00:00Z"),
            ],
            &constraints(),
            None,
        )
        .expect("resolves");
        assert_eq!(resolved.target_version, "0.1.0");
        assert!(resolved
            .rejected
            .iter()
            .any(|rejection| rejection.rule == "invalid_revision"));
        assert!(resolved
            .rejected
            .iter()
            .any(|rejection| rejection.rule == "invalid_artifact_hash"));
    }
}
