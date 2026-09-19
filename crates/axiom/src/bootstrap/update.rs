//! Update the managed policy across every registered repository (task E-022).
//!
//! `docs/18-BOOTSTRAP-AND-MANAGED-INSTRUCTIONS.md` section 7 defines the update
//! flow: a new template version is planned against the explicitly approved
//! repository set, every repository is diffed, and only owned content moves.
//! This module is that flow's decision layer. It adds exactly three things on
//! top of the engine the earlier tasks built:
//!
//! 1. a **template compatibility gate** - the installed version and the shipped
//!    version are compared before a single repository is read, so a downgrade or
//!    a major-version change is refused as a whole instead of half-applied;
//! 2. a **per-repository update row** - old version, new version, the planned
//!    change class and, for a repository bootstrap will not touch, the same
//!    stable refusal the plan carried, so a conflicted repository is *skipped
//!    with an explicit report* rather than silently dropped;
//! 3. an **ownership proof over the planned bytes** - [`ensure_owned_paths`]
//!    refuses a plan that would write anything outside
//!    [`OWNED_PATHS`], and [`ensure_only_owned_span`] refuses a planned
//!    `AGENTS.md` change that is not exactly the owned span replaced (an append
//!    must keep the previous document as an exact prefix).
//!
//! The actual merge is not re-implemented here: [`plan_update`] calls
//! [`plan::plan_repository`] per repository, so an update and an initial
//! bootstrap can never disagree about the managed-merge algorithm, the encoding
//! rules or the ownership manifest. [`UpdatePlan::to_bootstrap_plan`] hands the
//! same rows back as a [`BootstrapPlan`], so an approved update is applied and
//! journalled by the existing `apply` path with its before-hash
//! re-verification intact.
//!
//! Update never decides to publish anything: a plan is a review document, and
//! the commit/push decision belongs to `bootstrap::commit_plan`.

use graph_core::error::AxiomError;
use serde::{Deserialize, Serialize};

use super::markers;
use super::ownership::{self, Ownership};
use super::plan::{
    self, BootstrapPlan, ChangeClass, Refusal, RepositoryPlan, RepositoryTarget, Templates,
};
use super::policy::POLICY_PATH;
use super::refuse;
use super::text;

/// The repository-relative paths bootstrap owns and may therefore update.
///
/// This is the same owned set the plan and the ownership manifest already
/// describe; it is restated here as one value so an update can *check* that a
/// plan stayed inside it instead of trusting that it did.
pub const OWNED_PATHS: [&str; 3] = [plan::AGENTS_PATH, POLICY_PATH, ownership::OWNERSHIP_PATH];

/// Stable rule code: a template version is not a version this build can parse.
pub const RULE_UPDATE_VERSION: &str = "update-template-version";

/// Stable rule code: the target template is older than the installed one.
pub const RULE_UPDATE_DOWNGRADE: &str = "update-template-downgrade";

/// Stable rule code: the target template changes the major version.
pub const RULE_UPDATE_MAJOR: &str = "update-template-major-change";

/// Stable rule code: a planned update would write a path bootstrap does not own.
pub const RULE_UPDATE_UNOWNED_PATH: &str = "update-unowned-path";

/// Stable rule code: a planned `AGENTS.md` change alters bytes outside the
/// managed span, or an append does not keep the previous document as a prefix.
pub const RULE_UPDATE_OUTSIDE: &str = "update-outside-owned-span";

/// How a shipped template compares with the template a repository has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TemplateCompatibility {
    /// Same major version, newer minor/patch: the compatible update this task
    /// exists for.
    Newer,
    /// The same version: a re-apply is a no-op.
    Same,
    /// An older version: refused, because the ownership manifest would move
    /// backwards over content a human may already have reviewed.
    Downgrade,
    /// A different major version: refused; that is a migration, not an update.
    MajorChange,
}

impl TemplateCompatibility {
    /// Stable string form for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Newer => "newer",
            Self::Same => "same",
            Self::Downgrade => "downgrade",
            Self::MajorChange => "major-change",
        }
    }

    /// Whether the target template may be planned against an installation at
    /// this version.
    #[must_use]
    pub const fn is_acceptable(self) -> bool {
        matches!(self, Self::Newer | Self::Same)
    }
}

/// A parsed `MAJOR.MINOR.PATCH` template version with an optional pre-release.
///
/// Only the ordering properties update needs are interpreted; build metadata is
/// ignored, exactly as SemVer says it should be for precedence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateVersion {
    /// Major version: changes require a migration, not an update.
    pub major: u64,
    /// Minor version.
    pub minor: u64,
    /// Patch version.
    pub patch: u64,
    /// Pre-release identifier, when present. `None` sorts after `Some(_)`.
    pub prerelease: Option<String>,
}

impl Ord for TemplateVersion {
    /// SemVer precedence over the fields that order a template.
    ///
    /// Build metadata is already dropped at parse time, a missing pre-release
    /// sorts *after* a present one (so `1.2.0` is newer than `1.2.0-rc.1`), and
    /// two pre-releases compare lexically - enough for the ordered
    /// `2.0.0-draft.N` templates this build ships, and deliberately not a claim
    /// of full numeric pre-release precedence.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.prerelease, &other.prerelease) {
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (Some(_), None) => std::cmp::Ordering::Less,
                (Some(left), Some(right)) => left.cmp(right),
            })
    }
}

impl PartialOrd for TemplateVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TemplateVersion {
    /// Parse a template version.
    ///
    /// # Errors
    ///
    /// Returns a conflict carrying [`RULE_UPDATE_VERSION`] for an empty or
    /// malformed version. The observed value is attached, so a caller can report
    /// what it saw without re-parsing.
    pub fn parse(text: &str) -> Result<Self, AxiomError> {
        let invalid = || {
            refuse(RULE_UPDATE_VERSION, "not a template version")
                .with_detail("field", "template_version")
                .with_detail("observed", text)
        };
        let (numbers, prerelease) = match text.split_once('+') {
            Some((head, _build)) => (head, None),
            None => match text.split_once('-') {
                Some((head, pre)) => (head, Some(pre.to_owned())),
                None => (text, None),
            },
        };
        // A pre-release identifier contains only the characters SemVer allows.
        if prerelease.as_deref().is_some_and(|pre| {
            pre.is_empty()
                || !pre.split('.').all(|part| {
                    !part.is_empty()
                        && part
                            .chars()
                            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
                })
        }) {
            return Err(invalid());
        }
        let mut parts = numbers.split('.');
        let mut next = || {
            parts.next().ok_or_else(invalid).and_then(|part| {
                if part.is_empty() || !part.chars().all(|ch| ch.is_ascii_digit()) {
                    return Err(invalid());
                }
                part.parse::<u64>().map_err(|_error| invalid())
            })
        };
        let major = next()?;
        let minor = next()?;
        let patch = next()?;
        if parts.next().is_some() {
            return Err(invalid());
        }
        Ok(Self {
            major,
            minor,
            patch,
            prerelease,
        })
    }
}

impl std::fmt::Display for TemplateVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.prerelease {
            Some(pre) => write!(
                formatter,
                "{}.{}.{}-{pre}",
                self.major, self.minor, self.patch
            ),
            None => write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch),
        }
    }
}

/// How the shipped template compares with the installed one.
///
/// # Errors
///
/// Returns [`RULE_UPDATE_VERSION`] when either version is malformed.
pub fn compatibility(installed: &str, shipped: &str) -> Result<TemplateCompatibility, AxiomError> {
    let installed = TemplateVersion::parse(installed)?;
    let shipped = TemplateVersion::parse(shipped)?;
    if installed.major != shipped.major {
        return Ok(TemplateCompatibility::MajorChange);
    }
    Ok(match shipped.cmp(&installed) {
        std::cmp::Ordering::Equal => TemplateCompatibility::Same,
        std::cmp::Ordering::Less => TemplateCompatibility::Downgrade,
        std::cmp::Ordering::Greater => TemplateCompatibility::Newer,
    })
}

/// Accept only a template version this installation may move to.
///
/// # Errors
///
/// Returns [`RULE_UPDATE_DOWNGRADE`] for an older version, [`RULE_UPDATE_MAJOR`]
/// for a different major version and [`RULE_UPDATE_VERSION`] for a malformed
/// version. The check happens before any repository is read, so an unacceptable
/// template can never produce a partial update.
pub fn require_compatible_template(
    installed: &str,
    shipped: &str,
) -> Result<TemplateCompatibility, AxiomError> {
    let compatibility = compatibility(installed, shipped)?;
    match compatibility {
        TemplateCompatibility::Downgrade => Err(refuse(
            RULE_UPDATE_DOWNGRADE,
            format!("refusing to move the managed template from {installed} back to {shipped}"),
        )
        .with_detail("field", "template_version")
        .with_detail("observed", shipped)),
        TemplateCompatibility::MajorChange => Err(refuse(
            RULE_UPDATE_MAJOR,
            format!(
                "refusing to update across a major template version ({installed} to {shipped}); that is a migration"
            ),
        )
        .with_detail("field", "template_version")
        .with_detail("observed", shipped)),
        _ => Ok(compatibility),
    }
}

/// What an update would do to one repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateOutcome {
    /// The repository would move to the shipped template.
    Update,
    /// The repository already matches the shipped template.
    Unchanged,
    /// Bootstrap refuses this repository; it is skipped and reported.
    Skipped,
}

impl UpdateOutcome {
    /// Stable string form for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::Unchanged => "unchanged",
            Self::Skipped => "skipped",
        }
    }
}

/// One repository's row in an update plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryUpdate {
    /// Stable identifier of the repository.
    pub repository_id: String,
    /// Display root of the repository.
    pub root: String,
    /// Template version observed in the ownership manifest, when there is one.
    pub from_version: Option<String>,
    /// Template version this update proposes.
    pub to_version: String,
    /// What the update would do.
    pub outcome: UpdateOutcome,
    /// Why the repository is skipped, when it is.
    pub refusal: Option<Refusal>,
    /// The underlying plan row, so applying reuses the reviewed bytes.
    pub plan: RepositoryPlan,
}

impl RepositoryUpdate {
    /// The change class the underlying plan recorded.
    #[must_use]
    pub fn change(&self) -> ChangeClass {
        self.plan.change
    }

    /// The repository-relative paths this row would write.
    #[must_use]
    pub fn paths(&self) -> Vec<&str> {
        self.plan
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect()
    }
}

/// The whole multi-repository update decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePlan {
    /// Template version the approved repositories were at when planned.
    pub from_version: String,
    /// Template version this plan moves to.
    pub to_version: String,
    /// Compatibility verdict between the two versions.
    pub compatibility: TemplateCompatibility,
    /// One row per approved repository, in the order it was given.
    pub repositories: Vec<RepositoryUpdate>,
}

impl UpdatePlan {
    /// How many repositories would move to the shipped template.
    #[must_use]
    pub fn updated(&self) -> usize {
        self.repositories
            .iter()
            .filter(|row| row.outcome == UpdateOutcome::Update)
            .count()
    }

    /// How many repositories already match.
    #[must_use]
    pub fn unchanged(&self) -> usize {
        self.repositories
            .iter()
            .filter(|row| row.outcome == UpdateOutcome::Unchanged)
            .count()
    }

    /// The repositories this update skips, with their refusal.
    #[must_use]
    pub fn skipped(&self) -> Vec<&RepositoryUpdate> {
        self.repositories
            .iter()
            .filter(|row| row.outcome == UpdateOutcome::Skipped)
            .collect()
    }

    /// The repositories that will *not* move to the shipped version, whether
    /// because they already match or because bootstrap refuses them. This is the
    /// "remaining repositories" list section 7 of the contract requires.
    #[must_use]
    pub fn remaining(&self) -> Vec<&RepositoryUpdate> {
        self.repositories
            .iter()
            .filter(|row| row.outcome != UpdateOutcome::Update)
            .collect()
    }

    /// Whether every repository would move or already matches.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.skipped().is_empty()
    }

    /// A human-readable review document: per repository, old version, new
    /// version, outcome and the planned paths.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "bootstrap update {} -> {} ({})\n",
            self.from_version,
            self.to_version,
            self.compatibility.as_str()
        ));
        for row in &self.repositories {
            out.push_str(&format!(
                "\n== {} ({}) - {}\n   version: {} -> {}\n",
                row.repository_id,
                row.root,
                row.outcome.as_str(),
                row.from_version.as_deref().unwrap_or("absent"),
                row.to_version
            ));
            if let Some(refusal) = &row.refusal {
                out.push_str(&format!(
                    "   skipped: {} - {}\n",
                    refusal.rule, refusal.message
                ));
            }
            for path in row.paths() {
                out.push_str(&format!("   {path}\n"));
            }
        }
        out
    }

    /// The same rows as a [`BootstrapPlan`], so the existing re-verifying apply
    /// path can carry the update out.
    ///
    /// # Errors
    ///
    /// Returns a conflict when the document cannot be encoded.
    pub fn to_bootstrap_plan(&self, templates: &Templates) -> Result<BootstrapPlan, AxiomError> {
        BootstrapPlan::new(
            self.repositories
                .iter()
                .map(|row| row.plan.clone())
                .collect(),
            templates,
        )
    }
}

/// Refuse a plan that would write a path outside [`OWNED_PATHS`].
///
/// The plan is generated by this build, so this is a cheap structural assertion
/// rather than a parser: it makes "an update only ever touches owned paths" a
/// checked property of the value that reaches apply.
///
/// # Errors
///
/// Returns a conflict carrying [`RULE_UPDATE_UNOWNED_PATH`].
pub fn ensure_owned_paths(plan: &RepositoryPlan) -> Result<(), AxiomError> {
    for file in &plan.files {
        if !OWNED_PATHS.contains(&file.path.as_str()) {
            return Err(refuse(
                RULE_UPDATE_UNOWNED_PATH,
                format!(
                    "refusing to update the unowned path {} in {}",
                    file.path, plan.repository_id
                ),
            )
            .with_detail("field", "path")
            .with_detail("observed", file.path.as_str()));
        }
    }
    Ok(())
}

/// Refuse an `AGENTS.md` change that is not exactly the owned span replaced.
///
/// When the before-document already has a managed span, the after-document must
/// be that span replaced by the new block and nothing else
/// ([`text::replaces_only_span`], the same definition the planner and the
/// applier use). When it has none, the append must keep the previous document as
/// an exact prefix.
///
/// # Errors
///
/// Returns a conflict carrying [`RULE_UPDATE_OUTSIDE`].
pub fn ensure_only_owned_span(before: &str, after: &str) -> Result<(), AxiomError> {
    let preserved = match markers::managed_span(before) {
        Ok(Some(span)) => {
            let replacement = markers::managed_span(after)
                .ok()
                .flatten()
                .and_then(|after_span| after_span.slice(after))
                .unwrap_or_default();
            text::replaces_only_span(before, after, span, replacement)
        }
        // No managed span yet: appending must leave every existing byte in place.
        Ok(None) => after.starts_with(before),
        // An ambiguous marker shape is the plan's conflict to report; it is not
        // this assertion's job to re-derive it.
        Err(_) => true,
    };
    if preserved {
        return Ok(());
    }
    Err(refuse(
        RULE_UPDATE_OUTSIDE,
        "the planned update changes content outside the owned span",
    )
    .with_detail("field", "managed_span")
    .with_detail("observed", "outside-content-changed"))
}

/// Plan an update of the approved repository set to `templates`.
///
/// The compatibility gate runs first, so an unacceptable template is refused
/// before any repository is read. Each repository is then planned by
/// [`plan::plan_repository`] and guarded by [`ensure_owned_paths`] and
/// [`ensure_only_owned_span`]; a repository bootstrap refuses becomes a
/// [`UpdateOutcome::Skipped`] row carrying its refusal, and the remaining
/// repositories are still planned.
///
/// # Errors
///
/// Returns the compatibility refusal, a conflict when a template is unusable or
/// an owned-path/span assertion fails, and propagates a reader that cannot read
/// its host.
pub fn plan_update(
    targets: &[RepositoryTarget<'_>],
    templates: &Templates,
    installed_version: &str,
) -> Result<UpdatePlan, AxiomError> {
    let compatibility = require_compatible_template(installed_version, &templates.version)?;
    let mut repositories = Vec::with_capacity(targets.len());
    for target in targets {
        let repository = plan::plan_repository(target, templates)?;
        ensure_owned_paths(&repository)?;
        if repository.change == ChangeClass::Replace {
            let before_raw = target.reader.read(plan::AGENTS_PATH)?;
            let after_raw = repository
                .files
                .iter()
                .find(|file| file.path == plan::AGENTS_PATH)
                .map(|file| file.bytes.as_slice());
            if let (Some(before_raw), Some(after_raw)) = (before_raw.as_deref(), after_raw) {
                let before = std::str::from_utf8(before_raw).unwrap_or_default();
                let after = std::str::from_utf8(after_raw).unwrap_or_default();
                ensure_only_owned_span(before, after)?;
            }
        }
        let refusal = repository.refusal.clone();
        let outcome = if repository.is_conflict() {
            UpdateOutcome::Skipped
        } else if repository.change == ChangeClass::Unchanged {
            UpdateOutcome::Unchanged
        } else {
            UpdateOutcome::Update
        };
        repositories.push(RepositoryUpdate {
            repository_id: repository.repository_id.clone(),
            root: repository.root.clone(),
            from_version: installed_in(target.reader)?,
            to_version: templates.version.clone(),
            outcome,
            refusal,
            plan: repository,
        });
    }
    Ok(UpdatePlan {
        from_version: installed_version.to_owned(),
        to_version: templates.version.clone(),
        compatibility,
        repositories,
    })
}

/// The template version a repository's ownership manifest records, when it has
/// a readable one.
fn installed_in(reader: &dyn plan::RepositoryReader) -> Result<Option<String>, AxiomError> {
    let Some(bytes) = reader.read(ownership::OWNERSHIP_PATH)? else {
        return Ok(None);
    };
    Ok(Ownership::parse(&bytes)
        .map(|owner| owner.template_version().to_owned())
        .ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::plan::{FileChange, MapRepositoryReader};

    /// The policy a 1.0.0 installation owns.
    const POLICY_V1: &[u8] = b"# Axiom managed policy\n\nManaged policy version: 1.0.0\n";

    /// The policy the 1.2.0 template ships.
    const POLICY_V2: &[u8] = b"# Axiom managed policy\n\nManaged policy version: 1.2.0\n";

    /// A managed block for `version` that points at the owned policy.
    fn block(version: &str) -> String {
        format!(
            "{}\n## Axiom code graph (v{version})\nRead `.axiom/agent/POLICY.md` before changing code.\n{}",
            markers::BEGIN_MARKER,
            markers::END_MARKER
        )
    }

    /// A repository whose owned content is current at template version 1.0.0.
    fn installed_repository(human: &str) -> MapRepositoryReader {
        let block = block("1.0.0");
        let mut reader = MapRepositoryReader::new();
        reader.insert(
            plan::AGENTS_PATH,
            format!("{human}{block}\n\nHuman trailer.\n").into_bytes(),
        );
        reader.insert(POLICY_PATH, POLICY_V1.to_vec());
        reader.insert(
            ownership::OWNERSHIP_PATH,
            Ownership::new("1.0.0", &block, POLICY_V1)
                .encode()
                .expect("the manifest encodes"),
        );
        reader
    }

    /// The 1.2.0 templates the update would move to.
    fn templates_v2() -> Templates {
        Templates::new(block("1.2.0"), POLICY_V2.to_vec(), "1.2.0")
    }

    fn rule_of(error: &AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    /// A synthetic plan row that names `paths`.
    fn synthetic_plan(paths: &[&str]) -> RepositoryPlan {
        RepositoryPlan {
            repository_id: "synthetic".to_owned(),
            root: "/repo/synthetic".to_owned(),
            change: ChangeClass::Replace,
            before_block_sha256: None,
            after_block_sha256: None,
            files: paths
                .iter()
                .map(|path| FileChange {
                    path: (*path).to_owned(),
                    before_sha256: None,
                    after_sha256: "0".repeat(64),
                    diff: String::new(),
                    bytes: Vec::new(),
                })
                .collect(),
            refusal: None,
        }
    }

    /// AC1: a newer compatible template updates a healthy repository inside its
    /// owned span only, and a conflicted repository is skipped with its refusal
    /// still attached to the report.
    #[test]
    fn a_newer_template_updates_owned_spans_and_skips_conflicts() {
        let human = "# Demo repository\n\n";
        let healthy = installed_repository(human);
        let mut edited = installed_repository(human);
        edited.insert(
            plan::AGENTS_PATH,
            format!(
                "{human}{}\n\nHuman trailer.\n",
                block("1.0.0").replace("before changing code", "before changing code EDITED")
            )
            .into_bytes(),
        );

        let templates = templates_v2();
        let targets = [
            RepositoryTarget::new("healthy", "/repo/healthy", &healthy),
            RepositoryTarget::new("edited", "/repo/edited", &edited),
        ];
        let plan = plan_update(&targets, &templates, "1.0.0").expect("the update plans");

        assert_eq!(plan.compatibility, TemplateCompatibility::Newer);
        assert!(plan.compatibility.is_acceptable());
        assert_eq!(plan.updated(), 1);
        assert_eq!(plan.unchanged(), 0);
        assert_eq!(plan.skipped().len(), 1);
        assert!(!plan.is_complete());
        assert_eq!(plan.skipped()[0].repository_id, "edited");
        assert_eq!(
            plan.skipped()[0]
                .refusal
                .as_ref()
                .expect("a skipped repository reports why")
                .rule,
            ownership::RULE_BLOCK_EDITED
        );

        let healthy_row = &plan.repositories[0];
        assert_eq!(healthy_row.outcome, UpdateOutcome::Update);
        assert_eq!(healthy_row.change(), ChangeClass::Replace);
        assert_eq!(healthy_row.from_version.as_deref(), Some("1.0.0"));
        assert_eq!(healthy_row.to_version, "1.2.0");
        for path in healthy_row.paths() {
            assert!(OWNED_PATHS.contains(&path), "unowned path planned: {path}");
        }

        // Only the owned span moved: the human head and trailer are byte-identical.
        let agents = healthy_row
            .plan
            .files
            .iter()
            .find(|file| file.path == plan::AGENTS_PATH)
            .expect("AGENTS.md is planned");
        let after = std::str::from_utf8(&agents.bytes).expect("the plan writes UTF-8");
        assert!(after.starts_with(human));
        assert!(after.ends_with("\n\nHuman trailer.\n"));
        assert!(after.contains("(v1.2.0)"));

        // The review document names the skipped repository and its rule.
        let rendered = plan.render();
        assert!(rendered.contains("skipped"), "{rendered}");
        assert!(
            rendered.contains(ownership::RULE_BLOCK_EDITED),
            "{rendered}"
        );

        // Applying goes through the same rows, so it re-verifies before-hashes.
        let sealed = plan.to_bootstrap_plan(&templates).expect("the plan seals");
        assert_eq!(sealed.repositories.len(), 2);
        assert_eq!(sealed.conflicts().len(), 1);
    }

    /// Boundary: the same template version is a no-op for every repository.
    #[test]
    fn the_same_version_updates_nothing() {
        let human = "# Demo repository\n\n";
        let repository = installed_repository(human);
        let targets = [RepositoryTarget::new("demo", "/repo/demo", &repository)];
        let templates = Templates::new(block("1.0.0"), POLICY_V1.to_vec(), "1.0.0");

        let plan = plan_update(&targets, &templates, "1.0.0").expect("the update plans");
        assert_eq!(plan.compatibility, TemplateCompatibility::Same);
        assert_eq!(plan.updated(), 0);
        assert_eq!(plan.unchanged(), 1);
        assert!(plan.remaining().len() == 1);
        assert!(plan.repositories[0].paths().is_empty());
        assert!(plan.is_complete());
        assert_eq!(plan.repositories[0].change(), ChangeClass::Unchanged);
    }

    /// Negative: an unacceptable template is refused as a whole, before any
    /// repository is read, so a downgrade or a major change can never produce a
    /// partial update.
    #[test]
    fn an_unacceptable_template_is_refused_before_any_repository_is_read() {
        let templates = templates_v2();
        let error = plan_update(&[], &templates, "1.5.0").expect_err("a downgrade is refused");
        assert_eq!(rule_of(&error), Some(RULE_UPDATE_DOWNGRADE));

        let error = plan_update(&[], &templates, "2.0.0").expect_err("a major change is refused");
        assert_eq!(rule_of(&error), Some(RULE_UPDATE_MAJOR));

        let error = plan_update(&[], &templates, "1.x.0").expect_err("a bad version is refused");
        assert_eq!(rule_of(&error), Some(RULE_UPDATE_VERSION));
    }

    /// Boundary: version parsing accepts SemVer pre-releases and refuses the
    /// malformed shapes around them.
    #[test]
    fn template_versions_parse_strictly() {
        let version = TemplateVersion::parse("1.2.0-rc.1").expect("a pre-release parses");
        assert_eq!(version.to_string(), "1.2.0-rc.1");
        assert_eq!(
            compatibility("1.2.0-rc.1", "1.2.0").expect("comparable"),
            TemplateCompatibility::Newer
        );
        assert_eq!(
            compatibility("1.2.0-rc.1", "1.2.0-rc.2").expect("comparable"),
            TemplateCompatibility::Newer
        );
        // A release outranks its own pre-release, and the reverse is a
        // downgrade: the ordering is not the derive-order of `Option`.
        assert_eq!(
            compatibility("1.2.0", "1.2.0-rc.1").expect("comparable"),
            TemplateCompatibility::Downgrade
        );
        assert!(
            TemplateVersion::parse("2.0.0-draft.2").expect("parses")
                > TemplateVersion::parse("2.0.0-draft.1").expect("parses")
        );

        for malformed in ["", "1", "1.2", "1.2.3.4", "1.2.x", "1.2.-1", "1.2.3-rc..1"] {
            let error = TemplateVersion::parse(malformed).expect_err(malformed);
            assert_eq!(rule_of(&error), Some(RULE_UPDATE_VERSION), "{malformed}");
        }
    }

    /// Negative: a plan that would write an unowned path is refused even though
    /// this build itself produced it.
    #[test]
    fn a_plan_outside_the_owned_paths_is_refused() {
        let error =
            ensure_owned_paths(&synthetic_plan(&["src/main.rs"])).expect_err("unowned path");
        assert_eq!(rule_of(&error), Some(RULE_UPDATE_UNOWNED_PATH));

        for path in OWNED_PATHS {
            ensure_owned_paths(&synthetic_plan(&[path])).expect("owned path");
        }
    }

    /// AC1 boundary: the span assertion accepts a pure span replacement and an
    /// append, and refuses a change that reaches outside the owned span.
    #[test]
    fn only_the_owned_span_may_change() {
        let human = "# Demo\n\n";
        let before = format!("{human}{}\n\ntail\n", block("1.0.0"));
        let replaced = format!("{human}{}\n\ntail\n", block("1.2.0"));
        ensure_only_owned_span(&before, &replaced).expect("only the span changed");

        let outside = format!("{human}{}\n\ntail EDITED\n", block("1.2.0"));
        let error = ensure_only_owned_span(&before, &outside).expect_err("outside edit");
        assert_eq!(rule_of(&error), Some(RULE_UPDATE_OUTSIDE));

        // An append keeps the previous document as an exact prefix.
        let fresh = format!("{human}no block here\n");
        let appended = format!("{fresh}{}\n", block("1.2.0"));
        ensure_only_owned_span(&fresh, &appended).expect("append preserves the prefix");

        let rewritten = format!("{human}REWRITTEN\n{}\n", block("1.2.0"));
        let error = ensure_only_owned_span(&fresh, &rewritten).expect_err("prefix lost");
        assert_eq!(rule_of(&error), Some(RULE_UPDATE_OUTSIDE));
    }
}
