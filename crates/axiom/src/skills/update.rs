//! Expose skills versions and approved updates (task E-033).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 2 gives the skills bundle
//! three commands (`axiom skills version/check/update`), section 4 fixes the
//! check policy (offline never contacts anything, a network failure never
//! reports "up to date"), and section 6 fixes the update: versioned directories
//! and a reviewed manifest, activated by a plan. Task E-033 fixes the two rules
//! this module exists for:
//!
//! > Check is read-only and apply uses an approved component plan; Markdown is
//! > not claimed to self-update without an executable.
//!
//! ## Read-only check
//!
//! [`check_skills`] reads through [`SkillsSource`], which can only report what
//! is installed, what was published and what a bundle declares. There is no
//! write, download or process call on that trait, so the check cannot install,
//! activate or execute anything - and an offline request returns before the
//! candidate list is even consulted.
//!
//! ## Honest self-update claim
//!
//! A skills bundle is Markdown plus whatever the declaration authorises. When a
//! bundle declares no executable entry there is nothing in it that could run an
//! update, so the report says so ([`UPDATE_POLICY_INSTRUCTIONAL`], and
//! `self_update_available = false`) and [`admit_self_update`] refuses a request
//! that treats it as one with `self_update_requires_executable`. The bundle is
//! still installable; it just is not claimed to update itself.
//!
//! ## Apply uses the approved plan
//!
//! [`plan_update`] builds the frozen update-plan document for the `skills`
//! component through the single planner (E-039), never a second plan format.
//! [`apply_update`] admits that document - structure plus an approval that still
//! matches the plan digest - and only then installs the bundle it names, through
//! the E-032 versioned-directory installer. A plan naming another component, or
//! a bundle other than the plan's target, is refused before a byte is written.

use serde::{Deserialize, Serialize};

use graph_core::error::{AxiomError, ErrorCode};

use crate::skills::install::{self, InstallFs, InstallReport, PayloadSource, SkillBundle};
use crate::update::plan::{self, PlanComponent, UpdatePlanInput};
use crate::update::resolve::{self, ComponentRelease, Constraints, Rejection, ResolvedAction};
use crate::version::UpdateStatus;

/// Component name of the skills bundle in the ecosystem version vocabulary.
pub const COMPONENT: &str = "skills";

/// Update policy of a bundle that declares an executable entry.
pub const UPDATE_POLICY_EXECUTABLE: &str = "executable_bundle_self_update_supported";

/// Update policy of a bundle that declares no executable entry.
pub const UPDATE_POLICY_INSTRUCTIONAL: &str = "instructional_bundle_no_self_update";

/// Update policy of a check that did not evaluate any candidate.
pub const UPDATE_POLICY_NOT_EVALUATED: &str = "not_evaluated";

/// What is installed on this host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledSkills {
    /// Installed bundle version.
    pub version: String,
    /// Source revision the installed bundle was built from.
    pub revision: String,
}

/// The read-only facts a skills check is allowed to consult.
///
/// The trait deliberately has no mutation, download or process method: a check
/// can only report. Candidates come from the resolver input of E-038, so
/// "latest" is never inferred here either.
pub trait SkillsSource {
    /// The installed bundle, when one is recorded.
    fn installed(&self) -> Option<InstalledSkills>;

    /// Every published candidate of the skills component.
    fn candidates(&self) -> Vec<ComponentRelease>;

    /// The declaration of one published version, when it is known.
    fn bundle(&self, version: &str) -> Option<SkillBundle>;
}

/// The two caller inputs a check needs beyond the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckInput {
    /// Configured origin the candidates came from, for honest reporting.
    pub source_origin: String,
    /// `--offline`: the check must contact nothing.
    pub offline: bool,
}

/// The skills check report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillsCheck {
    /// Reporting component; always [`COMPONENT`].
    pub component: String,
    /// Installed version, when one is recorded.
    pub installed_version: Option<String>,
    /// Installed revision, when one is recorded.
    pub installed_revision: Option<String>,
    /// Version this check would install, when a candidate was evaluated.
    pub target_version: Option<String>,
    /// Revision of that version, when a candidate was evaluated.
    pub target_revision: Option<String>,
    /// Resolved action (`install`, `upgrade`, `noop`), when one was resolved.
    pub action: Option<String>,
    /// Honest update state; never `current` when nothing was evaluated.
    pub status: UpdateStatus,
    /// Channel the check followed.
    pub channel: String,
    /// Specification baseline of this build.
    pub spec_version: String,
    /// Number of candidates that satisfied every constraint.
    pub compatible_candidates: usize,
    /// Every rejected candidate with its named rule.
    pub rejected: Vec<Rejection>,
    /// Whether the target bundle declares an executable entry.
    pub self_update_available: bool,
    /// Which update policy applies to the target bundle.
    pub update_policy: String,
    /// Whether the host must be restarted for the change to take effect.
    pub needs_restart: bool,
    /// Configured origin the candidates came from.
    pub source_origin: String,
    /// Records that the check surface is read-only by construction.
    pub read_only: bool,
}

/// Check the skills bundle for an available, compatible update.
///
/// # Errors
///
/// Fails closed with a named `rule`: `unexpected_component` when the
/// constraints do not describe the skills component, `bundle_manifest_missing`
/// when the selected version has no pinned declaration, the declaration rules of
/// [`SkillBundle::validate`], and the resolver's own refusals (for example
/// `no_compatible_release`) when nothing is compatible.
pub fn check_skills(
    source: &dyn SkillsSource,
    constraints: &Constraints,
    input: &CheckInput,
) -> Result<SkillsCheck, AxiomError> {
    if constraints.component != COMPONENT {
        return Err(refuse("unexpected_component", &constraints.component));
    }
    let installed = source.installed();
    let base = SkillsCheck {
        component: String::from(COMPONENT),
        installed_version: installed.as_ref().map(|value| value.version.clone()),
        installed_revision: installed.as_ref().map(|value| value.revision.clone()),
        target_version: None,
        target_revision: None,
        action: None,
        status: UpdateStatus::NotChecked,
        channel: constraints.channel.clone(),
        spec_version: constraints.spec_version.clone(),
        compatible_candidates: 0,
        rejected: Vec::new(),
        self_update_available: false,
        update_policy: String::from(UPDATE_POLICY_NOT_EVALUATED),
        needs_restart: false,
        source_origin: input.source_origin.clone(),
        read_only: true,
    };
    if input.offline {
        // An offline check contacts nothing at all: it does not even read the
        // candidate list, so no reported value can depend on a network call.
        return Ok(SkillsCheck {
            status: UpdateStatus::Offline,
            ..base
        });
    }
    let resolved = resolve::resolve(
        &source.candidates(),
        constraints,
        installed.as_ref().map(|value| value.version.as_str()),
    )?;
    let Some(bundle) = source.bundle(&resolved.target_version) else {
        return Err(refuse("bundle_manifest_missing", &resolved.target_version));
    };
    bundle.validate()?;
    let self_update_available = bundle.installs_executable();
    let status = match resolved.action {
        ResolvedAction::Noop => UpdateStatus::Current,
        ResolvedAction::Install | ResolvedAction::Upgrade => UpdateStatus::Available,
    };
    Ok(SkillsCheck {
        target_version: Some(resolved.target_version),
        target_revision: Some(resolved.target_revision),
        action: Some(resolved.action.as_str().to_string()),
        status,
        compatible_candidates: resolved.compatible_candidates,
        rejected: resolved.rejected,
        self_update_available,
        update_policy: String::from(if self_update_available {
            UPDATE_POLICY_EXECUTABLE
        } else {
            UPDATE_POLICY_INSTRUCTIONAL
        }),
        needs_restart: self_update_available && resolved.action != ResolvedAction::Noop,
        ..base
    })
}

/// Refuse a request that treats a Markdown-only bundle as self-updating.
///
/// # Errors
///
/// Fails closed with `rule=self_update_requires_executable` and
/// `observed=no_executable_entry` when the checked bundle declares no executable
/// entry, because such a bundle has no code that could perform an update.
pub fn admit_self_update(check: &SkillsCheck) -> Result<(), AxiomError> {
    if check.self_update_available {
        return Ok(());
    }
    Err(
        refuse("self_update_requires_executable", "no_executable_entry")
            .with_detail("version", check.target_version.clone().unwrap_or_default())
            .with_detail("observed", &check.update_policy),
    )
}

/// Build the frozen update-plan document for one skills update.
///
/// # Errors
///
/// Fails closed with a named `rule`: `skills_plan_component_count` when the
/// input does not carry exactly one component row, `plan_component_not_skills`
/// when that row is not the skills component, `unsupported_component_action`
/// when the action is outside the plan contract, and the planner's own
/// `invalid_plan` refusal.
pub fn plan_update(input: &UpdatePlanInput) -> Result<serde_json::Value, AxiomError> {
    let [row] = input.components.as_slice() else {
        return Err(refuse(
            "skills_plan_component_count",
            &input.components.len().to_string(),
        )
        .with_detail("expected", "1"));
    };
    if row.component != COMPONENT {
        return Err(refuse("plan_component_not_skills", &row.component));
    }
    if !crate::plan::ACTIONS.contains(&row.action.as_str()) {
        return Err(refuse("unsupported_component_action", &row.action));
    }
    plan::build_plan(input)
}

/// What one applied skills update did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillsApply {
    /// The install the versioned-directory installer performed.
    pub install: InstallReport,
    /// Whether the host must be restarted for the change to take effect.
    pub needs_restart: bool,
}

/// Apply an approved skills plan, installing exactly the bundle it names.
///
/// # Errors
///
/// Fails closed with a named `rule`: `plan_not_approved` when the supplied
/// digest does not match the plan's current body or the plan is not approved,
/// `plan_component_not_skills` when the plan does not target the skills
/// component, `plan_target_version_mismatch` / `plan_revision_mismatch` when the
/// bundle is not the plan's target, the planner's `invalid_plan` refusal, the
/// E-032 declaration and payload refusals, and the installer's filesystem
/// refusals.
pub fn apply_update(
    plan: &serde_json::Value,
    approved_digest: &str,
    bundle: &SkillBundle,
    payload: &dyn PayloadSource,
    fs: &dyn InstallFs,
) -> Result<SkillsApply, AxiomError> {
    let reasons = crate::plan::approval_reasons(plan, approved_digest);
    if !reasons.is_empty() {
        return Err(refuse("plan_not_approved", &reasons.join(",")));
    }
    plan::admit(plan)?;
    let row = skills_row(plan)?;
    if row.target_version != bundle.version {
        return Err(refuse("plan_target_version_mismatch", &bundle.version)
            .with_detail("expected", &row.target_version));
    }
    if row.target_revision != bundle.revision {
        return Err(refuse("plan_revision_mismatch", &bundle.revision)
            .with_detail("expected", &row.target_revision));
    }
    let install_plan = install::plan_install(bundle, payload)?;
    let report = install::install(&install_plan, payload, fs)?;
    Ok(SkillsApply {
        needs_restart: report.installs_executable,
        install: report,
    })
}

/// The one skills component row of an approved plan.
fn skills_row(plan: &serde_json::Value) -> Result<PlanComponent, AxiomError> {
    let rows = plan
        .get("components")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| refuse("plan_component_not_skills", "missing_components"))?;
    let mut found: Option<PlanComponent> = None;
    for row in rows {
        let Some(object) = row.as_object() else {
            return Err(refuse("plan_component_not_skills", "non_object_component"));
        };
        let component = object
            .get("component")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if component != COMPONENT {
            return Err(refuse("plan_component_not_skills", component));
        }
        if found.is_some() {
            return Err(refuse("skills_plan_component_count", "2"));
        }
        found = Some(PlanComponent {
            component: String::from(COMPONENT),
            installed_version: object
                .get("installed_version")
                .and_then(serde_json::Value::as_str)
                .map(String::from),
            installed_revision: object
                .get("installed_revision")
                .and_then(serde_json::Value::as_str)
                .map(String::from),
            target_version: object
                .get("target_version")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            target_revision: object
                .get("target_revision")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            artifact_sha256: object
                .get("artifact_sha256")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            action: object
                .get("action")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
        });
    }
    found.ok_or_else(|| refuse("plan_component_not_skills", "no_skills_row"))
}

/// The one refusal shape of this module.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the skills check or update violates the skills update contract",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use serde_json::Value;

    use super::*;

    const REVISION: &str = "1111111111111111111111111111111111111111";
    const SPEC_REVISION: &str = "2222222222222222222222222222222222222222";
    const TARGET_REVISION: &str = "3333333333333333333333333333333333333333";
    const SKILL_MD: &[u8] = b"# axiom-analyze\n\nread the graph, never guess.\n";
    const SCRIPT: &[u8] = b"#!/bin/sh\necho bounded\n";

    fn digest(bytes: &[u8]) -> String {
        graph_export::sha256_hex(bytes)
    }

    fn instruction_entry() -> install::DeclaredEntry {
        install::DeclaredEntry::new(
            "axiom-analyze/SKILL.md",
            "instruction",
            digest(SKILL_MD),
            SKILL_MD.len() as u64,
        )
    }

    fn script_entry() -> install::DeclaredEntry {
        install::DeclaredEntry::new(
            "axiom-analyze/scripts/check.sh",
            "script",
            digest(SCRIPT),
            SCRIPT.len() as u64,
        )
        .reviewed(&["read", "execute"])
    }

    fn bundle(entries: Vec<install::DeclaredEntry>) -> SkillBundle {
        SkillBundle::new("0.2.0", TARGET_REVISION, SPEC_REVISION, entries)
    }

    fn instructional_bundle() -> SkillBundle {
        bundle(vec![instruction_entry()])
    }

    fn executable_bundle() -> SkillBundle {
        bundle(vec![instruction_entry(), script_entry()])
    }

    fn staged(path: &str, bytes: &[u8]) -> install::StagedFile {
        install::StagedFile {
            path: String::from(path),
            size_bytes: bytes.len() as u64,
            sha256: digest(bytes),
            executable: install::is_executable_path(path),
        }
    }

    fn release(version: &str) -> ComponentRelease {
        ComponentRelease {
            component: String::from(COMPONENT),
            version: String::from(version),
            revision: String::from(TARGET_REVISION),
            channel: String::from("stable"),
            spec_version: String::from(crate::version::SPEC_VERSION),
            graph_schema: crate::version::GRAPH_SCHEMA_VERSION,
            control_api: crate::version::CONTROL_API_VERSION,
            queue_schema: crate::version::QUEUE_SCHEMA_VERSION,
            artifact_sha256: "4".repeat(64),
            published_at: String::from("2026-09-18T00:00:00Z"),
        }
    }

    fn constraints() -> Constraints {
        Constraints {
            component: String::from(COMPONENT),
            channel: String::from("stable"),
            graph_schema_major: crate::version::GRAPH_SCHEMA_VERSION,
            control_api: crate::version::CONTROL_API_VERSION,
            queue_schema: crate::version::QUEUE_SCHEMA_VERSION,
            spec_version: String::from(crate::version::SPEC_VERSION),
        }
    }

    fn check_input(offline: bool) -> CheckInput {
        CheckInput {
            source_origin: String::from("https://github.com/orchex006/axiom-skills"),
            offline,
        }
    }

    #[derive(Default)]
    struct Source {
        installed: Option<InstalledSkills>,
        candidates: Vec<ComponentRelease>,
        bundles: BTreeMap<String, SkillBundle>,
        consulted: RefCell<u32>,
    }

    impl Source {
        fn installed(version: &str) -> Self {
            Self {
                installed: Some(InstalledSkills {
                    version: String::from(version),
                    revision: String::from(REVISION),
                }),
                ..Self::default()
            }
        }

        fn with_candidate(mut self, version: &str) -> Self {
            self.candidates.push(release(version));
            self
        }

        fn with_bundle(mut self, bundle: SkillBundle) -> Self {
            self.bundles.insert(bundle.version.clone(), bundle);
            self
        }

        fn consultations(&self) -> u32 {
            *self.consulted.borrow()
        }
    }

    impl SkillsSource for Source {
        fn installed(&self) -> Option<InstalledSkills> {
            self.installed.clone()
        }

        fn candidates(&self) -> Vec<ComponentRelease> {
            *self.consulted.borrow_mut() += 1;
            self.candidates.clone()
        }

        fn bundle(&self, version: &str) -> Option<SkillBundle> {
            self.bundles.get(version).cloned()
        }
    }

    struct Payload {
        files: Vec<install::StagedFile>,
    }

    impl Payload {
        fn declaring(entries: &[(&str, &[u8])]) -> Self {
            Self {
                files: entries
                    .iter()
                    .map(|(path, bytes)| staged(path, bytes))
                    .collect(),
            }
        }
    }

    impl PayloadSource for Payload {
        fn files(&self) -> Result<Vec<install::StagedFile>, AxiomError> {
            Ok(self.files.clone())
        }

        fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
            match path {
                "axiom-analyze/SKILL.md" => Ok(SKILL_MD.to_vec()),
                "axiom-analyze/scripts/check.sh" => Ok(SCRIPT.to_vec()),
                other => Err(refuse("payload_unreadable", other)),
            }
        }
    }

    #[derive(Default)]
    struct MemoryFs {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        writes: RefCell<Vec<String>>,
    }

    impl MemoryFs {
        fn get(&self, path: &str) -> Option<Vec<u8>> {
            self.files.borrow().get(path).cloned()
        }

        fn writes(&self) -> Vec<String> {
            self.writes.borrow().clone()
        }
    }

    impl InstallFs for MemoryFs {
        fn exists(&self, path: &str) -> bool {
            let files = self.files.borrow();
            files.contains_key(path)
                || files
                    .keys()
                    .any(|known| known.starts_with(&format!("{path}/")))
        }

        fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
            self.get(path)
                .ok_or_else(|| refuse("payload_unreadable", path))
        }

        fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError> {
            self.writes.borrow_mut().push(String::from(path));
            self.files
                .borrow_mut()
                .insert(String::from(path), bytes.to_vec());
            Ok(())
        }

        fn rename(&self, from: &str, to: &str) -> Result<(), AxiomError> {
            let bytes = self
                .get(from)
                .ok_or_else(|| refuse("pointer_write_failed", from))?;
            let mut files = self.files.borrow_mut();
            files.remove(from);
            files.insert(String::from(to), bytes);
            Ok(())
        }
    }

    fn rule_of(error: &AxiomError) -> String {
        error.details().get("rule").cloned().unwrap_or_default()
    }

    fn plan_input() -> UpdatePlanInput {
        UpdatePlanInput {
            spec_version: String::from(crate::version::SPEC_VERSION),
            plan_id: String::from("update-2026-09-19-skills-0-2-0"),
            created_at: String::from("2026-09-19T02:00:00Z"),
            expires_at: String::from("2026-09-20T02:00:00Z"),
            channel: String::from("stable"),
            target: plan::PlanTarget {
                component: String::from(COMPONENT),
                host: String::from("windows-x64"),
                install_root: String::from("/home/demo/.axiom/components/skills/0.2.0"),
            },
            components: vec![PlanComponent {
                component: String::from(COMPONENT),
                installed_version: Some(String::from("0.1.0")),
                installed_revision: Some(String::from(REVISION)),
                target_version: String::from("0.2.0"),
                target_revision: String::from(TARGET_REVISION),
                artifact_sha256: "4".repeat(64),
                action: String::from("upgrade"),
            }],
            downloads: vec![plan::PlanDownload {
                artifact: String::from("skills-0.2.0-all.zip"),
                url: String::from(
                    "https://github.com/orchex006/axiom-skills/releases/download/v0.2.0/skills-0.2.0-all.zip",
                ),
                sha256: "4".repeat(64),
                size_bytes: 4_194_304,
            }],
            migrations: Vec::new(),
            backup: plan::PlanBackup {
                required: false,
                targets: Vec::new(),
            },
            disk_headroom_bytes: 268_435_456,
            service_interruptions: Vec::new(),
            host_reconnect: plan::PlanHostReconnect {
                required: true,
                reason: String::from("the reviewed manifest pointer changes"),
            },
            bootstrap_changes: Vec::new(),
            rollback: plan::PlanRollback {
                supported: true,
                restores_previous_versions: true,
                limits: Vec::new(),
            },
            trust: plan::PlanTrust {
                metadata_version: 7,
                metadata_expiry: String::from("2026-09-25T02:00:00Z"),
                trust_root: Some("5".repeat(64)),
                signature_present: true,
            },
        }
    }

    fn approved_plan() -> (Value, String) {
        let mut plan = plan_update(&plan_input()).expect("the skills plan builds");
        let digest = crate::plan::record_approval(&mut plan, "operator", "2026-09-19T02:05:00Z")
            .expect("the approval records");
        (plan, digest)
    }

    const STAGED: [(&str, &[u8]); 2] = [
        ("axiom-analyze/SKILL.md", SKILL_MD),
        ("axiom-analyze/scripts/check.sh", SCRIPT),
    ];

    #[test]
    fn a_check_is_read_only_and_names_the_compatible_update() {
        let source = Source::installed("0.1.0")
            .with_candidate("0.2.0")
            .with_bundle(executable_bundle());
        let check = check_skills(&source, &constraints(), &check_input(false))
            .expect("the check succeeds against a compatible candidate");
        assert_eq!(check.component, COMPONENT);
        assert!(check.read_only);
        assert_eq!(check.installed_version.as_deref(), Some("0.1.0"));
        assert_eq!(check.status, UpdateStatus::Available);
        assert_eq!(check.action.as_deref(), Some("upgrade"));
        assert_eq!(check.target_version.as_deref(), Some("0.2.0"));
        assert_eq!(check.target_revision.as_deref(), Some(TARGET_REVISION));
        assert_eq!(check.compatible_candidates, 1);
        assert!(check.self_update_available);
        assert_eq!(check.update_policy, UPDATE_POLICY_EXECUTABLE);
        assert!(check.needs_restart);
        assert_eq!(source.consultations(), 1);
        admit_self_update(&check).expect("an executable bundle may self-update");
    }

    #[test]
    fn an_offline_check_never_consults_the_candidates() {
        let source = Source::installed("0.1.0")
            .with_candidate("0.2.0")
            .with_bundle(executable_bundle());
        let check = check_skills(&source, &constraints(), &check_input(true))
            .expect("an offline check reports honestly");
        assert_eq!(check.status, UpdateStatus::Offline);
        assert_eq!(check.target_version, None);
        assert_eq!(check.compatible_candidates, 0);
        assert_eq!(check.update_policy, UPDATE_POLICY_NOT_EVALUATED);
        assert!(!check.self_update_available);
        assert!(check.read_only);
        assert_eq!(
            source.consultations(),
            0,
            "an offline check reads no candidate list"
        );
    }

    #[test]
    fn a_markdown_bundle_is_not_claimed_to_self_update() {
        let source = Source::installed("0.1.0")
            .with_candidate("0.2.0")
            .with_bundle(instructional_bundle());
        let check = check_skills(&source, &constraints(), &check_input(false))
            .expect("the check succeeds against a compatible candidate");
        assert_eq!(check.status, UpdateStatus::Available);
        assert!(!check.self_update_available);
        assert_eq!(check.update_policy, UPDATE_POLICY_INSTRUCTIONAL);
        assert!(!check.needs_restart);
        let error = admit_self_update(&check).expect_err("a markdown bundle cannot self-update");
        assert_eq!(rule_of(&error), "self_update_requires_executable");
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some(UPDATE_POLICY_INSTRUCTIONAL)
        );
    }

    #[test]
    fn an_installed_target_is_current_not_available() {
        let source = Source::installed("0.2.0")
            .with_candidate("0.2.0")
            .with_bundle(executable_bundle());
        let check = check_skills(&source, &constraints(), &check_input(false))
            .expect("the check succeeds against a compatible candidate");
        assert_eq!(check.status, UpdateStatus::Current);
        assert_eq!(check.action.as_deref(), Some("noop"));
        assert!(!check.needs_restart);
    }

    #[test]
    fn a_check_for_another_component_is_refused() {
        let source = Source::installed("0.1.0").with_candidate("0.2.0");
        let mut other = constraints();
        other.component = String::from("axiom-mcp");
        let error = check_skills(&source, &other, &check_input(false))
            .expect_err("a non-skills check is refused");
        assert_eq!(rule_of(&error), "unexpected_component");
    }

    #[test]
    fn a_selected_version_without_a_pinned_declaration_is_refused() {
        let source = Source::installed("0.1.0").with_candidate("0.2.0");
        let error = check_skills(&source, &constraints(), &check_input(false))
            .expect_err("a selected version without a declaration is refused");
        assert_eq!(rule_of(&error), "bundle_manifest_missing");
    }

    #[test]
    fn planning_requires_exactly_one_skills_row() {
        let mut two = plan_input();
        two.components.push(two.components[0].clone());
        let error = plan_update(&two).expect_err("two component rows are refused");
        assert_eq!(rule_of(&error), "skills_plan_component_count");

        let mut other = plan_input();
        other.components[0].component = String::from("axiom-graphd");
        let error = plan_update(&other).expect_err("another component is refused");
        assert_eq!(rule_of(&error), "plan_component_not_skills");

        plan_update(&plan_input()).expect("the skills plan builds");
    }

    #[test]
    fn an_apply_requires_the_approved_plan_digest() {
        let (plan, _digest) = approved_plan();
        let payload = Payload::declaring(&STAGED);
        let fs = MemoryFs::default();
        let error = apply_update(&plan, &"0".repeat(64), &executable_bundle(), &payload, &fs)
            .expect_err("an unapproved digest is refused");
        assert_eq!(rule_of(&error), "plan_not_approved");
        assert!(
            fs.writes().is_empty(),
            "nothing is written without approval"
        );
    }

    #[test]
    fn an_unapproved_plan_is_refused_even_with_a_matching_digest() {
        let plan = plan_update(&plan_input()).expect("the skills plan builds");
        let digest = crate::plan::plan_digest(&plan).expect("the plan seals a digest");
        let payload = Payload::declaring(&STAGED);
        let fs = MemoryFs::default();
        let error = apply_update(&plan, &digest, &executable_bundle(), &payload, &fs)
            .expect_err("an unapproved major change is refused");
        assert_eq!(rule_of(&error), "plan_requires_approval");
        assert!(fs.writes().is_empty());
    }

    #[test]
    fn an_approved_skills_plan_installs_the_bundle_it_names() {
        let (plan, digest) = approved_plan();
        let payload = Payload::declaring(&STAGED);
        let fs = MemoryFs::default();
        let applied = apply_update(&plan, &digest, &executable_bundle(), &payload, &fs)
            .expect("the approved plan applies");
        assert_eq!(applied.install.version, "0.2.0");
        assert_eq!(applied.install.directory, "skills/0.2.0");
        assert_eq!(
            applied.install.installed,
            vec![
                String::from("axiom-analyze/SKILL.md"),
                String::from("axiom-analyze/scripts/check.sh"),
            ]
        );
        assert!(applied.install.installs_executable);
        assert!(applied.needs_restart);
        assert!(fs.get("skills/current").is_some(), "the pointer activates");
        assert!(fs.get("skills/0.2.0/bundle.json").is_some());
    }

    #[test]
    fn a_bundle_that_is_not_the_plans_target_is_refused() {
        let (plan, digest) = approved_plan();
        let wrong = SkillBundle::new(
            "0.9.0",
            TARGET_REVISION,
            SPEC_REVISION,
            vec![instruction_entry()],
        );
        let payload = Payload::declaring(&[("axiom-analyze/SKILL.md", SKILL_MD)]);
        let fs = MemoryFs::default();
        let error = apply_update(&plan, &digest, &wrong, &payload, &fs)
            .expect_err("a bundle that is not the plan target is refused");
        assert_eq!(rule_of(&error), "plan_target_version_mismatch");
        assert!(fs.writes().is_empty());
    }
}
