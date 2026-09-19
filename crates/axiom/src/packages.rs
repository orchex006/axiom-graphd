//! Report ecosystem package and provenance versions (task E-034).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 1 fixes *one core release*:
//! the daemon and the standalone CLI are published from one locked workspace
//! with one version and one revision. `contracts/schemas/version-report.schema.json`
//! is frozen at eight properties with `additionalProperties: false`, so this
//! task cannot widen [`crate::version::VersionReport`]; it reports the
//! ecosystem package view as its own document instead. Task E-034 fixes what
//! that document must say:
//!
//! > Version report lists graphd/CLI as one core release, MCP and skills as
//! > independent components, plus pinned spec/fixture revisions. Documentation
//! > inherits owner versions; no standalone docs/conformance update packages are
//! > required.
//!
//! Three rules carry that sentence, and each is enforced structurally rather
//! than by convention:
//!
//! 1. [`build_report`] resolves the core release from two pins and refuses a
//!    split ([`Components`] with `core_release_split`) or a version that is not
//!    this build's [`crate::version::CORE_VERSION`] (`core_version_mismatch`).
//!    The daemon and the CLI are therefore one release in the report, never two.
//! 2. MCP and skills are independent: each must be present and pinned, an
//!    unknown component is refused (`unexpected_package_component`), and their
//!    versions are never forced to the core version.
//! 3. Documentation inherits: a `docs`/`conformance` row that declares its own
//!    version is refused (`standalone_documentation_version`) and
//!    [`require_updatable`] refuses to treat documentation as an update package
//!    (`no_standalone_documentation_package`), so no standalone docs or
//!    conformance release can be created by accident.
//!
//! Fixture provenance is reported honestly: component-local fixtures are *not*
//! the shared contract fixture index, so a claim that they are shared is
//! refused (`shared_fixture_index_not_supported`) rather than relabelled.
//!
//! Nothing here reads the network, a Git object store or a filesystem: every
//! fact is an injected input, and the only outputs are a validated value and its
//! canonical JSON text.

use serde::{Deserialize, Serialize};

use graph_core::error::{AxiomError, ErrorCode};

use crate::install::plan::is_digest;

/// Component name of the daemon half of the core release.
pub const DAEMON_COMPONENT: &str = crate::version::CORE_COMPONENT;

/// Component name of the CLI half of the core release.
pub const CLI_COMPONENT: &str = crate::version::COMPONENT;

/// Both halves of the single core release, in report order.
pub const CORE_COMPONENTS: [&str; 2] = [DAEMON_COMPONENT, CLI_COMPONENT];

/// Components published and updated independently of the core release.
pub const INDEPENDENT_COMPONENTS: [&str; 2] = ["axiom-mcp", "skills"];

/// Components whose documentation inherits an owner version instead of carrying
/// its own, and which therefore never get a standalone update package.
pub const INHERITED_COMPONENTS: [&str; 2] = ["docs", "conformance"];

/// Component that owns the pinned specification baseline documentation follows.
pub const SPECS_COMPONENT: &str = "specs";

/// Schema version of the packages report this build writes.
pub const REPORT_SCHEMA_VERSION: u64 = 1;

/// Fixture scope of component-local fixtures, which are never the shared
/// contract fixture index.
pub const FIXTURE_SCOPE_COMPONENT_LOCAL: &str = "component_local";

/// One component with its version and pinned source revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentPin {
    /// Component name.
    pub component: String,
    /// Component version.
    pub version: String,
    /// Pinned lowercase 40-hex source revision.
    pub revision: String,
}

/// The single core release: the daemon and the CLI, one version, one revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreRelease {
    /// The daemon half.
    pub daemon: ComponentPin,
    /// The CLI half.
    pub cli: ComponentPin,
}

/// The pinned specification baseline this build implements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecPin {
    /// Specification version.
    pub spec_version: String,
    /// Immutable specification revision.
    pub spec_revision: String,
}

/// Where the fixtures a component ships came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixturePin {
    /// Pinned lowercase 40-hex fixture revision.
    pub revision: String,
    /// Lowercase 64-hex digest of the fixture inventory.
    pub index_sha256: String,
    /// True only when the fixtures are the shared contract fixture index.
    pub shared: bool,
}

/// One documentation component and the owner whose version it follows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationVersion {
    /// Documentation component (`docs` or `conformance`).
    pub component: String,
    /// Component whose version this documentation follows.
    pub inherits_from: String,
    /// A standalone version, if the caller wrongly declared one.
    pub version: Option<String>,
}

/// Every input the packages report needs, so the report is a pure function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagesInput {
    /// The core release.
    pub core: CoreRelease,
    /// Independently published components.
    pub independent: Vec<ComponentPin>,
    /// Pinned specification baseline.
    pub specifications: SpecPin,
    /// Fixture provenance.
    pub fixtures: FixturePin,
    /// Documentation components and their owners.
    pub documentation: Vec<DocumentationVersion>,
}

/// The resolved core release row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreReleaseReport {
    /// The one shared version.
    pub version: String,
    /// The one shared revision.
    pub revision: String,
    /// Both component names, in [`CORE_COMPONENTS`] order.
    pub components: Vec<String>,
    /// Immutable specification revision the release was reviewed against.
    pub spec_revision: String,
}

/// The resolved documentation row: an owner version, never its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InheritedDocumentation {
    /// Documentation component.
    pub component: String,
    /// Owner whose version is inherited.
    pub inherits_from: String,
    /// The inherited version.
    pub version: String,
}

/// The packages and provenance report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagesReport {
    /// Report schema version.
    pub schema_version: u64,
    /// The one core release.
    pub core_release: CoreReleaseReport,
    /// Independently published components, in [`INDEPENDENT_COMPONENTS`] order.
    pub independent: Vec<ComponentPin>,
    /// Pinned specification baseline.
    pub specifications: SpecPin,
    /// Fixture provenance.
    pub fixtures: FixturePin,
    /// Documentation components with their inherited versions.
    pub documentation: Vec<InheritedDocumentation>,
    /// Components that carry their own update package.
    pub update_packages: Vec<String>,
}

impl PackagesReport {
    /// Refuse a report this build would not publish.
    ///
    /// # Errors
    ///
    /// Fails closed with a named `rule`: `report_schema_unsupported`,
    /// `core_version_mismatch`, `core_component_mismatch`,
    /// `core_revision_not_pinned` or `update_package_set_mismatch`.
    pub fn validate(&self) -> Result<(), AxiomError> {
        if self.schema_version != REPORT_SCHEMA_VERSION {
            return Err(refuse(
                "report_schema_unsupported",
                &self.schema_version.to_string(),
            )
            .with_detail("expected", REPORT_SCHEMA_VERSION.to_string()));
        }
        if self.core_release.version != crate::version::CORE_VERSION {
            return Err(refuse("core_version_mismatch", &self.core_release.version)
                .with_detail("expected", crate::version::CORE_VERSION));
        }
        if self.core_release.components != core_component_names() {
            return Err(refuse(
                "core_component_mismatch",
                &self.core_release.components.join(","),
            ));
        }
        if !is_pinned_revision(&self.core_release.revision) {
            return Err(refuse(
                "core_revision_not_pinned",
                &self.core_release.revision,
            ));
        }
        if self.update_packages != update_packages() {
            return Err(refuse(
                "update_package_set_mismatch",
                &self.update_packages.join(","),
            ));
        }
        Ok(())
    }

    /// One canonical JSON document for reporting.
    ///
    /// # Errors
    ///
    /// Fails closed when the report is not publishable or cannot be encoded.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        self.validate()?;
        serde_json::to_string(self).map_err(|_| {
            AxiomError::new(
                ErrorCode::Internal,
                "the packages report is not serialisable",
            )
        })
    }
}

/// Build the packages and provenance report from its injected inputs.
///
/// # Errors
///
/// Fails closed with a named `rule`: the [`Components`] of [`build_report`],
/// `unexpected_package_component`, `missing_independent_component`,
/// `independent_revision_not_pinned`, `spec_version_mismatch`,
/// `spec_revision_not_pinned`, `fixture_revision_not_pinned`,
/// `fixture_index_not_digest`, `shared_fixture_index_not_supported`,
/// `unexpected_documentation_component`, `standalone_documentation_version` or
/// `documentation_owner_missing`.
pub fn build_report(input: &PackagesInput) -> Result<PackagesReport, AxiomError> {
    validate_spec_pin(&input.specifications)?;
    validate_fixture_pin(&input.fixtures)?;
    let core_release = resolve_core(&input.core, &input.specifications.spec_revision)?;
    let independent = resolve_independent(&input.independent)?;
    let documentation = resolve_documentation(
        &input.documentation,
        &core_release,
        &independent,
        &input.specifications.spec_version,
    )?;
    let report = PackagesReport {
        schema_version: REPORT_SCHEMA_VERSION,
        core_release,
        independent,
        specifications: input.specifications.clone(),
        fixtures: input.fixtures.clone(),
        documentation,
        update_packages: update_packages(),
    };
    report.validate()?;
    Ok(report)
}

/// Every component that carries its own update package, in report order.
///
/// Documentation and conformance are deliberately absent: they inherit an owner
/// version and are not released on their own.
#[must_use]
pub fn update_packages() -> Vec<String> {
    CORE_COMPONENTS
        .iter()
        .chain(INDEPENDENT_COMPONENTS.iter())
        .map(|name| String::from(*name))
        .collect()
}

/// Refuse an update package for documentation or an unknown component.
///
/// # Errors
///
/// Fails closed with `no_standalone_documentation_package` for `docs` or
/// `conformance`, and `unexpected_package_component` for anything that is not a
/// component with its own update package.
pub fn require_updatable(component: &str) -> Result<(), AxiomError> {
    if INHERITED_COMPONENTS.contains(&component) {
        return Err(refuse("no_standalone_documentation_package", component));
    }
    if !CORE_COMPONENTS.contains(&component) && !INDEPENDENT_COMPONENTS.contains(&component) {
        return Err(refuse("unexpected_package_component", component));
    }
    Ok(())
}

/// The component names of the core release, in report order.
fn core_component_names() -> Vec<String> {
    CORE_COMPONENTS
        .iter()
        .map(|name| String::from(*name))
        .collect()
}

/// Resolve the two core pins into one release row.
fn resolve_core(core: &CoreRelease, spec_revision: &str) -> Result<CoreReleaseReport, AxiomError> {
    if core.daemon.component != DAEMON_COMPONENT {
        return Err(refuse("core_component_mismatch", &core.daemon.component));
    }
    if core.cli.component != CLI_COMPONENT {
        return Err(refuse("core_component_mismatch", &core.cli.component));
    }
    if core.daemon.version != core.cli.version {
        return Err(refuse("core_release_split", &core.daemon.version)
            .with_detail("expected", &core.cli.version));
    }
    if core.daemon.revision != core.cli.revision {
        return Err(refuse("core_release_split", &core.daemon.revision)
            .with_detail("expected", &core.cli.revision));
    }
    if core.daemon.version != crate::version::CORE_VERSION {
        return Err(refuse("core_version_mismatch", &core.daemon.version)
            .with_detail("expected", crate::version::CORE_VERSION));
    }
    if !is_pinned_revision(&core.daemon.revision) {
        return Err(refuse("core_revision_not_pinned", &core.daemon.revision));
    }
    Ok(CoreReleaseReport {
        version: core.daemon.version.clone(),
        revision: core.daemon.revision.clone(),
        components: core_component_names(),
        spec_revision: String::from(spec_revision),
    })
}

/// Resolve the independent components, requiring each one and pinning it.
fn resolve_independent(pins: &[ComponentPin]) -> Result<Vec<ComponentPin>, AxiomError> {
    for pin in pins {
        if !INDEPENDENT_COMPONENTS.contains(&pin.component.as_str()) {
            return Err(refuse("unexpected_package_component", &pin.component));
        }
        if !is_pinned_revision(&pin.revision) {
            return Err(refuse("independent_revision_not_pinned", &pin.component));
        }
    }
    for required in INDEPENDENT_COMPONENTS {
        if !pins.iter().any(|pin| pin.component == required) {
            return Err(refuse("missing_independent_component", required));
        }
    }
    let mut ordered = Vec::with_capacity(INDEPENDENT_COMPONENTS.len());
    for name in INDEPENDENT_COMPONENTS {
        if let Some(pin) = pins.iter().find(|pin| pin.component == name) {
            ordered.push(pin.clone());
        }
    }
    Ok(ordered)
}

/// Validate the pinned specification baseline.
fn validate_spec_pin(pin: &SpecPin) -> Result<(), AxiomError> {
    if pin.spec_version != crate::version::SPEC_VERSION {
        return Err(refuse("spec_version_mismatch", &pin.spec_version)
            .with_detail("expected", crate::version::SPEC_VERSION));
    }
    if !is_pinned_revision(&pin.spec_revision) {
        return Err(refuse("spec_revision_not_pinned", &pin.spec_revision));
    }
    Ok(())
}

/// Validate fixture provenance without widening component-local fixtures into a
/// shared contract index.
fn validate_fixture_pin(pin: &FixturePin) -> Result<(), AxiomError> {
    if !is_pinned_revision(&pin.revision) {
        return Err(refuse("fixture_revision_not_pinned", &pin.revision));
    }
    if !is_digest(&pin.index_sha256) {
        return Err(refuse("fixture_index_not_digest", &pin.index_sha256));
    }
    if pin.shared {
        return Err(refuse(
            "shared_fixture_index_not_supported",
            FIXTURE_SCOPE_COMPONENT_LOCAL,
        ));
    }
    Ok(())
}

/// Resolve documentation versions, each inherited from its owner.
fn resolve_documentation(
    docs: &[DocumentationVersion],
    core_release: &CoreReleaseReport,
    independent: &[ComponentPin],
    spec_version: &str,
) -> Result<Vec<InheritedDocumentation>, AxiomError> {
    let mut resolved = Vec::with_capacity(docs.len());
    for entry in docs {
        if !INHERITED_COMPONENTS.contains(&entry.component.as_str()) {
            return Err(refuse(
                "unexpected_documentation_component",
                &entry.component,
            ));
        }
        if entry.version.is_some() {
            return Err(refuse("standalone_documentation_version", &entry.component));
        }
        let version = owner_version(
            &entry.inherits_from,
            core_release,
            independent,
            spec_version,
        )
        .ok_or_else(|| refuse("documentation_owner_missing", &entry.inherits_from))?;
        resolved.push(InheritedDocumentation {
            component: entry.component.clone(),
            inherits_from: entry.inherits_from.clone(),
            version,
        });
    }
    Ok(resolved)
}

/// The version a documentation owner publishes, when the owner is known.
fn owner_version(
    owner: &str,
    core_release: &CoreReleaseReport,
    independent: &[ComponentPin],
    spec_version: &str,
) -> Option<String> {
    if CORE_COMPONENTS.contains(&owner) {
        return Some(core_release.version.clone());
    }
    if owner == SPECS_COMPONENT {
        return Some(String::from(spec_version));
    }
    independent
        .iter()
        .find(|pin| pin.component == owner)
        .map(|pin| pin.version.clone())
}

/// True when `text` is a lowercase 40-hex revision.
fn is_pinned_revision(text: &str) -> bool {
    text.len() == 40
        && text
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
}

/// The one refusal shape of this module.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the packages report violates the ecosystem provenance contract",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORE_REVISION: &str = "1111111111111111111111111111111111111111";
    const MCP_REVISION: &str = "2222222222222222222222222222222222222222";
    const SKILLS_REVISION: &str = "3333333333333333333333333333333333333333";
    const SPEC_REVISION: &str = "4444444444444444444444444444444444444444";
    const FIXTURE_REVISION: &str = "5555555555555555555555555555555555555555";
    const FIXTURE_INDEX: &str = "6666666666666666666666666666666666666666666666666666666666666666";

    fn core_pin(component: &str, version: &str, revision: &str) -> ComponentPin {
        ComponentPin {
            component: String::from(component),
            version: String::from(version),
            revision: String::from(revision),
        }
    }

    fn input() -> PackagesInput {
        PackagesInput {
            core: CoreRelease {
                daemon: core_pin(
                    DAEMON_COMPONENT,
                    crate::version::CORE_VERSION,
                    CORE_REVISION,
                ),
                cli: core_pin(CLI_COMPONENT, crate::version::CORE_VERSION, CORE_REVISION),
            },
            independent: vec![
                core_pin("axiom-mcp", "0.4.0", MCP_REVISION),
                core_pin("skills", "0.3.0", SKILLS_REVISION),
            ],
            specifications: SpecPin {
                spec_version: String::from(crate::version::SPEC_VERSION),
                spec_revision: String::from(SPEC_REVISION),
            },
            fixtures: FixturePin {
                revision: String::from(FIXTURE_REVISION),
                index_sha256: String::from(FIXTURE_INDEX),
                shared: false,
            },
            documentation: vec![
                DocumentationVersion {
                    component: String::from("docs"),
                    inherits_from: String::from(CLI_COMPONENT),
                    version: None,
                },
                DocumentationVersion {
                    component: String::from("conformance"),
                    inherits_from: String::from(SPECS_COMPONENT),
                    version: None,
                },
            ],
        }
    }

    fn rule_of(error: &AxiomError) -> String {
        error.details().get("rule").cloned().unwrap_or_default()
    }

    #[test]
    fn a_report_names_one_core_release_and_independent_components() {
        let report = build_report(&input()).expect("the report builds");
        assert_eq!(report.core_release.components, CORE_COMPONENTS);
        assert_eq!(report.core_release.version, crate::version::CORE_VERSION);
        assert_eq!(report.core_release.revision, CORE_REVISION);
        assert_eq!(report.core_release.spec_revision, SPEC_REVISION);
        let independent: Vec<&str> = report
            .independent
            .iter()
            .map(|pin| pin.component.as_str())
            .collect();
        assert_eq!(independent, vec!["axiom-mcp", "skills"]);
        assert!(!report.fixtures.shared);
        assert_eq!(report.documentation.len(), 2);
        assert_eq!(report.documentation[0].component, "docs");
        assert_eq!(
            report.documentation[0].version,
            crate::version::CORE_VERSION
        );
        assert_eq!(report.documentation[1].component, "conformance");
        assert_eq!(
            report.documentation[1].version,
            crate::version::SPEC_VERSION
        );
        assert_eq!(
            report.update_packages,
            vec!["axiom-graphd", "axiom", "axiom-mcp", "skills"]
        );
        report.validate().expect("the report is publishable");
        let json = report.to_json().expect("the report is serialisable");
        let decoded: PackagesReport = serde_json::from_str(&json).expect("the report round-trips");
        assert_eq!(decoded, report);
    }

    #[test]
    fn the_reported_component_constants_stay_inside_the_frozen_vocabulary() {
        for name in CORE_COMPONENTS
            .iter()
            .chain(INDEPENDENT_COMPONENTS.iter())
            .chain(INHERITED_COMPONENTS.iter())
        {
            assert!(
                crate::version::COMPONENTS.contains(name),
                "{name} is not a component of the frozen report schema"
            );
        }
        assert!(crate::version::COMPONENTS.contains(&SPECS_COMPONENT));
    }

    #[test]
    fn a_core_release_that_splits_its_version_is_refused() {
        let mut split = input();
        split.core.cli.version = String::from("9.9.9");
        let error = build_report(&split).expect_err("a split core release is refused");
        assert_eq!(rule_of(&error), "core_release_split");
    }

    #[test]
    fn a_core_version_other_than_this_build_is_refused() {
        let mut other = input();
        other.core.daemon.version = String::from("9.9.9");
        other.core.cli.version = String::from("9.9.9");
        let error = build_report(&other).expect_err("another core version is refused");
        assert_eq!(rule_of(&error), "core_version_mismatch");
    }

    #[test]
    fn a_documentation_component_carrying_its_own_version_is_refused() {
        let mut standalone = input();
        standalone.documentation[0].version = Some(String::from("1.0.0"));
        let error = build_report(&standalone).expect_err("a standalone docs version is refused");
        assert_eq!(rule_of(&error), "standalone_documentation_version");
    }

    #[test]
    fn documentation_with_an_unknown_owner_is_refused() {
        let mut orphan = input();
        orphan.documentation[0].inherits_from = String::from("axiom-bootstrap");
        let error = build_report(&orphan).expect_err("an unknown owner is refused");
        assert_eq!(rule_of(&error), "documentation_owner_missing");
    }

    #[test]
    fn an_unpinned_fixture_or_spec_revision_is_refused() {
        let mut fixture = input();
        fixture.fixtures.revision = String::from("abc");
        let error = build_report(&fixture).expect_err("an unpinned fixture revision is refused");
        assert_eq!(rule_of(&error), "fixture_revision_not_pinned");

        let mut spec = input();
        spec.specifications.spec_revision = String::from("abc");
        let error = build_report(&spec).expect_err("an unpinned spec revision is refused");
        assert_eq!(rule_of(&error), "spec_revision_not_pinned");

        let mut shared = input();
        shared.fixtures.shared = true;
        let error = build_report(&shared).expect_err("a shared fixture claim is refused");
        assert_eq!(rule_of(&error), "shared_fixture_index_not_supported");
    }

    #[test]
    fn an_unknown_independent_component_is_refused() {
        let mut unknown = input();
        unknown
            .independent
            .push(core_pin("axiom-bootstrap", "0.1.0", MCP_REVISION));
        let error = build_report(&unknown).expect_err("an unknown component is refused");
        assert_eq!(rule_of(&error), "unexpected_package_component");
    }

    #[test]
    fn an_independent_component_may_not_be_absent() {
        let mut absent = input();
        absent.independent.retain(|pin| pin.component != "skills");
        let error = build_report(&absent).expect_err("a missing independent component is refused");
        assert_eq!(rule_of(&error), "missing_independent_component");
    }

    #[test]
    fn documentation_is_not_a_standalone_update_package() {
        let error = require_updatable("docs").expect_err("docs is not an update package");
        assert_eq!(rule_of(&error), "no_standalone_documentation_package");
        let error =
            require_updatable("conformance").expect_err("conformance is not an update package");
        assert_eq!(rule_of(&error), "no_standalone_documentation_package");
        require_updatable("axiom-graphd").expect("the core release is updatable");
        require_updatable("skills").expect("skills is updatable");
        let error =
            require_updatable("axiom-bootstrap").expect_err("an unknown component is refused");
        assert_eq!(rule_of(&error), "unexpected_package_component");
    }
}
