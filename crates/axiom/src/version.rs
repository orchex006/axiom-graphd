//! Honest version and build reporting for the `axiom` operations CLI (task E-001).
//!
//! `contracts/schemas/version-report.schema.json` fixes an eight-property report
//! with `additionalProperties: false`; [`VersionReport`] is that object verbatim,
//! so the CLI reports the same document shape as the daemon and any other
//! component of the ecosystem.
//!
//! One core release, one version: `docs/20-VERSION-CHECK-UPDATE-RELEASE.md`
//! section 1 pins the `axiom` CLI to `same version/revision as axiom-graphd`.
//! Every report is built from [`CORE_VERSION`], and [`VersionReport::validate`]
//! refuses a report whose version is not the shared core version, so a drifting
//! second version is a test failure rather than a release surprise.
//!
//! Update state is honest: this build has no trusted update source configured, so
//! it reports `unconfigured` and can never claim `current`.

use serde::{Deserialize, Serialize};

use graph_core::error::{AxiomError, ErrorCode};

/// Component name of the operations CLI in the frozen report schema.
pub const COMPONENT: &str = "axiom";

/// Component name of the daemon that shares this core release.
pub const CORE_COMPONENT: &str = "axiom-graphd";

/// Component names accepted by the frozen report schema, in schema order.
pub const COMPONENTS: &[&str] = &[
    "axiom-graphd",
    "axiom-mcp",
    "axiom",
    "skills",
    "specs",
    "conformance",
    "docs",
];

/// Specification baseline this build implements.
pub const SPEC_VERSION: &str = "2.0.0-draft.1";

/// Graph payload schema version this build reads and writes.
pub const GRAPH_SCHEMA_VERSION: u32 = 1;

/// Control API version this build speaks.
pub const CONTROL_API_VERSION: u32 = 1;

/// Durable queue schema version this build speaks.
pub const QUEUE_SCHEMA_VERSION: u32 = 1;

/// Build revision injected at build time; `unknown` when not injected.
pub const BUILD_REVISION: &str = match option_env!("AXIOM_BUILD_REVISION") {
    Some(revision) => revision,
    None => "unknown",
};

/// The single core version shared by the daemon and the CLI.
///
/// It is the workspace package version, so both crates can only disagree if they
/// stop being built together, which is exactly the condition `validate` refuses.
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Update-source state reported in the version report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStatus {
    /// No check has run yet.
    NotChecked,
    /// The installed component is up to date.
    Current,
    /// An update is available.
    Available,
    /// The update source could not be reached.
    Offline,
    /// No trusted update source is configured.
    Unconfigured,
    /// The check was refused, for example by an unapproved trust pin.
    Blocked,
}

impl UpdateStatus {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::Current => "current",
            Self::Available => "available",
            Self::Offline => "offline",
            Self::Unconfigured => "unconfigured",
            Self::Blocked => "blocked",
        }
    }

    /// Every accepted value, for contract tests and documentation.
    #[must_use]
    pub const fn all() -> &'static [UpdateStatus] {
        &[
            Self::NotChecked,
            Self::Current,
            Self::Available,
            Self::Offline,
            Self::Unconfigured,
            Self::Blocked,
        ]
    }
}

/// The frozen version report.
///
/// Exactly the eight properties of `contracts/schemas/version-report.schema.json`
/// with `additionalProperties: false`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionReport {
    /// Reporting component.
    pub component: String,
    /// Component version.
    pub version: String,
    /// Specification baseline.
    pub spec_version: String,
    /// Graph database schema version.
    pub graph_schema: u32,
    /// Control API version.
    pub control_api: u32,
    /// Durable queue schema version.
    pub queue_schema: u32,
    /// Build revision of this binary.
    pub build_revision: String,
    /// Honest update-source state.
    pub update_status: UpdateStatus,
}

impl VersionReport {
    /// The report for one component of this build.
    #[must_use]
    pub fn for_component(component: impl Into<String>) -> Self {
        Self::with_version(component, CORE_VERSION)
    }

    /// The report for the operations CLI itself.
    #[must_use]
    pub fn cli() -> Self {
        Self::for_component(COMPONENT)
    }

    /// The report for the daemon that shares this core release.
    #[must_use]
    pub fn core() -> Self {
        Self::for_component(CORE_COMPONENT)
    }

    /// Every component this build can report without a registry lookup.
    ///
    /// The CLI and the daemon are one core release, so `axiom version --all`
    /// reports both from the same compiled version instead of inferring the
    /// daemon's version from the environment.
    #[must_use]
    pub fn all() -> Vec<VersionReport> {
        vec![Self::cli(), Self::core()]
    }

    /// Build a report with an explicit version, for tests and embedders.
    ///
    /// The result is not automatically valid: [`Self::validate`] refuses a
    /// version that is not the shared core version, which is what makes the
    /// lockstep rule enforced rather than documented.
    #[must_use]
    pub fn with_version(component: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            component: component.into(),
            version: version.into(),
            spec_version: String::from(SPEC_VERSION),
            graph_schema: GRAPH_SCHEMA_VERSION,
            control_api: CONTROL_API_VERSION,
            queue_schema: QUEUE_SCHEMA_VERSION,
            build_revision: String::from(BUILD_REVISION),
            update_status: UpdateStatus::Unconfigured,
        }
    }

    /// Refuse a report that the frozen schema or the core-release rule rejects.
    ///
    /// The checks are the parts of the schema that a Rust struct cannot express
    /// (the component enum and non-empty strings) plus the lockstep version rule
    /// from `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 1.
    pub fn validate(&self) -> Result<(), AxiomError> {
        if !COMPONENTS.contains(&self.component.as_str()) {
            return Err(refuse("component", &self.component));
        }
        if self.version != CORE_VERSION {
            return Err(AxiomError::new(
                ErrorCode::Internal,
                "the report violates the one-core-release version rule",
            )
            .with_detail("expected", CORE_VERSION)
            .with_detail("actual", &self.version));
        }
        if self.spec_version.trim().is_empty() {
            return Err(refuse("spec_version", &self.spec_version));
        }
        if self.build_revision.trim().is_empty() {
            return Err(refuse("build_revision", &self.build_revision));
        }
        Ok(())
    }

    /// One canonical JSON line for `--json` mode.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        self.validate()?;
        serde_json::to_string(self).map_err(|_| {
            AxiomError::new(
                ErrorCode::Internal,
                "the version report is not serialisable",
            )
        })
    }

    /// One human-readable line for text mode.
    #[must_use]
    pub fn text_line(&self) -> String {
        format!(
            "{} {} (spec {}, graph schema {}, control api {}, queue schema {}, build {}, update {})",
            self.component,
            self.version,
            self.spec_version,
            self.graph_schema,
            self.control_api,
            self.queue_schema,
            self.build_revision,
            self.update_status.as_str()
        )
    }
}

fn refuse(field: &str, value: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::Internal,
        "the version report violates the frozen report schema",
    )
    .with_detail("observed", format!("{field}={value}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FROZEN_PROPERTIES: [&str; 8] = [
        "component",
        "version",
        "spec_version",
        "graph_schema",
        "control_api",
        "queue_schema",
        "build_revision",
        "update_status",
    ];

    #[test]
    fn the_frozen_report_has_exactly_the_schema_properties() {
        let report = VersionReport::cli();
        report.validate().expect("the default report is valid");
        let value: serde_json::Value =
            serde_json::from_str(&report.to_json().expect("serialisable"))
                .expect("the report is JSON");
        let mut keys: Vec<String> = value
            .as_object()
            .expect("object")
            .keys()
            .map(String::to_string)
            .collect();
        keys.sort();
        let mut expected: Vec<String> = FROZEN_PROPERTIES
            .iter()
            .map(|key| String::from(*key))
            .collect();
        expected.sort();
        assert_eq!(keys, expected);
        assert_eq!(value["component"], serde_json::Value::from(COMPONENT));
        assert_eq!(value["version"], serde_json::Value::from(CORE_VERSION));
        assert_eq!(
            value["update_status"],
            serde_json::Value::from("unconfigured")
        );
        let decoded: VersionReport =
            serde_json::from_str(&report.to_json().expect("serialisable")).expect("round trip");
        assert_eq!(decoded, report);
    }

    #[test]
    fn every_component_of_this_build_reports_the_single_core_version() {
        let reports = VersionReport::all();
        assert_eq!(reports.len(), 2);
        for report in &reports {
            report.validate().expect("every build report is valid");
            assert_eq!(report.version, CORE_VERSION);
        }
        assert_eq!(reports[0].component, COMPONENT);
        assert_eq!(reports[1].component, CORE_COMPONENT);
    }

    #[test]
    fn a_second_version_is_refused() {
        let drifting = VersionReport::with_version(COMPONENT, "9.9.9");
        let error = drifting
            .validate()
            .expect_err("a drifting version must fail");
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(
            error.details().get("expected").map(String::as_str),
            Some(CORE_VERSION)
        );
        assert_eq!(
            error.details().get("actual").map(String::as_str),
            Some("9.9.9")
        );
        assert!(
            drifting.to_json().is_err(),
            "an invalid report never serialises"
        );
    }

    #[test]
    fn an_unknown_component_is_refused() {
        let unknown = VersionReport::for_component("axiom-bootstrap");
        let error = unknown
            .validate()
            .expect_err("an unknown component must fail");
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("component=axiom-bootstrap")
        );
    }

    #[test]
    fn every_update_status_matches_the_frozen_schema() {
        let encoded: Vec<&str> = UpdateStatus::all().iter().map(|s| s.as_str()).collect();
        assert_eq!(
            encoded,
            vec![
                "not_checked",
                "current",
                "available",
                "offline",
                "unconfigured",
                "blocked"
            ]
        );
        for status in UpdateStatus::all() {
            let json = serde_json::to_string(status).expect("serialisable");
            assert_eq!(json, format!("\"{}\"", status.as_str()));
        }
        assert_eq!(
            VersionReport::cli().update_status,
            UpdateStatus::Unconfigured
        );
    }
}
