//! Honest version and build reporting (task B-008).
//!
//! `version-report.schema.json` fixes an eight-property report with
//! `additionalProperties: false`; [`VersionReport`] is that object, verbatim.
//! docs/16-CLI-AND-CONTROL-API.md section 1 additionally requires the actual
//! SQLite runtime version and the analyzer set, which the frozen schema of this
//! pinned revision does not model. [`VersionOutput`] emits the frozen object
//! first and adds exactly those runtime facts, and the gap is recorded as a
//! limitation in the B-008 evidence rather than hidden by dropping either
//! requirement.
//!
//! Update state is reported honestly: a build with no trusted update source
//! says `unconfigured` and can never claim `current`.

use serde::{Deserialize, Serialize};

use graph_core::error::{AxiomError, ErrorCode};
use graph_store::migrations::CURRENT_SCHEMA_VERSION;
use graph_store::open::{runtime_version_probe, MIN_SQLITE_VERSION};

/// Component name used in the version report.
pub const COMPONENT: &str = "axiom-graphd";

/// Component names accepted by the frozen report schema.
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

/// Control API version this build implements.
pub const CONTROL_API_VERSION: u32 = 1;

/// Durable queue schema version this build implements.
pub const QUEUE_SCHEMA_VERSION: u32 = 1;

/// Build revision injected at build time; `unknown` when not injected.
pub const BUILD_REVISION: &str = match option_env!("AXIOM_BUILD_REVISION") {
    Some(revision) => revision,
    None => "unknown",
};

/// Value reported for the SQLite version when the runtime cannot be probed.
pub const SQLITE_VERSION_UNAVAILABLE: &str = "unavailable";

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

    /// Every accepted value, for contract tests.
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

/// Whether a trusted update source is configured for this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateConfiguration {
    configured: bool,
    status: UpdateStatus,
}

impl Default for UpdateConfiguration {
    fn default() -> Self {
        Self::unconfigured()
    }
}

impl UpdateConfiguration {
    /// No trusted update source is configured.
    #[must_use]
    pub const fn unconfigured() -> Self {
        Self {
            configured: false,
            status: UpdateStatus::Unconfigured,
        }
    }

    /// A trusted update source is configured and produced `status`.
    #[must_use]
    pub const fn configured(status: UpdateStatus) -> Self {
        Self {
            configured: true,
            status,
        }
    }

    /// Build from raw parts; the report validation rejects dishonest pairs.
    #[must_use]
    pub const fn from_parts(configured: bool, status: UpdateStatus) -> Self {
        Self { configured, status }
    }

    /// Whether a trusted update source exists.
    #[must_use]
    pub const fn is_configured(self) -> bool {
        self.configured
    }

    /// The status to report.
    #[must_use]
    pub const fn status(self) -> UpdateStatus {
        self.status
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
    /// Build revision, or `unknown`.
    pub build_revision: String,
    /// Update-source state.
    pub update_status: UpdateStatus,
}

impl VersionReport {
    /// Build a report for `update`.
    ///
    /// # Errors
    /// Returns [`ErrorCode::Internal`] when an update source that is not
    /// configured is reported as anything other than `unconfigured`.
    pub fn build(update: UpdateConfiguration) -> Result<Self, AxiomError> {
        if !update.is_configured() && update.status() != UpdateStatus::Unconfigured {
            return Err(AxiomError::new(
                ErrorCode::Internal,
                "an unconfigured update source cannot report any other status",
            )
            .with_detail("expected", UpdateStatus::Unconfigured.as_str())
            .with_detail("actual", update.status().as_str()));
        }
        Ok(Self {
            component: String::from(COMPONENT),
            version: String::from(env!("CARGO_PKG_VERSION")),
            spec_version: String::from(SPEC_VERSION),
            graph_schema: CURRENT_SCHEMA_VERSION,
            control_api: CONTROL_API_VERSION,
            queue_schema: QUEUE_SCHEMA_VERSION,
            build_revision: String::from(BUILD_REVISION),
            update_status: update.status(),
        })
    }

    /// The report for this build: no trusted update source is configured.
    #[must_use]
    pub fn current() -> Self {
        Self::build(UpdateConfiguration::unconfigured())
            .expect("the default version report is always honest")
    }

    /// Re-check the frozen constraints: enumerations and `minLength: 1`.
    ///
    /// # Errors
    /// Returns [`ErrorCode::Internal`] when the report would violate the schema.
    pub fn validate(&self) -> Result<(), AxiomError> {
        if !COMPONENTS.contains(&self.component.as_str()) {
            return Err(invalid("component", &self.component));
        }
        for (field, value) in [
            ("version", &self.version),
            ("spec_version", &self.spec_version),
            ("build_revision", &self.build_revision),
        ] {
            if value.is_empty() {
                return Err(invalid(field, value));
            }
        }
        Ok(())
    }

    /// JSON text of the frozen report.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| String::from("{}"))
    }
}

/// What `axiom-graphd version --json` prints: the frozen report plus the runtime
/// facts docs/16 section 1 requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionOutput {
    /// The frozen report, flattened into the same JSON object.
    #[serde(flatten)]
    pub report: VersionReport,
    /// Actual `sqlite_version()` of the linked runtime.
    pub sqlite_version: String,
    /// WAL baseline this build requires.
    pub sqlite_wal_baseline: String,
    /// Whether the linked runtime meets the WAL baseline.
    pub sqlite_wal_supported: bool,
    /// Analyzer identifiers compiled into this build, in stable order.
    pub analyzers: Vec<String>,
}

impl VersionOutput {
    /// Report the current build, probing the runtime SQLite version.
    #[must_use]
    pub fn current() -> Self {
        let (sqlite_version, sqlite_wal_supported) = match runtime_version_probe() {
            Ok(version) => (version.to_string(), version.is_supported_for_wal()),
            Err(_) => (String::from(SQLITE_VERSION_UNAVAILABLE), false),
        };
        Self {
            report: VersionReport::current(),
            sqlite_version,
            sqlite_wal_baseline: MIN_SQLITE_VERSION.to_string(),
            sqlite_wal_supported,
            analyzers: Vec::new(),
        }
    }

    /// One-line human summary used by text mode and `--version`.
    #[must_use]
    pub fn text_line(&self) -> String {
        format!(
            "{} {} (spec {}, sqlite {}, graph schema {}, control API {})",
            self.report.component,
            self.report.version,
            self.report.spec_version,
            self.sqlite_version,
            self.report.graph_schema,
            self.report.control_api
        )
    }
}

fn invalid(field: &str, value: &str) -> AxiomError {
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

    const RUNTIME_PROPERTIES: [&str; 4] = [
        "sqlite_version",
        "sqlite_wal_baseline",
        "sqlite_wal_supported",
        "analyzers",
    ];

    fn keys(value: &serde_json::Value) -> Vec<String> {
        let mut keys: Vec<String> = value
            .as_object()
            .expect("object")
            .keys()
            .map(String::to_string)
            .collect();
        keys.sort();
        keys
    }

    #[test]
    fn the_frozen_core_has_exactly_the_schema_properties() {
        let report = VersionReport::current();
        report.validate().expect("the default report is valid");
        let value: serde_json::Value =
            serde_json::from_str(&report.to_json()).expect("the report is JSON");
        let mut expected: Vec<String> =
            FROZEN_PROPERTIES.iter().map(|k| String::from(*k)).collect();
        expected.sort();
        assert_eq!(keys(&value), expected);
        assert_eq!(value["component"], serde_json::Value::from(COMPONENT));
        assert_eq!(value["graph_schema"], serde_json::Value::from(1));
        assert_eq!(value["control_api"], serde_json::Value::from(1));
        assert_eq!(value["queue_schema"], serde_json::Value::from(1));
        assert_eq!(value["spec_version"], serde_json::Value::from(SPEC_VERSION));
        assert_eq!(
            value["update_status"],
            serde_json::Value::from("unconfigured")
        );
        // A round trip through the exact schema shape must preserve every field.
        let decoded: VersionReport = serde_json::from_str(&report.to_json()).expect("round trip");
        assert_eq!(decoded, report);
    }

    #[test]
    fn an_unconfigured_update_source_never_claims_a_checked_status() {
        let dishonest = UpdateConfiguration::from_parts(false, UpdateStatus::Current);
        let error = VersionReport::build(dishonest).expect_err("must be refused");
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(
            error.details().get("actual").map(String::as_str),
            Some("current")
        );
        assert_eq!(
            VersionReport::build(UpdateConfiguration::configured(UpdateStatus::Current))
                .expect("configured is allowed")
                .update_status,
            UpdateStatus::Current
        );
        assert_eq!(
            VersionReport::current().update_status,
            UpdateStatus::Unconfigured
        );
    }

    #[test]
    fn the_cli_output_adds_exactly_the_runtime_facts() {
        let output = VersionOutput::current();
        let value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&output).expect("serialisable"))
                .expect("JSON object");
        let mut expected: Vec<String> = FROZEN_PROPERTIES
            .iter()
            .chain(RUNTIME_PROPERTIES.iter())
            .map(|key| String::from(*key))
            .collect();
        expected.sort();
        assert_eq!(keys(&value), expected);

        let probed = runtime_version_probe().expect("the linked runtime is usable");
        assert_eq!(output.sqlite_version, probed.to_string());
        assert_eq!(output.sqlite_wal_baseline, MIN_SQLITE_VERSION.to_string());
        assert_eq!(
            output.sqlite_wal_supported,
            probed.is_supported_for_wal(),
            "the reported baseline verdict must match the runtime"
        );
        assert!(output.analyzers.is_empty(), "no analyzer is compiled yet");
        assert!(output.text_line().contains(&output.sqlite_version));
        assert!(!output.text_line().contains('\\'));
    }

    #[test]
    fn every_enum_value_matches_the_frozen_schema() {
        assert!(COMPONENTS.contains(&COMPONENT));
        assert_eq!(UpdateStatus::all().len(), 6);
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
    }
}
