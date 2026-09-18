//! Project-manifest facts from `csproj` and `package.json` (task B-047).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` and
//! `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 7 both treat manifests as
//! a reconciliation trigger: a changed `.csproj` or `package.json` can invalidate
//! a whole project or solution. To do that safely the analyser must record what
//! the manifest *declares* without pretending to know what it *evaluates to*.
//!
//! An MSBuild property such as `$(PackageVersion)`, a `git+https://` dependency
//! and an npm `preinstall` script are all understood as declarations, but their
//! resolved value requires evaluation, a network fetch or code execution. Those
//! facts carry [`FactResolution::Unresolved`] with a reason and are never folded
//! into a resolved dependency edge. The extraction is deliberately narrow and
//! textual rather than a general MSBuild or npm evaluator; anything the narrow
//! extractor does not recognise is left out rather than guessed.

use graph_core::error::{AxiomError, ErrorCode};
use serde_json::Value;

use crate::{Diagnostic, Severity, Span};

/// Reason for an MSBuild property reference.
pub const REASON_MSBUILD_PROPERTY: &str = "msbuild-property";
/// Reason for a dependency with no declared version.
pub const REASON_VERSION_NOT_DECLARED: &str = "version-not-declared";
/// Reason for a value that needs resolution outside this build.
pub const REASON_REQUIRES_RESOLUTION: &str = "requires-resolution";
/// Reason for a value that needs code execution, such as an npm script.
pub const REASON_REQUIRES_EXECUTION: &str = "requires-execution";
/// Reason recorded when a manifest document cannot be parsed.
pub const REASON_MANIFEST_PARSE_FAILED: &str = "manifest-parse-failed";

/// A recognised manifest kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ManifestKind {
    /// An MSBuild C# project file (`.csproj`).
    CSharpProject,
    /// An npm package manifest (`package.json`).
    NpmPackage,
}

impl ManifestKind {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CSharpProject => "csproj",
            Self::NpmPackage => "package.json",
        }
    }

    /// Recognise the manifest kind from a portably relative path.
    #[must_use]
    pub fn from_path(path: &str) -> Option<Self> {
        let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
        if name == "package.json" {
            return Some(Self::NpmPackage);
        }
        if name.to_ascii_lowercase().ends_with(".csproj") {
            return Some(Self::CSharpProject);
        }
        None
    }
}

/// Whether a declared value is usable as-is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactResolution {
    /// The declaration is complete on its own.
    Resolved,
    /// The declaration is understood but its value needs something this build
    /// will not do: property evaluation, resolution or code execution.
    Unresolved {
        /// One of the `REASON_*` constants.
        reason: &'static str,
    },
}

impl FactResolution {
    /// Whether the fact resolved.
    #[must_use]
    pub const fn is_resolved(self) -> bool {
        matches!(self, Self::Resolved)
    }

    /// The reason, when unresolved.
    #[must_use]
    pub const fn reason(self) -> Option<&'static str> {
        match self {
            Self::Resolved => None,
            Self::Unresolved { reason } => Some(reason),
        }
    }

    /// Stable spelling for evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Unresolved { reason } => reason,
        }
    }
}

/// One declared project fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectFact {
    /// Deterministic key, e.g. `dependency:Newtonsoft.Json`.
    pub key: String,
    /// Which manifest kind produced it.
    pub kind: ManifestKind,
    /// The declared value.
    pub value: String,
    /// Whether the value is usable as-is.
    pub resolution: FactResolution,
    /// Where the declaration was found.
    pub span: Span,
}

/// The facts and diagnostics extracted from one manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFacts {
    /// The manifest kind.
    pub kind: ManifestKind,
    /// Facts, ordered deterministically by key.
    pub facts: Vec<ProjectFact>,
    /// Diagnostics, ordered deterministically by span start.
    pub diagnostics: Vec<Diagnostic>,
}

impl ManifestFacts {
    /// Facts, ordered by key then value.
    #[must_use]
    pub fn facts(&self) -> &[ProjectFact] {
        &self.facts
    }

    /// How many facts are declared but unresolved.
    #[must_use]
    pub fn unresolved(&self) -> usize {
        self.facts
            .iter()
            .filter(|fact| !fact.resolution.is_resolved())
            .count()
    }

    /// Diagnostic codes of severity `error`.
    #[must_use]
    pub fn error_codes(&self) -> Vec<&str> {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Error)
            .map(|diagnostic| diagnostic.code.as_str())
            .collect()
    }

    /// Look up one fact by key.
    #[must_use]
    pub fn fact(&self, key: &str) -> Option<&ProjectFact> {
        self.facts.iter().find(|fact| fact.key == key)
    }
}

/// Extract facts from `document`, which came from `path`.
///
/// # Errors
/// [`ErrorCode::IncompatibleInput`] with `manifest-parse-failed` when the
/// document cannot be parsed. A malformed manifest is never reported as an empty
/// but successful extraction.
pub fn extract(path: &str, document: &str) -> Result<ManifestFacts, AxiomError> {
    let Some(kind) = ManifestKind::from_path(path) else {
        return Err(AxiomError::new(
            ErrorCode::IncompatibleInput,
            "the path is not a recognised manifest",
        )
        .with_detail("rule", REASON_MANIFEST_PARSE_FAILED)
        .with_detail("portable_path", path));
    };
    match kind {
        ManifestKind::CSharpProject => Ok(extract_csproj(document)),
        ManifestKind::NpmPackage => extract_package_json(document),
    }
}

fn extract_csproj(document: &str) -> ManifestFacts {
    let mut facts = Vec::new();
    let mut diagnostics = Vec::new();
    for (offset, _) in document.match_indices("<PackageReference") {
        let span = element_span(document, offset);
        let element = span.slice(document).unwrap_or_default();
        let Some(include) = attribute(element, "Include") else {
            diagnostics.push(Diagnostic::error(
                "csproj-missing-include",
                "a PackageReference without an Include attribute declares no dependency",
                span,
            ));
            continue;
        };
        facts.push(ProjectFact {
            key: format!("dependency:{include}"),
            kind: ManifestKind::CSharpProject,
            value: include.clone(),
            resolution: FactResolution::Resolved,
            span,
        });
        let (resolution, value) = match attribute(element, "Version") {
            Some(version) if version.contains("$(") => (
                FactResolution::Unresolved {
                    reason: REASON_MSBUILD_PROPERTY,
                },
                version,
            ),
            Some(version) => (FactResolution::Resolved, version),
            None => (
                FactResolution::Unresolved {
                    reason: REASON_VERSION_NOT_DECLARED,
                },
                String::new(),
            ),
        };
        facts.push(ProjectFact {
            key: format!("dependency-version:{include}"),
            kind: ManifestKind::CSharpProject,
            value,
            resolution,
            span,
        });
    }
    for (offset, _) in document.match_indices("<ProjectReference") {
        let span = element_span(document, offset);
        let element = span.slice(document).unwrap_or_default();
        if let Some(include) = attribute(element, "Include") {
            facts.push(ProjectFact {
                key: format!("project-reference:{include}"),
                kind: ManifestKind::CSharpProject,
                value: include,
                resolution: FactResolution::Resolved,
                span,
            });
        }
    }
    for property in ["TargetFramework", "TargetFrameworks", "RootNamespace"] {
        let open = format!("<{property}>");
        let close = format!("</{property}>");
        if let Some(start) = document.find(&open) {
            if let Some(relative_end) = document[start..].find(&close) {
                let value_start = start + open.len();
                let value_end = start + relative_end;
                let value = document[value_start..value_end].trim().to_string();
                let resolution = if value.contains("$(") {
                    FactResolution::Unresolved {
                        reason: REASON_MSBUILD_PROPERTY,
                    }
                } else {
                    FactResolution::Resolved
                };
                facts.push(ProjectFact {
                    key: format!("property:{property}"),
                    kind: ManifestKind::CSharpProject,
                    value,
                    resolution,
                    span: Span::new(value_start, value_end),
                });
            }
        }
    }
    facts.sort_by(|left, right| left.key.cmp(&right.key));
    diagnostics.sort_by_key(|diagnostic| diagnostic.span.start);
    ManifestFacts {
        kind: ManifestKind::CSharpProject,
        facts,
        diagnostics,
    }
}

fn extract_package_json(document: &str) -> Result<ManifestFacts, AxiomError> {
    let parsed: Value = serde_json::from_str(document).map_err(|error| {
        AxiomError::new(
            ErrorCode::IncompatibleInput,
            "package.json did not parse as JSON",
        )
        .with_detail("rule", REASON_MANIFEST_PARSE_FAILED)
        .with_detail("actual", error.to_string())
    })?;
    let mut facts = Vec::new();
    for section in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        let Some(map) = parsed.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (name, value) in map {
            let declared = value.as_str().unwrap_or_default().to_string();
            let resolution = if requires_resolution(&declared) {
                FactResolution::Unresolved {
                    reason: REASON_REQUIRES_RESOLUTION,
                }
            } else {
                FactResolution::Resolved
            };
            facts.push(ProjectFact {
                key: format!("{section}:{name}"),
                kind: ManifestKind::NpmPackage,
                value: declared,
                resolution,
                span: Span::new(0, 0),
            });
        }
    }
    if let Some(scripts) = parsed.get("scripts").and_then(Value::as_object) {
        for (name, value) in scripts {
            facts.push(ProjectFact {
                key: format!("script:{name}"),
                kind: ManifestKind::NpmPackage,
                value: value.as_str().unwrap_or_default().to_string(),
                resolution: FactResolution::Unresolved {
                    reason: REASON_REQUIRES_EXECUTION,
                },
                span: Span::new(0, 0),
            });
        }
    }
    facts.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(ManifestFacts {
        kind: ManifestKind::NpmPackage,
        facts,
        diagnostics: Vec::new(),
    })
}

/// Whether a declared dependency specifier needs work this build will not do.
fn requires_resolution(declared: &str) -> bool {
    const PROTOCOLS: &[&str] = &[
        "file:",
        "link:",
        "portal:",
        "workspace:",
        "npm:",
        "git+",
        "git:",
        "http:",
        "https:",
        "github:",
    ];
    let lowered = declared.to_ascii_lowercase();
    PROTOCOLS.iter().any(|prefix| lowered.starts_with(prefix))
        || matches!(lowered.as_str(), "*" | "latest" | "")
}

/// The span of the element starting at `offset` (`<Name ... />` or `<Name ...>`).
fn element_span(document: &str, offset: usize) -> Span {
    let rest = &document[offset..];
    let end = rest
        .find("/>")
        .map(|index| offset + index + 2)
        .or_else(|| rest.find('>').map(|index| offset + index + 1))
        .unwrap_or(document.len());
    Span::new(offset, end)
}

/// Value of `name="..."` or `name='...'` inside `element`.
fn attribute(element: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    let start = element.find(&needle)? + needle.len();
    let rest = element.get(start..)?;
    let mut chars = rest.chars();
    let quote = chars.next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let value = chars.as_str();
    let end = value.find(quote)?;
    Some(value.get(..end)?.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        extract, FactResolution, ManifestKind, REASON_MSBUILD_PROPERTY, REASON_REQUIRES_EXECUTION,
        REASON_REQUIRES_RESOLUTION, REASON_VERSION_NOT_DECLARED,
    };
    use graph_core::error::ErrorCode;

    const CSPROJ: &str = r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <RootNamespace>App</RootNamespace>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Refit" Version="$(RefitVersion)" />
    <PackageReference Include="NoVersion" />
    <ProjectReference Include="..\Core\Core.csproj" />
  </ItemGroup>
</Project>
"#;

    const PACKAGE_JSON: &str = r#"{
  "name": "demo",
  "dependencies": { "lodash": "^4.17.21", "local": "file:../local" },
  "devDependencies": { "typescript": "5.6.2" },
  "scripts": { "build": "tsc -p ." }
}
"#;

    #[test]
    fn a_csproj_yields_dependency_and_property_facts() {
        let facts = extract("src/App/App.csproj", CSPROJ).expect("csproj");
        assert_eq!(facts.kind, ManifestKind::CSharpProject);
        let dependency = facts
            .fact("dependency:Newtonsoft.Json")
            .expect("dependency");
        assert_eq!(dependency.value, "Newtonsoft.Json");
        assert!(dependency.resolution.is_resolved());
        let version = facts
            .fact("dependency-version:Newtonsoft.Json")
            .expect("version");
        assert_eq!(version.value, "13.0.3");
        assert!(version.resolution.is_resolved());
        let property = facts.fact("property:TargetFramework").expect("property");
        assert_eq!(property.value, "net8.0");
        assert_eq!(
            facts
                .fact("project-reference:..\\Core\\Core.csproj")
                .map(|fact| fact.value.as_str()),
            Some("..\\Core\\Core.csproj")
        );
    }

    #[test]
    fn values_requiring_evaluation_or_a_version_are_unresolved_with_a_reason() {
        let facts = extract("App.csproj", CSPROJ).expect("csproj");
        let version = facts
            .fact("dependency-version:Refit")
            .expect("refit version");
        assert_eq!(
            version.resolution,
            FactResolution::Unresolved {
                reason: REASON_MSBUILD_PROPERTY
            }
        );
        assert_eq!(version.resolution.reason(), Some(REASON_MSBUILD_PROPERTY));
        let missing = facts
            .fact("dependency-version:NoVersion")
            .expect("missing version");
        assert_eq!(
            missing.resolution.reason(),
            Some(REASON_VERSION_NOT_DECLARED)
        );
        assert_eq!(facts.unresolved(), 2);
    }

    #[test]
    fn a_package_json_yields_resolved_and_unresolved_facts() {
        let facts = extract("web/package.json", PACKAGE_JSON).expect("package.json");
        assert_eq!(facts.kind, ManifestKind::NpmPackage);
        let lodash = facts.fact("dependencies:lodash").expect("lodash");
        assert!(lodash.resolution.is_resolved());
        assert_eq!(lodash.value, "^4.17.21");
        let local = facts.fact("dependencies:local").expect("local");
        assert_eq!(local.resolution.reason(), Some(REASON_REQUIRES_RESOLUTION));
        let script = facts.fact("script:build").expect("script");
        assert_eq!(script.resolution.reason(), Some(REASON_REQUIRES_EXECUTION));
        assert_eq!(script.value, "tsc -p .");
        assert_eq!(facts.unresolved(), 2);
        assert!(facts.error_codes().is_empty());
    }

    #[test]
    fn a_csproj_package_reference_without_an_include_is_a_diagnostic() {
        let document =
            r#"<Project><ItemGroup><PackageReference Version="1.0" /></ItemGroup></Project>"#;
        let facts = extract("App.csproj", document).expect("csproj");
        assert_eq!(facts.error_codes(), vec!["csproj-missing-include"]);
        assert!(facts.facts.is_empty());
    }

    #[test]
    fn extraction_is_deterministic_and_key_sorted() {
        let first = extract("App.csproj", CSPROJ).expect("csproj");
        let second = extract("App.csproj", CSPROJ).expect("csproj");
        assert_eq!(first, second);
        let mut keys: Vec<&str> = first.facts().iter().map(|fact| fact.key.as_str()).collect();
        let sorted = keys.clone();
        keys.sort_unstable();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn a_malformed_manifest_is_an_error_and_not_an_empty_success() {
        let error = extract("web/package.json", "{ not json").expect_err("malformed");
        assert_eq!(error.code(), ErrorCode::IncompatibleInput);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(super::REASON_MANIFEST_PARSE_FAILED)
        );
        let error = extract("README.md", "hello").expect_err("not a manifest");
        assert_eq!(error.code(), ErrorCode::IncompatibleInput);
    }

    #[test]
    fn an_empty_dependency_map_is_a_complete_but_empty_extraction() {
        let facts = extract("web/package.json", "{\"name\":\"x\"}").expect("package.json");
        assert!(facts.facts.is_empty());
        assert_eq!(facts.unresolved(), 0);
        assert_eq!(ManifestKind::from_path("a/b/Package.JSON"), None);
        assert_eq!(
            ManifestKind::from_path("a/b/package.json"),
            Some(ManifestKind::NpmPackage)
        );
    }
}
