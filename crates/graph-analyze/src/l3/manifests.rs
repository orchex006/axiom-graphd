//! Allowlisted deployment and dependency hints from manifests (task B-064).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 2 allows a bounded manifest
//! subset: the keys this adapter knows how to read, each with a provenance
//! pointing at the file and key path it came from. Two rules are absolute:
//!
//! * secret values are never exported. A key whose name says it holds a
//!   credential is recorded as a redacted reference carrying the key name only,
//!   and the parser throws the value away without storing it anywhere;
//! * a value that is a variable reference (`${TAG}`) or otherwise not literal is
//!   reported as unsupported instead of being recorded as a fact.
//!
//! This is deliberately not a YAML parser. It reads the deployment keys the
//! coverage document allowlists, and it says "unsupported" for anything else
//! rather than pretending to understand the whole document.

use crate::{Diagnostic, Span};

use super::{lines_with_offsets, strip_line_comment};

/// Pattern id for a literal image hint.
pub const PATTERN_IMAGE: &str = "manifest-image";
/// Pattern id for a literal service reference.
pub const PATTERN_SERVICE_REFERENCE: &str = "manifest-service-reference";
/// Pattern id for a literal dependency entry.
pub const PATTERN_DEPENDENCY: &str = "manifest-dependency";
/// Pattern id for a literal, non-secret environment variable.
pub const PATTERN_ENVIRONMENT: &str = "manifest-environment-variable";
/// Pattern id for a literal port declaration.
pub const PATTERN_PORT: &str = "manifest-port";
/// Pattern id for a value that is not a literal.
pub const PATTERN_UNSUPPORTED_VALUE: &str = "manifest-unsupported-value";
/// Pattern id for a file that is not a recognised manifest.
pub const PATTERN_NOT_A_MANIFEST: &str = "manifest-not-recognised";

/// Reason recorded when a value is a variable or computed expression.
pub const REASON_DYNAMIC_VALUE: &str = "unresolved-dynamic-value";
/// Reason recorded when a credential-bearing key's value was withheld.
pub const REASON_SECRET_WITHHELD: &str = "redacted-secret-value";

/// The manifest dialect this adapter recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ManifestKind {
    /// A `docker-compose` document.
    Compose,
    /// A Kubernetes manifest.
    Kubernetes,
}

impl ManifestKind {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compose => "compose",
            Self::Kubernetes => "kubernetes",
        }
    }
}

/// What an exported hint describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HintKind {
    /// A container image reference.
    Image,
    /// A service host, URL or endpoint.
    ServiceReference,
    /// A `depends_on` entry.
    Dependency,
    /// A non-secret environment variable name and literal value.
    Environment,
    /// A declared port.
    Port,
}

impl HintKind {
    /// The `PATTERN_*` id that produced this hint.
    #[must_use]
    pub const fn pattern(self) -> &'static str {
        match self {
            Self::Image => PATTERN_IMAGE,
            Self::ServiceReference => PATTERN_SERVICE_REFERENCE,
            Self::Dependency => PATTERN_DEPENDENCY,
            Self::Environment => PATTERN_ENVIRONMENT,
            Self::Port => PATTERN_PORT,
        }
    }
}

/// One exported manifest hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestHint {
    /// Declaring file.
    pub file: String,
    /// Recognised manifest dialect.
    pub kind: ManifestKind,
    /// What the hint describes.
    pub hint: HintKind,
    /// The manifest key, for example `image`.
    pub key: String,
    /// The literal value.
    pub value: String,
    /// Where the hint came from, for example `compose:services.api.image`.
    pub provenance: String,
    /// One-based line of the declaring key.
    pub line: usize,
    /// Span of the declaring line.
    pub span: Span,
}

/// A credential-bearing key whose value was withheld.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedSecret {
    /// Declaring file.
    pub file: String,
    /// The credential key name. The value is never stored.
    pub key: String,
    /// Where the key came from.
    pub provenance: String,
    /// One-based line of the declaring key.
    pub line: usize,
    /// Span of the declaring line.
    pub span: Span,
}

/// A manifest fragment this adapter refused to read as a literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedManifestValue {
    /// Declaring file.
    pub file: String,
    /// The manifest key, when the line had one.
    pub key: String,
    /// A `PATTERN_*` id naming what was not analysed.
    pub pattern: String,
    /// A `REASON_*` value explaining the refusal.
    pub reason: String,
    /// Span of the fragment.
    pub span: Span,
}

/// Result of scanning one manifest file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ManifestAnalysis {
    /// The dialect, when the file was recognised as a manifest.
    pub kind: Option<ManifestKind>,
    /// Exported hints, in source order.
    pub hints: Vec<ManifestHint>,
    /// Withheld credentials, in source order.
    pub redacted: Vec<RedactedSecret>,
    /// Refused fragments, in source order.
    pub unsupported: Vec<UnsupportedManifestValue>,
    /// Diagnostics attached to the file.
    pub diagnostics: Vec<Diagnostic>,
}

impl ManifestAnalysis {
    /// Whether the file was not recognised as a manifest at all.
    #[must_use]
    pub fn not_a_manifest(&self) -> bool {
        self.kind.is_none()
    }

    /// Whether any fragment was refused or withheld.
    #[must_use]
    pub fn has_unresolved(&self) -> bool {
        !self.unsupported.is_empty() || !self.redacted.is_empty()
    }

    /// Whether any exported value or provenance contains `needle`.
    ///
    /// Evidence uses this to prove that a withheld secret did not leak into the
    /// exported facts. Redacted entries carry key names only, so a secret value
    /// can never be found here.
    #[must_use]
    pub fn leaks(&self, needle: &str) -> bool {
        if needle.is_empty() {
            return false;
        }
        self.hints.iter().any(|hint| {
            hint.value.contains(needle)
                || hint.key.contains(needle)
                || hint.provenance.contains(needle)
        })
    }
}

/// Key names whose value must never be exported.
const SECRET_MARKERS: [&str; 12] = [
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "credential",
    "connectionstring",
    "connection_string",
    "sas",
];

/// Whether a key name says it holds a credential.
#[must_use]
pub fn is_secret_key(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    SECRET_MARKERS.iter().any(|marker| lowered.contains(marker))
}

/// Strip quotes and a trailing YAML comment from a scalar value.
fn scalar(raw: &str) -> String {
    let without_comment = raw.split(" #").next().unwrap_or(raw);
    without_comment
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\''))
        .to_string()
}

/// Whether a scalar is a literal rather than a variable reference.
fn is_literal(value: &str) -> bool {
    !value.is_empty() && !value.contains("${") && !value.starts_with('$')
}

/// Detect the manifest dialect from the file name and contents.
#[must_use]
pub fn kind_of(file: &str, source: &str) -> Option<ManifestKind> {
    let lowered_name = file.to_ascii_lowercase();
    if source.contains("apiVersion:") || source.trim_start().starts_with("kind:") {
        return Some(ManifestKind::Kubernetes);
    }
    if source.contains("services:") || lowered_name.ends_with("docker-compose.yml") {
        return Some(ManifestKind::Compose);
    }
    None
}

/// The key of a `key: value` line, with any leading list dash removed.
fn key_of(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim().trim_start_matches("- ").trim();
    let (key, value) = trimmed.split_once(':')?;
    let key = key.trim().trim_matches(|ch| matches!(ch, '"' | '\''));
    if key.is_empty() || key.contains(' ') {
        return None;
    }
    Some((key.to_string(), value.to_string()))
}

/// One environment entry under consideration for allowlisted export.
struct EnvEntry<'a> {
    kind: ManifestKind,
    name: &'a str,
    raw_value: &'a str,
    provenance: &'a str,
    line: usize,
    span: Span,
}

/// Record one environment entry, applying the never-export-a-secret rule.
fn record_env(analysis: &mut ManifestAnalysis, file: &str, entry: EnvEntry<'_>) {
    let EnvEntry {
        kind,
        name,
        raw_value,
        provenance,
        line,
        span,
    } = entry;
    if is_secret_key(name) {
        analysis.redacted.push(RedactedSecret {
            file: file.to_string(),
            key: name.to_string(),
            provenance: provenance.to_string(),
            line,
            span,
        });
        return;
    }
    if raw_value.is_empty() {
        // A declared name with no value carries no literal fact.
        return;
    }
    if !is_literal(raw_value) {
        analysis.unsupported.push(UnsupportedManifestValue {
            file: file.to_string(),
            key: name.to_string(),
            pattern: PATTERN_UNSUPPORTED_VALUE.to_string(),
            reason: REASON_DYNAMIC_VALUE.to_string(),
            span,
        });
        return;
    }
    analysis.hints.push(ManifestHint {
        file: file.to_string(),
        kind,
        hint: HintKind::Environment,
        key: name.to_string(),
        value: raw_value.to_string(),
        provenance: provenance.to_string(),
        line,
        span,
    });
}

/// Scan one manifest file for allowlisted hints.
#[must_use]
pub fn analyze(file: &str, source: &str) -> ManifestAnalysis {
    let Some(kind) = kind_of(file, source) else {
        return ManifestAnalysis {
            diagnostics: vec![Diagnostic::warning(
                PATTERN_NOT_A_MANIFEST,
                "file is not a recognised manifest; no hints were exported",
                Span::new(0, 0),
            )],
            ..ManifestAnalysis::default()
        };
    };
    let mut analysis = ManifestAnalysis {
        kind: Some(kind),
        ..ManifestAnalysis::default()
    };
    let kind_word = kind.as_str();
    let mut section = String::new();
    let mut service = String::new();
    let mut services_child_indent: Option<usize> = None;
    let mut pending_env_name: Option<String> = None;
    for (index, (offset, raw_line)) in lines_with_offsets(source).into_iter().enumerate() {
        let line = strip_line_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let span = Span::new(offset, offset + line.len());
        let line_number = index + 1;
        let indent = line.len() - line.trim_start().len();
        if trimmed.starts_with("- ") {
            let item = scalar(trimmed.trim_start_matches("- ").trim());
            if item.is_empty() {
                continue;
            }
            match section.as_str() {
                "depends_on" => analysis.hints.push(ManifestHint {
                    file: file.to_string(),
                    kind,
                    hint: HintKind::Dependency,
                    key: item.clone(),
                    value: item,
                    provenance: format!("{kind_word}:services.{service}.depends_on"),
                    line: line_number,
                    span,
                }),
                "ports" => analysis.hints.push(ManifestHint {
                    file: file.to_string(),
                    kind,
                    hint: HintKind::Port,
                    key: item.clone(),
                    value: item,
                    provenance: format!("{kind_word}:services.{service}.ports"),
                    line: line_number,
                    span,
                }),
                "environment" => {
                    if let Some(rest) = item.strip_prefix("name:") {
                        pending_env_name = Some(scalar(rest));
                    } else if let Some(rest) = item.strip_prefix("value:") {
                        if let Some(name) = pending_env_name.clone() {
                            let provenance =
                                format!("{kind_word}:services.{service}.environment.{name}");
                            record_env(
                                &mut analysis,
                                file,
                                EnvEntry {
                                    kind,
                                    name: &name,
                                    raw_value: &scalar(rest),
                                    provenance: &provenance,
                                    line: line_number,
                                    span,
                                },
                            );
                        }
                    } else if let Some((name, raw_value)) = item.split_once('=') {
                        let provenance =
                            format!("{kind_word}:services.{service}.environment.{}", name.trim());
                        record_env(
                            &mut analysis,
                            file,
                            EnvEntry {
                                kind,
                                name: name.trim(),
                                raw_value: raw_value.trim(),
                                provenance: &provenance,
                                line: line_number,
                                span,
                            },
                        );
                    } else {
                        let provenance =
                            format!("{kind_word}:services.{service}.environment.{item}");
                        record_env(
                            &mut analysis,
                            file,
                            EnvEntry {
                                kind,
                                name: &item,
                                raw_value: "",
                                provenance: &provenance,
                                line: line_number,
                                span,
                            },
                        );
                    }
                }
                _ => {}
            }
            continue;
        }
        let Some((key, value)) = key_of(trimmed) else {
            continue;
        };
        // A K8s env pair is `- name: X` followed by `value: Y`; the value line
        // must not clear the name it belongs to.
        if key != "value" {
            pending_env_name = None;
        }
        let value_scalar = scalar(&value);
        // A key back at the service level starts a new service and ends the
        // previous service's nested section.
        if let Some(child) = services_child_indent {
            if indent == child && !value_scalar.is_empty() {
                section = "services".to_string();
                service = key.clone();
            }
        }
        if value_scalar.is_empty() {
            match key.as_str() {
                "services" => {
                    section = "services".to_string();
                    services_child_indent = None;
                    continue;
                }
                "environment" | "env" => {
                    section = "environment".to_string();
                    continue;
                }
                "depends_on" => {
                    section = "depends_on".to_string();
                    continue;
                }
                "ports" => {
                    section = "ports".to_string();
                    continue;
                }
                _ => {}
            }
            if section == "services" {
                match services_child_indent {
                    None => {
                        services_child_indent = Some(indent);
                        service = key.clone();
                    }
                    Some(child) if indent == child => service = key.clone(),
                    _ => {}
                }
            }
            continue;
        }
        if section == "services" && services_child_indent.is_none() {
            services_child_indent = Some(indent);
            service = key.clone();
        }
        let path = if service.is_empty() {
            format!("{kind_word}:{key}")
        } else {
            format!("{kind_word}:services.{service}.{key}")
        };
        if section == "environment" {
            if key == "name" {
                pending_env_name = Some(value_scalar);
                continue;
            }
            if key == "value" {
                if let Some(name) = pending_env_name.clone() {
                    let provenance = format!("{kind_word}:services.{service}.environment.{name}");
                    record_env(
                        &mut analysis,
                        file,
                        EnvEntry {
                            kind,
                            name: &name,
                            raw_value: &value_scalar,
                            provenance: &provenance,
                            line: line_number,
                            span,
                        },
                    );
                }
                continue;
            }
            record_env(
                &mut analysis,
                file,
                EnvEntry {
                    kind,
                    name: &key,
                    raw_value: &value_scalar,
                    provenance: &path,
                    line: line_number,
                    span,
                },
            );
            continue;
        }
        if is_secret_key(&key) {
            analysis.redacted.push(RedactedSecret {
                file: file.to_string(),
                key: key.clone(),
                provenance: path,
                line: line_number,
                span,
            });
            continue;
        }
        if !is_literal(&value_scalar) {
            analysis.unsupported.push(UnsupportedManifestValue {
                file: file.to_string(),
                key: key.clone(),
                pattern: PATTERN_UNSUPPORTED_VALUE.to_string(),
                reason: REASON_DYNAMIC_VALUE.to_string(),
                span,
            });
            continue;
        }
        let hint = match key.as_str() {
            "image" => Some(HintKind::Image),
            "host" | "url" | "endpoint" | "hostname" => Some(HintKind::ServiceReference),
            _ => None,
        };
        if let Some(hint_kind) = hint {
            analysis.hints.push(ManifestHint {
                file: file.to_string(),
                kind,
                hint: hint_kind,
                key,
                value: value_scalar,
                provenance: path,
                line: line_number,
                span,
            });
        }
    }
    analysis
}

#[cfg(test)]
mod tests {
    use super::{
        analyze, is_secret_key, kind_of, HintKind, ManifestKind, REASON_DYNAMIC_VALUE,
        REASON_SECRET_WITHHELD,
    };

    const COMPOSE: &str = r#"
services:
  api:
    image: registry.example.com/shop/api:1.4.2
    host: api.internal.example
    environment:
      - DB_HOST=db
      - DB_PASSWORD=hunter2-not-a-fact
      - REGISTRY_URL=${REGISTRY_URL}
    depends_on:
      - db
    ports:
      - "8080:8080"
  db:
    image: postgres:16
"#;

    #[test]
    fn safe_service_references_are_exported_with_provenance() {
        let analysis = analyze("deploy/docker-compose.yml", COMPOSE);
        assert_eq!(analysis.kind, Some(ManifestKind::Compose));
        let images: Vec<_> = analysis
            .hints
            .iter()
            .filter(|hint| hint.hint == HintKind::Image)
            .collect();
        assert_eq!(images.len(), 2);
        assert!(images
            .iter()
            .any(|hint| hint.value == "registry.example.com/shop/api:1.4.2"));
        assert!(images
            .iter()
            .all(|hint| hint.provenance.starts_with("compose:")));
        assert!(analysis
            .hints
            .iter()
            .any(|hint| hint.hint == HintKind::Dependency && hint.value == "db"));
        assert!(analysis
            .hints
            .iter()
            .any(|hint| hint.key == "DB_HOST" && hint.value == "db"));
        assert!(analysis
            .hints
            .iter()
            .any(|hint| hint.hint == HintKind::Port));
    }

    #[test]
    fn a_secret_value_is_never_exported() {
        let analysis = analyze("deploy/docker-compose.yml", COMPOSE);
        assert!(analysis
            .redacted
            .iter()
            .any(|entry| entry.key == "DB_PASSWORD"));
        assert!(!analysis.leaks("hunter2-not-a-fact"));
        assert!(analysis
            .redacted
            .iter()
            .all(|entry| !entry.provenance.contains("hunter2-not-a-fact")));
    }

    #[test]
    fn a_variable_reference_is_unsupported_not_a_fact() {
        let analysis = analyze("deploy/docker-compose.yml", COMPOSE);
        let unsupported: Vec<_> = analysis
            .unsupported
            .iter()
            .filter(|entry| entry.reason == REASON_DYNAMIC_VALUE)
            .collect();
        assert_eq!(unsupported.len(), 1);
        assert_eq!(unsupported[0].key, "REGISTRY_URL");
        assert!(!analysis.leaks("${REGISTRY_URL}"));
    }

    #[test]
    fn a_kubernetes_manifest_is_recognised_and_its_secret_withheld() {
        let source = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  containers:
    - name: api
      image: registry.example.com/shop/api:1.4.2
      env:
        - name: JWT_SECRET
          value: super-secret-token-value
        - name: LOG_LEVEL
          value: info
"#;
        let analysis = analyze("deploy/k8s/deployment.yaml", source);
        assert_eq!(analysis.kind, Some(ManifestKind::Kubernetes));
        assert!(analysis
            .hints
            .iter()
            .any(|hint| hint.hint == HintKind::Image));
        assert!(analysis
            .hints
            .iter()
            .any(|hint| hint.key == "LOG_LEVEL" && hint.value == "info"));
        assert!(analysis
            .redacted
            .iter()
            .any(|entry| entry.key == "JWT_SECRET"));
        assert!(!analysis.leaks("super-secret-token-value"));
    }

    #[test]
    fn a_non_manifest_file_exports_nothing_and_says_so() {
        let analysis = analyze("src/main.rs", "fn main() { println!(\"hi\"); }");
        assert!(analysis.not_a_manifest());
        assert!(analysis.hints.is_empty());
        assert!(analysis
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == super::PATTERN_NOT_A_MANIFEST));
    }

    #[test]
    fn secret_key_detection_is_name_based_and_case_insensitive() {
        assert!(is_secret_key("DB_PASSWORD"));
        assert!(is_secret_key("jwt_token"));
        assert!(is_secret_key("ApiKey"));
        assert!(is_secret_key("ConnectionString"));
        assert!(!is_secret_key("LOG_LEVEL"));
        assert!(!is_secret_key("image"));
    }

    #[test]
    fn manifest_kind_is_detected_from_content_not_just_the_name() {
        assert_eq!(
            kind_of("anything.yml", "apiVersion: v1\nkind: Service\n"),
            Some(ManifestKind::Kubernetes)
        );
        assert_eq!(
            kind_of("compose.yaml", "services:\n  api:\n"),
            Some(ManifestKind::Compose)
        );
        assert_eq!(kind_of("notes.md", "# hello"), None);
    }

    #[test]
    fn redaction_reason_is_recorded_for_withheld_values() {
        let analysis = analyze("deploy/docker-compose.yml", COMPOSE);
        assert_eq!(REASON_SECRET_WITHHELD, "redacted-secret-value");
        assert!(analysis.redacted.iter().all(|entry| !entry.key.is_empty()));
    }
}
