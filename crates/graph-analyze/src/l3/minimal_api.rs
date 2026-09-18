//! Explicit minimal API mappings (task B-058).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 2 names `basic literal
//! MapGet/MapPost/MapGroup` as the supported subset of the `aspnet-routes`
//! profile and requires dynamic routes and generated endpoints to be reported
//! instead of guessed.
//!
//! A mapping is accepted only when its receiver is a variable this file
//! declared as a built `WebApplication` root or as a literal `MapGroup`
//! prefix. A mapping on an unknown variable, on a builder that was never
//! built, or with a computed route pattern is reported with a named pattern
//! and reason; it never becomes an endpoint.

use std::collections::{BTreeMap, BTreeSet};

use crate::{Diagnostic, Span};

use super::dotnet_routes::HttpVerb;
use super::{
    first_literal_argument, lines_with_offsets, normalize_route, split_arguments,
    strip_line_comment,
};

/// Pattern id for `MapControllers`, which discovers endpoints by convention.
pub const PATTERN_MAP_CONTROLLERS: &str = "minimal-api-map-controllers";
/// Pattern id for `MapRazorPages`.
pub const PATTERN_MAP_RAZOR_PAGES: &str = "minimal-api-map-razor-pages";
/// Pattern id for `MapHub`.
pub const PATTERN_MAP_HUB: &str = "minimal-api-map-hub";
/// Pattern id for `MapHealthChecks`.
pub const PATTERN_MAP_HEALTH_CHECKS: &str = "minimal-api-map-health-checks";
/// Pattern id for `MapFallback`.
pub const PATTERN_MAP_FALLBACK: &str = "minimal-api-map-fallback";
/// Pattern id for `MapMethods`, whose verb list is not a literal.
pub const PATTERN_MAP_METHODS: &str = "minimal-api-map-methods";
/// Pattern id for a mapping on a receiver this file never declared.
pub const PATTERN_UNKNOWN_RECEIVER: &str = "minimal-api-unknown-receiver";
/// Pattern id for a mapping on a builder that was never built.
pub const PATTERN_APP_NOT_BUILT: &str = "minimal-api-app-not-built";
/// Pattern id for a `MapGroup` whose prefix is not a literal.
pub const PATTERN_DYNAMIC_MAP_GROUP: &str = "minimal-api-dynamic-map-group";
/// Pattern id for a mapping without a request delegate.
pub const PATTERN_MISSING_HANDLER: &str = "minimal-api-missing-handler";

/// Reason recorded for a convention-driven pattern.
pub const REASON_CONVENTION_PATTERN: &str = "unsupported-convention-pattern";
/// Reason recorded for a computed route pattern.
pub const REASON_DYNAMIC_ROUTE: &str = "unresolved-dynamic-route";
/// Reason recorded for a receiver this file never declared.
pub const REASON_UNKNOWN_RECEIVER: &str = "unresolved-unknown-receiver";
/// Reason recorded for a mapping with no request delegate.
pub const REASON_MISSING_HANDLER: &str = "unresolved-missing-handler";

/// One literal endpoint mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalEndpoint {
    /// The receiver that declared the mapping.
    pub receiver: String,
    /// The composed literal template, without a leading slash.
    pub template: String,
    /// The bound verb.
    pub verb: HttpVerb,
    /// Span of the mapping call.
    pub span: Span,
}

/// One mapping the adapter refused to analyse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedPattern {
    /// A `PATTERN_*` id naming the pattern that was not analysed.
    pub pattern: String,
    /// A `REASON_*` value explaining the refusal.
    pub reason: String,
    /// Span of the refused call.
    pub span: Span,
}

/// Result of analysing one C# file for minimal API mappings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MinimalApiAnalysis {
    /// Literal endpoints, in source order.
    pub endpoints: Vec<MinimalEndpoint>,
    /// Refused patterns, in source order.
    pub unsupported: Vec<UnsupportedPattern>,
    /// Diagnostics attached to the file.
    pub diagnostics: Vec<Diagnostic>,
}

impl MinimalApiAnalysis {
    /// Whether any pattern was refused instead of analysed.
    #[must_use]
    pub fn has_unsupported(&self) -> bool {
        !self.unsupported.is_empty()
    }

    /// Endpoints that bind `verb`, in source order.
    #[must_use]
    pub fn endpoints_for(&self, verb: HttpVerb) -> Vec<&MinimalEndpoint> {
        self.endpoints
            .iter()
            .filter(|endpoint| endpoint.verb == verb)
            .collect()
    }
}

/// The mappers this adapter knows, with the verb when the name is a verb.
const MAPPERS: [(&str, Option<HttpVerb>); 11] = [
    ("MapGet", Some(HttpVerb::Get)),
    ("MapPost", Some(HttpVerb::Post)),
    ("MapPut", Some(HttpVerb::Put)),
    ("MapDelete", Some(HttpVerb::Delete)),
    ("MapPatch", Some(HttpVerb::Patch)),
    ("MapMethods", None),
    ("MapControllers", None),
    ("MapRazorPages", None),
    ("MapHub", None),
    ("MapHealthChecks", None),
    ("MapFallback", None),
];

fn convention_pattern(name: &str) -> &'static str {
    match name {
        "MapRazorPages" => PATTERN_MAP_RAZOR_PAGES,
        "MapHub" => PATTERN_MAP_HUB,
        "MapHealthChecks" => PATTERN_MAP_HEALTH_CHECKS,
        "MapFallback" => PATTERN_MAP_FALLBACK,
        "MapMethods" => PATTERN_MAP_METHODS,
        _ => PATTERN_MAP_CONTROLLERS,
    }
}

/// Analyse one C# file for literal minimal API mappings.
#[must_use]
pub fn analyze(_file: &str, source: &str) -> MinimalApiAnalysis {
    let mut analysis = MinimalApiAnalysis::default();
    let mut builders: BTreeSet<String> = BTreeSet::new();
    let mut roots: BTreeSet<String> = BTreeSet::new();
    let mut groups: BTreeMap<String, Option<String>> = BTreeMap::new();

    for (offset, raw_line) in lines_with_offsets(source) {
        let line = strip_line_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let declared = declared_variable(trimmed);

        if let Some(name) = &declared {
            if trimmed.contains("CreateBuilder(") {
                builders.insert(name.clone());
            }
            if trimmed.contains(".Build(") {
                roots.insert(name.clone());
            }
            if let Some((dot, args)) = find_call(trimmed, "MapGroup") {
                let span = Span::new(
                    offset + dot,
                    offset + dot + 1 + "MapGroup".len() + args.len() + 2,
                );
                match first_literal_argument(&args) {
                    Some(prefix) => {
                        groups.insert(name.clone(), Some(normalize_route(&prefix)));
                    }
                    None => {
                        groups.insert(name.clone(), None);
                        analysis.unsupported.push(UnsupportedPattern {
                            pattern: PATTERN_DYNAMIC_MAP_GROUP.to_string(),
                            reason: REASON_DYNAMIC_ROUTE.to_string(),
                            span,
                        });
                        analysis.diagnostics.push(Diagnostic::warning(
                            PATTERN_DYNAMIC_MAP_GROUP,
                            "MapGroup prefix is not a literal template",
                            span,
                        ));
                    }
                }
            }
        }

        for (name, verb) in MAPPERS {
            let Some((dot, args)) = find_call(trimmed, name) else {
                continue;
            };
            let span = Span::new(offset + dot, offset + dot + 1 + name.len() + args.len() + 2);
            let receiver = receiver_of(trimmed, dot);

            let Some(verb) = verb else {
                analysis.unsupported.push(UnsupportedPattern {
                    pattern: convention_pattern(name).to_string(),
                    reason: REASON_CONVENTION_PATTERN.to_string(),
                    span,
                });
                analysis.diagnostics.push(Diagnostic::warning(
                    convention_pattern(name),
                    "endpoint discovery by convention is not analysed",
                    span,
                ));
                break;
            };

            let prefix = match receiver.as_deref() {
                Some(name) if groups.contains_key(name) => groups[name].clone(),
                Some(name) if roots.contains(name) => Some(String::new()),
                Some(name) if builders.contains(name) => {
                    analysis.unsupported.push(UnsupportedPattern {
                        pattern: PATTERN_APP_NOT_BUILT.to_string(),
                        reason: REASON_UNKNOWN_RECEIVER.to_string(),
                        span,
                    });
                    break;
                }
                Some(_) => {
                    analysis.unsupported.push(UnsupportedPattern {
                        pattern: PATTERN_UNKNOWN_RECEIVER.to_string(),
                        reason: REASON_UNKNOWN_RECEIVER.to_string(),
                        span,
                    });
                    break;
                }
                None => {
                    analysis.unsupported.push(UnsupportedPattern {
                        pattern: PATTERN_UNKNOWN_RECEIVER.to_string(),
                        reason: REASON_UNKNOWN_RECEIVER.to_string(),
                        span,
                    });
                    break;
                }
            };

            let mut arguments = split_arguments(&args);
            if arguments.len() < 2 {
                analysis.unsupported.push(UnsupportedPattern {
                    pattern: PATTERN_MISSING_HANDLER.to_string(),
                    reason: REASON_MISSING_HANDLER.to_string(),
                    span,
                });
                break;
            }
            arguments.clear();
            let Some(template) = first_literal_argument(&args) else {
                analysis.unsupported.push(UnsupportedPattern {
                    pattern: name.to_string(),
                    reason: REASON_DYNAMIC_ROUTE.to_string(),
                    span,
                });
                analysis.diagnostics.push(Diagnostic::warning(
                    name,
                    "route pattern is not a literal template",
                    span,
                ));
                break;
            };
            let Some(prefix) = prefix else {
                analysis.unsupported.push(UnsupportedPattern {
                    pattern: PATTERN_DYNAMIC_MAP_GROUP.to_string(),
                    reason: REASON_DYNAMIC_ROUTE.to_string(),
                    span,
                });
                break;
            };
            // Minimal API patterns always compose with their group prefix; a
            // leading separator is not an absolute-route override here.
            let template = normalize_route(&format!("{prefix}/{template}"));
            analysis.endpoints.push(MinimalEndpoint {
                receiver: receiver.unwrap_or_default(),
                template,
                verb,
                span,
            });
            break;
        }
    }
    analysis
}

fn declared_variable(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("var ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if name.is_empty() {
        return None;
    }
    Some(name)
}

fn receiver_of(line: &str, dot: usize) -> Option<String> {
    let before = line.get(..dot)?.trim_end();
    if before.is_empty() || before.ends_with(')') {
        return None;
    }
    let start = before
        .char_indices()
        .rev()
        .find(|(_, c)| !(c.is_alphanumeric() || *c == '_'))
        .map_or(0, |(index, c)| index + c.len_utf8());
    let name = &before[start..];
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

/// Find `.<name>(` in one line; returns the `.` offset and the raw arguments.
fn find_call(line: &str, name: &str) -> Option<(usize, String)> {
    for (index, _) in line.match_indices(name) {
        if index == 0 || line.as_bytes()[index - 1] != b'.' {
            continue;
        }
        let open = index + name.len();
        if line.as_bytes().get(open) != Some(&b'(') {
            continue;
        }
        if let Some(args) = call_arguments(line, open) {
            return Some((index - 1, args));
        }
    }
    None
}

fn call_arguments(line: &str, open: usize) -> Option<String> {
    let bytes = line.as_bytes();
    let mut depth = 0_i32;
    let mut in_string: Option<u8> = None;
    let mut escaped = false;
    for index in open..bytes.len() {
        let value = bytes[index];
        if let Some(quote) = in_string {
            if escaped {
                escaped = false;
            } else if value == b'\\' {
                escaped = true;
            } else if value == quote {
                in_string = None;
            }
            continue;
        }
        match value {
            b'"' | b'\'' => in_string = Some(value),
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(line[open + 1..index].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        analyze, PATTERN_APP_NOT_BUILT, PATTERN_MAP_CONTROLLERS, PATTERN_MAP_METHODS,
        PATTERN_UNKNOWN_RECEIVER, REASON_CONVENTION_PATTERN, REASON_DYNAMIC_ROUTE,
        REASON_UNKNOWN_RECEIVER,
    };
    use crate::l3::dotnet_routes::HttpVerb;

    const SAMPLE: &str = r#"var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

var api = app.MapGroup("/api");

app.MapGet("/health", () => Results.Ok());

api.MapGet("/items/{id}", (int id) => Results.Ok(id));
api.MapPost("/items", (Item item) => Results.Ok(item));

app.MapControllers();

app.MapGet(pattern, () => Results.Ok());

app.MapMethods("/x", new[] { "GET", "POST" }, () => Results.Ok());

other.MapGet("/leak", () => Results.Ok());
"#;

    #[test]
    fn literal_map_get_and_map_post_expose_endpoints() {
        let analysis = analyze("Program.cs", SAMPLE);
        let health = analysis
            .endpoints
            .iter()
            .find(|endpoint| endpoint.template == "health")
            .expect("health endpoint");
        assert_eq!(health.verb, HttpVerb::Get);
        assert_eq!(health.receiver, "app");
        let item = analysis
            .endpoints
            .iter()
            .find(|endpoint| endpoint.template == "api/items/{id}")
            .expect("grouped endpoint");
        assert_eq!(item.verb, HttpVerb::Get);
        assert_eq!(analysis.endpoints_for(HttpVerb::Post).len(), 1);
        assert_eq!(analysis.endpoints.len(), 3);
    }

    #[test]
    fn a_grouped_post_mapping_composes_the_literal_group_prefix() {
        let analysis = analyze("Program.cs", SAMPLE);
        let post = analysis
            .endpoints
            .iter()
            .find(|endpoint| endpoint.verb == HttpVerb::Post)
            .expect("post endpoint");
        assert_eq!(post.template, "api/items");
        assert_eq!(post.receiver, "api");
    }

    #[test]
    fn convention_mappers_are_reported_as_unsupported_patterns() {
        let analysis = analyze("Program.cs", SAMPLE);
        assert!(analysis.unsupported.iter().any(|pattern| {
            pattern.pattern == PATTERN_MAP_CONTROLLERS
                && pattern.reason == REASON_CONVENTION_PATTERN
        }));
        assert!(analysis.unsupported.iter().any(|pattern| {
            pattern.pattern == PATTERN_MAP_METHODS && pattern.reason == REASON_CONVENTION_PATTERN
        }));
        assert!(analysis.has_unsupported());
        assert!(analysis
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == PATTERN_MAP_CONTROLLERS));
    }

    #[test]
    fn a_computed_route_pattern_is_unresolved_and_never_an_endpoint() {
        let analysis = analyze("Program.cs", SAMPLE);
        assert!(!analysis
            .endpoints
            .iter()
            .any(|endpoint| endpoint.template.contains("pattern")));
        assert!(analysis
            .unsupported
            .iter()
            .any(|unsupported| unsupported.reason == REASON_DYNAMIC_ROUTE));
    }

    #[test]
    fn a_mapping_on_an_undeclared_receiver_is_never_an_endpoint() {
        let analysis = analyze("Program.cs", SAMPLE);
        assert!(!analysis
            .endpoints
            .iter()
            .any(|endpoint| endpoint.template.contains("leak")));
        assert!(analysis.unsupported.iter().any(|unsupported| {
            unsupported.pattern == PATTERN_UNKNOWN_RECEIVER
                && unsupported.reason == REASON_UNKNOWN_RECEIVER
        }));
    }

    #[test]
    fn a_mapping_on_an_unbuilt_builder_is_reported_separately() {
        const NOT_BUILT: &str = "var builder = WebApplication.CreateBuilder(args);\nbuilder.MapGet(\"/x\", () => Results.Ok());\n";
        let analysis = analyze("Program.cs", NOT_BUILT);
        assert!(analysis.endpoints.is_empty());
        assert!(analysis
            .unsupported
            .iter()
            .any(|unsupported| unsupported.pattern == PATTERN_APP_NOT_BUILT));
    }

    #[test]
    fn a_mapping_without_a_handler_is_reported() {
        const NO_HANDLER: &str = "var builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();\napp.MapGet(\"/x\");\n";
        let analysis = analyze("Program.cs", NO_HANDLER);
        assert!(analysis.endpoints.is_empty());
        assert!(analysis
            .unsupported
            .iter()
            .any(|unsupported| unsupported.reason == "unresolved-missing-handler"));
    }

    #[test]
    fn analysis_is_deterministic() {
        let first = analyze("Program.cs", SAMPLE);
        for _ in 0..3 {
            assert_eq!(analyze("Program.cs", SAMPLE), first);
        }
    }
}
