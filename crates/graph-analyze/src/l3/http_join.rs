//! Join HTTP relations through configured solution mappings (task B-060).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 2 requires a Level-3 relation
//! to be published only when the source literally names its two ends. A client
//! call whose address is a runtime value names only one end, so this join is
//! deliberately narrow:
//!
//! * a client request is joined only when its target host matches an alias the
//!   solution explicitly configured, and that alias names one project;
//! * the join is only made when a declared server endpoint has the same HTTP
//!   verb and a path template the request path actually satisfies;
//! * more than one candidate route stays [`FactQuality::InferredStatic`] -
//!   ambiguous - instead of the build picking a favourite;
//! * a host with no configured alias is reported unresolved. The build never
//!   invents a project from the shape of a URL.
//!
//! This module records no network traffic and executes no user source.

use crate::{Diagnostic, Span};

use super::dotnet_routes::HttpVerb;
use super::{normalize_route, FactQuality};

/// Pattern id for a request joined through a configured project alias.
pub const PATTERN_ALIAS_JOIN: &str = "http-join-configured-alias";
/// Pattern id for a host that no configured alias names.
pub const PATTERN_UNCONFIGURED_HOST: &str = "http-join-unconfigured-host";
/// Pattern id for a relative client address with no detectable host.
pub const PATTERN_RELATIVE_CLIENT: &str = "http-join-relative-client";
/// Pattern id for a configured host with zero matching server routes.
pub const PATTERN_NO_ROUTE_CANDIDATE: &str = "http-join-no-route-candidate";
/// Pattern id for a configured host with more than one matching server route.
pub const PATTERN_AMBIGUOUS_ROUTE: &str = "http-join-ambiguous-route";

/// Reason recorded when the request host has no configured solution alias.
pub const REASON_NO_CONFIGURED_ALIAS: &str = "unresolved-no-configured-alias";
/// Reason recorded when a client address carries no absolute host at all.
pub const REASON_RUNTIME_BASE_URL: &str = "unresolved-runtime-base-url";
/// Reason recorded when no declared route matches verb and path.
pub const REASON_NO_ROUTE_CANDIDATE: &str = "unresolved-no-matching-route";
/// Reason recorded when several declared routes match equally well.
pub const REASON_AMBIGUOUS_ROUTE: &str = "unresolved-ambiguous-route-candidate";

/// One configured alias from the solution mapping.
///
/// An alias is an absolute host spelling (`api.contoso.example`,
/// `10.0.0.4:8080`) that the solution says belongs to one project. Anything not
/// listed here is not joinable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SolutionAlias {
    /// The host spelling this alias matches, normalised (lowercase, no scheme).
    pub alias: String,
    /// The project the alias belongs to.
    pub project: String,
}

impl SolutionAlias {
    /// Build a configured alias, normalising the host spelling.
    #[must_use]
    pub fn new(alias: impl Into<String>, project: impl Into<String>) -> Self {
        Self {
            alias: normalize_host(&alias.into()),
            project: project.into(),
        }
    }
}

/// The configured aliases and known projects of one solution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SolutionMapping {
    /// Configured host-to-project aliases.
    pub aliases: Vec<SolutionAlias>,
}

impl SolutionMapping {
    /// The project a request host resolves to, when exactly one alias matches.
    #[must_use]
    pub fn project_for(&self, host: &str) -> Option<&str> {
        let host = normalize_host(host);
        let mut found: Option<&str> = None;
        for alias in &self.aliases {
            if alias.alias == host {
                if let Some(previous) = found {
                    if previous != alias.project {
                        // Two projects claim the same host: the mapping itself is
                        // ambiguous, so nothing may be joined from it.
                        return None;
                    }
                }
                found = Some(&alias.project);
            }
        }
        found
    }
}

/// One declared server endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEndpointFact {
    /// Owning project.
    pub project: String,
    /// Declaring file.
    pub file: String,
    /// Bound verb.
    pub method: HttpVerb,
    /// Declared path template, e.g. `api/items/{id}`.
    pub template: String,
    /// Span of the declaration.
    pub span: Span,
}

/// One client request with an address the adapter could read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpClientFact {
    /// Owning project.
    pub project: String,
    /// Declaring file.
    pub file: String,
    /// Bound verb.
    pub method: HttpVerb,
    /// The absolute URL when the source wrote one.
    pub absolute_url: Option<String>,
    /// The request path (without query) when the source wrote one.
    pub path: Option<String>,
    /// Span of the request.
    pub span: Span,
}

/// One joined client/server relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinedHttpRelation {
    /// Client-side project.
    pub client_project: String,
    /// Client-side file.
    pub client_file: String,
    /// Server-side project named by the configured alias.
    pub server_project: String,
    /// Server-side declaring file.
    pub server_file: String,
    /// The shared verb.
    pub method: HttpVerb,
    /// The request path as written, normalised.
    pub request_path: String,
    /// The matched server template.
    pub endpoint_template: String,
    /// Quality of the join. A unique match is `exact_static`.
    pub quality: FactQuality,
    /// Span of the client request.
    pub span: Span,
}

/// A candidate route that took part in an ambiguous match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCandidate {
    /// Server-side project.
    pub project: String,
    /// Server-side declaring file.
    pub file: String,
    /// Matched template.
    pub template: String,
    /// Span of the declaration.
    pub span: Span,
}

/// A request that matched more than one declared route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguousHttpRelation {
    /// Client-side project.
    pub client_project: String,
    /// Client-side file.
    pub client_file: String,
    /// Client-side verb.
    pub method: HttpVerb,
    /// Request path as written, normalised.
    pub request_path: String,
    /// Every equally good candidate, in source order.
    pub candidates: Vec<RouteCandidate>,
    /// Span of the client request.
    pub span: Span,
}

impl AmbiguousHttpRelation {
    /// The reason this join stayed ambiguous.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        REASON_AMBIGUOUS_ROUTE
    }
}

/// A request the join refused to analyse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedHttpRelation {
    /// Client-side project.
    pub client_project: String,
    /// Client-side file.
    pub client_file: String,
    /// A `PATTERN_*` id naming what was not analysed.
    pub pattern: String,
    /// A `REASON_*` value explaining the refusal.
    pub reason: String,
    /// Span of the client request.
    pub span: Span,
}

/// Result of joining client requests against declared endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpJoinReport {
    /// Unique joins, in client source order.
    pub relations: Vec<JoinedHttpRelation>,
    /// Ambiguous joins, in client source order.
    pub ambiguous: Vec<AmbiguousHttpRelation>,
    /// Refused requests, in client source order.
    pub unresolved: Vec<UnresolvedHttpRelation>,
    /// Diagnostics attached to the join.
    pub diagnostics: Vec<Diagnostic>,
}

impl HttpJoinReport {
    /// Whether any request was refused or left ambiguous.
    #[must_use]
    pub fn has_unresolved(&self) -> bool {
        !self.unresolved.is_empty() || !self.ambiguous.is_empty()
    }

    /// Every relation attributed to `project`, in report order.
    #[must_use]
    pub fn relations_for(&self, project: &str) -> Vec<&JoinedHttpRelation> {
        self.relations
            .iter()
            .filter(|relation| relation.client_project == project)
            .collect()
    }
}

/// Normalise a host spelling: drop scheme and path, lowercase, drop default port.
#[must_use]
pub fn normalize_host(raw: &str) -> String {
    let lowered = raw.trim().to_ascii_lowercase();
    let after_scheme = match lowered.find("://") {
        Some(index) => &lowered[index + 3..],
        None => lowered.as_str(),
    };
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let mut host = authority.to_string();
    for default in [":80", ":443"] {
        if let Some(stripped) = host.strip_suffix(default) {
            host = stripped.to_string();
        }
    }
    host
}

/// The host of an absolute URL, or `None` for a relative address.
#[must_use]
pub fn host_of(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if !trimmed.contains("://") && !trimmed.starts_with("//") {
        return None;
    }
    let host = normalize_host(trimmed);
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Whether a declared template satisfies a concrete request path.
///
/// Segment counts must agree, literal segments must agree case-insensitively,
/// `{name}` matches exactly one segment and `{*name}` matches the remainder.
#[must_use]
pub fn path_matches(template: &str, request: &str) -> bool {
    let normalized_template = normalize_route(template);
    let normalized_request = normalize_route(request);
    let template_segments: Vec<&str> = normalized_template
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let request_segments: Vec<&str> = normalized_request
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let mut index = 0_usize;
    while index < template_segments.len() {
        let template_segment = template_segments[index];
        if template_segment.starts_with('{') && template_segment.ends_with('}') {
            let name = &template_segment[1..template_segment.len() - 1];
            if name.starts_with('*') || name.starts_with("**") {
                return index < request_segments.len();
            }
            if index >= request_segments.len() {
                return false;
            }
        } else if request_segments
            .get(index)
            .map(|segment| segment.eq_ignore_ascii_case(template_segment))
            != Some(true)
        {
            return false;
        }
        index += 1;
    }
    index == request_segments.len()
}

fn request_path(client: &HttpClientFact) -> Option<String> {
    match (&client.absolute_url, &client.path) {
        (Some(url), _) => {
            let after_scheme = match url.find("://") {
                Some(index) => &url[index + 3..],
                None => url.as_str(),
            };
            let path_and_rest = match after_scheme.find('/') {
                Some(index) => &after_scheme[index..],
                // An absolute URL with no path addresses the service root.
                None => "/",
            };
            let path = path_and_rest
                .split(['?', '#'])
                .next()
                .unwrap_or(path_and_rest);
            Some(normalize_route(path))
        }
        (None, Some(path)) => Some(normalize_route(path)),
        (None, None) => None,
    }
}

/// Join client requests against declared endpoints through the solution mapping.
#[must_use]
pub fn join(
    endpoints: &[HttpEndpointFact],
    clients: &[HttpClientFact],
    mapping: &SolutionMapping,
) -> HttpJoinReport {
    let mut report = HttpJoinReport::default();
    for client in clients {
        let Some(host) = client.absolute_url.as_deref().and_then(host_of) else {
            report.unresolved.push(UnresolvedHttpRelation {
                client_project: client.project.clone(),
                client_file: client.file.clone(),
                pattern: PATTERN_RELATIVE_CLIENT.to_string(),
                reason: REASON_RUNTIME_BASE_URL.to_string(),
                span: client.span,
            });
            continue;
        };
        let Some(project) = mapping.project_for(&host) else {
            report.unresolved.push(UnresolvedHttpRelation {
                client_project: client.project.clone(),
                client_file: client.file.clone(),
                pattern: PATTERN_UNCONFIGURED_HOST.to_string(),
                reason: REASON_NO_CONFIGURED_ALIAS.to_string(),
                span: client.span,
            });
            continue;
        };
        let Some(path) = request_path(client) else {
            report.unresolved.push(UnresolvedHttpRelation {
                client_project: client.project.clone(),
                client_file: client.file.clone(),
                pattern: PATTERN_RELATIVE_CLIENT.to_string(),
                reason: REASON_RUNTIME_BASE_URL.to_string(),
                span: client.span,
            });
            continue;
        };
        let candidates: Vec<&HttpEndpointFact> = endpoints
            .iter()
            .filter(|endpoint| {
                endpoint.project == project
                    && endpoint.method == client.method
                    && path_matches(&endpoint.template, &path)
            })
            .collect();
        match candidates.len() {
            0 => report.unresolved.push(UnresolvedHttpRelation {
                client_project: client.project.clone(),
                client_file: client.file.clone(),
                pattern: PATTERN_NO_ROUTE_CANDIDATE.to_string(),
                reason: REASON_NO_ROUTE_CANDIDATE.to_string(),
                span: client.span,
            }),
            1 => {
                let endpoint = candidates[0];
                report.relations.push(JoinedHttpRelation {
                    client_project: client.project.clone(),
                    client_file: client.file.clone(),
                    server_project: endpoint.project.clone(),
                    server_file: endpoint.file.clone(),
                    method: client.method,
                    request_path: path,
                    endpoint_template: normalize_route(&endpoint.template),
                    quality: FactQuality::ExactStatic,
                    span: client.span,
                });
            }
            _ => report.ambiguous.push(AmbiguousHttpRelation {
                client_project: client.project.clone(),
                client_file: client.file.clone(),
                method: client.method,
                request_path: path,
                candidates: candidates
                    .iter()
                    .map(|endpoint| RouteCandidate {
                        project: endpoint.project.clone(),
                        file: endpoint.file.clone(),
                        template: normalize_route(&endpoint.template),
                        span: endpoint.span,
                    })
                    .collect(),
                span: client.span,
            }),
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::{
        host_of, join, normalize_host, path_matches, HttpClientFact, HttpEndpointFact,
        SolutionAlias, SolutionMapping, REASON_AMBIGUOUS_ROUTE, REASON_NO_CONFIGURED_ALIAS,
        REASON_NO_ROUTE_CANDIDATE, REASON_RUNTIME_BASE_URL,
    };
    use crate::l3::dotnet_routes::HttpVerb;
    use crate::l3::FactQuality;
    use crate::Span;

    fn mapping() -> SolutionMapping {
        SolutionMapping {
            aliases: vec![
                SolutionAlias::new("https://orders.contoso.example/", "Orders"),
                SolutionAlias::new("billing.contoso.example:443", "Billing"),
            ],
        }
    }

    fn endpoint(project: &str, file: &str, method: HttpVerb, template: &str) -> HttpEndpointFact {
        HttpEndpointFact {
            project: project.to_string(),
            file: file.to_string(),
            method,
            template: template.to_string(),
            span: Span::new(0, 0),
        }
    }

    fn client(
        project: &str,
        file: &str,
        method: HttpVerb,
        url: Option<&str>,
        path: Option<&str>,
    ) -> HttpClientFact {
        HttpClientFact {
            project: project.to_string(),
            file: file.to_string(),
            method,
            absolute_url: url.map(str::to_string),
            path: path.map(str::to_string),
            span: Span::new(0, 0),
        }
    }

    #[test]
    fn only_a_configured_alias_and_a_compatible_route_join() {
        let endpoints = vec![
            endpoint(
                "Orders",
                "Orders/Controllers/Items.cs",
                HttpVerb::Get,
                "api/items/{id}",
            ),
            endpoint(
                "Orders",
                "Orders/Controllers/Items.cs",
                HttpVerb::Get,
                "api/items",
            ),
        ];
        let clients = vec![
            client(
                "Web",
                "web/src/app/items.service.ts",
                HttpVerb::Get,
                Some("https://orders.contoso.example/api/items/42"),
                None,
            ),
            client(
                "Web",
                "web/src/app/items.service.ts",
                HttpVerb::Post,
                Some("https://orders.contoso.example/api/items/42"),
                None,
            ),
        ];
        let report = join(&endpoints, &clients, &mapping());
        assert_eq!(report.relations.len(), 1);
        let relation = &report.relations[0];
        assert_eq!(relation.server_project, "Orders");
        assert_eq!(relation.endpoint_template, "api/items/{id}");
        assert_eq!(relation.quality, FactQuality::ExactStatic);
        assert!(relation.quality.is_proven());
        // The POST request has no declared POST route, so it is not joined.
        assert_eq!(report.unresolved.len(), 1);
        assert_eq!(report.unresolved[0].reason, REASON_NO_ROUTE_CANDIDATE);
        assert!(report.has_unresolved());
    }

    #[test]
    fn an_unconfigured_host_never_resolves_to_a_project() {
        let endpoints = vec![endpoint("Orders", "a.cs", HttpVerb::Get, "api/items")];
        let clients = vec![client(
            "Web",
            "w.ts",
            HttpVerb::Get,
            Some("https://unknown.example/api/items"),
            None,
        )];
        let report = join(&endpoints, &clients, &mapping());
        assert!(report.relations.is_empty());
        assert_eq!(report.unresolved.len(), 1);
        assert_eq!(report.unresolved[0].reason, REASON_NO_CONFIGURED_ALIAS);
    }

    #[test]
    fn duplicate_route_candidates_stay_ambiguous() {
        let endpoints = vec![
            endpoint("Orders", "a.cs", HttpVerb::Get, "api/items"),
            endpoint("Orders", "b.cs", HttpVerb::Get, "api/{controller}"),
        ];
        let clients = vec![client(
            "Web",
            "w.ts",
            HttpVerb::Get,
            Some("https://orders.contoso.example/api/items"),
            None,
        )];
        let report = join(&endpoints, &clients, &mapping());
        assert!(report.relations.is_empty());
        assert_eq!(report.ambiguous.len(), 1);
        assert_eq!(report.ambiguous[0].candidates.len(), 2);
        assert_eq!(report.ambiguous[0].reason(), REASON_AMBIGUOUS_ROUTE);
        assert!(report.ambiguous[0]
            .candidates
            .iter()
            .all(|candidate| candidate.project == "Orders"));
        assert!(report.relations_for("Web").is_empty());
    }

    #[test]
    fn a_relative_address_is_a_runtime_base_url() {
        let clients = vec![client(
            "Web",
            "w.ts",
            HttpVerb::Get,
            None,
            Some("/api/items"),
        )];
        let report = join(&[], &clients, &mapping());
        assert_eq!(report.unresolved.len(), 1);
        assert_eq!(report.unresolved[0].reason, REASON_RUNTIME_BASE_URL);
    }

    #[test]
    fn templates_match_segment_wise_and_never_by_prefix() {
        assert!(path_matches("api/items/{id}", "api/items/42"));
        assert!(path_matches("api/items", "api/items/"));
        assert!(!path_matches("api/items", "api/items/42"));
        assert!(!path_matches("api/items/{id}", "api/items"));
        assert!(path_matches("api/{*rest}", "api/items/42"));
        assert!(path_matches("api/items", "API/Items"));
        assert!(path_matches("Api/Items", "api/items"));
    }

    #[test]
    fn hosts_normalise_scheme_port_and_case() {
        assert_eq!(
            normalize_host("HTTPS://Orders.Contoso.Example:443/x"),
            "orders.contoso.example"
        );
        assert_eq!(
            normalize_host("http://billing.contoso.example:80"),
            "billing.contoso.example"
        );
        assert_eq!(host_of("/api/items"), None);
        assert_eq!(host_of("api/items"), None);
        assert_eq!(
            host_of("https://orders.contoso.example/api/items?x=1").as_deref(),
            Some("orders.contoso.example")
        );
    }

    #[test]
    fn a_host_claimed_by_two_projects_is_not_joinable() {
        let mut mapping = mapping();
        mapping
            .aliases
            .push(SolutionAlias::new("orders.contoso.example", "Another"));
        let endpoints = vec![endpoint("Orders", "a.cs", HttpVerb::Get, "api/items")];
        let clients = vec![client(
            "Web",
            "w.ts",
            HttpVerb::Get,
            Some("https://orders.contoso.example/api/items"),
            None,
        )];
        let report = join(&endpoints, &clients, &mapping);
        assert!(report.relations.is_empty());
        assert_eq!(report.unresolved.len(), 1);
        assert_eq!(report.unresolved[0].reason, REASON_NO_CONFIGURED_ALIAS);
    }
}
