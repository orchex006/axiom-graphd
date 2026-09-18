//! ASP.NET literal route attributes (task B-057).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 2 requires the `aspnet-routes`
//! profile to understand `Controller` `Route`/`Http*` attributes, literal
//! prefixes and the basic literal `MapGet`/`MapPost`/`MapGroup` shape, and to
//! report dynamic routes, middleware conditionals and generated endpoints as
//! unsupported.
//!
//! This adapter composes a controller prefix with an action template only when
//! both are literal. `[controller]` and `[action]` tokens are substituted from
//! the declared names, because both the token and the name are literally
//! present in the source. A template built by concatenation, interpolation or
//! any computed expression is reported unresolved with a reason; it never
//! becomes an endpoint and the adapter never guesses a prefix to replace it.

use crate::{Diagnostic, Span};

use super::{first_literal_argument, lines_with_offsets, strip_line_comment, FactQuality};

/// Stable code for a dynamic route diagnostic.
pub const CODE_DYNAMIC_ROUTE: &str = "aspnet-dynamic-route";

/// Reason recorded when a route or verb template is not a literal.
pub const REASON_DYNAMIC_ROUTE: &str = "unresolved-dynamic-route";

/// One HTTP verb an ASP.NET attribute can bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HttpVerb {
    /// `HttpGet`.
    Get,
    /// `HttpPost`.
    Post,
    /// `HttpPut`.
    Put,
    /// `HttpDelete`.
    Delete,
    /// `HttpPatch`.
    Patch,
    /// `HttpHead`.
    Head,
    /// `HttpOptions`.
    Options,
}

impl HttpVerb {
    /// Every verb this adapter recognises, in a stable order.
    #[must_use]
    pub const fn all() -> &'static [HttpVerb] {
        &[
            Self::Get,
            Self::Post,
            Self::Put,
            Self::Delete,
            Self::Patch,
            Self::Head,
            Self::Options,
        ]
    }

    /// Parse an attribute head such as `HttpGet`.
    #[must_use]
    pub fn parse(head: &str) -> Option<Self> {
        Some(match head {
            "HttpGet" => Self::Get,
            "HttpPost" => Self::Post,
            "HttpPut" => Self::Put,
            "HttpDelete" => Self::Delete,
            "HttpPatch" => Self::Patch,
            "HttpHead" => Self::Head,
            "HttpOptions" => Self::Options,
            _ => return None,
        })
    }

    /// Stable uppercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }
}

/// One composed endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEndpoint {
    /// Declaring controller name, as written.
    pub controller: String,
    /// Declaring action name, as written.
    pub action: String,
    /// The composed literal template, without a leading slash.
    pub template: String,
    /// The verbs the endpoint binds; empty means the route matched any verb.
    pub verbs: Vec<HttpVerb>,
    /// Always `exact_static`, because only literal composition gets this far.
    pub quality: FactQuality,
    /// Span of the declaration that produced the endpoint.
    pub span: Span,
}

impl RouteEndpoint {
    /// Whether the endpoint declared no verb and therefore matched any verb.
    #[must_use]
    pub fn is_verb_wildcard(&self) -> bool {
        self.verbs.is_empty()
    }
}

/// One attribute the adapter refused to turn into an endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedRoute {
    /// Declaring controller name.
    pub controller: String,
    /// Declaring action name, when the refusal was at action level.
    pub action: Option<String>,
    /// One of the `REASON_*` constants.
    pub reason: String,
    /// Span of the refused attribute.
    pub span: Span,
}

/// Result of analysing one C# source file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouteAnalysis {
    /// Composed endpoints, in source order.
    pub endpoints: Vec<RouteEndpoint>,
    /// Refused attributes, in source order.
    pub unresolved: Vec<UnresolvedRoute>,
    /// Diagnostics attached to the file.
    pub diagnostics: Vec<Diagnostic>,
}

impl RouteAnalysis {
    /// Whether any attribute was refused instead of analysed.
    #[must_use]
    pub fn has_unresolved(&self) -> bool {
        !self.unresolved.is_empty()
    }

    /// Endpoints that bind `verb`, in source order.
    #[must_use]
    pub fn endpoints_for(&self, verb: HttpVerb) -> Vec<&RouteEndpoint> {
        self.endpoints
            .iter()
            .filter(|endpoint| endpoint.verbs.contains(&verb))
            .collect()
    }
}

#[derive(Debug, Clone)]
struct Controller {
    name: String,
    prefix: String,
    dynamic: bool,
    close_depth: i32,
}

/// Analyse one C# source file for literal ASP.NET routes.
#[must_use]
pub fn analyze(_file: &str, source: &str) -> RouteAnalysis {
    let mut analysis = RouteAnalysis::default();
    let mut pending: Vec<(String, usize)> = Vec::new();
    let mut controller: Option<Controller> = None;
    let mut depth: i32 = 0;

    for (offset, raw_line) in lines_with_offsets(source) {
        let line = strip_line_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('[') {
            pending.extend(attributes_on_line(line, offset));
            depth += brace_delta(line);
            continue;
        }

        let attributes: Vec<(String, Option<String>)> = pending
            .iter()
            .map(|(text, _)| head_and_args(text))
            .collect();
        let attribute_span = pending.first().map_or_else(
            || Span::new(offset, offset + trimmed.len()),
            |(text, at)| Span::new(*at, *at + text.len()),
        );

        if let Some(name) = type_declaration(trimmed) {
            let mut literal: Option<String> = None;
            let mut dynamic = false;
            for (head, args) in &attributes {
                if head == "Route" {
                    match args.as_deref().and_then(first_literal_argument) {
                        Some(template) => {
                            if literal.is_none() {
                                literal = Some(template);
                            }
                        }
                        None => dynamic = true,
                    }
                }
            }
            if dynamic {
                analysis.unresolved.push(UnresolvedRoute {
                    controller: name.clone(),
                    action: None,
                    reason: REASON_DYNAMIC_ROUTE.to_string(),
                    span: attribute_span,
                });
                analysis.diagnostics.push(Diagnostic::warning(
                    CODE_DYNAMIC_ROUTE,
                    "controller route prefix is not a literal template",
                    attribute_span,
                ));
            }
            controller = Some(Controller {
                name,
                prefix: literal.unwrap_or_default(),
                dynamic,
                close_depth: depth,
            });
            pending.clear();
            depth += brace_delta(line);
            continue;
        }

        if let Some(action) = method_declaration(trimmed) {
            if let Some(current) = &controller {
                let mut verbs: Vec<HttpVerb> = Vec::new();
                let mut method_route: Option<String> = None;
                let mut routed = false;
                let mut dynamic = false;
                for (head, args) in &attributes {
                    if let Some(verb) = HttpVerb::parse(head) {
                        routed = true;
                        if !verbs.contains(&verb) {
                            verbs.push(verb);
                        }
                        match args.as_deref().and_then(first_literal_argument) {
                            Some(template) => {
                                if method_route.is_none() {
                                    method_route = Some(template);
                                }
                            }
                            // A bare `[HttpPost]` carries no template and is not a
                            // computed expression, so it composes the action name.
                            None if args.is_some() => dynamic = true,
                            None => {}
                        }
                    } else if head == "Route" {
                        routed = true;
                        match args.as_deref().and_then(first_literal_argument) {
                            Some(template) => {
                                if method_route.is_none() {
                                    method_route = Some(template);
                                }
                            }
                            None => dynamic = true,
                        }
                    }
                }
                if routed {
                    if dynamic || current.dynamic {
                        analysis.unresolved.push(UnresolvedRoute {
                            controller: current.name.clone(),
                            action: Some(action),
                            reason: REASON_DYNAMIC_ROUTE.to_string(),
                            span: attribute_span,
                        });
                        analysis.diagnostics.push(Diagnostic::warning(
                            CODE_DYNAMIC_ROUTE,
                            "action route template is not a literal",
                            attribute_span,
                        ));
                    } else {
                        verbs.sort_unstable();
                        let template = compose(
                            &current.prefix,
                            &current.name,
                            &action,
                            method_route.as_deref(),
                        );
                        analysis.endpoints.push(RouteEndpoint {
                            controller: current.name.clone(),
                            action,
                            template,
                            verbs,
                            quality: FactQuality::ExactStatic,
                            span: attribute_span,
                        });
                    }
                }
            }
        }

        pending.clear();
        let delta = brace_delta(line);
        depth += delta;
        let clear = delta < 0
            && controller
                .as_ref()
                .is_some_and(|current| depth <= current.close_depth);
        if clear {
            controller = None;
        }
    }
    analysis
}

/// Compose a controller prefix with an action template.
fn compose(
    class_prefix: &str,
    controller: &str,
    action: &str,
    method_route: Option<&str>,
) -> String {
    let controller_token = controller.strip_suffix("Controller").unwrap_or(controller);
    let method = match method_route {
        Some(route) => route.to_string(),
        None => action.to_string(),
    };
    let substituted = method
        .replace("[controller]", controller_token)
        .replace("[action]", action);
    if substituted.starts_with('/') {
        return normalize(&substituted);
    }
    let prefix = class_prefix
        .replace("[controller]", controller_token)
        .replace("[action]", action);
    if prefix.is_empty() {
        return normalize(&substituted);
    }
    normalize(&format!(
        "{}/{}",
        prefix.trim_end_matches('/'),
        substituted.trim_start_matches('/')
    ))
}

/// Collapse repeated separators and drop leading/trailing separators.
fn normalize(template: &str) -> String {
    let mut out = String::with_capacity(template.len());
    let mut last_slash = false;
    for ch in template.chars() {
        if ch == '/' {
            if last_slash {
                continue;
            }
            last_slash = true;
        } else {
            last_slash = false;
        }
        out.push(ch);
    }
    out.trim_matches('/').to_string()
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn word_position(text: &str, word: &str) -> Option<usize> {
    for (start, _) in text.match_indices(word) {
        let end = start + word.len();
        let before_ok = start == 0 || !is_word_byte(text.as_bytes()[start - 1]);
        let after_ok = end >= text.len() || !is_word_byte(text.as_bytes()[end]);
        if before_ok && after_ok {
            return Some(start);
        }
    }
    None
}

fn first_identifier(text: &str) -> Option<String> {
    let start = text.find(|c: char| c.is_ascii_alphabetic() || c == '_')?;
    let rest = &text[start..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

fn type_declaration(trimmed: &str) -> Option<String> {
    const KEYWORDS: [&str; 5] = ["class", "interface", "record", "struct", "enum"];
    for keyword in KEYWORDS {
        if let Some(position) = word_position(trimmed, keyword) {
            if let Some(name) = first_identifier(&trimmed[position + keyword.len()..]) {
                return Some(name);
            }
        }
    }
    None
}

fn strip_trailing_generics(text: &str) -> &str {
    let trimmed = text.trim_end();
    if !trimmed.ends_with('>') {
        return trimmed;
    }
    let mut depth = 0_i32;
    for (index, ch) in trimmed.char_indices().rev() {
        match ch {
            '>' => depth += 1,
            '<' => {
                depth -= 1;
                if depth == 0 {
                    return trimmed[..index].trim_end();
                }
            }
            _ => {}
        }
    }
    trimmed
}

fn method_declaration(trimmed: &str) -> Option<String> {
    if type_declaration(trimmed).is_some() {
        return None;
    }
    let open = trimmed.find('(')?;
    let before = strip_trailing_generics(trimmed[..open].trim_end());
    let name_start = before
        .char_indices()
        .rev()
        .find(|(_, c)| !(c.is_alphanumeric() || *c == '_'))
        .map_or(0, |(index, c)| index + c.len_utf8());
    let name = &before[name_start..];
    if name.is_empty() || !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
        return None;
    }
    const CONTROL: [&str; 10] = [
        "if", "for", "while", "switch", "catch", "using", "foreach", "lock", "return", "new",
    ];
    if CONTROL.contains(&name) {
        return None;
    }
    let head = before[..name_start].trim_end();
    if head.is_empty() || head.ends_with("new") || head.contains('=') {
        return None;
    }
    Some(name.to_string())
}

fn brace_delta(line: &str) -> i32 {
    let code = strip_line_comment(line);
    let mut delta = 0_i32;
    let mut in_string: Option<char> = None;
    let mut escaped = false;
    for ch in code.chars() {
        if let Some(quote) = in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                in_string = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => in_string = Some(ch),
            '{' => delta += 1,
            '}' => delta -= 1,
            _ => {}
        }
    }
    delta
}

/// Every `[...]` attribute on a line, with its byte offset.
fn attributes_on_line(line: &str, line_offset: usize) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() {
        if bytes[index] != b'[' {
            let byte = bytes[index];
            if !byte.is_ascii_whitespace() && byte != b',' {
                break;
            }
            index += 1;
            continue;
        }
        let mut depth = 0_i32;
        let mut in_string: Option<u8> = None;
        let mut escaped = false;
        let mut end: Option<usize> = None;
        for (step, byte) in bytes[index..].iter().enumerate() {
            let value = *byte;
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
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(index + step);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = end else { break };
        out.push((line[index + 1..close].to_string(), line_offset + index + 1));
        index = close + 1;
    }
    out
}

/// The normalised attribute head and its raw argument text.
fn head_and_args(attribute: &str) -> (String, Option<String>) {
    let text = attribute.trim();
    let (head, args) = match text.find('(') {
        Some(open) => {
            let body = &text[open + 1..];
            let args = body.strip_suffix(')').unwrap_or(body);
            (text[..open].trim(), Some(args.to_string()))
        }
        None => (text, None),
    };
    let leaf = head.rsplit('.').next().unwrap_or(head).trim();
    let normalized = leaf.strip_suffix("Attribute").unwrap_or(leaf);
    (normalized.to_string(), args)
}

#[cfg(test)]
mod tests {
    use super::{analyze, HttpVerb, REASON_DYNAMIC_ROUTE};
    use crate::l3::FactQuality;

    const SAMPLE: &str = r#"using Microsoft.AspNetCore.Mvc;

namespace Demo;

[ApiController]
[Route("api/[controller]")]
public class ItemsController : ControllerBase
{
    [HttpGet("{id}")]
    public IActionResult GetItem(int id) => Ok(id);

    [HttpPost]
    public IActionResult Create([FromBody] Item item) { return Ok(item); }

    [HttpPut("rename/{id}")]
    [HttpPatch("rename/{id}")]
    public IActionResult Rename(int id) => Ok();

    [Route("absolute")]
    public IActionResult Absolute() => Ok();

    [HttpGet(prefix + "/dynamic")]
    public IActionResult Dynamic() => Ok();

    [HttpGet($"/interpolated/{id}")]
    public IActionResult Interpolated(int id) => Ok();
}
"#;

    #[test]
    fn literal_controller_and_action_routes_compose_with_http_verbs() {
        let analysis = analyze("ItemsController.cs", SAMPLE);
        let item = analysis
            .endpoints
            .iter()
            .find(|endpoint| endpoint.action == "GetItem")
            .expect("GetItem endpoint");
        assert_eq!(item.controller, "ItemsController");
        assert_eq!(item.template, "api/Items/{id}");
        assert_eq!(item.verbs, vec![HttpVerb::Get]);
        assert_eq!(item.quality, FactQuality::ExactStatic);
        assert!(!item.is_verb_wildcard());
        assert_eq!(analysis.endpoints_for(HttpVerb::Get).len(), 1);
        assert_eq!(analysis.endpoints_for(HttpVerb::Post).len(), 1);
    }

    #[test]
    fn a_bare_verb_attribute_composes_the_declared_action_name() {
        let analysis = analyze("ItemsController.cs", SAMPLE);
        let create = analysis
            .endpoints
            .iter()
            .find(|endpoint| endpoint.action == "Create")
            .expect("Create endpoint");
        assert_eq!(create.template, "api/Items/Create");
        assert_eq!(create.verbs, vec![HttpVerb::Post]);
    }

    #[test]
    fn one_action_can_bind_two_verbs_and_a_route_attribute_is_an_explicit_wildcard() {
        let analysis = analyze("ItemsController.cs", SAMPLE);
        let rename = analysis
            .endpoints
            .iter()
            .find(|endpoint| endpoint.action == "Rename")
            .expect("Rename endpoint");
        assert_eq!(rename.template, "api/Items/rename/{id}");
        assert_eq!(rename.verbs, vec![HttpVerb::Put, HttpVerb::Patch]);
        let absolute = analysis
            .endpoints
            .iter()
            .find(|endpoint| endpoint.action == "Absolute")
            .expect("Absolute endpoint");
        assert!(absolute.is_verb_wildcard());
        assert_eq!(absolute.template, "api/Items/absolute");
    }

    #[test]
    fn a_dynamic_route_expression_is_unresolved_and_never_an_endpoint() {
        let analysis = analyze("ItemsController.cs", SAMPLE);
        assert!(!analysis
            .endpoints
            .iter()
            .any(|endpoint| endpoint.action == "Dynamic"));
        let refused = analysis
            .unresolved
            .iter()
            .find(|route| route.action.as_deref() == Some("Dynamic"))
            .expect("Dynamic refusal");
        assert_eq!(refused.reason, REASON_DYNAMIC_ROUTE);
        assert_eq!(refused.controller, "ItemsController");
        assert!(analysis.has_unresolved());
    }

    #[test]
    fn an_interpolated_verb_template_is_unresolved() {
        let analysis = analyze("ItemsController.cs", SAMPLE);
        assert!(!analysis
            .endpoints
            .iter()
            .any(|endpoint| endpoint.action == "Interpolated"));
        assert!(analysis
            .unresolved
            .iter()
            .any(|route| route.action.as_deref() == Some("Interpolated")
                && route.reason == REASON_DYNAMIC_ROUTE));
        assert!(analysis
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "aspnet-dynamic-route"));
    }

    #[test]
    fn plain_methods_and_actions_outside_a_controller_body_are_not_endpoints() {
        const LOOSE: &str = "public class Helper\n{\n    public void Run() { }\n}\n[HttpGet(\"x\")]\npublic void Free() { }\n";
        let analysis = analyze("Helper.cs", LOOSE);
        assert!(analysis.endpoints.is_empty());
        assert!(analysis.unresolved.is_empty());
    }

    #[test]
    fn analysis_is_deterministic() {
        let first = analyze("ItemsController.cs", SAMPLE);
        for _ in 0..3 {
            assert_eq!(analyze("ItemsController.cs", SAMPLE), first);
        }
        assert_eq!(first.endpoints.len(), 4);
    }
}
