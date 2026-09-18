//! Angular `HttpClient` literal requests (task B-059).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 2 names
//! `HttpClient.get/post/put/delete/patch` with a literal or allowlisted
//! constant service base and absolute routes as the supported `angular-http`
//! subset, and requires arbitrary template expressions, interceptors and
//! runtime environment values to be reported as unsupported.
//!
//! The adapter records the verb and the literal route, and it records whether a
//! route is absolute or relative. A relative route's base URL is a runtime
//! value, so it is exposed as such and never resolved to a server here; B-060
//! may join it only through an explicitly configured solution alias.

use crate::{Diagnostic, Span};

use super::dotnet_routes::HttpVerb;
use super::{
    first_literal_argument, lines_with_offsets, normalize_route, split_arguments,
    strip_line_comment, FactQuality,
};

/// Pattern id for a call with a plain literal route.
pub const PATTERN_LITERAL_ROUTE: &str = "angular-http-literal-route";
/// Pattern id for a call with an absolute literal URL.
pub const PATTERN_ABSOLUTE_URL: &str = "angular-http-absolute-url";
/// Pattern id for a call whose route is a template literal.
pub const PATTERN_TEMPLATE_LITERAL: &str = "angular-http-template-literal";
/// Pattern id for a call whose route is a computed expression.
pub const PATTERN_DYNAMIC_ROUTE: &str = "angular-http-dynamic-route";
/// Pattern id for a method call on something that is not an HTTP client.
pub const PATTERN_NON_CLIENT_RECEIVER: &str = "angular-http-non-client-receiver";
/// Pattern id for `request(` without a literal verb.
pub const PATTERN_REQUEST_VERB: &str = "angular-http-request-verb";

/// Reason recorded when a route is not a plain literal.
pub const REASON_DYNAMIC_ROUTE: &str = "unresolved-dynamic-route";
/// Reason recorded when a method call is not on an HTTP client.
pub const REASON_NON_CLIENT_RECEIVER: &str = "unresolved-not-an-http-client";
/// Reason recorded when a `request(` verb is not a literal.
pub const REASON_NON_LITERAL_VERB: &str = "unresolved-non-literal-verb";

/// One observed method call with a literal route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCall {
    /// The receiver text, for example `this.http`.
    pub client: String,
    /// The bound verb.
    pub method: HttpVerb,
    /// The literal route as written, normalised.
    pub route: String,
    /// The absolute URL when the literal route was absolute.
    pub absolute_url: Option<String>,
    /// Quality of the recorded route.
    pub quality: FactQuality,
    /// Span of the call.
    pub span: Span,
}

impl HttpCall {
    /// Whether the call needs a runtime base URL to become a concrete address.
    #[must_use]
    pub fn base_url_is_runtime(&self) -> bool {
        self.absolute_url.is_none()
    }
}

/// One observed call the adapter refused to analyse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedHttpCall {
    /// The receiver text.
    pub client: String,
    /// A `PATTERN_*` id naming what was not analysed.
    pub pattern: String,
    /// A `REASON_*` value explaining the refusal.
    pub reason: String,
    /// Span of the call.
    pub span: Span,
}

/// A declared base-URL binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseUrlBinding {
    /// The literal value, or `None` when the value is computed at runtime.
    pub value: Option<String>,
    /// Span of the declaration.
    pub span: Span,
}

/// Result of analysing one TypeScript file for Angular HTTP calls.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AngularHttpAnalysis {
    /// Literal calls, in source order.
    pub calls: Vec<HttpCall>,
    /// Refused calls, in source order.
    pub unresolved: Vec<UnresolvedHttpCall>,
    /// Base-URL declarations found in the file.
    pub declared_base_urls: Vec<BaseUrlBinding>,
    /// Diagnostics attached to the file.
    pub diagnostics: Vec<Diagnostic>,
}

impl AngularHttpAnalysis {
    /// Whether any call was refused instead of analysed.
    #[must_use]
    pub fn has_unresolved(&self) -> bool {
        !self.unresolved.is_empty()
    }

    /// Calls that bind `method`, in source order.
    #[must_use]
    pub fn calls_for(&self, method: HttpVerb) -> Vec<&HttpCall> {
        self.calls
            .iter()
            .filter(|call| call.method == method)
            .collect()
    }
}

/// The methods this adapter treats as HTTP calls on a client.
const METHODS: [&str; 8] = [
    "get", "post", "put", "delete", "patch", "head", "options", "request",
];

/// Analyse one TypeScript file for literal Angular HTTP calls.
#[must_use]
pub fn analyze(_file: &str, source: &str) -> AngularHttpAnalysis {
    let mut analysis = AngularHttpAnalysis::default();
    for (offset, raw_line) in lines_with_offsets(source) {
        let line = strip_line_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((value, span)) = base_url_binding(line, trimmed, offset) {
            analysis
                .declared_base_urls
                .push(BaseUrlBinding { value, span });
        }
        for method in METHODS {
            let Some((dot, args)) = find_method_call(trimmed, method) else {
                continue;
            };
            let span = Span::new(offset + dot, offset + dot + method.len() + args.len() + 2);
            let Some(client) = receiver_of(trimmed, dot) else {
                continue;
            };
            if !looks_like_http_client(&client) {
                analysis.unresolved.push(UnresolvedHttpCall {
                    client,
                    pattern: PATTERN_NON_CLIENT_RECEIVER.to_string(),
                    reason: REASON_NON_CLIENT_RECEIVER.to_string(),
                    span,
                });
                break;
            }
            let resolved = resolve_call(method, &args);
            match resolved {
                Ok((verb, route)) => {
                    let absolute = route.starts_with("http://") || route.starts_with("https://");
                    analysis.calls.push(HttpCall {
                        client,
                        method: verb,
                        route: normalize_route(&route),
                        absolute_url: absolute.then(|| normalize_route(&route)),
                        quality: FactQuality::ExactStatic,
                        span,
                    });
                }
                Err((pattern, reason)) => {
                    analysis.unresolved.push(UnresolvedHttpCall {
                        client,
                        pattern: pattern.to_string(),
                        reason: reason.to_string(),
                        span,
                    });
                    analysis
                        .diagnostics
                        .push(Diagnostic::warning(pattern, reason, span));
                }
            }
            break;
        }
    }
    analysis
}

fn resolve_call(
    method: &str,
    args: &str,
) -> Result<(HttpVerb, String), (&'static str, &'static str)> {
    if method == "request" {
        let arguments = split_arguments(args);
        let mut parts = arguments.iter();
        let verb_text = parts
            .next()
            .and_then(|value| super::parse_string_literal(value))
            .ok_or((PATTERN_REQUEST_VERB, REASON_NON_LITERAL_VERB))?;
        let verb =
            parse_method(&verb_text).ok_or((PATTERN_REQUEST_VERB, REASON_NON_LITERAL_VERB))?;
        let route = parts
            .next()
            .and_then(|value| super::parse_string_literal(value))
            .ok_or((PATTERN_DYNAMIC_ROUTE, REASON_DYNAMIC_ROUTE))?;
        return Ok((verb, route));
    }
    let verb = parse_method(method).ok_or((PATTERN_DYNAMIC_ROUTE, REASON_DYNAMIC_ROUTE))?;
    let arguments = split_arguments(args);
    let first = arguments.first().copied().unwrap_or_default();
    if first.starts_with('`') {
        return Err((PATTERN_TEMPLATE_LITERAL, REASON_DYNAMIC_ROUTE));
    }
    let route =
        super::parse_string_literal(first).ok_or((PATTERN_DYNAMIC_ROUTE, REASON_DYNAMIC_ROUTE))?;
    Ok((verb, route))
}

fn parse_method(text: &str) -> Option<HttpVerb> {
    let upper = text.to_uppercase();
    HttpVerb::all()
        .iter()
        .copied()
        .find(|verb| verb.as_str() == upper)
}

fn looks_like_http_client(receiver: &str) -> bool {
    let leaf = receiver
        .rsplit('.')
        .next()
        .unwrap_or(receiver)
        .to_lowercase();
    leaf.contains("http") || leaf.ends_with("client")
}

fn receiver_of(line: &str, dot: usize) -> Option<String> {
    let before = line.get(..dot)?.trim_end();
    if before.is_empty() {
        return None;
    }
    let start = before
        .char_indices()
        .rev()
        .find(|(_, c)| !(c.is_alphanumeric() || *c == '_' || *c == '.'))
        .map_or(0, |(index, c)| index + c.len_utf8());
    let name = before[start..].trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn base_url_binding(line: &str, trimmed: &str, offset: usize) -> Option<(Option<String>, Span)> {
    let at = trimmed.find("baseUrl")?;
    let rest = trimmed[at + "baseUrl".len()..].trim_start();
    let rest = rest.strip_prefix(':').or_else(|| rest.strip_prefix('='))?;
    let text = rest.trim().trim_end_matches(';').trim();
    let value = first_literal_argument(text);
    let start = offset + line.find("baseUrl")?;
    Some((value, Span::new(start, start + "baseUrl".len())))
}

/// Find `.<name>(` in one line; returns the `.` offset and the raw arguments.
fn find_method_call(line: &str, name: &str) -> Option<(usize, String)> {
    for (index, _) in line.match_indices(name) {
        if index == 0 || line.as_bytes()[index - 1] != b'.' {
            continue;
        }
        let mut open = index + name.len();
        if line.as_bytes().get(open) == Some(&b'<') {
            let mut depth = 0_i32;
            let mut end = None;
            for (step, byte) in line.as_bytes()[open..].iter().enumerate() {
                match byte {
                    b'<' => depth += 1,
                    b'>' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(open + step + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            open = end?;
        }
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
        analyze, PATTERN_DYNAMIC_ROUTE, PATTERN_NON_CLIENT_RECEIVER, PATTERN_TEMPLATE_LITERAL,
    };
    use crate::l3::dotnet_routes::HttpVerb;

    const SAMPLE: &str = r#"import { HttpClient } from '@angular/common/http';

@Injectable()
export class ItemsService {
  private readonly baseUrl = environment.apiUrl;

  constructor(private http: HttpClient) {}

  list() {
    return this.http.get<Item[]>('/api/items');
  }

  create(item: Item) {
    return this.http.post('/api/items', item);
  }

  remove(id: string) {
    return this.http.delete(`/api/items/${id}`);
  }

  absolute() {
    return this.http.get('https://cdn.example.com/health');
  }

  dynamic(id: string) {
    return this.http.get(this.urlFor(id));
  }

  custom() {
    return this.http.request('PUT', '/api/items/1', body);
  }

  notHttp() {
    return map.get('/x');
  }
}
"#;

    #[test]
    fn method_and_literal_route_evidence_are_recorded() {
        let analysis = analyze("items.service.ts", SAMPLE);
        let list = analysis
            .calls
            .iter()
            .find(|call| call.client == "this.http" && call.route == "api/items")
            .expect("list call");
        assert_eq!(list.method, HttpVerb::Get);
        assert_eq!(list.quality, crate::l3::FactQuality::ExactStatic);
        assert_eq!(analysis.calls_for(HttpVerb::Post).len(), 1);
        assert_eq!(analysis.calls.len(), 4);
    }

    #[test]
    fn an_absolute_literal_url_is_not_a_runtime_base_binding() {
        let analysis = analyze("items.service.ts", SAMPLE);
        let absolute = analysis
            .calls
            .iter()
            .find(|call| call.absolute_url.is_some())
            .expect("absolute call");
        assert!(!absolute.base_url_is_runtime());
        let relative = analysis
            .calls
            .iter()
            .find(|call| call.client == "this.http" && call.route == "api/items")
            .expect("relative call");
        assert!(relative.base_url_is_runtime());
    }

    #[test]
    fn a_literal_verb_and_route_are_read_from_a_request_call() {
        let analysis = analyze("items.service.ts", SAMPLE);
        let custom = analysis
            .calls
            .iter()
            .find(|call| call.method == HttpVerb::Put)
            .expect("request call");
        assert_eq!(custom.route, "api/items/1");
    }

    #[test]
    fn a_runtime_base_url_is_surfaced_and_never_resolved_to_a_server() {
        let analysis = analyze("items.service.ts", SAMPLE);
        assert_eq!(analysis.declared_base_urls.len(), 1);
        assert!(analysis.declared_base_urls[0].value.is_none());
    }

    #[test]
    fn a_literal_base_url_is_recorded_as_a_declared_binding() {
        const LITERAL: &str = "const baseUrl = '/api';\nthis.http.get('/items');\n";
        let analysis = analyze("x.ts", LITERAL);
        assert_eq!(
            analysis.declared_base_urls[0].value.as_deref(),
            Some("/api")
        );
    }

    #[test]
    fn a_template_literal_route_is_unresolved_and_never_a_call() {
        let analysis = analyze("items.service.ts", SAMPLE);
        assert!(!analysis.calls.iter().any(|call| call.route.contains("${")));
        assert!(analysis
            .unresolved
            .iter()
            .any(|call| call.pattern == PATTERN_TEMPLATE_LITERAL));
    }

    #[test]
    fn a_computed_route_is_unresolved() {
        let analysis = analyze("items.service.ts", SAMPLE);
        assert!(analysis
            .unresolved
            .iter()
            .any(|call| call.pattern == PATTERN_DYNAMIC_ROUTE));
    }

    #[test]
    fn a_method_call_on_a_non_client_is_not_an_http_call() {
        let analysis = analyze("items.service.ts", SAMPLE);
        assert!(!analysis.calls.iter().any(|call| call.route == "x"));
        assert!(analysis
            .unresolved
            .iter()
            .any(|call| call.pattern == PATTERN_NON_CLIENT_RECEIVER));
    }

    #[test]
    fn analysis_is_deterministic() {
        let first = analyze("items.service.ts", SAMPLE);
        for _ in 0..3 {
            assert_eq!(analyze("items.service.ts", SAMPLE), first);
        }
    }
}
