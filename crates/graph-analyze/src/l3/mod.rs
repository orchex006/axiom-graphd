//! Level-3 static adapters (tasks B-057 - B-066).
//!
//! Level 1 is the language registry and level 2 is syntax extraction; this
//! module tree holds the level-3 adapters that turn bounded literal syntax into
//! candidate architecture relations. Every adapter follows the same rule from
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 2: a versioned pattern
//! registry with explicit positive and negative cases, and an explicit report
//! for every pattern the build cannot analyse. Nothing here executes user
//! source, and nothing here guesses a target the source does not literally
//! name.

pub mod angular_http;
pub mod annotations;
pub mod dotnet_routes;
pub mod ef_mapping;
pub mod http_join;
pub mod manifests;
pub mod messaging;
pub mod minimal_api;
pub mod report;
pub mod sql_literals;

/// How strongly a fact is supported by the analysed source.
///
/// The spellings match `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactQuality {
    /// A literal fact that resolves uniquely.
    ExactStatic,
    /// A candidate set the source does not narrow to one target.
    InferredStatic,
    /// The source does not let this build decide.
    Unresolved,
}

impl FactQuality {
    /// Stable spelling used in coverage and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactStatic => "exact_static",
            Self::InferredStatic => "inferred_static",
            Self::Unresolved => "unresolved",
        }
    }

    /// Whether the fact may be published as a proven relation.
    #[must_use]
    pub const fn is_proven(self) -> bool {
        matches!(self, Self::ExactStatic)
    }
}

/// Reason recorded when a fragment is a computed expression, not a literal.
pub const REASON_DYNAMIC_EXPRESSION: &str = "unresolved-dynamic-expression";
/// Reason recorded when a fragment is not exactly one string literal.
pub const REASON_NOT_A_LITERAL: &str = "unresolved-not-a-literal";

/// Unquote one string-literal fragment.
///
/// `fragment` must be exactly one quoted literal with nothing around it. A
/// prefix such as C# `$"..."` or a TypeScript template literal returns `None`,
/// which is how a computed or interpolated value is refused instead of guessed.
#[must_use]
pub fn parse_string_literal(fragment: &str) -> Option<String> {
    let text = fragment.trim();
    let quote = text.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    if text.len() < 2 || !text.ends_with(quote) {
        return None;
    }
    let inner = &text[1..text.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut escaped = false;
    for ch in inner.chars() {
        if escaped {
            match ch {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                other => out.push(other),
            }
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == quote {
            // An unescaped quote inside the body means this was not one literal.
            return None;
        } else {
            out.push(ch);
        }
    }
    if escaped {
        return None;
    }
    Some(out)
}

/// Split a parenthesised argument list at top-level commas.
#[must_use]
pub fn split_arguments(arguments: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0_i32;
    let mut start = 0_usize;
    let mut in_string: Option<char> = None;
    let mut escaped = false;
    for (index, ch) in arguments.char_indices() {
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
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                out.push(arguments[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    let tail = arguments[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

/// The first argument that is exactly one string literal.
#[must_use]
pub fn first_literal_argument(arguments: &str) -> Option<String> {
    split_arguments(arguments)
        .into_iter()
        .find_map(parse_string_literal)
}

/// Every line of `source` with its byte offset, without the line terminator.
#[must_use]
pub fn lines_with_offsets(source: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut offset = 0_usize;
    for line in source.split('\n') {
        out.push((offset, line.strip_suffix('\r').unwrap_or(line)));
        offset += line.len() + 1;
    }
    out
}

/// The code part of a line, with a trailing `//` comment removed.
#[must_use]
pub fn strip_line_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string: Option<u8> = None;
    let mut escaped = false;
    let mut index = 0_usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(quote) = in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == quote {
                in_string = None;
            }
        } else if byte == b'"' || byte == b'\'' {
            in_string = Some(byte);
        } else if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            return &line[..index];
        }
        index += 1;
    }
    line
}

/// Collapse repeated separators and drop leading/trailing separators.
///
/// Route templates are compared and published in this normal form so that
/// `api//items/` and `api/items` are the same declared route.
#[must_use]
pub fn normalize_route(template: &str) -> String {
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

/// Byte span of the first `needle` at or after `from`.
#[must_use]
pub fn find_from(source: &str, needle: &str, from: usize) -> crate::Span {
    let Some(hay) = source.get(from..) else {
        return crate::Span::new(source.len(), source.len());
    };
    match hay.find(needle) {
        Some(offset) if !needle.is_empty() => {
            let start = from + offset;
            crate::Span::new(start, start + needle.len())
        }
        Some(_) => crate::Span::new(from, from),
        None => crate::Span::new(source.len(), source.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::{first_literal_argument, parse_string_literal, split_arguments};

    #[test]
    fn a_string_literal_is_unquoted_and_never_partially_matched() {
        assert_eq!(
            parse_string_literal("\"api/items\""),
            Some("api/items".to_string())
        );
        assert_eq!(parse_string_literal("'x'"), Some("x".to_string()));
        assert_eq!(parse_string_literal("\"\""), Some(String::new()));
        assert_eq!(parse_string_literal("$\"/items/{id}\""), None);
        assert_eq!(parse_string_literal("prefix + \"/x\""), None);
        assert_eq!(parse_string_literal("\"unterminated"), None);
        assert_eq!(parse_string_literal("\"a\"b\""), None);
    }

    #[test]
    fn arguments_split_only_at_top_level_commas() {
        assert_eq!(
            split_arguments("\"a\", Name = \"b\", new[] { 1, 2 }"),
            vec!["\"a\"", "Name = \"b\"", "new[] { 1, 2 }"]
        );
        assert!(split_arguments("").is_empty());
        assert_eq!(
            first_literal_argument("\"a\", Name = \"b\""),
            Some("a".to_string())
        );
        assert_eq!(first_literal_argument("Name = \"b\""), None);
    }
}
