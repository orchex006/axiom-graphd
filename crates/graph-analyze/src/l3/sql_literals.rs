//! Literal SQL access operations (task B-061).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 2 allows a coarse data-access
//! fact when the SQL text is a compile-time constant: the statement kind and,
//! when the text literally names one, the target object. Two things are
//! therefore never reported as analysed:
//!
//! * interpolated or concatenated SQL. `$"SELECT ... {id}"` and
//!   `"SELECT ... " + id` are computed at runtime, so the build records the
//!   statement as unresolved instead of guessing the executed text;
//! * a literal statement whose target this adapter cannot narrow, such as a
//!   derived table or a parameterised object name.
//!
//! The facts stay coarse on purpose: this is a hint about which objects a file
//! touches, not a SQL parser. No statement is ever executed.

use crate::{Diagnostic, Span};

use super::{
    lines_with_offsets, parse_string_literal, strip_line_comment, FactQuality,
    REASON_DYNAMIC_EXPRESSION, REASON_NOT_A_LITERAL,
};

/// Pattern id for a recognised literal statement.
pub const PATTERN_LITERAL_STATEMENT: &str = "sql-literal-statement";
/// Pattern id for a statement that cannot name its target object.
pub const PATTERN_UNNARROWED_OBJECT: &str = "sql-literal-unresolved-object";
/// Pattern id for interpolated or concatenated SQL.
pub const PATTERN_DYNAMIC_SQL: &str = "sql-dynamic-statement";
/// Pattern id for text that is not SQL at all.
pub const PATTERN_NOT_SQL: &str = "sql-not-a-statement";

/// Reason recorded when SQL text is assembled at runtime.
pub const REASON_DYNAMIC_SQL: &str = "unresolved-dynamic-sql";
/// Reason recorded when a literal statement does not let the adapter name one
/// target object.
pub const REASON_UNNARROWED_OBJECT: &str = "unresolved-unnarrowed-object";

/// The statement kind this adapter recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SqlOperation {
    /// `SELECT`.
    Select,
    /// `INSERT`.
    Insert,
    /// `UPDATE`.
    Update,
    /// `DELETE`.
    Delete,
    /// A stored procedure or `EXEC`/`EXECUTE` call.
    StoredProcedure,
}

impl SqlOperation {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::StoredProcedure => "stored_procedure",
        }
    }

    /// Every operation, in a stable order.
    #[must_use]
    pub const fn all() -> &'static [SqlOperation] {
        &[
            Self::Select,
            Self::Insert,
            Self::Update,
            Self::Delete,
            Self::StoredProcedure,
        ]
    }
}

/// One coarse data-access fact from literal SQL text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlAccess {
    /// Owning file.
    pub file: String,
    /// Statement kind.
    pub operation: SqlOperation,
    /// Literal target object, when the text names exactly one.
    pub object: Option<String>,
    /// Literal schema qualifier, when the text writes one.
    pub schema: Option<String>,
    /// Quality of the fact. A named object is `exact_static`; a statement with
    /// no single named object is `inferred_static`.
    pub quality: FactQuality,
    /// The literal statement, whitespace-collapsed and bounded.
    pub text: String,
    /// Span of the literal.
    pub span: Span,
}

impl SqlAccess {
    /// Fully qualified object name, when both parts are known.
    #[must_use]
    pub fn qualified_object(&self) -> Option<String> {
        match (&self.schema, &self.object) {
            (Some(schema), Some(object)) => Some(format!("{schema}.{object}")),
            (None, Some(object)) => Some(object.clone()),
            _ => None,
        }
    }
}

/// One fragment this adapter refused to analyse as a complete statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedSql {
    /// Owning file.
    pub file: String,
    /// A `PATTERN_*` id naming what was not analysed.
    pub pattern: String,
    /// A `REASON_*` value explaining the refusal.
    pub reason: String,
    /// The fragment, whitespace-collapsed and bounded.
    pub text: String,
    /// Span of the fragment.
    pub span: Span,
}

/// Result of scanning one source file for literal SQL.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SqlLiteralAnalysis {
    /// Coarse access facts, in source order.
    pub accesses: Vec<SqlAccess>,
    /// Refused fragments, in source order.
    pub unresolved: Vec<UnresolvedSql>,
    /// Diagnostics attached to the file.
    pub diagnostics: Vec<Diagnostic>,
}

impl SqlLiteralAnalysis {
    /// Whether any fragment was refused instead of analysed.
    #[must_use]
    pub fn has_unresolved(&self) -> bool {
        !self.unresolved.is_empty()
    }

    /// Facts for one operation, in source order.
    #[must_use]
    pub fn accesses_for(&self, operation: SqlOperation) -> Vec<&SqlAccess> {
        self.accesses
            .iter()
            .filter(|access| access.operation == operation)
            .collect()
    }
}

/// One quoted literal found in a line of source.
struct Literal {
    text: String,
    span: Span,
    interpolated: bool,
    concatenated: bool,
}

/// Extract every string literal in `line`, flagging interpolation and `+`
/// concatenation. A doubled quote inside a literal is an escape, not a break.
fn literals_in(line: &str, offset: usize) -> Vec<Literal> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut index = 0_usize;
    while index < bytes.len() {
        let byte = bytes[index];
        let (quote, interpolated, mut start) =
            if byte == b'$' && bytes.get(index + 1) == Some(&b'"') {
                (b'"', true, index)
            } else if byte == b'"' || byte == b'\'' {
                (byte, false, index)
            } else if byte == b'`' {
                (b'`', true, index)
            } else {
                index += 1;
                continue;
            };
        if byte == b'$' {
            index += 1;
        }
        let body_start = index + 1;
        let mut cursor = body_start;
        let mut interpolated = interpolated;
        while cursor < bytes.len() {
            if bytes[cursor] == b'\\' && quote != b'`' {
                cursor += 2;
                continue;
            }
            if bytes[cursor] == quote {
                if bytes.get(cursor + 1) == Some(&quote) && quote != b'`' {
                    cursor += 2;
                    continue;
                }
                break;
            }
            if bytes[cursor] == b'$' && bytes.get(cursor + 1) == Some(&b'{') && quote == b'`' {
                interpolated = true;
            }
            if bytes[cursor] == b'{'
                && bytes.get(cursor.wrapping_sub(1)) == Some(&b'{')
                && quote == b'"'
                && line[..cursor].ends_with("$\"")
            {
                interpolated = true;
            }
            cursor += 1;
        }
        if cursor >= bytes.len() {
            break;
        }
        let raw = &line[start..=cursor];
        let text = if quote == b'"' || quote == b'\'' {
            parse_string_literal(raw).unwrap_or_else(|| strip_delimiters(raw))
        } else {
            strip_delimiters(raw)
        };
        let before = line[..start].trim_end();
        let after = line[cursor + 1..].trim_start();
        let concatenated = before.ends_with('+') || after.starts_with('+');
        start += offset;
        out.push(Literal {
            text,
            span: Span::new(start, start + (cursor + 1 - (start - offset))),
            interpolated,
            concatenated,
        });
        index = cursor + 1;
    }
    out
}

/// Collapse whitespace and bound the recorded text.
fn collapse(text: &str) -> String {
    let joined = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.len() <= 400 {
        joined
    } else {
        let mut truncated: String = joined.chars().take(400).collect();
        truncated.push_str("...");
        truncated
    }
}

/// Unquote and split a possibly schema-qualified object name.
fn object_name(token: &str) -> (Option<String>, Option<String>) {
    let parts: Vec<String> = token
        .trim()
        .trim_end_matches(';')
        .split('.')
        .map(|part| {
            part.trim()
                .trim_matches(|ch| matches!(ch, '[' | ']' | '"' | '`'))
                .to_string()
        })
        .filter(|part| !part.is_empty())
        .collect();
    let is_identifier = |part: &str| {
        !part.is_empty()
            && part
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' || ch == '#')
            && part.chars().next().is_some_and(|ch| !ch.is_ascii_digit())
    };
    match parts.as_slice() {
        [object] if is_identifier(object) => (None, Some(object.clone())),
        [schema, object] if is_identifier(schema) && is_identifier(object) => {
            (Some(schema.clone()), Some(object.clone()))
        }
        _ => (None, None),
    }
}

/// Strip a literal's delimiters when it could not be parsed as exactly one
/// plain string, so an interpolated `$"..."` still yields its SQL head.
fn strip_delimiters(raw: &str) -> String {
    let mut text = raw.trim();
    if let Some(rest) = text.strip_prefix('$') {
        text = rest;
    }
    text.trim_matches(|ch| matches!(ch, '"' | '\'' | '`'))
        .to_string()
}

/// Classify one literal as SQL and derive its coarse operation.
fn classify(text: &str) -> Option<(SqlOperation, Option<String>, Option<String>, bool)> {
    let upper = text.trim().to_ascii_uppercase();
    let tokens: Vec<&str> = upper.split_whitespace().collect();
    let head = *tokens.first()?;
    // `head` borrows `upper`, but the object token must come from the original
    // text so that case and quoting are preserved.
    let original: Vec<&str> = text.split_whitespace().collect();
    let operation = match head {
        "SELECT" => SqlOperation::Select,
        "INSERT" => SqlOperation::Insert,
        "UPDATE" => SqlOperation::Update,
        "DELETE" => SqlOperation::Delete,
        "EXEC" | "EXECUTE" => SqlOperation::StoredProcedure,
        _ => return None,
    };
    let marker = match operation {
        SqlOperation::Select => "FROM",
        SqlOperation::Insert => "INTO",
        SqlOperation::Update => "",
        SqlOperation::Delete => "FROM",
        SqlOperation::StoredProcedure => "",
    };
    let mut narrowed = true;
    let object_token = if marker.is_empty() {
        original.get(1).copied()
    } else {
        match tokens.iter().position(|token| *token == marker) {
            Some(index) => original.get(index + 1).copied(),
            None => None,
        }
    };
    let (schema, object) = match object_token {
        Some(token) => {
            if token.contains('(') || token.starts_with('@') || token.starts_with('$') {
                narrowed = false;
                (None, None)
            } else {
                let (schema, object) = object_name(token);
                if object.is_none() {
                    narrowed = false;
                }
                (schema, object)
            }
        }
        None => {
            narrowed = false;
            (None, None)
        }
    };
    Some((operation, schema, object, narrowed))
}

/// Scan one source file for literal SQL access operations.
#[must_use]
pub fn analyze(file: &str, source: &str) -> SqlLiteralAnalysis {
    let mut analysis = SqlLiteralAnalysis::default();
    for (offset, raw_line) in lines_with_offsets(source) {
        let line = strip_line_comment(raw_line);
        if line.trim().is_empty() {
            continue;
        }
        for literal in literals_in(line, offset) {
            let Some((operation, schema, object, narrowed)) = classify(&literal.text) else {
                continue;
            };
            if literal.interpolated || literal.concatenated {
                analysis.unresolved.push(UnresolvedSql {
                    file: file.to_string(),
                    pattern: PATTERN_DYNAMIC_SQL.to_string(),
                    reason: REASON_DYNAMIC_SQL.to_string(),
                    text: collapse(&literal.text),
                    span: literal.span,
                });
                continue;
            }
            if !narrowed {
                analysis.unresolved.push(UnresolvedSql {
                    file: file.to_string(),
                    pattern: PATTERN_UNNARROWED_OBJECT.to_string(),
                    reason: REASON_UNNARROWED_OBJECT.to_string(),
                    text: collapse(&literal.text),
                    span: literal.span,
                });
                continue;
            }
            analysis.accesses.push(SqlAccess {
                file: file.to_string(),
                operation,
                object,
                schema,
                quality: FactQuality::ExactStatic,
                text: collapse(&literal.text),
                span: literal.span,
            });
        }
    }
    analysis
}

/// Whether a fragment is a literal this adapter could not read as one string.
#[must_use]
pub fn refuse_non_literal(file: &str, fragment: &str, span: Span) -> UnresolvedSql {
    UnresolvedSql {
        file: file.to_string(),
        pattern: PATTERN_NOT_SQL.to_string(),
        reason: if parse_string_literal(fragment).is_none() {
            REASON_NOT_A_LITERAL.to_string()
        } else {
            REASON_DYNAMIC_EXPRESSION.to_string()
        },
        text: collapse(fragment),
        span,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        analyze, SqlOperation, PATTERN_DYNAMIC_SQL, PATTERN_UNNARROWED_OBJECT, REASON_DYNAMIC_SQL,
        REASON_UNNARROWED_OBJECT,
    };

    #[test]
    fn supported_literal_statements_yield_coarse_facts() {
        let source = r#"
            var a = "SELECT Id, Name FROM [dbo].[Customers] WHERE Id = 1";
            var b = "INSERT INTO Orders (Id) VALUES (1)";
            var c = "UPDATE Orders SET Total = 0 WHERE Id = 1";
            var d = "DELETE FROM Orders WHERE Id = 1";
            var e = "EXEC dbo.GetOrderTotals";
        "#;
        let analysis = analyze("Data/Repo.cs", source);
        assert_eq!(analysis.accesses.len(), 5);
        let select = &analysis.accesses_for(SqlOperation::Select)[0];
        assert_eq!(select.schema.as_deref(), Some("dbo"));
        assert_eq!(select.object.as_deref(), Some("Customers"));
        assert_eq!(select.qualified_object().as_deref(), Some("dbo.Customers"));
        assert_eq!(
            analysis.accesses_for(SqlOperation::Insert)[0]
                .object
                .as_deref(),
            Some("Orders")
        );
        assert_eq!(
            analysis.accesses_for(SqlOperation::Update)[0]
                .object
                .as_deref(),
            Some("Orders")
        );
        assert_eq!(
            analysis.accesses_for(SqlOperation::Delete)[0]
                .object
                .as_deref(),
            Some("Orders")
        );
        assert_eq!(
            analysis.accesses_for(SqlOperation::StoredProcedure)[0]
                .qualified_object()
                .as_deref(),
            Some("dbo.GetOrderTotals")
        );
        assert!(!analysis.has_unresolved());
    }

    #[test]
    fn dynamic_sql_is_never_labelled_fully_analysed() {
        let source = "var q = $\"SELECT * FROM Orders WHERE Id = {id}\";";
        let analysis = analyze("Repo.cs", source);
        assert!(analysis.accesses.is_empty());
        assert_eq!(analysis.unresolved.len(), 1);
        assert_eq!(analysis.unresolved[0].pattern, PATTERN_DYNAMIC_SQL);
        assert_eq!(analysis.unresolved[0].reason, REASON_DYNAMIC_SQL);
        assert!(analysis.has_unresolved());
    }

    #[test]
    fn concatenated_sql_is_unresolved_boundary_case() {
        let source = "var q = \"SELECT * FROM \" + table + \" WHERE Id = 1\";";
        let analysis = analyze("Repo.cs", source);
        assert!(analysis.accesses.is_empty());
        assert!(analysis
            .unresolved
            .iter()
            .all(|entry| entry.reason == REASON_DYNAMIC_SQL));
    }

    #[test]
    fn a_derived_table_object_is_reported_rather_than_guessed() {
        let source = "var q = \"SELECT * FROM (SELECT Id FROM Orders) t\";";
        let analysis = analyze("Repo.cs", source);
        assert!(analysis.accesses.is_empty());
        assert_eq!(analysis.unresolved.len(), 1);
        assert_eq!(analysis.unresolved[0].pattern, PATTERN_UNNARROWED_OBJECT);
        assert_eq!(analysis.unresolved[0].reason, REASON_UNNARROWED_OBJECT);
    }

    #[test]
    fn non_sql_literals_are_ignored_entirely() {
        let source = r#"
            var greeting = "hello world";
            var path = "/api/items";
        "#;
        let analysis = analyze("Repo.cs", source);
        assert!(analysis.accesses.is_empty());
        assert!(analysis.unresolved.is_empty());
    }

    #[test]
    fn stored_procedure_with_a_variable_name_is_unresolved() {
        let source = "var q = \"EXEC @procName\";";
        let analysis = analyze("Repo.cs", source);
        assert!(analysis.accesses.is_empty());
        assert_eq!(analysis.unresolved.len(), 1);
        assert_eq!(analysis.unresolved[0].reason, REASON_UNNARROWED_OBJECT);
    }
}
