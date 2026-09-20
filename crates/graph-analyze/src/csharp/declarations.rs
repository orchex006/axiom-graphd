//! C# namespace, type, interface and method declarations with source spans.

use crate::identity::{declaration_key, unique_declaration_keys};
use crate::{line_span, line_starts, Coverage, Diagnostic, Severity, Span};

/// Diagnostic code for a declaration keyword with no name.
pub const CODE_MISSING_NAME: &str = "csharp-missing-name";
/// Diagnostic code for braces that do not balance.
pub const CODE_UNBALANCED_BRACES: &str = "csharp-unbalanced-braces";
/// Diagnostic code for a file with no namespace declaration.
pub const CODE_MISSING_NAMESPACE: &str = "csharp-missing-namespace";

/// The declaration kinds this scan recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CsharpDeclarationKind {
    /// `namespace X`.
    Namespace,
    /// `class X`.
    Class,
    /// `interface X`.
    Interface,
    /// `struct X`.
    Struct,
    /// `record X` / `record class X` / `record struct X`.
    Record,
    /// `enum X`.
    Enum,
    /// A method declaration.
    Method,
}

impl CsharpDeclarationKind {
    /// Stable spelling used in identity keys.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Namespace => "namespace",
            Self::Class => "class",
            Self::Interface => "interface",
            Self::Struct => "struct",
            Self::Record => "record",
            Self::Enum => "enum",
            Self::Method => "method",
        }
    }

    /// Whether this kind is a type-like declaration.
    #[must_use]
    pub const fn is_type(self) -> bool {
        matches!(
            self,
            Self::Class | Self::Interface | Self::Struct | Self::Record | Self::Enum
        )
    }
}

/// One C# declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsharpDeclaration {
    /// Declaration kind.
    pub kind: CsharpDeclarationKind,
    /// Declared name.
    pub name: String,
    /// Enclosing namespace and type names, outermost first.
    pub semantic_path: Vec<String>,
    /// Byte span of the declared name.
    pub span: Span,
    /// Stable identity key.
    pub key: String,
}

/// The result of scanning one C# source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsharpAnalysis {
    /// Declarations in source order.
    pub declarations: Vec<CsharpDeclaration>,
    /// Diagnostics in source order.
    pub diagnostics: Vec<Diagnostic>,
}

impl CsharpAnalysis {
    /// The first declaration of a given kind, in source order.
    #[must_use]
    pub fn first_of_kind(&self, kind: CsharpDeclarationKind) -> Option<&CsharpDeclaration> {
        self.declarations
            .iter()
            .find(|declaration| declaration.kind == kind)
    }

    /// Declarations of a given kind, in source order.
    #[must_use]
    pub fn of_kind(&self, kind: CsharpDeclarationKind) -> Vec<&CsharpDeclaration> {
        self.declarations
            .iter()
            .filter(|declaration| declaration.kind == kind)
            .collect()
    }

    /// Namespace declarations.
    #[must_use]
    pub fn namespaces(&self) -> Vec<&CsharpDeclaration> {
        self.of_kind(CsharpDeclarationKind::Namespace)
    }

    /// Method declarations.
    #[must_use]
    pub fn methods(&self) -> Vec<&CsharpDeclaration> {
        self.of_kind(CsharpDeclarationKind::Method)
    }

    /// Whether any diagnostic is an error.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
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

    /// Coverage for this file.
    ///
    /// A file with syntax errors is `partial`, never `complete_for_profile`.
    #[must_use]
    pub fn coverage(&self) -> Coverage {
        if self.has_errors() {
            return Coverage::partial(
                1,
                0,
                0,
                self.error_codes()
                    .iter()
                    .map(|c| (*c).to_string())
                    .collect(),
            );
        }
        Coverage::complete_for_profile(1, 0)
    }
}

/// Scan `source`, which came from `file`.
#[must_use]
pub fn analyze(file: &str, source: &str) -> CsharpAnalysis {
    let starts = line_starts(source);
    let lines: Vec<&str> = source.split_inclusive('\n').collect();
    let mut declarations = Vec::new();
    let mut diagnostics = Vec::new();
    let mut scopes: Vec<(i32, String)> = Vec::new();
    let mut pending: Option<CsharpDeclarationKind> = None;
    let mut depth: i32 = 0;
    let mut persistent: Vec<String> = Vec::new();

    for (index, raw_line) in lines.iter().enumerate() {
        let line_span = line_span(source, &starts, index);
        let line_start = line_span.start;
        let code = strip_line_comment(raw_line);
        let trimmed = code.trim();
        if trimmed.is_empty() {
            continue;
        }
        let opens = trimmed.matches('{').count() as i32;
        let closes = trimmed.matches('}').count() as i32;

        if trimmed.starts_with('{') {
            if let Some(kind) = pending.take() {
                scopes.push((depth, current_scope_name(&declarations, kind)));
            }
        } else {
            pending = None;
            let mut enclosing: Vec<String> = persistent.clone();
            enclosing.extend(scopes.iter().map(|(_, name)| name.clone()));

            if let Some(namespace) = namespace_name(trimmed) {
                let span = name_span(source, line_start, code, &namespace);
                declarations.push(CsharpDeclaration {
                    kind: CsharpDeclarationKind::Namespace,
                    name: namespace.clone(),
                    semantic_path: enclosing.clone(),
                    span,
                    key: declaration_key(file, "namespace", &path_refs(&enclosing, &namespace)),
                });
                // A file-scoped `namespace X;` governs the rest of the file, so
                // it is kept separately from the brace-scoped stack, which would
                // otherwise pop it on the very next line. A braceless
                // `namespace X` is completed by the following `{` line.
                scopes.clear();
                if trimmed.ends_with(';') {
                    persistent = vec![namespace.clone()];
                } else if opens > 0 {
                    scopes.push((depth, namespace));
                } else {
                    pending = Some(CsharpDeclarationKind::Namespace);
                }
            } else if let Some((kind, name)) = type_declaration(trimmed) {
                let span = name_span(source, line_start, code, &name);
                declarations.push(CsharpDeclaration {
                    kind,
                    name: name.clone(),
                    semantic_path: enclosing.clone(),
                    span,
                    key: declaration_key(file, kind.as_str(), &path_refs(&enclosing, &name)),
                });
                if opens == 0 {
                    pending = Some(kind);
                } else {
                    scopes.push((depth, name));
                }
            } else if let Some((keyword_index, _keyword)) = type_keyword_without_name(trimmed) {
                diagnostics.push(Diagnostic::error(
                    CODE_MISSING_NAME,
                    "a type declaration keyword has no name",
                    Span::new(line_start + keyword_index, line_span.end),
                ));
            } else if let Some(name) = method_name(trimmed) {
                let span = name_span_before(source, line_start, code, &name, Some('('));
                declarations.push(CsharpDeclaration {
                    kind: CsharpDeclarationKind::Method,
                    name: name.clone(),
                    semantic_path: enclosing.clone(),
                    span,
                    key: declaration_key(file, "method", &path_refs(&enclosing, &name)),
                });
            }
        }
        depth += opens - closes;
        while let Some((scope_depth, _)) = scopes.last() {
            if *scope_depth >= depth {
                scopes.pop();
            } else {
                break;
            }
        }
    }

    // Two declarations can legitimately share one semantic path inside a single
    // file: method overloads, a `namespace P { }` block repeated, a partial type
    // split across blocks, and constructor overloads (recorded as methods named
    // after their type). A repeated declaration key is not a usable identity -
    // the graph data contract rejects a file whose fact set repeats a node id -
    // so every member of a repeated group is rewritten with its occurrence
    // ordinal. Keys that do not repeat are left byte-identical to what
    // `declaration_key` produced, so a file with no repeated key is unaffected.
    let base_keys: Vec<String> = declarations
        .iter()
        .map(|declaration| declaration.key.clone())
        .collect();
    for (declaration, key) in declarations
        .iter_mut()
        .zip(unique_declaration_keys(&base_keys))
    {
        declaration.key = key;
    }
    if depth != 0 {
        let last = line_span(source, &starts, lines.len().saturating_sub(1));
        diagnostics.push(Diagnostic::error(
            CODE_UNBALANCED_BRACES,
            "the source has unbalanced braces",
            last,
        ));
    }
    if !declarations
        .iter()
        .any(|declaration| declaration.kind == CsharpDeclarationKind::Namespace)
    {
        diagnostics.push(Diagnostic::warning(
            CODE_MISSING_NAMESPACE,
            "the file declares no namespace; identities use the file scope",
            Span::new(0, 0),
        ));
    }

    CsharpAnalysis {
        declarations,
        diagnostics,
    }
}

/// The name recorded for a scope pushed before its name was known.
fn current_scope_name(declarations: &[CsharpDeclaration], kind: CsharpDeclarationKind) -> String {
    declarations
        .iter()
        .rev()
        .find(|declaration| declaration.kind == kind)
        .map_or_else(String::new, |declaration| declaration.name.clone())
}

fn path_refs<'a>(enclosing: &'a [String], name: &'a str) -> Vec<&'a str> {
    let mut parts: Vec<&str> = enclosing.iter().map(String::as_str).collect();
    parts.push(name);
    parts
}

/// `namespace X` / `file-scoped namespace X;`
fn namespace_name(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("namespace ")?;
    let name = rest
        .trim_end_matches('{')
        .trim_end_matches(';')
        .trim()
        .to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

const TYPE_KEYWORDS: &[&str] = &["class", "interface", "struct", "record", "enum"];

/// A type declaration, or a type keyword with no name.
fn type_declaration(trimmed: &str) -> Option<(CsharpDeclarationKind, String)> {
    let (_, keyword, name) = type_keyword_position(trimmed)?;
    let name = name?;
    let kind = match keyword {
        "class" => CsharpDeclarationKind::Class,
        "interface" => CsharpDeclarationKind::Interface,
        "struct" => CsharpDeclarationKind::Struct,
        "record" => CsharpDeclarationKind::Record,
        "enum" => CsharpDeclarationKind::Enum,
        _ => return None,
    };
    Some((kind, name))
}

/// A type keyword with no name, which is a syntax error rather than an
/// anonymous declaration.
fn type_keyword_without_name(trimmed: &str) -> Option<(usize, &'static str)> {
    let (index, keyword, name) = type_keyword_position(trimmed)?;
    if name.is_some() {
        return None;
    }
    Some((index, keyword))
}

/// Byte index, keyword and declared name of a type declaration.
///
/// A generic constraint such as `where T : class` also contains a type keyword;
/// those occurrences are skipped by rejecting a keyword whose prefix ends with a
/// colon, and by requiring an identifier before the keyword.
fn type_keyword_position(trimmed: &str) -> Option<(usize, &'static str, Option<String>)> {
    let bytes = trimmed.as_bytes();
    for keyword in TYPE_KEYWORDS {
        let mut search_from = 0;
        while let Some(relative) = trimmed[search_from..].find(keyword) {
            let at = search_from + relative;
            let before_ok = at > 0 && !is_identifier_byte(bytes[at - 1]);
            let after_index = at + keyword.len();
            let after_ok = bytes
                .get(after_index)
                .is_none_or(|byte| !is_identifier_byte(*byte));
            let constraint = trimmed[..at].trim_end().ends_with(':');
            if before_ok && after_ok && !constraint {
                let mut rest = trimmed[after_index..].trim_start();
                if *keyword == "record" {
                    for prefix in ["class", "struct"] {
                        if let Some(tail) = rest.strip_prefix(prefix) {
                            rest = tail.trim_start();
                        }
                    }
                }
                return Some((at, keyword, take_type_name(rest)));
            }
            search_from = after_index;
        }
    }
    None
}

/// The declared name at the start of `rest`, without generic parameters.
fn take_type_name(rest: &str) -> Option<String> {
    let mut name = String::new();
    for character in rest.chars() {
        if character.is_alphanumeric() || character == '_' || character == '.' {
            name.push(character);
        } else {
            break;
        }
    }
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

const CONTROL_KEYWORDS: &[&str] = &[
    "if", "for", "foreach", "while", "switch", "catch", "using", "lock", "return", "new", "throw",
    "do", "else", "case", "when", "yield", "await", "nameof", "typeof", "sizeof",
];

/// The declared method name, when the line is a method declaration.
fn method_name(trimmed: &str) -> Option<String> {
    let (before, _) = trimmed.split_once('(')?;
    if !trimmed.contains(')') {
        return None;
    }
    // Only the declaration part may not look like an assignment or a lambda: a
    // lambda in the body after the parameter list is irrelevant.
    if before.contains("=>") || before.contains('=') {
        return None;
    }
    let name = last_identifier(before)?;
    if CONTROL_KEYWORDS.contains(&name) {
        return None;
    }
    let tokens: Vec<&str> = before.split_whitespace().collect();
    if tokens.len() < 2 {
        return None;
    }
    if tokens
        .iter()
        .any(|token| token.ends_with(':') && *token != ":")
    {
        // A generic constraint or label, not a method.
        return None;
    }
    Some(name.to_string())
}

fn last_identifier(text: &str) -> Option<&str> {
    let mut start = None;
    let mut end = None;
    for (index, character) in text.char_indices().rev() {
        if character.is_alphanumeric() || character == '_' {
            start = Some(index);
            if end.is_none() {
                end = Some(index + character.len_utf8());
            }
        } else if end.is_some() {
            break;
        }
    }
    text.get(start?..end?)
}

/// Byte span of `name` inside the line that starts at `line_start`.
fn name_span(source: &str, line_start: usize, code: &str, name: &str) -> Span {
    name_span_before(source, line_start, code, name, None)
}

/// Byte span of `name`, preferring the occurrence followed by `terminator`.
fn name_span_before(
    source: &str,
    line_start: usize,
    code: &str,
    name: &str,
    terminator: Option<char>,
) -> Span {
    let offset = terminator
        .map(|terminator| format!("{name}{terminator}"))
        .and_then(|needle| code.find(&needle))
        .or_else(|| code.find(name))
        .unwrap_or(0);
    let start = line_start + offset;
    let end = start + name.len();
    Span::new(start.min(source.len()), end.min(source.len()))
}

fn strip_line_comment(line: &str) -> &str {
    line.split_once("//").map_or(line, |(code, _)| code)
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::{
        analyze, CsharpAnalysis, CsharpDeclaration, CsharpDeclarationKind, CODE_MISSING_NAME,
        CODE_MISSING_NAMESPACE, CODE_UNBALANCED_BRACES,
    };
    use crate::CoverageStatus;

    const SAMPLE: &str = "namespace App.Core\n{\n    public interface IThing\n    {\n        void Run();\n    }\n\n    public sealed class Thing : IThing\n    {\n        public int Count { get; set; }\n\n        public void Run()\n        {\n        }\n    }\n\n    public record Point(int X, int Y);\n\n    public struct Vec { }\n\n    public enum Color { Red }\n}\n";

    #[test]
    fn namespaces_types_interfaces_and_methods_carry_spans() {
        let analysis = analyze("src/app/Core.cs", SAMPLE);
        assert!(!analysis.has_errors(), "{:?}", analysis.diagnostics);

        let namespace = analysis.namespaces();
        assert_eq!(namespace.len(), 1);
        assert_eq!(namespace[0].name, "App.Core");
        assert_eq!(namespace[0].span.slice(SAMPLE), Some("App.Core"));

        let kinds: Vec<CsharpDeclarationKind> = analysis
            .declarations
            .iter()
            .filter(|declaration| declaration.kind.is_type())
            .map(|declaration| declaration.kind)
            .collect();
        assert_eq!(
            kinds,
            vec![
                CsharpDeclarationKind::Interface,
                CsharpDeclarationKind::Class,
                CsharpDeclarationKind::Record,
                CsharpDeclarationKind::Struct,
                CsharpDeclarationKind::Enum,
            ]
        );

        let interface = analysis
            .first_of_kind(CsharpDeclarationKind::Interface)
            .expect("interface");
        assert_eq!(interface.semantic_path, vec!["App.Core".to_string()]);
        assert_eq!(interface.span.slice(SAMPLE), Some("IThing"));

        let methods = analysis.methods();
        assert_eq!(methods.len(), 2);
        assert_eq!(methods[0].name, "Run");
        assert_eq!(
            methods[0].semantic_path,
            vec!["App.Core".to_string(), "IThing".to_string()]
        );
        assert_eq!(
            methods[1].semantic_path,
            vec!["App.Core".to_string(), "Thing".to_string()]
        );
        // The two `Run` methods must not share a key.
        assert_ne!(methods[0].key, methods[1].key);
        assert_eq!(methods[0].span.slice(SAMPLE), Some("Run"));
    }

    #[test]
    fn a_property_is_not_reported_as_a_method() {
        let analysis = analyze("src/app/Core.cs", SAMPLE);
        assert!(analysis
            .methods()
            .iter()
            .all(|method| method.name != "Count"));
    }

    #[test]
    fn malformed_type_declaration_and_unbalanced_braces_are_diagnostics() {
        let malformed = "namespace App\n{\n    public class { }\n";
        let analysis = analyze("src/app/Broken.cs", malformed);
        assert!(analysis.has_errors());
        let codes = analysis.error_codes();
        assert!(codes.contains(&CODE_MISSING_NAME), "{codes:?}");
        assert!(codes.contains(&CODE_UNBALANCED_BRACES), "{codes:?}");
        assert_eq!(analysis.coverage().status, CoverageStatus::Partial);
    }

    #[test]
    fn a_file_without_a_namespace_warns_and_still_records_types() {
        let analysis = analyze("src/app/Loose.cs", "public class Loose { }\n");
        assert!(!analysis.has_errors());
        assert!(analysis
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == CODE_MISSING_NAMESPACE));
        assert_eq!(analysis.of_kind(CsharpDeclarationKind::Class).len(), 1);
        assert_eq!(
            analysis.coverage().status,
            CoverageStatus::CompleteForProfile
        );
    }

    #[test]
    fn generic_constraints_and_lambdas_are_not_declarations() {
        let source = "namespace App\n{\n    public class Box<T> where T : class\n    {\n        public void Fill() { items.ForEach(x => x.Run()); }\n    }\n}\n";
        let analysis = analyze("src/app/Box.cs", source);
        let names: Vec<&str> = analysis
            .declarations
            .iter()
            .map(|declaration| declaration.name.as_str())
            .collect();
        assert_eq!(names, vec!["App", "Box", "Fill"]);
        assert!(!analysis.has_errors());
    }

    #[test]
    fn keys_are_stable_across_runs_and_change_with_the_file() {
        let first = analyze("src/app/Core.cs", SAMPLE);
        let second = analyze("src/app/Core.cs", SAMPLE);
        assert_eq!(first, second);
        let other = analyze("src/other/Core.cs", SAMPLE);
        assert_ne!(first.declarations[0].key, other.declarations[0].key);
    }

    #[test]
    fn a_fully_malformed_file_is_reported_not_silently_empty() {
        let analysis = analyze("src/app/Nothing.cs", "}}}\n");
        assert!(analysis.has_errors());
        assert!(analysis.declarations.is_empty());
    }

    /// H-007: no file may contribute a repeated node id. Every test below drives
    /// the declared-and-then-disambiguated keys through this check, because a
    /// file that still repeats a key is a failure, not a partial success.
    fn assert_every_declaration_key_is_unique(analysis: &CsharpAnalysis) {
        let mut keys: Vec<&str> = analysis
            .declarations
            .iter()
            .map(|declaration| declaration.key.as_str())
            .collect();
        let total = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(
            keys.len(),
            total,
            "a file must not contribute two declarations with one key: {:?}",
            analysis.declarations
        );
    }

    /// Overloads: two methods with one name and one signature position inside
    /// one type. The two declarations are distinct symbols that shared one base
    /// key before H-007, which made the whole file invalid input for the store.
    #[test]
    fn method_overloads_in_one_type_get_distinct_keys() {
        let source = "namespace Demo\n{\n    public class Calc\n    {\n        public int Get(int id)\n        {\n            return id;\n        }\n\n        public int Get(string key)\n        {\n            return key.Length;\n        }\n    }\n}\n";
        let analysis = analyze("src/app/Calc.cs", source);
        assert!(!analysis.has_errors(), "{:?}", analysis.diagnostics);
        assert_every_declaration_key_is_unique(&analysis);

        let overloads: Vec<&CsharpDeclaration> = analysis
            .methods()
            .into_iter()
            .filter(|method| method.name == "Get")
            .collect();
        assert_eq!(overloads.len(), 2, "both overloads are recorded");
        assert_eq!(
            overloads[0].semantic_path, overloads[1].semantic_path,
            "the ambiguity is real: the two declarations share one semantic path"
        );
        assert_ne!(overloads[0].key, overloads[1].key);
        assert_eq!(analysis, analyze("src/app/Calc.cs", source));
    }

    /// A brace-scoped `namespace P { }` block repeated in one file declares the
    /// same namespace twice, so both records share one base key.
    #[test]
    fn a_repeated_namespace_block_gets_distinct_keys() {
        let source =
            "namespace P\n{\n    public class First { }\n}\n\nnamespace P\n{\n    public class Second { }\n}\n";
        let analysis = analyze("src/app/P.cs", source);
        assert!(!analysis.has_errors(), "{:?}", analysis.diagnostics);
        assert_every_declaration_key_is_unique(&analysis);

        let namespaces = analysis.namespaces();
        assert_eq!(namespaces.len(), 2, "both namespace blocks are recorded");
        assert_eq!(namespaces[0].name, "P");
        assert_eq!(namespaces[1].name, "P");
        assert_ne!(namespaces[0].key, namespaces[1].key);
        assert_eq!(analysis, analyze("src/app/P.cs", source));
    }

    /// A partial type split across two blocks is one type written twice; the two
    /// declarations are distinct records on one semantic path, so they may not
    /// share a key. Members keep their own distinct keys.
    #[test]
    fn partial_type_split_across_two_blocks_gets_distinct_keys() {
        let source = "namespace App\n{\n    public partial class Widget\n    {\n        public void First()\n        {\n        }\n    }\n\n    public partial class Widget\n    {\n        public void Second()\n        {\n        }\n    }\n}\n";
        let analysis = analyze("src/app/Widget.cs", source);
        assert!(!analysis.has_errors(), "{:?}", analysis.diagnostics);
        assert_every_declaration_key_is_unique(&analysis);

        let widgets: Vec<&CsharpDeclaration> = analysis
            .of_kind(CsharpDeclarationKind::Class)
            .into_iter()
            .filter(|declaration| declaration.name == "Widget")
            .collect();
        assert_eq!(widgets.len(), 2);
        assert_ne!(widgets[0].key, widgets[1].key);
        assert_eq!(analysis, analyze("src/app/Widget.cs", source));
    }

    /// Constructor overloads are recorded as methods named after their type, so
    /// they take exactly the same path as method overloads.
    #[test]
    fn constructor_overloads_get_distinct_keys() {
        let source = "namespace App\n{\n    public class Service\n    {\n        public Service()\n        {\n        }\n\n        public Service(string name)\n        {\n            Name = name;\n        }\n\n        public string Name { get; }\n    }\n}\n";
        let analysis = analyze("src/app/Service.cs", source);
        assert!(!analysis.has_errors(), "{:?}", analysis.diagnostics);
        assert_every_declaration_key_is_unique(&analysis);

        let constructors: Vec<&CsharpDeclaration> = analysis
            .methods()
            .into_iter()
            .filter(|method| method.name == "Service")
            .collect();
        assert_eq!(constructors.len(), 2, "both constructors are recorded");
        assert_ne!(constructors[0].key, constructors[1].key);
        assert_eq!(analysis, analyze("src/app/Service.cs", source));
    }

    /// Control: a file with no repeated declaration must keep, byte for byte,
    /// the keys the pre-H-007 scheme produced. The expected digests below were
    /// taken from the pre-H-007 `declaration_key` (FNV-1a over
    /// `[version, file, kind, path...]`), so a change to the disambiguation that
    /// leaked into a non-colliding declaration fails here.
    #[test]
    fn a_file_without_a_repeated_declaration_keeps_its_exact_keys() {
        let analysis = analyze("src/app/Core.cs", SAMPLE);
        assert_every_declaration_key_is_unique(&analysis);
        let observed: Vec<(&str, &str, &str)> = analysis
            .declarations
            .iter()
            .map(|declaration| {
                (
                    declaration.kind.as_str(),
                    declaration.name.as_str(),
                    declaration.key.as_str(),
                )
            })
            .collect();
        assert_eq!(
            observed,
            vec![
                ("namespace", "App.Core", "10eb657f34b6e11b"),
                ("interface", "IThing", "681dfa2a9297ae60"),
                ("method", "Run", "b120f0621025d653"),
                ("class", "Thing", "8f840184faf90653"),
                ("method", "Run", "33a247d2519fa0d7"),
                ("record", "Point", "5ef51eb602ba0647"),
                ("struct", "Vec", "64a826b89c9148e9"),
                ("enum", "Color", "624700a527e3c444"),
            ]
        );
    }

    /// A repeated key is only disambiguated inside the file that repeats it: the
    /// same semantic path in another file keeps a key derived from that file.
    #[test]
    fn disambiguation_never_leaks_across_files() {
        let source = "namespace Demo\n{\n    public class Calc\n    {\n        public int Get(int id)\n        {\n            return id;\n        }\n\n        public int Get(string key)\n        {\n            return key.Length;\n        }\n    }\n}\n";
        let first = analyze("src/app/Calc.cs", source);
        let second = analyze("src/other/Calc.cs", source);
        for declaration in &first.declarations {
            assert!(
                !second
                    .declarations
                    .iter()
                    .any(|other| other.key == declaration.key),
                "keys must stay file-scoped: {} collided across files",
                declaration.key
            );
        }
    }
}
