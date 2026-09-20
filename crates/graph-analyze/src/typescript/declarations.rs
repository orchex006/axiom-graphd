//! TypeScript class, function, interface, type and member declarations.

use crate::identity::{anonymous_key, declaration_key, unique_declaration_keys};
use crate::{line_span, line_starts, Coverage, Diagnostic, Severity, Span};

/// Diagnostic code for braces that do not balance.
pub const CODE_UNBALANCED_BRACES: &str = "typescript-unbalanced-braces";

/// The declaration kinds this scan recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TsDeclarationKind {
    /// `class X`.
    Class,
    /// `function f`.
    Function,
    /// `interface I`.
    Interface,
    /// `type T = ...`.
    TypeAlias,
    /// `const`/`let`/`var` binding.
    Variable,
    /// `namespace X`.
    Namespace,
    /// `export default ...`.
    DefaultExport,
}

impl TsDeclarationKind {
    /// Stable spelling used in identity keys.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Function => "function",
            Self::Interface => "interface",
            Self::TypeAlias => "type-alias",
            Self::Variable => "variable",
            Self::Namespace => "namespace",
            Self::DefaultExport => "default-export",
        }
    }
}

/// How much syntactic identity a declaration actually has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentityQuality {
    /// The declaration has an explicit name; the name is part of the key.
    Explicit,
    /// The declaration is anonymous; the key is positional and stable, but no
    /// name was invented for it.
    Anonymous,
    /// The name is computed or destructured at runtime and is not a static
    /// identity.
    Computed,
}

impl IdentityQuality {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Anonymous => "anonymous",
            Self::Computed => "computed",
        }
    }
}

/// One TypeScript declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsDeclaration {
    /// Declaration kind.
    pub kind: TsDeclarationKind,
    /// The explicit name, when the syntax has one.
    pub name: Option<String>,
    /// How much identity the declaration has.
    pub quality: IdentityQuality,
    /// Enclosing namespace and class names, outermost first.
    pub semantic_path: Vec<String>,
    /// Byte span of the name, or of the declaration keyword when anonymous.
    pub span: Span,
    /// Stable identity key.
    pub key: String,
}

/// The result of scanning one TypeScript source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsAnalysis {
    /// Declarations in source order.
    pub declarations: Vec<TsDeclaration>,
    /// Diagnostics in source order.
    pub diagnostics: Vec<Diagnostic>,
}

impl TsAnalysis {
    /// The first declaration of a given kind, in source order.
    #[must_use]
    pub fn first_of_kind(&self, kind: TsDeclarationKind) -> Option<&TsDeclaration> {
        self.declarations
            .iter()
            .find(|declaration| declaration.kind == kind)
    }

    /// Declarations of a given kind, in source order.
    #[must_use]
    pub fn of_kind(&self, kind: TsDeclarationKind) -> Vec<&TsDeclaration> {
        self.declarations
            .iter()
            .filter(|declaration| declaration.kind == kind)
            .collect()
    }

    /// Declarations without an explicit name.
    #[must_use]
    pub fn not_explicit(&self) -> Vec<&TsDeclaration> {
        self.declarations
            .iter()
            .filter(|declaration| declaration.quality != IdentityQuality::Explicit)
            .collect()
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

    /// Coverage for this file; a file with syntax errors is `partial`.
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
pub fn analyze(file: &str, source: &str) -> TsAnalysis {
    let starts = line_starts(source);
    let lines: Vec<&str> = source.split_inclusive('\n').collect();
    let mut declarations = Vec::new();
    let mut diagnostics = Vec::new();
    let mut scopes: Vec<(i32, String)> = Vec::new();
    let mut depth: i32 = 0;
    let mut anonymous_ordinal: usize = 0;

    for (index, raw_line) in lines.iter().enumerate() {
        let span = line_span(source, &starts, index);
        let line_start = span.start;
        let code = strip_line_comment(raw_line);
        let trimmed = code.trim();
        if trimmed.is_empty() {
            continue;
        }
        let opens = trimmed.matches('{').count() as i32;
        let closes = trimmed.matches('}').count() as i32;
        let mut enclosing: Vec<String> = scopes.iter().map(|(_, name)| name.clone()).collect();

        if let Some(declaration) = classify(trimmed) {
            let name_span = match &declaration.name {
                Some(name) => name_span_before(source, line_start, code, name, Some('(')),
                None => Span::new(line_start, line_start + trimmed.len()),
            };
            let key = match declaration.quality {
                IdentityQuality::Explicit => declaration_key(
                    file,
                    declaration.kind.as_str(),
                    &path_refs(&enclosing, declaration.name.as_deref().unwrap_or_default()),
                ),
                IdentityQuality::Anonymous => {
                    anonymous_ordinal += 1;
                    anonymous_key(file, declaration.kind.as_str(), anonymous_ordinal)
                }
                IdentityQuality::Computed => {
                    anonymous_ordinal += 1;
                    let ordinal = anonymous_ordinal.to_string();
                    declaration_key(
                        file,
                        declaration.kind.as_str(),
                        &["<computed>", ordinal.as_str()],
                    )
                }
            };
            if opens > 0 {
                scopes.push((depth, declaration.name.clone().unwrap_or_default()));
            }
            declarations.push(TsDeclaration {
                kind: declaration.kind,
                name: declaration.name,
                quality: declaration.quality,
                semantic_path: std::mem::take(&mut enclosing),
                span: name_span,
                key,
            });
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

    // TypeScript has the same repeated-path class as C#: overloaded function
    // declarations, an interface merged across two blocks, a repeated namespace
    // block and a class or namespace declared twice all produce two
    // declarations on one semantic path. A repeated key is not a usable
    // identity - the graph data contract rejects a file whose fact set repeats
    // a node id - so every member of a repeated group is rewritten with its
    // occurrence ordinal. Non-repeated keys, including the anonymous and
    // computed keys that already carry an ordinal, are left untouched.
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

    TsAnalysis {
        declarations,
        diagnostics,
    }
}

/// A classified declaration before its key is computed.
struct Classified {
    kind: TsDeclarationKind,
    name: Option<String>,
    quality: IdentityQuality,
}

fn classify(trimmed: &str) -> Option<Classified> {
    let body = trimmed
        .strip_prefix("export ")
        .unwrap_or(trimmed)
        .trim_start();
    if let Some(rest) = body.strip_prefix("default ") {
        return Some(default_export(rest));
    }
    let body = body.strip_prefix("abstract ").unwrap_or(body);
    for (keyword, kind) in [
        ("class ", TsDeclarationKind::Class),
        ("interface ", TsDeclarationKind::Interface),
        ("namespace ", TsDeclarationKind::Namespace),
        ("type ", TsDeclarationKind::TypeAlias),
    ] {
        // `class {` and a bare `class` are anonymous declarations with no name
        // to key on; they are quality `anonymous`, never a fabricated name.
        let bare = keyword.trim_end();
        let rest = body.strip_prefix(keyword).or_else(|| {
            body.strip_prefix(bare).filter(|rest| {
                let rest = rest.trim_start();
                rest.starts_with('{') || rest.is_empty()
            })
        });
        if let Some(rest) = rest {
            let name = take_identifier(rest);
            return Some(Classified {
                kind,
                quality: if name.is_some() {
                    IdentityQuality::Explicit
                } else {
                    IdentityQuality::Anonymous
                },
                name,
            });
        }
    }
    let function_body = body
        .strip_prefix("async ")
        .unwrap_or(body)
        .strip_prefix("function ")
        .or_else(|| body.strip_prefix("function "));
    if let Some(rest) = function_body {
        let name = take_identifier(rest);
        return Some(Classified {
            kind: TsDeclarationKind::Function,
            quality: if name.is_some() {
                IdentityQuality::Explicit
            } else {
                IdentityQuality::Anonymous
            },
            name,
        });
    }
    for keyword in ["const ", "let ", "var "] {
        if let Some(rest) = body.strip_prefix(keyword) {
            let computed = rest.starts_with('{') || rest.starts_with('[');
            return Some(Classified {
                kind: TsDeclarationKind::Variable,
                quality: if computed {
                    IdentityQuality::Computed
                } else if take_identifier(rest).is_some() {
                    IdentityQuality::Explicit
                } else {
                    IdentityQuality::Computed
                },
                name: if computed {
                    None
                } else {
                    take_identifier(rest)
                },
            });
        }
    }
    None
}

fn default_export(rest: &str) -> Classified {
    let inner = rest.strip_prefix("abstract ").unwrap_or(rest);
    for keyword in [
        "class ",
        "function ",
        "async function ",
        "interface ",
        "enum ",
    ] {
        if let Some(tail) = inner.strip_prefix(keyword) {
            let name = take_identifier(tail);
            return Classified {
                kind: TsDeclarationKind::DefaultExport,
                quality: if name.is_some() {
                    IdentityQuality::Explicit
                } else {
                    IdentityQuality::Anonymous
                },
                name,
            };
        }
    }
    Classified {
        kind: TsDeclarationKind::DefaultExport,
        quality: IdentityQuality::Anonymous,
        name: None,
    }
}

fn take_identifier(text: &str) -> Option<String> {
    let mut name = String::new();
    for character in text.chars() {
        if character.is_alphanumeric() || character == '_' || character == '$' {
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

fn path_refs<'a>(enclosing: &'a [String], name: &'a str) -> Vec<&'a str> {
    let mut parts: Vec<&str> = enclosing.iter().map(String::as_str).collect();
    parts.push(name);
    parts
}

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

#[cfg(test)]
mod tests {
    use super::{analyze, IdentityQuality, TsAnalysis, TsDeclarationKind, CODE_UNBALANCED_BRACES};
    use crate::CoverageStatus;

    const SAMPLE: &str = "export interface Widget {\n  run(): void;\n}\n\nexport type Id = string;\n\nexport class Panel implements Widget {\n  run(): void {}\n}\n\nexport async function build(name: string): Promise<Panel> {\n  return new Panel();\n}\n\nconst counter = 0;\n";

    #[test]
    fn classes_functions_and_exported_members_get_explicit_stable_keys() {
        let analysis = analyze("src/panel.ts", SAMPLE);
        assert!(!analysis.has_errors(), "{:?}", analysis.diagnostics);
        let names: Vec<&str> = analysis
            .declarations
            .iter()
            .filter_map(|declaration| declaration.name.as_deref())
            .collect();
        assert_eq!(names, vec!["Widget", "Id", "Panel", "build", "counter"]);
        for declaration in &analysis.declarations {
            assert_eq!(declaration.quality, IdentityQuality::Explicit);
        }
        let panel = analysis
            .first_of_kind(TsDeclarationKind::Class)
            .expect("class");
        assert_eq!(panel.span.slice(SAMPLE), Some("Panel"));
        assert_eq!(
            analysis.coverage().status,
            CoverageStatus::CompleteForProfile
        );

        let again = analyze("src/panel.ts", SAMPLE);
        assert_eq!(analysis, again);
        let other_file = analyze("src/other.ts", SAMPLE);
        assert_ne!(analysis.declarations[0].key, other_file.declarations[0].key);
    }

    #[test]
    fn an_anonymous_default_export_has_explicit_identity_quality() {
        let source = "export default class {\n  run() {}\n}\n";
        let analysis = analyze("src/index.ts", source);
        let declaration = analysis
            .first_of_kind(TsDeclarationKind::DefaultExport)
            .expect("default export");
        assert_eq!(declaration.quality, IdentityQuality::Anonymous);
        assert_eq!(declaration.quality.as_str(), "anonymous");
        assert_eq!(declaration.name, None);
        assert!(!declaration.key.is_empty());
        // Stability: the same anonymous declaration keeps the same positional key.
        assert_eq!(analysis, analyze("src/index.ts", source));
    }

    #[test]
    fn an_anonymous_default_value_is_never_given_a_name() {
        let analysis = analyze("src/index.ts", "export default 42;\n");
        let declaration = analysis
            .first_of_kind(TsDeclarationKind::DefaultExport)
            .expect("default export");
        assert_eq!(declaration.quality, IdentityQuality::Anonymous);
        assert!(declaration.name.is_none());
    }

    #[test]
    fn two_anonymous_declarations_do_not_share_a_key() {
        let source = "export default function () {}\nexport default function () {}\n";
        let analysis = analyze("src/two.ts", source);
        let defaults = analysis.of_kind(TsDeclarationKind::DefaultExport);
        let keys: Vec<&str> = defaults
            .iter()
            .map(|declaration| declaration.key.as_str())
            .collect();
        assert_eq!(keys.len(), 2);
        assert_ne!(keys[0], keys[1]);
    }

    #[test]
    fn a_computed_or_destructured_binding_is_marked_computed() {
        let analysis = analyze(
            "src/computed.ts",
            "export const { a, b } = require(\"x\");\nexport const [first] = list;\n",
        );
        assert_eq!(analysis.declarations.len(), 2);
        for declaration in &analysis.declarations {
            assert_eq!(declaration.quality, IdentityQuality::Computed);
            assert_eq!(declaration.name, None);
            assert_eq!(declaration.quality.as_str(), "computed");
        }
        assert_ne!(analysis.declarations[0].key, analysis.declarations[1].key);
    }

    #[test]
    fn a_bare_class_keyword_is_anonymous_not_a_fabricated_name() {
        let analysis = analyze("src/mixed.ts", "class Named {}\nclass {\n}\n");
        assert!(!analysis.has_errors(), "{:?}", analysis.diagnostics);
        assert!(analysis.error_codes().is_empty());
        assert_eq!(analysis.declarations[0].name.as_deref(), Some("Named"));
        assert_eq!(analysis.declarations[0].quality, IdentityQuality::Explicit);
        assert_eq!(analysis.declarations[1].name, None);
        assert_eq!(analysis.declarations[1].quality, IdentityQuality::Anonymous);
    }

    #[test]
    fn unbalanced_braces_are_a_diagnostic_and_partial_coverage() {
        let analysis = analyze("src/broken.ts", "export class Broken {\n");
        assert!(analysis.has_errors());
        assert_eq!(analysis.error_codes(), vec![CODE_UNBALANCED_BRACES]);
        assert_eq!(analysis.coverage().status, CoverageStatus::Partial);
        assert!(!analysis.coverage().claims_completeness());
    }

    #[test]
    fn class_bodies_are_not_reported_as_declarations_by_this_scan() {
        let source = "export class Outer {\n  method() {}\n}\n";
        let analysis = analyze("src/outer.ts", source);
        assert_eq!(analysis.declarations.len(), 1);
        assert_eq!(analysis.declarations[0].semantic_path, Vec::<String>::new());
        assert_eq!(analysis.declarations[0].name.as_deref(), Some("Outer"));
        assert!(analysis.not_explicit().is_empty());
    }

    #[test]
    fn unchanged_symbols_keep_their_key_across_repeated_runs() {
        let first = analyze("src/panel.ts", SAMPLE);
        for _ in 0..3 {
            assert_eq!(analyze("src/panel.ts", SAMPLE), first);
        }
    }
    /// H-007: no file may contribute a repeated node id. Every test below drives
    /// the disambiguated keys through this check, because a file that still
    /// repeats a key is a failure, not a partial success.
    fn assert_every_declaration_key_is_unique(analysis: &TsAnalysis) {
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

    /// Control: a file with no repeated declaration keeps exactly the keys the
    /// shared `declaration_key` produces, byte for byte, so the H-007
    /// disambiguation cannot leak into a non-colliding declaration.
    #[test]
    fn a_file_without_a_repeated_declaration_keeps_its_exact_keys() {
        let analysis = analyze("src/panel.ts", SAMPLE);
        assert_every_declaration_key_is_unique(&analysis);
        for declaration in &analysis.declarations {
            let name = declaration.name.as_deref().expect("explicit name");
            let mut path: Vec<&str> = declaration
                .semantic_path
                .iter()
                .map(String::as_str)
                .collect();
            path.push(name);
            assert_eq!(
                declaration.key,
                crate::identity::declaration_key("src/panel.ts", declaration.kind.as_str(), &path),
                "a non-colliding declaration must keep its pre-H-007 key"
            );
        }
    }

    /// Overloaded or re-declared functions share one name and one module scope.
    #[test]
    fn repeated_function_declarations_get_distinct_keys() {
        let source = "export function foo(value: number): void;\nexport function foo(value: string): void;\nexport function foo(value: unknown): void {\n}\n";
        let analysis = analyze("src/foo.ts", source);
        assert!(!analysis.has_errors(), "{:?}", analysis.diagnostics);
        assert_every_declaration_key_is_unique(&analysis);
        let functions = analysis.of_kind(TsDeclarationKind::Function);
        assert_eq!(functions.len(), 3, "all three declarations are recorded");
        assert_eq!(
            functions[0].semantic_path, functions[1].semantic_path,
            "the ambiguity is real: the two declarations share one semantic path"
        );
        let keys: Vec<&str> = functions
            .iter()
            .map(|declaration| declaration.key.as_str())
            .collect();
        assert!(keys[0] != keys[1] && keys[1] != keys[2] && keys[0] != keys[2]);
        assert_eq!(analysis, analyze("src/foo.ts", source));
    }

    /// An interface merged across two blocks is one name in one scope, twice.
    #[test]
    fn an_interface_merged_across_two_blocks_gets_distinct_keys() {
        let source = "interface A {\n  a: string;\n}\n\ninterface A {\n  b: number;\n}\n";
        let analysis = analyze("src/a.ts", source);
        assert!(!analysis.has_errors(), "{:?}", analysis.diagnostics);
        assert_every_declaration_key_is_unique(&analysis);
        let interfaces = analysis.of_kind(TsDeclarationKind::Interface);
        assert_eq!(interfaces.len(), 2, "both interface blocks are recorded");
        assert_ne!(interfaces[0].key, interfaces[1].key);
        assert_eq!(analysis, analyze("src/a.ts", source));
    }

    /// A brace-scoped `namespace N { }` block repeated in one file declares the
    /// same namespace twice.
    #[test]
    fn a_repeated_namespace_block_gets_distinct_keys() {
        let source = "namespace N {\n}\n\nnamespace N {\n}\n";
        let analysis = analyze("src/n.ts", source);
        assert!(!analysis.has_errors(), "{:?}", analysis.diagnostics);
        assert_every_declaration_key_is_unique(&analysis);
        let namespaces = analysis.of_kind(TsDeclarationKind::Namespace);
        assert_eq!(namespaces.len(), 2, "both namespace blocks are recorded");
        assert_ne!(namespaces[0].key, namespaces[1].key);
        assert_eq!(analysis, analyze("src/n.ts", source));
    }

    /// A type declared twice in one module is two declarations on one path.
    #[test]
    fn a_type_declared_twice_gets_distinct_keys() {
        let source = "class C {\n}\n\nclass C {\n}\n";
        let analysis = analyze("src/c.ts", source);
        assert!(!analysis.has_errors(), "{:?}", analysis.diagnostics);
        assert_every_declaration_key_is_unique(&analysis);
        let classes = analysis.of_kind(TsDeclarationKind::Class);
        assert_eq!(classes.len(), 2, "both class declarations are recorded");
        assert_ne!(classes[0].key, classes[1].key);
        assert_eq!(analysis, analyze("src/c.ts", source));
    }

    /// A repeated key is only disambiguated inside the file that repeats it: the
    /// same semantic path in another file keeps a key derived from that file.
    #[test]
    fn disambiguation_never_leaks_across_files() {
        let source = "interface A {\n  a: string;\n}\n\ninterface A {\n  b: number;\n}\n";
        let first = analyze("src/a.ts", source);
        let second = analyze("src/other/a.ts", source);
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
