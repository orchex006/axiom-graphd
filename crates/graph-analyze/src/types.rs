//! Explicit inheritance and interface facts (task B-053).
//!
//! A type edge is emitted only when the source *declares* the relationship and
//! the named base resolves to exactly one declaration the analyser can see.
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 3 additionally says DI
//! registration is a **declared binding**, not a runtime guarantee, so this
//! module deliberately produces no call-routing edge from a service
//! registration: it records who was registered, with provenance, and states
//! that the runtime selection is unproven.
//!
//! Base lists are read by a bounded literal header parser. It accepts the
//! C# `class A : B, IC` and TypeScript `class A extends B implements IC`
//! shapes and keeps only identifier-shaped names; a name it cannot read is
//! dropped rather than guessed, and the caller sees the resulting unresolved
//! entry when that name cannot be linked.

use std::collections::BTreeMap;

use crate::adapter::Language;

/// Reason recorded for a declared base with no matching declaration.
pub const REASON_BASE_NOT_IN_PROJECT: &str = "type-base-not-in-project";
/// Reason recorded when a declared base matches several declarations.
pub const REASON_AMBIGUOUS_BASE: &str = "type-base-ambiguous";
/// Reason recorded when two declarations share one qualified name.
pub const REASON_DUPLICATE_TYPE: &str = "type-duplicate-declaration";

/// What kind of type declaration this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypeKind {
    /// A class.
    Class,
    /// An interface.
    Interface,
    /// A struct.
    Struct,
    /// An enum.
    Enum,
}

impl TypeKind {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Interface => "interface",
            Self::Struct => "struct",
            Self::Enum => "enum",
        }
    }

    /// Whether the kind can be an interface implementation target.
    #[must_use]
    pub const fn is_interface(self) -> bool {
        matches!(self, Self::Interface)
    }
}

/// One explicitly declared type and its literal base list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeDeclaration {
    /// Stable key from [`crate::identity::declaration_key`].
    pub key: String,
    /// File the declaration appears in.
    pub file: String,
    /// Semantic path, outermost first, ending in the type name.
    pub qualified: Vec<String>,
    /// Declared name (the last qualified segment).
    pub name: String,
    /// Declaration kind.
    pub kind: TypeKind,
    /// Literal base/interface names exactly as written.
    pub bases: Vec<String>,
}

impl TypeDeclaration {
    /// Build a declaration.
    #[must_use]
    pub fn new(
        key: impl Into<String>,
        file: impl Into<String>,
        qualified: impl IntoIterator<Item = impl Into<String>>,
        kind: TypeKind,
        bases: impl IntoIterator<Item = String>,
    ) -> Self {
        let qualified: Vec<String> = qualified.into_iter().map(Into::into).collect();
        let name = qualified.last().cloned().unwrap_or_default();
        Self {
            key: key.into(),
            file: file.into(),
            qualified,
            name,
            kind,
            bases: bases.into_iter().collect(),
        }
    }

    /// The dotted qualified name, e.g. `App.Widget`.
    #[must_use]
    pub fn dotted(&self) -> String {
        self.qualified.join(".")
    }
}

/// One explicit DI/service registration found in source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiRegistration {
    /// Registered service name as written.
    pub service: String,
    /// Registered implementation name as written.
    pub implementation: String,
    /// Declared lifetime as written, when the source has one.
    pub lifetime: Option<String>,
    /// File the registration appears in.
    pub file: String,
    /// One-based line of the registration.
    pub line: usize,
}

/// A declared binding produced by a registration.
///
/// This is deliberately *not* a call-routing edge and not an `implements`
/// edge: the source states an intent, and only a running container could prove
/// which implementation is selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredBinding {
    /// Registered service name.
    pub service: String,
    /// Registered implementation name.
    pub implementation: String,
    /// Declared lifetime.
    pub lifetime: Option<String>,
    /// File of the registration.
    pub file: String,
    /// One-based line.
    pub line: usize,
    /// Provenance tag, always `explicit-service-registration`.
    pub evidence: Vec<String>,
}

impl DeclaredBinding {
    /// Registration never proves runtime routing.
    #[must_use]
    pub const fn proves_runtime_routing(&self) -> bool {
        false
    }
}

/// The kind of type edge produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypeEdgeKind {
    /// A class extends another class or struct.
    Inherits,
    /// A type implements an interface.
    Implements,
}

impl TypeEdgeKind {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inherits => "INHERITS",
            Self::Implements => "IMPLEMENTS",
        }
    }
}

/// One resolved type edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeEdge {
    /// Declaring type key.
    pub source: String,
    /// Base or interface key.
    pub target: String,
    /// Edge kind.
    pub kind: TypeEdgeKind,
    /// Always `exact_static`: the relationship is written in the source.
    pub quality: &'static str,
    /// Provenance tags.
    pub evidence: Vec<String>,
}

/// A declared base that could not be linked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedBase {
    /// File of the declaring type.
    pub file: String,
    /// Declaring type key.
    pub source: String,
    /// The base name exactly as written.
    pub name: String,
    /// One of the `REASON_*` constants.
    pub reason: String,
    /// Candidate keys, when the name matched several declarations.
    pub candidates: Vec<String>,
}

/// The result of linking explicit type declarations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TypeFacts {
    /// Type edges, in declaration then base order.
    pub edges: Vec<TypeEdge>,
    /// Declared bases that could not be linked.
    pub unresolved: Vec<UnresolvedBase>,
    /// Service registrations, kept as declared bindings only.
    pub bindings: Vec<DeclaredBinding>,
}

impl TypeFacts {
    /// Edges declared by `source`.
    #[must_use]
    pub fn edges_of(&self, source: &str) -> Vec<&TypeEdge> {
        self.edges
            .iter()
            .filter(|edge| edge.source == source)
            .collect()
    }

    /// Whether any binding was treated as runtime routing. Always `false`;
    /// the method exists so the invariant is checked by tests.
    #[must_use]
    pub fn any_binding_proves_runtime_routing(&self) -> bool {
        self.bindings
            .iter()
            .any(DeclaredBinding::proves_runtime_routing)
    }
}

/// The analyser input.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TypeInput {
    /// Explicit type declarations.
    pub declarations: Vec<TypeDeclaration>,
    /// Explicit service registrations.
    pub registrations: Vec<DiRegistration>,
}

impl TypeInput {
    /// Link declarations and keep registrations as declared bindings.
    #[must_use]
    pub fn resolve(&self) -> TypeFacts {
        let mut by_name: BTreeMap<String, Vec<&TypeDeclaration>> = BTreeMap::new();
        for declaration in &self.declarations {
            by_name
                .entry(declaration.dotted())
                .or_default()
                .push(declaration);
            by_name
                .entry(declaration.name.clone())
                .or_default()
                .push(declaration);
        }

        let mut facts = TypeFacts::default();
        for declaration in &self.declarations {
            for base in &declaration.bases {
                let candidates = by_name.get(base).cloned().unwrap_or_default();
                match candidates.as_slice() {
                    [] => facts.unresolved.push(UnresolvedBase {
                        file: declaration.file.clone(),
                        source: declaration.key.clone(),
                        name: base.clone(),
                        reason: REASON_BASE_NOT_IN_PROJECT.to_string(),
                        candidates: Vec::new(),
                    }),
                    [only] => {
                        if only.key == declaration.key {
                            continue;
                        }
                        facts.edges.push(TypeEdge {
                            source: declaration.key.clone(),
                            target: only.key.clone(),
                            kind: if only.kind.is_interface() {
                                TypeEdgeKind::Implements
                            } else {
                                TypeEdgeKind::Inherits
                            },
                            quality: "exact_static",
                            evidence: vec!["explicit-base-list".to_string()],
                        });
                    }
                    many => {
                        let mut keys: Vec<String> =
                            many.iter().map(|target| target.key.clone()).collect();
                        keys.sort();
                        keys.dedup();
                        facts.unresolved.push(UnresolvedBase {
                            file: declaration.file.clone(),
                            source: declaration.key.clone(),
                            name: base.clone(),
                            reason: if keys.len() > 1 {
                                REASON_AMBIGUOUS_BASE.to_string()
                            } else {
                                REASON_DUPLICATE_TYPE.to_string()
                            },
                            candidates: keys,
                        });
                    }
                }
            }
        }
        for registration in &self.registrations {
            facts.bindings.push(DeclaredBinding {
                service: registration.service.clone(),
                implementation: registration.implementation.clone(),
                lifetime: registration.lifetime.clone(),
                file: registration.file.clone(),
                line: registration.line,
                evidence: vec!["explicit-service-registration".to_string()],
            });
        }
        facts
    }
}

/// Link declarations directly.
#[must_use]
pub fn resolve(input: &TypeInput) -> TypeFacts {
    input.resolve()
}

/// Extract the literal base/interface names from a type header.
///
/// The parser is deliberately bounded: it reads one header line, keeps only
/// identifier-shaped names and drops everything it does not recognise.
#[must_use]
pub fn literal_base_names(language: Language, header: &str) -> Vec<String> {
    let clause = match language {
        Language::CSharp => header
            .split_once(':')
            .map(|(_, clause)| clause)
            .unwrap_or_default(),
        Language::TypeScript => {
            let mut names = Vec::new();
            for keyword in ["extends", "implements"] {
                if let Some((_, rest)) = header.split_once(keyword) {
                    names.push(rest);
                }
            }
            return names.iter().flat_map(|rest| split_names(rest)).collect();
        }
    };
    split_names(clause)
}

/// Split a clause into identifier-shaped names.
fn split_names(clause: &str) -> Vec<String> {
    let clause = clause
        .split_once("where")
        .map_or(clause, |(before, _)| before);
    clause
        .split(',')
        .map(|part| {
            let part = part.split_once("/*").map_or(part, |(before, _)| before);
            part.trim()
                .chars()
                .take_while(|ch| ch.is_alphanumeric() || *ch == '_' || *ch == '.')
                .collect::<String>()
        })
        .filter(|name| !name.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        literal_base_names, resolve, DiRegistration, TypeDeclaration, TypeEdgeKind, TypeInput,
        TypeKind, REASON_AMBIGUOUS_BASE, REASON_BASE_NOT_IN_PROJECT, REASON_DUPLICATE_TYPE,
    };
    use crate::adapter::Language;

    fn declaration(
        key: &str,
        file: &str,
        qualified: &[&str],
        kind: TypeKind,
        bases: &[&str],
    ) -> TypeDeclaration {
        TypeDeclaration::new(
            key,
            file,
            qualified.iter().map(|part| (*part).to_string()),
            kind,
            bases.iter().map(|base| (*base).to_string()),
        )
    }

    #[test]
    fn explicit_type_declarations_link_with_evidence() {
        let input = TypeInput {
            declarations: vec![
                declaration(
                    "base",
                    "src/Base.cs",
                    &["App", "Base"],
                    TypeKind::Class,
                    &[],
                ),
                declaration(
                    "greeter",
                    "src/Greeter.cs",
                    &["App", "Greeter"],
                    TypeKind::Class,
                    &["Base"],
                ),
                declaration(
                    "clock-iface",
                    "src/IClock.cs",
                    &["App", "IClock"],
                    TypeKind::Interface,
                    &[],
                ),
                declaration(
                    "clock",
                    "src/Clock.cs",
                    &["App", "Clock"],
                    TypeKind::Class,
                    &["IClock"],
                ),
            ],
            registrations: Vec::new(),
        };
        let facts = resolve(&input);
        assert_eq!(facts.unresolved, Vec::new());
        assert_eq!(facts.edges_of("greeter").len(), 1);
        assert_eq!(facts.edges_of("greeter")[0].kind, TypeEdgeKind::Inherits);
        assert_eq!(facts.edges_of("greeter")[0].target, "base");
        assert_eq!(facts.edges_of("greeter")[0].quality, "exact_static");
        assert_eq!(facts.edges_of("clock")[0].kind, TypeEdgeKind::Implements);
        assert_eq!(facts.edges_of("clock")[0].target, "clock-iface");
    }

    #[test]
    fn a_registration_is_a_declared_binding_not_runtime_routing() {
        let input = TypeInput {
            declarations: vec![
                declaration(
                    "clock-iface",
                    "src/IClock.cs",
                    &["App", "IClock"],
                    TypeKind::Interface,
                    &[],
                ),
                declaration(
                    "clock",
                    "src/Clock.cs",
                    &["App", "Clock"],
                    TypeKind::Class,
                    &["IClock"],
                ),
            ],
            registrations: vec![DiRegistration {
                service: "IClock".to_string(),
                implementation: "Clock".to_string(),
                lifetime: Some("singleton".to_string()),
                file: "src/Program.cs".to_string(),
                line: 8,
            }],
        };
        let facts = resolve(&input);
        assert_eq!(facts.bindings.len(), 1);
        assert_eq!(facts.bindings[0].service, "IClock");
        assert_eq!(facts.bindings[0].lifetime.as_deref(), Some("singleton"));
        assert_eq!(
            facts.bindings[0].evidence,
            vec!["explicit-service-registration".to_string()]
        );
        assert!(!facts.bindings[0].proves_runtime_routing());
        assert!(!facts.any_binding_proves_runtime_routing());
        assert!(
            !facts
                .edges
                .iter()
                .any(|edge| edge.target == "clock-iface" && edge.source == "clock-iface"),
            "registration must not synthesise an implementation edge"
        );
    }

    #[test]
    fn a_framework_base_is_unresolved_not_invented() {
        let input = TypeInput {
            declarations: vec![declaration(
                "controller",
                "src/HomeController.cs",
                &["App", "HomeController"],
                TypeKind::Class,
                &["ControllerBase"],
            )],
            registrations: Vec::new(),
        };
        let facts = resolve(&input);
        assert!(facts.edges.is_empty());
        assert_eq!(facts.unresolved.len(), 1);
        assert_eq!(facts.unresolved[0].reason, REASON_BASE_NOT_IN_PROJECT);
        assert_eq!(facts.unresolved[0].name, "ControllerBase");
    }

    #[test]
    fn a_name_matching_two_declarations_is_ambiguous() {
        let input = TypeInput {
            declarations: vec![
                declaration("a", "src/a/Base.cs", &["A", "Base"], TypeKind::Class, &[]),
                declaration("b", "src/b/Base.cs", &["B", "Base"], TypeKind::Class, &[]),
                declaration(
                    "child",
                    "src/Child.cs",
                    &["App", "Child"],
                    TypeKind::Class,
                    &["Base"],
                ),
            ],
            registrations: Vec::new(),
        };
        let facts = resolve(&input);
        assert!(facts.edges.is_empty());
        assert_eq!(facts.unresolved[0].reason, REASON_AMBIGUOUS_BASE);
        assert_eq!(facts.unresolved[0].candidates, vec!["a", "b"]);
    }

    #[test]
    fn a_duplicated_key_is_reported_and_never_linked_silently() {
        // The same stable key declared twice is a duplicate, not a choice
        // between two real types; the analyser reports it instead of linking.
        let input = TypeInput {
            declarations: vec![
                declaration("w", "src/one/W.cs", &["App"], TypeKind::Class, &[]),
                declaration("w", "src/two/W.cs", &["App"], TypeKind::Class, &[]),
                declaration(
                    "child",
                    "src/Child.cs",
                    &["App", "Child"],
                    TypeKind::Class,
                    &["App"],
                ),
            ],
            registrations: Vec::new(),
        };
        let facts = resolve(&input);
        assert!(facts.edges.is_empty());
        assert_eq!(facts.unresolved.len(), 1);
        assert_eq!(facts.unresolved[0].reason, REASON_DUPLICATE_TYPE);
        assert_eq!(facts.unresolved[0].candidates, vec!["w"]);
    }

    #[test]
    fn a_self_reference_never_creates_an_edge() {
        let input = TypeInput {
            declarations: vec![declaration(
                "w",
                "src/W.cs",
                &["App", "W"],
                TypeKind::Class,
                &["App.W"],
            )],
            registrations: Vec::new(),
        };
        let facts = resolve(&input);
        assert!(facts.edges.is_empty());
        assert!(facts.unresolved.is_empty());
    }

    #[test]
    fn csharp_headers_yield_literal_base_names_only() {
        assert_eq!(
            literal_base_names(
                Language::CSharp,
                "public class HomeController : ControllerBase, IHome"
            ),
            vec!["ControllerBase".to_string(), "IHome".to_string()]
        );
        assert_eq!(
            literal_base_names(
                Language::CSharp,
                "internal sealed class Repo<T> : Base<T> where T : class"
            ),
            vec!["Base".to_string()]
        );
        assert_eq!(
            literal_base_names(Language::CSharp, "public class Plain {"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn typescript_headers_yield_extends_and_implements() {
        assert_eq!(
            literal_base_names(
                Language::TypeScript,
                "export class Widget extends Base implements IWidget"
            ),
            vec!["Base".to_string(), "IWidget".to_string()]
        );
        assert_eq!(
            literal_base_names(Language::TypeScript, "class Plain {"),
            Vec::<String>::new()
        );
    }
}
