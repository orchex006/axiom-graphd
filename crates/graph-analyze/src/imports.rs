//! Within-project import resolution (task B-051).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 3 requires an explicit
//! project reference or import that resolves **uniquely** to become an
//! `exact_static` edge. A specifier that matches several files is reported as
//! ambiguous with its candidate set, and one that matches none stays
//! unresolved; the resolver never picks the first candidate to make a graph
//! look complete.
//!
//! Two configured rule kinds are supported and must both be declared:
//!
//! * a **relative** specifier (`./`, `../`) resolves against the directory of
//!   the importing file; and
//! * an **alias** rule (`baseUrl`/`paths` style, or an explicit project alias)
//!   maps a long specifier prefix onto one or more configured target
//!   directories.
//!
//! A bare package specifier is deliberately *not* guessed. It carries no
//! configured target, so it is reported as external/unmapped and the caller
//! decides whether the dependency facts of B-047 are enough to tag it.

use std::collections::BTreeSet;

use crate::Span;

/// Reason recorded when a specifier matches no known file.
pub const REASON_MISSING_TARGET: &str = "unresolved-missing-target";
/// Reason recorded when a specifier matches more than one known file.
pub const REASON_AMBIGUOUS_TARGET: &str = "unresolved-ambiguous-target";
/// Reason recorded for a specifier that is not a literal we can resolve.
pub const REASON_NOT_A_LITERAL: &str = "unresolved-not-a-literal";
/// Reason recorded for a bare specifier with no configured alias.
pub const REASON_EXTERNAL_PACKAGE: &str = "unresolved-external-package";
/// Reason recorded when a relative specifier escapes the project root.
pub const REASON_OUTSIDE_PROJECT: &str = "unresolved-outside-project";

/// The syntactic shape of a specifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SpecifierKind {
    /// `./x` or `../x`.
    Relative,
    /// Prefix matched by a configured alias rule.
    Alias,
    /// A bare package or namespace specifier with no configured alias.
    External,
    /// Not a literal string (computed, interpolated or absent).
    Unsupported,
}

impl SpecifierKind {
    /// Stable spelling used in coverage and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Relative => "relative",
            Self::Alias => "alias",
            Self::External => "external",
            Self::Unsupported => "unsupported",
        }
    }
}

/// One configured alias: a specifier prefix and its declared target roots.
///
/// An alias with two or more target roots can never resolve uniquely; it is
/// kept as a candidate set so the caller can report `ambiguous`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasRule {
    prefix: String,
    targets: BTreeSet<String>,
}

impl AliasRule {
    /// Build an alias rule from a prefix and one or more target roots.
    #[must_use]
    pub fn new(prefix: impl Into<String>, targets: impl IntoIterator<Item = String>) -> Self {
        Self {
            prefix: prefix.into(),
            targets: targets.into_iter().collect(),
        }
    }

    /// The specifier prefix this rule owns.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The declared target roots, in deterministic order.
    #[must_use]
    pub fn targets(&self) -> Vec<&str> {
        self.targets.iter().map(String::as_str).collect()
    }

    /// Whether this rule owns `specifier` (`prefix` itself or `prefix/...`).
    #[must_use]
    pub fn matches(&self, specifier: &str) -> bool {
        specifier == self.prefix
            || (specifier.len() > self.prefix.len()
                && specifier.starts_with(&self.prefix)
                && specifier.as_bytes()[self.prefix.len()] == b'/')
    }

    /// The remainder of a matching specifier, without the prefix separator.
    fn remainder<'a>(&self, specifier: &'a str) -> &'a str {
        let rest = &specifier[self.prefix.len()..];
        rest.strip_prefix('/').unwrap_or(rest)
    }
}

/// Resolution configuration: the rules a project declares, never a guess.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PathConfig {
    aliases: Vec<AliasRule>,
    extensions: Vec<String>,
    index_names: Vec<String>,
}

impl PathConfig {
    /// A configuration with no aliases and the given file suffixes.
    #[must_use]
    pub fn new(extensions: impl IntoIterator<Item = String>) -> Self {
        Self {
            aliases: Vec::new(),
            extensions: extensions.into_iter().collect(),
            index_names: vec!["index".to_string()],
        }
    }

    /// Add an alias rule.
    #[must_use]
    pub fn with_alias(mut self, rule: AliasRule) -> Self {
        self.aliases.push(rule);
        self
    }

    /// Replace the index file stems tried when a specifier names a directory.
    #[must_use]
    pub fn with_index_names(mut self, names: impl IntoIterator<Item = String>) -> Self {
        self.index_names = names.into_iter().collect();
        self
    }

    /// The configured alias rules.
    #[must_use]
    pub fn aliases(&self) -> &[AliasRule] {
        &self.aliases
    }

    /// The configured file suffixes.
    #[must_use]
    pub fn extensions(&self) -> Vec<&str> {
        self.extensions.iter().map(String::as_str).collect()
    }
}

/// One literal import/using/project-reference statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportStatement {
    /// Importing file, portably relative to the project root.
    pub file: String,
    /// The literal specifier, or `None` when the source does not carry one.
    pub specifier: Option<String>,
    /// Where the specifier appears in the importing file.
    pub span: Span,
}

impl ImportStatement {
    /// A relative or alias specifier.
    #[must_use]
    pub fn literal(file: impl Into<String>, specifier: impl Into<String>, span: Span) -> Self {
        Self {
            file: file.into(),
            specifier: Some(specifier.into()),
            span,
        }
    }

    /// A statement whose specifier is computed or absent.
    #[must_use]
    pub fn unsupported(file: impl Into<String>, span: Span) -> Self {
        Self {
            file: file.into(),
            specifier: None,
            span,
        }
    }

    /// Classify the statement against `config`.
    #[must_use]
    pub fn kind(&self, config: &PathConfig) -> SpecifierKind {
        let Some(specifier) = self.specifier.as_deref() else {
            return SpecifierKind::Unsupported;
        };
        if specifier.is_empty() {
            return SpecifierKind::Unsupported;
        }
        if specifier.starts_with("./") || specifier.starts_with("../") || specifier == "." {
            return SpecifierKind::Relative;
        }
        if config.aliases.iter().any(|rule| rule.matches(specifier)) {
            return SpecifierKind::Alias;
        }
        SpecifierKind::External
    }
}

/// Resolution quality of an import edge.
///
/// The vocabulary matches the resolution rules of the coverage document: a
/// unique configured match is `exact_static`; a match that needed several
/// candidates is `inferred_static` and always carries the candidate set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolutionQuality {
    /// Exactly one target matched a configured rule.
    ExactStatic,
    /// Several targets matched; the caller must keep the candidate set.
    InferredStatic,
}

impl ResolutionQuality {
    /// Stable spelling used in evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactStatic => "exact_static",
            Self::InferredStatic => "inferred_static",
        }
    }
}

/// The outcome of resolving one statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// One target resolved through a named rule.
    Resolved {
        /// Resolved target file, portably relative.
        target: String,
        /// Rule that produced the match.
        rule: String,
        /// `exact_static` for a unique match.
        quality: ResolutionQuality,
    },
    /// Several targets matched a configured rule.
    Ambiguous {
        /// Candidate targets, sorted and deduplicated.
        candidates: Vec<String>,
        /// Rule that produced the ambiguity.
        rule: String,
    },
    /// No target matched, or the specifier is not resolvable at all.
    Unresolved {
        /// One of the `REASON_*` constants.
        reason: String,
    },
}

impl Resolution {
    /// Whether this outcome produced a resolved edge.
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved { .. })
    }
}

/// A resolved import ready to become a graph edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImport {
    /// The importing statement.
    pub statement: ImportStatement,
    /// The statement shape.
    pub kind: SpecifierKind,
    /// The resolution outcome.
    pub resolution: Resolution,
}

/// Resolve one import statement against a known-file set and configuration.
///
/// `known` is the set of files the project actually contains, so a specifier
/// that points at a path with no file is unresolved instead of inventing a
/// target.
#[must_use]
pub fn resolve(
    statement: &ImportStatement,
    known: &BTreeSet<String>,
    config: &PathConfig,
) -> ResolvedImport {
    let kind = statement.kind(config);
    let resolution = match kind {
        SpecifierKind::Unsupported => Resolution::Unresolved {
            reason: REASON_NOT_A_LITERAL.to_string(),
        },
        SpecifierKind::External => Resolution::Unresolved {
            reason: REASON_EXTERNAL_PACKAGE.to_string(),
        },
        SpecifierKind::Relative => {
            let specifier = statement.specifier.as_deref().unwrap_or_default();
            let Some(joined) = join_relative(&statement.file, specifier) else {
                return ResolvedImport {
                    statement: statement.clone(),
                    kind,
                    resolution: Resolution::Unresolved {
                        reason: REASON_OUTSIDE_PROJECT.to_string(),
                    },
                };
            };
            match candidates_for(&joined, known, config).as_slice() {
                [] => Resolution::Unresolved {
                    reason: REASON_MISSING_TARGET.to_string(),
                },
                [only] => Resolution::Resolved {
                    target: only.clone(),
                    rule: "relative".to_string(),
                    quality: ResolutionQuality::ExactStatic,
                },
                many => Resolution::Ambiguous {
                    candidates: many.to_vec(),
                    rule: "relative".to_string(),
                },
            }
        }
        SpecifierKind::Alias => {
            let specifier = statement.specifier.as_deref().unwrap_or_default();
            let mut candidates = BTreeSet::new();
            for rule in config.aliases.iter().filter(|rule| rule.matches(specifier)) {
                let remainder = rule.remainder(specifier);
                for target in rule.targets() {
                    let joined = join_target(target, remainder);
                    candidates.extend(candidates_for(&joined, known, config));
                }
            }
            match candidates.into_iter().collect::<Vec<_>>().as_slice() {
                [] => Resolution::Unresolved {
                    reason: REASON_MISSING_TARGET.to_string(),
                },
                [only] => Resolution::Resolved {
                    target: only.clone(),
                    rule: "alias".to_string(),
                    quality: ResolutionQuality::ExactStatic,
                },
                many => Resolution::Ambiguous {
                    candidates: many.to_vec(),
                    rule: "alias".to_string(),
                },
            }
        }
    };
    ResolvedImport {
        statement: statement.clone(),
        kind,
        resolution,
    }
}

/// Resolve every statement, preserving input order.
#[must_use]
pub fn resolve_all(
    statements: &[ImportStatement],
    known: &BTreeSet<String>,
    config: &PathConfig,
) -> Vec<ResolvedImport> {
    statements
        .iter()
        .map(|statement| resolve(statement, known, config))
        .collect()
}

/// Join a relative specifier onto the directory of `file`.
///
/// Returns `None` when the path escapes the project root, because a resolved
/// target outside the project would claim a dependency the analyser cannot see.
fn join_relative(file: &str, specifier: &str) -> Option<String> {
    let mut segments: Vec<&str> = file
        .rsplit_once('/')
        .map_or_else(Vec::new, |(directory, _)| directory.split('/').collect());
    for part in specifier.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            other => segments.push(other),
        }
    }
    Some(segments.join("/"))
}

/// Join an alias target root with the remainder of the specifier.
fn join_target(target: &str, remainder: &str) -> String {
    let target = target.trim_end_matches('/');
    let mut segments: Vec<&str> = Vec::new();
    if !target.is_empty() {
        segments.extend(
            target
                .split('/')
                .filter(|part| !part.is_empty() && *part != "."),
        );
    }
    for part in remainder.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    segments.join("/")
}

/// Candidate known files for an exact path, an extensionless path or a
/// directory specifier.
fn candidates_for(joined: &str, known: &BTreeSet<String>, config: &PathConfig) -> Vec<String> {
    let mut candidates = BTreeSet::new();
    if known.contains(joined) {
        candidates.insert(joined.to_string());
    }
    for extension in &config.extensions {
        let with_extension = format!("{joined}.{extension}");
        if known.contains(&with_extension) {
            candidates.insert(with_extension);
        }
    }
    for index in &config.index_names {
        for extension in &config.extensions {
            let with_index = format!("{joined}/{index}.{extension}");
            if known.contains(&with_index) {
                candidates.insert(with_index);
            }
        }
    }
    candidates.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        resolve, resolve_all, AliasRule, ImportStatement, PathConfig, Resolution,
        ResolutionQuality, SpecifierKind, REASON_EXTERNAL_PACKAGE, REASON_MISSING_TARGET,
        REASON_NOT_A_LITERAL, REASON_OUTSIDE_PROJECT,
    };
    use crate::Span;

    fn known(files: &[&str]) -> BTreeSet<String> {
        files.iter().map(|file| (*file).to_string()).collect()
    }

    fn config() -> PathConfig {
        PathConfig::new(["ts".to_string(), "tsx".to_string()])
            .with_alias(AliasRule::new("@app", vec!["src/app".to_string()]))
            .with_alias(AliasRule::new(
                "@shared",
                vec!["src/shared".to_string(), "src/vendor/shared".to_string()],
            ))
    }

    fn span() -> Span {
        Span::new(0, 1)
    }

    #[test]
    fn relative_imports_resolve_against_the_importing_directory() {
        let files = known(&["src/app/Foo.ts", "src/app/Widget.ts"]);
        let statement = ImportStatement::literal("src/app/Foo.ts", "./Widget", span());
        let resolved = resolve(&statement, &files, &config());
        assert_eq!(resolved.kind, SpecifierKind::Relative);
        assert!(matches!(
            &resolved.resolution,
            Resolution::Resolved { target, rule, quality }
                if target == "src/app/Widget.ts" && rule == "relative"
                    && *quality == ResolutionQuality::ExactStatic
        ));
        assert!(resolved.resolution.is_resolved());
    }

    #[test]
    fn parent_relative_imports_are_normalized() {
        let files = known(&["src/app/deep/Leaf.ts", "src/app/Entry.ts"]);
        let statement = ImportStatement::literal("src/app/deep/Leaf.ts", "../Entry", span());
        let resolved = resolve(&statement, &files, &config());
        assert!(matches!(
            &resolved.resolution,
            Resolution::Resolved { target, .. } if target == "src/app/Entry.ts"
        ));
    }

    #[test]
    fn explicit_aliases_resolve_through_configured_targets() {
        let files = known(&["src/app/Widget.ts", "src/shared/Clock.ts"]);
        let alias = resolve(
            &ImportStatement::literal("src/app/Foo.ts", "@app/Widget", span()),
            &files,
            &config(),
        );
        assert_eq!(alias.kind, SpecifierKind::Alias);
        assert!(matches!(
            &alias.resolution,
            Resolution::Resolved { target, rule, .. }
                if target == "src/app/Widget.ts" && rule == "alias"
        ));
        let shared = resolve(
            &ImportStatement::literal("src/app/Foo.ts", "@shared/Clock", span()),
            &files,
            &config(),
        );
        assert!(matches!(
            &shared.resolution,
            Resolution::Resolved { target, .. } if target == "src/shared/Clock.ts"
        ));
    }

    #[test]
    fn a_missing_relative_target_stays_unresolved() {
        let files = known(&["src/app/Foo.ts"]);
        let resolved = resolve(
            &ImportStatement::literal("src/app/Foo.ts", "./Missing", span()),
            &files,
            &config(),
        );
        assert_eq!(
            resolved.resolution,
            Resolution::Unresolved {
                reason: REASON_MISSING_TARGET.to_string()
            }
        );
    }

    #[test]
    fn a_multi_root_alias_is_ambiguous_and_never_picks_the_first_target() {
        let files = known(&["src/shared/Clock.ts", "src/vendor/shared/Clock.ts"]);
        let resolved = resolve(
            &ImportStatement::literal("src/app/Foo.ts", "@shared/Clock", span()),
            &files,
            &config(),
        );
        match resolved.resolution {
            Resolution::Ambiguous { candidates, rule } => {
                assert_eq!(rule, "alias");
                assert_eq!(
                    candidates,
                    vec![
                        "src/shared/Clock.ts".to_string(),
                        "src/vendor/shared/Clock.ts".to_string()
                    ]
                );
            }
            other => panic!("expected ambiguity, got {other:?}"),
        }
    }

    #[test]
    fn an_ambiguous_extension_choice_is_ambiguous() {
        let files = known(&["src/app/Widget.ts", "src/app/Widget.tsx"]);
        let resolved = resolve(
            &ImportStatement::literal("src/app/Foo.ts", "./Widget", span()),
            &files,
            &config(),
        );
        assert!(matches!(
            resolved.resolution,
            Resolution::Ambiguous { candidates, .. } if candidates.len() == 2
        ));
    }

    #[test]
    fn a_bare_package_specifier_is_never_guessed() {
        let resolved = resolve(
            &ImportStatement::literal("src/app/Foo.ts", "rxjs", span()),
            &known(&["src/app/Foo.ts"]),
            &config(),
        );
        assert_eq!(resolved.kind, SpecifierKind::External);
        assert_eq!(
            resolved.resolution,
            Resolution::Unresolved {
                reason: REASON_EXTERNAL_PACKAGE.to_string()
            }
        );
    }

    #[test]
    fn computed_and_escaping_specifiers_are_unresolved() {
        let computed = resolve(
            &ImportStatement::unsupported("src/app/Foo.ts", span()),
            &known(&["src/app/Foo.ts"]),
            &config(),
        );
        assert_eq!(computed.kind, SpecifierKind::Unsupported);
        assert_eq!(
            computed.resolution,
            Resolution::Unresolved {
                reason: REASON_NOT_A_LITERAL.to_string()
            }
        );

        let escaping = resolve(
            &ImportStatement::literal("src/app/Foo.ts", "../../../../etc/passwd", span()),
            &known(&["src/app/Foo.ts"]),
            &config(),
        );
        assert_eq!(
            escaping.resolution,
            Resolution::Unresolved {
                reason: REASON_OUTSIDE_PROJECT.to_string()
            }
        );
    }

    #[test]
    fn resolution_order_and_results_are_deterministic() {
        let files = known(&["src/app/Foo.ts", "src/app/Widget.ts"]);
        let statements = vec![
            ImportStatement::literal("src/app/Widget.ts", "./Widget", span()),
            ImportStatement::literal("src/app/Foo.ts", "./Widget", span()),
        ];
        let first = resolve_all(&statements, &files, &config());
        for _ in 0..3 {
            assert_eq!(resolve_all(&statements, &files, &config()), first);
        }
        assert_eq!(first.len(), 2);
    }
}
