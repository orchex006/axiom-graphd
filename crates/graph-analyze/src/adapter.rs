//! Parser adapter trait and language registry (task B-045).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` requires the analyser to state what it
//! actually understood. The registry is the single place that answers "can this
//! build analyse this file?" and it must never answer with silence: a file whose
//! language is unknown is reported as **unsupported**, with the reason, not as a
//! complete analysis of zero facts. That distinction is the difference between
//! "nothing to find" and "we did not look", and callers depend on it.
//!
//! Every adapter names the pinned grammar version it is compiled against, so the
//! coverage report of a run can be attributed to an exact parser build.

use graph_core::error::{AxiomError, ErrorCode};

use crate::grammar::PinnedGrammar;

/// Reason recorded when a path has no registered adapter.
pub const REASON_UNKNOWN_LANGUAGE: &str = "unsupported-language";
/// Reason recorded when a registry would contain two adapters for one language.
pub const REASON_DUPLICATE_LANGUAGE: &str = "duplicate-language";

/// A source language this build can analyse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Language {
    /// C# sources (`.cs`).
    CSharp,
    /// TypeScript and TSX sources.
    TypeScript,
}

impl Language {
    /// Every supported language, in stable order.
    #[must_use]
    pub const fn all() -> &'static [Language] {
        &[Language::CSharp, Language::TypeScript]
    }

    /// Stable spelling used in keys, coverage and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CSharp => "csharp",
            Self::TypeScript => "typescript",
        }
    }

    /// Parse the stable spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::all().iter().copied().find(|l| l.as_str() == value)
    }

    /// File extensions handled by this language, without the dot.
    #[must_use]
    pub const fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::CSharp => &["cs"],
            Self::TypeScript => &["ts", "tsx", "mts", "cts"],
        }
    }

    /// The language of a portably relative path, if it has a known extension.
    #[must_use]
    pub fn from_path(path: &str) -> Option<Self> {
        let extension = path.rsplit_once('.').map(|(_, extension)| extension)?;
        let extension = extension.to_ascii_lowercase();
        Self::all()
            .iter()
            .copied()
            .find(|language| language.extensions().contains(&extension.as_str()))
    }
}

/// A parser adapter: a language plus the pinned parser build that handles it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterDescriptor {
    language: Language,
    grammar_id: String,
    parser_version: String,
    abi: u32,
}

impl AdapterDescriptor {
    /// Build a descriptor.
    #[must_use]
    pub fn new(
        language: Language,
        grammar_id: impl Into<String>,
        parser_version: impl Into<String>,
        abi: u32,
    ) -> Self {
        Self {
            language,
            grammar_id: grammar_id.into(),
            parser_version: parser_version.into(),
            abi,
        }
    }

    /// The language this adapter handles.
    #[must_use]
    pub const fn language(&self) -> Language {
        self.language
    }

    /// The pinned grammar id.
    #[must_use]
    pub fn grammar_id(&self) -> &str {
        &self.grammar_id
    }

    /// The pinned parser version.
    #[must_use]
    pub fn parser_version(&self) -> &str {
        &self.parser_version
    }

    /// The grammar ABI the adapter was built against.
    #[must_use]
    pub const fn abi(&self) -> u32 {
        self.abi
    }

    /// Whether this adapter handles the given path.
    #[must_use]
    pub fn handles(&self, path: &str) -> bool {
        Language::from_path(path) == Some(self.language)
    }
}

/// The parser adapter contract.
///
/// Implementors wrap one language front end. The trait deliberately exposes no
/// parse entry point yet: declaration extraction is defined per language by
/// tasks B-048/B-049, and the registry only needs to route and to declare what
/// it is compiled against.
pub trait ParserAdapter {
    /// The language and pinned parser this adapter uses.
    fn descriptor(&self) -> &AdapterDescriptor;

    /// Whether this adapter handles the given path.
    fn supports(&self, path: &str) -> bool {
        self.descriptor().handles(path)
    }
}

/// The descriptor-only adapter used when the grammar table is the source of
/// truth and no language-specific front end has been attached yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedAdapter {
    descriptor: AdapterDescriptor,
}

impl PinnedAdapter {
    /// Wrap a descriptor.
    #[must_use]
    pub fn new(descriptor: AdapterDescriptor) -> Self {
        Self { descriptor }
    }

    /// Build from a pinned grammar row.
    #[must_use]
    pub fn from_pinned(grammar: &PinnedGrammar) -> Self {
        Self::new(grammar.descriptor())
    }
}

impl ParserAdapter for PinnedAdapter {
    fn descriptor(&self) -> &AdapterDescriptor {
        &self.descriptor
    }
}

/// Why a path could not be routed to an adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedLanguage {
    /// The path that could not be routed.
    pub path: String,
    /// The lowercased extension, when the path had one.
    pub extension: Option<String>,
}

impl UnsupportedLanguage {
    /// Classify a path.
    #[must_use]
    pub fn new(path: &str) -> Self {
        let extension = path
            .rsplit_once('.')
            .map(|(_, extension)| extension.to_ascii_lowercase());
        Self {
            path: path.to_string(),
            extension,
        }
    }

    /// The coverage pattern recorded for this path.
    #[must_use]
    pub fn pattern(&self) -> String {
        match &self.extension {
            Some(extension) => format!("{REASON_UNKNOWN_LANGUAGE}:{extension}"),
            None => format!("{REASON_UNKNOWN_LANGUAGE}:<none>"),
        }
    }
}

/// The routing answer for one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LanguageSupport<'a> {
    /// An adapter handles this path.
    Supported(&'a AdapterDescriptor),
    /// No adapter handles this path; this is not an empty analysis.
    Unsupported(UnsupportedLanguage),
}

impl LanguageSupport<'_> {
    /// Whether an adapter handles the path.
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        matches!(self, Self::Supported(_))
    }
}

/// The set of adapters available to one analysis run.
pub struct ParserRegistry {
    adapters: Vec<Box<dyn ParserAdapter>>,
}

impl std::fmt::Debug for ParserRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParserRegistry")
            .field("languages", &self.languages())
            .finish()
    }
}

impl ParserRegistry {
    /// Build a registry, rejecting a duplicate adapter for one language.
    ///
    /// # Errors
    /// [`ErrorCode::Conflict`] with `duplicate-language` when two adapters claim
    /// the same language, and [`ErrorCode::ValidationError`] for an empty set.
    pub fn new(adapters: Vec<Box<dyn ParserAdapter>>) -> Result<Self, AxiomError> {
        if adapters.is_empty() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a parser registry must contain at least one adapter",
            )
            .with_detail("rule", REASON_UNKNOWN_LANGUAGE));
        }
        let mut seen: Vec<Language> = Vec::new();
        for adapter in &adapters {
            let language = adapter.descriptor().language();
            if seen.contains(&language) {
                return Err(AxiomError::new(
                    ErrorCode::Conflict,
                    "a parser registry must not contain two adapters for one language",
                )
                .with_detail("rule", REASON_DUPLICATE_LANGUAGE)
                .with_detail("actual", language.as_str()));
            }
            seen.push(language);
        }
        Ok(Self { adapters })
    }

    /// The adapters, in registration order.
    #[must_use]
    pub fn adapters(&self) -> &[Box<dyn ParserAdapter>] {
        &self.adapters
    }

    /// The languages this registry can analyse, in registration order.
    #[must_use]
    pub fn languages(&self) -> Vec<Language> {
        self.adapters
            .iter()
            .map(|adapter| adapter.descriptor().language())
            .collect()
    }

    /// The descriptor for a language, when one is registered.
    #[must_use]
    pub fn descriptor(&self, language: Language) -> Option<&AdapterDescriptor> {
        self.adapters
            .iter()
            .map(|adapter| adapter.descriptor())
            .find(|descriptor| descriptor.language() == language)
    }

    /// Route a portably relative path to its adapter.
    #[must_use]
    pub fn for_path(&self, path: &str) -> LanguageSupport<'_> {
        self.adapters
            .iter()
            .map(|adapter| adapter.descriptor())
            .find(|descriptor| descriptor.handles(path))
            .map_or_else(
                || LanguageSupport::Unsupported(UnsupportedLanguage::new(path)),
                LanguageSupport::Supported,
            )
    }

    /// Coverage for a path no adapter handles: `unsupported`, never
    /// `complete_for_profile` with zero files.
    #[must_use]
    pub fn coverage_for_unsupported(&self, path: &str) -> crate::Coverage {
        crate::Coverage::unsupported_language(path)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AdapterDescriptor, Language, LanguageSupport, ParserRegistry, PinnedAdapter,
        REASON_DUPLICATE_LANGUAGE, REASON_UNKNOWN_LANGUAGE,
    };
    use crate::grammar::GrammarSet;

    fn descriptor(language: Language) -> AdapterDescriptor {
        AdapterDescriptor::new(language, "test-grammar", "0.0.1", 14)
    }

    fn registry() -> ParserRegistry {
        ParserRegistry::new(vec![
            Box::new(PinnedAdapter::new(descriptor(Language::CSharp))),
            Box::new(PinnedAdapter::new(descriptor(Language::TypeScript))),
        ])
        .expect("registry")
    }

    #[test]
    fn supported_languages_and_versions_are_enumerated() {
        let registry = registry();
        assert_eq!(registry.languages(), Language::all().to_vec());
        for language in Language::all() {
            let descriptor = registry.descriptor(*language).expect("descriptor");
            assert_eq!(descriptor.language(), *language);
            assert!(!descriptor.parser_version().is_empty());
            assert!(!descriptor.grammar_id().is_empty());
        }
        assert_eq!(Language::parse("csharp"), Some(Language::CSharp));
        assert_eq!(Language::parse("CSharp"), None);
        assert_eq!(Language::parse("python"), None);
    }

    #[test]
    fn paths_route_to_their_language() {
        let registry = registry();
        assert!(matches!(
            registry.for_path("src/App/Foo.cs"),
            LanguageSupport::Supported(descriptor) if descriptor.language() == Language::CSharp
        ));
        assert!(matches!(
            registry.for_path("src/index.TSX"),
            LanguageSupport::Supported(descriptor) if descriptor.language() == Language::TypeScript
        ));
    }

    #[test]
    fn an_unknown_language_reports_unsupported_not_empty_complete() {
        let registry = registry();
        let support = registry.for_path("README.md");
        let LanguageSupport::Unsupported(unsupported) = support else {
            panic!("markdown must not be routed to an adapter");
        };
        assert_eq!(unsupported.extension.as_deref(), Some("md"));
        assert_eq!(
            unsupported.pattern(),
            format!("{REASON_UNKNOWN_LANGUAGE}:md")
        );

        let coverage = registry.coverage_for_unsupported("README.md");
        assert_eq!(coverage.status, crate::CoverageStatus::Unsupported);
        assert_eq!(coverage.input_files, 1);
        assert_eq!(coverage.processed_files, 0);
        assert_eq!(coverage.status.as_str(), "unsupported");
    }

    #[test]
    fn a_path_without_an_extension_is_unsupported_with_a_named_pattern() {
        let registry = registry();
        let LanguageSupport::Unsupported(unsupported) = registry.for_path("Makefile") else {
            panic!("no extension must not match");
        };
        assert_eq!(unsupported.extension, None);
        assert_eq!(
            unsupported.pattern(),
            format!("{REASON_UNKNOWN_LANGUAGE}:<none>")
        );
    }

    #[test]
    fn a_duplicate_language_is_rejected_before_any_analysis() {
        let error = ParserRegistry::new(vec![
            Box::new(PinnedAdapter::new(descriptor(Language::CSharp))),
            Box::new(PinnedAdapter::new(descriptor(Language::CSharp))),
        ])
        .expect_err("duplicate");
        assert_eq!(error.code(), graph_core::error::ErrorCode::Conflict);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_DUPLICATE_LANGUAGE)
        );
    }

    #[test]
    fn the_documented_default_registry_matches_the_pinned_grammar_table() {
        let set = GrammarSet::load_documented_default().expect("grammar set");
        let registry = set.registry().expect("registry");
        assert_eq!(
            registry.languages().len(),
            GrammarSet::documented_default().len()
        );
        for language in Language::all() {
            let descriptor = registry.descriptor(*language).expect("descriptor");
            let pinned = set.grammar(*language).expect("pinned grammar");
            assert_eq!(descriptor.parser_version(), pinned.version());
            assert_eq!(descriptor.abi(), crate::grammar::GRAMMAR_ABI_VERSION);
        }
    }
}
