//! Pinned grammar table and ABI gate (task B-046).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` requires the analysis result to be
//! attributable to an exact parser build. A grammar whose compiled ABI does not
//! match the ABI this build links against must fail *at startup or build*: if the
//! mismatch were tolerated, every declaration span and every identity key
//! produced afterwards would silently refer to a different language definition,
//! and a stable key would stop being stable without any error being raised.
//!
//! The table below is the authoritative pin. The byte-level integrity of the
//! pinned crate versions is proven by `Cargo.lock` (and by `cargo deny check`),
//! which is why this module does not carry a second, hand-maintained checksum
//! that could drift. [`GrammarSet::fingerprint`] is the deterministic digest of
//! the table itself and is recorded in evidence for each run.

use graph_core::error::{AxiomError, ErrorCode};

use crate::adapter::{AdapterDescriptor, Language, ParserRegistry, PinnedAdapter};
use crate::identity;

/// The grammar ABI this build links against.
///
/// tree-sitter's ABI is stable per major line; a grammar compiled against a
/// different ABI number must be rejected rather than interpreted.
pub const GRAMMAR_ABI_VERSION: u32 = 14;

/// Reason recorded when a grammar's ABI does not match this build.
pub const REASON_ABI_MISMATCH: &str = "grammar_abi_mismatch";
/// Reason recorded when a language has no pinned grammar.
pub const REASON_UNKNOWN_GRAMMAR: &str = "unknown_grammar";
/// Reason recorded when the pinned table is empty.
pub const REASON_EMPTY_GRAMMAR_TABLE: &str = "empty_grammar_table";

/// One pinned grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedGrammar {
    /// Language handled by this grammar.
    pub language: Language,
    /// Grammar id, matching the upstream crate name.
    pub grammar_id: &'static str,
    /// Pinned upstream version.
    pub version: &'static str,
    /// ABI the grammar is compiled against.
    pub abi: u32,
}

impl PinnedGrammar {
    /// The language handled by this grammar.
    #[must_use]
    pub const fn language(&self) -> Language {
        self.language
    }

    /// Grammar id.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.grammar_id
    }

    /// Pinned version.
    #[must_use]
    pub const fn version(&self) -> &'static str {
        self.version
    }

    /// Compiled ABI.
    #[must_use]
    pub const fn abi(&self) -> u32 {
        self.abi
    }

    /// The adapter descriptor for this grammar.
    #[must_use]
    pub fn descriptor(&self) -> AdapterDescriptor {
        AdapterDescriptor::new(self.language, self.grammar_id, self.version, self.abi)
    }

    /// Deterministic identity of this pin, used in the set fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        identity::digest(&[
            identity::IDENTITY_SCHEME_VERSION,
            self.language.as_str(),
            self.grammar_id,
            self.version,
            &self.abi.to_string(),
        ])
    }
}

/// The pinned grammar table.
pub const PINNED_GRAMMARS: &[PinnedGrammar] = &[
    PinnedGrammar {
        language: Language::CSharp,
        grammar_id: "tree-sitter-c-sharp",
        version: "0.23.1",
        abi: GRAMMAR_ABI_VERSION,
    },
    PinnedGrammar {
        language: Language::TypeScript,
        grammar_id: "tree-sitter-typescript",
        version: "0.23.2",
        abi: GRAMMAR_ABI_VERSION,
    },
];

/// A validated set of grammars.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrammarSet {
    grammars: Vec<PinnedGrammar>,
}

impl GrammarSet {
    /// Validate `grammars` against `compiled_abi`.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with `empty_grammar_table` for an empty
    /// table, and [`ErrorCode::IncompatibleInput`] with `grammar_abi_mismatch`
    /// when a grammar was compiled against a different ABI.
    pub fn load(grammars: &[PinnedGrammar], compiled_abi: u32) -> Result<Self, AxiomError> {
        if grammars.is_empty() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "the pinned grammar table must not be empty",
            )
            .with_detail("rule", REASON_EMPTY_GRAMMAR_TABLE));
        }
        for grammar in grammars {
            if grammar.abi != compiled_abi {
                return Err(AxiomError::new(
                    ErrorCode::IncompatibleInput,
                    "a pinned grammar was compiled against a different ABI",
                )
                .with_detail("rule", REASON_ABI_MISMATCH)
                .with_detail("expected", compiled_abi.to_string())
                .with_detail("actual", grammar.abi.to_string())
                .with_detail("config_key", grammar.grammar_id));
            }
        }
        let mut set = Self {
            grammars: grammars.to_vec(),
        };
        set.grammars
            .sort_unstable_by_key(|grammar| grammar.language);
        Ok(set)
    }

    /// Load the documented default table against this build's ABI.
    ///
    /// # Errors
    /// The errors of [`GrammarSet::load`]; the documented table is already
    /// consistent, so this fails only if the build itself is inconsistent, which
    /// is exactly the startup failure the task requires.
    pub fn load_documented_default() -> Result<Self, AxiomError> {
        Self::load(Self::documented_default(), GRAMMAR_ABI_VERSION)
    }

    /// The unvalidated documented default table.
    #[must_use]
    pub const fn documented_default() -> &'static [PinnedGrammar] {
        PINNED_GRAMMARS
    }

    /// The validated grammars, ordered by language.
    #[must_use]
    pub fn grammars(&self) -> &[PinnedGrammar] {
        &self.grammars
    }

    /// The grammar for a language, when pinned.
    #[must_use]
    pub fn grammar(&self, language: Language) -> Option<&PinnedGrammar> {
        self.grammars
            .iter()
            .find(|grammar| grammar.language == language)
    }

    /// Deterministic digest of the whole set.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let parts: Vec<String> = self
            .grammars
            .iter()
            .map(PinnedGrammar::fingerprint)
            .collect();
        let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
        identity::digest(&parts)
    }

    /// Build the registry for this grammar set.
    ///
    /// # Errors
    /// The errors of [`ParserRegistry::new`].
    pub fn registry(&self) -> Result<ParserRegistry, AxiomError> {
        let adapters = self
            .grammars
            .iter()
            .map(|grammar| {
                Box::new(PinnedAdapter::from_pinned(grammar))
                    as Box<dyn crate::adapter::ParserAdapter>
            })
            .collect();
        ParserRegistry::new(adapters)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GrammarSet, PinnedGrammar, GRAMMAR_ABI_VERSION, PINNED_GRAMMARS, REASON_ABI_MISMATCH,
        REASON_EMPTY_GRAMMAR_TABLE,
    };
    use crate::adapter::Language;
    use graph_core::error::ErrorCode;

    fn rule(error: &graph_core::error::AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    #[test]
    fn every_supported_language_has_one_pinned_grammar() {
        let set = GrammarSet::load_documented_default().expect("defaults");
        assert_eq!(set.grammars().len(), Language::all().len());
        for language in Language::all() {
            let grammar = set.grammar(*language).expect("pinned");
            assert_eq!(grammar.abi(), GRAMMAR_ABI_VERSION);
            assert!(!grammar.version().is_empty());
            assert!(!grammar.id().is_empty());
        }
    }

    #[test]
    fn the_build_is_deterministic() {
        let first = GrammarSet::load_documented_default().expect("defaults");
        let second = GrammarSet::load_documented_default().expect("defaults");
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first, second);
        // Re-ordering the input table must not change the set or its fingerprint.
        let reversed: Vec<PinnedGrammar> = PINNED_GRAMMARS.iter().rev().copied().collect();
        let reordered = GrammarSet::load(&reversed, GRAMMAR_ABI_VERSION).expect("reordered");
        assert_eq!(reordered, first);
        assert_eq!(reordered.fingerprint(), first.fingerprint());
    }

    #[test]
    fn an_incompatible_grammar_abi_fails_before_any_analysis() {
        let error = GrammarSet::load(PINNED_GRAMMARS, GRAMMAR_ABI_VERSION + 1)
            .expect_err("ABI mismatch must fail at startup");
        assert_eq!(error.code(), ErrorCode::IncompatibleInput);
        assert_eq!(rule(&error), Some(REASON_ABI_MISMATCH));
        assert_eq!(
            error.details().get("expected").map(String::as_str),
            Some((GRAMMAR_ABI_VERSION + 1).to_string().as_str())
        );
    }

    #[test]
    fn a_single_mismatched_grammar_is_enough_to_fail_the_set() {
        let mut table = PINNED_GRAMMARS.to_vec();
        let mismatched = PinnedGrammar {
            abi: GRAMMAR_ABI_VERSION + 2,
            ..PINNED_GRAMMARS[0]
        };
        table[0] = mismatched;
        let error = GrammarSet::load(&table, GRAMMAR_ABI_VERSION).expect_err("one bad row fails");
        assert_eq!(rule(&error), Some(REASON_ABI_MISMATCH));
    }

    #[test]
    fn an_empty_table_is_rejected() {
        let error = GrammarSet::load(&[], GRAMMAR_ABI_VERSION).expect_err("empty");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(rule(&error), Some(REASON_EMPTY_GRAMMAR_TABLE));
    }
}
