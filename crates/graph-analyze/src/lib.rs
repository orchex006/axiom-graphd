//! Static analysis for the Axiom graph engine (`axiom-graphd`).
//!
//! This crate owns the syntax-and-project-analysis work package (B-045 - B-066)
//! and the coverage vocabulary of `contracts/schemas/coverage.schema.json`:
//!
//! * B-045 ([`adapter`]) - the language registry and parser adapter contract.
//! * B-046 ([`grammar`]) - the pinned grammar table and its ABI gate.
//! * B-047 ([`project_manifests`]) - `csproj`/`package.json` project facts.
//! * B-048 ([`csharp`]) - C# declarations with source spans and diagnostics.
//! * B-049 ([`typescript`]) - TypeScript declarations with explicit identity
//!   quality for anonymous and computed names.
//! * B-050 ([`identity`]) - canonical length-delimited symbol identity.
//! * B-051 ([`imports`]) - within-project literal import resolution.
//! * B-052 ([`calls`]) - conservative call-site evidence with explicit
//!   dynamic-dispatch handling.
//! * B-053 ([`types`]) - inheritance and interface facts from explicit
//!   declarations.
//! * B-054 ([`incremental`]) - owner-scoped incremental file replacement.
//! * B-055 ([`invalidation`]) - exported-signature invalidation propagation.
//! * B-056 ([`coverage`]) - per-file parse failure and coverage reporting.
//! * L3 adapters ([`l3`]) - B-057 - B-066 literal route, SQL, mapping,
//!   messaging, manifest, annotation and report extraction.
//!
//! Two rules shape every module here.
//!
//! First, the analyser must never confuse "we found nothing" with "we could not
//! look". An unknown language, an unparsed construct and a value that needs code
//! execution are all reported as such, with a reason, and they lower the coverage
//! status instead of silently producing an empty complete result.
//!
//! Second, a symbol key must be reproducible. Keys come from
//! [`identity::declaration_key`] over length-delimited tuples, so an unchanged
//! symbol keeps its id across runs and a renamed one does not silently collide
//! with its neighbour.

pub mod adapter;
pub mod calls;
pub mod coverage;
pub mod csharp;
pub mod grammar;
pub mod identity;
pub mod imports;
pub mod incremental;
pub mod invalidation;
pub mod l3;
pub mod project_manifests;
pub mod types;
pub mod typescript;

use serde::{Deserialize, Serialize};

/// The `status` vocabulary of `contracts/schemas/coverage.schema.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    /// Every input file in the profile was analysed.
    CompleteForProfile,
    /// Some inputs were analysed and some were not; the counts say which.
    Partial,
    /// The profile cannot be analysed by this build at all.
    Unsupported,
}

impl CoverageStatus {
    /// Every status, in schema order.
    #[must_use]
    pub const fn all() -> &'static [CoverageStatus] {
        &[
            CoverageStatus::CompleteForProfile,
            CoverageStatus::Partial,
            CoverageStatus::Unsupported,
        ]
    }

    /// Stable spelling, matching the schema enum.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompleteForProfile => "complete_for_profile",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
        }
    }

    /// Parse the stable spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::all().iter().copied().find(|s| s.as_str() == value)
    }

    /// Whether this status claims the profile was fully understood.
    #[must_use]
    pub const fn claims_completeness(self) -> bool {
        matches!(self, Self::CompleteForProfile)
    }
}

/// A coverage report, shaped exactly like `coverage.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// Overall status.
    pub status: CoverageStatus,
    /// Files the profile selected as input.
    pub input_files: usize,
    /// Files whose facts were produced.
    pub processed_files: usize,
    /// References that could not be resolved to a target.
    pub unresolved_references: usize,
    /// Named patterns this build could not analyse.
    pub unsupported_patterns: Vec<String>,
}

impl Coverage {
    /// A complete analysis of `input_files` files.
    #[must_use]
    pub fn complete_for_profile(input_files: usize, unresolved_references: usize) -> Self {
        Self {
            status: CoverageStatus::CompleteForProfile,
            input_files,
            processed_files: input_files,
            unresolved_references,
            unsupported_patterns: Vec::new(),
        }
    }

    /// A partial analysis; the counts must agree with the status.
    #[must_use]
    pub fn partial(
        input_files: usize,
        processed_files: usize,
        unresolved_references: usize,
        unsupported_patterns: Vec<String>,
    ) -> Self {
        Self {
            status: CoverageStatus::Partial,
            input_files,
            processed_files,
            unresolved_references,
            unsupported_patterns,
        }
    }

    /// An unsupported input: one selected file, zero processed, with the reason.
    ///
    /// This constructor is the guard against the failure mode the analysis work
    /// package calls out: an unknown language must never be reported as a
    /// complete analysis of zero facts.
    #[must_use]
    pub fn unsupported_language(path: &str) -> Self {
        Self {
            status: CoverageStatus::Unsupported,
            input_files: 1,
            processed_files: 0,
            unresolved_references: 0,
            unsupported_patterns: vec![adapter::UnsupportedLanguage::new(path).pattern()],
        }
    }

    /// Whether the report claims the profile was fully understood.
    #[must_use]
    pub const fn claims_completeness(&self) -> bool {
        self.status.claims_completeness()
    }

    /// Whether the counts are self-consistent with the status.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        match self.status {
            CoverageStatus::CompleteForProfile => {
                self.processed_files == self.input_files && self.unsupported_patterns.is_empty()
            }
            CoverageStatus::Partial => self.processed_files < self.input_files,
            CoverageStatus::Unsupported => self.processed_files == 0,
        }
    }
}

/// A half-open byte range inside one source document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Span {
    /// Inclusive start byte offset.
    pub start: usize,
    /// Exclusive end byte offset.
    pub end: usize,
}

impl Span {
    /// Build a span.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Number of bytes covered.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether the span covers no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The covered text, or `None` when the span does not lie inside `source`.
    #[must_use]
    pub fn slice<'a>(&self, source: &'a str) -> Option<&'a str> {
        source.get(self.start..self.end)
    }

    /// One-based line number of the span start.
    #[must_use]
    pub fn line(&self, source: &str) -> usize {
        source.as_bytes().get(..self.start).map_or(1, |prefix| {
            prefix.iter().filter(|byte| **byte == b'\n').count() + 1
        })
    }
}

/// Severity of an analysis diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// The construct could not be understood; coverage must not claim it.
    Error,
    /// The construct was understood but something is unusual.
    Warning,
}

/// One analysis diagnostic, always carrying a span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Stable, greppable code, e.g. `csharp-missing-name`.
    pub code: String,
    /// Severity.
    pub severity: Severity,
    /// Human-readable explanation.
    pub message: String,
    /// Where in the source the problem is.
    pub span: Span,
}

impl Diagnostic {
    /// Build an error diagnostic.
    #[must_use]
    pub fn error(code: impl Into<String>, message: impl Into<String>, span: Span) -> Self {
        Self {
            code: code.into(),
            severity: Severity::Error,
            message: message.into(),
            span,
        }
    }

    /// Build a warning diagnostic.
    #[must_use]
    pub fn warning(code: impl Into<String>, message: impl Into<String>, span: Span) -> Self {
        Self {
            code: code.into(),
            severity: Severity::Warning,
            message: message.into(),
            span,
        }
    }
}

/// Byte offset at the start of every line in `source`.
#[must_use]
pub fn line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0_usize];
    for (index, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(index + 1);
        }
    }
    starts
}

/// Byte span of line `line` (zero-based), excluding the line terminator.
#[must_use]
pub fn line_span(source: &str, starts: &[usize], line: usize) -> Span {
    let Some(start) = starts.get(line).copied() else {
        return Span::new(source.len(), source.len());
    };
    let end = starts
        .get(line + 1)
        .map_or(source.len(), |next| next.saturating_sub(1))
        .min(source.len());
    Span::new(start, end.max(start))
}

#[cfg(test)]
mod tests {
    use super::{line_span, line_starts, Coverage, CoverageStatus, Severity, Span};

    #[test]
    fn the_status_vocabulary_matches_the_contract_schema() {
        let spellings: Vec<&str> = CoverageStatus::all().iter().map(|s| s.as_str()).collect();
        assert_eq!(
            spellings,
            vec!["complete_for_profile", "partial", "unsupported"]
        );
        for status in CoverageStatus::all() {
            assert_eq!(CoverageStatus::parse(status.as_str()), Some(*status));
        }
        assert_eq!(CoverageStatus::parse("complete"), None);
    }

    #[test]
    fn an_unsupported_language_never_claims_completeness() {
        let coverage = Coverage::unsupported_language("README.md");
        assert!(!coverage.claims_completeness());
        assert!(coverage.is_consistent());
        assert_eq!(coverage.input_files, 1);
        assert_eq!(coverage.processed_files, 0);
        assert_eq!(coverage.unresolved_references, 0);
        assert_eq!(coverage.unsupported_patterns.len(), 1);
    }

    #[test]
    fn coverage_consistency_is_enforced_by_construction() {
        assert!(Coverage::complete_for_profile(4, 2).is_consistent());
        assert!(Coverage::partial(4, 3, 1, vec!["tsx-jsx".to_string()]).is_consistent());
        assert!(!Coverage::partial(4, 4, 0, Vec::new()).is_consistent());
        assert!(!Coverage::unsupported_language("x.bin").claims_completeness());
    }

    #[test]
    fn spans_slice_the_source_and_report_one_based_lines() {
        let source = "one\ntwo\nthree";
        let starts = line_starts(source);
        assert_eq!(starts, vec![0, 4, 8]);
        let span = line_span(source, &starts, 1);
        assert_eq!(span.slice(source), Some("two"));
        assert_eq!(span.line(source), 2);
        let span = line_span(source, &starts, 2);
        assert_eq!(span.slice(source), Some("three"));
        assert_eq!(span.line(source), 3);
        let missing = line_span(source, &starts, 9);
        assert!(missing.is_empty());
        let outside = Span::new(100, 900);
        assert_eq!(outside.slice(source), None);
    }

    #[test]
    fn diagnostics_keep_their_severity_and_span() {
        let error = super::Diagnostic::error("x", "boom", Span::new(1, 2));
        assert_eq!(error.severity, Severity::Error);
        let warning = super::Diagnostic::warning("y", "hmm", Span::new(3, 4));
        assert_eq!(warning.severity, Severity::Warning);
    }
}
