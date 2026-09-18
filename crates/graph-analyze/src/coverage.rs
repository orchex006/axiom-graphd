//! Parse failures and per-file coverage (task B-056).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 4 is the contract: a parse
//! error must not crash the daemon, an editor's mid-save write must be detected
//! instead of parsed, and a retained last-known-good extract must be marked
//! `stale_for_file` so no consumer can mistake the old graph for fresh. Files
//! that are binary, oversized or not valid UTF-8 are skipped with a named
//! reason and lower the coverage status rather than producing nothing and
//! calling that complete.
//!
//! The report aggregates into the frozen [`crate::Coverage`] vocabulary, which
//! is the shape published by `contracts/schemas/coverage.schema.json`.

use std::collections::BTreeSet;

use crate::{Coverage, Diagnostic, Severity};

/// Reason recorded when a file could not be parsed.
pub const REASON_PARSE_ERROR: &str = "file-parse-error";
/// Reason recorded when a read changed between the before/after probes.
pub const REASON_UNSTABLE_READ: &str = "file-unstable-read";
/// Reason recorded for a file that is not valid UTF-8.
pub const REASON_INVALID_ENCODING: &str = "file-invalid-encoding";
/// Reason recorded for a binary file.
pub const REASON_BINARY: &str = "file-binary";
/// Reason recorded for a file beyond the configured limit.
pub const REASON_TOO_LARGE: &str = "file-too-large";
/// Reason recorded for generated or build output that is ignored by default.
pub const REASON_IGNORED_GENERATED: &str = "file-ignored-generated";
/// Reason recorded for a file whose extract is retained from an earlier parse.
pub const REASON_RETAINED: &str = "file-retained-last-known-good";

/// What happened to one file during analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileOutcome {
    /// The file parsed and its facts are current.
    Fresh {
        /// Number of facts produced.
        facts: usize,
    },
    /// The file failed to parse.
    ParseError {
        /// Facts retained from the last good parse, if any.
        retained_facts: usize,
    },
    /// The file was skipped before parsing, with a named reason.
    Skipped {
        /// One of the `REASON_*` skip constants.
        reason: String,
    },
}

impl FileOutcome {
    /// Whether this outcome may be published as fresh.
    #[must_use]
    pub const fn claims_fresh(&self) -> bool {
        matches!(self, Self::Fresh { .. })
    }

    /// Stable spelling of the outcome kind.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Fresh { .. } => "fresh",
            Self::ParseError { .. } => "parse_error",
            Self::Skipped { .. } => "skipped",
        }
    }
}

/// The per-file report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReport {
    /// Portably relative file path.
    pub file: String,
    /// What happened.
    pub outcome: FileOutcome,
    /// Diagnostics attached to the file.
    pub diagnostics: Vec<Diagnostic>,
    /// Digest of the parse the facts were produced from, when there is one.
    pub parsed_digest: Option<String>,
    /// Digest of the latest observed write, when a read was attempted.
    pub observed_digest: Option<String>,
    /// Whether the published facts for this file are older than the observed
    /// write. A retained extract always sets this.
    pub stale_for_file: bool,
}

impl FileReport {
    /// Whether the file may be published as fresh.
    #[must_use]
    pub const fn claims_fresh(&self) -> bool {
        self.outcome.claims_fresh() && !self.stale_for_file
    }

    /// Reason codes attached to this file, sorted and deduplicated.
    #[must_use]
    pub fn reason_codes(&self) -> Vec<String> {
        let mut codes = BTreeSet::new();
        for diagnostic in &self.diagnostics {
            if diagnostic.severity == Severity::Error {
                codes.insert(diagnostic.code.clone());
            }
        }
        if let FileOutcome::Skipped { reason } = &self.outcome {
            codes.insert(reason.clone());
        }
        if self.stale_for_file {
            codes.insert(REASON_RETAINED.to_string());
        }
        codes.into_iter().collect()
    }
}

/// A whole-run coverage report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoverageReport {
    files: Vec<FileReport>,
}

impl CoverageReport {
    /// An empty report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a file that parsed cleanly.
    pub fn record_fresh(
        &mut self,
        file: impl Into<String>,
        digest: impl Into<String>,
        facts: usize,
    ) -> &FileReport {
        self.push(FileReport {
            file: file.into(),
            outcome: FileOutcome::Fresh { facts },
            diagnostics: Vec::new(),
            parsed_digest: Some(digest.into()),
            observed_digest: None,
            stale_for_file: false,
        })
    }

    /// Record a parse error, optionally retaining a last-known-good digest.
    pub fn record_parse_error(
        &mut self,
        file: impl Into<String>,
        observed_digest: Option<String>,
        error: Diagnostic,
        retained_digest: Option<String>,
        retained_facts: usize,
    ) -> &FileReport {
        let stale = retained_digest.is_some();
        self.push(FileReport {
            file: file.into(),
            outcome: FileOutcome::ParseError { retained_facts },
            diagnostics: vec![error],
            parsed_digest: retained_digest,
            observed_digest,
            stale_for_file: stale,
        })
    }

    /// Record a read that changed between the before/after probes.
    pub fn record_unstable_read(
        &mut self,
        file: impl Into<String>,
        before_digest: String,
        after_digest: String,
    ) -> &FileReport {
        let error = Diagnostic::error(
            REASON_UNSTABLE_READ,
            "the file changed between the before and after read probes; the write is treated as transient",
            crate::Span::new(0, 0),
        );
        self.push(FileReport {
            file: file.into(),
            outcome: FileOutcome::ParseError { retained_facts: 0 },
            diagnostics: vec![error],
            parsed_digest: Some(before_digest),
            observed_digest: Some(after_digest),
            stale_for_file: true,
        })
    }

    /// Record a skipped file with a named reason.
    pub fn record_skipped(
        &mut self,
        file: impl Into<String>,
        reason: impl Into<String>,
    ) -> &FileReport {
        self.push(FileReport {
            file: file.into(),
            outcome: FileOutcome::Skipped {
                reason: reason.into(),
            },
            diagnostics: Vec::new(),
            parsed_digest: None,
            observed_digest: None,
            stale_for_file: false,
        })
    }

    fn push(&mut self, report: FileReport) -> &FileReport {
        self.files.push(report);
        self.files.last().expect("just pushed")
    }

    /// Every file report, in insertion order.
    #[must_use]
    pub fn files(&self) -> &[FileReport] {
        &self.files
    }

    /// Files whose published facts are stale.
    #[must_use]
    pub fn stale_files(&self) -> Vec<&str> {
        self.files
            .iter()
            .filter(|report| report.stale_for_file)
            .map(|report| report.file.as_str())
            .collect()
    }

    /// Files that failed to parse.
    #[must_use]
    pub fn parse_error_files(&self) -> Vec<&str> {
        self.files
            .iter()
            .filter(|report| matches!(report.outcome, FileOutcome::ParseError { .. }))
            .map(|report| report.file.as_str())
            .collect()
    }

    /// Aggregate into the frozen coverage vocabulary.
    ///
    /// Any parse error, stale extract or skip means `partial`; only a run in
    /// which every selected input is fresh may claim completeness.
    #[must_use]
    pub fn coverage(&self) -> Coverage {
        let input_files = self.files.len();
        let processed_files = self
            .files
            .iter()
            .filter(|report| report.claims_fresh())
            .count();
        let unresolved_references = self
            .files
            .iter()
            .flat_map(|report| report.diagnostics.iter())
            .filter(|diagnostic| diagnostic.severity == Severity::Error)
            .count();
        let mut patterns = BTreeSet::new();
        for report in &self.files {
            for code in report.reason_codes() {
                patterns.insert(code);
            }
        }
        if processed_files == input_files {
            return Coverage::complete_for_profile(input_files, unresolved_references);
        }
        Coverage::partial(
            input_files,
            processed_files,
            unresolved_references,
            patterns.into_iter().collect(),
        )
    }

    /// The invariant this task exists for: a run with any parse error, stale
    /// extract or skip never claims completeness.
    #[must_use]
    pub fn is_honest(&self) -> bool {
        let any_unusable = self.files.iter().any(|report| !report.claims_fresh());
        let coverage = self.coverage();
        if any_unusable {
            !coverage.claims_completeness()
        } else {
            coverage.claims_completeness()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CoverageReport, FileOutcome, REASON_BINARY, REASON_IGNORED_GENERATED, REASON_PARSE_ERROR,
        REASON_RETAINED, REASON_TOO_LARGE, REASON_UNSTABLE_READ,
    };
    use crate::{Diagnostic, Severity, Span};

    fn parse_error() -> Diagnostic {
        Diagnostic::error(
            REASON_PARSE_ERROR,
            "unexpected end of file",
            Span::new(4, 5),
        )
    }

    #[test]
    fn a_parse_error_with_a_retained_extract_is_stale_and_never_fresh() {
        let mut report = CoverageReport::new();
        report.record_parse_error(
            "src/Broken.cs",
            Some("new".to_string()),
            parse_error(),
            Some("old".to_string()),
            7,
        );
        let file = &report.files()[0];
        assert!(file.stale_for_file);
        assert!(!file.claims_fresh());
        assert_eq!(file.parsed_digest.as_deref(), Some("old"));
        assert_eq!(file.observed_digest.as_deref(), Some("new"));
        assert_eq!(
            file.reason_codes(),
            vec![REASON_PARSE_ERROR.to_string(), REASON_RETAINED.to_string()]
        );
        assert!(!report.coverage().claims_completeness());
        assert!(report.is_honest());
    }

    #[test]
    fn a_parse_error_does_not_crash_and_still_reports_partial() {
        let mut report = CoverageReport::new();
        report.record_parse_error(
            "src/Broken.cs",
            Some("d".to_string()),
            parse_error(),
            None,
            0,
        );
        let file = &report.files()[0];
        assert!(!file.stale_for_file);
        assert!(!file.claims_fresh());
        assert!(matches!(file.outcome, FileOutcome::ParseError { .. }));
        let coverage = report.coverage();
        assert_eq!(coverage.status.as_str(), "partial");
        assert_eq!(coverage.input_files, 1);
        assert_eq!(coverage.processed_files, 0);
    }

    #[test]
    fn an_unstable_read_is_reported_as_transient_not_as_parsed_content() {
        let mut report = CoverageReport::new();
        report.record_unstable_read("src/Saving.ts", "before".to_string(), "after".to_string());
        let file = &report.files()[0];
        assert!(file.stale_for_file);
        assert!(!file.claims_fresh());
        assert!(file
            .reason_codes()
            .contains(&REASON_UNSTABLE_READ.to_string()));
        assert!(!report.coverage().claims_completeness());
    }

    #[test]
    fn skipped_binary_oversized_and_generated_files_keep_named_reasons() {
        let mut report = CoverageReport::new();
        report.record_skipped("assets/logo.png", REASON_BINARY);
        report.record_skipped("huge.log", REASON_TOO_LARGE);
        report.record_skipped("obj/Debug/Generated.cs", REASON_IGNORED_GENERATED);
        let coverage = report.coverage();
        assert!(!coverage.claims_completeness());
        assert_eq!(coverage.processed_files, 0);
        for reason in [REASON_BINARY, REASON_TOO_LARGE, REASON_IGNORED_GENERATED] {
            assert!(coverage.unsupported_patterns.contains(&reason.to_string()));
        }
    }

    #[test]
    fn only_a_fully_fresh_run_claims_completeness() {
        let mut report = CoverageReport::new();
        report.record_fresh("src/A.cs", "d1", 3);
        report.record_fresh("src/B.ts", "d2", 4);
        let coverage = report.coverage();
        assert!(coverage.claims_completeness());
        assert_eq!(coverage.input_files, 2);
        assert_eq!(coverage.processed_files, 2);
        assert!(report.is_honest());

        report.record_skipped("src/C.bin", REASON_BINARY);
        let coverage = report.coverage();
        assert_eq!(coverage.status.as_str(), "partial");
        assert_eq!(coverage.processed_files, 2);
        assert!(report.is_honest());
    }

    #[test]
    fn error_diagnostics_increase_the_unresolved_count() {
        let mut report = CoverageReport::new();
        report.record_parse_error("src/A.cs", None, parse_error(), None, 0);
        let coverage = report.coverage();
        assert_eq!(coverage.unresolved_references, 1);
        assert!(report.files()[0]
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.severity == Severity::Error));
    }
}
