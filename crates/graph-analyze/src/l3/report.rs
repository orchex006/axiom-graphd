//! Per-rule coverage report for the level-3 adapters (task B-066).
//!
//! `docs/15-STATIC-ANALYSIS-COVERAGE.md` section 3 requires coverage to say
//! *which* patterns produced facts and *which* the build could not analyse. A
//! single "we found nothing" number cannot express that, so this report keeps a
//! row per pattern with three separate counts, and it refuses to turn zero
//! findings into a completeness claim:
//!
//! * `analysed` - inputs the rule read successfully;
//! * `unsupported` - inputs the rule refused, with their reasons;
//! * `findings` - facts the rule published.
//!
//! A rule that was never exercised reports [`RuleStatus::NotExercised`] and the
//! report as a whole cannot claim `complete_for_profile` while any row is
//! anything other than [`RuleStatus::Analysed`]. "No findings" is never read as
//! "the architecture has no such relation".

use crate::{CoverageStatus, Diagnostic, Span};

/// Pattern id for a rule that was never exercised.
pub const PATTERN_NOT_EXERCISED: &str = "coverage-rule-not-exercised";
/// Pattern id for a rule that refused at least one input.
pub const PATTERN_UNSUPPORTED_INPUTS: &str = "coverage-rule-unsupported-inputs";
/// Pattern id for a row whose findings exceed the inputs it analysed.
pub const PATTERN_INCONSISTENT_COUNTS: &str = "coverage-inconsistent-counts";

/// Reason recorded when a rule saw no input at all.
pub const REASON_NOT_EXERCISED: &str = "coverage-not-exercised";
/// Reason recorded when a rule could not analyse some of its inputs.
pub const REASON_UNSUPPORTED_INPUTS: &str = "coverage-unsupported-inputs";
/// Reason recorded when a row's findings exceed its analysed inputs.
pub const REASON_INCONSISTENT_COUNTS: &str = "coverage-findings-exceed-analysed";

/// How far one rule got with the inputs it saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleStatus {
    /// Every input was analysed.
    Analysed,
    /// Some inputs were analysed and some were refused.
    PartiallyAnalysed,
    /// Every input the rule saw was refused.
    Unsupported,
    /// The rule saw no input, so it proves nothing either way.
    NotExercised,
}

impl RuleStatus {
    /// Stable snake_case spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Analysed => "analysed",
            Self::PartiallyAnalysed => "partially_analysed",
            Self::Unsupported => "unsupported",
            Self::NotExercised => "not_exercised",
        }
    }

    /// Whether this status lets the rule contribute to a completeness claim.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Analysed)
    }
}

/// One row of the per-rule coverage report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCoverage {
    /// The `PATTERN_*` id of the rule.
    pub rule_id: String,
    /// Version of the pattern definition that ran.
    pub pattern_version: String,
    /// Inputs this rule analysed successfully.
    pub analysed: usize,
    /// Inputs this rule refused.
    pub unsupported: usize,
    /// Facts this rule published.
    pub findings: usize,
}

impl RuleCoverage {
    /// Build a row from its three independent counts.
    #[must_use]
    pub fn new(
        rule_id: impl Into<String>,
        pattern_version: impl Into<String>,
        analysed: usize,
        unsupported: usize,
        findings: usize,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            pattern_version: pattern_version.into(),
            analysed,
            unsupported,
            findings,
        }
    }

    /// The rule's status, derived from the separate counts.
    #[must_use]
    pub const fn status(&self) -> RuleStatus {
        match (self.analysed, self.unsupported) {
            (0, 0) => RuleStatus::NotExercised,
            (0, _) => RuleStatus::Unsupported,
            (_, 0) => RuleStatus::Analysed,
            (_, _) => RuleStatus::PartiallyAnalysed,
        }
    }

    /// Whether the rule saw any input at all.
    #[must_use]
    pub const fn is_exercised(&self) -> bool {
        self.analysed > 0 || self.unsupported > 0
    }

    /// Whether the row's counts are internally consistent.
    #[must_use]
    pub const fn is_consistent(&self) -> bool {
        self.findings <= self.analysed
    }

    /// Every input this rule saw, analysed or refused.
    #[must_use]
    pub const fn inputs(&self) -> usize {
        self.analysed + self.unsupported
    }
}

/// The per-rule coverage report of one analysis profile.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoverageReport {
    /// One row per rule, in caller order.
    pub rules: Vec<RuleCoverage>,
    /// Diagnostics attached to the report.
    pub diagnostics: Vec<Diagnostic>,
}

impl CoverageReport {
    /// An empty report; it proves nothing and claims nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a row.
    pub fn push(&mut self, row: RuleCoverage) {
        self.rules.push(row);
    }

    /// Rows that analysed at least one input and refused none.
    #[must_use]
    pub fn supported_rules(&self) -> Vec<&RuleCoverage> {
        self.rules
            .iter()
            .filter(|row| row.status() == RuleStatus::Analysed)
            .collect()
    }

    /// Rows that refused at least one input.
    #[must_use]
    pub fn unsupported_rules(&self) -> Vec<&RuleCoverage> {
        self.rules
            .iter()
            .filter(|row| row.unsupported > 0)
            .collect()
    }

    /// Rules that saw no input, so they prove nothing.
    #[must_use]
    pub fn unexercised_rules(&self) -> Vec<&str> {
        self.rules
            .iter()
            .filter(|row| !row.is_exercised())
            .map(|row| row.rule_id.as_str())
            .collect()
    }

    /// Total inputs analysed across every rule.
    #[must_use]
    pub fn total_analysed(&self) -> usize {
        self.rules.iter().map(|row| row.analysed).sum()
    }

    /// Total inputs refused across every rule.
    #[must_use]
    pub fn total_unsupported(&self) -> usize {
        self.rules.iter().map(|row| row.unsupported).sum()
    }

    /// Total findings across every rule.
    #[must_use]
    pub fn total_findings(&self) -> usize {
        self.rules.iter().map(|row| row.findings).sum()
    }

    /// Whether every row's counts are internally consistent.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.rules.iter().all(RuleCoverage::is_consistent)
    }

    /// The overall coverage status.
    ///
    /// Only a report in which every row analysed every input it saw, and in
    /// which at least one row actually ran, may claim completeness. An empty
    /// report and a report of never-exercised rules both stay `unsupported`.
    #[must_use]
    pub fn status(&self) -> CoverageStatus {
        if self.rules.is_empty() || self.rules.iter().all(|row| !row.is_exercised()) {
            return CoverageStatus::Unsupported;
        }
        if self
            .rules
            .iter()
            .all(|row| row.status() == RuleStatus::Analysed)
        {
            return CoverageStatus::CompleteForProfile;
        }
        CoverageStatus::Partial
    }

    /// Whether this report may describe the architecture as complete.
    ///
    /// Zero findings is never enough: the report must have exercised every
    /// rule, refused nothing, and published at least one fact.
    #[must_use]
    pub fn claims_complete_architecture(&self) -> bool {
        self.status() == CoverageStatus::CompleteForProfile && self.total_findings() > 0
    }

    /// Diagnostics for rows whose counts cannot be trusted.
    #[must_use]
    pub fn inconsistencies(&self) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        for row in &self.rules {
            if !row.is_consistent() {
                out.push(Diagnostic::error(
                    PATTERN_INCONSISTENT_COUNTS,
                    format!(
                        "rule {} published {} findings from {} analysed inputs",
                        row.rule_id, row.findings, row.analysed
                    ),
                    Span::new(0, 0),
                ));
            }
        }
        out
    }

    /// One diagnostic per rule that proves nothing or refused inputs.
    #[must_use]
    pub fn coverage_notes(&self) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        for row in &self.rules {
            if !row.is_exercised() {
                out.push(Diagnostic::warning(
                    PATTERN_NOT_EXERCISED,
                    format!("rule {} was not exercised; it proves nothing", row.rule_id),
                    Span::new(0, 0),
                ));
            } else if row.unsupported > 0 {
                out.push(Diagnostic::warning(
                    PATTERN_UNSUPPORTED_INPUTS,
                    format!(
                        "rule {} refused {} of {} inputs",
                        row.rule_id,
                        row.unsupported,
                        row.inputs()
                    ),
                    Span::new(0, 0),
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CoverageReport, RuleCoverage, RuleStatus, PATTERN_NOT_EXERCISED,
        PATTERN_UNSUPPORTED_INPUTS, REASON_NOT_EXERCISED, REASON_UNSUPPORTED_INPUTS,
    };
    use crate::CoverageStatus;

    #[test]
    fn supported_and_unsupported_counts_stay_separate() {
        let mut report = CoverageReport::new();
        report.push(RuleCoverage::new("aspnet-http-route", "1", 3, 0, 3));
        report.push(RuleCoverage::new(
            "angular-http-literal-route",
            "1",
            2,
            1,
            1,
        ));
        assert_eq!(report.supported_rules().len(), 1);
        assert_eq!(report.unsupported_rules().len(), 1);
        assert_eq!(report.total_analysed(), 5);
        assert_eq!(report.total_unsupported(), 1);
        assert_eq!(report.total_findings(), 4);
        assert_eq!(report.status(), CoverageStatus::Partial);
        assert!(!report.claims_complete_architecture());
        assert_eq!(
            report.unsupported_rules()[0].status(),
            RuleStatus::PartiallyAnalysed
        );
    }

    #[test]
    fn zero_findings_never_means_the_architecture_is_complete() {
        let mut report = CoverageReport::new();
        report.push(RuleCoverage::new("sql-literal-statement", "1", 0, 0, 0));
        assert_eq!(report.status(), CoverageStatus::Unsupported);
        assert!(!report.claims_complete_architecture());
        assert_eq!(report.unexercised_rules(), vec!["sql-literal-statement"]);
        assert_eq!(report.rules[0].status(), RuleStatus::NotExercised);

        // Even a fully analysed profile with no findings cannot claim the
        // architecture is complete.
        let mut quiet = CoverageReport::new();
        quiet.push(RuleCoverage::new("manifest-image", "1", 4, 0, 0));
        assert_eq!(quiet.status(), CoverageStatus::CompleteForProfile);
        assert!(!quiet.claims_complete_architecture());
    }

    #[test]
    fn every_rule_analysed_is_the_only_complete_for_profile_case() {
        let mut report = CoverageReport::new();
        report.push(RuleCoverage::new("aspnet-http-route", "1", 2, 0, 2));
        report.push(RuleCoverage::new("minimal-api-route", "1", 1, 0, 1));
        assert_eq!(report.status(), CoverageStatus::CompleteForProfile);
        assert!(report.claims_complete_architecture());
        assert!(report.unexercised_rules().is_empty());
        assert!(report.is_consistent());
    }

    #[test]
    fn an_empty_report_proves_nothing() {
        let report = CoverageReport::new();
        assert_eq!(report.status(), CoverageStatus::Unsupported);
        assert!(!report.claims_complete_architecture());
        assert_eq!(report.total_analysed(), 0);
    }

    #[test]
    fn findings_exceeding_analysed_inputs_are_flagged() {
        let mut report = CoverageReport::new();
        report.push(RuleCoverage::new("edge-join", "1", 1, 0, 3));
        assert!(!report.is_consistent());
        let diagnostics = report.inconsistencies();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, super::PATTERN_INCONSISTENT_COUNTS);
    }

    #[test]
    fn notes_explain_unexercised_and_unsupported_rules() {
        let mut report = CoverageReport::new();
        report.push(RuleCoverage::new("a", "1", 0, 0, 0));
        report.push(RuleCoverage::new("b", "1", 1, 1, 1));
        let notes = report.coverage_notes();
        assert_eq!(notes.len(), 2);
        assert!(notes.iter().any(|note| note.code == PATTERN_NOT_EXERCISED));
        assert!(notes
            .iter()
            .any(|note| note.code == PATTERN_UNSUPPORTED_INPUTS));
        assert_eq!(REASON_NOT_EXERCISED, "coverage-not-exercised");
        assert_eq!(REASON_UNSUPPORTED_INPUTS, "coverage-unsupported-inputs");
    }
}
