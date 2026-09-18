//! Human architectural annotations merged with generated facts (task B-065).
//!
//! A human annotation is evidence about the architecture that no pattern in the
//! source can produce. It is useful precisely because it can disagree with the
//! generated facts, so this adapter never lets an annotation replace one:
//!
//! * an annotated edge must carry a source and a version. A line without them
//!   is rejected, because an unattributable claim is not evidence;
//! * when an annotation agrees with a generated fact the two are merged and
//!   both sources are kept;
//! * when an annotation contradicts a generated fact the contradiction is
//!   reported and the generated fact is left exactly as it was - the merge does
//!   not silently pick a winner.
//!
//! The annotation text format is one edge per line:
//!
//! ```text
//! Orders -> Billing : publishes ; source=review-2026-09 ; version=3
//! ```

use crate::{Diagnostic, Span};

use super::{lines_with_offsets, strip_line_comment, FactQuality};

/// Pattern id for an annotated edge with no generated counterpart.
pub const PATTERN_ANNOTATED_EDGE: &str = "annotation-annotated-edge";
/// Pattern id for an annotation that agrees with a generated fact.
pub const PATTERN_CONFIRMED_EDGE: &str = "annotation-confirmed-edge";
/// Pattern id for an annotation that contradicts a generated fact.
pub const PATTERN_CONTRADICTION: &str = "annotation-contradiction";
/// Pattern id for an annotation line that could not be read.
pub const PATTERN_REJECTED_ANNOTATION: &str = "annotation-rejected";

/// Reason recorded when an annotation carries no source or version.
pub const REASON_MISSING_PROVENANCE: &str = "rejected-missing-provenance";
/// Reason recorded when an annotation line has no `from -> to` head.
pub const REASON_MALFORMED_ANNOTATION: &str = "rejected-malformed-annotation";
/// Reason recorded when an annotation uses the reserved generated source id.
pub const REASON_RESERVED_SOURCE: &str = "rejected-reserved-source";

/// One architectural edge a human asserted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    /// Source end of the edge.
    pub from: String,
    /// Target end of the edge.
    pub to: String,
    /// Asserted relation.
    pub relation: String,
    /// Evidence id, for example `review-2026-09`.
    pub source: String,
    /// Version of the annotation source.
    pub version: String,
    /// One-based line in the annotation text.
    pub line: usize,
    /// Span of the line.
    pub span: Span,
}

/// One fact the analyser generated from source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedFact {
    /// Source end of the edge.
    pub from: String,
    /// Target end of the edge.
    pub to: String,
    /// Generated relation.
    pub relation: String,
    /// The `PATTERN_*` id or analyser that produced the fact.
    pub pattern: String,
    /// Quality the analyser assigned.
    pub quality: FactQuality,
}

/// One edge in the merged result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedEdge {
    /// Source end of the edge.
    pub from: String,
    /// Target end of the edge.
    pub to: String,
    /// The relation the edge actually has. A contradiction never changes this.
    pub relation: String,
    /// The generated pattern, when a generated fact exists for this edge.
    pub generated_pattern: Option<String>,
    /// Quality of the edge: the generated quality when generated, otherwise the
    /// annotated quality.
    pub quality: FactQuality,
    /// Annotation sources that support this edge.
    pub annotation_sources: Vec<String>,
    /// Annotation versions that support this edge, in the same order.
    pub annotation_versions: Vec<String>,
}

/// An annotation that disagrees with a generated fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contradiction {
    /// The annotation as written; it is retained, never applied.
    pub annotation: Annotation,
    /// The generated relation that stands.
    pub generated_relation: String,
    /// The generated pattern that produced the standing relation.
    pub generated_pattern: String,
}

/// An annotation line this adapter refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedAnnotation {
    /// A `PATTERN_*` id naming what was refused.
    pub pattern: String,
    /// A `REASON_*` value explaining the refusal.
    pub reason: String,
    /// The line as written.
    pub text: String,
    /// One-based line number.
    pub line: usize,
    /// Span of the line.
    pub span: Span,
}

/// Result of merging annotations with generated facts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnnotationReport {
    /// Every edge the merge produced, in generated-then-annotated order.
    pub edges: Vec<MergedEdge>,
    /// Contradictions, in annotation order.
    pub contradictions: Vec<Contradiction>,
    /// Rejected annotation lines, in source order.
    pub rejected: Vec<RejectedAnnotation>,
    /// Diagnostics attached to the merge.
    pub diagnostics: Vec<Diagnostic>,
}

impl AnnotationReport {
    /// Whether any annotation was rejected or contradicted a generated fact.
    #[must_use]
    pub fn has_unresolved(&self) -> bool {
        !self.contradictions.is_empty() || !self.rejected.is_empty()
    }

    /// The edge for `from`/`to`, when the merge produced one.
    #[must_use]
    pub fn edge(&self, from: &str, to: &str) -> Option<&MergedEdge> {
        self.edges
            .iter()
            .find(|edge| edge.from == from && edge.to == to)
    }
}

/// The source id reserved for generated facts; a human annotation may not
/// claim it.
pub const GENERATED_SOURCE: &str = "generated";

/// Parse the documented annotation format.
#[must_use]
pub fn parse_annotations(text: &str) -> (Vec<Annotation>, Vec<RejectedAnnotation>) {
    let mut annotations = Vec::new();
    let mut rejected = Vec::new();
    for (index, (offset, raw_line)) in lines_with_offsets(text).into_iter().enumerate() {
        let line = strip_line_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let span = Span::new(offset, offset + line.len());
        let line_number = index + 1;
        let mut segments = trimmed.split(';');
        let Some(head) = segments.next() else {
            continue;
        };
        let mut source = None;
        let mut version = None;
        for attribute in segments {
            let Some((key, value)) = attribute.split_once('=') else {
                continue;
            };
            match key.trim() {
                "source" => source = Some(value.trim().to_string()),
                "version" => version = Some(value.trim().to_string()),
                _ => {}
            }
        }
        let Some((ends, relation)) = head.split_once(':') else {
            rejected.push(RejectedAnnotation {
                pattern: PATTERN_REJECTED_ANNOTATION.to_string(),
                reason: REASON_MALFORMED_ANNOTATION.to_string(),
                text: trimmed.to_string(),
                line: line_number,
                span,
            });
            continue;
        };
        let Some((from, to)) = ends.split_once("->") else {
            rejected.push(RejectedAnnotation {
                pattern: PATTERN_REJECTED_ANNOTATION.to_string(),
                reason: REASON_MALFORMED_ANNOTATION.to_string(),
                text: trimmed.to_string(),
                line: line_number,
                span,
            });
            continue;
        };
        let (from, to, relation) = (from.trim(), to.trim(), relation.trim());
        if from.is_empty() || to.is_empty() || relation.is_empty() {
            rejected.push(RejectedAnnotation {
                pattern: PATTERN_REJECTED_ANNOTATION.to_string(),
                reason: REASON_MALFORMED_ANNOTATION.to_string(),
                text: trimmed.to_string(),
                line: line_number,
                span,
            });
            continue;
        }
        let (Some(source), Some(version)) = (source, version) else {
            rejected.push(RejectedAnnotation {
                pattern: PATTERN_REJECTED_ANNOTATION.to_string(),
                reason: REASON_MISSING_PROVENANCE.to_string(),
                text: trimmed.to_string(),
                line: line_number,
                span,
            });
            continue;
        };
        if source == GENERATED_SOURCE {
            rejected.push(RejectedAnnotation {
                pattern: PATTERN_REJECTED_ANNOTATION.to_string(),
                reason: REASON_RESERVED_SOURCE.to_string(),
                text: trimmed.to_string(),
                line: line_number,
                span,
            });
            continue;
        }
        annotations.push(Annotation {
            from: from.to_string(),
            to: to.to_string(),
            relation: relation.to_string(),
            source,
            version,
            line: line_number,
            span,
        });
    }
    (annotations, rejected)
}

/// Merge human annotations with generated facts without overwriting either.
#[must_use]
pub fn merge(generated: &[GeneratedFact], annotations: &[Annotation]) -> AnnotationReport {
    let mut report = AnnotationReport::default();
    for fact in generated {
        report.edges.push(MergedEdge {
            from: fact.from.clone(),
            to: fact.to.clone(),
            relation: fact.relation.clone(),
            generated_pattern: Some(fact.pattern.clone()),
            quality: fact.quality,
            annotation_sources: Vec::new(),
            annotation_versions: Vec::new(),
        });
    }
    for annotation in annotations {
        let existing = report
            .edges
            .iter()
            .position(|edge| edge.from == annotation.from && edge.to == annotation.to);
        match existing {
            None => report.edges.push(MergedEdge {
                from: annotation.from.clone(),
                to: annotation.to.clone(),
                relation: annotation.relation.clone(),
                generated_pattern: None,
                quality: FactQuality::ExactStatic,
                annotation_sources: vec![annotation.source.clone()],
                annotation_versions: vec![annotation.version.clone()],
            }),
            Some(index) => {
                let edge = &mut report.edges[index];
                if edge.relation != annotation.relation {
                    let generated_relation = edge.relation.clone();
                    let generated_pattern = edge
                        .generated_pattern
                        .clone()
                        .unwrap_or_else(|| GENERATED_SOURCE.to_string());
                    report.contradictions.push(Contradiction {
                        annotation: annotation.clone(),
                        generated_relation,
                        generated_pattern,
                    });
                    continue;
                }
                edge.annotation_sources.push(annotation.source.clone());
                edge.annotation_versions.push(annotation.version.clone());
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::{
        merge, parse_annotations, GeneratedFact, PATTERN_CONTRADICTION,
        REASON_MALFORMED_ANNOTATION, REASON_MISSING_PROVENANCE,
    };
    use crate::l3::FactQuality;

    fn generated(from: &str, to: &str, relation: &str) -> GeneratedFact {
        GeneratedFact {
            from: from.to_string(),
            to: to.to_string(),
            relation: relation.to_string(),
            pattern: "angular-http-literal-route".to_string(),
            quality: FactQuality::ExactStatic,
        }
    }

    #[test]
    fn a_new_annotated_edge_retains_its_source_and_version() {
        let (annotations, rejected) =
            parse_annotations("Orders -> Billing : publishes ; source=review-2026-09 ; version=3");
        assert!(rejected.is_empty());
        assert_eq!(annotations.len(), 1);
        let report = merge(&[], &annotations);
        assert_eq!(report.edges.len(), 1);
        let edge = &report.edges[0];
        assert_eq!(edge.relation, "publishes");
        assert!(edge.generated_pattern.is_none());
        assert_eq!(edge.annotation_sources, vec!["review-2026-09".to_string()]);
        assert_eq!(edge.annotation_versions, vec!["3".to_string()]);
        assert_eq!(edge.quality, FactQuality::ExactStatic);
        assert!(!report.has_unresolved());
    }

    #[test]
    fn an_agreeing_annotation_merges_without_losing_either_source() {
        let (annotations, _) = parse_annotations(
            "Orders -> Billing : calls ; source=arch-review ; version=2\n\
             Orders -> Billing : calls ; source=security-review ; version=1",
        );
        let report = merge(&[generated("Orders", "Billing", "calls")], &annotations);
        assert_eq!(report.edges.len(), 1);
        let edge = report.edge("Orders", "Billing").expect("edge");
        assert_eq!(
            edge.generated_pattern.as_deref(),
            Some("angular-http-literal-route")
        );
        assert_eq!(edge.annotation_sources.len(), 2);
        assert_eq!(
            edge.annotation_versions,
            vec!["2".to_string(), "1".to_string()]
        );
        assert!(report.contradictions.is_empty());
    }

    #[test]
    fn a_contradicting_annotation_never_overwrites_the_generated_fact() {
        let (annotations, _) =
            parse_annotations("Orders -> Billing : owns ; source=arch-review ; version=2");
        let report = merge(&[generated("Orders", "Billing", "calls")], &annotations);
        assert_eq!(report.contradictions.len(), 1);
        assert_eq!(report.contradictions[0].generated_relation, "calls");
        assert_eq!(report.contradictions[0].annotation.relation, "owns");
        assert_eq!(report.contradictions[0].annotation.source, "arch-review");
        // The generated fact is unchanged and still the only edge.
        let edge = report.edge("Orders", "Billing").expect("edge");
        assert_eq!(edge.relation, "calls");
        assert!(edge.annotation_sources.is_empty());
        assert!(report.has_unresolved());
        assert_eq!(
            report.contradictions[0].generated_pattern,
            "angular-http-literal-route"
        );
    }

    #[test]
    fn an_annotation_without_provenance_is_rejected() {
        let (annotations, rejected) = parse_annotations(
            "Orders -> Billing : calls ; source=arch-review\nOrders -> Billing : calls\n",
        );
        assert!(annotations.is_empty());
        assert_eq!(rejected.len(), 2);
        assert!(rejected
            .iter()
            .all(|entry| entry.reason == REASON_MISSING_PROVENANCE));
        let report = merge(&[generated("Orders", "Billing", "calls")], &annotations);
        assert!(report.edges[0].annotation_sources.is_empty());
        assert!(!report.has_unresolved());
    }

    #[test]
    fn a_malformed_line_is_rejected_with_a_reason() {
        let (annotations, rejected) = parse_annotations("this is not an edge");
        assert!(annotations.is_empty());
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].reason, REASON_MALFORMED_ANNOTATION);
        assert_eq!(rejected[0].pattern, super::PATTERN_REJECTED_ANNOTATION);
    }

    #[test]
    fn contradictory_annotation_pattern_is_recorded() {
        let (annotations, _) = parse_annotations("A -> B : uses ; source=human ; version=1");
        let report = merge(&[generated("A", "B", "calls")], &annotations);
        assert_eq!(report.contradictions[0].annotation.source, "human");
        assert_eq!(PATTERN_CONTRADICTION, "annotation-contradiction");
    }
}
