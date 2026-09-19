//! Fence-aware, fail-closed managed marker parsing (task E-014).
//!
//! The owned block of `AGENTS.md` is delimited by two HTML comments. The parser
//! has exactly one job: find the single managed span or refuse, so the writer
//! never has to guess. `docs/18-BOOTSTRAP-AND-MANAGED-INSTRUCTIONS.md` section 4
//! fixes the outcomes this module must produce:
//!
//! * exactly one marker pair outside a code fence - one accepted block;
//! * a lone begin or end marker - unbalanced, refuse;
//! * two end markers or two begin markers or an inverted span - refuse;
//! * three or more markers - two candidate blocks, refuse;
//! * marker text *inside* a Markdown code fence - a quoted example, not an
//!   owned block; the detector must ignore it and keep the example.
//!
//! Refusing here is what keeps bootstrap non-destructive: a parser that picked
//! the first of two spans, or truncated at a lone begin marker, would corrupt
//! human text that it does not own. Every refusal therefore carries a stable
//! [`MarkerConflict`] instead of a byte range.

/// Opening marker of the managed block.
pub const BEGIN_MARKER: &str = "<!-- axiom-graph:begin -->";

/// Closing marker of the managed block.
pub const END_MARKER: &str = "<!-- axiom-graph:end -->";

/// Why a document does not hold exactly one managed block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerConflict {
    /// Exactly one marker is present, so a span cannot be closed.
    Unbalanced,
    /// More markers than one pair are present, in a shape that is not an
    /// inverted pair.
    Duplicate,
    /// The end marker precedes the begin marker.
    OutOfOrder,
}

impl MarkerConflict {
    /// Stable, greppable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unbalanced => "markers-unbalanced",
            Self::Duplicate => "markers-duplicate",
            Self::OutOfOrder => "markers-out-of-order",
        }
    }

    /// Human-readable refusal message. Every message contains the word `marker`
    /// so the operator-facing report and the `fixtures/bootstrap` corpus agree
    /// on what was wrong.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Unbalanced => "a lone managed marker is unbalanced",
            Self::Duplicate => "duplicate managed markers name more than one block",
            Self::OutOfOrder => "managed markers are out of order",
        }
    }
}

impl std::fmt::Display for MarkerConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

/// The byte span of the one managed block, excluding the newline that follows
/// the end marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedSpan {
    /// Byte offset of the begin marker.
    pub start: usize,
    /// Byte offset just past the end marker.
    pub end: usize,
}

impl ManagedSpan {
    /// Length of the span in bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end - self.start
    }

    /// Whether the span is empty. Always `false` for a parsed span; present so
    /// the type does not grow a `len` without an `is_empty`.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.end <= self.start
    }

    /// The covered text of `document`, when the span fits it.
    #[must_use]
    pub fn slice(self, document: &str) -> Option<&str> {
        document.get(self.start..self.end)
    }
}

/// Leading Markdown fence run on `line`: the fence character, its run length
/// and whether the remainder of the line is blank (which is what makes a fence
/// close the open one).
#[must_use]
pub fn fence_run(line: &str) -> Option<(char, usize, bool)> {
    let mut rest = line;
    let mut spaces = 0usize;
    while spaces < 3 {
        match rest.strip_prefix(' ') {
            Some(stripped) => {
                rest = stripped;
                spaces += 1;
            }
            None => break,
        }
    }
    let fence_char = rest.chars().next()?;
    if fence_char != '`' && fence_char != '~' {
        return None;
    }
    let run = rest.chars().take_while(|ch| *ch == fence_char).count();
    if run < 3 {
        return None;
    }
    let remainder: String = rest.chars().skip(run).collect();
    Some((fence_char, run, remainder.trim().is_empty()))
}

/// Find the managed span bounded by [`BEGIN_MARKER`] and [`END_MARKER`].
///
/// # Errors
///
/// Returns the [`MarkerConflict`] that describes why the document does not hold
/// exactly one block. Human text is never altered by this call: it only reads.
pub fn managed_span(document: &str) -> Result<Option<ManagedSpan>, MarkerConflict> {
    managed_span_with(document, BEGIN_MARKER, END_MARKER)
}

/// Find the managed span bounded by an explicit marker pair.
///
/// The markers are compared after trimming surrounding whitespace, so a marker
/// indented inside a list item still delimits a block. A marker whose line is
/// inside an open code fence is an example and is ignored.
///
/// # Errors
///
/// Same refusals as [`managed_span`].
pub fn managed_span_with(
    document: &str,
    begin: &str,
    end: &str,
) -> Result<Option<ManagedSpan>, MarkerConflict> {
    let mut offset = 0usize;
    let mut found: Vec<(bool, usize, usize)> = Vec::new();
    let mut fence: Option<(char, usize)> = None;
    for line in document.split_inclusive('\n') {
        let plain = line.trim_end_matches(['\r', '\n']);
        let clean = if offset == 0 {
            plain.trim_start_matches('\u{feff}')
        } else {
            plain
        };
        if let Some((fence_char, run, remainder_blank)) = fence_run(clean) {
            match fence {
                None => fence = Some((fence_char, run)),
                Some((open, length)) if fence_char == open && run >= length && remainder_blank => {
                    fence = None;
                }
                Some(_) => {}
            }
            offset += line.len();
            continue;
        }
        if fence.is_none() {
            let trimmed = clean.trim();
            if trimmed == begin || trimmed == end {
                let start = if offset == 0 && plain.starts_with('\u{feff}') {
                    offset + '\u{feff}'.len_utf8()
                } else {
                    offset
                };
                found.push((trimmed == begin, start, offset + plain.len()));
            }
        }
        offset += line.len();
    }
    classify(found)
}

fn classify(found: Vec<(bool, usize, usize)>) -> Result<Option<ManagedSpan>, MarkerConflict> {
    match found.len() {
        0 => Ok(None),
        1 => Err(MarkerConflict::Unbalanced),
        2 => match (found[0].0, found[1].0) {
            (true, false) => Ok(Some(ManagedSpan {
                start: found[0].1,
                end: found[1].2,
            })),
            (false, true) => Err(MarkerConflict::OutOfOrder),
            _ => Err(MarkerConflict::Duplicate),
        },
        _ => Err(MarkerConflict::Duplicate),
    }
}

/// Whether `document` holds exactly one managed block.
///
/// # Errors
///
/// Propagates the marker refusal.
pub fn has_managed_block(document: &str) -> Result<bool, MarkerConflict> {
    managed_span(document).map(|span| span.is_some())
}

/// Number of markers that appear outside a code fence.
#[must_use]
pub fn marker_count(document: &str) -> usize {
    let mut offset = 0usize;
    let mut count = 0usize;
    let mut fence: Option<(char, usize)> = None;
    for line in document.split_inclusive('\n') {
        let plain = line.trim_end_matches(['\r', '\n']);
        let clean = if offset == 0 {
            plain.trim_start_matches('\u{feff}')
        } else {
            plain
        };
        if let Some((fence_char, run, remainder_blank)) = fence_run(clean) {
            match fence {
                None => fence = Some((fence_char, run)),
                Some((open, length)) if fence_char == open && run >= length && remainder_blank => {
                    fence = None;
                }
                Some(_) => {}
            }
            offset += line.len();
            continue;
        }
        if fence.is_none() {
            let trimmed = clean.trim();
            if trimmed == BEGIN_MARKER || trimmed == END_MARKER {
                count += 1;
            }
        }
        offset += line.len();
    }
    count
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;

    fn corpus_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("bootstrap")
    }

    fn corpus_block() -> String {
        format!(
            "# Repository\n\n{BEGIN_MARKER}\n## Axiom Graph workflow\nRead `.axiom/agent/POLICY.md`.\n{END_MARKER}\n\nHuman trailer.\n"
        )
    }

    /// AC1 positive: exactly one complete block is accepted and located.
    #[test]
    fn one_complete_block_is_accepted() {
        let document = corpus_block();
        let span = managed_span(&document).expect("one block").expect("a span");
        let block = span.slice(&document).expect("slice");
        assert!(block.starts_with(BEGIN_MARKER));
        assert!(block.ends_with(END_MARKER));
        assert!(block.contains("POLICY.md"));
        assert!(has_managed_block(&document).expect("verdict"));
        assert_eq!(marker_count(&document), 2);
        assert_eq!(span.len(), block.len());
        assert!(!span.is_empty());

        let clean = "# Human instructions only.\n";
        assert_eq!(managed_span(clean).expect("no markers"), None);
        assert!(!has_managed_block(clean).expect("verdict"));
    }

    /// AC1 negative: a lone marker and a doubled pair are refused, and the
    /// document is left untouched.
    #[test]
    fn unbalanced_and_duplicate_markers_are_refused_without_touching_the_text() {
        let lone_begin = format!("# Human text\n{BEGIN_MARKER}\nunterminated\n");
        let original = lone_begin.clone();
        assert_eq!(
            managed_span(&lone_begin).expect_err("lone begin"),
            MarkerConflict::Unbalanced
        );
        assert_eq!(lone_begin, original, "the parser never rewrites its input");

        let lone_end = format!("trailing\n{END_MARKER}\n");
        assert_eq!(
            managed_span(&lone_end).expect_err("lone end"),
            MarkerConflict::Unbalanced
        );

        let doubled =
            format!("{BEGIN_MARKER}\none\n{END_MARKER}\n{BEGIN_MARKER}\ntwo\n{END_MARKER}\n");
        assert_eq!(
            managed_span(&doubled).expect_err("two blocks"),
            MarkerConflict::Duplicate
        );

        let two_begins = format!("{BEGIN_MARKER}\n{BEGIN_MARKER}\n{END_MARKER}\n");
        assert_eq!(
            managed_span(&two_begins).expect_err("two begins"),
            MarkerConflict::Duplicate
        );

        let inverted = format!("{END_MARKER}\nbody\n{BEGIN_MARKER}\n");
        assert_eq!(
            managed_span(&inverted).expect_err("inverted span"),
            MarkerConflict::OutOfOrder
        );
    }

    /// AC1 boundary: marker text inside a fenced example is not an owned block,
    /// and a real block appended after the fence still parses.
    #[test]
    fn markers_inside_a_code_fence_are_examples_not_blocks() {
        let fenced_only = format!(
            "Here is the shape of the block:\n\n```markdown\n{BEGIN_MARKER}\nquoted example\n{END_MARKER}\n```\n\nReal human text after the fence.\n"
        );
        assert_eq!(managed_span(&fenced_only).expect("fence ignored"), None);
        assert_eq!(marker_count(&fenced_only), 0);

        let with_real_block = format!("{fenced_only}\n{BEGIN_MARKER}\nreal\n{END_MARKER}\n");
        let span = managed_span(&with_real_block)
            .expect("one real block")
            .expect("a span");
        let block = span.slice(&with_real_block).expect("slice");
        assert!(block.contains("real"));
        assert!(!block.contains("quoted example"));

        let tilde_fence = format!("~~~\n{BEGIN_MARKER}\n{END_MARKER}\n~~~\n");
        assert_eq!(managed_span(&tilde_fence).expect("tilde fence"), None);
    }

    /// AC2: the corpus vectors that the contract refuses for a marker reason
    /// really are refused by this parser, and the accepted example vector has no
    /// marker outside its fence.
    #[test]
    fn the_bootstrap_corpus_marker_vectors_match_this_parser() {
        let root = corpus_root();
        let manifest = std::fs::read_to_string(root.join("vectors.json")).expect("vectors.json");
        let parsed: serde_json::Value = serde_json::from_str(&manifest).expect("parse vectors");
        let vectors = parsed["vectors"].as_array().expect("vectors array");
        assert!(!vectors.is_empty(), "the corpus must not be empty");

        let mut refused = 0usize;
        for vector in vectors {
            let id = vector["id"].as_str().expect("id");
            let agents = root
                .join("vectors")
                .join(id)
                .join("before")
                .join("AGENTS.md");
            let Ok(bytes) = std::fs::read(&agents) else {
                continue;
            };
            let text = String::from_utf8(bytes).expect("corpus is UTF-8");
            let reason = vector["reason_contains"].as_str();
            if reason == Some("marker") {
                let conflict = managed_span(&text)
                    .err()
                    .unwrap_or_else(|| panic!("{id} must be refused"));
                assert!(
                    conflict.message().to_lowercase().contains("marker"),
                    "{id}: {} does not mention the marker",
                    conflict.message()
                );
                refused += 1;
            } else if id == "markers_in_fence" {
                assert_eq!(
                    managed_span(&text).expect("fence is ignored"),
                    None,
                    "{id} must hold no real marker"
                );
            }
        }
        assert_eq!(refused, 4, "four corpus vectors are marker conflicts");
    }
}
