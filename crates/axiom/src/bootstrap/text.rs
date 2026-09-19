//! Byte-, BOM- and newline-preserving text handling (task E-015).
//!
//! Bootstrap rewrites exactly one byte range of one file: the managed block of
//! `AGENTS.md`. Everything around that range - the leading UTF-8 BOM, the
//! repository's own line endings, the human instructions above and below the
//! block, the final newline - is not bootstrap's to change, so this module turns
//! "preserve the rest" into a type instead of a habit.
//!
//! `docs/18-BOOTSTRAP-AND-MANAGED-INSTRUCTIONS.md` section 4 and the
//! `fixtures/bootstrap` corpus fix the rules this slice implements:
//!
//! * a UTF-8 document with an optional single leading BOM is the only accepted
//!   encoding; anything else is refused with [`RULE_ENCODING`] and the caller's
//!   bytes are left exactly as they were;
//! * the dominant newline of the document (`\r\n` when the text contains one,
//!   `\n` otherwise) is also the newline of the block that is written, so a CRLF
//!   repository is never converted to LF by bootstrap and an LF repository never
//!   gains a CRLF;
//! * the block template is trimmed of its surrounding newlines and re-expressed
//!   in that newline before it is spliced in;
//! * a replacement keeps every byte outside the owned span, and an append keeps
//!   the whole original document as an exact prefix.
//!
//! The module is pure: it reads bytes and returns bytes, never touching a
//! filesystem, so a refusal has no side effect at all.

use graph_core::error::AxiomError;

use super::markers::ManagedSpan;
use super::refuse;

/// The UTF-8 byte-order mark, as it appears at the head of a document.
pub const UTF8_BOM: &[u8] = &[0xef, 0xbb, 0xbf];

/// Stable rule code for bytes this build cannot read as UTF-8.
pub const RULE_ENCODING: &str = "text-encoding";

/// Stable rule code for a span that does not fit the document it was planned
/// against.
pub const RULE_SPAN: &str = "text-span-out-of-range";

/// Line-ending convention of a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Newline {
    /// Unix line feed.
    Lf,
    /// Windows carriage return + line feed.
    Crlf,
}

impl Newline {
    /// The bytes of an LF.
    pub const LF: &'static str = "\n";

    /// The bytes of a CRLF.
    pub const CRLF: &'static str = "\r\n";

    /// The newline as text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lf => Self::LF,
            Self::Crlf => Self::CRLF,
        }
    }

    /// The dominant newline of a document.
    ///
    /// A document that contains a single CRLF is treated as CRLF, which is the
    /// rule the corpus pins: a repository must not be converted to LF by
    /// bootstrap, and one CRLF is enough evidence of the repository's intent.
    #[must_use]
    pub fn of(document: &str) -> Self {
        if document.contains(Self::CRLF) {
            Self::Crlf
        } else {
            Self::Lf
        }
    }
}

impl std::fmt::Display for Newline {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Whether `bytes` begin with a UTF-8 BOM.
#[must_use]
pub fn starts_with_bom(bytes: &[u8]) -> bool {
    bytes.starts_with(UTF8_BOM)
}

/// A decoded document: its exact text (including a leading BOM character, when
/// the bytes carried one) plus the encoding facts bootstrap needs.
///
/// The type deliberately keeps the document verbatim. Round-tripping it with
/// [`SourceText::encode`] returns the original bytes, which is what makes
/// "bytes outside the owned block are preserved" a property of the type rather
/// than of a caller's care.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceText {
    document: String,
    bom: bool,
}

impl SourceText {
    /// Decode a repository file.
    ///
    /// # Errors
    ///
    /// Returns a conflict carrying [`RULE_ENCODING`] when the bytes are not
    /// valid UTF-8. Nothing is modified: this only reads.
    pub fn decode(bytes: &[u8]) -> Result<Self, AxiomError> {
        let document = std::str::from_utf8(bytes).map_err(|error| {
            refuse(
                RULE_ENCODING,
                format!("refusing an unsupported encoding: {error}"),
            )
            .with_detail("field", "encoding")
            .with_detail("observed", "non-utf-8")
        })?;
        Ok(Self {
            bom: starts_with_bom(bytes),
            document: document.to_owned(),
        })
    }

    /// Adopt already-decoded text, deriving the BOM flag from the text itself.
    #[must_use]
    pub fn from_text(document: impl Into<String>) -> Self {
        let document = document.into();
        Self {
            bom: document.starts_with('\u{feff}'),
            document,
        }
    }

    /// Whether the document carried a leading BOM.
    #[must_use]
    pub const fn has_bom(&self) -> bool {
        self.bom
    }

    /// The document's dominant newline.
    #[must_use]
    pub fn newline(&self) -> Newline {
        Newline::of(&self.document)
    }

    /// The document text, BOM character included when present.
    #[must_use]
    pub fn document(&self) -> &str {
        &self.document
    }

    /// Byte length of the decoded document.
    #[must_use]
    pub fn len(&self) -> usize {
        self.document.len()
    }

    /// Whether the document is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.document.is_empty()
    }

    /// The exact bytes this document decoded from.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.document.as_bytes().to_vec()
    }

    /// Replace the owned span with `block`, preserving every other byte.
    ///
    /// The span is a byte range of [`SourceText::document`], so a leading BOM
    /// stays outside it and is never re-encoded.
    ///
    /// # Errors
    ///
    /// Returns a conflict carrying [`RULE_SPAN`] when the span does not sit on
    /// UTF-8 boundaries inside this document.
    pub fn replace_span(&self, span: ManagedSpan, block: &str) -> Result<String, AxiomError> {
        if span.end < span.start {
            return Err(self.span_refusal(span));
        }
        let (Some(head), Some(tail)) = (
            self.document.get(..span.start),
            self.document.get(span.end..),
        ) else {
            return Err(self.span_refusal(span));
        };
        Ok(format!("{head}{block}{tail}"))
    }

    /// Append a block after the existing document.
    ///
    /// The original document is kept as an exact prefix. Exactly one newline is
    /// inserted when the document already ends with one, and a blank separator
    /// line is inserted otherwise, so the block never abuts human text.
    #[must_use]
    pub fn append_block(&self, block: &str) -> String {
        append_block(&self.document, block, self.newline())
    }

    fn span_refusal(&self, span: ManagedSpan) -> AxiomError {
        refuse(
            RULE_SPAN,
            format!(
                "refusing a managed span {}..{} outside a {}-byte document",
                span.start,
                span.end,
                self.document.len()
            ),
        )
        .with_detail("field", "span")
        .with_detail("observed", format!("{}..{}", span.start, span.end))
    }
}

/// Re-express a block template in a document's newline.
///
/// Surrounding newlines are trimmed first, so a template file that ends with a
/// final newline does not accumulate a blank line on every re-apply. Any CRLF in
/// the template is normalised to LF before the target newline is applied, so the
/// rendered block uses exactly one convention.
#[must_use]
pub fn render_block(template: &str, newline: Newline) -> String {
    let trimmed = template.trim_matches(['\r', '\n']);
    let normalised = trimmed.replace(Newline::CRLF, Newline::LF);
    if newline == Newline::Crlf {
        normalised.replace(Newline::LF, Newline::CRLF)
    } else {
        normalised
    }
}

/// Append `block` after `document` using `newline`.
#[must_use]
pub fn append_block(document: &str, block: &str, newline: Newline) -> String {
    let separator = newline.as_str();
    let suffix = if document.is_empty() {
        String::new()
    } else if document.ends_with('\n') || document.ends_with('\r') {
        separator.to_owned()
    } else {
        format!("{separator}{separator}")
    };
    format!("{document}{suffix}{block}{separator}")
}

/// Whether `after` is exactly `before` with `span` replaced by `replacement`,
/// and nothing else.
///
/// This is the assertion behind "bytes outside the owned block are preserved",
/// written once so the planner, the applier and the verifier can all use the
/// same definition of *only* the owned span changing.
#[must_use]
pub fn replaces_only_span(before: &str, after: &str, span: ManagedSpan, replacement: &str) -> bool {
    if span.end < span.start {
        return false;
    }
    let (Some(head), Some(tail)) = (before.get(..span.start), before.get(span.end..)) else {
        return false;
    };
    let Some(replacement_end) = span.start.checked_add(replacement.len()) else {
        return false;
    };
    let (Some(after_head), Some(after_middle), Some(after_tail)) = (
        after.get(..span.start),
        after.get(span.start..replacement_end),
        after.get(replacement_end..),
    ) else {
        return false;
    };
    after_head == head && after_middle == replacement && after_tail == tail
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::markers;

    fn corpus_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("bootstrap")
    }

    fn template() -> String {
        std::fs::read_to_string(corpus_root().join("templates").join("AGENTS.block.md"))
            .expect("block template")
    }

    fn has_bare_lf(text: &str) -> bool {
        text.replace(Newline::CRLF, "").contains('\n')
    }

    /// AC1 positive: a BOM stays a single BOM, and a CRLF or LF document keeps
    /// its own newline inside the rendered block.
    #[test]
    fn bom_and_line_endings_survive_a_replace_and_an_append() {
        let block_template = template();

        let crlf = "# Demo\r\n\r\nHuman text.\r\n";
        let source = SourceText::from_text(crlf);
        assert!(!source.has_bom());
        assert_eq!(source.newline(), Newline::Crlf);
        assert_eq!(source.encode(), crlf.as_bytes());
        let block = render_block(&block_template, source.newline());
        assert!(block.contains(Newline::CRLF));
        assert!(!has_bare_lf(&block), "a CRLF block has no bare LF");
        let appended = source.append_block(&block);
        assert!(appended.starts_with(crlf));
        assert!(!has_bare_lf(&appended));

        let lf = SourceText::from_text("# Demo\n\nHuman text.\n");
        assert_eq!(lf.newline(), Newline::Lf);
        assert!(!render_block(&block_template, lf.newline()).contains(Newline::CRLF));

        let bytes = [UTF8_BOM, b"# Demo\n\nHuman text after a BOM.\n"].concat();
        let source = SourceText::decode(&bytes).expect("BOM is valid UTF-8");
        assert!(source.has_bom());
        assert_eq!(source.encode(), bytes);
        let block = render_block(&block_template, source.newline());
        let after = source.append_block(&block);
        let after_bytes = after.as_bytes();
        assert!(starts_with_bom(after_bytes));
        assert!(
            !starts_with_bom(&after_bytes[UTF8_BOM.len()..]),
            "the BOM is never duplicated"
        );
        assert!(after_bytes.starts_with(&bytes));
        assert!(after.contains("POLICY.md"));
    }

    /// AC1 boundary: replacing a span changes that span and not one byte around
    /// it, and a span that does not fit is refused rather than clamped.
    #[test]
    fn replacing_a_span_touches_only_that_span() {
        let document = format!(
            "{bom}# Demo\n\n{begin}\nold body\n{end}\ntrailer\n",
            bom = '\u{feff}',
            begin = markers::BEGIN_MARKER,
            end = markers::END_MARKER,
        );
        let source = SourceText::from_text(document.clone());
        let span = markers::managed_span(&document)
            .expect("balanced")
            .expect("a span");
        let block = "<!-- axiom-graph:begin -->\nnew\n<!-- axiom-graph:end -->";
        let after = source.replace_span(span, block).expect("the span fits");
        assert!(replaces_only_span(&document, &after, span, block));
        assert!(after.starts_with('\u{feff}'));
        assert!(after.ends_with("trailer\n"));
        assert_eq!(
            source.document(),
            document,
            "replace never mutates the source"
        );

        let overflowing = ManagedSpan {
            start: 0,
            end: document.len() + 1,
        };
        let error = source
            .replace_span(overflowing, block)
            .expect_err("refused");
        assert_eq!(error.code(), graph_core::error::ErrorCode::Conflict);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(RULE_SPAN)
        );

        let inverted = ManagedSpan { start: 4, end: 2 };
        assert!(source.replace_span(inverted, block).is_err());
        assert!(!replaces_only_span(&document, &after, inverted, block));
    }

    /// AC1 negative: an unsupported encoding is a conflict, the reason names the
    /// encoding, and the caller's bytes are untouched.
    #[test]
    fn unsupported_encoding_is_refused_without_touching_the_bytes() {
        let latin1 = b"caf\xe9\r\nhuman text\r\n".to_vec();
        let original = latin1.clone();
        let error = SourceText::decode(&latin1).expect_err("latin-1 is not UTF-8");
        assert_eq!(error.code(), graph_core::error::ErrorCode::Conflict);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(RULE_ENCODING)
        );
        assert!(
            error.message().to_lowercase().contains("encoding"),
            "the refusal names the encoding: {}",
            error.message()
        );
        assert_eq!(latin1, original, "decoding never rewrites its input");

        let utf16 = [0xff_u8, 0xfe, 0x41, 0x00].to_vec();
        assert!(SourceText::decode(&utf16).is_err());
        assert!(
            SourceText::decode(&[0xef, 0xbb]).is_err(),
            "a truncated BOM"
        );
    }

    /// AC2: the whole corpus is replayed through this module. Every before-state
    /// round-trips byte for byte, the append vectors keep the original document
    /// as an exact prefix, and the replace vectors change only the owned span.
    #[test]
    fn the_bootstrap_corpus_round_trips_and_preserves_unowned_bytes() {
        let root = corpus_root();
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(root.join("vectors.json")).expect("vectors.json"),
        )
        .expect("parse vectors");
        let vectors = manifest["vectors"].as_array().expect("vectors array");
        let block_template = template();

        let mut decoded = 0usize;
        let mut refused = 0usize;
        let mut appended = 0usize;
        let mut replaced = 0usize;
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
            let source = match SourceText::decode(&bytes) {
                Ok(source) => source,
                Err(error) => {
                    assert_eq!(error.code(), graph_core::error::ErrorCode::Conflict, "{id}");
                    refused += 1;
                    continue;
                }
            };
            decoded += 1;
            assert_eq!(source.encode(), bytes, "{id} must round-trip byte for byte");

            let expect_crlf = vector["expect_crlf"].as_bool().unwrap_or(false);
            if expect_crlf {
                assert_eq!(source.newline(), Newline::Crlf, "{id} is a CRLF document");
            }
            let block = render_block(&block_template, source.newline());
            assert_eq!(
                block.contains(Newline::CRLF),
                expect_crlf,
                "{id} rendered its block in the wrong newline"
            );

            let outcome = vector["outcome"].as_str().expect("outcome");
            let preserve: Vec<&str> = vector["preserve_literals"]
                .as_array()
                .map(|values| values.iter().filter_map(|value| value.as_str()).collect())
                .unwrap_or_default();

            if outcome == "append" {
                let after = source.append_block(&block);
                if vector["expect_prefix"].as_bool().unwrap_or(false) {
                    assert!(
                        after.as_bytes().starts_with(&bytes),
                        "{id} did not keep the original bytes as an exact prefix"
                    );
                }
                assert_eq!(
                    after.starts_with('\u{feff}'),
                    source.has_bom(),
                    "{id} changed the BOM"
                );
                for literal in preserve {
                    assert!(after.contains(literal), "{id} dropped {literal:?}");
                }
                appended += 1;
            } else if outcome == "replace" {
                let span = markers::managed_span(source.document())
                    .expect("balanced markers")
                    .expect("a span");
                let after = source.replace_span(span, &block).expect("the span fits");
                assert!(
                    replaces_only_span(source.document(), &after, span, &block),
                    "{id} rewrote bytes outside the owned span"
                );
                assert_eq!(
                    after.starts_with('\u{feff}'),
                    source.has_bom(),
                    "{id} changed the BOM"
                );
                for literal in preserve {
                    assert!(after.contains(literal), "{id} dropped {literal:?}");
                }
                replaced += 1;
            }
        }

        assert_eq!(refused, 0, "every corpus file is UTF-8");
        assert_eq!(decoded, 14, "fourteen corpus before-states carry AGENTS.md");
        assert_eq!(appended, 4, "four corpus vectors append");
        assert_eq!(replaced, 2, "two corpus vectors replace");
    }
}
