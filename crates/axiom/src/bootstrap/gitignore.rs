//! Plan the managed Git-ignore rules for generated live output (task E-023).
//!
//! `docs/19-GIT-SNAPSHOTS-AND-MERGES.md` section 1 splits a project's `.axiom/`
//! namespace into two lanes: live graph output, staging trees, native runtime
//! state and temporary artifacts that Git must ignore, and the portable
//! configuration, human annotations, managed policy and optional checkpoint
//! snapshots that stay trackable and Git-reviewable. This module turns that
//! split into one managed span of `.gitignore`:
//!
//! * the span is bounded by [`GITIGNORE_BEGIN_MARKER`] and
//!   [`GITIGNORE_END_MARKER`], the same block the pinned `axiom-skills`
//!   `templates/bootstrap/gitignore.fragment` renders, so bootstrap owns a
//!   *part* of `.gitignore` and never the whole file;
//! * everything outside the span is preserved byte for byte - a repository's
//!   existing ignore rules are an exact prefix of the planned bytes and are
//!   never reformatted, reordered or dropped;
//! * the fragment is an input, not a constant of this crate. The canonical
//!   bytes live in the pinned skills package
//!   (`templates/bootstrap/gitignore.fragment`, task V2-008); copying them here
//!   would be a second source of truth for an ecosystem contract.
//!
//! The second half of the module is the property that makes "ignore live
//! output" safe to review: [`GitignoreRules`] evaluates the managed span with
//! gitignore semantics over the namespaces the contract names, and the tests
//! pin both directions - the live/cache lanes are ignored, and the optional
//! tracked checkpoint, the portable configuration, the human annotations, the
//! managed policy and the ownership manifest are *not*.

use graph_core::error::AxiomError;
use graph_export::sha256_hex;
use serde::{Deserialize, Serialize};

use super::markers::{self, ManagedSpan, MarkerConflict};
use super::plan::{self, ChangeClass, FileChange};
use super::refuse;
use super::text::{self, Newline, SourceText};

/// The repository-relative path this module plans.
pub const GITIGNORE_PATH: &str = ".gitignore";

/// The line that begins the managed ignore span.
///
/// This is the exact marker the pinned `axiom-skills`
/// `templates/bootstrap/gitignore.fragment` opens with; the fragment is only
/// accepted when its whole content is one such span.
pub const GITIGNORE_BEGIN_MARKER: &str = "# BEGIN axiom-graph generated runtime ignores";

/// The line that ends the managed ignore span.
pub const GITIGNORE_END_MARKER: &str = "# END axiom-graph generated runtime ignores";

/// Stable rule code: the existing `.gitignore` has an ambiguous managed span.
pub const RULE_GITIGNORE_MARKERS: &str = "gitignore-markers";

/// Stable rule code: the supplied fragment is not exactly one managed span.
pub const RULE_GITIGNORE_FRAGMENT: &str = "gitignore-fragment";

/// Find the managed ignore span, refusing anything ambiguous.
///
/// The lookup is the fence-aware [`markers::managed_span_with`] the managed
/// `AGENTS.md` block already uses, so a fragment quoted inside a Markdown code
/// fence is never mistaken for a real block, and duplicate, nested, unbalanced
/// or inverted markers are refused rather than guessed.
///
/// # Errors
///
/// Returns a conflict carrying [`RULE_GITIGNORE_MARKERS`] with the observed
/// marker conflict attached.
pub fn managed_span(document: &str) -> Result<Option<ManagedSpan>, AxiomError> {
    markers::managed_span_with(document, GITIGNORE_BEGIN_MARKER, GITIGNORE_END_MARKER)
        .map_err(marker_refusal)
}

/// Render a fragment into the newline convention of the target file.
///
/// # Errors
///
/// Returns a conflict carrying [`RULE_GITIGNORE_FRAGMENT`] when the fragment is
/// not UTF-8 or is not exactly one managed span.
pub fn fragment_block(fragment: &str, newline: Newline) -> Result<String, AxiomError> {
    let span = managed_span(fragment)?.ok_or_else(|| not_a_fragment("no managed span"))?;
    let head = fragment.get(..span.start).unwrap_or_default();
    let tail = fragment.get(span.end..).unwrap_or_default();
    if !head.trim().is_empty() || !tail.trim().is_empty() {
        return Err(not_a_fragment("the fragment carries text outside its span"));
    }
    Ok(text::render_block(fragment, newline))
}

/// What planning would do to `.gitignore`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitignorePlan {
    /// Repository-relative destination path.
    pub path: String,
    /// The change class: `append`, `replace` or `unchanged`.
    pub change: ChangeClass,
    /// The file this plan would write; `None` when a re-apply changes nothing.
    pub file: Option<FileChange>,
}

impl GitignorePlan {
    /// Whether applying this plan would write anything.
    #[must_use]
    pub fn would_write(&self) -> bool {
        self.file.is_some()
    }

    /// The hash the file would have afterwards.
    #[must_use]
    pub fn after_sha256(&self) -> Option<&str> {
        self.file.as_ref().map(|file| file.after_sha256.as_str())
    }
}

/// Plan the managed ignore span against the current `.gitignore`.
///
/// The existing file is decoded with [`SourceText`], so a UTF-8 BOM and a CRLF
/// convention are preserved and the appended or replacement block uses the
/// file's own newline. `None` means the repository has no `.gitignore` yet.
///
/// # Errors
///
/// Returns the fragment refusal, a conflict carrying [`RULE_GITIGNORE_MARKERS`]
/// for an ambiguous existing span, and the `text-encoding` conflict for a
/// `.gitignore` that is not UTF-8.
pub fn plan_gitignore(
    existing: Option<&[u8]>,
    fragment: &str,
) -> Result<GitignorePlan, AxiomError> {
    let source = match existing {
        Some(bytes) => SourceText::decode(bytes)?,
        None => SourceText::from_text(String::new()),
    };
    let block = fragment_block(fragment, source.newline())?;
    let before = source.document();
    let span = managed_span(before)?;
    let after = match span {
        Some(span) => {
            let current = span.slice(before).unwrap_or_default();
            if current == block {
                return Ok(GitignorePlan {
                    path: GITIGNORE_PATH.to_owned(),
                    change: ChangeClass::Unchanged,
                    file: None,
                });
            }
            source.replace_span(span, &block)?
        }
        None => source.append_block(&block),
    };
    if after == before {
        return Ok(GitignorePlan {
            path: GITIGNORE_PATH.to_owned(),
            change: ChangeClass::Unchanged,
            file: None,
        });
    }
    let bytes = after.into_bytes();
    let change = if span.is_some() {
        ChangeClass::Replace
    } else {
        ChangeClass::Append
    };
    Ok(GitignorePlan {
        path: GITIGNORE_PATH.to_owned(),
        change,
        file: Some(FileChange {
            path: GITIGNORE_PATH.to_owned(),
            before_sha256: existing.map(sha256_hex),
            after_sha256: sha256_hex(&bytes),
            diff: plan::unified_diff(
                GITIGNORE_PATH,
                before,
                std::str::from_utf8(&bytes).unwrap_or_default(),
            ),
            bytes,
        }),
    })
}

/// One parsed ignore pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pattern {
    /// The pattern segments, without the negation marker or the trailing slash.
    segments: Vec<String>,
    /// Whether the pattern ends with `/` and therefore matches only directories.
    directory_only: bool,
    /// Whether a leading `!` re-includes a path a previous pattern ignored.
    negated: bool,
    /// Whether the pattern contains no `/` and therefore matches at any depth.
    anywhere: bool,
}

/// The managed ignore span evaluated with gitignore semantics.
///
/// This is the bounded subset of `.gitignore` the managed fragment needs:
/// comments (`#`) and blank lines are ignored, `!` negates, a trailing `/`
/// matches only directories, `*` matches within one path segment, `?` matches
/// one character and `**` matches across segments. Patterns are evaluated in
/// file order, the last match wins, and a path is ignored when any of its
/// ancestor directories is ignored.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GitignoreRules {
    patterns: Vec<Pattern>,
}

impl GitignoreRules {
    /// Parse `text` - normally one managed span - into rules.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut patterns = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let (negated, body) = match trimmed.strip_prefix('!') {
                Some(rest) => (true, rest.trim()),
                None => (false, trimmed),
            };
            if body.is_empty() {
                continue;
            }
            let directory_only = body.ends_with('/');
            let body = body.trim_end_matches('/');
            if body.is_empty() {
                continue;
            }
            patterns.push(Pattern {
                segments: body.split('/').map(str::to_owned).collect(),
                directory_only,
                negated,
                anywhere: !body.contains('/'),
            });
        }
        Self { patterns }
    }

    /// How many rules the managed span contains.
    #[must_use]
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Whether the managed span contains no rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Whether `path` is ignored.
    ///
    /// `path` is repository-relative and uses `/`; a leading `./` is ignored.
    /// `is_dir` says whether the path itself is a directory.
    #[must_use]
    pub fn is_ignored(&self, path: &str, is_dir: bool) -> bool {
        let path = path.trim_start_matches("./").trim_matches('/');
        if path.is_empty() {
            return false;
        }
        let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        // A path is ignored when any ancestor directory is ignored, because
        // Git does not descend into an ignored directory.
        for depth in 1..segments.len() {
            let candidate = &segments[..depth];
            if self.evaluate(candidate, true) {
                return true;
            }
        }
        self.evaluate(&segments, is_dir)
    }

    /// Evaluate every pattern against one candidate path; the last match wins.
    fn evaluate(&self, segments: &[&str], is_dir: bool) -> bool {
        let mut ignored = false;
        for pattern in &self.patterns {
            if pattern.directory_only && !is_dir {
                continue;
            }
            if matches_pattern(pattern, segments) {
                ignored = !pattern.negated;
            }
        }
        ignored
    }
}

/// Whether one path matches one pattern.
fn matches_pattern(pattern: &Pattern, segments: &[&str]) -> bool {
    if pattern.anywhere {
        return segments
            .iter()
            .any(|segment| match_segment(&pattern.segments[0], segment));
    }
    match_segments(&pattern.segments, segments)
}

/// Match pattern segments against path segments, with `**` spanning zero or
/// more path segments.
fn match_segments(pattern: &[String], path: &[&str]) -> bool {
    let Some(head) = pattern.first() else {
        return path.is_empty();
    };
    if head == "**" {
        if match_segments(&pattern[1..], path) {
            return true;
        }
        return !path.is_empty() && match_segments(pattern, &path[1..]);
    }
    let Some(segment) = path.first() else {
        return false;
    };
    match_segment(head, segment) && match_segments(&pattern[1..], &path[1..])
}

/// Match one segment of a pattern against one path segment (`*`, `?`).
fn match_segment(pattern: &str, segment: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let segment: Vec<char> = segment.chars().collect();
    let mut pattern_at = 0usize;
    let mut segment_at = 0usize;
    let mut star: Option<(usize, usize)> = None;
    while segment_at < segment.len() {
        match pattern.get(pattern_at) {
            Some('*') => {
                star = Some((pattern_at, segment_at));
                pattern_at += 1;
            }
            Some('?') => {
                pattern_at += 1;
                segment_at += 1;
            }
            Some(next) if *next == segment[segment_at] => {
                pattern_at += 1;
                segment_at += 1;
            }
            _ => match star {
                Some((star_at, star_segment)) => {
                    pattern_at = star_at + 1;
                    segment_at = star_segment + 1;
                    star = Some((star_at, star_segment + 1));
                }
                None => return false,
            },
        }
    }
    while pattern.get(pattern_at) == Some(&'*') {
        pattern_at += 1;
    }
    pattern_at == pattern.len()
}

/// The refusal for an ambiguous managed ignore span.
fn marker_refusal(conflict: MarkerConflict) -> AxiomError {
    refuse(
        RULE_GITIGNORE_MARKERS,
        format!("refusing an ambiguous managed ignore span: {conflict}"),
    )
    .with_detail("field", "gitignore")
    .with_detail("observed", conflict.as_str())
}

/// The refusal for a fragment that is not exactly one managed span.
fn not_a_fragment(observed: &str) -> AxiomError {
    refuse(
        RULE_GITIGNORE_FRAGMENT,
        "the ignore fragment must be exactly one managed span",
    )
    .with_detail("field", "fragment")
    .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The managed span the pinned `axiom-skills`
    /// `templates/bootstrap/gitignore.fragment` (task V2-008) renders. It is a
    /// test fixture, not a second source of truth: production code takes the
    /// fragment as an input and this crate ships no copy of it.
    const FRAGMENT: &str = "# BEGIN axiom-graph generated runtime ignores\n\
# Scoped to the Axiom namespace; the whole .axiom/ directory is never ignored.\n\
.axiom/graph/**/live/\n\
.axiom/graph/**/.staging/\n\
.axiom/local/\n\
.axiom/tmp/\n\
.axiom/**/*.sqlite-wal\n\
.axiom/**/*.sqlite-shm\n\
.axiom/**/*.lock\n\
# END axiom-graph generated runtime ignores\n";

    /// A previous revision of the same managed span.
    const FRAGMENT_V1: &str = "# BEGIN axiom-graph generated runtime ignores\n\
.axiom/graph/**/live/\n\
# END axiom-graph generated runtime ignores\n";

    fn rule_of(error: &AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    fn block_of(document: &str) -> String {
        managed_span(document)
            .expect("the span parses")
            .expect("the span exists")
            .slice(document)
            .expect("the span fits")
            .to_owned()
    }

    /// AC1: the live and cache lanes are ignored, and the existing ignore rules
    /// of the repository survive the append byte for byte.
    #[test]
    fn existing_rules_survive_and_live_lanes_are_ignored() {
        let existing = "__pycache__/\n*.py[cod]\ntarget/\n";
        let plan = plan_gitignore(Some(existing.as_bytes()), FRAGMENT).expect("the plan builds");
        assert_eq!(plan.path, GITIGNORE_PATH);
        assert_eq!(plan.change, ChangeClass::Append);
        let file = plan.file.as_ref().expect("a plan would write");
        let after = String::from_utf8(file.bytes.clone()).expect("UTF-8");
        assert!(
            after.starts_with(existing),
            "existing rules must stay an exact prefix: {after}"
        );
        assert!(file.diff.contains("target/"), "{}", file.diff);

        let rules = GitignoreRules::parse(&block_of(&after));
        assert!(!rules.is_empty());
        for lane in [
            ".axiom/graph/demo/live/current.json",
            ".axiom/graph/demo/.staging/export/nodes.json",
            ".axiom/local/state.json",
            ".axiom/tmp/scratch",
            ".axiom/graph/demo/queue.sqlite-wal",
            ".axiom/graph/demo/db.sqlite-shm",
            ".axiom/graph/demo/daemon.lock",
        ] {
            assert!(rules.is_ignored(lane, false), "{lane} must be ignored");
        }
        assert!(rules.is_ignored(".axiom/graph/demo/live", true));
        // A same-named directory outside the namespace is untouched.
        assert!(!rules.is_ignored("vendor/live/current.json", false));
    }

    /// AC1: the optional tracked checkpoint, the portable configuration, the
    /// human annotations and the bootstrap-owned files are never hidden, and the
    /// `.axiom/` directory itself is never ignored as a whole.
    #[test]
    fn optional_tracked_content_is_not_hidden() {
        let plan = plan_gitignore(None, FRAGMENT).expect("the plan builds");
        let after = String::from_utf8(plan.file.expect("writes").bytes).expect("UTF-8");
        let rules = GitignoreRules::parse(&block_of(&after));

        for tracked in [
            ".axiom/graph/demo/checkpoint/current.json",
            ".axiom/graph/demo/checkpoint/gen-1/edges.json",
            ".axiom/config/solutions/demo.json",
            ".axiom/annotations/note.json",
            ".axiom/agent/POLICY.md",
            ".axiom/agent/POLICY.local.md",
            ".axiom/agent/bootstrap.lock.json",
            ".axiom/graph/demo/checkpoint",
            "src/main.rs",
            "README.md",
            "docs/guides/bootstrap.md",
        ] {
            assert!(
                !rules.is_ignored(tracked, false),
                "{tracked} must stay trackable"
            );
        }
        assert!(
            !rules.is_ignored(".axiom", true),
            "the namespace root stays trackable"
        );
        assert!(!rules.is_ignored(".axiom/graph", true));
    }

    /// AC1 boundary: a re-apply is a no-op, and a fragment change replaces only
    /// the managed span, keeping the human rules before and after it.
    #[test]
    fn only_the_managed_span_changes_and_a_reapply_is_a_no_op() {
        let existing =
            format!("__pycache__/\n\n{FRAGMENT_V1}\n# human rule after the block\n.DS_Store\n");
        let plan = plan_gitignore(Some(existing.as_bytes()), FRAGMENT).expect("the plan builds");
        assert_eq!(plan.change, ChangeClass::Replace);
        let file = plan.file.expect("writes");
        let after = String::from_utf8(file.bytes).expect("UTF-8");
        assert!(after.starts_with("__pycache__/\n\n"));
        assert!(after.ends_with("\n# human rule after the block\n.DS_Store\n"));

        let span = managed_span(&existing)
            .expect("the span parses")
            .expect("the span exists");
        let replacement = fragment_block(FRAGMENT, Newline::Lf).expect("the fragment renders");
        assert!(
            text::replaces_only_span(&existing, &after, span, &replacement),
            "only the managed span may change:\n{after}"
        );

        // The rendered bytes are already the managed span, so a re-apply is a
        // no-op rather than a second block.
        let again = plan_gitignore(Some(after.as_bytes()), FRAGMENT).expect("the plan builds");
        assert_eq!(again.change, ChangeClass::Unchanged);
        assert!(!again.would_write());
        assert!(again.after_sha256().is_none());
    }

    /// AC2 negative: duplicate, unbalanced or unowned markers are refused, so
    /// bootstrap never appends a second block or adopts a fragment silently.
    #[test]
    fn ambiguous_or_unowned_markers_are_refused() {
        let doubled = format!("{FRAGMENT}{FRAGMENT}");
        let error = plan_gitignore(Some(doubled.as_bytes()), FRAGMENT).expect_err("double block");
        assert_eq!(rule_of(&error), Some(RULE_GITIGNORE_MARKERS));

        let unbalanced = FRAGMENT.replace("# END axiom-graph generated runtime ignores\n", "");
        let error = plan_gitignore(Some(unbalanced.as_bytes()), FRAGMENT).expect_err("unbalanced");
        assert_eq!(rule_of(&error), Some(RULE_GITIGNORE_MARKERS));

        let not_one_span = [
            "target/\n".to_owned(),
            format!("lead-in\n{FRAGMENT}"),
            format!("{FRAGMENT}trail\n"),
        ];
        for fragment in &not_one_span {
            let error = plan_gitignore(None, fragment).expect_err("not one span");
            assert_eq!(rule_of(&error), Some(RULE_GITIGNORE_FRAGMENT), "{fragment}");
        }
    }

    /// AC2 boundary: the target file's newline convention and BOM are preserved
    /// and the appended block uses the file's own newline.
    #[test]
    fn newline_and_bom_are_preserved() {
        let existing = "__pycache__/\r\n";
        let plan = plan_gitignore(Some(existing.as_bytes()), FRAGMENT).expect("the plan builds");
        let after = String::from_utf8(plan.file.expect("writes").bytes).expect("UTF-8");
        assert!(after.starts_with(existing));
        assert!(after.contains(".axiom/graph/**/live/\r\n"), "{after}");
        assert!(
            !after.replace("\r\n", "").contains('\n'),
            "every newline is the file's own CRLF: {after}"
        );

        let bom = b"\xef\xbb\xbf__pycache__/\n";
        let plan = plan_gitignore(Some(bom), FRAGMENT).expect("the plan builds");
        let bytes = plan.file.expect("writes").bytes;
        assert!(bytes.starts_with(bom));
        assert_eq!(
            bytes.iter().filter(|byte| **byte == 0xef).count(),
            1,
            "exactly one leading BOM survives"
        );
    }
}
