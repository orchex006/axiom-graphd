//! F-008 bootstrap human-edit conformance vectors.
//!
//! The corpus under `fixtures/bootstrap/vectors/<id>/before/` holds byte-exact
//! before-states for the managed AGENTS.md bootstrap/update contract. The
//! production Rust updater does not exist in this crate yet: `commands::update`
//! implements version/trust gating and delegated `update apply` argv handling,
//! and `control` implements the control-token surface, but neither reads or
//! rewrites a managed block. This test therefore carries the documented oracle:
//! the managed-merge algorithm of
//! `docs/18-BOOTSTRAP-AND-MANAGED-INSTRUCTIONS.md` sections 4 and 5, the
//! conformance rows CF-018 (reapply is a no-op outside owned content), CF-019
//! (a human-modified block or stale plan conflicts and preserves content) and
//! CF-020 (half bootstrap/update crash recovers without losing user changes) of
//! `axiom-specs/docs/24-TEST-STRATEGY-AND-RELEASE-GATES.md`, and section 9 of
//! `axiom-specs/SOURCE-OF-TRUST.md`. It follows the semantics of the offline
//! reference `axiom-specs/reference/bootstrap_reference.py`.
//!
//! The negative half is the point of the slice: every conflict vector must be
//! refused with the destination tree left byte-identical, so a missing marker,
//! an out-of-order pair, a shadowed in-fence example or a human edit inside the
//! owned span can never be truncated or silently overwritten.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use graph_export::sha256_hex;
use serde::Deserialize;

/// Fenced marker examples use the same text as the real markers.
const BOM: &[u8] = &[0xef, 0xbb, 0xbf];

#[derive(Deserialize)]
struct Manifest {
    schema_version: u32,
    task: String,
    contract: Contract,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Contract {
    begin_marker: String,
    end_marker: String,
    block_template: String,
    policy_template: String,
    block_file_sha256: String,
    block_span_sha256: String,
    policy_sha256: String,
    template_version: String,
}

#[derive(Deserialize)]
struct Vector {
    id: String,
    outcome: String,
    #[serde(default)]
    reason_contains: Option<String>,
    #[serde(default)]
    changes: Vec<String>,
    #[serde(default)]
    preserve_literals: Vec<String>,
    #[serde(default)]
    expect_prefix: bool,
    #[serde(default)]
    expect_bom: bool,
    #[serde(default)]
    expect_crlf: bool,
    #[serde(default)]
    note: String,
}

#[derive(Deserialize)]
struct Ownership {
    schema_version: u32,
    managed_block_sha256: String,
    policy_sha256: String,
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("bootstrap")
}

fn read_opt(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot read {}: {error}", path.display())),
    }
}

fn decode(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes)
        .map_err(|_| "Unsupported encoding; this contract is UTF-8 only".to_owned())
}

/// Leading Markdown fence run on `line`: (fence character, run length, whether
/// the remainder of the line is blank).
fn fence_run(line: &str) -> Option<(char, usize, bool)> {
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

/// Byte span of the single managed block, excluding the newline that follows the
/// end marker. Returns `None` when no marker appears outside a code fence, and
/// refuses duplicate, nested or unbalanced markers.
fn managed_span(text: &str, begin: &str, end: &str) -> Result<Option<(usize, usize)>, String> {
    let mut offset = 0usize;
    let mut found: Vec<(bool, usize, usize)> = Vec::new();
    let mut fence: Option<(char, usize)> = None;
    for line in text.split_inclusive('\n') {
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
    if found.is_empty() {
        return Ok(None);
    }
    if found.len() != 2 || !found[0].0 || found[1].0 {
        return Err("Duplicate, nested or unbalanced managed markers".to_owned());
    }
    Ok(Some((found[0].1, found[1].2)))
}

fn ownership_bytes(template_version: &str, block_hash: &str, policy_hash: &str) -> Vec<u8> {
    format!(
        "{{\"managed_block_sha256\":\"{block_hash}\",\"policy_sha256\":\"{policy_hash}\",\"schema_version\":2,\"template_version\":\"{template_version}\"}}\n"
    )
    .into_bytes()
}

/// The managed-merge oracle. Returns the complete set of destination writes for
/// a successful plan, or the refusal reason for a conflict. It never returns a
/// partial result: a refused plan carries no bytes at all.
fn plan_repo(
    root: &Path,
    contract: &Contract,
    block_template: &str,
    policy: &[u8],
) -> Result<Vec<(PathBuf, Vec<u8>)>, String> {
    let agents_path = root.join("AGENTS.md");
    let policy_path = root.join(".axiom").join("agent").join("POLICY.md");
    let ownership_path = root
        .join(".axiom")
        .join("agent")
        .join("bootstrap.lock.json");

    let agents_raw = read_opt(&agents_path)?;
    let policy_raw = read_opt(&policy_path)?;
    let ownership_raw = read_opt(&ownership_path)?;

    let ownership: Option<Ownership> = match ownership_raw.as_deref() {
        Some(bytes) => {
            let parsed: Ownership = serde_json::from_str(decode(bytes)?)
                .map_err(|error| format!("Malformed ownership manifest: {error}"))?;
            if parsed.schema_version != 2 {
                return Err("Unsupported ownership schema".to_owned());
            }
            Some(parsed)
        }
        None => None,
    };

    let agents = decode(agents_raw.as_deref().unwrap_or(b""))?;
    let begin = contract.begin_marker.as_str();
    let end = contract.end_marker.as_str();
    let span = managed_span(agents, begin, end)?;

    match &ownership {
        None => {
            if span.is_some() {
                return Err("Managed markers exist without ownership".to_owned());
            }
            if policy_raw.is_some() {
                return Err("Existing policy file is unowned; refusing to overwrite it".to_owned());
            }
        }
        Some(owner) => {
            let (start, finish) =
                span.ok_or_else(|| "Managed AGENTS block was removed or edited".to_owned())?;
            if sha256_hex(&agents.as_bytes()[start..finish]) != owner.managed_block_sha256 {
                return Err("Managed AGENTS block was edited".to_owned());
            }
            match &policy_raw {
                None => return Err("Managed policy was removed or edited".to_owned()),
                Some(bytes) if sha256_hex(bytes) != owner.policy_sha256 => {
                    return Err("Managed policy was removed or edited".to_owned());
                }
                Some(_) => {}
            }
        }
    }

    let newline = if agents.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let template = block_template.trim_matches(|ch: char| ch == '\r' || ch == '\n');
    let new_block = template.replace("\r\n", "\n").replace('\n', newline);
    let after_agents = match span {
        Some((start, finish)) => format!("{}{}{}", &agents[..start], new_block, &agents[finish..]),
        None => {
            let suffix = if agents.is_empty() {
                String::new()
            } else if agents.ends_with('\n') || agents.ends_with('\r') {
                newline.to_owned()
            } else {
                format!("{newline}{newline}")
            };
            format!("{agents}{suffix}{new_block}{newline}")
        }
    };

    let after_text = decode(after_agents.as_bytes())?;
    let (block_start, block_end) = managed_span(after_text, begin, end)?
        .ok_or_else(|| "Planned content lost its managed block".to_owned())?;
    let block_hash = sha256_hex(&after_text.as_bytes()[block_start..block_end]);
    let policy_hash = sha256_hex(policy);

    let mut writes = Vec::new();
    if agents_raw.as_deref() != Some(after_agents.as_bytes()) {
        writes.push((agents_path, after_agents.into_bytes()));
    }
    if policy_raw.as_deref() != Some(policy) {
        writes.push((policy_path, policy.to_vec()));
    }
    let ownership_current = ownership.as_ref().is_some_and(|owner| {
        owner.managed_block_sha256 == block_hash && owner.policy_sha256 == policy_hash
    });
    if !ownership_current {
        writes.push((
            ownership_path,
            ownership_bytes(&contract.template_version, &block_hash, &policy_hash),
        ));
    }
    Ok(writes)
}

fn collect_files(root: &Path, prefix: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(root)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", root.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    entries.sort();
    for entry in entries {
        let relative = prefix.join(entry.file_name().expect("file name"));
        if entry.is_dir() {
            collect_files(&entry, &relative, out);
        } else {
            out.push(relative);
        }
    }
}

fn copy_tree(from: &Path, to: &Path) {
    let mut files = Vec::new();
    collect_files(from, Path::new(""), &mut files);
    for relative in files {
        let destination = to.join(&relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::copy(from.join(&relative), &destination).expect("copy fixture file");
    }
}

fn load_manifest(root: &Path) -> Manifest {
    let text = fs::read_to_string(root.join("vectors.json")).expect("read vectors.json");
    serde_json::from_str(&text).expect("parse vectors.json")
}

#[test]
fn every_bootstrap_vector_is_non_destructive() {
    let root = corpus_root();
    let manifest = load_manifest(&root);
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.task, "F-008");

    let contract = &manifest.contract;
    let block_template =
        fs::read_to_string(root.join(&contract.block_template)).expect("read block template");
    let policy = fs::read(root.join(&contract.policy_template)).expect("read policy template");
    assert_eq!(
        sha256_hex(block_template.as_bytes()),
        contract.block_file_sha256,
        "block template drifted from the pinned digest"
    );
    assert_eq!(
        sha256_hex(
            block_template
                .trim_matches(|ch: char| ch == '\r' || ch == '\n')
                .as_bytes()
        ),
        contract.block_span_sha256,
        "managed block span drifted from the pinned digest"
    );
    assert_eq!(
        sha256_hex(&policy),
        contract.policy_sha256,
        "policy template drifted from the pinned digest"
    );

    for outcome in ["append", "replace", "conflict", "unchanged"] {
        assert!(
            manifest
                .vectors
                .iter()
                .any(|vector| vector.outcome == outcome),
            "the corpus must keep at least one {outcome} vector"
        );
    }

    for vector in &manifest.vectors {
        assert!(
            !vector.note.trim().is_empty(),
            "vector {} carries no provenance note",
            vector.id
        );
        let before = root.join("vectors").join(&vector.id).join("before");
        assert!(before.is_dir(), "missing before tree for {}", vector.id);

        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("repo");
        copy_tree(&before, &repo);

        let mut before_files = Vec::new();
        collect_files(&repo, Path::new(""), &mut before_files);
        let before_bytes: Vec<Vec<u8>> = before_files
            .iter()
            .map(|relative| fs::read(repo.join(relative)).expect("read before file"))
            .collect();
        let before_agents = read_opt(&repo.join("AGENTS.md")).expect("read AGENTS.md");

        let planned = plan_repo(&repo, contract, &block_template, &policy);

        let expected_changes: BTreeSet<String> = vector
            .changes
            .iter()
            .map(|path| path.replace('\\', "/"))
            .collect();
        let mut actual_changes: BTreeSet<String> = BTreeSet::new();

        match vector.outcome.as_str() {
            "conflict" => {
                let reason =
                    planned.expect_err(&format!("{} must be refused, not planned", vector.id));
                if let Some(needle) = &vector.reason_contains {
                    assert!(
                        reason.to_lowercase().contains(&needle.to_lowercase()),
                        "{}: refusal {reason:?} does not mention {needle:?}",
                        vector.id
                    );
                }
            }
            _ => {
                let writes = planned.unwrap_or_else(|reason: String| {
                    panic!("{} must not conflict: {reason}", vector.id)
                });
                for (path, bytes) in &writes {
                    let relative = path
                        .strip_prefix(&repo)
                        .expect("write stays inside the repository")
                        .to_string_lossy()
                        .replace('\\', "/");
                    actual_changes.insert(relative);
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent).expect("create write parent");
                    }
                    fs::write(path, bytes).expect("apply planned write");
                }
            }
        }

        assert_eq!(
            actual_changes, expected_changes,
            "{} changed the wrong path set",
            vector.id
        );

        // Non-destructive core: every path the plan did not own is byte-identical.
        for (relative, original) in before_files.iter().zip(before_bytes.iter()) {
            let key = relative.to_string_lossy().replace('\\', "/");
            let current = fs::read(repo.join(relative)).expect("read after file");
            if expected_changes.contains(&key) {
                continue;
            }
            assert_eq!(
                &current, original,
                "{} rewrote unowned path {key}",
                vector.id
            );
        }

        if vector.outcome != "conflict" {
            let agents = fs::read(repo.join("AGENTS.md")).expect("read resulting AGENTS.md");
            if vector.expect_bom {
                assert!(
                    agents.starts_with(BOM),
                    "{} lost its leading BOM",
                    vector.id
                );
                assert!(
                    !agents[BOM.len()..].starts_with(BOM),
                    "{} duplicated its BOM",
                    vector.id
                );
            } else {
                assert!(
                    !agents.starts_with(BOM),
                    "{} gained a BOM it did not have",
                    vector.id
                );
            }
            let text = decode(&agents).expect("resulting AGENTS.md is UTF-8");
            let (start, finish) = managed_span(text, &contract.begin_marker, &contract.end_marker)
                .expect("resulting markers are valid")
                .expect("resulting markers exist");
            if vector.expect_crlf {
                assert!(
                    text[start..finish].contains("\r\n"),
                    "{} did not keep CRLF inside the managed block",
                    vector.id
                );
            } else {
                assert!(
                    !text[start..finish].contains("\r\n"),
                    "{} introduced CRLF into an LF managed block",
                    vector.id
                );
            }
            if vector.expect_prefix {
                let original = before_agents
                    .as_deref()
                    .expect("an append vector starts from an existing AGENTS.md");
                assert!(
                    agents.starts_with(original),
                    "{} did not keep the original bytes as an exact prefix",
                    vector.id
                );
            }
            for literal in &vector.preserve_literals {
                assert!(
                    text.contains(literal.as_str()),
                    "{} dropped preserved literal {literal:?}",
                    vector.id
                );
            }
        }
    }
}
