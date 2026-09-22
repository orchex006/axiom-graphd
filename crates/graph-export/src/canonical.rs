//! Canonical publication bytes (task B-067).
//!
//! Every artifact in a generation is written in one byte form, so two runs that
//! read the same facts produce the same bytes and therefore the same hashes:
//!
//! * compact JSON - no insignificant whitespace;
//! * object keys sorted by code point;
//! * UTF-8 with `\n` line endings, one complete value per line;
//! * a trailing newline, so a line-oriented reader sees every record.
//!
//! Identity is stricter than the published bytes. The published bytes keep the
//! facts a reader needs; the identity digest additionally removes the values
//! that change every run - timestamps, host names and absolute paths - and
//! makes path-like values relative to the configured workspace root. A record
//! therefore keeps the same identity when it is published from a different
//! checkout, on a different machine, on a different day.

use serde_json::{Map, Value};

use crate::{ExportError, GraphRecord, Result, ERR_CANONICAL};

/// Field names whose value never contributes to identity.
///
/// These change between runs without the analysed facts changing.
pub const VOLATILE_FIELDS: [&str; 8] = [
    "generated_at",
    "timestamp",
    "updated_at",
    "created_at",
    "mtime",
    "host",
    "hostname",
    "run_id",
];

/// Field names whose value is a filesystem path and is made root-relative.
pub const PATH_FIELDS: [&str; 4] = ["path", "absolute_path", "abs_path", "file"];

/// The token written in place of a path outside the workspace root.
pub const OUTSIDE_ROOT: &str = "<outside-root>";

/// How identity is computed for a record set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentityPolicy {
    /// The workspace root absolute paths are made relative to.
    pub workspace_root: Option<String>,
}

impl IdentityPolicy {
    /// A policy that makes paths relative to `root`.
    #[must_use]
    pub fn rooted(root: impl Into<String>) -> Self {
        Self {
            workspace_root: Some(root.into()),
        }
    }

    /// The canonical, identity-stable form of a path.
    #[must_use]
    pub fn normalize_path(&self, raw: &str) -> String {
        let forward = raw.replace('\\', "/");
        let trimmed = forward.trim();
        match &self.workspace_root {
            None => trimmed.trim_start_matches("./").to_string(),
            Some(root) => {
                let normalized_root = root.replace('\\', "/");
                let root = normalized_root.trim_end_matches('/');
                let trimmed = trimmed.trim_start_matches("./");
                if let Some(rest) = trimmed.strip_prefix(root) {
                    return rest.trim_start_matches('/').to_string();
                }
                if !trimmed.starts_with('/') && !looks_absolute(trimmed) {
                    return trimmed.to_string();
                }
                OUTSIDE_ROOT.to_string()
            }
        }
    }
}

/// Whether a path is absolute on either supported platform.
fn looks_absolute(path: &str) -> bool {
    path.starts_with('/') || path.starts_with("//") || path.as_bytes().get(1) == Some(&b':')
}

/// Canonically encode one value: compact, sorted keys, no newline.
pub fn canonical_value(value: &Value) -> Result<String> {
    serde_json::to_string(value).map_err(|error| {
        ExportError::new(ERR_CANONICAL, format!("value cannot be encoded: {error}"))
    })
}

/// Canonically encode one record as a single line, without its newline.
pub fn canonical_record(record: &GraphRecord) -> Result<String> {
    let value = serde_json::to_value(record).map_err(|error| {
        ExportError::new(ERR_CANONICAL, format!("record cannot be encoded: {error}"))
    })?;
    canonical_value(&value)
}

/// Canonically encode a record set: one line per record, in caller order.
pub fn canonical_document(records: &[GraphRecord]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for record in records {
        out.extend_from_slice(canonical_record(record)?.as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

/// Canonically encode one value as a standalone document.
///
/// The contract fixes one byte form for every metadata document a generation
/// publishes: compact separators, object keys sorted by code point, UTF-8 with
/// no BOM and exactly one trailing LF. A document is a JSON array or object, not
/// a sequence of lines, so `docs/11-GRAPH-DATA-CONTRACT.md` section 6's "JSON
/// ทุกไฟล์ parse แยกได้ ไม่เป็น JSONL" holds: a reader parses the whole file,
/// and the shipped `axiom-mcp` reader's canonical check accepts these bytes
/// unchanged.
///
/// # Errors
///
/// [`ERR_CANONICAL`] when the value cannot be encoded.
pub fn canonical_document_value(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = canonical_value(value)?.into_bytes();
    bytes.push(b'\n');
    Ok(bytes)
}
/// Return a copy of `value` with volatile fields removed and paths normalised.
#[must_use]
pub fn identity_value(value: &Value, policy: &IdentityPolicy) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, child) in map {
                if VOLATILE_FIELDS.contains(&key.as_str()) {
                    continue;
                }
                if PATH_FIELDS.contains(&key.as_str()) {
                    if let Value::String(path) = child {
                        out.insert(key.clone(), Value::String(policy.normalize_path(path)));
                        continue;
                    }
                }
                out.insert(key.clone(), identity_value(child, policy));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| identity_value(item, policy))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The identity bytes of a record set: stripped, sorted, newline terminated.
///
/// Sorting makes the digest independent of the order a producer happened to
/// emit records in, which is not part of the analysed architecture.
pub fn identity_document(records: &[GraphRecord], policy: &IdentityPolicy) -> Result<Vec<u8>> {
    let mut lines = Vec::with_capacity(records.len());
    for record in records {
        let value = serde_json::to_value(record).map_err(|error| {
            ExportError::new(ERR_CANONICAL, format!("record cannot be encoded: {error}"))
        })?;
        lines.push(canonical_value(&identity_value(&value, policy))?);
    }
    lines.sort_unstable();
    let mut out = String::new();
    for line in lines {
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out.into_bytes())
}

/// The SHA-256 identity digest of a record set.
pub fn identity_sha256(records: &[GraphRecord], policy: &IdentityPolicy) -> Result<String> {
    Ok(crate::sha256_hex(&identity_document(records, policy)?))
}

/// Whether `text` is already in the canonical line form this module produces.
#[must_use]
pub fn is_canonical_text(text: &str) -> bool {
    if !text.is_empty() && !text.ends_with('\n') {
        return false;
    }
    text.lines().all(|line| {
        if line.is_empty() {
            return true;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(value) => canonical_value(&value).is_ok_and(|canonical| canonical == line),
            Err(_) => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        canonical_document, canonical_record, identity_sha256, is_canonical_text, IdentityPolicy,
    };
    use crate::GraphRecord;

    fn records() -> Vec<GraphRecord> {
        vec![
            GraphRecord::new(
                "edge:a->b",
                "edge",
                json!({"relation": "calls", "from": "a", "to": "b"}),
            ),
            GraphRecord::new(
                "edge:b->c",
                "edge",
                json!({"relation": "calls", "from": "b", "to": "c"}),
            ),
        ]
    }

    #[test]
    fn canonical_bytes_match_the_python_golden_bytes() {
        // The equivalent Python is
        // `json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"`.
        let record = GraphRecord::new(
            "edge:a->b",
            "edge",
            json!({"relation": "calls", "from": "a", "to": "b"}),
        );
        assert_eq!(
            canonical_record(&record).expect("canonical"),
            r#"{"body":{"from":"a","relation":"calls","to":"b"},"key":"edge:a->b","kind":"edge"}"#
        );
        let document = canonical_document(&[record]).expect("canonical");
        assert_eq!(
            String::from_utf8(document).expect("utf8"),
            "{\"body\":{\"from\":\"a\",\"relation\":\"calls\",\"to\":\"b\"},\"key\":\"edge:a->b\",\"kind\":\"edge\"}\n"
        );
    }

    #[test]
    fn keys_are_sorted_and_there_is_no_insignificant_whitespace() {
        let record = GraphRecord::new("k", "edge", json!({"z": 1, "a": 2, "m": {"y": 1, "b": 2}}));
        let line = canonical_record(&record).expect("canonical");
        assert_eq!(
            line,
            r#"{"body":{"a":2,"m":{"b":2,"y":1},"z":1},"key":"k","kind":"edge"}"#
        );
        assert!(!line.contains(' '));
        assert!(is_canonical_text(&format!("{line}\n")));
        assert!(!is_canonical_text(&line));
    }

    #[test]
    fn timestamps_hostnames_and_absolute_paths_cannot_perturb_identity() {
        let policy = IdentityPolicy::rooted("D:/repo");
        let first = GraphRecord::new(
            "k",
            "symbol",
            json!({
                "path": "D:\\repo\\crates\\graph-core\\src\\lib.rs",
                "generated_at": "2026-01-01T00:00:00Z",
                "host": "build-agent-1",
                "name": "Config"
            }),
        );
        let second = GraphRecord::new(
            "k",
            "symbol",
            json!({
                "path": "crates/graph-core/src/lib.rs",
                "generated_at": "2027-09-18T12:34:56Z",
                "host": "build-agent-9",
                "name": "Config"
            }),
        );
        assert_eq!(
            identity_sha256(std::slice::from_ref(&first), &policy).expect("digest"),
            identity_sha256(std::slice::from_ref(&second), &policy).expect("digest")
        );
        let different_name = GraphRecord::new(
            "k",
            "symbol",
            json!({"path": "crates/graph-core/src/lib.rs", "name": "Other"}),
        );
        assert_ne!(
            identity_sha256(&[first], &policy).expect("digest"),
            identity_sha256(&[different_name], &policy).expect("digest")
        );
    }

    #[test]
    fn identity_is_independent_of_record_order() {
        let policy = IdentityPolicy::default();
        let forward = identity_sha256(&records(), &policy).expect("digest");
        let mut reversed = records();
        reversed.reverse();
        assert_eq!(
            forward,
            identity_sha256(&reversed, &policy).expect("digest")
        );
    }

    #[test]
    fn a_path_outside_the_workspace_root_cannot_leak_into_identity() {
        let policy = IdentityPolicy::rooted("D:/repo");
        assert_eq!(policy.normalize_path("D:\\repo\\a\\b.rs"), "a/b.rs");
        assert_eq!(policy.normalize_path("./a/b.rs"), "a/b.rs");
        assert_eq!(
            policy.normalize_path("C:\\users\\someone\\secrets.rs"),
            super::OUTSIDE_ROOT
        );
        assert_eq!(
            policy.normalize_path("/home/other/x.rs"),
            super::OUTSIDE_ROOT
        );
    }
}
