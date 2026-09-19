//! The ownership manifest and template version (task E-017).
//!
//! Bootstrap owns exactly two artifacts inside a repository: the managed span of
//! `AGENTS.md` and the managed policy file. The manifest at
//! [`OWNERSHIP_PATH`] is the record of what was written, and it deliberately
//! records *only* digests of that owned content plus the template version that
//! produced it. There is no per-path hash map, no directory listing and no
//! timestamp, so the manifest cannot grow into a description of files bootstrap
//! does not own.
//!
//! The manifest is also the reason a re-apply is safe. The digests are computed
//! from the exact bytes that were written - [`Ownership::new`] is the only
//! constructor and it takes those bytes - and [`detect_drift`] recomputes them
//! from the repository before an update is planned. A human edit inside the
//! owned block or inside the owned policy is therefore detected *before* any
//! write, and refused with a named rule instead of being overwritten.
//!
//! The manifest bytes are pinned by `fixtures/bootstrap`: every corpus lock file
//! re-encodes byte-identically, which is what makes "a re-apply is a no-op" true
//! rather than approximately true.

use graph_core::error::AxiomError;
use graph_export::canonical::canonical_value;
use graph_export::sha256_hex;
use serde::{Deserialize, Serialize};

use super::policy::POLICY_PATH;
use super::refuse;

/// The ownership manifest, relative to a repository root.
pub const OWNERSHIP_PATH: &str = ".axiom/agent/bootstrap.lock.json";

/// Schema version of the manifest this build writes.
pub const OWNERSHIP_SCHEMA_VERSION: u32 = 2;

/// Stable rule code: the manifest is not readable JSON in this schema.
pub const RULE_MALFORMED: &str = "ownership-malformed";

/// Stable rule code: the manifest declares a schema this build does not know.
pub const RULE_SCHEMA: &str = "ownership-schema";

/// Stable rule code: a recorded digest is not a canonical SHA-256.
pub const RULE_DIGEST: &str = "ownership-digest";

/// Stable rule code: the owned block no longer matches its recorded digest.
pub const RULE_BLOCK_EDITED: &str = "ownership-block-edited";

/// Stable rule code: the owned block is gone.
pub const RULE_BLOCK_REMOVED: &str = "ownership-block-removed";

/// Stable rule code: the owned policy no longer matches its recorded digest.
pub const RULE_POLICY_EDITED: &str = "ownership-policy-edited";

/// Stable rule code: the owned policy is gone.
pub const RULE_POLICY_REMOVED: &str = "ownership-policy-removed";

/// The two artifacts the manifest records, named for reports.
///
/// This list is what "hashes only for owned content" means in practice: the
/// manifest covers these two and nothing else.
pub const OWNED_ARTIFACTS: [&str; 2] = ["AGENTS.md managed block", POLICY_PATH];

/// The recorded ownership of one repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ownership {
    /// SHA-256 of the managed block text (the bytes between the markers).
    pub managed_block_sha256: String,
    /// SHA-256 of the whole managed policy file.
    pub policy_sha256: String,
    /// Schema version of this record.
    pub schema_version: u32,
    /// Template version that produced the recorded content.
    pub template_version: String,
}

impl Ownership {
    /// Record ownership of exactly the bytes that were written.
    ///
    /// The digests are computed here from the managed block text and the policy
    /// bytes, so a manifest can never claim ownership of content that was not
    /// handed to it.
    #[must_use]
    pub fn new(template_version: &str, managed_block: &str, policy: &[u8]) -> Self {
        Self {
            managed_block_sha256: sha256_hex(managed_block.as_bytes()),
            policy_sha256: sha256_hex(policy),
            schema_version: OWNERSHIP_SCHEMA_VERSION,
            template_version: template_version.to_owned(),
        }
    }

    /// The template version that wrote the owned content.
    #[must_use]
    pub fn template_version(&self) -> &str {
        &self.template_version
    }

    /// The recorded digest of the managed block.
    #[must_use]
    pub fn block_hash(&self) -> &str {
        &self.managed_block_sha256
    }

    /// The recorded digest of the managed policy file.
    #[must_use]
    pub fn policy_hash(&self) -> &str {
        &self.policy_sha256
    }

    /// Whether this manifest was written by the given template version.
    #[must_use]
    pub fn written_by(&self, template_version: &str) -> bool {
        self.template_version == template_version
    }

    /// The canonical bytes of this manifest, with a trailing newline.
    ///
    /// `fixtures/bootstrap` pins these bytes, so the encoding is part of the
    /// contract rather than an implementation detail: keys are sorted, the JSON
    /// is a single line and the file ends with exactly one newline.
    ///
    /// # Errors
    ///
    /// Returns a conflict when the record cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, AxiomError> {
        let value = serde_json::to_value(self).map_err(|error| {
            refuse(
                RULE_MALFORMED,
                format!("ownership manifest cannot be encoded: {error}"),
            )
        })?;
        let mut bytes = canonical_value(&value)
            .map_err(|error| refuse(RULE_MALFORMED, error.message))?
            .into_bytes();
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Parse and validate a manifest read from a repository.
    ///
    /// # Errors
    ///
    /// Returns a conflict carrying [`RULE_MALFORMED`] for unreadable or
    /// incomplete JSON, [`RULE_SCHEMA`] for an unknown schema version and
    /// [`RULE_DIGEST`] for a digest that is not a canonical SHA-256.
    pub fn parse(bytes: &[u8]) -> Result<Self, AxiomError> {
        let text = std::str::from_utf8(bytes).map_err(|error| {
            refuse(
                RULE_MALFORMED,
                format!("ownership manifest is not UTF-8: {error}"),
            )
        })?;
        let parsed: Self = serde_json::from_str(text).map_err(|error| {
            refuse(
                RULE_MALFORMED,
                format!("ownership manifest is malformed: {error}"),
            )
        })?;
        if parsed.schema_version != OWNERSHIP_SCHEMA_VERSION {
            return Err(refuse(
                RULE_SCHEMA,
                format!("unsupported ownership schema {}", parsed.schema_version),
            )
            .with_detail("field", "schema_version")
            .with_detail("observed", parsed.schema_version.to_string()));
        }
        for (field, digest) in [
            ("managed_block_sha256", parsed.managed_block_sha256.as_str()),
            ("policy_sha256", parsed.policy_sha256.as_str()),
        ] {
            if !is_sha256_hex(digest) {
                return Err(refuse(
                    RULE_DIGEST,
                    format!("ownership manifest records an invalid {field} digest"),
                )
                .with_detail("field", field)
                .with_detail("observed", digest));
            }
        }
        if parsed.template_version.trim().is_empty() {
            return Err(refuse(
                RULE_SCHEMA,
                "ownership manifest records an empty template_version",
            )
            .with_detail("field", "template_version"));
        }
        Ok(parsed)
    }

    /// Whether the observed owned content still matches this manifest.
    #[must_use]
    pub fn is_current(&self, managed_block: Option<&str>, policy: Option<&[u8]>) -> bool {
        detect_drift(self, managed_block, policy) == Drift::None
    }
}

/// How the repository diverged from its recorded ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drift {
    /// The owned content still matches the manifest.
    None,
    /// The managed block is present but its bytes changed.
    BlockEdited,
    /// The managed block (or its markers) is gone.
    BlockRemoved,
    /// The policy file is present but its bytes changed.
    PolicyEdited,
    /// The policy file is gone.
    PolicyRemoved,
}

impl Drift {
    /// Stable, greppable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "ownership-current",
            Self::BlockEdited => RULE_BLOCK_EDITED,
            Self::BlockRemoved => RULE_BLOCK_REMOVED,
            Self::PolicyEdited => RULE_POLICY_EDITED,
            Self::PolicyRemoved => RULE_POLICY_REMOVED,
        }
    }

    /// Whether this drift refuses the repository.
    #[must_use]
    pub const fn is_conflict(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Human-readable message. Each message carries the word the contract uses
    /// for that failure (`edited` for the block, `policy` for the policy).
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::None => "the owned content still matches the ownership manifest",
            Self::BlockEdited => "the managed AGENTS block was edited; refusing to overwrite it",
            Self::BlockRemoved => {
                "the managed AGENTS block was removed or edited; refusing to recreate it"
            }
            Self::PolicyEdited => "the managed policy file was edited; refusing to overwrite it",
            Self::PolicyRemoved => {
                "the managed policy file was removed or edited; refusing to recreate it"
            }
        }
    }

    /// The refusal for a conflicting drift.
    #[must_use]
    pub fn refusal(self) -> Option<AxiomError> {
        if !self.is_conflict() {
            return None;
        }
        Some(
            refuse(self.as_str(), self.message())
                .with_detail("field", "owned-content")
                .with_detail("observed", self.as_str()),
        )
    }
}

/// Detect whether the observed owned content still matches the manifest.
///
/// The block is checked before the policy, so a repository whose block was
/// removed reports that first instead of blaming a policy it still owns.
#[must_use]
pub fn detect_drift(
    ownership: &Ownership,
    managed_block: Option<&str>,
    policy: Option<&[u8]>,
) -> Drift {
    match (managed_block, policy) {
        (None, _) => Drift::BlockRemoved,
        (Some(block), _) if sha256_hex(block.as_bytes()) != ownership.managed_block_sha256 => {
            Drift::BlockEdited
        }
        (Some(_), None) => Drift::PolicyRemoved,
        (Some(_), Some(bytes)) if sha256_hex(bytes) != ownership.policy_sha256 => {
            Drift::PolicyEdited
        }
        (Some(_), Some(_)) => Drift::None,
    }
}

/// Refuse a repository whose owned content drifted from its manifest.
///
/// # Errors
///
/// Returns the [`Drift`] refusal. The caller's bytes are never modified.
pub fn ensure_no_drift(
    ownership: &Ownership,
    managed_block: Option<&str>,
    policy: Option<&[u8]>,
) -> Result<(), AxiomError> {
    match detect_drift(ownership, managed_block, policy).refusal() {
        Some(refusal) => Err(refusal),
        None => Ok(()),
    }
}

/// Whether `digest` is a canonical lowercase SHA-256 hex string.
#[must_use]
fn is_sha256_hex(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::markers;
    use crate::bootstrap::TEMPLATE_VERSION;
    use graph_core::error::ErrorCode;

    fn corpus_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("bootstrap")
    }

    fn rule_of(error: &AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    /// AC1 positive: the manifest records exactly the two owned digests and the
    /// template version, and round-trips through its own canonical encoding.
    #[test]
    fn the_manifest_records_only_owned_content_and_its_template_version() {
        let block = "<!-- axiom-graph:begin -->\nbody\n<!-- axiom-graph:end -->";
        let policy = b"# Axiom Graph Policy\n";
        let ownership = Ownership::new(TEMPLATE_VERSION, block, policy);

        assert_eq!(ownership.block_hash(), sha256_hex(block.as_bytes()));
        assert_eq!(ownership.policy_hash(), sha256_hex(policy));
        assert_eq!(ownership.template_version(), TEMPLATE_VERSION);
        assert_eq!(ownership.schema_version, OWNERSHIP_SCHEMA_VERSION);
        assert!(ownership.written_by(TEMPLATE_VERSION));
        assert!(!ownership.written_by("1.0.0"));

        let encoded = ownership.encode().expect("encodes");
        let text = std::str::from_utf8(&encoded).expect("UTF-8");
        assert!(text.ends_with('\n'), "the file ends with one newline");
        assert_eq!(text.matches('\n').count(), 1, "the JSON is a single line");
        let parsed: serde_json::Value = serde_json::from_str(text).expect("valid JSON");
        let keys: Vec<&String> = parsed.as_object().expect("object").keys().collect();
        assert_eq!(
            keys.len(),
            4,
            "only owned content and the version are recorded"
        );
        assert_eq!(
            keys,
            vec![
                "managed_block_sha256",
                "policy_sha256",
                "schema_version",
                "template_version"
            ],
            "the key set is exactly the owned hashes and the version"
        );
        assert_eq!(Ownership::parse(&encoded).expect("parses"), ownership);
        assert!(ownership.is_current(Some(block), Some(policy)));
        assert_eq!(OWNED_ARTIFACTS.len(), 2, "two artifacts are owned");
    }

    /// AC1 negative: a human edit inside owned content is detected before any
    /// update, and the refusal names the failure rather than the file.
    #[test]
    fn a_human_edit_inside_owned_content_is_detected_before_the_update() {
        let block = "<!-- axiom-graph:begin -->\nbody\n<!-- axiom-graph:end -->";
        let policy = b"# Axiom Graph Policy\n";
        let ownership = Ownership::new(TEMPLATE_VERSION, block, policy);

        let edited_block = format!("{block}\nmy own extra line");
        let drift = detect_drift(&ownership, Some(&edited_block), Some(policy));
        assert_eq!(drift, Drift::BlockEdited);
        let error = ensure_no_drift(&ownership, Some(&edited_block), Some(policy))
            .expect_err("an edited block is refused");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(rule_of(&error), Some(RULE_BLOCK_EDITED));
        assert!(error.message().contains("edited"), "{}", error.message());

        let removed = detect_drift(&ownership, None, Some(policy));
        assert_eq!(removed, Drift::BlockRemoved);
        assert!(
            removed.message().contains("edited"),
            "{}",
            removed.message()
        );

        let edited_policy = detect_drift(&ownership, Some(block), Some(b"# other\n"));
        assert_eq!(edited_policy, Drift::PolicyEdited);
        let error = ensure_no_drift(&ownership, Some(block), Some(b"# other\n"))
            .expect_err("an edited policy is refused");
        assert_eq!(rule_of(&error), Some(RULE_POLICY_EDITED));
        assert!(error.message().contains("policy"), "{}", error.message());

        let removed_policy = detect_drift(&ownership, Some(block), None);
        assert_eq!(removed_policy, Drift::PolicyRemoved);
        assert!(
            removed_policy.message().contains("policy"),
            "{}",
            removed_policy.message()
        );

        assert_eq!(
            detect_drift(&ownership, Some(block), Some(policy)),
            Drift::None
        );
        assert_eq!(Drift::None.refusal(), None);
        assert!(ensure_no_drift(&ownership, Some(block), Some(policy)).is_ok());
    }

    /// AC1 boundary: a manifest this build cannot trust is refused instead of
    /// being partially understood.
    #[test]
    fn an_untrusted_manifest_is_refused() {
        let ownership = Ownership::new(
            TEMPLATE_VERSION,
            &format!("{}\nbody\n{}", markers::BEGIN_MARKER, markers::END_MARKER),
            b"# policy\n",
        );
        let encoded = ownership.encode().expect("encodes");

        let truncated = &encoded[..encoded.len() - 4];
        let error = Ownership::parse(truncated).expect_err("malformed");
        assert_eq!(rule_of(&error), Some(RULE_MALFORMED));

        let not_utf8 = [0xff_u8, 0xfe, 0x00];
        assert_eq!(
            rule_of(&Ownership::parse(&not_utf8).expect_err("not utf-8")),
            Some(RULE_MALFORMED)
        );

        let wrong_schema = String::from_utf8(encoded.clone())
            .expect("UTF-8")
            .replace("\"schema_version\":2", "\"schema_version\":1");
        let error = Ownership::parse(wrong_schema.as_bytes()).expect_err("schema");
        assert_eq!(rule_of(&error), Some(RULE_SCHEMA));

        let short_digest = String::from_utf8(encoded.clone())
            .expect("UTF-8")
            .replace(&ownership.policy_sha256, "abc");
        let error = Ownership::parse(short_digest.as_bytes()).expect_err("digest");
        assert_eq!(rule_of(&error), Some(RULE_DIGEST));

        let uppercase = String::from_utf8(encoded.clone()).expect("UTF-8").replace(
            &ownership.policy_sha256,
            &ownership.policy_sha256.to_uppercase(),
        );
        assert_eq!(
            rule_of(&Ownership::parse(uppercase.as_bytes()).expect_err("not canonical")),
            Some(RULE_DIGEST)
        );

        let empty_version = String::from_utf8(encoded)
            .expect("UTF-8")
            .replace(TEMPLATE_VERSION, "");
        let error = Ownership::parse(empty_version.as_bytes()).expect_err("empty version");
        assert_eq!(rule_of(&error), Some(RULE_SCHEMA));
    }

    /// AC2: every corpus manifest re-encodes byte-identically - which is what
    /// makes "a re-apply is a no-op" true - and every recorded drift matches the
    /// failure the contract expects for that vector.
    #[test]
    fn the_bootstrap_corpus_manifests_match_this_record() {
        let root = corpus_root();
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(root.join("vectors.json")).expect("vectors.json"),
        )
        .expect("parse vectors");
        let vectors = manifest["vectors"].as_array().expect("vectors array");

        let mut manifests = 0usize;
        let mut current = 0usize;
        let mut refused = 0usize;
        for vector in vectors {
            let id = vector["id"].as_str().expect("id");
            let before = root.join("vectors").join(id).join("before");
            let Ok(bytes) = std::fs::read(
                before
                    .join(".axiom")
                    .join("agent")
                    .join("bootstrap.lock.json"),
            ) else {
                continue;
            };
            let ownership = Ownership::parse(&bytes)
                .unwrap_or_else(|error| panic!("{id}: corpus manifest is unreadable: {error}"));
            manifests += 1;
            assert_eq!(ownership.template_version(), TEMPLATE_VERSION, "{id}");
            assert_eq!(
                ownership.encode().expect("encodes"),
                bytes,
                "{id}: the manifest must re-encode byte-identically"
            );

            let agents = std::fs::read_to_string(before.join("AGENTS.md")).ok();
            let block = agents
                .as_deref()
                .and_then(|text| markers::managed_span(text).ok().flatten())
                .and_then(|span| agents.as_deref().and_then(|text| span.slice(text)));
            let policy = std::fs::read(before.join(".axiom").join("agent").join("POLICY.md")).ok();

            let drift = detect_drift(&ownership, block, policy.as_deref());
            match vector["reason_contains"].as_str() {
                Some(needle @ ("edited" | "policy")) => {
                    assert!(drift.is_conflict(), "{id} must be refused");
                    assert!(
                        drift.message().contains(needle),
                        "{id}: {:?} does not mention {needle:?}",
                        drift.message()
                    );
                    refused += 1;
                }
                _ => {
                    assert_eq!(drift, Drift::None, "{id} must still be current");
                    current += 1;
                }
            }
        }

        assert_eq!(manifests, 6, "six corpus before-states carry a manifest");
        assert_eq!(refused, 3, "three corpus vectors drifted");
        assert_eq!(current, 3, "three corpus vectors are still current");
    }
}
