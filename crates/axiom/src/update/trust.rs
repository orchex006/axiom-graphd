//! Signed update-metadata freshness and rollback/freeze protection (task E-036).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 3 is explicit that transport
//! is not authorship: "GitHub transport + SHA256 helps check completeness but
//! does not prove the publisher"; a signed metadata chain with a pinned trust
//! root is required, and an unsigned or untrusted update is refused. Section 4
//! repeats it for this exact slice: root, targets, snapshot and timestamp
//! metadata, expiry, rollback/freeze protection and root rotation are required
//! release gates.
//!
//! This module is the freshness gate for the metadata document a version check
//! reads. It enforces, fail-closed and with a named `rule` in every refusal:
//!
//! * the metadata baseline is the one this build reads;
//! * the document is not expired at the injected instant, and equals the expiry
//!   instant is already expired;
//! * the signature is present and uses an allowlisted algorithm;
//! * the signing key is one of the *configured* trust roots, matched by key id,
//!   algorithm and public key, so a release cannot self-certify;
//! * the signature verifier confirms the message that binds every trusted field;
//! * the metadata version never moves backwards (`rollback_refused`) and is never
//!   re-issued at the version already seen (`freeze_refused`);
//! * plain HTTP is refused even before the signature is considered, and HTTPS is
//!   still not accepted on its own, because the signature rules run regardless.
//!
//! The signature *math* is delegated to the [`SignatureVerifier`] the release
//! authority owns, exactly as the install trust gate does (task E-005). This
//! module must not carry a signing scheme or a private key, so it refuses every
//! document whose signature that verifier does not confirm.

use graph_core::error::{AxiomError, ErrorCode};
use serde::{Deserialize, Serialize};

use crate::install::verify::{
    is_rfc3339_utc, ArtifactSignature, SignatureVerifier, TrustedRoot, SIGNATURE_ALGORITHMS,
};

/// `schema_version` of the update metadata this build reads.
pub const UPDATE_METADATA_SCHEMA_VERSION: u64 = 1;

/// Domain separator of the bytes an update-metadata signature covers.
pub const SIGNING_MESSAGE_PREFIX: &str = "axiom-update-metadata-v1";

/// Channels a metadata document may declare, matching the install vocabulary.
pub const CHANNELS: [&str; 2] = ["stable", "prerelease"];

/// Transport the metadata arrived over.
///
/// It is an input rather than an assumption because HTTPS is necessary but not
/// sufficient: a document that arrived over TLS without a verified signature is
/// still unsigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// TLS was used.
    Https,
    /// No TLS was used; refused before the signature is considered.
    PlainHttp,
}

/// One signed update-metadata document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateMetadata {
    /// Baseline of this document.
    pub schema_version: u64,
    /// Monotonic metadata version; it must never move backwards.
    pub metadata_version: u64,
    /// RFC 3339 UTC creation time.
    pub generated_at: String,
    /// RFC 3339 UTC expiry; the document is refused at or after this instant.
    pub expires_at: String,
    /// Release channel this metadata describes.
    pub channel: String,
    /// The key the metadata claims to be signed by.
    pub root: TrustedRoot,
    /// The signature over [`signing_message`].
    pub signature: ArtifactSignature,
}

/// The trust roots the host was configured to accept.
///
/// An empty set is not "accept anything": a document can only be verified
/// against a key that is present, so a missing configuration refuses every
/// document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRoots {
    /// Pinned keys the host accepts.
    pub roots: Vec<TrustedRoot>,
}

impl TrustRoots {
    /// Build a pin set from explicit roots.
    #[must_use]
    pub fn pinned(roots: Vec<TrustedRoot>) -> Self {
        Self { roots }
    }

    /// True when no key was configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

/// The rollback/freeze protection state of the host.
///
/// `highest_metadata_version` is the highest metadata version this host has
/// already accepted. It is persisted state, injected here so freshness is a
/// pure function of its inputs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustState {
    /// Highest accepted metadata version; `0` means nothing accepted yet.
    pub highest_metadata_version: u64,
}

impl TrustState {
    /// State that has accepted nothing yet.
    #[must_use]
    pub fn fresh() -> Self {
        Self::default()
    }

    /// State that has already accepted `metadata_version`.
    #[must_use]
    pub fn at(metadata_version: u64) -> Self {
        Self {
            highest_metadata_version: metadata_version,
        }
    }
}

/// The proof produced by a successful [`verify_metadata`].
///
/// The type is the proof: it is only constructed at the end of the checks, so
/// downstream planning can take one by value and know the metadata was signed by
/// a configured root, was fresh and did not move the version backwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedMetadata {
    /// Accepted metadata version.
    pub metadata_version: u64,
    /// Channel the metadata describes.
    pub channel: String,
    /// Creation time of the accepted document.
    pub generated_at: String,
    /// Expiry of the accepted document.
    pub expires_at: String,
    /// Key id that confirmed the signature.
    pub key_id: String,
    /// Lowercase 64-hex fingerprint of the trust root that confirmed it.
    pub trust_root: String,
}

/// The exact bytes an update-metadata signature covers.
///
/// The message binds every trusted property of the document, so a signature
/// cannot be replayed for different metadata, a different version or a different
/// key.
#[must_use]
pub fn signing_message(metadata: &UpdateMetadata) -> Vec<u8> {
    format!(
        "{SIGNING_MESSAGE_PREFIX}\nschema_version={}\nmetadata_version={}\nchannel={}\ngenerated_at={}\nexpires_at={}\nroot_key_id={}\nroot_algorithm={}\nroot_public_key={}\n",
        metadata.schema_version,
        metadata.metadata_version,
        metadata.channel,
        metadata.generated_at,
        metadata.expires_at,
        metadata.root.key_id,
        metadata.root.algorithm,
        metadata.root.public_key
    )
    .into_bytes()
}

/// Lowercase 64-hex fingerprint of a trust root.
///
/// It binds the whole key definition, so the plan's `trust_root` field names the
/// exact pinned key and not merely its id.
#[must_use]
pub fn root_fingerprint(root: &TrustedRoot) -> String {
    graph_export::sha256_hex(
        format!(
            "axiom-update-root-v1\nkey_id={}\nalgorithm={}\npublic_key={}\n",
            root.key_id, root.algorithm, root.public_key
        )
        .as_bytes(),
    )
}

/// Verify one signed update-metadata document.
///
/// # Errors
///
/// Fails closed, with the `rule` detail naming the first violated rule, when the
/// transport is plain HTTP, the baseline is unknown, a timestamp is malformed,
/// the document is expired, the channel is unsupported, no trust root is
/// configured, the claimed key is not a configured root, the signature is
/// unsigned or uses an unallowlisted algorithm, the verifier rejects it, or the
/// metadata version would roll back or freeze.
pub fn verify_metadata(
    metadata: &UpdateMetadata,
    roots: &TrustRoots,
    state: &TrustState,
    now: &str,
    transport: Transport,
    verifier: &impl SignatureVerifier,
) -> Result<VerifiedMetadata, AxiomError> {
    if transport != Transport::Https {
        return Err(forbid(
            "insecure_transport",
            "transport=plain-http",
            "update metadata was not fetched over TLS",
        ));
    }
    if metadata.schema_version != UPDATE_METADATA_SCHEMA_VERSION {
        return Err(refuse(
            "unsupported_metadata_schema",
            &format!("schema_version={}", metadata.schema_version),
        ));
    }
    if !is_rfc3339_utc(now) {
        return Err(refuse("invalid_now", &format!("now={now}")));
    }
    for (field, value) in [
        ("generated_at", &metadata.generated_at),
        ("expires_at", &metadata.expires_at),
    ] {
        if !is_rfc3339_utc(value) {
            return Err(refuse("invalid_timestamp", &format!("{field}={value}")));
        }
    }
    if metadata.expires_at <= metadata.generated_at {
        return Err(refuse(
            "expiry_not_after_creation",
            &format!(
                "generated_at={};expires_at={}",
                metadata.generated_at, metadata.expires_at
            ),
        ));
    }
    if now >= metadata.expires_at.as_str() {
        return Err(refuse(
            "metadata_expired",
            &format!("now={now};expires_at={}", metadata.expires_at),
        ));
    }
    if !CHANNELS.contains(&metadata.channel.as_str()) {
        return Err(refuse(
            "unsupported_channel",
            &format!("channel={}", metadata.channel),
        ));
    }
    if metadata.metadata_version == 0 {
        return Err(refuse("invalid_metadata_version", "metadata_version=0"));
    }
    if roots.is_empty() {
        return Err(forbid(
            "unconfigured_trust_root",
            "roots=0",
            "no trust root is configured, so no update metadata can be verified",
        ));
    }
    let configured = roots
        .roots
        .iter()
        .find(|root| root.key_id == metadata.root.key_id)
        .ok_or_else(|| {
            forbid(
                "untrusted_root",
                &format!("key_id={}", metadata.root.key_id),
                "the metadata signing key is not a configured trust root",
            )
        })?;
    if configured.algorithm != metadata.root.algorithm
        || configured.public_key != metadata.root.public_key
    {
        return Err(forbid(
            "root_mismatch",
            &format!("key_id={}", metadata.root.key_id),
            "the metadata key does not match the configured trust root",
        ));
    }
    if !SIGNATURE_ALGORITHMS.contains(&metadata.signature.algorithm.as_str()) {
        return Err(refuse(
            "unsupported_signature_algorithm",
            &format!("algorithm={}", metadata.signature.algorithm),
        ));
    }
    if metadata.signature.value.is_empty() {
        return Err(forbid(
            "unsigned_metadata",
            "signature=<empty>",
            "update metadata carries no signature; absence is never implicit trust",
        ));
    }
    if !verifier.verify(
        &metadata.signature.algorithm,
        &metadata.root.public_key,
        &signing_message(metadata),
        &metadata.signature.value,
    ) {
        return Err(forbid(
            "signature_invalid",
            &format!("key_id={}", metadata.root.key_id),
            "the update-metadata signature was not confirmed by the trust root",
        ));
    }
    if metadata.metadata_version < state.highest_metadata_version {
        return Err(refuse(
            "rollback_refused",
            &format!(
                "metadata_version={};highest={}",
                metadata.metadata_version, state.highest_metadata_version
            ),
        ));
    }
    if metadata.metadata_version == state.highest_metadata_version {
        return Err(refuse(
            "freeze_refused",
            &format!(
                "metadata_version={};highest={}",
                metadata.metadata_version, state.highest_metadata_version
            ),
        ));
    }
    Ok(VerifiedMetadata {
        metadata_version: metadata.metadata_version,
        channel: metadata.channel.clone(),
        generated_at: metadata.generated_at.clone(),
        expires_at: metadata.expires_at.clone(),
        key_id: metadata.root.key_id.clone(),
        trust_root: root_fingerprint(configured),
    })
}

/// The one refusal shape of this module.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the update metadata violates the freshness contract",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

/// Refuse something the host is not authorized to accept.
fn forbid(rule: &str, observed: &str, message: &str) -> AxiomError {
    AxiomError::new(ErrorCode::Forbidden, message)
        .with_detail("rule", rule)
        .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_KEY: &str = "3f1c9a5d2b7e4f80a1c6d9e2b5f8a3c0d7e4b1f9a6c3d0e7b4f1a8c5d2e9b6f3";
    const NOW: &str = "2026-09-19T00:00:00Z";

    /// A verifier double that confirms exactly the signature it was handed.
    struct AcceptingVerifier {
        expected: String,
    }

    impl SignatureVerifier for AcceptingVerifier {
        fn verify(
            &self,
            _algorithm: &str,
            _public_key: &str,
            _message: &[u8],
            signature: &str,
        ) -> bool {
            signature == self.expected
        }
    }

    fn root() -> TrustedRoot {
        TrustedRoot {
            key_id: "release-2026".to_string(),
            algorithm: "ed25519".to_string(),
            public_key: PUBLIC_KEY.to_string(),
        }
    }

    fn metadata() -> UpdateMetadata {
        UpdateMetadata {
            schema_version: UPDATE_METADATA_SCHEMA_VERSION,
            metadata_version: 7,
            generated_at: "2026-09-01T00:00:00Z".to_string(),
            expires_at: "2026-10-01T00:00:00Z".to_string(),
            channel: "stable".to_string(),
            root: root(),
            signature: ArtifactSignature {
                algorithm: "ed25519".to_string(),
                key_id: "release-2026".to_string(),
                value: "sig-7".to_string(),
            },
        }
    }

    fn verify(metadata: &UpdateMetadata) -> Result<VerifiedMetadata, AxiomError> {
        verify_metadata(
            metadata,
            &TrustRoots::pinned(vec![root()]),
            &TrustState::at(6),
            NOW,
            Transport::Https,
            &AcceptingVerifier {
                expected: "sig-7".to_string(),
            },
        )
    }

    fn rule_of(error: &AxiomError) -> String {
        error.details().get("rule").cloned().unwrap_or_default()
    }

    #[test]
    fn signed_fresh_metadata_from_a_configured_root_is_accepted() {
        let verified = verify(&metadata()).expect("a valid document is accepted");
        assert_eq!(verified.metadata_version, 7);
        assert_eq!(verified.channel, "stable");
        assert_eq!(verified.key_id, "release-2026");
        assert_eq!(verified.trust_root, root_fingerprint(&root()));
        assert_eq!(verified.trust_root.len(), 64);
        // The signed message binds every trusted field, so none can be replayed.
        let message = String::from_utf8(signing_message(&metadata())).expect("utf8");
        for field in [
            "schema_version=1",
            "metadata_version=7",
            "channel=stable",
            "generated_at=2026-09-01T00:00:00Z",
            "expires_at=2026-10-01T00:00:00Z",
            "root_key_id=release-2026",
            "root_public_key=",
        ] {
            assert!(message.contains(field), "message missing {field}");
        }
        assert!(message.starts_with(SIGNING_MESSAGE_PREFIX));
    }

    #[test]
    fn https_alone_is_not_enough() {
        // A perfectly valid HTTPS fetch of an unsigned document is refused.
        let mut unsigned = metadata();
        unsigned.signature.value = String::new();
        let error = verify(&unsigned).expect_err("unsigned metadata must be refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule_of(&error), "unsigned_metadata");

        // Plain HTTP is refused earlier, even when the signature would verify.
        let error = verify_metadata(
            &metadata(),
            &TrustRoots::pinned(vec![root()]),
            &TrustState::at(6),
            NOW,
            Transport::PlainHttp,
            &AcceptingVerifier {
                expected: "sig-7".to_string(),
            },
        )
        .expect_err("plain http must be refused");
        assert_eq!(rule_of(&error), "insecure_transport");
    }

    #[test]
    fn a_key_that_is_not_a_configured_root_is_refused() {
        let mut foreign = metadata();
        foreign.root.key_id = "release-attacker".to_string();
        let error = verify(&foreign).expect_err("an unpinned key must be refused");
        assert_eq!(rule_of(&error), "untrusted_root");

        // The same key id with different key material is not the pinned root.
        let mut swapped = metadata();
        swapped.root.public_key = "00".repeat(32);
        let error = verify(&swapped).expect_err("swapped key material must be refused");
        assert_eq!(rule_of(&error), "root_mismatch");

        // An empty pin set refuses instead of accepting anything.
        let error = verify_metadata(
            &metadata(),
            &TrustRoots::default(),
            &TrustState::at(0),
            NOW,
            Transport::Https,
            &AcceptingVerifier {
                expected: "sig-7".to_string(),
            },
        )
        .expect_err("no configured root must refuse");
        assert_eq!(rule_of(&error), "unconfigured_trust_root");
        assert!(TrustRoots::default().is_empty());
    }

    #[test]
    fn expiry_and_creation_time_are_enforced() {
        let mut expired = metadata();
        expired.generated_at = "2026-08-01T00:00:00Z".to_string();
        expired.expires_at = "2026-09-01T00:00:00Z".to_string();
        let error = verify(&expired).expect_err("expired metadata must be refused");
        assert_eq!(rule_of(&error), "metadata_expired");

        // Equal to the expiry instant is already expired, so it is a boundary.
        let mut boundary = metadata();
        boundary.generated_at = "2026-08-01T00:00:00Z".to_string();
        boundary.expires_at = NOW.to_string();
        let error = verify(&boundary).expect_err("expiry == now must be refused");
        assert_eq!(rule_of(&error), "metadata_expired");

        let mut inverted = metadata();
        inverted.generated_at = "2026-10-01T00:00:00Z".to_string();
        inverted.expires_at = "2026-09-01T00:00:00Z".to_string();
        let error = verify(&inverted).expect_err("expiry before creation must be refused");
        assert_eq!(rule_of(&error), "expiry_not_after_creation");

        let mut malformed = metadata();
        malformed.expires_at = "2026-10-01T00:00:00+07:00".to_string();
        let error = verify(&malformed).expect_err("a local offset must be refused");
        assert_eq!(rule_of(&error), "invalid_timestamp");
    }

    #[test]
    fn rollback_and_freeze_are_refused() {
        let mut rolled_back = metadata();
        rolled_back.metadata_version = 5;
        let error = verify(&rolled_back).expect_err("a lower metadata version must be refused");
        assert_eq!(rule_of(&error), "rollback_refused");

        let mut frozen = metadata();
        frozen.metadata_version = 6;
        let error = verify(&frozen).expect_err("a re-issued metadata version must be refused");
        assert_eq!(rule_of(&error), "freeze_refused");

        // Exactly one step forward is the accepted boundary.
        let mut forward = metadata();
        forward.metadata_version = 7;
        assert!(verify(&forward).is_ok());
        // And a host that has accepted nothing yet accepts version 1.
        let mut first = metadata();
        first.metadata_version = 1;
        assert!(verify_metadata(
            &first,
            &TrustRoots::pinned(vec![root()]),
            &TrustState::fresh(),
            NOW,
            Transport::Https,
            &AcceptingVerifier {
                expected: "sig-7".to_string(),
            },
        )
        .is_ok());
    }

    #[test]
    fn an_unsupported_algorithm_or_channel_is_refused() {
        let mut weak = metadata();
        weak.signature.algorithm = "hmac-sha256".to_string();
        let error = verify(&weak).expect_err("a non-allowlisted algorithm must be refused");
        assert_eq!(rule_of(&error), "unsupported_signature_algorithm");

        let mut nightly = metadata();
        nightly.channel = "nightly".to_string();
        let error = verify(&nightly).expect_err("an unknown channel must be refused");
        assert_eq!(rule_of(&error), "unsupported_channel");

        let mut future = metadata();
        future.schema_version = 2;
        let error = verify(&future).expect_err("an unknown baseline must be refused");
        assert_eq!(rule_of(&error), "unsupported_metadata_schema");

        assert_eq!(SIGNATURE_ALGORITHMS, ["ed25519"]);
        assert_eq!(UPDATE_METADATA_SCHEMA_VERSION, 1);
        assert_eq!(CHANNELS, ["stable", "prerelease"]);
    }

    #[test]
    fn a_signature_that_does_not_verify_is_refused() {
        let error = verify_metadata(
            &metadata(),
            &TrustRoots::pinned(vec![root()]),
            &TrustState::at(6),
            NOW,
            Transport::Https,
            &AcceptingVerifier {
                expected: "some-other-signature".to_string(),
            },
        )
        .expect_err("a rejected signature must be refused");
        assert_eq!(rule_of(&error), "signature_invalid");
        // A malformed instant is refused before any key work.
        let error = verify_metadata(
            &metadata(),
            &TrustRoots::pinned(vec![root()]),
            &TrustState::at(6),
            "now",
            Transport::Https,
            &AcceptingVerifier {
                expected: "sig-7".to_string(),
            },
        )
        .expect_err("a malformed now must be refused");
        assert_eq!(rule_of(&error), "invalid_now");
    }
}
