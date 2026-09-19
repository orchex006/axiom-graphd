//! Trusted release metadata and artifact verification (task E-005).
//!
//! `21-INSTALLATION.md` section C step 2 requires the installer to verify the
//! checksum *and* the signature of a downloaded bundle against a known trust
//! root before anything is executed, and to have an offline verification
//! procedure. This module is that gate. It is deliberately the strictest layer
//! in the install pipeline: every refusal below is fail-closed, and no function
//! here can execute, install or contact anything.
//!
//! ## What this module decides, and what it delegates
//!
//! The trust *policy* is decided here, structurally and without any dependency
//! on a particular signature scheme:
//!
//! * the metadata baseline must be the one this build reads;
//! * the metadata must not be expired at the injected [TrustPolicy::now];
//! * the artifact must be built for a host this policy accepts;
//! * the actual bytes must match the trusted digest and size exactly;
//! * the signature must be present, non-empty and use an allowlisted algorithm;
//! * the signing key must be a key this release itself publishes.
//!
//! The signature *math* is delegated to a caller-supplied [SignatureVerifier].
//! That is not a weakening: axiom-graphd must not invent a signing scheme or
//! carry a private key, so the release authority supplies the verifier that
//! understands its key material, and this module simply refuses any artifact
//! whose signature that verifier does not confirm. [RejectingVerifier] is the
//! fail-closed default when no verifier is configured at all.
//!
//! ## Offline
//!
//! Nothing here opens a socket. Bytes arrive through the [ArtifactReader]
//! abstraction, so the same verification runs over a local bundle, a cached
//! release directory or an injected fixture, and the offline procedure of
//! section H is the same code path as the online one.

use std::io::Read as _;
use std::path::Path;

use graph_core::error::{AxiomError, ErrorCode};
use serde::{Deserialize, Serialize};

use crate::install::plan::{is_digest, ArtifactKind, COMPONENTS, HOSTS};

/// `schema_version` of the trusted release metadata this build reads.
pub const RELEASE_METADATA_SCHEMA_VERSION: u64 = 1;

/// Name of the trusted metadata document inside a release directory.
pub const TRUSTED_METADATA_FILE: &str = "release-metadata.json";

/// Upper bound on the metadata bytes this module reads.
pub const MAX_METADATA_BYTES: u64 = 256 * 1024;

/// Upper bound on one artifact this module will hash.
pub const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

/// Upper bound on artifacts one metadata document may declare.
pub const MAX_ARTIFACTS: usize = 64;

/// Signature algorithms a release may declare.
///
/// The list is an allowlist, not a menu: an algorithm outside it is refused
/// even when a verifier would accept it, so one compromised release cannot
/// silently downgrade the ecosystem to a different scheme.
pub const SIGNATURE_ALGORITHMS: [&str; 1] = ["ed25519"];

/// Channels a release may declare.
pub const CHANNELS: [&str; 2] = ["stable", "prerelease"];

/// One key the release authority publishes as a trust root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRoot {
    /// Stable identifier of the key.
    pub key_id: String,
    /// Algorithm the key is used with, from [SIGNATURE_ALGORITHMS].
    pub algorithm: String,
    /// Public key material, as the release authority encodes it.
    pub public_key: String,
}

/// The signature an artifact carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSignature {
    /// Algorithm the signature was produced with.
    pub algorithm: String,
    /// Key the signature claims to be from.
    pub key_id: String,
    /// The signature itself. An empty value is an unsigned artifact.
    pub value: String,
}

/// One artifact a release declares, with the trusted view of its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactMetadata {
    /// Component name from the install vocabulary.
    pub component: String,
    /// Version of the artifact.
    pub version: String,
    /// Host the artifact was built for, from [HOSTS].
    pub host: String,
    /// Kind of payload.
    pub kind: ArtifactKind,
    /// Bundle-relative location of the payload.
    pub artifact: String,
    /// Trusted lowercase 64-hex digest of the payload.
    pub sha256: String,
    /// Trusted size of the payload in bytes.
    pub size_bytes: u64,
    /// Signature over [signing_message].
    pub signature: ArtifactSignature,
}

/// The trusted metadata document of one release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseMetadata {
    /// Baseline of this document.
    pub schema_version: u64,
    /// Identifier of the release.
    pub release_id: String,
    /// Channel of the release.
    pub channel: String,
    /// RFC 3339 UTC creation time.
    pub generated_at: String,
    /// RFC 3339 UTC expiry; the document is refused at or after this instant.
    pub expires_at: String,
    /// Keys this release is willing to be verified against.
    pub roots: Vec<TrustedRoot>,
    /// Artifacts this release declares.
    pub artifacts: Vec<ArtifactMetadata>,
}

/// The trust policy of the host doing the install.
///
/// `now` is injected rather than read from a clock, so verification is a pure
/// function of its inputs and two runs over one release agree exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    /// Hosts this install accepts artifacts for.
    pub accepted_hosts: Vec<String>,
    /// RFC 3339 UTC instant the policy is evaluated at.
    pub now: String,
}

impl TrustPolicy {
    /// A policy that accepts exactly one host at one instant.
    #[must_use]
    pub fn for_host(host: impl Into<String>, now: impl Into<String>) -> Self {
        Self {
            accepted_hosts: vec![host.into()],
            now: now.into(),
        }
    }
}

/// One artifact this module proved against trusted metadata.
///
/// The type is the proof: it is only produced at the end of a successful
/// [verify_artifact], so downstream code can take one by value and know the
/// bytes, the digest, the host and the signing key were all checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedArtifact {
    /// Component the artifact belongs to.
    pub component: String,
    /// Version of the artifact.
    pub version: String,
    /// Host the artifact was verified for.
    pub host: String,
    /// Bundle-relative location that was verified.
    pub artifact: String,
    /// Digest of the bytes that were hashed.
    pub sha256: String,
    /// Size of the bytes that were hashed.
    pub size_bytes: u64,
    /// Key that confirmed the signature.
    pub key_id: String,
}

/// Confirms a signature over a message.
///
/// Implementations exist outside this crate: the release authority owns the key
/// material, and axiom-graphd must not carry a signing scheme or a private key.
/// The method returns a plain boolean because "the signature is wrong" and "the
/// key is unknown" are both simply a refusal to accept; the policy reason is
/// recorded by this module, not by the verifier.
pub trait SignatureVerifier {
    /// True only when `signature` is a valid `algorithm` signature of `message`
    /// under `public_key`.
    fn verify(&self, algorithm: &str, public_key: &str, message: &[u8], signature: &str) -> bool;
}

/// The fail-closed default: confirms nothing.
///
/// Installed whenever no release verifier is configured, so a missing verifier
/// refuses every artifact instead of trusting one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RejectingVerifier;

impl SignatureVerifier for RejectingVerifier {
    fn verify(
        &self,
        _algorithm: &str,
        _public_key: &str,
        _message: &[u8],
        _signature: &str,
    ) -> bool {
        false
    }
}

/// Supplies the bytes of one declared artifact.
///
/// The reader is the only source of payload bytes and it is bounded: a reader
/// that returns more than [MAX_ARTIFACT_BYTES] is refused, so a hostile or
/// corrupt bundle cannot make verification hash an unbounded stream.
pub trait ArtifactReader {
    /// Read one bundle-relative artifact location.
    ///
    /// # Errors
    /// [ErrorCode::NotFound] when the artifact is absent.
    fn read(&self, artifact: &str) -> Result<Vec<u8>, AxiomError>;
}

/// Reads artifacts from one local bundle directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalBundle {
    root: String,
}

impl LocalBundle {
    /// A reader over `root`/`artifact`.
    #[must_use]
    pub fn new(root: impl Into<String>) -> Self {
        Self { root: root.into() }
    }
}

impl ArtifactReader for LocalBundle {
    fn read(&self, artifact: &str) -> Result<Vec<u8>, AxiomError> {
        let path = Path::new(&self.root).join(artifact);
        let file = std::fs::File::open(&path).map_err(|error| {
            AxiomError::new(ErrorCode::NotFound, "the artifact could not be opened")
                .with_detail("rule", "artifact_missing")
                .with_detail("observed", artifact)
                .with_detail("actual", error.kind().to_string())
        })?;
        let mut bytes = Vec::new();
        file.take(MAX_ARTIFACT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                AxiomError::new(ErrorCode::ValidationError, "the artifact could not be read")
                    .with_detail("rule", "artifact_read")
                    .with_detail("observed", artifact)
                    .with_detail("actual", error.kind().to_string())
            })?;
        if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
            return Err(refuse("artifact_bytes", artifact)
                .with_detail("limit", MAX_ARTIFACT_BYTES.to_string()));
        }
        Ok(bytes)
    }
}

/// The one refusal shape of this module.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the release metadata violates the verification contract",
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

/// True when `value` is an RFC 3339 UTC instant of the shape this module sorts.
///
/// Only the Z form is accepted, because the freshness check compares two of
/// these strings lexically and a local offset would make that comparison lie.
#[must_use]
pub fn is_rfc3339_utc(value: &str) -> bool {
    value.len() >= 20
        && value.ends_with('Z')
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(10) == Some(&b'T')
        && value.as_bytes().get(13) == Some(&b':')
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '-' | ':' | 'T' | '.' | 'Z'))
}

/// The exact bytes a release signature covers for one artifact.
///
/// The message binds every trusted property of the artifact, not only its
/// digest, so a signature cannot be replayed for the same bytes under a
/// different component, version, host or location.
#[must_use]
pub fn signing_message(artifact: &ArtifactMetadata) -> Vec<u8> {
    format!(
        "axiom-artifact-v1\ncomponent={}\nversion={}\nhost={}\nkind={}\nartifact={}\nsha256={}\nsize_bytes={}\n",
        artifact.component,
        artifact.version,
        artifact.host,
        artifact.kind.as_str(),
        artifact.artifact,
        artifact.sha256,
        artifact.size_bytes
    )
    .into_bytes()
}

impl ArtifactMetadata {
    /// Validate one declared artifact against this build's vocabulary.
    ///
    /// # Errors
    /// [ErrorCode::ValidationError] for an unknown component, an empty or
    /// oversized version, an unknown host, an empty artifact location, a
    /// non-digest `sha256`, a zero size or an unsigned signature claim.
    pub fn validate(&self) -> Result<(), AxiomError> {
        if !COMPONENTS.contains(&self.component.as_str()) {
            return Err(refuse("component", &self.component));
        }
        if self.version.trim().is_empty() || self.version.len() > 64 {
            return Err(refuse("version", &self.version));
        }
        if !HOSTS.contains(&self.host.as_str()) {
            return Err(refuse("host", &self.host));
        }
        if self.artifact.trim().is_empty() {
            return Err(refuse("artifact", "empty"));
        }
        if !is_digest(&self.sha256) {
            return Err(refuse("sha256", &self.sha256));
        }
        if self.size_bytes == 0 {
            return Err(refuse("size_bytes", "0"));
        }
        if self.signature.algorithm.trim().is_empty() {
            return Err(refuse("signature.algorithm", "empty"));
        }
        if self.signature.key_id.trim().is_empty() {
            return Err(refuse("signature.key_id", "empty"));
        }
        Ok(())
    }
}

impl ReleaseMetadata {
    /// Validate one trusted metadata document.
    ///
    /// # Errors
    /// [ErrorCode::ValidationError] when the baseline is not this build's, when
    /// a timestamp is not the accepted RFC 3339 UTC form, when the expiry does
    /// not follow the creation time, when a root is malformed, when an artifact
    /// is malformed, or when more than [MAX_ARTIFACTS] artifacts are declared.
    pub fn validate(&self) -> Result<(), AxiomError> {
        if self.schema_version != RELEASE_METADATA_SCHEMA_VERSION {
            return Err(refuse("schema_version", &self.schema_version.to_string()));
        }
        if self.release_id.trim().is_empty() {
            return Err(refuse("release_id", "empty"));
        }
        if !CHANNELS.contains(&self.channel.as_str()) {
            return Err(refuse("channel", &self.channel));
        }
        if !is_rfc3339_utc(&self.generated_at) {
            return Err(refuse("generated_at", &self.generated_at));
        }
        if !is_rfc3339_utc(&self.expires_at) {
            return Err(refuse("expires_at", &self.expires_at));
        }
        if self.expires_at <= self.generated_at {
            return Err(refuse("expires_at", &self.expires_at));
        }
        if self.roots.is_empty() {
            return Err(refuse("roots", "empty"));
        }
        for root in &self.roots {
            if root.key_id.trim().is_empty() {
                return Err(refuse("roots.key_id", "empty"));
            }
            if !SIGNATURE_ALGORITHMS.contains(&root.algorithm.as_str()) {
                return Err(refuse("roots.algorithm", &root.algorithm));
            }
            if root.public_key.trim().is_empty() {
                return Err(refuse("roots.public_key", "empty"));
            }
        }
        if self.artifacts.is_empty() {
            return Err(refuse("artifacts", "empty"));
        }
        if self.artifacts.len() > MAX_ARTIFACTS {
            return Err(refuse("artifacts", &self.artifacts.len().to_string())
                .with_detail("limit", MAX_ARTIFACTS.to_string()));
        }
        for artifact in &self.artifacts {
            artifact.validate()?;
        }
        Ok(())
    }

    /// The root a `key_id` names, if this release carries it.
    #[must_use]
    pub fn root_for(&self, key_id: &str) -> Option<&TrustedRoot> {
        self.roots.iter().find(|root| root.key_id == key_id)
    }
}

/// Read and parse the trusted metadata of one release directory.
///
/// This is the only filesystem call in this module, and it is read-only.
///
/// # Errors
/// [ErrorCode::NotFound] when the document cannot be opened;
/// [ErrorCode::ValidationError] when it exceeds [MAX_METADATA_BYTES], is not
/// UTF-8, is not JSON, carries unknown keys or fails
/// [ReleaseMetadata::validate].
pub fn read_release_metadata(directory: &Path) -> Result<(ReleaseMetadata, String), AxiomError> {
    let path = directory.join(TRUSTED_METADATA_FILE);
    let file = std::fs::File::open(&path).map_err(|error| {
        AxiomError::new(
            ErrorCode::NotFound,
            "the release metadata could not be opened",
        )
        .with_detail("rule", "release_metadata")
        .with_detail("observed", TRUSTED_METADATA_FILE)
        .with_detail("actual", error.kind().to_string())
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            AxiomError::new(
                ErrorCode::ValidationError,
                "the release metadata could not be read",
            )
            .with_detail("rule", "release_metadata")
            .with_detail("observed", TRUSTED_METADATA_FILE)
            .with_detail("actual", error.kind().to_string())
        })?;
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(refuse("metadata_bytes", TRUSTED_METADATA_FILE)
            .with_detail("limit", MAX_METADATA_BYTES.to_string()));
    }
    let text = String::from_utf8(bytes).map_err(|_| {
        AxiomError::new(
            ErrorCode::ValidationError,
            "the release metadata is not valid UTF-8",
        )
        .with_detail("rule", "release_metadata_utf8")
        .with_detail("observed", "invalid utf-8")
    })?;
    let metadata: ReleaseMetadata = serde_json::from_str(&text).map_err(|error| {
        AxiomError::new(
            ErrorCode::ValidationError,
            "the release metadata is not valid release metadata",
        )
        .with_detail("rule", "release_metadata_json")
        .with_detail("observed", error.to_string())
    })?;
    metadata.validate()?;
    Ok((metadata, graph_export::sha256_hex(text.as_bytes())))
}

/// Verify one artifact's bytes against trusted metadata.
///
/// The checks run in the order a reviewer would want to read them, and every
/// one is a refusal: an unsigned artifact, an untrusted key, a non-allowlisted
/// algorithm, an expired release, a foreign host and any disagreement between
/// metadata and bytes all fail closed.
///
/// # Errors
/// [ErrorCode::ValidationError] when the metadata, the artifact or the policy is
/// malformed, when the release is expired, or when the bytes disagree with the
/// trusted digest or size; [ErrorCode::Forbidden] when the host is not accepted,
/// when the signature is absent, when the key is not a trust root, or when the
/// verifier rejects the signature.
pub fn verify_artifact(
    metadata: &ReleaseMetadata,
    artifact: &ArtifactMetadata,
    payload: &[u8],
    policy: &TrustPolicy,
    verifier: &impl SignatureVerifier,
) -> Result<VerifiedArtifact, AxiomError> {
    metadata.validate()?;
    artifact.validate()?;
    if metadata.root_for(&artifact.signature.key_id).is_none() {
        // Checked before the expensive work, so an untrusted release cannot make
        // this module hash a large payload before refusing it.
        return Err(forbid(
            "untrusted_key",
            &artifact.signature.key_id,
            "the artifact is signed by a key this release does not publish",
        ));
    }
    if !SIGNATURE_ALGORITHMS.contains(&artifact.signature.algorithm.as_str()) {
        return Err(forbid(
            "signature_algorithm",
            &artifact.signature.algorithm,
            "the artifact signature uses an algorithm this build does not accept",
        ));
    }
    if artifact.signature.value.trim().is_empty() {
        return Err(forbid(
            "signature_absent",
            &artifact.artifact,
            "an unsigned artifact is never accepted",
        ));
    }
    if !policy
        .accepted_hosts
        .iter()
        .any(|host| host == &artifact.host)
    {
        return Err(forbid(
            "host",
            &artifact.host,
            "the artifact was not built for a host this install accepts",
        ));
    }
    if !is_rfc3339_utc(&policy.now) {
        return Err(refuse("policy.now", &policy.now));
    }
    if policy.now >= metadata.expires_at {
        return Err(
            refuse("metadata_expired", &metadata.expires_at).with_detail("actual", &policy.now)
        );
    }
    if payload.len() as u64 != artifact.size_bytes {
        return Err(refuse("size_bytes", &payload.len().to_string())
            .with_detail("expected", artifact.size_bytes.to_string()));
    }
    let actual = graph_export::sha256_hex(payload);
    if actual != artifact.sha256 {
        return Err(refuse("sha256", &actual).with_detail("expected", &artifact.sha256));
    }
    let root = metadata
        .root_for(&artifact.signature.key_id)
        .ok_or_else(|| {
            forbid(
                "untrusted_key",
                &artifact.signature.key_id,
                "the artifact is signed by a key this release does not publish",
            )
        })?;
    if root.algorithm != artifact.signature.algorithm {
        return Err(forbid(
            "signature_algorithm",
            &artifact.signature.algorithm,
            "the artifact and its trust root disagree about the algorithm",
        ));
    }
    if !verifier.verify(
        &artifact.signature.algorithm,
        &root.public_key,
        &signing_message(artifact),
        &artifact.signature.value,
    ) {
        return Err(forbid(
            "signature",
            &artifact.artifact,
            "the artifact signature was not confirmed by the trust root",
        ));
    }
    Ok(VerifiedArtifact {
        component: artifact.component.clone(),
        version: artifact.version.clone(),
        host: artifact.host.clone(),
        artifact: artifact.artifact.clone(),
        sha256: actual,
        size_bytes: artifact.size_bytes,
        key_id: artifact.signature.key_id.clone(),
    })
}

/// Verify every artifact one release declares, reading bytes through `reader`.
///
/// This is fail-closed over the whole set: one artifact that cannot be read,
/// disagrees with its digest, or is signed by an untrusted key refuses the
/// bundle, and the caller receives no partial list it could mistake for a
/// verified release.
///
/// # Errors
/// Any refusal of [verify_artifact], plus [ErrorCode::NotFound] when the reader
/// cannot supply a declared artifact.
pub fn verify_bundle(
    metadata: &ReleaseMetadata,
    policy: &TrustPolicy,
    reader: &impl ArtifactReader,
    verifier: &impl SignatureVerifier,
) -> Result<Vec<VerifiedArtifact>, AxiomError> {
    metadata.validate()?;
    let mut verified = Vec::with_capacity(metadata.artifacts.len());
    for artifact in &metadata.artifacts {
        let payload = reader.read(&artifact.artifact)?;
        verified.push(verify_artifact(
            metadata, artifact, &payload, policy, verifier,
        )?);
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// A lowercase 64-hex digest built from one repeated byte.
    fn hex(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

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

    /// One artifact whose trusted digest and size describe `payload`.
    fn artifact_for(payload: &[u8]) -> ArtifactMetadata {
        ArtifactMetadata {
            component: "axiom-graphd".to_string(),
            version: "0.1.0".to_string(),
            host: "linux-x64".to_string(),
            kind: ArtifactKind::Binary,
            artifact: "bin/axiom-graphd".to_string(),
            sha256: graph_export::sha256_hex(payload),
            size_bytes: payload.len() as u64,
            signature: ArtifactSignature {
                algorithm: "ed25519".to_string(),
                key_id: "release-key-1".to_string(),
                value: "c2lnbmF0dXJl".to_string(),
            },
        }
    }

    /// One metadata document describing exactly `artifacts`.
    fn metadata_for(artifacts: Vec<ArtifactMetadata>) -> ReleaseMetadata {
        ReleaseMetadata {
            schema_version: RELEASE_METADATA_SCHEMA_VERSION,
            release_id: "axiom-core-0.1.0".to_string(),
            channel: "stable".to_string(),
            generated_at: "2026-09-19T00:00:00Z".to_string(),
            expires_at: "2026-10-19T00:00:00Z".to_string(),
            roots: vec![TrustedRoot {
                key_id: "release-key-1".to_string(),
                algorithm: "ed25519".to_string(),
                public_key: "00112233".to_string(),
            }],
            artifacts,
        }
    }

    /// A reader over an in-memory bundle.
    struct MemBundle(BTreeMap<String, Vec<u8>>);

    impl ArtifactReader for MemBundle {
        fn read(&self, artifact: &str) -> Result<Vec<u8>, AxiomError> {
            self.0.get(artifact).cloned().ok_or_else(|| {
                AxiomError::new(ErrorCode::NotFound, "the artifact could not be opened")
                    .with_detail("rule", "artifact_missing")
                    .with_detail("observed", artifact)
            })
        }
    }

    #[test]
    fn a_matching_artifact_is_verified_against_metadata_and_key() {
        let payload = b"an axiom binary".to_vec();
        let artifact = artifact_for(&payload);
        let metadata = metadata_for(vec![artifact.clone()]);
        let policy = TrustPolicy::for_host("linux-x64", "2026-09-20T00:00:00Z");
        let verifier = AcceptingVerifier {
            expected: artifact.signature.value.clone(),
        };
        let verified = verify_artifact(&metadata, &artifact, &payload, &policy, &verifier)
            .expect("matching bytes and a confirmed signature verify");
        assert_eq!(verified.sha256, artifact.sha256);
        assert_eq!(verified.size_bytes, payload.len() as u64);
        assert_eq!(verified.key_id, "release-key-1");
    }

    #[test]
    fn bytes_that_disagree_with_the_trusted_digest_are_refused() {
        let payload = b"an axiom binary".to_vec();
        let artifact = artifact_for(&payload);
        let metadata = metadata_for(vec![artifact.clone()]);
        let policy = TrustPolicy::for_host("linux-x64", "2026-09-20T00:00:00Z");
        let verifier = AcceptingVerifier {
            expected: artifact.signature.value.clone(),
        };
        let mut tampered = payload.clone();
        tampered[0] ^= 0xff;
        let error = verify_artifact(&metadata, &artifact, &tampered, &policy, &verifier)
            .expect_err("a single changed byte is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("sha256")
        );
    }

    #[test]
    fn an_unsigned_artifact_is_refused_even_when_the_bytes_match() {
        let payload = b"an axiom binary".to_vec();
        let mut artifact = artifact_for(&payload);
        artifact.signature.value = String::new();
        let metadata = metadata_for(vec![artifact.clone()]);
        let policy = TrustPolicy::for_host("linux-x64", "2026-09-20T00:00:00Z");
        let error = verify_artifact(
            &metadata,
            &artifact,
            &payload,
            &policy,
            &AcceptingVerifier {
                expected: String::new(),
            },
        )
        .expect_err("an unsigned artifact is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("signature_absent")
        );
    }

    #[test]
    fn a_key_that_is_not_a_trust_root_is_refused() {
        let payload = b"an axiom binary".to_vec();
        let mut artifact = artifact_for(&payload);
        artifact.signature.key_id = "release-key-2".to_string();
        let metadata = metadata_for(vec![artifact.clone()]);
        let policy = TrustPolicy::for_host("linux-x64", "2026-09-20T00:00:00Z");
        let error = verify_artifact(
            &metadata,
            &artifact,
            &payload,
            &policy,
            &AcceptingVerifier {
                expected: artifact.signature.value.clone(),
            },
        )
        .expect_err("an unknown signing key is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("untrusted_key")
        );
    }

    #[test]
    fn an_algorithm_outside_the_allowlist_is_refused() {
        let payload = b"an axiom binary".to_vec();
        let mut artifact = artifact_for(&payload);
        // The trust root stays on the allowlisted algorithm, so this reaches the
        // artifact-level allowlist check rather than metadata validation.
        artifact.signature.algorithm = "hmac-sha256".to_string();
        let metadata = metadata_for(vec![artifact.clone()]);
        let policy = TrustPolicy::for_host("linux-x64", "2026-09-20T00:00:00Z");
        let error = verify_artifact(
            &metadata,
            &artifact,
            &payload,
            &policy,
            &AcceptingVerifier {
                expected: artifact.signature.value.clone(),
            },
        )
        .expect_err("a non-allowlisted artifact algorithm is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("signature_algorithm")
        );

        // The same value declared on a trust root is malformed metadata, refused
        // before any signature work with the validation code.
        let mut untrusted_root = metadata_for(vec![artifact_for(&payload)]);
        untrusted_root.roots[0].algorithm = "hmac-sha256".to_string();
        let root_artifact = untrusted_root.artifacts[0].clone();
        let error = verify_artifact(
            &untrusted_root,
            &root_artifact,
            &payload,
            &policy,
            &AcceptingVerifier {
                expected: root_artifact.signature.value.clone(),
            },
        )
        .expect_err("a non-allowlisted root algorithm is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("roots.algorithm")
        );
    }

    #[test]
    fn an_artifact_for_another_host_is_refused() {
        let payload = b"an axiom binary".to_vec();
        let artifact = artifact_for(&payload);
        let metadata = metadata_for(vec![artifact.clone()]);
        let policy = TrustPolicy::for_host("windows-x64", "2026-09-20T00:00:00Z");
        let error = verify_artifact(
            &metadata,
            &artifact,
            &payload,
            &policy,
            &AcceptingVerifier {
                expected: artifact.signature.value.clone(),
            },
        )
        .expect_err("a foreign host is refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("host")
        );
    }

    #[test]
    fn an_expired_release_is_refused_at_the_boundary() {
        let payload = b"an axiom binary".to_vec();
        let artifact = artifact_for(&payload);
        let metadata = metadata_for(vec![artifact.clone()]);
        let verifier = AcceptingVerifier {
            expected: artifact.signature.value.clone(),
        };
        // One second before expiry is accepted; the expiry instant is not.
        let before = TrustPolicy::for_host("linux-x64", "2026-10-18T23:59:59Z");
        assert!(verify_artifact(&metadata, &artifact, &payload, &before, &verifier).is_ok());
        let at = TrustPolicy::for_host("linux-x64", "2026-10-19T00:00:00Z");
        let error = verify_artifact(&metadata, &artifact, &payload, &at, &verifier)
            .expect_err("the expiry instant is refused");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("metadata_expired")
        );
    }

    #[test]
    fn the_default_verifier_rejects_everything() {
        let payload = b"an axiom binary".to_vec();
        let artifact = artifact_for(&payload);
        let metadata = metadata_for(vec![artifact.clone()]);
        let policy = TrustPolicy::for_host("linux-x64", "2026-09-20T00:00:00Z");
        let error = verify_artifact(&metadata, &artifact, &payload, &policy, &RejectingVerifier)
            .expect_err("the fail-closed default refuses");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("signature")
        );
    }

    #[test]
    fn one_bad_artifact_refuses_the_whole_bundle() {
        let good = b"an axiom binary".to_vec();
        let bad = b"an axiom wheel".to_vec();
        let mut bundle = BTreeMap::new();
        bundle.insert("bin/axiom-graphd".to_string(), good.clone());
        bundle.insert("python/axiom_mcp.whl".to_string(), bad.clone());
        let mut wheel = artifact_for(&bad);
        wheel.component = "axiom-mcp".to_string();
        wheel.kind = ArtifactKind::Python;
        wheel.artifact = "python/axiom_mcp.whl".to_string();
        let binary = artifact_for(&good);
        let verifier = AcceptingVerifier {
            expected: binary.signature.value.clone(),
        };
        let metadata = metadata_for(vec![binary, wheel]);
        let policy = TrustPolicy::for_host("linux-x64", "2026-09-20T00:00:00Z");
        // Untampered, the bundle verifies as a set.
        assert_eq!(
            verify_bundle(&metadata, &policy, &MemBundle(bundle.clone()), &verifier)
                .expect("the fixture bundle verifies")
                .len(),
            2
        );
        // One tampered payload refuses the set; the good artifact is not
        // returned as a usable partial result.
        let mut tampered = bundle;
        tampered.insert("python/axiom_mcp.whl".to_string(), b"evil".to_vec());
        let error = verify_bundle(&metadata, &policy, &MemBundle(tampered), &verifier)
            .expect_err("a tampered member refuses the bundle");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("size_bytes")
        );
    }

    #[test]
    fn a_missing_member_refuses_the_bundle() {
        let good = b"an axiom binary".to_vec();
        let binary = artifact_for(&good);
        let mut wheel = artifact_for(b"a wheel payload");
        wheel.component = "axiom-mcp".to_string();
        wheel.artifact = "python/axiom_mcp.whl".to_string();
        let metadata = metadata_for(vec![binary.clone(), wheel]);
        let policy = TrustPolicy::for_host("linux-x64", "2026-09-20T00:00:00Z");
        let mut bundle = BTreeMap::new();
        bundle.insert("bin/axiom-graphd".to_string(), good);
        let error = verify_bundle(
            &metadata,
            &policy,
            &MemBundle(bundle),
            &AcceptingVerifier {
                expected: binary.signature.value.clone(),
            },
        )
        .expect_err("an absent member refuses the bundle");
        assert_eq!(error.code(), ErrorCode::NotFound);
    }

    #[test]
    fn a_malformed_metadata_document_fails_closed() {
        let temporary = tempfile::TempDir::new().expect("a temporary release directory");
        let path = temporary.path().join(TRUSTED_METADATA_FILE);

        std::fs::write(&path, b"not json at all").expect("the fixture is written");
        let error = read_release_metadata(temporary.path()).expect_err("invalid JSON is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);

        let mut metadata = metadata_for(vec![artifact_for(b"a payload")]);
        metadata.schema_version = 9;
        std::fs::write(
            &path,
            serde_json::to_vec(&metadata).expect("the fixture serialises"),
        )
        .expect("the fixture is written");
        let error =
            read_release_metadata(temporary.path()).expect_err("a foreign baseline is refused");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("schema_version")
        );

        let mut metadata = metadata_for(vec![artifact_for(b"a payload")]);
        metadata.expires_at = "2026-09-19T00:00:00Z".to_string();
        std::fs::write(
            &path,
            serde_json::to_vec(&metadata).expect("the fixture serialises"),
        )
        .expect("the fixture is written");
        let error = read_release_metadata(temporary.path())
            .expect_err("an expiry before creation is refused");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("expires_at")
        );
    }

    #[test]
    fn a_missing_metadata_document_is_not_found_and_names_the_file() {
        let error = read_release_metadata(Path::new("/no-such-axiom-release-directory"))
            .expect_err("a missing metadata document is refused");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some(TRUSTED_METADATA_FILE)
        );
    }

    #[test]
    fn the_vocabulary_and_timestamp_form_are_the_frozen_ones() {
        assert_eq!(hex(0x11).len(), 64);
        assert!(is_digest(&hex(0x11)));
        assert!(is_rfc3339_utc("2026-09-19T00:00:00Z"));
        assert!(!is_rfc3339_utc("2026-09-19 00:00:00"));
        assert!(!is_rfc3339_utc("2026-09-19T07:00:00+07:00"));
        assert_eq!(COMPONENTS.len(), 3);
        assert_eq!(HOSTS.len(), 4);
    }

    #[test]
    fn the_signing_message_binds_every_trusted_property() {
        let artifact = artifact_for(b"payload");
        let message = String::from_utf8(signing_message(&artifact)).expect("utf-8");
        assert!(message.contains("component=axiom-graphd"));
        assert!(message.contains(&format!("sha256={}", artifact.sha256)));
        assert!(message.starts_with("axiom-artifact-v1\n"));
        assert!(message.ends_with('\n'));
    }
}
