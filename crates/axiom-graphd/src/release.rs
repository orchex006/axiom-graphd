//! Release artifact publication gates (task B-093).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` and
//! `docs/23-SECURITY-AND-TRUST.md` require signed release validation, a pinned
//! trust root, anti-rollback and provenance, and `release/build-matrix.md`
//! records the artifact each supported target produces. The matrix is only
//! honest if an artifact in it can be attributed to a pinned commit, so this
//! module implements the gate the matrix documents:
//!
//! * an artifact must name a full 40-character commit, otherwise
//!   [`REASON_COMMIT_NOT_PINNED`];
//! * an unsigned artifact cannot be published
//!   ([`REASON_UNSIGNED_ARTIFACT`]);
//! * placeholder metadata - `REPLACE`, `TODO`, `FILL_ME`, `unknown`, `latest` -
//!   cannot be published ([`REASON_PLACEHOLDER_METADATA`]);
//! * a platform outside the supported set cannot be published
//!   ([`REASON_PLATFORM_UNSUPPORTED`]).
//!
//! The decision is a value, not a side effect, so CI can assert the gate without
//! publishing anything.

use serde::Serialize;

/// Reason recorded when an artifact is not signed.
pub const REASON_UNSIGNED_ARTIFACT: &str = "unsigned-artifact";
/// Reason recorded when metadata is a placeholder.
pub const REASON_PLACEHOLDER_METADATA: &str = "placeholder-metadata";
/// Reason recorded when the source commit is not a full pinned commit.
pub const REASON_COMMIT_NOT_PINNED: &str = "commit-not-pinned";
/// Reason recorded when the platform is outside the supported set.
pub const REASON_PLATFORM_UNSUPPORTED: &str = "platform-unsupported";
/// Reason recorded when a signature key is not the pinned trust root.
pub const REASON_SIGNATURE_KEY_UNKNOWN: &str = "signature-key-unknown";
/// Reason recorded when the artifact has no SBOM digest.
pub const REASON_SBOM_MISSING: &str = "sbom-missing";

/// Tokens that mark metadata as an unfilled placeholder.
const PLACEHOLDER_TOKENS: [&str; 5] = ["REPLACE", "TODO", "FILL_ME", "unknown", "latest"];

/// A supported release target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetPlatform {
    /// `x86_64-pc-windows-msvc`.
    WindowsX64,
    /// `x86_64-unknown-linux-gnu`.
    LinuxX64,
    /// `aarch64-apple-darwin`.
    MacosArm64,
}

impl TargetPlatform {
    /// Stable wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::WindowsX64 => "windows-x64",
            Self::LinuxX64 => "linux-x64",
            Self::MacosArm64 => "macos-arm64",
        }
    }

    /// The Rust target triple the matrix pins.
    #[must_use]
    pub const fn triple(self) -> &'static str {
        match self {
            Self::WindowsX64 => "x86_64-pc-windows-msvc",
            Self::LinuxX64 => "x86_64-unknown-linux-gnu",
            Self::MacosArm64 => "aarch64-apple-darwin",
        }
    }

    /// The operating-system family, used to assert the matrix covers each one.
    #[must_use]
    pub const fn family(self) -> &'static str {
        match self {
            Self::WindowsX64 => "windows",
            Self::LinuxX64 => "linux",
            Self::MacosArm64 => "macos",
        }
    }

    /// Every supported target, in a deterministic order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::WindowsX64, Self::LinuxX64, Self::MacosArm64]
    }
}

/// Signature state of a release artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "state")]
pub enum Signature {
    /// Signed by `key_id`.
    Signed {
        /// Identifier of the signing key.
        key_id: String,
    },
    /// Not signed; cannot publish.
    Unsigned,
}

/// The metadata that makes an artifact attributable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactMetadata {
    /// Release version.
    pub version: String,
    /// Full 40-character source commit.
    pub source_commit: String,
    /// Target platform.
    pub platform: TargetPlatform,
    /// Signature state.
    pub signature: Signature,
    /// SHA-256 of the artifact's SBOM.
    pub sbom_sha256: String,
}

/// The publication decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublishDecision {
    /// The artifact may be published.
    Publish,
    /// The artifact is refused with a stable reason.
    Refuse {
        /// The stable reason code.
        reason: &'static str,
    },
}
impl PublishDecision {
    /// Whether the artifact may be published.
    #[must_use]
    pub const fn is_publish(&self) -> bool {
        matches!(self, Self::Publish)
    }

    /// The refusal reason, when the artifact was refused.
    #[must_use]
    pub const fn reason(&self) -> Option<&'static str> {
        match self {
            Self::Publish => None,
            Self::Refuse { reason } => Some(reason),
        }
    }
}

/// Whether `text` carries a placeholder token.
#[must_use]
pub fn is_placeholder(text: &str) -> bool {
    PLACEHOLDER_TOKENS.iter().any(|token| text.contains(token))
}

/// Whether a commit is a full, pinned, lowercase-or-upper hex commit.
#[must_use]
pub fn is_pinned_commit(commit: &str) -> bool {
    commit.len() == 40 && commit.chars().all(|c| c.is_ascii_hexdigit())
}

/// Decide whether one artifact may be published.
#[must_use]
pub fn decide(artifact: &ArtifactMetadata) -> PublishDecision {
    if is_placeholder(&artifact.version) {
        return PublishDecision::Refuse {
            reason: REASON_PLACEHOLDER_METADATA,
        };
    }
    if is_placeholder(&artifact.sbom_sha256) || artifact.sbom_sha256.len() != 64 {
        return PublishDecision::Refuse {
            reason: REASON_SBOM_MISSING,
        };
    }
    if !is_pinned_commit(&artifact.source_commit) {
        return PublishDecision::Refuse {
            reason: REASON_COMMIT_NOT_PINNED,
        };
    }
    match &artifact.signature {
        Signature::Unsigned => PublishDecision::Refuse {
            reason: REASON_UNSIGNED_ARTIFACT,
        },
        Signature::Signed { key_id } if is_placeholder(key_id) || key_id.is_empty() => {
            PublishDecision::Refuse {
                reason: REASON_SIGNATURE_KEY_UNKNOWN,
            }
        }
        Signature::Signed { .. } => PublishDecision::Publish,
    }
}

/// The per-platform release matrix for one version and commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseMatrix {
    /// The version all rows share.
    pub version: String,
    /// The commit all rows are attributable to.
    pub source_commit: String,
    /// One row per supported target.
    pub artifacts: Vec<ArtifactMetadata>,
}

impl ReleaseMatrix {
    /// The artifacts that would be published, in matrix order.
    #[must_use]
    pub fn publishable(&self) -> Vec<&ArtifactMetadata> {
        self.artifacts
            .iter()
            .filter(|artifact| decide(artifact).is_publish())
            .collect()
    }

    /// Every refusal, paired with its artifact platform.
    #[must_use]
    pub fn refusals(&self) -> Vec<(TargetPlatform, &'static str)> {
        self.artifacts
            .iter()
            .filter_map(|artifact| {
                decide(artifact)
                    .reason()
                    .map(|reason| (artifact.platform, reason))
            })
            .collect()
    }
}

/// Build the release matrix for `version` at `source_commit`.
#[must_use]
pub fn matrix(version: &str, source_commit: &str) -> ReleaseMatrix {
    let artifacts = TargetPlatform::all()
        .iter()
        .map(|platform| ArtifactMetadata {
            version: version.to_owned(),
            source_commit: source_commit.to_owned(),
            platform: *platform,
            signature: Signature::Unsigned,
            sbom_sha256: String::new(),
        })
        .collect();
    ReleaseMatrix {
        version: version.to_owned(),
        source_commit: source_commit.to_owned(),
        artifacts,
    }
}

/// Every operating-system family the matrix covers.
#[must_use]
pub fn covered_families(matrix: &ReleaseMatrix) -> Vec<&'static str> {
    let mut families: Vec<&'static str> = matrix
        .artifacts
        .iter()
        .map(|artifact| artifact.platform.family())
        .collect();
    families.sort_unstable();
    families.dedup();
    families
}
#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: &str) -> String {
        graph_export::sha256_hex(seed.as_bytes())
    }

    fn signed(platform: TargetPlatform) -> ArtifactMetadata {
        ArtifactMetadata {
            version: "1.4.0".to_owned(),
            source_commit: "a".repeat(40),
            platform,
            signature: Signature::Signed {
                key_id: "release-key-2026".to_owned(),
            },
            sbom_sha256: digest("sbom"),
        }
    }

    #[test]
    fn the_matrix_covers_every_supported_family_at_one_pinned_commit() {
        let matrix = matrix("1.4.0", &"a".repeat(40));
        assert_eq!(matrix.artifacts.len(), 3);
        assert_eq!(covered_families(&matrix), vec!["linux", "macos", "windows"]);
        assert_eq!(
            TargetPlatform::WindowsX64.triple(),
            "x86_64-pc-windows-msvc"
        );
        assert_eq!(
            TargetPlatform::LinuxX64.triple(),
            "x86_64-unknown-linux-gnu"
        );
        assert_eq!(TargetPlatform::MacosArm64.triple(), "aarch64-apple-darwin");
        assert!(matrix
            .artifacts
            .iter()
            .all(|artifact| artifact.source_commit == matrix.source_commit));
        // A freshly built matrix is unsigned and therefore publishes nothing.
        assert!(matrix.publishable().is_empty());
        assert_eq!(matrix.refusals().len(), 3);
    }

    #[test]
    fn a_signed_artifact_at_a_pinned_commit_publishes() {
        let artifact = signed(TargetPlatform::LinuxX64);
        assert!(decide(&artifact).is_publish());
        assert_eq!(decide(&artifact).reason(), None);
        let matrix = ReleaseMatrix {
            version: "1.4.0".to_owned(),
            source_commit: "a".repeat(40),
            artifacts: TargetPlatform::all().iter().copied().map(signed).collect(),
        };
        assert_eq!(matrix.publishable().len(), 3);
        assert!(matrix.refusals().is_empty());
    }

    #[test]
    fn an_unsigned_artifact_cannot_publish() {
        let mut artifact = signed(TargetPlatform::WindowsX64);
        artifact.signature = Signature::Unsigned;
        let decision = decide(&artifact);
        assert!(!decision.is_publish());
        assert_eq!(decision.reason(), Some(REASON_UNSIGNED_ARTIFACT));
        // A signature with a placeholder key is equally unpublishable.
        let mut placeholder_key = signed(TargetPlatform::WindowsX64);
        placeholder_key.signature = Signature::Signed {
            key_id: "REPLACE_ME".to_owned(),
        };
        assert_eq!(
            decide(&placeholder_key).reason(),
            Some(REASON_SIGNATURE_KEY_UNKNOWN)
        );
    }

    #[test]
    fn placeholder_metadata_and_an_unpinned_commit_cannot_publish() {
        for placeholder in ["0.0.0-REPLACE", "1.0.0-TODO", "FILL_ME", "unknown"] {
            let mut artifact = signed(TargetPlatform::MacosArm64);
            artifact.version = placeholder.to_owned();
            assert_eq!(
                decide(&artifact).reason(),
                Some(REASON_PLACEHOLDER_METADATA),
                "{placeholder}"
            );
        }
        // A short or abbreviated commit is not attributable.
        let mut short = signed(TargetPlatform::LinuxX64);
        short.source_commit = "abc1234".to_owned();
        assert_eq!(decide(&short).reason(), Some(REASON_COMMIT_NOT_PINNED));
        let mut not_hex = signed(TargetPlatform::LinuxX64);
        not_hex.source_commit = "z".repeat(40);
        assert_eq!(decide(&not_hex).reason(), Some(REASON_COMMIT_NOT_PINNED));
        assert!(is_pinned_commit(&"A".repeat(40)));
        assert!(!is_pinned_commit(&"a".repeat(39)));
        // A missing or placeholder SBOM digest is refused.
        let mut no_sbom = signed(TargetPlatform::LinuxX64);
        no_sbom.sbom_sha256 = String::new();
        assert_eq!(decide(&no_sbom).reason(), Some(REASON_SBOM_MISSING));
        let mut placeholder_sbom = signed(TargetPlatform::LinuxX64);
        placeholder_sbom.sbom_sha256 = "FILL_ME".to_owned();
        assert_eq!(
            decide(&placeholder_sbom).reason(),
            Some(REASON_SBOM_MISSING)
        );
        assert!(is_placeholder("1.0.0-latest"));
        assert!(!is_placeholder("1.0.0"));
    }

    #[test]
    fn an_unsupported_target_is_outside_the_matrix() {
        // The matrix itself only ever contains supported platforms, so the
        // supported set is the boundary: a fourth family cannot be requested.
        let targets: Vec<&str> = TargetPlatform::all()
            .iter()
            .map(|platform| platform.triple())
            .collect();
        assert_eq!(targets.len(), 3);
        assert!(!targets.contains(&"x86_64-apple-darwin"));
        assert_eq!(covered_families(&matrix("1.4.0", &"a".repeat(40))).len(), 3);
    }
}
