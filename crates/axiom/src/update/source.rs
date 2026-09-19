//! Trusted update-source configuration (task E-035).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 3 makes the allowlist the
//! first half of the update trust chain: production updates come from published
//! GitHub releases and their assets in repositories the *user* configured, and
//! the draft leaves `REPLACE_ME` where an owner, a URL or a root public key still
//! has to be set. Section 8 adds the development opt-in: a trusted-repository
//! allowlist, never an implicit `git pull main`.
//!
//! This module is one allowlist entry. It decides exactly one thing:
//!
//! * an [`UpdateSource`] is built only from an explicit owner, repository and
//!   channel; an unset or placeholder value is refused, never filled in from a
//!   binary name or a component name;
//! * every URL this module can produce is derived from the configured
//!   `owner/repo` and is `https://`; there is no branch, commit or arbitrary
//!   file download here;
//! * the channel is one of the two frozen channel names.
//!
//! "Do not invent a default from the component name" is structural, not a
//! convention: [`UpdateSource::from_config`] is the only constructor that takes
//! a component name at all, and it uses that name only in the refusal it
//! produces. A test asserts the refusal never turns the component into an owner.

use graph_core::error::{AxiomError, ErrorCode};
use serde::{Deserialize, Serialize};

/// Release channels an update source may name, in spec order.
pub const CHANNELS: [&str; 2] = ["stable", "prerelease"];

/// Markers the specification draft leaves where a real value must be set.
///
/// Section 3 of the contract requires the installer to reject a value that was
/// never filled in, so a marker is a refusal and never a usable default.
pub const PLACEHOLDER_MARKERS: [&str; 2] = ["REPLACE_ME", "FILL_ME"];

/// Longest accepted owner, repository or tag field.
pub const MAX_FIELD_LEN: usize = 100;

/// The GitHub host every release URL is built on.
pub const RELEASE_HOST: &str = "github.com";

/// One allowlisted release source: an owner, a repository and a channel.
///
/// The fields are private so the only ways to obtain a value are [`Self::new`]
/// and [`Self::from_config`], and both validate. A source that was never
/// configured cannot be constructed at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSource {
    owner: String,
    repo: String,
    channel: String,
}

/// The raw user configuration of an update source.
///
/// Every field is optional because the interesting case is a configuration that
/// was never completed; [`UpdateSource::from_config`] refuses that instead of
/// guessing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    /// Configured repository owner.
    pub owner: Option<String>,
    /// Configured repository name.
    pub repo: Option<String>,
    /// Configured release channel.
    pub channel: Option<String>,
}

impl SourceConfig {
    /// A complete configuration, for callers that already know the values.
    #[must_use]
    pub fn configured(owner: &str, repo: &str, channel: &str) -> Self {
        Self {
            owner: Some(owner.to_string()),
            repo: Some(repo.to_string()),
            channel: Some(channel.to_string()),
        }
    }
}

/// Where an update answer came from, for the `source_origin` field a version
/// report must separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceOrigin {
    /// A source is configured and was used.
    Configured,
    /// No trusted source is configured; nothing was contacted.
    Unconfigured,
}

impl SourceOrigin {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Unconfigured => "unconfigured",
        }
    }

    /// Every accepted value, for contract tests.
    #[must_use]
    pub const fn all() -> &'static [SourceOrigin] {
        &[Self::Configured, Self::Unconfigured]
    }
}

impl UpdateSource {
    /// Build a source from explicit values, refusing anything unusable.
    ///
    /// # Errors
    ///
    /// Fails closed with a named `rule` detail when a field is empty, longer
    /// than [`MAX_FIELD_LEN`], still a [`PLACEHOLDER_MARKERS`] placeholder,
    /// carries a character outside the GitHub owner/repo alphabet, or begins or
    /// ends with `-`/`.` where it would be ambiguous with a path or an option.
    pub fn new(owner: &str, repo: &str, channel: &str) -> Result<Self, AxiomError> {
        Ok(Self {
            owner: name("owner", owner)?,
            repo: name("repo", repo)?,
            channel: channel_name(channel)?,
        })
    }

    /// Build a source from a user configuration, or refuse.
    ///
    /// `component` is recorded in the refusal only. It is never used to derive
    /// an owner, a repository or a channel: a build that has not been configured
    /// reports itself unconfigured instead of downloading from a name an agent
    /// guessed.
    ///
    /// # Errors
    ///
    /// Fails with rule `unconfigured` when any of owner, repo or channel is
    /// absent, and with every reason [`Self::new`] can produce otherwise.
    pub fn from_config(config: &SourceConfig, component: &str) -> Result<Self, AxiomError> {
        let (Some(owner), Some(repo)) = (config.owner.as_deref(), config.repo.as_deref()) else {
            return Err(unconfigured(component, "owner/repo"));
        };
        let Some(channel) = config.channel.as_deref() else {
            return Err(unconfigured(component, "channel"));
        };
        Self::new(owner, repo, channel)
    }

    /// Configured repository owner.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Configured repository name.
    #[must_use]
    pub fn repo(&self) -> &str {
        &self.repo
    }

    /// Configured release channel, from [`CHANNELS`].
    #[must_use]
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// `owner/repo`, the repository identity of this source.
    #[must_use]
    pub fn slug(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }

    /// The `https://github.com/<owner>/<repo>/releases` base URL.
    #[must_use]
    pub fn release_base_url(&self) -> String {
        format!(
            "https://{RELEASE_HOST}/{}/{}/releases",
            self.owner, self.repo
        )
    }

    /// The URL of one release asset under an explicit tag.
    ///
    /// # Errors
    ///
    /// Fails closed when the tag or the asset name is empty, oversized or
    /// carries a path separator, so a caller cannot escape the configured
    /// repository with a crafted name.
    pub fn asset_url(&self, tag: &str, asset: &str) -> Result<String, AxiomError> {
        let tag = segment("tag", tag)?;
        let asset = segment("asset", asset)?;
        Ok(format!(
            "{}/download/{tag}/{asset}",
            self.release_base_url()
        ))
    }

    /// The origin of an answer produced with this source.
    #[must_use]
    pub const fn origin(&self) -> SourceOrigin {
        SourceOrigin::Configured
    }
}

/// A refusal of one unusable source field.
fn refuse(rule: &str, observed: &str, message: &str) -> AxiomError {
    AxiomError::new(ErrorCode::ValidationError, message)
        .with_detail("rule", rule)
        .with_detail("observed", observed)
}

/// The refusal for a configuration that was never completed.
fn unconfigured(component: &str, missing: &str) -> AxiomError {
    refuse(
        "unconfigured",
        &format!("component={component};missing={missing}"),
        "no trusted update source is configured; a source default is never invented from a component name",
    )
}

/// Validate one owner or repository name.
fn name(kind: &str, value: &str) -> Result<String, AxiomError> {
    let text = value.trim();
    if text.is_empty() {
        return Err(refuse(
            "empty_source_field",
            &format!("{kind}=<empty>"),
            "an update source field must not be empty",
        ));
    }
    if text.len() > MAX_FIELD_LEN {
        return Err(refuse(
            "oversized_source_field",
            &format!("{kind}.len={}", text.len()),
            "an update source field is longer than the accepted maximum",
        ));
    }
    if has_placeholder(text) {
        return Err(refuse(
            "placeholder_source_field",
            &format!("{kind}={text}"),
            "an update source field still carries a specification placeholder",
        ));
    }
    if !text
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(refuse(
            "invalid_source_char",
            &format!("{kind}={text}"),
            "an update source field carries a character outside the GitHub owner/repo alphabet",
        ));
    }
    if text.starts_with('-') || text.starts_with('.') || text.ends_with('-') || text.ends_with('.')
    {
        return Err(refuse(
            "ambiguous_source_field",
            &format!("{kind}={text}"),
            "an update source field begins or ends where it would be ambiguous with a path or an option",
        ));
    }
    Ok(text.to_string())
}

/// Validate one URL path segment.
fn segment(kind: &str, value: &str) -> Result<String, AxiomError> {
    let text = value.trim();
    if text.is_empty() || text.len() > MAX_FIELD_LEN {
        return Err(refuse(
            "invalid_url_segment",
            &format!("{kind}.len={}", text.len()),
            "a release URL segment must be present and bounded",
        ));
    }
    if !text
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
    {
        return Err(refuse(
            "invalid_url_segment",
            &format!("{kind}={text}"),
            "a release URL segment carries a character that could escape the configured repository",
        ));
    }
    Ok(text.to_string())
}

/// Validate one channel name against the frozen set.
fn channel_name(value: &str) -> Result<String, AxiomError> {
    let text = value.trim();
    if !CHANNELS.contains(&text) {
        return Err(refuse(
            "unsupported_channel",
            &format!("channel={text}"),
            "a release channel must be one of the frozen channel names",
        ));
    }
    Ok(text.to_string())
}

/// True when a value still carries a specification placeholder.
fn has_placeholder(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| upper.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_of(error: &AxiomError) -> String {
        error.details().get("rule").cloned().unwrap_or_default()
    }

    #[test]
    fn an_explicit_source_builds_only_https_release_urls() {
        let source = UpdateSource::new("orchex006", "axiom-graphd", "stable").expect("valid");
        assert_eq!(source.slug(), "orchex006/axiom-graphd");
        assert_eq!(source.channel(), "stable");
        assert_eq!(
            source.release_base_url(),
            "https://github.com/orchex006/axiom-graphd/releases"
        );
        assert_eq!(
            source
                .asset_url("v0.2.0", "axiom-graphd-0.2.0-linux-x64.tar.gz")
                .expect("valid asset"),
            "https://github.com/orchex006/axiom-graphd/releases/download/v0.2.0/axiom-graphd-0.2.0-linux-x64.tar.gz"
        );
        assert!(source.release_base_url().starts_with("https://"));
        assert_eq!(source.origin(), SourceOrigin::Configured);
        // The same source is reconstructible from its own configuration.
        let config = SourceConfig::configured(source.owner(), source.repo(), source.channel());
        assert_eq!(
            UpdateSource::from_config(&config, "ignored").expect("valid"),
            source
        );
    }

    #[test]
    fn an_unconfigured_source_is_refused_and_never_borrows_the_component_name() {
        let error = UpdateSource::from_config(&SourceConfig::default(), "axiom-graphd")
            .expect_err("an unset source must be refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(rule_of(&error), "unconfigured");
        let observed = error.details().get("observed").cloned().unwrap_or_default();
        assert!(observed.contains("component=axiom-graphd"), "{observed}");
        // The refusal names the component but never promotes it to an owner:
        // there is no source to read an owner from.
        assert_eq!(SourceOrigin::Unconfigured.as_str(), "unconfigured");
        assert_eq!(
            SourceOrigin::all(),
            &[SourceOrigin::Configured, SourceOrigin::Unconfigured]
        );

        // A half-configured source is refused too, and the missing half is named.
        let partial = SourceConfig {
            owner: Some("orchex006".to_string()),
            repo: None,
            channel: Some("stable".to_string()),
        };
        let error = UpdateSource::from_config(&partial, "axiom").expect_err("partial");
        assert_eq!(rule_of(&error), "unconfigured");
        assert!(error
            .details()
            .get("observed")
            .is_some_and(|value| value.contains("missing=owner/repo")));
    }

    #[test]
    fn a_placeholder_or_missing_field_is_refused() {
        for marker in PLACEHOLDER_MARKERS {
            let lower = marker.to_ascii_lowercase();
            for value in [marker, &lower] {
                let error = UpdateSource::new(value, "axiom-graphd", "stable")
                    .expect_err("a placeholder owner must be refused");
                assert_eq!(rule_of(&error), "placeholder_source_field", "{value}");
            }
        }
        assert_eq!(PLACEHOLDER_MARKERS, ["REPLACE_ME", "FILL_ME"]);
        let error = UpdateSource::new("   ", "axiom-graphd", "stable").expect_err("empty owner");
        assert_eq!(rule_of(&error), "empty_source_field");
    }

    #[test]
    fn a_channel_outside_the_frozen_set_is_refused() {
        for channel in ["latest", "nightly", "", "Stable"] {
            let error = UpdateSource::new("orchex006", "axiom-graphd", channel)
                .expect_err("an unknown channel must be refused");
            assert_eq!(rule_of(&error), "unsupported_channel", "{channel}");
        }
        assert_eq!(CHANNELS, ["stable", "prerelease"]);
        for channel in CHANNELS {
            assert!(UpdateSource::new("orchex006", "axiom-graphd", channel).is_ok());
        }
    }

    #[test]
    fn a_field_that_could_smuggle_a_path_or_option_is_refused() {
        for owner in [
            "a/b",
            "-option",
            ".hidden",
            "trailing-",
            "trailing.",
            "two words",
        ] {
            let error = UpdateSource::new(owner, "axiom-graphd", "stable")
                .expect_err("an escaping owner must be refused");
            assert!(
                matches!(
                    rule_of(&error).as_str(),
                    "invalid_source_char" | "ambiguous_source_field"
                ),
                "{owner}: {error}"
            );
        }
        let oversized = "x".repeat(MAX_FIELD_LEN + 1);
        let error = UpdateSource::new(&oversized, "axiom-graphd", "stable")
            .expect_err("an oversized owner must be refused");
        assert_eq!(rule_of(&error), "oversized_source_field");
        assert_eq!(MAX_FIELD_LEN, 100);
    }

    #[test]
    fn an_asset_name_that_would_escape_the_repository_is_refused() {
        let source = UpdateSource::new("orchex006", "axiom-graphd", "stable").expect("valid");
        for asset in ["../other-repo/blob", "sub/dir/file", "", "space name"] {
            let error = source
                .asset_url("v0.2.0", asset)
                .expect_err("an escaping asset must be refused");
            assert_eq!(rule_of(&error), "invalid_url_segment", "{asset}");
        }
        let error = source
            .asset_url("v0.2.0/../other", "file.zip")
            .expect_err("an escaping tag must be refused");
        assert_eq!(rule_of(&error), "invalid_url_segment");
    }
}
