//! Cached, TTL- and offline-aware version check (task E-037).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 4 fixes the check policy:
//! the default auto-check may run in a maintenance window when the network policy
//! allows it, with a 24 hour TTL plus jitter, a 10 second request timeout and
//! cached metadata; a network failure must not stop graph queries but reports the
//! last successful check and stale update information, and `--offline` must not
//! touch the network at all. The same section says a check never installs
//! anything: default auto-apply is disabled and a major version, a schema
//! migration, a host-config rewrite or a trust-root change each need an explicit
//! plan approval.
//!
//! This module is that policy for the *check* step only. It can read cached
//! metadata and ask a [`CheckTransport`] for fresh metadata, and it has no way to
//! download an artifact, run a process or write an install:
//!
//! * [`CheckPolicy::validate`] bounds the TTL, the timeout and the jitter;
//! * [`decide`] says whether a check is due, and an offline or disabled policy
//!   never contacts anything;
//! * [`run_check`] enforces the offline and TTL decision again at the transport
//!   boundary, refuses a transport that downloaded anything implicitly
//!   (`implicit_download`), and on a transport failure reports `offline` with the
//!   last successful check and its age - never `current`.
//!
//! The clock is injected as an epoch second for the arithmetic and as an RFC 3339
//! instant for the report, so TTL behaviour is a pure function of its inputs and
//! two runs over one cache agree exactly.

use std::cell::Cell;

use graph_core::error::{AxiomError, ErrorCode};
use serde::{Deserialize, Serialize};

use crate::update::trust::UpdateMetadata;
use crate::version::UpdateStatus;

/// The default TTL of one cached check: 24 hours.
pub const DEFAULT_TTL_SECONDS: u64 = 24 * 60 * 60;

/// Shortest accepted TTL.
pub const MIN_TTL_SECONDS: u64 = 60;

/// Longest accepted TTL: the contract's 24 hours.
pub const MAX_TTL_SECONDS: u64 = DEFAULT_TTL_SECONDS;

/// The contract's request timeout: 10 seconds.
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 10;

/// Longest accepted request timeout.
pub const MAX_TIMEOUT_SECONDS: u64 = DEFAULT_TIMEOUT_SECONDS;

/// Longest accepted jitter added to the TTL.
pub const MAX_JITTER_SECONDS: u64 = 15 * 60;

/// The check policy of one host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckPolicy {
    /// `--offline`: no network call of any kind.
    pub offline: bool,
    /// Whether the automatic maintenance-window check is enabled at all.
    pub auto_check_allowed: bool,
    /// Cache lifetime in seconds.
    pub ttl_seconds: u64,
    /// Bounded request timeout in seconds.
    pub timeout_seconds: u64,
    /// Bounded jitter added to the TTL.
    pub jitter_seconds: u64,
}

impl Default for CheckPolicy {
    fn default() -> Self {
        Self {
            offline: false,
            auto_check_allowed: true,
            ttl_seconds: DEFAULT_TTL_SECONDS,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            jitter_seconds: 0,
        }
    }
}

impl CheckPolicy {
    /// An offline policy, which contacts nothing.
    #[must_use]
    pub fn offline() -> Self {
        Self {
            offline: true,
            ..Self::default()
        }
    }

    /// Refuse a policy outside the contract's bounds.
    ///
    /// # Errors
    ///
    /// Fails closed with a named `rule` when the TTL is below
    /// [`MIN_TTL_SECONDS`] or above [`MAX_TTL_SECONDS`], the timeout is zero or
    /// above [`MAX_TIMEOUT_SECONDS`], or the jitter exceeds
    /// [`MAX_JITTER_SECONDS`].
    pub fn validate(&self) -> Result<(), AxiomError> {
        if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&self.ttl_seconds) {
            return Err(refuse(
                "ttl_out_of_range",
                &format!(
                    "ttl_seconds={};min={MIN_TTL_SECONDS};max={MAX_TTL_SECONDS}",
                    self.ttl_seconds
                ),
            ));
        }
        if self.timeout_seconds == 0 || self.timeout_seconds > MAX_TIMEOUT_SECONDS {
            return Err(refuse(
                "timeout_out_of_range",
                &format!(
                    "timeout_seconds={};max={MAX_TIMEOUT_SECONDS}",
                    self.timeout_seconds
                ),
            ));
        }
        if self.jitter_seconds > MAX_JITTER_SECONDS {
            return Err(refuse(
                "jitter_out_of_range",
                &format!(
                    "jitter_seconds={};max={MAX_JITTER_SECONDS}",
                    self.jitter_seconds
                ),
            ));
        }
        Ok(())
    }

    /// TTL plus jitter: the age at which a cached check becomes due.
    #[must_use]
    pub fn effective_ttl_seconds(&self) -> u64 {
        self.ttl_seconds.saturating_add(self.jitter_seconds)
    }
}

/// One previously successful check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedCheck {
    /// RFC 3339 UTC instant of the successful check, for reporting.
    pub checked_at: String,
    /// The same instant as an epoch second, for exact TTL arithmetic.
    pub checked_at_epoch: u64,
    /// Channel that was checked.
    pub channel: String,
    /// Metadata version that was accepted.
    pub metadata_version: u64,
    /// Available version, when the check observed one.
    pub available_version: Option<String>,
}

/// The cached metadata of one host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckCache {
    /// Last successful check, if any.
    pub last: Option<CachedCheck>,
}

/// The decision the policy makes before any network work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckDecision {
    /// The cache is fresh; serve it and contact nothing.
    ServeCached {
        /// Age of the cached check in seconds.
        age_seconds: u64,
    },
    /// The cache is missing or older than the effective TTL.
    NetworkDue {
        /// Age of the effective TTL in seconds.
        effective_ttl_seconds: u64,
    },
    /// `--offline`: contact nothing.
    Offline,
    /// The automatic check is disabled: contact nothing automatically.
    Disabled,
}

/// A verified metadata fetch plus the release version it advertises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedMetadata {
    /// Verified signed metadata.
    pub metadata: UpdateMetadata,
    /// A newer version the metadata advertises, if any.
    pub available_version: Option<String>,
}

/// The metadata transport of one check.
///
/// The trait has no method that can download an artifact or run anything, and
/// [`Self::downloads`] must stay zero: [`run_check`] refuses a transport that
/// reports otherwise.
pub trait CheckTransport {
    /// Fetch and verify the signed metadata for a channel.
    ///
    /// # Errors
    ///
    /// Any transport, TLS or verification failure.
    fn fetch(&self, channel: &str) -> Result<FetchedMetadata, AxiomError>;

    /// Number of metadata fetches performed by this transport.
    fn fetches(&self) -> u64;

    /// Number of artifact downloads performed by this transport; always zero.
    fn downloads(&self) -> u64;
}

/// The report of one check run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckReport {
    /// Honest update state.
    pub status: UpdateStatus,
    /// Whether a network call was made.
    pub network_used: bool,
    /// Artifact downloads performed; zero by construction.
    pub downloads: u64,
    /// True when the answer is older than the effective TTL.
    pub stale: bool,
    /// RFC 3339 instant of the last successful check, if any.
    pub last_successful_check: Option<String>,
    /// Metadata version that was accepted, if any.
    pub metadata_version: Option<u64>,
    /// Available version, if the check observed one.
    pub available_version: Option<String>,
    /// Named reason a transport failure was recorded, never a pass.
    pub transport_error: Option<String>,
}

/// Decide whether a check is due, without contacting anything.
///
/// An offline policy and a disabled automatic check both win over the cache, so
/// a stale cache can never turn into a network call by accident.
#[must_use]
pub fn decide(policy: &CheckPolicy, cache: &CheckCache, now_epoch: u64) -> CheckDecision {
    if policy.offline {
        return CheckDecision::Offline;
    }
    if !policy.auto_check_allowed {
        return CheckDecision::Disabled;
    }
    let effective = policy.effective_ttl_seconds();
    match &cache.last {
        Some(last) => {
            let age = now_epoch.saturating_sub(last.checked_at_epoch);
            if age < effective {
                CheckDecision::ServeCached { age_seconds: age }
            } else {
                CheckDecision::NetworkDue {
                    effective_ttl_seconds: effective,
                }
            }
        }
        None => CheckDecision::NetworkDue {
            effective_ttl_seconds: effective,
        },
    }
}

/// Run one check under a policy.
///
/// The offline and TTL decision is re-evaluated here against the transport, so a
/// caller cannot ask for a network call the policy refused. A transport failure
/// is not an error: it is reported as [`UpdateStatus::Offline`] with the last
/// successful check and its staleness, because graph queries must keep working.
///
/// # Errors
///
/// Fails closed with a named `rule` when the policy is outside its bounds, or
/// when the transport reports an artifact download (`implicit_download`) - a
/// check must never download or run an installer.
pub fn run_check(
    policy: &CheckPolicy,
    cache: &mut CheckCache,
    now_epoch: u64,
    now: &str,
    transport: &impl CheckTransport,
) -> Result<CheckReport, AxiomError> {
    policy.validate()?;
    let decision = decide(policy, cache, now_epoch);
    let last_successful_check = cache.last.as_ref().map(|last| last.checked_at.clone());
    let cached_status = |available: &Option<String>| {
        if available.is_some() {
            UpdateStatus::Available
        } else {
            UpdateStatus::Current
        }
    };

    match decision {
        CheckDecision::Disabled => {
            let age_stale = cache.last.as_ref().is_some_and(|last| {
                now_epoch.saturating_sub(last.checked_at_epoch) >= policy.effective_ttl_seconds()
            });
            Ok(CheckReport {
                status: cache
                    .last
                    .as_ref()
                    .map_or(UpdateStatus::NotChecked, |last| {
                        cached_status(&last.available_version)
                    }),
                network_used: false,
                downloads: transport.downloads(),
                stale: age_stale,
                last_successful_check,
                metadata_version: cache.last.as_ref().map(|last| last.metadata_version),
                available_version: cache
                    .last
                    .as_ref()
                    .and_then(|last| last.available_version.clone()),
                transport_error: None,
            })
        }
        CheckDecision::Offline => Ok(CheckReport {
            // Offline is never reported as up to date, even with a warm cache.
            status: UpdateStatus::Offline,
            network_used: false,
            downloads: transport.downloads(),
            stale: cache.last.is_some(),
            last_successful_check,
            metadata_version: cache.last.as_ref().map(|last| last.metadata_version),
            available_version: cache
                .last
                .as_ref()
                .and_then(|last| last.available_version.clone()),
            transport_error: None,
        }),
        CheckDecision::ServeCached { .. } => Ok(CheckReport {
            status: cache
                .last
                .as_ref()
                .map_or(UpdateStatus::NotChecked, |last| {
                    cached_status(&last.available_version)
                }),
            network_used: false,
            downloads: transport.downloads(),
            stale: false,
            last_successful_check,
            metadata_version: cache.last.as_ref().map(|last| last.metadata_version),
            available_version: cache
                .last
                .as_ref()
                .and_then(|last| last.available_version.clone()),
            transport_error: None,
        }),
        CheckDecision::NetworkDue { .. } => {
            let fetched = transport.fetch(&policy_channel(cache));
            let downloads = transport.downloads();
            if downloads != 0 {
                return Err(forbid(
                    "implicit_download",
                    &format!("downloads={downloads}"),
                ));
            }
            match fetched {
                Ok(fetched) => {
                    let channel = fetched.metadata.channel.clone();
                    cache.last = Some(CachedCheck {
                        checked_at: now.to_string(),
                        checked_at_epoch: now_epoch,
                        channel,
                        metadata_version: fetched.metadata.metadata_version,
                        available_version: fetched.available_version.clone(),
                    });
                    Ok(CheckReport {
                        status: cached_status(&fetched.available_version),
                        network_used: true,
                        downloads,
                        stale: false,
                        last_successful_check: Some(now.to_string()),
                        metadata_version: Some(fetched.metadata.metadata_version),
                        available_version: fetched.available_version,
                        transport_error: None,
                    })
                }
                Err(error) => Ok(CheckReport {
                    status: UpdateStatus::Offline,
                    network_used: true,
                    downloads: transport.downloads(),
                    stale: cache.last.is_some(),
                    last_successful_check,
                    metadata_version: cache.last.as_ref().map(|last| last.metadata_version),
                    available_version: cache
                        .last
                        .as_ref()
                        .and_then(|last| last.available_version.clone()),
                    transport_error: Some(
                        error
                            .details()
                            .get("rule")
                            .cloned()
                            .unwrap_or_else(|| error.code().as_str().to_string()),
                    ),
                }),
            }
        }
    }
}

/// The channel a due check asks for: the last checked channel, else `stable`.
fn policy_channel(cache: &CheckCache) -> String {
    cache
        .last
        .as_ref()
        .map_or_else(|| "stable".to_string(), |last| last.channel.clone())
}

/// The one refusal shape of this module.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the check policy violates the version-check contract",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

/// Refuse something the host is not authorized to do.
fn forbid(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::Forbidden,
        "the version check attempted an operation the policy forbids",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

/// A counting transport double shared with the tests.
///
/// It exists in the module, not only in `#[cfg(test)]`, so an embedder can reuse
/// the same counting shape; it performs no I/O.
#[derive(Debug, Default)]
pub struct CountingTransport {
    fetches: Cell<u64>,
    downloads: Cell<u64>,
    result: Option<Result<FetchedMetadata, AxiomError>>,
}

impl CountingTransport {
    /// A transport that never performs I/O and answers `result`.
    #[must_use]
    pub fn answering(result: Result<FetchedMetadata, AxiomError>) -> Self {
        Self {
            fetches: Cell::new(0),
            downloads: Cell::new(0),
            result: Some(result),
        }
    }

    /// A transport that reports an implicit artifact download it must not make.
    #[must_use]
    pub fn with_downloads(count: u64) -> Self {
        Self {
            fetches: Cell::new(0),
            downloads: Cell::new(count),
            result: None,
        }
    }
}

impl CheckTransport for CountingTransport {
    fn fetch(&self, _channel: &str) -> Result<FetchedMetadata, AxiomError> {
        self.fetches.set(self.fetches.get() + 1);
        match &self.result {
            Some(Ok(fetched)) => Ok(fetched.clone()),
            Some(Err(error)) => Err(error.clone()),
            None => Err(refuse("no_transport_result", "result=<none>")),
        }
    }

    fn fetches(&self) -> u64 {
        self.fetches.get()
    }

    fn downloads(&self) -> u64 {
        self.downloads.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::verify::{ArtifactSignature, TrustedRoot};

    const NOW: &str = "2026-09-19T00:00:00Z";
    const NOW_EPOCH: u64 = 1_789_977_600;

    fn metadata(version: u64) -> UpdateMetadata {
        UpdateMetadata {
            schema_version: 1,
            metadata_version: version,
            generated_at: "2026-09-01T00:00:00Z".to_string(),
            expires_at: "2026-12-01T00:00:00Z".to_string(),
            channel: "stable".to_string(),
            root: TrustedRoot {
                key_id: "release".to_string(),
                algorithm: "ed25519".to_string(),
                public_key: "ab".repeat(32),
            },
            signature: ArtifactSignature {
                algorithm: "ed25519".to_string(),
                key_id: "release".to_string(),
                value: "sig".to_string(),
            },
        }
    }

    fn fetched(available: Option<&str>) -> FetchedMetadata {
        FetchedMetadata {
            metadata: metadata(9),
            available_version: available.map(str::to_string),
        }
    }

    fn cached(age: u64, available: Option<&str>) -> CheckCache {
        CheckCache {
            last: Some(CachedCheck {
                checked_at: "2026-09-18T00:00:00Z".to_string(),
                checked_at_epoch: NOW_EPOCH - age,
                channel: "stable".to_string(),
                metadata_version: 8,
                available_version: available.map(str::to_string),
            }),
        }
    }

    fn rule_of(error: &AxiomError) -> String {
        error.details().get("rule").cloned().unwrap_or_default()
    }

    #[test]
    fn the_default_policy_matches_the_contract_bounds() {
        let policy = CheckPolicy::default();
        policy.validate().expect("the default policy is valid");
        assert_eq!(policy.ttl_seconds, 24 * 60 * 60);
        assert_eq!(policy.timeout_seconds, 10);
        assert_eq!(policy.jitter_seconds, 0);
        assert!(!policy.offline);
        assert_eq!(MIN_TTL_SECONDS, 60);
        assert_eq!(MAX_TTL_SECONDS, DEFAULT_TTL_SECONDS);
        assert_eq!(MAX_TIMEOUT_SECONDS, 10);
        assert_eq!(MAX_JITTER_SECONDS, 15 * 60);
        assert_eq!(policy.effective_ttl_seconds(), DEFAULT_TTL_SECONDS);
        let jittered = CheckPolicy {
            jitter_seconds: 120,
            ..CheckPolicy::default()
        };
        assert_eq!(jittered.effective_ttl_seconds(), DEFAULT_TTL_SECONDS + 120);
    }

    #[test]
    fn a_fresh_cache_is_served_without_touching_the_network() {
        let policy = CheckPolicy::default();
        let cache = cached(60, Some("0.2.0"));
        assert_eq!(
            decide(&policy, &cache, NOW_EPOCH),
            CheckDecision::ServeCached { age_seconds: 60 }
        );
        let transport = CountingTransport::answering(Ok(fetched(Some("0.3.0"))));
        let mut cache = cache;
        let report =
            run_check(&policy, &mut cache, NOW_EPOCH, NOW, &transport).expect("check runs");
        assert_eq!(report.status, UpdateStatus::Available);
        assert!(!report.network_used);
        assert_eq!(transport.fetches(), 0, "a fresh cache contacts nothing");
        assert_eq!(report.downloads, 0);
        assert!(!report.stale);
        assert_eq!(
            report.last_successful_check.as_deref(),
            Some("2026-09-18T00:00:00Z")
        );
        assert_eq!(report.metadata_version, Some(8));
    }

    #[test]
    fn the_ttl_boundary_decides_when_a_check_is_due() {
        let policy = CheckPolicy::default();
        let ttl = policy.effective_ttl_seconds();
        // One second before the TTL is still cached.
        assert!(matches!(
            decide(&policy, &cached(ttl - 1, None), NOW_EPOCH),
            CheckDecision::ServeCached { .. }
        ));
        // Exactly the TTL is already due.
        assert_eq!(
            decide(&policy, &cached(ttl, None), NOW_EPOCH),
            CheckDecision::NetworkDue {
                effective_ttl_seconds: ttl
            }
        );
        // An empty cache is due immediately.
        assert_eq!(
            decide(&policy, &CheckCache::default(), NOW_EPOCH),
            CheckDecision::NetworkDue {
                effective_ttl_seconds: ttl
            }
        );

        // Jitter moves the boundary, and a due cache is fetched exactly once.
        let jittered = CheckPolicy {
            jitter_seconds: 300,
            ..CheckPolicy::default()
        };
        let at_ttl = cached(ttl, None);
        assert!(matches!(
            decide(&jittered, &at_ttl, NOW_EPOCH),
            CheckDecision::ServeCached { .. }
        ));
        // Past the jittered boundary the check is due and is fetched exactly once.
        let transport = CountingTransport::answering(Ok(fetched(None)));
        let mut cache = cached(ttl + jittered.jitter_seconds, None);
        let report =
            run_check(&jittered, &mut cache, NOW_EPOCH, NOW, &transport).expect("a due check runs");
        assert_eq!(transport.fetches(), 1);
        assert!(report.network_used);
        assert_eq!(report.status, UpdateStatus::Current);
        assert_eq!(report.downloads, 0);
    }

    #[test]
    fn offline_never_contacts_the_network_and_never_claims_current() {
        let policy = CheckPolicy::offline();
        let cache = cached(60, Some("0.2.0"));
        assert_eq!(decide(&policy, &cache, NOW_EPOCH), CheckDecision::Offline);
        let transport = CountingTransport::answering(Ok(fetched(Some("0.9.0"))));
        let mut cache = cache;
        let report =
            run_check(&policy, &mut cache, NOW_EPOCH, NOW, &transport).expect("offline runs");
        assert_eq!(report.status, UpdateStatus::Offline);
        assert_ne!(report.status, UpdateStatus::Current);
        assert!(!report.network_used);
        assert_eq!(transport.fetches(), 0, "offline contacts nothing");
        assert_eq!(transport.downloads(), 0);
        assert!(report.stale);
        assert_eq!(
            report.last_successful_check.as_deref(),
            Some("2026-09-18T00:00:00Z")
        );
        assert_eq!(policy.validate(), Ok(()));
    }

    #[test]
    fn a_disabled_auto_check_contacts_nothing() {
        let policy = CheckPolicy {
            auto_check_allowed: false,
            ..CheckPolicy::default()
        };
        assert_eq!(
            decide(&policy, &CheckCache::default(), NOW_EPOCH),
            CheckDecision::Disabled
        );
        let transport = CountingTransport::answering(Ok(fetched(None)));
        let mut cache = CheckCache::default();
        let report =
            run_check(&policy, &mut cache, NOW_EPOCH, NOW, &transport).expect("disabled runs");
        assert_eq!(transport.fetches(), 0);
        assert!(!report.network_used);
        assert_eq!(report.status, UpdateStatus::NotChecked);
        assert!(report.last_successful_check.is_none());
    }

    #[test]
    fn a_failed_network_check_reports_stale_offline_not_current() {
        let policy = CheckPolicy::default();
        let transport = CountingTransport::answering(Err(AxiomError::new(
            ErrorCode::NotReady,
            "the release endpoint could not be reached",
        )
        .with_detail("rule", "endpoint_unreachable")));
        let mut cache = cached(
            CheckPolicy::default().effective_ttl_seconds(),
            Some("0.2.0"),
        );
        let report = run_check(&policy, &mut cache, NOW_EPOCH, NOW, &transport)
            .expect("failure is reported");
        assert_eq!(transport.fetches(), 1);
        assert_eq!(report.status, UpdateStatus::Offline);
        assert_ne!(report.status, UpdateStatus::Current);
        assert!(report.stale);
        assert_eq!(
            report.transport_error.as_deref(),
            Some("endpoint_unreachable")
        );
        assert_eq!(
            report.last_successful_check.as_deref(),
            Some("2026-09-18T00:00:00Z")
        );
        assert_eq!(report.downloads, 0);
        // The cache is preserved, not overwritten by a failure.
        assert_eq!(
            cache.last.as_ref().map(|last| last.metadata_version),
            Some(8)
        );
    }

    #[test]
    fn a_check_never_downloads_an_installer_implicitly() {
        let policy = CheckPolicy::default();
        let transport = CountingTransport::with_downloads(1);
        let mut cache = CheckCache::default();
        let error = run_check(&policy, &mut cache, NOW_EPOCH, NOW, &transport)
            .expect_err("an implicit download must be refused");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(rule_of(&error), "implicit_download");
        assert_eq!(transport.downloads(), 1);
    }

    #[test]
    fn a_policy_outside_its_bounds_is_refused() {
        for (policy, rule) in [
            (
                CheckPolicy {
                    ttl_seconds: 0,
                    ..CheckPolicy::default()
                },
                "ttl_out_of_range",
            ),
            (
                CheckPolicy {
                    ttl_seconds: MAX_TTL_SECONDS + 1,
                    ..CheckPolicy::default()
                },
                "ttl_out_of_range",
            ),
            (
                CheckPolicy {
                    timeout_seconds: 0,
                    ..CheckPolicy::default()
                },
                "timeout_out_of_range",
            ),
            (
                CheckPolicy {
                    timeout_seconds: MAX_TIMEOUT_SECONDS + 1,
                    ..CheckPolicy::default()
                },
                "timeout_out_of_range",
            ),
            (
                CheckPolicy {
                    jitter_seconds: MAX_JITTER_SECONDS + 1,
                    ..CheckPolicy::default()
                },
                "jitter_out_of_range",
            ),
        ] {
            let error = policy
                .validate()
                .expect_err("an out-of-range policy must be refused");
            assert_eq!(rule_of(&error), rule, "{policy:?}");
        }
    }
}
