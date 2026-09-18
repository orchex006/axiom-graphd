//! Bounded freshness barrier that never fakes freshness (task B-044).
//!
//! `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 8 fixes the semantics:
//! an on-demand freshness request captures a `target_event_seq` **and** an input
//! inventory baseline. The request succeeds only when
//!
//! 1. every required scope is indexed up to the barrier sequence,
//! 2. publication is available for those scopes,
//! 3. the catalog/vector view is verified, and
//! 4. the post-validation fingerprint did not change inside the verification
//!    window.
//!
//! `--wait-timeout` is bounded (30 s by default). When it expires the caller gets
//! the pending job ids and `WORKTREE_BUSY`; it never receives a fabricated fresh
//! snapshot. Changes that arrive *after* a successful barrier are not lost and
//! are not folded into the committed snapshot: they are reported honestly as a
//! new dirty generation, which is why the success carries `verified_at` and a
//! `snapshot_id`.
//!
//! Like the rest of this crate the module is a pure decision layer: it reads an
//! observation assembled from durable state and the worktree fingerprint, and it
//! never touches a database or the filesystem itself.

use graph_core::error::{AxiomError, ErrorCode};

/// Default bounded wait; matches `--wait-timeout 30s`.
pub const DEFAULT_WAIT_TIMEOUT_MS: i64 = 30_000;
/// Longest wait this build will honour, so a completion hook cannot block a full
/// rebuild without an upper bound.
pub const MAX_WAIT_TIMEOUT_MS: i64 = 600_000;
/// Default window in which the input fingerprint must stay unchanged.
pub const DEFAULT_VERIFICATION_WINDOW_MS: i64 = 250;
/// Reason returned when the bounded wait expired with work still outstanding.
pub const REASON_WORKTREE_BUSY: &str = "WORKTREE_BUSY";
/// Reason returned when required publication is not available yet.
pub const REASON_PUBLICATION_UNAVAILABLE: &str = "publication_unavailable";
/// Reason returned when the catalog/vector view is not verified yet.
pub const REASON_CATALOG_NOT_VERIFIED: &str = "catalog_not_verified";
/// Reason returned when the worktree changed inside the verification window.
pub const REASON_FINGERPRINT_CHANGED: &str = "fingerprint_changed";
/// Reason recorded when a requested wait is outside the supported bound.
pub const REASON_TIMEOUT_OUT_OF_RANGE: &str = "timeout_out_of_range";
/// Reason recorded when a request carries no required scope.
pub const REASON_EMPTY_SCOPE: &str = "empty_scope";

/// One bounded freshness request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierRequest {
    target_event_seq: i64,
    required_scopes: Vec<String>,
    require_publication: bool,
    timeout_ms: i64,
}

impl BarrierRequest {
    /// A request covering `required_scopes` up to `target_event_seq`.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] when no scope is required or the target
    /// sequence is negative.
    pub fn new(
        target_event_seq: i64,
        required_scopes: Vec<String>,
        require_publication: bool,
    ) -> Result<Self, AxiomError> {
        if target_event_seq < 0 {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a barrier target event sequence must not be negative",
            )
            .with_detail("rule", REASON_TIMEOUT_OUT_OF_RANGE)
            .with_detail("actual", target_event_seq.to_string()));
        }
        if required_scopes.is_empty() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "a barrier must name at least one required scope",
            )
            .with_detail("rule", REASON_EMPTY_SCOPE));
        }
        Ok(Self {
            target_event_seq,
            required_scopes,
            require_publication,
            timeout_ms: DEFAULT_WAIT_TIMEOUT_MS,
        })
    }

    /// Override the bounded wait.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] when the wait is negative or above
    /// [`MAX_WAIT_TIMEOUT_MS`].
    pub fn with_timeout_ms(mut self, timeout_ms: i64) -> Result<Self, AxiomError> {
        if !(0..=MAX_WAIT_TIMEOUT_MS).contains(&timeout_ms) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "the barrier wait must be inside the supported bound",
            )
            .with_detail("rule", REASON_TIMEOUT_OUT_OF_RANGE)
            .with_detail("expected", MAX_WAIT_TIMEOUT_MS.to_string())
            .with_detail("actual", timeout_ms.to_string()));
        }
        self.timeout_ms = timeout_ms;
        Ok(self)
    }

    /// Sequence the barrier must cover.
    #[must_use]
    pub const fn target_event_seq(&self) -> i64 {
        self.target_event_seq
    }

    /// Scopes whose indexing must reach the barrier sequence.
    #[must_use]
    pub fn required_scopes(&self) -> &[String] {
        &self.required_scopes
    }

    /// Whether a published generation must be available.
    #[must_use]
    pub const fn require_publication(&self) -> bool {
        self.require_publication
    }

    /// The bounded wait in milliseconds.
    #[must_use]
    pub const fn timeout_ms(&self) -> i64 {
        self.timeout_ms
    }
}

/// Indexed progress of one required scope, read from durable state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeProgress {
    /// Scope key, e.g. a portably relative project path.
    pub scope: String,
    /// Highest event sequence whose facts for this scope are durable.
    pub indexed_event_seq: i64,
}

impl ScopeProgress {
    /// Build a progress row.
    #[must_use]
    pub fn new(scope: impl Into<String>, indexed_event_seq: i64) -> Self {
        Self {
            scope: scope.into(),
            indexed_event_seq,
        }
    }
}

/// Publication and catalog state for the required scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PublicationState {
    /// A published generation exists for every required scope.
    pub available: bool,
    /// The catalog/vector view was verified against that generation.
    pub catalog_verified: bool,
}

impl PublicationState {
    /// Both publication and catalog verification observed.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        self.available && self.catalog_verified
    }
}

/// The worktree fingerprint before and after the verification window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationWindow {
    /// Fingerprint captured when the required scopes were believed complete.
    pub before: String,
    /// Fingerprint re-read after the verification window elapsed.
    pub after: String,
}

impl VerificationWindow {
    /// Build a window from two fingerprints.
    #[must_use]
    pub fn new(before: impl Into<String>, after: impl Into<String>) -> Self {
        Self {
            before: before.into(),
            after: after.into(),
        }
    }

    /// Whether the input is stable across the window.
    #[must_use]
    pub fn is_stable(&self) -> bool {
        self.before == self.after
    }
}

/// Everything the barrier decision needs, assembled from durable state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierObservation {
    /// Indexed progress per required scope.
    pub scopes: Vec<ScopeProgress>,
    /// Publication/catalog state.
    pub publication: PublicationState,
    /// Non-terminal jobs that still cover a required scope, for the timeout
    /// report. Never used to declare success.
    pub pending_job_ids: Vec<String>,
}

impl BarrierObservation {
    /// Build an observation.
    #[must_use]
    pub fn new(
        scopes: Vec<ScopeProgress>,
        publication: PublicationState,
        pending_job_ids: Vec<String>,
    ) -> Self {
        Self {
            scopes,
            publication,
            pending_job_ids,
        }
    }

    /// Whether every scope the request names is indexed to the barrier sequence.
    #[must_use]
    pub fn covers(&self, request: &BarrierRequest) -> bool {
        request.required_scopes().iter().all(|required| {
            self.scopes.iter().any(|progress| {
                &progress.scope == required
                    && progress.indexed_event_seq >= request.target_event_seq()
            })
        })
    }
}

/// A committed barrier success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSnapshot {
    /// Monotonic time of the successful verification.
    pub verified_at: i64,
    /// Deterministic id of the verified generation.
    pub snapshot_id: String,
    /// Sequence the snapshot covers.
    pub target_event_seq: i64,
    /// Input fingerprint that was stable across the verification window.
    pub fingerprint: String,
}

/// The result of a barrier attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BarrierOutcome {
    /// The barrier succeeded for the target generation.
    Verified(VerifiedSnapshot),
    /// The barrier did not succeed; freshness was never claimed.
    TimedOut {
        /// Jobs still covering a required scope.
        pending_job_ids: Vec<String>,
        /// Why the barrier did not succeed.
        reason: &'static str,
        /// Sequence that was requested.
        target_event_seq: i64,
        /// How long the caller waited.
        waited_ms: i64,
    },
}

impl BarrierOutcome {
    /// Whether this outcome claims freshness.
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified(_))
    }
}

/// Decide a barrier attempt.
///
/// # Errors
/// [`ErrorCode::ValidationError`] when the observation cannot satisfy the
/// request shape (for example the wait is out of bound).
pub fn evaluate(
    request: &BarrierRequest,
    observation: &BarrierObservation,
    window: &VerificationWindow,
    now: i64,
    waited_ms: i64,
) -> Result<BarrierOutcome, AxiomError> {
    let waited_ms = crate::clamp_duration(waited_ms, request.timeout_ms());
    if observation.covers(request)
        && (!request.require_publication() || observation.publication.available)
        && observation.publication.catalog_verified
        && window.is_stable()
    {
        return Ok(BarrierOutcome::Verified(VerifiedSnapshot {
            verified_at: now,
            snapshot_id: snapshot_id(request, window),
            target_event_seq: request.target_event_seq(),
            fingerprint: window.after.clone(),
        }));
    }
    Ok(BarrierOutcome::TimedOut {
        pending_job_ids: observation.pending_job_ids.clone(),
        reason: refusal_reason(request, observation, window),
        target_event_seq: request.target_event_seq(),
        waited_ms,
    })
}

/// Classify why a barrier did not succeed, in precedence order: a moving
/// worktree outranks publication, which outranks an unverified catalog, which
/// outranks plain outstanding work.
#[must_use]
pub fn refusal_reason(
    request: &BarrierRequest,
    observation: &BarrierObservation,
    window: &VerificationWindow,
) -> &'static str {
    if !window.is_stable() {
        return REASON_FINGERPRINT_CHANGED;
    }
    if request.require_publication() && !observation.publication.available {
        return REASON_PUBLICATION_UNAVAILABLE;
    }
    if !observation.publication.catalog_verified {
        return REASON_CATALOG_NOT_VERIFIED;
    }
    REASON_WORKTREE_BUSY
}

/// Whether the bounded wait may poll again at `waited_ms`.
#[must_use]
pub fn may_poll_again(request: &BarrierRequest, waited_ms: i64) -> bool {
    waited_ms < request.timeout_ms()
}

/// Whether a change observed at `observed_at` is a new dirty generation after a
/// committed snapshot, rather than part of that snapshot.
///
/// `docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 8: new changes after a
/// barrier are reported directly; they are never silently folded into a snapshot
/// that was already declared fresh.
#[must_use]
pub fn is_new_generation_after(snapshot: &VerifiedSnapshot, observed_at: i64) -> bool {
    observed_at > snapshot.verified_at
}

/// Deterministic snapshot id: a length-delimited digest of the barrier inputs.
///
/// The scopes are sorted before hashing so the same barrier requested in a
/// different order yields the same id, and the length prefix stops `("ab","c")`
/// from colliding with `("a","bc")`.
#[must_use]
pub fn snapshot_id(request: &BarrierRequest, window: &VerificationWindow) -> String {
    let mut scopes = request.required_scopes().to_vec();
    scopes.sort_unstable();
    scopes.dedup();
    let mut parts: Vec<&str> = vec![&window.after];
    parts.extend(scopes.iter().map(String::as_str));
    format!("snap-{}", digest(&parts))
}

/// FNV-1a over length-delimited UTF-8 parts.
fn digest(parts: &[&str]) -> String {
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        hash ^= part.len() as u64;
        hash = hash.wrapping_mul(PRIME);
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(PRIME);
        }
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::{
        evaluate, is_new_generation_after, may_poll_again, snapshot_id, BarrierObservation,
        BarrierOutcome, BarrierRequest, PublicationState, ScopeProgress, VerificationWindow,
        DEFAULT_WAIT_TIMEOUT_MS, MAX_WAIT_TIMEOUT_MS, REASON_CATALOG_NOT_VERIFIED,
        REASON_FINGERPRINT_CHANGED, REASON_PUBLICATION_UNAVAILABLE, REASON_WORKTREE_BUSY,
    };
    use graph_core::error::ErrorCode;

    fn request() -> BarrierRequest {
        BarrierRequest::new(7, vec!["src/app".to_string(), "src/lib".to_string()], true)
            .expect("request")
    }

    fn complete() -> BarrierObservation {
        BarrierObservation::new(
            vec![
                ScopeProgress::new("src/app", 7),
                ScopeProgress::new("src/lib", 9),
            ],
            PublicationState {
                available: true,
                catalog_verified: true,
            },
            Vec::new(),
        )
    }

    fn stable() -> VerificationWindow {
        VerificationWindow::new("fp-1", "fp-1")
    }

    #[test]
    fn a_fully_covered_scoped_publication_verifies() {
        let outcome = evaluate(&request(), &complete(), &stable(), 1_000, 120).expect("decision");
        let BarrierOutcome::Verified(ref snapshot) = outcome else {
            panic!("a covered barrier must verify");
        };
        assert_eq!(snapshot.target_event_seq, 7);
        assert_eq!(snapshot.fingerprint, "fp-1");
        assert_eq!(snapshot.verified_at, 1_000);
        assert!(outcome.is_verified());
    }

    #[test]
    fn a_scope_behind_the_barrier_is_never_reported_fresh() {
        let mut observation = complete();
        observation.scopes[1].indexed_event_seq = 6;
        let outcome =
            evaluate(&request(), &observation, &stable(), 1_000, 30_000).expect("decision");
        let BarrierOutcome::TimedOut {
            reason, waited_ms, ..
        } = outcome
        else {
            panic!("a short scope must not verify");
        };
        assert_eq!(reason, REASON_WORKTREE_BUSY);
        assert_eq!(waited_ms, 30_000);
    }

    #[test]
    fn a_timeout_returns_pending_job_ids_rather_than_fake_fresh() {
        let mut observation = complete();
        observation.scopes[0].indexed_event_seq = 0;
        observation.pending_job_ids = vec!["job-7".to_string(), "job-9".to_string()];
        let outcome =
            evaluate(&request(), &observation, &stable(), 1_000, 30_000).expect("decision");
        let BarrierOutcome::TimedOut {
            pending_job_ids,
            reason,
            target_event_seq,
            ..
        } = outcome
        else {
            panic!("must time out, never fake fresh");
        };
        assert_eq!(
            pending_job_ids,
            vec!["job-7".to_string(), "job-9".to_string()]
        );
        assert_eq!(reason, REASON_WORKTREE_BUSY);
        assert_eq!(target_event_seq, 7);
    }

    #[test]
    fn missing_publication_and_unverified_catalog_are_distinct_refusals() {
        let mut observation = complete();
        observation.publication.available = false;
        let outcome = evaluate(&request(), &observation, &stable(), 1_000, 10).expect("decision");
        let BarrierOutcome::TimedOut { reason, .. } = outcome else {
            panic!("must refuse");
        };
        assert_eq!(reason, REASON_PUBLICATION_UNAVAILABLE);

        let mut observation = complete();
        observation.publication.catalog_verified = false;
        let outcome = evaluate(&request(), &observation, &stable(), 1_000, 10).expect("decision");
        let BarrierOutcome::TimedOut { reason, .. } = outcome else {
            panic!("must refuse");
        };
        assert_eq!(reason, REASON_CATALOG_NOT_VERIFIED);
    }

    #[test]
    fn publication_is_only_required_when_the_request_asks_for_it() {
        let request = BarrierRequest::new(7, vec!["src/app".to_string()], false).expect("request");
        let observation = BarrierObservation::new(
            vec![ScopeProgress::new("src/app", 7)],
            PublicationState {
                available: false,
                catalog_verified: true,
            },
            Vec::new(),
        );
        assert!(evaluate(&request, &observation, &stable(), 1_000, 5)
            .expect("decision")
            .is_verified());
    }

    #[test]
    fn a_change_inside_the_verification_window_fails_the_barrier() {
        let window = VerificationWindow::new("fp-1", "fp-2");
        let outcome = evaluate(&request(), &complete(), &window, 1_000, 5).expect("decision");
        let BarrierOutcome::TimedOut { reason, .. } = outcome else {
            panic!("a changed window must not verify");
        };
        assert_eq!(reason, REASON_FINGERPRINT_CHANGED);
    }

    #[test]
    fn a_change_after_a_committed_snapshot_is_a_new_generation() {
        let snapshot =
            match evaluate(&request(), &complete(), &stable(), 100, 100).expect("decision") {
                BarrierOutcome::Verified(snapshot) => snapshot,
                BarrierOutcome::TimedOut { .. } => panic!("expected success"),
            };
        assert!(!is_new_generation_after(&snapshot, 100));
        assert!(is_new_generation_after(&snapshot, 101));
    }

    #[test]
    fn the_wait_is_bounded_and_the_default_is_thirty_seconds() {
        assert_eq!(request().timeout_ms(), DEFAULT_WAIT_TIMEOUT_MS);
        let bounded = request()
            .with_timeout_ms(MAX_WAIT_TIMEOUT_MS)
            .expect("bound");
        assert!(may_poll_again(&bounded, MAX_WAIT_TIMEOUT_MS - 1));
        assert!(!may_poll_again(&bounded, MAX_WAIT_TIMEOUT_MS));
        let error = request()
            .with_timeout_ms(MAX_WAIT_TIMEOUT_MS + 1)
            .expect_err("over the bound");
        assert_eq!(error.code(), ErrorCode::ValidationError);
    }

    #[test]
    fn a_request_without_a_scope_or_with_a_negative_target_is_rejected() {
        let error = BarrierRequest::new(0, Vec::new(), false).expect_err("empty scope");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        let error =
            BarrierRequest::new(-1, vec!["src".to_string()], false).expect_err("negative target");
        assert_eq!(error.code(), ErrorCode::ValidationError);
    }

    #[test]
    fn snapshot_ids_are_stable_and_scope_order_independent() {
        let forward =
            BarrierRequest::new(7, vec!["src/app".to_string(), "src/lib".to_string()], true)
                .expect("request");
        let reversed =
            BarrierRequest::new(7, vec!["src/lib".to_string(), "src/app".to_string()], true)
                .expect("request");
        assert_eq!(
            snapshot_id(&forward, &stable()),
            snapshot_id(&reversed, &stable())
        );
        // A different fingerprint is a different generation.
        assert_ne!(
            snapshot_id(&forward, &stable()),
            snapshot_id(&forward, &VerificationWindow::new("fp-1", "fp-2"))
        );
        // Length-delimited: ("ab","c") and ("a","bc") must not collide.
        assert_ne!(
            snapshot_id(
                &BarrierRequest::new(0, vec!["ab".to_string(), "c".to_string()], true)
                    .expect("request"),
                &stable()
            ),
            snapshot_id(
                &BarrierRequest::new(0, vec!["a".to_string(), "bc".to_string()], true)
                    .expect("request"),
                &stable()
            )
        );
    }
}
