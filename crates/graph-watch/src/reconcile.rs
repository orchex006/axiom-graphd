//! Bounded hint reconciliation with loss recovery (task V2-014, requirement R20).
//!
//! A native filesystem backend is a *hint* source, never the truth
//! (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 9). The modules this
//! one composes each own a single mechanism - [`crate::native`] delivers events,
//! [`crate::normalize`] turns them into actions, [`crate::ignore`] and
//! [`crate::input_policy`] refuse paths that must never be read, and
//! [`crate::recovery`] persists the sticky "a complete scan is required" flag.
//! None of them decides what to do with one observed batch.
//!
//! [`Reconciler`] is that decision. For every batch it answers one of three
//! things:
//!
//! * [`ReconcileOutcome::Apply`] - the hint stream is trustworthy, act on these
//!   normalized hints;
//! * [`ReconcileOutcome::Bounded`] - do not act yet; confirm this bounded set of
//!   paths with an inventory scan or a polling snapshot;
//! * [`ReconcileOutcome::FullScan`] - a complete inventory is required, because
//!   information was definitely lost (overflow, a rename whose origin was never
//!   paired, a save-all burst larger than one bounded batch) or a scan is still
//!   outstanding from an earlier batch.
//!
//! Two properties are load-bearing and are tested directly:
//!
//! * **Nothing is silently dropped.** A path excluded by the ignore policy is
//!   never replayed (the graph engine's own output must not requeue itself), but
//!   a path withheld by the input policy or absent from the known inventory
//!   produces a bounded rescan request instead of a silent no-op.
//! * **A missing native backend degrades to polling, not to failure.** Under
//!   [`BackendPolicy::PreferNative`] a target without native events binds the
//!   polling backend with the diagnostic reason preserved.
//!
//! The platform-dependent inputs are injected through [`ReconcileProbe`], so the
//! decision logic is exercised for real on any host (CP-02) while the native
//! Windows/macOS legs stay explicitly unverified.

use crate::ignore::{IgnoreDecision, IgnorePolicy};
use crate::input_policy::{InputDecision, InputPolicy, InputSkip, WatchedEntry};
use crate::inventory::KnownInventory;
use crate::native::{NativeSupport, MAX_DRAIN_HINTS};
use crate::normalize::{normalize, FileAction, NormalizedHint, RawHint, MAX_HINTS_PER_BATCH};
use crate::poll::{select_backend, BackendDecision, BackendPolicy, PollOutcome};
use crate::recovery::{BackendEvent, FullScanReason, RecoveryDecision, RecoveryState};
use graph_core::error::AxiomError;
use std::collections::BTreeSet;

/// Largest hint batch the reconciler applies without rescanning.
///
/// Re-exported from [`crate::normalize::MAX_HINTS_PER_BATCH`] so a caller has one
/// bound to reason about: a batch at or below this size may still be applied as a
/// delta, a larger one is a save-all burst and requires a scan.
pub const MAX_RECONCILE_HINTS: usize = MAX_HINTS_PER_BATCH;

/// Why the reconciler asked for a rescan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReconcileTrigger {
    /// The recovery state already required a scan, or the backend reported an
    /// explicit loss event.
    BackendEvent,
    /// A rename was delivered whose origin side was never paired with a
    /// destination, so the backend did not report everything.
    UnpairedRename,
    /// One flush carried more hints than a single bounded batch, which is what a
    /// save-all looks like from the watcher.
    SaveAllBurst,
    /// An upsert arrived for a path the known inventory does not contain.
    UntrackedInput,
    /// A rename changed only the case of a path, which is one file on a
    /// case-insensitive filesystem.
    CaseOnlyRename,
    /// A hinted path is a symlink that escapes the project root or cannot be
    /// resolved, so it must be re-observed rather than followed.
    SymlinkBoundary,
    /// The polling backend produced its first snapshot; a baseline cannot report
    /// a change honestly, so a complete inventory establishes it.
    FirstPoll,
}

impl ReconcileTrigger {
    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BackendEvent => "backend_event",
            Self::UnpairedRename => "unpaired_rename",
            Self::SaveAllBurst => "save_all_burst",
            Self::UntrackedInput => "untracked_input",
            Self::CaseOnlyRename => "case_only_rename",
            Self::SymlinkBoundary => "symlink_boundary",
            Self::FirstPoll => "first_poll",
        }
    }
}

/// A complete-inventory request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRequest {
    reason: FullScanReason,
    trigger: ReconcileTrigger,
    widened_by: Vec<String>,
}

impl ScanRequest {
    /// The sticky reason persisted in the recovery state.
    #[must_use]
    pub const fn reason(&self) -> FullScanReason {
        self.reason
    }

    /// What this batch observed that forced the scan.
    #[must_use]
    pub const fn trigger(&self) -> ReconcileTrigger {
        self.trigger
    }

    /// Paths the scan must include beyond whatever inventory already covers.
    #[must_use]
    pub fn widened_by(&self) -> &[String] {
        &self.widened_by
    }

    /// Whether the scan is widened to specific paths.
    #[must_use]
    pub fn is_widened(&self) -> bool {
        !self.widened_by.is_empty()
    }
}

/// A bounded, path-scoped rescan of paths that cannot be applied as a delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedRescan {
    paths: Vec<String>,
    trigger: ReconcileTrigger,
}

impl BoundedRescan {
    /// Paths to confirm with an inventory scan or a polling snapshot, in the
    /// order they were observed.
    #[must_use]
    pub fn paths(&self) -> &[String] {
        &self.paths
    }

    /// What this batch observed that forced the rescan.
    #[must_use]
    pub const fn trigger(&self) -> ReconcileTrigger {
        self.trigger
    }
}

/// What the caller may do with one observed batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// Act on exactly these normalized hints.
    Apply(Vec<NormalizedHint>),
    /// Confirm these paths before acting.
    Bounded(BoundedRescan),
    /// Run a complete inventory before acting.
    FullScan(ScanRequest),
}

impl ReconcileOutcome {
    /// Whether the batch may be applied directly.
    #[must_use]
    pub const fn is_apply(&self) -> bool {
        matches!(self, Self::Apply(_))
    }

    /// Whether the caller must scan before acting.
    #[must_use]
    pub const fn requires_scan(&self) -> bool {
        !self.is_apply()
    }

    /// The applicable hints, empty when a scan is required first.
    #[must_use]
    pub fn applied(&self) -> &[NormalizedHint] {
        match self {
            Self::Apply(hints) => hints,
            Self::Bounded(_) | Self::FullScan(_) => &[],
        }
    }

    /// The bounded rescan request, when the outcome is [`Self::Bounded`].
    #[must_use]
    pub const fn bounded(&self) -> Option<&BoundedRescan> {
        match self {
            Self::Bounded(rescan) => Some(rescan),
            Self::Apply(_) | Self::FullScan(_) => None,
        }
    }

    /// The complete-scan request, when the outcome is [`Self::FullScan`].
    #[must_use]
    pub const fn scan(&self) -> Option<&ScanRequest> {
        match self {
            Self::FullScan(request) => Some(request),
            Self::Apply(_) | Self::Bounded(_) => None,
        }
    }
}

/// Filesystem facts the reconciler cannot derive from a hint alone.
pub trait ReconcileProbe {
    /// How the target filesystem classifies one hinted path.
    ///
    /// A hint carries a path, not a file kind: whether that path is a regular
    /// file or a symlink is a filesystem fact, so it is injected here instead of
    /// being guessed.
    fn classify_entry(&self, path: &str) -> WatchedEntry;

    /// Native event support on this target.
    fn native_support(&self) -> NativeSupport;
}

/// A probe that treats every hinted path as a regular file.
///
/// This is the honest default when the caller has no native observation: a
/// regular file is the only kind a hint can be assumed to describe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileProbe {
    support: NativeSupport,
}

impl FileProbe {
    /// A probe reporting `support` as the target's native backend capability.
    #[must_use]
    pub const fn new(support: NativeSupport) -> Self {
        Self { support }
    }

    /// A probe for a target that offers native recursive events.
    #[must_use]
    pub const fn supported() -> Self {
        Self::new(NativeSupport::Supported)
    }

    /// A probe for a target that offers no native recursive backend.
    #[must_use]
    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self::new(NativeSupport::Unsupported {
            reason: reason.into(),
        })
    }
}

impl Default for FileProbe {
    fn default() -> Self {
        Self::supported()
    }
}

impl ReconcileProbe for FileProbe {
    fn classify_entry(&self, _path: &str) -> WatchedEntry {
        WatchedEntry::File
    }

    fn native_support(&self) -> NativeSupport {
        self.support.clone()
    }
}

/// Marker for the reconciler's accounting of one batch.
///
/// Every hint that is not applied is counted, so "the batch produced no work" is
/// always explainable rather than silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReconcileAccounting {
    excluded: usize,
    withheld: usize,
    dropped: usize,
}

impl ReconcileAccounting {
    /// Hints excluded by the ignore policy (generated output, build output).
    #[must_use]
    pub const fn excluded(&self) -> usize {
        self.excluded
    }

    /// Hints withheld by the input policy (secrets, symlink boundaries).
    #[must_use]
    pub const fn withheld(&self) -> usize {
        self.withheld
    }

    /// Hints the normalizer refused to model.
    #[must_use]
    pub const fn dropped(&self) -> usize {
        self.dropped
    }

    /// Total hints accounted for.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.excluded + self.withheld + self.dropped
    }
}

/// Bounded reconciliation of native hints with polling recovery.
#[derive(Debug, Clone)]
pub struct Reconciler {
    recovery: RecoveryState,
    ignore: IgnorePolicy,
    input: InputPolicy,
    backend: Option<BackendDecision>,
    accounting: ReconcileAccounting,
}

impl Reconciler {
    /// A reconciler for a project with the given exclusion and input policies.
    #[must_use]
    pub fn new(ignore: IgnorePolicy, input: InputPolicy) -> Self {
        Self {
            recovery: RecoveryState::new(),
            ignore,
            input,
            backend: None,
            accounting: ReconcileAccounting::default(),
        }
    }

    /// A reconciler for `project_root` under the default policies.
    ///
    /// The default graph-output root is [`crate::ignore::DEFAULT_GRAPH_OUTPUT_ROOT`]
    /// and symlinks are followed only when they stay inside the root.
    #[must_use]
    pub fn with_defaults(project_root: impl Into<String>) -> Self {
        let root = project_root.into();
        Self::new(IgnorePolicy::default(), InputPolicy::new(root))
    }

    /// The sticky recovery state.
    #[must_use]
    pub const fn recovery(&self) -> &RecoveryState {
        &self.recovery
    }

    /// Accounting for the most recent batch.
    #[must_use]
    pub const fn accounting(&self) -> ReconcileAccounting {
        self.accounting
    }

    /// The bound backend, when one was selected.
    #[must_use]
    pub const fn backend(&self) -> Option<&BackendDecision> {
        self.backend.as_ref()
    }

    /// Whether the bound backend delivers native events.
    ///
    /// `false` means observation is driven by polling, which is a working
    /// fallback rather than a failure.
    #[must_use]
    pub fn uses_native_events(&self) -> bool {
        self.backend
            .as_ref()
            .is_some_and(BackendDecision::is_native)
    }

    /// Confirm that a complete inventory finished successfully.
    pub fn acknowledge_scan(&mut self) {
        self.recovery.acknowledge_scan();
    }

    /// Persist the full-scan requirement without losing a stronger earlier reason.
    pub fn require_full_scan(&mut self, reason: FullScanReason) -> FullScanReason {
        self.recovery.require_full_scan(reason)
    }

    /// Select and bind the observation backend for this target.
    ///
    /// # Errors
    /// [`ErrorCode::NotReady`] when the policy is [`BackendPolicy::RequireNative`]
    /// and the target offers no native backend. Every other combination binds a
    /// backend: an unavailable native backend under
    /// [`BackendPolicy::PreferNative`] binds polling and preserves the reason.
    pub fn bind_backend(
        &mut self,
        policy: BackendPolicy,
        probe: &dyn ReconcileProbe,
    ) -> Result<BackendDecision, AxiomError> {
        let decision = select_backend(policy, &probe.native_support())?;
        self.backend = Some(decision.clone());
        Ok(decision)
    }
}

/// Whether one flush is small enough to be applied as a delta.
///
/// A larger flush is what a save-all looks like from the watcher: the backend
/// delivered more than one bounded batch, so the delta cannot be trusted to be
/// complete and a scan is required instead.
#[must_use]
pub fn is_bounded_batch(hint_count: usize) -> bool {
    hint_count <= MAX_RECONCILE_HINTS && hint_count <= MAX_DRAIN_HINTS
}

/// Whether an input-policy skip is a symlink boundary that must be re-observed.
///
/// A secret is deliberately never read; a symlink boundary is a path whose
/// identity could not be established, so the honest response is to re-observe it
/// rather than to treat the hint as fully handled.
#[must_use]
pub fn is_symlink_boundary(reason: &InputSkip) -> bool {
    matches!(
        reason,
        InputSkip::SymlinkEscape { .. }
            | InputSkip::SymlinkUnresolved
            | InputSkip::SymlinkDisallowed
    )
}

impl Reconciler {
    /// Persist a rescan requirement and describe it for the caller.
    fn request_scan(
        &mut self,
        trigger: ReconcileTrigger,
        reason: FullScanReason,
        widened_by: Vec<String>,
    ) -> ReconcileOutcome {
        let persisted = self.recovery.require_full_scan(reason);
        ReconcileOutcome::FullScan(ScanRequest {
            reason: persisted,
            trigger,
            widened_by,
        })
    }

    /// Decide what one observed batch may do.
    ///
    /// `hints` is the raw flush the backend delivered, `overflowed` reports that
    /// the backend itself dropped events, and `known` is the inventory the graph
    /// currently believes. A hint is a hint: a path the known inventory does not
    /// contain, a rename whose origin was never paired, or a symlink the input
    /// policy refused all produce a rescan request rather than a silent no-op.
    ///
    /// # Errors
    /// Propagates [`crate::normalize`] path validation failures; an invalid path
    /// is refused rather than repaired.
    pub fn reconcile(
        &mut self,
        hints: &[RawHint],
        overflowed: bool,
        known: &KnownInventory,
        probe: &dyn ReconcileProbe,
    ) -> Result<ReconcileOutcome, AxiomError> {
        self.accounting = ReconcileAccounting::default();

        if overflowed {
            return Ok(self.request_scan(
                ReconcileTrigger::BackendEvent,
                FullScanReason::Overflow,
                Vec::new(),
            ));
        }
        if !is_bounded_batch(hints.len()) {
            return Ok(self.request_scan(
                ReconcileTrigger::SaveAllBurst,
                FullScanReason::BufferOverflow,
                Vec::new(),
            ));
        }
        if let RecoveryDecision::FullScan(reason) =
            self.recovery.absorb(BackendEvent::Hints(hints.to_vec()))?
        {
            return Ok(self.request_scan(ReconcileTrigger::BackendEvent, reason, Vec::new()));
        }

        let normalized = normalize(hints)?;
        self.accounting.dropped = normalized.dropped();

        if !normalized.unmatched_renames_from().is_empty() {
            let widened_by = normalized.unmatched_renames_from().to_vec();
            return Ok(self.request_scan(
                ReconcileTrigger::UnpairedRename,
                FullScanReason::Overflow,
                widened_by,
            ));
        }

        let mut apply: Vec<NormalizedHint> = Vec::new();
        let mut untracked: Vec<String> = Vec::new();
        let mut boundary: Vec<String> = Vec::new();
        let mut case_only: Vec<String> = Vec::new();

        for hint in normalized.hints() {
            let path = hint.path();
            if let IgnoreDecision::Ignored { .. } = self.ignore.classify(path)? {
                // The graph engine's own output must never be replayed.
                self.accounting.excluded += 1;
                continue;
            }
            let entry = probe.classify_entry(path);
            if let InputDecision::Skipped(reason) = self.input.decide(path, &entry)? {
                self.accounting.withheld += 1;
                if is_symlink_boundary(&reason) {
                    boundary.push(path.to_string());
                }
                continue;
            }
            if hint.is_case_only_rename() {
                case_only.push(path.to_string());
            }
            if hint.action() == FileAction::Upsert && known.hash_of(path).is_none() {
                untracked.push(path.to_string());
            }
            apply.push(hint.clone());
        }

        if apply.is_empty() {
            return Ok(ReconcileOutcome::Apply(Vec::new()));
        }

        // Identity ambiguity is the most dangerous condition, then a path whose
        // identity could not be established, then an ordinary new path.
        let mut trigger: Option<ReconcileTrigger> = None;
        let mut paths: Vec<String> = Vec::new();
        for (candidate, observed) in [
            (ReconcileTrigger::CaseOnlyRename, case_only),
            (ReconcileTrigger::SymlinkBoundary, boundary),
            (ReconcileTrigger::UntrackedInput, untracked),
        ] {
            if observed.is_empty() {
                continue;
            }
            if trigger.is_none() {
                trigger = Some(candidate);
            }
            paths.extend(observed);
        }
        if let Some(trigger) = trigger {
            let mut seen: BTreeSet<String> = BTreeSet::new();
            paths.retain(|path| seen.insert(path.clone()));
            return Ok(ReconcileOutcome::Bounded(BoundedRescan { paths, trigger }));
        }

        Ok(ReconcileOutcome::Apply(apply))
    }

    /// Decide what one poll of the polling backend may do.
    ///
    /// A first snapshot cannot report a change honestly: the baseline it
    /// establishes is not a delta, so a complete inventory supplies the truth
    /// instead.
    ///
    /// # Errors
    /// Propagates [`Self::reconcile`] validation failures.
    pub fn reconcile_poll(
        &mut self,
        outcome: &PollOutcome,
        known: &KnownInventory,
        probe: &dyn ReconcileProbe,
    ) -> Result<ReconcileOutcome, AxiomError> {
        if outcome.is_first_scan() {
            return Ok(self.request_scan(
                ReconcileTrigger::FirstPoll,
                FullScanReason::BackendSwitch,
                Vec::new(),
            ));
        }
        self.reconcile(outcome.hints(), false, known, probe)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        is_bounded_batch, is_symlink_boundary, FileProbe, ReconcileProbe, ReconcileTrigger,
        Reconciler, MAX_RECONCILE_HINTS,
    };
    use crate::input_policy::{InputSkip, WatchedEntry};
    use crate::inventory::KnownInventory;
    use crate::native::NativeSupport;
    use crate::normalize::{FileAction, RawHint, RawKind};
    use crate::poll::{BackendKind, BackendPolicy, FileStamp, PollingWatcher, SnapshotSource};
    use crate::recovery::FullScanReason;
    use graph_core::error::{AxiomError, ErrorCode};
    use std::path::Path;

    const ROOT: &str = "D:/repo/Project";

    fn known(pairs: &[(&str, &str)]) -> KnownInventory {
        KnownInventory::from_pairs(pairs.iter().map(|(path, hash)| (*path, *hash)))
    }

    #[derive(Debug)]
    struct BoundaryProbe;

    impl ReconcileProbe for BoundaryProbe {
        fn classify_entry(&self, path: &str) -> WatchedEntry {
            match path {
                "src/escape.cs" => WatchedEntry::ResolvedSymlink {
                    target: "D:/other/secret.cs".to_string(),
                },
                "src/dangling.cs" => WatchedEntry::UnresolvedSymlink,
                _ => WatchedEntry::File,
            }
        }

        fn native_support(&self) -> NativeSupport {
            NativeSupport::Supported
        }
    }

    #[derive(Debug)]
    struct CannedSource {
        snapshot: Vec<(String, FileStamp)>,
    }

    impl SnapshotSource for CannedSource {
        fn snapshot(&self, _root: &Path) -> Result<Vec<(String, FileStamp)>, AxiomError> {
            Ok(self.snapshot.clone())
        }
    }

    #[test]
    fn an_overflow_and_an_unavailable_backend_both_recover_instead_of_failing() {
        let mut reconciler = Reconciler::with_defaults(ROOT);

        let decision = reconciler
            .bind_backend(
                BackendPolicy::PreferNative,
                &FileProbe::unsupported("no native recursive backend"),
            )
            .expect("an unavailable native backend falls back to polling");
        assert_eq!(decision.kind(), BackendKind::Polling);
        assert!(!reconciler.uses_native_events());
        assert_eq!(
            reconciler.backend().expect("bound").reason(),
            Some("no native recursive backend")
        );

        let outcome = reconciler
            .reconcile(
                &[RawHint::new("src/App.cs", RawKind::Modified)],
                true,
                &known(&[]),
                &FileProbe::supported(),
            )
            .expect("an overflow is a decision, not a failure");
        let scan = outcome.scan().expect("a complete scan is required");
        assert_eq!(scan.reason(), FullScanReason::Overflow);
        assert_eq!(scan.trigger(), ReconcileTrigger::BackendEvent);
        assert!(outcome.applied().is_empty());
        assert!(reconciler.recovery().requires_full_scan());

        reconciler.acknowledge_scan();
        assert!(!reconciler.recovery().requires_full_scan());

        let forced = reconciler
            .bind_backend(BackendPolicy::ForcePolling, &FileProbe::supported())
            .expect("polling was forced");
        assert_eq!(forced.kind(), BackendKind::Polling);

        let error = reconciler
            .bind_backend(
                BackendPolicy::RequireNative,
                &FileProbe::unsupported("no native"),
            )
            .expect_err("a hard native requirement is refused");
        assert_eq!(error.code(), ErrorCode::NotReady);
    }

    #[test]
    fn a_save_all_burst_beyond_one_bounded_batch_requires_a_complete_scan() {
        assert!(is_bounded_batch(MAX_RECONCILE_HINTS));
        assert!(!is_bounded_batch(MAX_RECONCILE_HINTS + 1));

        let mut reconciler = Reconciler::with_defaults(ROOT);
        let burst: Vec<RawHint> = (0..=MAX_RECONCILE_HINTS)
            .map(|index| RawHint::new(format!("src/file{index}.cs"), RawKind::Modified))
            .collect();
        let outcome = reconciler
            .reconcile(&burst, false, &known(&[]), &FileProbe::supported())
            .expect("a burst is refused with a scan, not an error");
        let scan = outcome.scan().expect("save-all requires a scan");
        assert_eq!(scan.trigger(), ReconcileTrigger::SaveAllBurst);
        assert_eq!(scan.reason(), FullScanReason::BufferOverflow);
        assert!(!scan.is_widened());
    }

    #[test]
    fn an_unpaired_rename_widens_the_scan_instead_of_losing_the_origin() {
        let mut reconciler = Reconciler::with_defaults(ROOT);
        let outcome = reconciler
            .reconcile(
                &[RawHint::new("src/old.cs", RawKind::RenamedFrom)],
                false,
                &known(&[("src/old.cs", "hash")]),
                &FileProbe::supported(),
            )
            .expect("decision");
        let scan = outcome.scan().expect("an unpaired rename requires a scan");
        assert_eq!(scan.trigger(), ReconcileTrigger::UnpairedRename);
        assert!(scan.is_widened());
        assert_eq!(scan.widened_by().len(), 1);
        assert_eq!(scan.widened_by()[0], "src/old.cs");
    }

    #[test]
    fn an_untracked_upsert_is_confirmed_by_a_bounded_rescan_while_output_is_never_replayed() {
        let mut reconciler = Reconciler::with_defaults(ROOT);
        let hints = vec![
            RawHint::new("live/manifest.json", RawKind::Modified),
            RawHint::new("src/New.cs", RawKind::Created),
            RawHint::new("src/App.cs", RawKind::Modified),
        ];
        let outcome = reconciler
            .reconcile(
                &hints,
                false,
                &known(&[("src/App.cs", "aaa")]),
                &FileProbe::supported(),
            )
            .expect("decision");
        let rescan = outcome.bounded().expect("an untracked path is confirmed");
        assert_eq!(rescan.trigger(), ReconcileTrigger::UntrackedInput);
        assert_eq!(rescan.paths().len(), 1);
        assert_eq!(rescan.paths()[0], "src/New.cs");
        assert_eq!(reconciler.accounting().excluded(), 1);
        assert!(outcome.requires_scan());

        let outcome = reconciler
            .reconcile(
                &hints,
                false,
                &known(&[("src/App.cs", "aaa"), ("src/New.cs", "bbb")]),
                &FileProbe::supported(),
            )
            .expect("decision");
        assert!(outcome.is_apply());
        assert_eq!(outcome.applied().len(), 2);
        assert_eq!(reconciler.accounting().excluded(), 1);
    }

    #[test]
    fn a_symlink_boundary_is_re_observed_rather_than_followed() {
        let mut reconciler = Reconciler::with_defaults(ROOT);
        let hints = vec![
            RawHint::new("src/escape.cs", RawKind::Modified),
            RawHint::new("src/dangling.cs", RawKind::Modified),
            RawHint::new("src/App.cs", RawKind::Modified),
        ];
        let outcome = reconciler
            .reconcile(
                &hints,
                false,
                &known(&[("src/App.cs", "aaa")]),
                &BoundaryProbe,
            )
            .expect("decision");
        let rescan = outcome.bounded().expect("a boundary rescan is required");
        assert_eq!(rescan.trigger(), ReconcileTrigger::SymlinkBoundary);
        assert_eq!(rescan.paths().len(), 2);
        assert_eq!(reconciler.accounting().withheld(), 2);
        assert!(is_symlink_boundary(&InputSkip::SymlinkUnresolved));
        assert!(!is_symlink_boundary(&InputSkip::Secret {
            matched: ".env".to_string()
        }));
    }

    #[test]
    fn a_withheld_secret_does_not_force_a_rescan_and_known_tombstones_still_apply() {
        let mut reconciler = Reconciler::with_defaults(ROOT);
        let hints = vec![
            RawHint::new(".env", RawKind::Modified),
            RawHint::new("src/Gone.cs", RawKind::Removed),
        ];
        let outcome = reconciler
            .reconcile(
                &hints,
                false,
                &known(&[("src/Gone.cs", "ccc")]),
                &FileProbe::supported(),
            )
            .expect("decision");
        assert!(outcome.is_apply());
        assert_eq!(outcome.applied().len(), 1);
        assert_eq!(outcome.applied()[0].action(), FileAction::Remove);
        assert_eq!(outcome.applied()[0].path(), "src/Gone.cs");
        assert_eq!(reconciler.accounting().withheld(), 1);
    }

    #[test]
    fn a_persisted_scan_requirement_outlives_the_batch_that_raised_it() {
        let mut reconciler = Reconciler::with_defaults(ROOT);
        reconciler
            .reconcile(&[], true, &known(&[]), &FileProbe::supported())
            .expect("overflow");
        assert!(reconciler.recovery().requires_full_scan());

        let gated = reconciler
            .reconcile(
                &[RawHint::new("src/App.cs", RawKind::Modified)],
                false,
                &known(&[]),
                &FileProbe::supported(),
            )
            .expect("gated batch");
        let scan = gated.scan().expect("the requirement is still sticky");
        assert_eq!(scan.reason(), FullScanReason::Overflow);
        assert!(gated.applied().is_empty());

        assert_eq!(
            reconciler.require_full_scan(FullScanReason::BufferOverflow),
            FullScanReason::Overflow,
            "a weaker later reason must not replace the persisted one"
        );

        reconciler.acknowledge_scan();
        let cleared = reconciler
            .reconcile(
                &[RawHint::new("src/App.cs", RawKind::Modified)],
                false,
                &known(&[("src/App.cs", "aaa")]),
                &FileProbe::supported(),
            )
            .expect("cleared");
        assert!(cleared.is_apply());
        assert_eq!(cleared.applied().len(), 1);
    }

    #[test]
    fn a_first_poll_establishes_a_baseline_instead_of_reporting_changes() {
        let mut reconciler = Reconciler::with_defaults(ROOT);
        let source = CannedSource {
            snapshot: vec![("src/App.cs".to_string(), FileStamp::new(10, 1))],
        };
        let mut watcher = PollingWatcher::new();
        let first = watcher.poll(&source, Path::new(ROOT)).expect("poll");
        assert!(first.is_first_scan());
        let outcome = reconciler
            .reconcile_poll(&first, &known(&[]), &FileProbe::supported())
            .expect("decision");
        let scan = outcome.scan().expect("a baseline needs an inventory");
        assert_eq!(scan.trigger(), ReconcileTrigger::FirstPoll);
        assert_eq!(scan.reason(), FullScanReason::BackendSwitch);
    }

    #[test]
    fn a_case_only_rename_is_re_observed_on_a_case_insensitive_host() {
        let mut reconciler = Reconciler::with_defaults(ROOT);
        let hints = vec![
            RawHint::new("src/App.cs", RawKind::RenamedFrom),
            RawHint::new("src/app.cs", RawKind::RenamedTo),
        ];
        let outcome = reconciler
            .reconcile(
                &hints,
                false,
                &known(&[("src/App.cs", "aaa")]),
                &FileProbe::supported(),
            )
            .expect("decision");
        if cfg!(windows) {
            let rescan = outcome.bounded().expect("a case-only rename is one file");
            assert_eq!(rescan.trigger(), ReconcileTrigger::CaseOnlyRename);
        } else {
            assert_ne!(
                outcome.bounded().map(|rescan| rescan.trigger()),
                Some(ReconcileTrigger::CaseOnlyRename),
                "a case-sensitive host must not report a case-only rename"
            );
        }
    }

    #[test]
    fn an_invalid_hint_path_is_refused_rather_than_repaired() {
        let mut reconciler = Reconciler::with_defaults(ROOT);
        let error = reconciler
            .reconcile(
                &[RawHint::new("C:/outside/App.cs", RawKind::Modified)],
                false,
                &known(&[]),
                &FileProbe::supported(),
            )
            .expect_err("an absolute path is refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
    }
}
