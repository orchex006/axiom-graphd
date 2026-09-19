//! Bounded service drain before activation (task E-040).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 6 places "pause claim new
//! jobs" and "bounded drain requests" in the middle of the install/update
//! transaction, after preflight and before the consistent DB backup. This
//! module is that slice, and it fixes two rules the specification repeats:
//!
//! * new work pauses first, and in-flight readers/workers get a *bounded* wait,
//!   so an update can never block forever on a busy reader;
//! * a forced kill is never the default update path. The default policy is
//!   [`DrainPolicy::default`], where `allow_forced_kill` is `false`, and
//!   [`drain`] never kills at all: a wait that runs out of budget returns
//!   [`DrainOutcome::TimedOut`] with new work still paused, and leaves the
//!   decision to the caller. Killing is a separate, explicitly permitted call.
//!
//! Nothing here opens a socket or spawns a process. The service under drain is
//! reached through the injected [`DrainControl`] trait and time comes from the
//! injected [`DrainClock`], so the decision is a pure function of its inputs and
//! a test can pin every boundary without waiting in real time.

use graph_core::error::{AxiomError, ErrorCode};

/// Default bound, in seconds, on how long a drain waits for in-flight work.
pub const DEFAULT_DRAIN_SECONDS: u64 = 30;

/// Smallest accepted drain bound. A caller may explicitly allow a zero wait, so
/// the lower bound is zero rather than one.
pub const MIN_DRAIN_SECONDS: u64 = 0;

/// Largest accepted drain bound.
pub const MAX_DRAIN_SECONDS: u64 = 300;

/// Every drain phase, in the order one drain reports them.
pub const DRAIN_PHASES: [DrainPhase; 3] = [
    DrainPhase::PauseNewWork,
    DrainPhase::DrainInFlight,
    DrainPhase::Resume,
];

/// Every drain outcome, for contract tests.
pub const DRAIN_OUTCOMES: [&str; 3] = ["drained", "timed_out", "force_killed"];

/// One ordered phase of a drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DrainPhase {
    /// New work is refused; in-flight work is untouched.
    PauseNewWork,
    /// In-flight readers/workers are waited on, within the policy bound.
    DrainInFlight,
    /// New work is accepted again after a clean drain.
    Resume,
}

impl DrainPhase {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PauseNewWork => "pause_new_work",
            Self::DrainInFlight => "drain_in_flight",
            Self::Resume => "resume",
        }
    }

    /// Every accepted value, in order.
    #[must_use]
    pub const fn all() -> &'static [DrainPhase] {
        &DRAIN_PHASES
    }
}

/// How one drain finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    /// In-flight work reached zero inside the bound; new work resumed.
    Drained,
    /// The bound was reached with work still in flight. New work stays paused
    /// and no process was killed.
    TimedOut {
        /// In-flight work observed at the last poll.
        remaining: u64,
    },
    /// An explicitly permitted forced kill was performed.
    ForceKilled,
}

impl DrainOutcome {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Drained => "drained",
            Self::TimedOut { .. } => "timed_out",
            Self::ForceKilled => "force_killed",
        }
    }

    /// Whether this outcome killed a process. Only [`Self::ForceKilled`] does.
    #[must_use]
    pub const fn killed(self) -> bool {
        matches!(self, Self::ForceKilled)
    }
}

/// The drain budget and whether a forced kill is permitted at all.
///
/// `allow_forced_kill` defaults to `false` because the specification makes a
/// forced kill an opt-in, never the default update path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainPolicy {
    /// Longest wait, in seconds, for in-flight work.
    pub max_seconds: u64,
    /// Whether [`force_kill`] is permitted for this policy.
    pub allow_forced_kill: bool,
}

impl Default for DrainPolicy {
    fn default() -> Self {
        Self {
            max_seconds: DEFAULT_DRAIN_SECONDS,
            allow_forced_kill: false,
        }
    }
}

impl DrainPolicy {
    /// A policy that permits a forced kill. The only way to obtain one.
    #[must_use]
    pub const fn with_forced_kill(max_seconds: u64) -> Self {
        Self {
            max_seconds,
            allow_forced_kill: true,
        }
    }

    /// Refuse an unusable bound before any work is paused.
    ///
    /// # Errors
    ///
    /// Fails closed with `rule=invalid_drain_seconds` when the bound is above
    /// [`MAX_DRAIN_SECONDS`].
    pub fn validate(&self) -> Result<(), AxiomError> {
        if self.max_seconds > MAX_DRAIN_SECONDS {
            return Err(refuse(
                "invalid_drain_seconds",
                &format!("max_seconds={};limit={MAX_DRAIN_SECONDS}", self.max_seconds),
            ));
        }
        Ok(())
    }
}

/// The service under drain, seen as the four operations a drain uses.
///
/// Production code implements this over the real service adapters; tests
/// implement it over a script, so no process or socket is needed here.
pub trait DrainControl {
    /// Refuse new work for `service`. Idempotent.
    ///
    /// # Errors
    ///
    /// Fails when the service cannot pause new work.
    fn pause_new_work(&mut self, service: &str) -> Result<(), AxiomError>;

    /// In-flight readers/workers for `service` right now.
    fn in_flight(&mut self, service: &str) -> u64;

    /// Accept new work for `service` again after a clean drain.
    ///
    /// # Errors
    ///
    /// Fails when the service cannot resume.
    fn resume(&mut self, service: &str) -> Result<(), AxiomError>;

    /// Kill `service`. Only reachable through [`force_kill`].
    ///
    /// # Errors
    ///
    /// Fails when the service cannot be killed.
    fn force_kill(&mut self, service: &str) -> Result<(), AxiomError>;
}

/// The clock a drain reads, injected so the bound is testable.
pub trait DrainClock {
    /// Seconds since the Unix epoch.
    fn now_epoch(&self) -> u64;
}

/// What one drain did, in the order it did it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainReport {
    /// Service that was drained.
    pub service: String,
    /// How the drain finished.
    pub outcome: DrainOutcome,
    /// Seconds the drain waited, measured with the injected clock.
    pub waited_seconds: u64,
    /// How many in-flight polls were made.
    pub polls: u64,
    /// Phases actually entered.
    pub phases: Vec<DrainPhase>,
    /// Whether new work was still refused when the drain returned.
    pub new_work_paused: bool,
    /// Whether a process was killed. Always `false` for [`drain`].
    pub forced_kill: bool,
}

/// Pause new work for `service`, wait a bounded time for in-flight work, and
/// resume only after a clean drain.
///
/// # Errors
///
/// Fails closed with a named `rule` when the policy bound is out of range
/// (`invalid_drain_seconds`), the service name is blank (`invalid_service`), or
/// the service cannot pause new work.
pub fn drain<C: DrainControl>(
    control: &mut C,
    service: &str,
    policy: &DrainPolicy,
    clock: &dyn DrainClock,
) -> Result<DrainReport, AxiomError> {
    policy.validate()?;
    require_service_name(service)?;

    let started = clock.now_epoch();
    let mut phases = vec![DrainPhase::PauseNewWork];
    control.pause_new_work(service)?;
    phases.push(DrainPhase::DrainInFlight);

    let mut waited_seconds = 0_u64;
    let mut polls = 0_u64;
    // The poll cap is the budget itself, so a clock that does not advance can
    // never turn a bounded wait into an unbounded one.
    let poll_limit = policy.max_seconds;
    let outcome = loop {
        let remaining = control.in_flight(service);
        if remaining == 0 {
            break DrainOutcome::Drained;
        }
        polls += 1;
        waited_seconds = clock.now_epoch().saturating_sub(started);
        if waited_seconds >= policy.max_seconds || polls > poll_limit {
            break DrainOutcome::TimedOut { remaining };
        }
    };

    if outcome == DrainOutcome::Drained {
        control.resume(service)?;
        phases.push(DrainPhase::Resume);
    }
    let new_work_paused = outcome != DrainOutcome::Drained;
    Ok(DrainReport {
        service: service.to_string(),
        outcome,
        waited_seconds,
        polls,
        phases,
        new_work_paused,
        forced_kill: false,
    })
}

/// Kill `service`, permitted only by a policy that explicitly allows it.
///
/// # Errors
///
/// Fails closed with `rule=forced_kill_refused` when `policy.allow_forced_kill`
/// is `false`, which is the default.
pub fn force_kill<C: DrainControl>(
    control: &mut C,
    service: &str,
    policy: &DrainPolicy,
) -> Result<DrainReport, AxiomError> {
    policy.validate()?;
    require_service_name(service)?;
    if !policy.allow_forced_kill {
        return Err(refuse(
            "forced_kill_refused",
            &format!("service={service};allow_forced_kill=false"),
        ));
    }
    control.force_kill(service)?;
    Ok(DrainReport {
        service: service.to_string(),
        outcome: DrainOutcome::ForceKilled,
        waited_seconds: 0,
        polls: 0,
        phases: vec![DrainPhase::PauseNewWork, DrainPhase::DrainInFlight],
        new_work_paused: true,
        forced_kill: true,
    })
}

/// Refuse a blank service name before any phase runs.
fn require_service_name(service: &str) -> Result<(), AxiomError> {
    if service.trim().is_empty() {
        return Err(refuse("invalid_service", "service=<blank>"));
    }
    Ok(())
}

/// One policy refusal, with the rule in a stable detail key.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the drain policy refuses this request",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;

    use super::{
        drain, force_kill, DrainClock, DrainControl, DrainOutcome, DrainPhase, DrainPolicy,
        MAX_DRAIN_SECONDS,
    };

    fn rule_of(error: &graph_core::error::AxiomError) -> String {
        error.details().get("rule").cloned().unwrap_or_default()
    }

    /// A clock that returns `start`, then advances by `step` on every read.
    struct StepClock {
        now: Cell<u64>,
        step: u64,
    }

    impl StepClock {
        fn new(start: u64, step: u64) -> Self {
            Self {
                now: Cell::new(start),
                step,
            }
        }
    }

    impl DrainClock for StepClock {
        fn now_epoch(&self) -> u64 {
            let value = self.now.get();
            self.now.set(value + self.step);
            value
        }
    }

    /// The scripted in-flight counts and the phases a drain entered.
    #[derive(Default)]
    struct ScriptedControl {
        schedule: VecDeque<u64>,
        last: u64,
        pause_calls: u64,
        resume_calls: u64,
        force_calls: u64,
    }

    impl ScriptedControl {
        fn with_counts(counts: &[u64]) -> Self {
            let mut schedule: VecDeque<u64> = counts.iter().copied().collect();
            let last = schedule.pop_front().unwrap_or(0);
            Self {
                schedule,
                last,
                ..Self::default()
            }
        }
    }

    impl DrainControl for ScriptedControl {
        fn pause_new_work(&mut self, _service: &str) -> Result<(), graph_core::error::AxiomError> {
            self.pause_calls += 1;
            Ok(())
        }

        fn in_flight(&mut self, _service: &str) -> u64 {
            let value = self.last;
            if let Some(next) = self.schedule.pop_front() {
                self.last = next;
            }
            value
        }

        fn resume(&mut self, _service: &str) -> Result<(), graph_core::error::AxiomError> {
            self.resume_calls += 1;
            Ok(())
        }

        fn force_kill(&mut self, _service: &str) -> Result<(), graph_core::error::AxiomError> {
            self.force_calls += 1;
            Ok(())
        }
    }

    #[test]
    fn drain_pauses_waits_and_resumes_inside_the_budget() {
        let mut control = ScriptedControl::with_counts(&[3, 1, 0]);
        let clock = StepClock::new(0, 5);
        let report = drain(
            &mut control,
            "axiom-graphd",
            &DrainPolicy::default(),
            &clock,
        )
        .expect("drains");
        assert_eq!(report.outcome, DrainOutcome::Drained);
        assert_eq!(report.waited_seconds, 10);
        assert_eq!(report.polls, 2);
        assert_eq!(
            report.phases,
            vec![
                DrainPhase::PauseNewWork,
                DrainPhase::DrainInFlight,
                DrainPhase::Resume
            ]
        );
        assert!(!report.new_work_paused);
        assert!(!report.forced_kill);
        assert_eq!(control.pause_calls, 1);
        assert_eq!(control.resume_calls, 1);
        assert_eq!(control.force_calls, 0);
    }

    #[test]
    fn a_drain_that_runs_out_of_budget_times_out_without_killing() {
        let mut control = ScriptedControl::with_counts(&[2]);
        let clock = StepClock::new(0, 10);
        let report = drain(
            &mut control,
            "axiom-graphd",
            &DrainPolicy::default(),
            &clock,
        )
        .expect("returns an outcome");
        assert_eq!(report.outcome, DrainOutcome::TimedOut { remaining: 2 });
        assert_eq!(report.waited_seconds, 30);
        assert_eq!(report.polls, 3);
        assert_eq!(
            report.phases,
            vec![DrainPhase::PauseNewWork, DrainPhase::DrainInFlight]
        );
        // New work stays refused and nothing was killed.
        assert!(report.new_work_paused);
        assert!(!report.forced_kill);
        assert_eq!(control.resume_calls, 0);
        assert_eq!(control.force_calls, 0);
    }

    #[test]
    fn a_zero_budget_stops_after_one_poll_even_with_a_frozen_clock() {
        let mut control = ScriptedControl::with_counts(&[1]);
        let clock = StepClock::new(0, 0);
        let policy = DrainPolicy {
            max_seconds: 0,
            allow_forced_kill: false,
        };
        let report = drain(&mut control, "axiom-graphd", &policy, &clock).expect("returns");
        assert_eq!(report.outcome, DrainOutcome::TimedOut { remaining: 1 });
        assert_eq!(report.polls, 1);
        assert!(!report.forced_kill);
        assert_eq!(control.force_calls, 0);
    }

    #[test]
    fn forced_kill_is_refused_by_the_default_policy() {
        let policy = DrainPolicy::default();
        assert!(
            !policy.allow_forced_kill,
            "forced kill must not be the default"
        );
        let mut control = ScriptedControl::with_counts(&[1]);
        let error = force_kill(&mut control, "axiom-graphd", &policy).expect_err("refused");
        assert_eq!(rule_of(&error), "forced_kill_refused");
        assert_eq!(control.force_calls, 0);
    }

    #[test]
    fn forced_kill_runs_only_under_an_explicit_policy() {
        let mut control = ScriptedControl::with_counts(&[1]);
        let policy = DrainPolicy::with_forced_kill(10);
        let report = force_kill(&mut control, "axiom-graphd", &policy).expect("kills");
        assert_eq!(report.outcome, DrainOutcome::ForceKilled);
        assert!(report.forced_kill);
        assert!(report.outcome.killed());
        assert_eq!(control.force_calls, 1);
    }

    #[test]
    fn the_policy_bound_is_inclusive_and_out_of_range_is_named() {
        assert!(DrainPolicy::with_forced_kill(MAX_DRAIN_SECONDS)
            .validate()
            .is_ok());
        let error = DrainPolicy {
            max_seconds: MAX_DRAIN_SECONDS + 1,
            allow_forced_kill: false,
        }
        .validate()
        .expect_err("refused");
        assert_eq!(rule_of(&error), "invalid_drain_seconds");

        let mut control = ScriptedControl::with_counts(&[0]);
        let clock = StepClock::new(0, 1);
        let error = drain(
            &mut control,
            "axiom-graphd",
            &DrainPolicy {
                max_seconds: MAX_DRAIN_SECONDS + 1,
                allow_forced_kill: false,
            },
            &clock,
        )
        .expect_err("refused");
        assert_eq!(rule_of(&error), "invalid_drain_seconds");
        // A refused policy pauses nothing.
        assert_eq!(control.pause_calls, 0);
    }

    #[test]
    fn a_blank_service_name_is_refused_before_any_phase() {
        let mut control = ScriptedControl::with_counts(&[0]);
        let clock = StepClock::new(0, 1);
        let error =
            drain(&mut control, "  ", &DrainPolicy::default(), &clock).expect_err("refused");
        assert_eq!(rule_of(&error), "invalid_service");
        assert_eq!(control.pause_calls, 0);
    }

    #[test]
    fn drain_phases_and_outcomes_have_stable_spellings() {
        assert_eq!(
            DrainPhase::all()
                .iter()
                .map(|phase| phase.as_str())
                .collect::<Vec<_>>(),
            vec!["pause_new_work", "drain_in_flight", "resume"]
        );
        assert_eq!(DrainOutcome::Drained.as_str(), "drained");
        assert_eq!(
            DrainOutcome::TimedOut { remaining: 0 }.as_str(),
            "timed_out"
        );
        assert_eq!(DrainOutcome::ForceKilled.as_str(), "force_killed");
    }
}
