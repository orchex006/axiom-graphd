//! Service adapters for the `axiom` CLI (tasks E-008..E-011).
//!
//! `21-INSTALLATION.md` section E makes one managed user process per component
//! the supported way to run the daemon and the gateway, and pins the per-host
//! mechanism: a per-user startup record on Windows, a systemd user unit on
//! Linux and a launchd agent on macOS. Section E is explicit that the choice is
//! per-user, that the adapter must cover logs, restart policy, stop and
//! uninstall, and that with no administrator permission the installer must fall
//! back to the foreground rather than change a machine-wide policy.
//!
//! This module holds the platform-neutral pieces every adapter shares:
//!
//! * [`Consent`] - the token that says a human saw the reviewed plan and agreed
//!   to register a startup record. It is required, not implied.
//! * [`RestartPolicy`] - how a managed process is restarted after a failure,
//!   validated so a policy cannot ask for an unbounded restart loop.
//! * [`StartupTrigger`] - when the managed process starts (logon, for now).
//!
//! The per-host adapters live beside it: [`windows`] implements the Windows
//! per-user Scheduled Task. Linux (`systemd --user`) and macOS (launchd agent)
//! land as their own work packages and record their own task ids.

use serde::{Deserialize, Serialize};

pub mod windows;

/// Directory, relative to the install root, that holds service definitions and
/// their rendered task/unit files.
pub const SERVICE_DIRECTORY: &str = "service";

/// Directory, relative to the install root, that holds the managed process logs.
pub const SERVICE_LOG_DIRECTORY: &str = "logs";

/// Upper bound on `max_attempts` in [`RestartPolicy`], matching the largest
/// count Windows Task Scheduler accepts.
pub const MAX_RESTART_ATTEMPTS: u32 = 999;

/// Upper bound, in seconds, on the restart delay in [`RestartPolicy`].
pub const MAX_RESTART_DELAY_SECONDS: u32 = 86_400;

/// Reason recorded when a restart policy asks for something out of range.
pub const REASON_RESTART_POLICY: &str = "restart-policy-out-of-range";

/// Explicit human consent to register a startup record.
///
/// Installation registers a startup record that runs a program after the user
/// signs in. That is a change to the user's session, so a front end must ask
/// first; this token is how the front end states that it did. The tuple field
/// is private, so the token cannot be produced with a struct literal - calling
/// [`Consent::explicit`] is the only way to make one, and it is always passed
/// to an adapter as its own argument rather than buried in a request struct.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Consent(());

impl Consent {
    /// The consent token, returned only from a deliberate call.
    #[must_use]
    pub const fn explicit() -> Self {
        Self(())
    }
}

/// When a managed process starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupTrigger {
    /// Start when the user signs in. The per-user default on every host.
    Logon,
}

impl StartupTrigger {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Logon => "logon",
        }
    }
}

/// How a managed process is restarted after it fails.
///
/// `on_failure: false` is the explicit "never restart" policy; when it is
/// `true` the delay and attempt count must be inside the range the host
/// scheduler accepts, so a policy cannot declare an unbounded restart loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartPolicy {
    /// Whether the host scheduler restarts the process after a failure.
    pub on_failure: bool,
    /// Seconds to wait before a restart; `0` when `on_failure` is `false`.
    pub delay_seconds: u32,
    /// Restart attempts before the scheduler gives up; `0` when `on_failure`
    /// is `false`.
    pub max_attempts: u32,
}

impl RestartPolicy {
    /// The explicit "never restart" policy.
    #[must_use]
    pub const fn never() -> Self {
        Self {
            on_failure: false,
            delay_seconds: 0,
            max_attempts: 0,
        }
    }

    /// A bounded on-failure policy.
    #[must_use]
    pub const fn on_failure(delay_seconds: u32, max_attempts: u32) -> Self {
        Self {
            on_failure: true,
            delay_seconds,
            max_attempts,
        }
    }

    /// True when this policy is inside the accepted range.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        if !self.on_failure {
            return self.delay_seconds == 0 && self.max_attempts == 0;
        }
        self.max_attempts >= 1
            && self.max_attempts <= MAX_RESTART_ATTEMPTS
            && self.delay_seconds >= 1
            && self.delay_seconds <= MAX_RESTART_DELAY_SECONDS
    }
}
