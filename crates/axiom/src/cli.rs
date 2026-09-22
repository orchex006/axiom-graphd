//! The `axiom` command line: argv in, one JSON object out (tasks E-001, I-003).
//!
//! `docs/16-CLI-AND-CONTROL-API.md` fixes the shape of this layer. Section 1
//! gives the shared CLI behaviour, section 4 lists the documented commands of
//! the Bootstrap/distribution CLI, section 6 is the frozen exit vocabulary and
//! section 7 fixes plan approval. Task E-001 built the envelope and the exit
//! table; task I-003 closes the composition gap E-001 left open so that every
//! documented command is reachable from argv and is listed by `--help`.
//!
//! The installation engine under `install/`, `service/`, `skills/`, `update/`,
//! `bootstrap/`, `hosts/` and `support` already exists and is unit tested. This
//! module only composes the argv surface in front of it, so it adds no new
//! installation behaviour: a form whose production behaviour is not built yet
//! answers `not ready/stale` (4) with the reason recorded in [`VERBS`].
//!
//! Two rules keep the surface honest:
//!
//! * [`VERBS`] is the single declared dispatcher table and [`USAGE`] is
//!   hand-written. The tests below compare them in *both* directions, so
//!   deleting a subcommand from one side while leaving it in the other fails a
//!   test instead of shipping a help text that lies.
//! * An unbuilt form can only fail closed: [`execute`] has no arm that could
//!   turn one into an empty success, and a declared-but-unexecutable form is an
//!   internal error rather than a silent success.

use std::io::Write;
use std::path::{Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{is_absolute_host_path, is_portable_id, AxiomHome, PathEnvironment};
use graph_core::redact;
use serde::{Deserialize, Serialize};

pub use graph_core::error::ExitCode;

use crate::hosts::detect::{HostKind, LocalHostProbe};
use crate::install::apply::{ApplyRequest, LocalFs};
use crate::install::ecosystem::{
    apply_ecosystem, plan_ecosystem, verify_ecosystem, EcosystemComponentPlan, EcosystemContext,
    EcosystemPlan, EcosystemProbe, NativeProbe, CORE_COMPONENTS, RULE_APPROVAL,
    RULE_STAGING_INCOMPLETE, SKILLS_DIRECTORY, SKILLS_PAYLOAD_DIRECTORY,
};
use crate::install::plan::{ComponentAction, InstallPlan};
use crate::skills::install::{LocalInstallFs, LocalPayloadSource};
use crate::version::VersionReport;

/// Exit code that a successful command returns.
pub const SUCCESS: ExitCode = ExitCode::Success;

/// The largest accepted option value or positional argument.
///
/// The documented surface carries identifiers, paths and digests only, so a
/// bound keeps a hostile argv from being buffered and echoed without limit.
const MAX_TOKEN_BYTES: usize = 4096;

/// The options every documented form accepts.
///
/// They are documented once in the `Options:` block of [`USAGE`] instead of
/// being repeated on every command line.
const GLOBAL_OPTIONS: &[&str] = &["--json", "--help", "-h", "--version", "-V"];

/// One option a documented form accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionSpec {
    /// The option token exactly as it is typed, for example `--bundle`.
    pub name: &'static str,
    /// Whether the option consumes the next argv token as its value.
    pub takes_value: bool,
    /// Whether the form refuses to run when the option is absent.
    pub required: bool,
}

/// One documented invocation form: a verb, its subcommand path and its options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormSpec {
    /// The top-level verb, for example `install`.
    pub verb: &'static str,
    /// The subcommand path after the verb; empty for a bare verb.
    pub subcommands: &'static [&'static str],
    /// The options this form accepts, including the ones it requires.
    pub options: &'static [OptionSpec],
    /// Why this form is not built yet, or `None` when it is implemented.
    pub not_ready: Option<&'static str>,
}

impl FormSpec {
    /// The canonical space-joined path of this form, for example `install plan`.
    #[must_use]
    pub fn path(&self) -> String {
        let mut tokens: Vec<&str> = Vec::with_capacity(1 + self.subcommands.len());
        tokens.push(self.verb);
        tokens.extend_from_slice(self.subcommands);
        tokens.join(" ")
    }

    /// Whether every token of this form's path matches the front of `words`.
    fn matches_prefix(&self, words: &[&str]) -> bool {
        let path_len = 1 + self.subcommands.len();
        words.len() >= path_len
            && words[0] == self.verb
            && words[1..path_len]
                .iter()
                .zip(self.subcommands.iter())
                .all(|(word, subcommand)| word == subcommand)
    }
}

/// Why the `bootstrap` forms are reachable but do no work yet.
const NOT_READY_BOOTSTRAP: &str = "the `crate::bootstrap` engine is unit tested, but bootstrapping a solution from the documented entrypoint is not composed in this build (task I-003 exposes the argv surface only)";
/// Why the `host` forms are reachable but do no work yet.
const NOT_READY_HOSTS: &str = "the `crate::hosts` detector is unit tested, but configuring a host client from the documented entrypoint is not composed in this build (task I-003 exposes the argv surface only)";
/// Why the `skills` forms are reachable but do no work yet.
const NOT_READY_SKILLS: &str = "the `crate::skills` engine is unit tested, but checking or updating skills from the documented entrypoint is not composed in this build (task I-003 exposes the argv surface only)";
/// Why the `specs` forms are reachable but do no work yet.
const NOT_READY_SPECS: &str = "the managed specification bundle slice is not composed into the `axiom` entrypoint in this build (task I-003 exposes the argv surface only)";
/// Why the `doctor` form is reachable but does no work yet.
const NOT_READY_DOCTOR: &str = "the diagnostics slice is not composed into the `axiom` entrypoint in this build (task I-003 exposes the argv surface only)";
/// Why the `support-bundle` form is reachable but does no work yet.
const NOT_READY_SUPPORT: &str = "the `crate::support` bundle slice is unit tested, but writing a support bundle from the documented entrypoint is not composed in this build (task I-003 exposes the argv surface only)";
/// Why the `migrate` forms are reachable but do no work yet.
const NOT_READY_MIGRATE: &str = "`docs/16-CLI-AND-CONTROL-API.md` V2 migration commands are intended interfaces rather than shipped commands, so `migrate` is not composed in this build (task I-003 exposes the argv surface only)";

/// `--all`, accepted by `version`, `update check` and `doctor`.
const OPT_ALL: OptionSpec = OptionSpec {
    name: "--all",
    takes_value: false,
    required: false,
};
/// `--out <file>`, optional where a plan or report path is not mandatory.
const OPT_OUT: OptionSpec = OptionSpec {
    name: "--out",
    takes_value: true,
    required: false,
};
/// `--out <file>`, required by `support-bundle`.
const OPT_OUT_REQUIRED: OptionSpec = OptionSpec {
    name: "--out",
    takes_value: true,
    required: true,
};
/// `--bundle <signed-bundle>`, the signed installation input.
const OPT_BUNDLE: OptionSpec = OptionSpec {
    name: "--bundle",
    takes_value: true,
    required: true,
};
/// `--plan <file>`, the canonical plan to apply.
const OPT_PLAN: OptionSpec = OptionSpec {
    name: "--plan",
    takes_value: true,
    required: true,
};
/// `--approve-digest <sha256>`, the approval binding of section 7.
const OPT_APPROVE_DIGEST: OptionSpec = OptionSpec {
    name: "--approve-digest",
    takes_value: true,
    required: false,
};
/// `--component <id>`, the managed component a service form acts on.
const OPT_COMPONENT: OptionSpec = OptionSpec {
    name: "--component",
    takes_value: true,
    required: true,
};
/// `--user`, a per-user managed service rather than a system-wide one.
const OPT_USER: OptionSpec = OptionSpec {
    name: "--user",
    takes_value: false,
    required: false,
};
/// `--solution <id>`, the solution a bootstrap form acts on.
const OPT_SOLUTION: OptionSpec = OptionSpec {
    name: "--solution",
    takes_value: true,
    required: true,
};
/// `--hosts <list>`, the comma-separated host kinds to bootstrap.
const OPT_HOSTS: OptionSpec = OptionSpec {
    name: "--hosts",
    takes_value: true,
    required: false,
};
/// `--host <name>`, the one host kind a client-configuration form acts on.
const OPT_HOST: OptionSpec = OptionSpec {
    name: "--host",
    takes_value: true,
    required: true,
};
/// `--dry-run`, report what a configuration change would do.
const OPT_DRY_RUN: OptionSpec = OptionSpec {
    name: "--dry-run",
    takes_value: false,
    required: false,
};
/// `--updates`, ask for the update check rather than the plain check.
const OPT_UPDATES: OptionSpec = OptionSpec {
    name: "--updates",
    takes_value: false,
    required: false,
};
/// `--to <target>`, the update target.
const OPT_TO: OptionSpec = OptionSpec {
    name: "--to",
    takes_value: true,
    required: false,
};
/// `--transaction <id>`, the recorded transaction to inspect or roll back.
const OPT_TRANSACTION: OptionSpec = OptionSpec {
    name: "--transaction",
    takes_value: true,
    required: true,
};
/// `--redact`, redact the support bundle before writing it.
const OPT_REDACT: OptionSpec = OptionSpec {
    name: "--redact",
    takes_value: false,
    required: false,
};
/// `--from <ref>`, the migration source layout (`auto` when unspecified).
const OPT_FROM: OptionSpec = OptionSpec {
    name: "--from",
    takes_value: true,
    required: false,
};
/// `--to-layout <n>`, the target namespace layout version.
const OPT_TO_LAYOUT: OptionSpec = OptionSpec {
    name: "--to-layout",
    takes_value: true,
    required: false,
};

/// Every invocation form this build declares, in help order.
///
/// The `Commands:` block of [`USAGE`] lists exactly these forms, in this order,
/// and `mod tests` enforces that correspondence in both directions. A new
/// documented command must be added here *and* to the usage text.
pub const VERBS: &[FormSpec] = &[
    FormSpec {
        verb: "version",
        subcommands: &[],
        options: &[OPT_ALL],
        not_ready: None,
    },
    FormSpec {
        verb: "help",
        subcommands: &[],
        options: &[],
        not_ready: None,
    },
    FormSpec {
        verb: "specs",
        subcommands: &["version"],
        options: &[],
        not_ready: Some(NOT_READY_SPECS),
    },
    FormSpec {
        verb: "skills",
        subcommands: &["version"],
        options: &[],
        not_ready: Some(NOT_READY_SKILLS),
    },
    FormSpec {
        verb: "install",
        subcommands: &["plan"],
        options: &[OPT_BUNDLE, OPT_OUT],
        not_ready: None,
    },
    FormSpec {
        verb: "install",
        subcommands: &["apply"],
        options: &[OPT_PLAN, OPT_APPROVE_DIGEST],
        not_ready: None,
    },
    FormSpec {
        verb: "uninstall",
        subcommands: &["plan"],
        options: &[OPT_OUT_REQUIRED],
        not_ready: None,
    },
    FormSpec {
        verb: "uninstall",
        subcommands: &["apply"],
        options: &[OPT_PLAN, OPT_APPROVE_DIGEST],
        not_ready: None,
    },
    FormSpec {
        verb: "service",
        subcommands: &["install"],
        options: &[OPT_COMPONENT, OPT_USER],
        not_ready: None,
    },
    FormSpec {
        verb: "service",
        subcommands: &["start"],
        options: &[OPT_COMPONENT],
        not_ready: None,
    },
    FormSpec {
        verb: "service",
        subcommands: &["stop"],
        options: &[OPT_COMPONENT],
        not_ready: None,
    },
    FormSpec {
        verb: "service",
        subcommands: &["status"],
        options: &[OPT_COMPONENT],
        not_ready: None,
    },
    FormSpec {
        verb: "service",
        subcommands: &["uninstall"],
        options: &[OPT_COMPONENT],
        not_ready: None,
    },
    FormSpec {
        verb: "bootstrap",
        subcommands: &["plan"],
        options: &[OPT_SOLUTION, OPT_HOSTS, OPT_OUT],
        not_ready: Some(NOT_READY_BOOTSTRAP),
    },
    FormSpec {
        verb: "bootstrap",
        subcommands: &["apply"],
        options: &[OPT_PLAN, OPT_APPROVE_DIGEST],
        not_ready: Some(NOT_READY_BOOTSTRAP),
    },
    FormSpec {
        verb: "bootstrap",
        subcommands: &["verify"],
        options: &[OPT_SOLUTION],
        not_ready: Some(NOT_READY_BOOTSTRAP),
    },
    FormSpec {
        verb: "bootstrap",
        subcommands: &["update", "plan"],
        options: &[OPT_SOLUTION, OPT_TO],
        not_ready: Some(NOT_READY_BOOTSTRAP),
    },
    FormSpec {
        verb: "bootstrap",
        subcommands: &["update", "apply"],
        options: &[OPT_PLAN, OPT_APPROVE_DIGEST],
        not_ready: Some(NOT_READY_BOOTSTRAP),
    },
    FormSpec {
        verb: "host",
        subcommands: &["detect"],
        options: &[],
        not_ready: Some(NOT_READY_HOSTS),
    },
    FormSpec {
        verb: "host",
        subcommands: &["configure"],
        options: &[OPT_HOST, OPT_DRY_RUN],
        not_ready: Some(NOT_READY_HOSTS),
    },
    FormSpec {
        verb: "host",
        subcommands: &["verify"],
        options: &[OPT_HOST],
        not_ready: Some(NOT_READY_HOSTS),
    },
    FormSpec {
        verb: "skills",
        subcommands: &["check"],
        options: &[OPT_UPDATES],
        not_ready: Some(NOT_READY_SKILLS),
    },
    FormSpec {
        verb: "skills",
        subcommands: &["update", "plan"],
        options: &[OPT_TO],
        not_ready: Some(NOT_READY_SKILLS),
    },
    FormSpec {
        verb: "skills",
        subcommands: &["update", "apply"],
        options: &[OPT_PLAN],
        not_ready: Some(NOT_READY_SKILLS),
    },
    FormSpec {
        verb: "specs",
        subcommands: &["check"],
        options: &[OPT_UPDATES],
        not_ready: Some(NOT_READY_SPECS),
    },
    FormSpec {
        verb: "specs",
        subcommands: &["update", "plan"],
        options: &[OPT_TO],
        not_ready: Some(NOT_READY_SPECS),
    },
    FormSpec {
        verb: "specs",
        subcommands: &["update", "apply"],
        options: &[OPT_PLAN],
        not_ready: Some(NOT_READY_SPECS),
    },
    FormSpec {
        verb: "update",
        subcommands: &["check"],
        options: &[OPT_ALL],
        not_ready: None,
    },
    FormSpec {
        verb: "update",
        subcommands: &["plan"],
        options: &[
            OptionSpec {
                required: true,
                ..OPT_TO
            },
            OPT_BUNDLE,
            OPT_OUT_REQUIRED,
        ],
        not_ready: None,
    },
    FormSpec {
        verb: "update",
        subcommands: &["apply"],
        options: &[OPT_PLAN, OPT_APPROVE_DIGEST],
        not_ready: None,
    },
    FormSpec {
        verb: "update",
        subcommands: &["rollback"],
        options: &[OPT_TRANSACTION],
        not_ready: None,
    },
    FormSpec {
        verb: "doctor",
        subcommands: &[],
        options: &[OPT_ALL],
        not_ready: Some(NOT_READY_DOCTOR),
    },
    FormSpec {
        verb: "support-bundle",
        subcommands: &[],
        options: &[OPT_OUT_REQUIRED, OPT_REDACT],
        not_ready: Some(NOT_READY_SUPPORT),
    },
    FormSpec {
        verb: "migrate",
        subcommands: &["plan"],
        options: &[OPT_SOLUTION, OPT_FROM, OPT_TO_LAYOUT, OPT_OUT],
        not_ready: Some(NOT_READY_MIGRATE),
    },
    FormSpec {
        verb: "migrate",
        subcommands: &["apply"],
        options: &[OPT_PLAN, OPT_APPROVE_DIGEST],
        not_ready: Some(NOT_READY_MIGRATE),
    },
    FormSpec {
        verb: "migrate",
        subcommands: &["status"],
        options: &[OPT_TRANSACTION],
        not_ready: Some(NOT_READY_MIGRATE),
    },
    FormSpec {
        verb: "migrate",
        subcommands: &["rollback"],
        options: &[OPT_TRANSACTION, OPT_APPROVE_DIGEST],
        not_ready: Some(NOT_READY_MIGRATE),
    },
];

/// Usage text without the generated exit-code table.
///
/// The `Commands:` block is the advertised surface and is hand-written on
/// purpose: `mod tests` parses it back and compares it with [`VERBS`] in both
/// directions, so it cannot silently drift from the dispatcher.
pub const USAGE: &str = "\
axiom - Axiom installation, bootstrap and operations CLI

Usage: axiom <command> [options]

Commands:
  version [--all]  print component and build versions
  help, --help  print this help
  specs version  print the managed specification bundle version
  skills version  print the managed skills bundle version
  install plan --bundle <signed-bundle> [--out <file>]  plan an installation from a signed bundle
  install apply --plan <file> [--approve-digest <sha256>]  apply an approved installation plan
  uninstall plan --out <file>  review removal of owned runtime while preserving user data
  uninstall apply --plan <file> --approve-digest <sha256>  remove the exact approved installation
  service install --component <id> [--user]  install the managed service for one component
  service start --component <id>  start the managed service
  service stop --component <id>  stop the managed service
  service status --component <id>  report the managed service status
  service uninstall --component <id>  remove the managed service
  bootstrap plan --solution <id> [--hosts <list>] [--out <file>]  plan a solution bootstrap for the named hosts
  bootstrap apply --plan <file> [--approve-digest <sha256>]  apply an approved bootstrap plan
  bootstrap verify --solution <id>  verify a bootstrapped solution
  bootstrap update plan --solution <id> [--to <version>]  plan a bootstrap update
  bootstrap update apply --plan <file> [--approve-digest <sha256>]  apply an approved bootstrap update plan
  host detect  detect the installed agent hosts
  host configure --host <name> [--dry-run]  configure one agent host client
  host verify --host <name>  verify one configured agent host client
  skills check [--updates]  check the managed skills bundle
  skills update plan [--to <target>]  plan a skills update
  skills update apply --plan <file>  apply an approved skills update plan
  specs check [--updates]  check the managed specification bundle
  specs update plan [--to <version>]  plan a specification update
  specs update apply --plan <file>  apply an approved specification update plan
  update check [--all]  check every updatable component
  update plan --to <version> --bundle <dir> --out <file>  plan a local ecosystem update
  update apply --plan <file> [--approve-digest <sha256>]  apply an approved core update plan
  update rollback --transaction <id>  roll back one recorded update transaction
  doctor [--all]  run diagnostics
  support-bundle --out <file> [--redact]  write a redacted support bundle
  migrate plan --solution <id> [--from <ref>] [--to-layout <n>] [--out <file>]  plan the V2 namespace migration
  migrate apply --plan <file> --approve-digest <sha256>  apply an approved migration plan
  migrate status --transaction <id>  report one migration transaction
  migrate rollback --transaction <id> --approve-digest <sha256>  roll back one migration transaction

Options:
  --all  report every component or host of this release
  --json  write exactly one JSON object to stdout; diagnostics go to stderr
  --help, -h  print this help
  --version, -V  print the version report

Every command above is reachable from argv. A command whose production
behaviour is not built yet answers the frozen not ready/stale code (4) with the
module that owns it, and never an empty success. `install apply`, `bootstrap
apply`, `bootstrap update apply`, `update apply` and `migrate apply` bind their
approval to the canonical plan digest recorded by --approve-digest.

Exit codes:
";

/// Top-level verbs of `docs/16-CLI-AND-CONTROL-API.md` section 4 that a later
/// installation work package implements. Recognising them keeps the distinction
/// between "not built yet" and "not a command" honest, and
/// `pending_verbs_match_the_declared_surface` proves this list still names
/// exactly the verbs whose declared forms are unbuilt.
pub const PENDING_VERBS: &[&str] = &[
    "bootstrap",
    "host",
    "skills",
    "specs",
    "doctor",
    "support-bundle",
    "migrate",
];

/// The frozen exit-code table, rendered from [`ExitCode`] itself.
#[must_use]
pub fn exit_code_table() -> String {
    let mut table = String::new();
    for code in ExitCode::all() {
        table.push_str(&format!("  {}  {}\n", code.as_i32(), code.meaning()));
    }
    table
}

/// Full usage text: [`USAGE`] followed by the generated exit-code table.
#[must_use]
pub fn usage() -> String {
    let mut text = String::from(USAGE);
    text.push_str(&exit_code_table());
    text
}

/// A parsed command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Print version information, optionally for every component of this release.
    Version {
        /// Report every component this build can report, not only the CLI.
        all: bool,
    },
    /// `install plan`: probe the declared prerequisites and write one plan.
    InstallPlan {
        /// The verified local bundle directory the plan is built from.
        bundle: String,
        /// Plan document to write, when the operator named one with `--out`.
        out: Option<String>,
    },
    /// `install apply`: activate one reviewed plan at its approved digest.
    InstallApply {
        /// The reviewed plan document to apply.
        plan: String,
        /// The digest the operator approved, from the plan document.
        approve_digest: Option<String>,
    },
    /// Inspect the active local ecosystem.
    UpdateCheck,
    /// Plan an update from a verified local bundle.
    UpdatePlan {
        /// Exact target core version.
        to: String,
        /// Local bundle directory.
        bundle: String,
        /// Reviewed plan destination.
        out: String,
    },
    /// Apply a reviewed ecosystem update.
    UpdateApply {
        /// Reviewed plan document.
        plan: String,
        /// Explicit digest approval.
        approve_digest: Option<String>,
    },
    /// Restore an exact recorded ecosystem transaction.
    UpdateRollback {
        /// Recorded transaction identifier.
        transaction: String,
    },
    /// Review removal of one owned ecosystem installation.
    UninstallPlan {
        /// Destination for the reviewed plan.
        out: String,
    },
    /// Apply an approved removal plan.
    UninstallApply {
        /// Reviewed plan path.
        plan: String,
        /// Explicit approval digest.
        approve_digest: Option<String>,
    },
    /// Operate one owned per-user service.
    Service {
        /// Declared lifecycle action.
        action: String,
        /// Component identity.
        component: String,
        /// Explicit per-user registration consent.
        user: bool,
    },
    /// A declared form whose production behaviour is not built yet.
    Slice {
        /// The declared form that was recognised.
        form: &'static FormSpec,
        /// Why that form does not run yet.
        reason: &'static str,
    },
    /// Print usage.
    Help,
    /// The arguments were rejected; the error carries the reason.
    Rejected {
        /// Why the arguments were rejected.
        error: AxiomError,
    },
}

/// One parsed invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    command: Command,
    json: bool,
}

impl Invocation {
    /// Build an invocation directly, for tests and embedders.
    #[must_use]
    pub fn new(command: Command, json: bool) -> Self {
        Self { command, json }
    }

    /// The parsed command.
    #[must_use]
    pub fn command(&self) -> &Command {
        &self.command
    }

    /// Whether the caller asked for machine-readable stdout.
    #[must_use]
    pub const fn json(&self) -> bool {
        self.json
    }
}

/// Parse argv (without the program name).
///
/// Parsing never fails: rejected arguments become [`Command::Rejected`] so the
/// caller still knows whether `--json` was requested and can emit the error
/// envelope on stdout.
#[must_use]
pub fn parse(arguments: &[String]) -> Invocation {
    let json = arguments
        .iter()
        .any(|argument| argument.as_str() == "--json");
    match resolve(arguments) {
        Ok(command) => Invocation { command, json },
        Err(error) => Invocation {
            command: Command::Rejected { error },
            json,
        },
    }
}

/// A rejected argument, carrying the frozen validation code.
fn validation(message: String) -> AxiomError {
    AxiomError::new(ErrorCode::ValidationError, message)
}

/// Turn argv into a declared command, or the one validation error it earns.
///
/// The order is deliberate: a leading `--help` short-circuits to usage, the
/// longest declared path that matches the leading words wins, options are then
/// resolved only against that form, and required or malformed values are
/// rejected before anything runs.
fn resolve(arguments: &[String]) -> Result<Command, AxiomError> {
    if arguments
        .iter()
        .any(|argument| matches!(argument.as_str(), "--help" | "-h"))
    {
        return Ok(Command::Help);
    }
    if let Some(first) = arguments.first() {
        if matches!(first.as_str(), "--version" | "-V") {
            let all = arguments
                .iter()
                .any(|argument| argument.as_str() == "--all");
            return Ok(Command::Version { all });
        }
    }

    let words: Vec<&str> = arguments
        .iter()
        .take_while(|argument| !argument.starts_with('-'))
        .map(String::as_str)
        .collect();

    let matched = VERBS
        .iter()
        .filter(|form| form.matches_prefix(&words))
        .max_by_key(|form| 1 + form.subcommands.len());

    let Some(form) = matched else {
        if words.is_empty() {
            // No command word at all: plain help, or the first option that is
            // not one of the documented global options is the error to report.
            return match arguments
                .iter()
                .find(|argument| !GLOBAL_OPTIONS.contains(&argument.as_str()))
            {
                None => Ok(Command::Help),
                Some(option) => Err(validation(format!("unrecognised option: {option}"))),
            };
        }
        return Err(validation(format!(
            "unrecognised command: {}",
            words.join(" ")
        )));
    };

    // Longest-prefix matching means the path is exactly as long as the words
    // consumed, so any remaining word is an argument this form does not take.
    let path_len = 1 + form.subcommands.len();
    if let Some(extra) = words.get(path_len) {
        return Err(validation(format!(
            "the {} command does not accept the argument {extra}",
            form.path()
        )));
    }

    let mut seen: Vec<&'static str> = Vec::new();
    let mut values: Vec<(&'static str, String)> = Vec::new();
    let mut index = path_len;
    while let Some(token) = arguments.get(index) {
        if GLOBAL_OPTIONS.contains(&token.as_str()) {
            index += 1;
            continue;
        }
        let Some(spec) = form
            .options
            .iter()
            .find(|option| option.name == token.as_str())
        else {
            let kind = if token.starts_with('-') {
                "option"
            } else {
                "argument"
            };
            return Err(validation(format!(
                "the {} command does not accept the {kind} {token}",
                form.path()
            )));
        };
        if seen.contains(&spec.name) {
            return Err(validation(format!(
                "the {} option was given more than once",
                spec.name
            )));
        }
        seen.push(spec.name);
        if spec.takes_value {
            index += 1;
            let Some(value) = arguments.get(index) else {
                return Err(validation(format!(
                    "the {} option requires a value",
                    spec.name
                )));
            };
            if value.starts_with('-') {
                return Err(validation(format!(
                    "the {} option requires a value, not the option {value}",
                    spec.name
                )));
            }
            values.push((spec.name, value.clone()));
        }
        index += 1;
    }

    for option in form.options {
        if option.required && !seen.contains(&option.name) {
            return Err(validation(format!(
                "the {} command requires the {} option",
                form.path(),
                option.name
            )));
        }
    }
    for (name, value) in &values {
        validate_value(name, value.as_str())?;
    }

    // A required option is present by construction above, so a miss here is
    // an internal defect in this table rather than a caller error.
    let required = |name: &str| -> Result<String, AxiomError> {
        values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.clone())
            .ok_or_else(|| {
                AxiomError::new(
                    ErrorCode::Internal,
                    format!("the {} command is declared to require {name}", form.path()),
                )
            })
    };
    let optional = |name: &str| -> Option<String> {
        values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.clone())
    };

    match form.not_ready {
        Some(reason) => Ok(Command::Slice { form, reason }),
        None => match form.path().as_str() {
            "version" => Ok(Command::Version {
                all: seen.contains(&"--all"),
            }),
            "help" => Ok(Command::Help),
            "install plan" => Ok(Command::InstallPlan {
                bundle: required("--bundle")?,
                out: optional("--out"),
            }),
            "install apply" => Ok(Command::InstallApply {
                plan: required("--plan")?,
                approve_digest: optional("--approve-digest"),
            }),
            "update check" => Ok(Command::UpdateCheck),
            "update plan" => Ok(Command::UpdatePlan {
                to: required("--to")?,
                bundle: required("--bundle")?,
                out: required("--out")?,
            }),
            "update apply" => Ok(Command::UpdateApply {
                plan: required("--plan")?,
                approve_digest: optional("--approve-digest"),
            }),
            "update rollback" => Ok(Command::UpdateRollback {
                transaction: required("--transaction")?,
            }),
            "uninstall plan" => Ok(Command::UninstallPlan {
                out: required("--out")?,
            }),
            "uninstall apply" => Ok(Command::UninstallApply {
                plan: required("--plan")?,
                approve_digest: optional("--approve-digest"),
            }),
            path if path.starts_with("service ") => Ok(Command::Service {
                action: form.subcommands[0].to_owned(),
                component: required("--component")?,
                user: seen.contains(&"--user"),
            }),
            other => Err(AxiomError::new(
                ErrorCode::Internal,
                format!("the {other} command is declared implemented but has no executor"),
            )),
        },
    }
}

/// Validate one option value against the vocabulary its contract fixes.
fn validate_value(name: &str, value: &str) -> Result<(), AxiomError> {
    if value.is_empty() {
        return Err(validation(format!(
            "the {name} option needs a non-empty value"
        )));
    }
    if value.len() > MAX_TOKEN_BYTES {
        return Err(validation(format!(
            "the {name} option value is longer than {MAX_TOKEN_BYTES} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(validation(format!(
            "the {name} option value contains a control character"
        )));
    }
    match name {
        "--approve-digest" => {
            let hexadecimal = value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
            if !hexadecimal {
                return Err(validation(String::from(
                    "the --approve-digest option needs a 64-character lowercase hexadecimal sha256 digest",
                )));
            }
        }
        "--to-layout" => {
            if value.parse::<u32>().is_err() {
                return Err(validation(String::from(
                    "the --to-layout option needs an integer namespace layout version",
                )));
            }
        }
        "--host" => {
            if HostKind::from_wire(value).is_none() {
                return Err(validation(format!(
                    "the --host option needs one of the known hosts, got {value}"
                )));
            }
        }
        "--hosts" => {
            for part in value.split(',') {
                if HostKind::from_wire(part).is_none() {
                    return Err(validation(format!(
                        "the --hosts option needs a comma-separated list of known hosts, got {value}"
                    )));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// One JSON object for `version --all`.
///
/// The frozen `version-report.schema.json` describes one component, and
/// `docs/16-CLI-AND-CONTROL-API.md` section 1 still requires machine-readable
/// mode to write exactly one JSON object. This envelope is that single object:
/// one frozen report per component this build can report honestly. Components
/// that need a registry lookup (MCP, skills, spec provenance) are added by the
/// work packages that implement the lookup instead of being guessed here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionEnvelope {
    /// Frozen version reports, in report order.
    pub components: Vec<VersionReport>,
}

/// Execute an invocation, writing stdout and diagnostics through the injected
/// sinks and returning the process exit code.
pub fn run(invocation: &Invocation, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode {
    match execute(invocation.command(), invocation.json()) {
        Ok(payload) => {
            let _ = writeln!(stdout, "{payload}");
            SUCCESS
        }
        Err(error) => report_failure(&error, invocation.json(), stdout, stderr),
    }
}

/// Report a failure: the error envelope on stdout in JSON mode, a redacted
/// diagnostic on stderr always.
pub fn report_failure(
    error: &AxiomError,
    json: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let _ = writeln!(stderr, "{}", redact::scrub(&error.to_string()));
    if json {
        if let Ok(line) = error.to_json() {
            let _ = writeln!(stdout, "{line}");
        }
    }
    error.exit_code()
}

/// Validate every report of one response or fail before anything is written.
fn validated(reports: Vec<VersionReport>) -> Result<Vec<VersionReport>, AxiomError> {
    for report in &reports {
        report.validate()?;
    }
    Ok(reports)
}

fn execute(command: &Command, json: bool) -> Result<String, AxiomError> {
    match command {
        Command::Help => Ok(usage()),
        Command::Rejected { error } => Err(error.clone()),
        // `version --json` is the frozen single-component object; `version --all`
        // is one envelope object, because machine-readable mode writes exactly
        // one JSON object and the frozen schema describes one component only.
        Command::Version { all: false } if json => VersionReport::cli().to_json(),
        Command::Version { all: true } if json => {
            let reports = validated(VersionReport::all())?;
            serde_json::to_string(&VersionEnvelope {
                components: reports,
            })
            .map_err(|_| {
                AxiomError::new(
                    ErrorCode::Internal,
                    "the version report is not serialisable",
                )
            })
        }
        Command::Version { all: false } => {
            let report = VersionReport::cli();
            report.validate()?;
            Ok(report.text_line())
        }
        Command::Version { all: true } => Ok(validated(VersionReport::all())?
            .iter()
            .map(VersionReport::text_line)
            .collect::<Vec<String>>()
            .join("\n")),
        // The only failure mode of a declared-but-unbuilt form, so it can never
        // become an empty success.
        Command::Slice { form, reason } => Err(AxiomError::new(
            ErrorCode::NotReady,
            format!(
                "the {} command is recognised, but not built: {reason}",
                form.path()
            ),
        )),
        Command::UpdateCheck => {
            let root = ecosystem_install_root()?;
            let value: serde_json::Value = serde_json::from_slice(&read_host_file(
                &Path::new(&root).join("current").to_string_lossy(),
            )?)
            .map_err(|e| internal_serialisation(&e))?;
            render_lifecycle(
                &serde_json::json!({"status":"installed", "current":value, "update_source":"explicit-local-bundle"}),
                json,
            )
        }
        Command::UpdatePlan { to, bundle, out } => plan_update(to, bundle, out, json),
        Command::UpdateApply {
            plan,
            approve_digest,
        } => apply_update(plan, approve_digest.as_deref(), json),
        Command::UpdateRollback { transaction } => rollback_update(transaction, json),
        Command::UninstallPlan { out } => {
            let root = ecosystem_install_root()?;
            let value = crate::install::ecosystem_uninstall::plan(Path::new(&root))?;
            let bytes =
                serde_json::to_vec_pretty(&value).map_err(|e| internal_serialisation(&e))?;
            let written = write_host_file(out, &bytes)?;
            render_lifecycle(
                &serde_json::json!({"status":"planned", "plan_digest":value["plan_digest"], "plan_file":written}),
                json,
            )
        }
        Command::UninstallApply {
            plan,
            approve_digest,
        } => {
            let approval = approve_digest.as_deref().ok_or_else(|| {
                AxiomError::new(
                    ErrorCode::Forbidden,
                    "uninstall apply requires --approve-digest",
                )
            })?;
            let value = serde_json::from_slice(&read_host_file(plan)?)
                .map_err(|e| internal_serialisation(&e))?;
            let root = ecosystem_install_root()?;
            let value = crate::install::ecosystem_uninstall::apply(
                Path::new(&root),
                value,
                approval,
                || crate::service::runtime::remove(Path::new(&root)),
            )?;
            render_lifecycle(&value, json)
        }
        Command::Service {
            action,
            component,
            user,
        } => {
            let root = ecosystem_install_root()?;
            render_lifecycle(
                &crate::service::runtime::run(action, component, *user, Path::new(&root))?,
                json,
            )
        }
        Command::InstallPlan { bundle, out } => plan_installation(bundle, out.as_deref(), json),
        Command::InstallApply {
            plan,
            approve_digest,
        } => apply_installation(plan, approve_digest.as_deref(), json),
    }
}

struct NativeLifecycle;
impl crate::update::ecosystem_runtime::ServiceLifecycle for NativeLifecycle {
    fn is_owned(&self, root: &Path) -> Result<bool, AxiomError> {
        Ok(
            crate::install::ecosystem_uninstall::checked_path(root, "state/service-v1.json")?
                .exists(),
        )
    }
    fn drain(&self, root: &Path) -> Result<(), AxiomError> {
        crate::service::runtime::remove(root)
    }
    fn reinstall(&self, root: &Path) -> Result<(), AxiomError> {
        crate::service::runtime::run_with_exec(
            "install",
            "axiom-graphd",
            true,
            root,
            &crate::service::SysExec,
        )
        .map(|_| ())
    }
}

fn plan_update(to: &str, bundle: &str, out: &str, json: bool) -> Result<String, AxiomError> {
    let root = ecosystem_install_root()?;
    let context = EcosystemContext::new(
        portable_id("update")?,
        graph_store::migrations::utc_timestamp(),
        host_identifier(),
        &root,
    );
    let host = LocalHostProbe::for_current_process();
    let probe = NativeProbe::new(&host, &root);
    let plan = crate::update::ecosystem_runtime::plan(&probe, Path::new(bundle), &context, to)?;
    if plan
        .ecosystem
        .component_plans
        .first()
        .map(|entry| entry.version.as_str())
        != Some(to)
    {
        return Err(validation(
            "--to must equal the verified bundle core version".into(),
        ));
    }
    crate::update::ecosystem_runtime::write_plan(Path::new(out), &plan)?;
    render_lifecycle(
        &serde_json::json!({"status":"planned", "plan_digest":plan.plan_digest, "plan_file":out}),
        json,
    )
}

fn apply_update(path: &str, approval: Option<&str>, json: bool) -> Result<String, AxiomError> {
    let approval = approval.ok_or_else(|| {
        AxiomError::new(
            ErrorCode::Forbidden,
            "update apply requires --approve-digest",
        )
    })?;
    let plan = crate::update::ecosystem_runtime::read_plan(Path::new(path))?;
    if plan.ecosystem.target.install_root != ecosystem_install_root()? {
        return Err(validation(
            "update plan belongs to another installation root".into(),
        ));
    }
    let result = crate::update::ecosystem_runtime::apply(
        &plan,
        approval,
        &portable_id("update")?,
        &graph_store::migrations::utc_timestamp(),
        &NativeLifecycle,
    )?;
    render_lifecycle(
        &serde_json::to_value(result).map_err(|e| internal_serialisation(&e))?,
        json,
    )
}

fn rollback_update(transaction: &str, json: bool) -> Result<String, AxiomError> {
    let root = ecosystem_install_root()?;
    let result = crate::update::ecosystem_runtime::rollback(
        Path::new(&root),
        transaction,
        &NativeLifecycle,
    )?;
    render_lifecycle(
        &serde_json::to_value(result).map_err(|e| internal_serialisation(&e))?,
        json,
    )
}

fn render_lifecycle(value: &serde_json::Value, json: bool) -> Result<String, AxiomError> {
    if json {
        serde_json::to_string(value)
    } else {
        serde_json::to_string_pretty(value)
    }
    .map_err(|error| internal_serialisation(&error))
}

/// The host identifier this build plans for.
///
/// The mapping lives in [`crate::install::plan::host_identifier`], next to the
/// [`crate::install::plan::HOSTS`] rows it has to agree with, so this module
/// cannot answer a different host than the planner validates against.
fn host_identifier() -> String {
    crate::install::plan::host_identifier()
}

/// Directory under `AXIOM_HOME` that owns one ecosystem installation.
///
/// It is derived from the resolved home, never generated: a re-run has to
/// compute the same install root as the run it repeats, which is what makes the
/// idempotent re-run of AC1(4) reachable at all.
const ECOSYSTEM_INSTALL_DIRECTORY: &str = "ecosystem";

/// The absolute install root `axiom install` targets.
///
/// `AXIOM_HOME` resolution is the same path policy the discovery slice uses, so
/// an unsafe or unconfigurable home is refused with its own frozen code instead
/// of being worked around here.
fn ecosystem_install_root() -> Result<String, AxiomError> {
    let home = AxiomHome::resolve(&PathEnvironment::for_current_process())?;
    Ok(home
        .installs_dir()
        .join(ECOSYSTEM_INSTALL_DIRECTORY)
        .to_string_lossy()
        .into_owned())
}

/// A fresh portable identifier, `^[a-z][a-z0-9-]{0,62}$`.
///
/// `graph_core::paths::is_portable_id` is the only accepted spelling and the OS
/// random source is the one the credentials slice already uses, so this adds no
/// second identifier scheme. The caller supplies the prefix, so a plan and a
/// transaction stay distinguishable in a journal.
fn portable_id(prefix: &str) -> Result<String, AxiomError> {
    use std::fmt::Write as _;

    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|error| {
        AxiomError::new(
            ErrorCode::Internal,
            "the operating system random source is unavailable",
        )
        .with_detail("rule", "entropy_unavailable")
        .with_detail("actual", error.to_string())
    })?;
    let mut entropy = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(entropy, "{byte:02x}");
    }
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let id = format!("{prefix}-{seconds}-{entropy}");
    if !is_portable_id(&id) {
        return Err(AxiomError::new(
            ErrorCode::Internal,
            "the generated identifier is not a portable Axiom identifier",
        )
        .with_detail("observed", id));
    }
    Ok(id)
}

/// Resolve one operator-supplied path against the current directory.
fn host_path(path: &str) -> Result<PathBuf, AxiomError> {
    if is_absolute_host_path(path) {
        return Ok(PathBuf::from(path));
    }
    let current = std::env::current_dir().map_err(|error| {
        AxiomError::new(
            ErrorCode::Internal,
            "the current directory could not be read",
        )
        .with_detail("actual", error.to_string())
    })?;
    Ok(current.join(path))
}

/// One host-path failure, with the path and the operating-system reason.
fn host_io_error(action: &str, path: &Path, error: &std::io::Error) -> AxiomError {
    AxiomError::new(ErrorCode::Internal, action)
        .with_detail("observed", path.to_string_lossy())
        .with_detail("actual", error.to_string())
}

/// Write one review artifact the operator named with `--out`.
fn write_host_file(path: &str, bytes: &[u8]) -> Result<String, AxiomError> {
    let resolved = host_path(path)?;
    if let Some(parent) = resolved.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            host_io_error("the plan directory could not be created", parent, &error)
        })?;
    }
    std::fs::write(&resolved, bytes).map_err(|error| {
        host_io_error("the plan document could not be written", &resolved, &error)
    })?;
    Ok(resolved.to_string_lossy().into_owned())
}

/// Read one plan document the operator named with `--plan`.
fn read_host_file(path: &str) -> Result<Vec<u8>, AxiomError> {
    let resolved = host_path(path)?;
    std::fs::read(&resolved).map_err(|error| {
        AxiomError::new(ErrorCode::NotFound, "the plan document could not be read")
            .with_detail("observed", resolved.to_string_lossy())
            .with_detail("actual", error.to_string())
    })
}

/// Compose `axiom install plan`.
fn plan_installation(bundle: &str, out: Option<&str>, json: bool) -> Result<String, AxiomError> {
    let install_root = ecosystem_install_root()?;
    let host = LocalHostProbe::for_current_process();
    let probe = NativeProbe::new(&host, &install_root);
    plan_with_probe(
        &probe,
        bundle,
        out,
        json,
        &install_root,
        &portable_id("install")?,
        &graph_store::migrations::utc_timestamp(),
    )
}

/// Probe, plan and render one installation plan over an injected probe.
///
/// The probe is a parameter so a test can plan over a deterministic matrix while
/// the operator surface always passes the real [`NativeProbe`].
fn plan_with_probe(
    probe: &impl EcosystemProbe,
    bundle: &str,
    out: Option<&str>,
    json: bool,
    install_root: &str,
    plan_id: &str,
    created_at: &str,
) -> Result<String, AxiomError> {
    let context = EcosystemContext::new(plan_id, created_at, host_identifier(), install_root);
    // The probe runs, and any blocking row refuses, before the bundle is opened
    // and before `--out` is written, so clause 1 and clause 2 are one code path.
    let plan = plan_ecosystem(probe, bundle, &context)?;
    let document = plan.to_json()?;
    let written = match out {
        Some(requested) => Some(write_host_file(requested, document.as_bytes())?),
        None => None,
    };
    if json {
        return match &written {
            Some(resolved) => serde_json::to_string(&serde_json::json!({
                "status": "planned",
                "plan_id": plan.plan_id,
                "plan_digest": plan.plan_digest,
                "plan_file": resolved,
            }))
            .map_err(|error| internal_serialisation(&error)),
            None => Ok(document),
        };
    }
    let mut text = plan.text().trim_end().to_string();
    if let Some(resolved) = &written {
        text.push_str(&format!("\nplan_file {resolved}"));
    }
    Ok(text)
}

/// Compose `axiom install apply`.
fn apply_installation(
    plan: &str,
    approve_digest: Option<&str>,
    json: bool,
) -> Result<String, AxiomError> {
    // Section 7 of `docs/16-CLI-AND-CONTROL-API.md`: merely supplying `--plan`
    // is not approval, so an unbound digest refuses instead of installing.
    let Some(approved) = approve_digest else {
        return Err(AxiomError::new(
            ErrorCode::Forbidden,
            "applying an ecosystem installation needs the digest it was approved at; supplying --plan alone is not approval",
        )
        .with_detail("rule", RULE_APPROVAL)
        .with_detail("observed", "no approved digest was bound to this run")
        .with_detail("expected", "--approve-digest <the reviewed plan digest>"));
    };
    let bytes = read_host_file(plan)?;
    let document: EcosystemPlan = serde_json::from_slice(&bytes).map_err(|error| {
        AxiomError::new(
            ErrorCode::ValidationError,
            "the plan document is not a readable ecosystem installation plan",
        )
        .with_detail("rule", "plan_document")
        .with_detail("observed", error.to_string())
    })?;
    apply_plan_document(
        &document,
        approved,
        json,
        &portable_id("ecosystem")?,
        &graph_store::migrations::utc_timestamp(),
    )
}

/// Verify approval, stage the planned payloads, then delegate to the engine.
///
/// The order is the point: the approved digest is re-verified before a single
/// byte is staged, so a stale or wrong approval cannot mutate the host. Staging
/// itself is the one piece of work this binding owns, because `plan_ecosystem`
/// only *names* the staging path and `apply_ecosystem` refuses to activate
/// planned bytes that are not there yet.
fn apply_plan_document(
    plan: &EcosystemPlan,
    approved: &str,
    json: bool,
    transaction_id: &str,
    applied_at: &str,
) -> Result<String, AxiomError> {
    verify_ecosystem(plan, approved)?;
    let root = Path::new(&plan.target.install_root);
    std::fs::create_dir_all(root)
        .map_err(|error| host_io_error("create installation root", root, &error))?;
    let _maintenance = crate::install::ecosystem_uninstall::maintenance_lock(root)?;
    crate::install::ecosystem_uninstall::prepare_install(root)?;
    stage_core_payloads(plan)?;
    let skills_source = LocalPayloadSource::new(skills_payload_root(plan));
    let skills_fs = LocalInstallFs::new(plan.target.install_root.as_str());
    let request = ApplyRequest::new(transaction_id, approved, applied_at);
    let applied = apply_ecosystem(
        plan,
        approved,
        &request,
        &LocalFs,
        &skills_source,
        &skills_fs,
    )?;
    if json {
        applied.to_json()
    } else {
        Ok(applied.text().trim_end().to_string())
    }
}

/// The verified skills payload root beside the bundle the plan was built from.
fn skills_payload_root(plan: &EcosystemPlan) -> PathBuf {
    Path::new(plan.bundle.location.as_str())
        .join(SKILLS_DIRECTORY)
        .join(SKILLS_PAYLOAD_DIRECTORY)
}

/// Read back one embedded core plan, without its two digest-excluded keys.
fn embedded_core_plan(entry: &EcosystemComponentPlan) -> Result<InstallPlan, AxiomError> {
    let mut body = entry.plan.clone();
    let object = body.as_object_mut().ok_or_else(|| {
        AxiomError::new(
            ErrorCode::ValidationError,
            "an embedded component plan is not a JSON object",
        )
        .with_detail("component", &entry.component)
    })?;
    for key in crate::plan::DIGEST_EXCLUDED {
        object.remove(key);
    }
    serde_json::from_value(body).map_err(|error| {
        AxiomError::new(
            ErrorCode::ValidationError,
            "an embedded component plan is not a readable install plan",
        )
        .with_detail("component", &entry.component)
        .with_detail("observed", error.to_string())
    })
}

/// The engine's staging refusal rule, reused rather than renamed.
fn staging_refusal(component: &str, observed: &str, expected: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::Conflict,
        "a planned payload is not staged as the plan declared, so nothing is activated",
    )
    .with_detail("rule", RULE_STAGING_INCOMPLETE)
    .with_detail("component", component)
    .with_detail("observed", observed)
    .with_detail("expected", expected)
}

/// Copy every planned core payload to its planned staging path.
///
/// It fails closed: a payload whose size or digest disagrees with the plan is
/// refused before it is written, and a destination that already holds the
/// planned bytes is left untouched so the re-run of AC1(4) rewrites nothing.
fn stage_core_payloads(plan: &EcosystemPlan) -> Result<(), AxiomError> {
    for entry in &plan.component_plans[..CORE_COMPONENTS.len()] {
        let child = embedded_core_plan(entry)?;
        let planned = child.components.first().ok_or_else(|| {
            staging_refusal(
                &entry.component,
                "no planned component",
                "one planned component",
            )
        })?;
        if planned.action == ComponentAction::Noop {
            continue;
        }
        let destination = Path::new(planned.destination.as_str());
        if destination.is_file() {
            if let Ok(bytes) = std::fs::read(destination) {
                if graph_export::sha256_hex(&bytes) == planned.source.sha256 {
                    continue;
                }
            }
        }
        let source = std::fs::read(planned.source.location.as_str()).map_err(|error| {
            AxiomError::new(
                ErrorCode::NotFound,
                "a planned payload is missing from the verified bundle",
            )
            .with_detail("rule", RULE_STAGING_INCOMPLETE)
            .with_detail("component", &entry.component)
            .with_detail("observed", planned.source.location.clone())
            .with_detail("actual", error.to_string())
        })?;
        if source.len() as u64 != planned.source.size_bytes {
            return Err(staging_refusal(
                &entry.component,
                &source.len().to_string(),
                &planned.source.size_bytes.to_string(),
            ));
        }
        let digest = graph_export::sha256_hex(&source);
        if digest != planned.source.sha256 {
            return Err(staging_refusal(
                &entry.component,
                &digest,
                &planned.source.sha256,
            ));
        }
        let staged = Path::new(planned.staged_destination.as_str());
        if let Some(parent) = staged.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                host_io_error("the staging directory could not be created", parent, &error)
            })?;
        }
        std::fs::write(staged, &source).map_err(|error| {
            host_io_error("the staged payload could not be written", staged, &error)
        })?;
    }
    Ok(())
}

/// One internal serialisation defect.
fn internal_serialisation(error: &serde_json::Error) -> AxiomError {
    AxiomError::new(
        ErrorCode::Internal,
        "the command output is not serialisable",
    )
    .with_detail("actual", error.to_string())
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Parse the `Commands:` block of a usage text into `(path, options)` pairs.
    ///
    /// This is deliberately a second, independent reader of the help text: it
    /// knows nothing about [`VERBS`], so comparing the two is a real drift check
    /// rather than a restatement of the table.
    fn parse_usage_commands(usage: &str) -> Vec<(Vec<String>, Vec<String>)> {
        let mut forms = Vec::new();
        let mut inside = false;
        for line in usage.lines() {
            if !inside {
                if line.trim_end() == "Commands:" {
                    inside = true;
                }
                continue;
            }
            if !line.starts_with("  ") {
                break;
            }
            let body = line.trim();
            let form = body.split("  ").next().unwrap_or_default().trim();
            let mut path = Vec::new();
            let mut options = Vec::new();
            for token in form.split_whitespace() {
                let token = token.trim_matches(|character: char| {
                    character == '[' || character == ']' || character == ','
                });
                if token.is_empty() || token.starts_with('<') {
                    continue;
                }
                if token.starts_with('-') {
                    if !GLOBAL_OPTIONS.contains(&token) {
                        options.push(String::from(token));
                    }
                } else {
                    path.push(String::from(token));
                }
            }
            forms.push((path, options));
        }
        forms
    }

    /// The declared path of one form, spelled as the usage text spells it.
    fn declared_path(form: &FormSpec) -> Vec<String> {
        let mut path = vec![String::from(form.verb)];
        path.extend(
            form.subcommands
                .iter()
                .map(|subcommand| String::from(*subcommand)),
        );
        path
    }

    /// Every declared form as `(path, options)`.
    fn declared_commands() -> Vec<(Vec<String>, Vec<String>)> {
        VERBS
            .iter()
            .map(|form| {
                let options = form
                    .options
                    .iter()
                    .map(|option| String::from(option.name))
                    .collect();
                (declared_path(form), options)
            })
            .collect()
    }

    /// A value that satisfies validation for one option.
    fn sample_value(name: &str) -> String {
        match name {
            "--approve-digest" => "a".repeat(64),
            "--to-layout" => String::from("2"),
            "--host" => String::from("codex"),
            "--hosts" => String::from("codex,gemini"),
            "--from" => String::from("auto"),
            "--component" => String::from("axiom-graphd"),
            "--solution" => String::from("solution-1"),
            "--bundle" => String::from("signed-bundle.zip"),
            "--plan" => String::from("install-plan.json"),
            "--out" => String::from("out.json"),
            "--transaction" => String::from("transaction-1"),
            "--to" => String::from("latest-compatible"),
            _ => String::from("value"),
        }
    }

    /// A valid argv for one form, optionally with the machine-readable switch.
    fn sample_argv(form: &FormSpec, json: bool) -> Vec<String> {
        let mut argv = vec![String::from(form.verb)];
        argv.extend(
            form.subcommands
                .iter()
                .map(|subcommand| String::from(*subcommand)),
        );
        for option in form.options {
            argv.push(String::from(option.name));
            if option.takes_value {
                argv.push(sample_value(option.name));
            }
        }
        if json {
            argv.push(String::from("--json"));
        }
        argv
    }

    /// Parse stdout as exactly one JSON object, as section 1 requires.
    fn single_json_object(bytes: &[u8]) -> serde_json::Value {
        let text = String::from_utf8(bytes.to_vec()).expect("stdout is UTF-8");
        let trimmed = text.trim_end_matches(['\n', '\r']);
        assert_eq!(
            trimmed.lines().count(),
            1,
            "stdout must hold exactly one JSON line, got {trimmed:?}"
        );
        serde_json::from_str(trimmed).expect("stdout is one JSON object")
    }

    /// Run one argv through the real parser and the real sinks.
    fn run_argv(argv: &[String]) -> (ExitCode, String, String) {
        let invocation = parse(argv);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(&invocation, &mut stdout, &mut stderr);
        (
            code,
            String::from_utf8(stdout).expect("stdout is UTF-8"),
            String::from_utf8(stderr).expect("stderr is UTF-8"),
        )
    }

    #[test]
    fn advertised_commands_match_the_dispatcher_in_both_directions() {
        let advertised = parse_usage_commands(USAGE);
        let declared = declared_commands();
        let advertised_paths: Vec<Vec<String>> =
            advertised.iter().map(|(path, _)| path.clone()).collect();
        let declared_paths: Vec<Vec<String>> =
            declared.iter().map(|(path, _)| path.clone()).collect();

        assert_eq!(
            advertised_paths, declared_paths,
            "--help must list exactly the declared forms, in dispatcher order"
        );
        for path in &declared_paths {
            assert!(
                advertised_paths.contains(path),
                "the dispatcher declares {path:?}, but --help never advertises it"
            );
        }
        for path in &advertised_paths {
            assert!(
                declared_paths.contains(path),
                "--help advertises {path:?}, but the dispatcher cannot reach it"
            );
        }
    }

    #[test]
    fn advertised_options_match_the_dispatcher_in_both_directions() {
        let advertised = parse_usage_commands(USAGE);
        let declared = declared_commands();
        assert_eq!(
            advertised, declared,
            "--help must list exactly each form's declared options"
        );
        for (path, options) in &declared {
            let shown = advertised
                .iter()
                .find(|(advertised_path, _)| advertised_path == path)
                .expect("the path was just asserted present");
            assert_eq!(
                &shown.1, options,
                "--help and the dispatcher disagree about {path:?}"
            );
        }
    }

    #[test]
    fn every_advertised_form_is_dispatchable() {
        for form in VERBS {
            let argv = sample_argv(form, false);
            let invocation = parse(&argv);
            if let Command::Rejected { error } = invocation.command() {
                panic!(
                    "{} must be dispatchable, but argv {argv:?} was rejected: {error}",
                    form.path()
                );
            }
            if let Command::Slice { form: resolved, .. } = invocation.command() {
                assert_eq!(
                    resolved.path(),
                    form.path(),
                    "argv {argv:?} resolved to the wrong form"
                );
            }
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let code = run(&invocation, &mut stdout, &mut stderr);
            if form.not_ready.is_some() {
                assert_eq!(
                    code,
                    ExitCode::NotReady,
                    "{} must stay not ready",
                    form.path()
                );
                assert!(stdout.is_empty(), "{} must print no payload", form.path());
                continue;
            }
            // A composed form is reachable from argv, but its sample argv
            // cannot satisfy the inputs the form really needs: `install plan`
            // is handed a relative bundle directory and `install apply` a plan
            // file that does not exist. Refusing those is correct behaviour, so
            // the honest contract is: succeed, or refuse with a real failure
            // code, and never fabricate a payload.
            match code {
                ExitCode::Success => {}
                ExitCode::Validation | ExitCode::NotFound | ExitCode::Authorization => {
                    assert!(
                        stdout.is_empty(),
                        "{} refused as {code:?}, so it must print no payload",
                        form.path()
                    );
                    assert!(
                        !stderr.is_empty(),
                        "{} refused as {code:?}, so it must state why on stderr",
                        form.path()
                    );
                }
                // A composed form may also refuse as `NotReady` when the
                // host's own prerequisite matrix blocks the run: the module
                // doc of `install::ecosystem` places `prerequisite_refusal`
                // *before* the bundle is read, so a host without Python 3.13
                // legitimately cannot produce a plan. That is a stated refusal
                // from a real probe, not the empty fallback this test exists to
                // forbid, so it is accepted only when it names the prerequisite
                // the form reported.
                ExitCode::NotReady => {
                    assert!(
                        stdout.is_empty(),
                        "{} refused as {code:?}, so it must print no payload",
                        form.path()
                    );
                    let text = String::from_utf8_lossy(&stderr);
                    assert!(
                        text.contains("prerequisite"),
                        "{} is declared composed, so its only NotReady is the host prerequisite matrix; observed: {text}",
                        form.path()
                    );
                }
                other => panic!(
                    "{} is dispatchable but answered {other:?} for argv {argv:?}",
                    form.path()
                ),
            }
        }
    }

    #[test]
    fn unbuilt_slices_answer_not_ready_with_a_stated_reason() {
        let mut unbuilt = 0;
        for form in VERBS {
            let Some(reason) = form.not_ready else {
                continue;
            };
            unbuilt += 1;
            assert!(
                !reason.trim().is_empty(),
                "{} must state why it is unbuilt",
                form.path()
            );

            let (code, stdout, stderr) = run_argv(&sample_argv(form, false));
            assert_eq!(code, ExitCode::NotReady, "{} must not succeed", form.path());
            assert!(
                stdout.is_empty(),
                "text mode must print no payload for {}",
                form.path()
            );
            assert!(
                stderr.contains(reason),
                "{} must state its reason on stderr, got {stderr:?}",
                form.path()
            );

            let (code, stdout, stderr) = run_argv(&sample_argv(form, true));
            assert_eq!(code, ExitCode::NotReady, "{} must not succeed", form.path());
            assert_eq!(
                single_json_object(stdout.as_bytes())["code"],
                "NOT_READY",
                "{} must never become a success envelope",
                form.path()
            );
            assert!(!stderr.is_empty());
        }
        assert!(unbuilt > 0, "this build must still have unbuilt forms");
    }

    #[test]
    fn pending_verbs_match_the_declared_surface() {
        let mut unbuilt: Vec<&str> = VERBS
            .iter()
            .filter(|form| form.not_ready.is_some())
            .map(|form| form.verb)
            .collect();
        unbuilt.sort_unstable();
        unbuilt.dedup();
        let mut declared = PENDING_VERBS.to_vec();
        declared.sort_unstable();
        assert_eq!(
            unbuilt, declared,
            "PENDING_VERBS must name exactly the verbs whose forms are unbuilt"
        );
    }

    #[test]
    fn invalid_arguments_are_rejected_with_the_validation_exit_code() {
        let cases: &[(&str, &[&str])] = &[
            ("an unknown verb", &["frobnicate"]),
            ("a verb with no subcommand", &["install"]),
            ("an unknown subcommand", &["install", "frobnicate"]),
            ("an option with no value", &["install", "plan", "--bundle"]),
            (
                "an option whose value is another option",
                &["install", "plan", "--bundle", "--out", "plan.json"],
            ),
            (
                "an option the form does not declare",
                &["install", "plan", "--bundle", "b.zip", "--all"],
            ),
            (
                "a repeated value option",
                &["install", "plan", "--bundle", "a.zip", "--bundle", "b.zip"],
            ),
            (
                "an unknown option after a valid form",
                &["install", "plan", "--bundle", "b.zip", "--nope"],
            ),
            ("--all with no command", &["--all"]),
            (
                "a stray argument after a valid form",
                &["install", "plan", "--bundle", "b.zip", "stray"],
            ),
            ("a missing required option", &["service", "start"]),
            (
                "a malformed approval digest",
                &[
                    "migrate",
                    "apply",
                    "--plan",
                    "plan.json",
                    "--approve-digest",
                    "not-a-digest",
                ],
            ),
            (
                "a non-numeric layout",
                &[
                    "migrate",
                    "plan",
                    "--solution",
                    "solution-1",
                    "--to-layout",
                    "two",
                ],
            ),
            (
                "an unknown host",
                &["host", "configure", "--host", "not-a-host"],
            ),
            (
                "an unknown host in a list",
                &[
                    "bootstrap",
                    "plan",
                    "--solution",
                    "solution-1",
                    "--hosts",
                    "codex,nope",
                ],
            ),
        ];
        for (description, argv) in cases {
            let arguments: Vec<String> = argv
                .iter()
                .map(|argument| String::from(*argument))
                .collect();
            let invocation = parse(&arguments);
            if let Command::Rejected { error } = invocation.command() {
                assert_eq!(
                    error.exit_code(),
                    ExitCode::Validation,
                    "{description} must be a validation error"
                );
            } else {
                panic!(
                    "{description} must be rejected, got {:?}",
                    invocation.command()
                );
            }

            let (code, stdout, stderr) = run_argv(&arguments);
            assert_eq!(code, ExitCode::Validation, "{description} must exit 2");
            assert!(
                stdout.is_empty(),
                "{description} must not write a text payload"
            );
            assert!(
                !stderr.is_empty(),
                "{description} must explain itself on stderr"
            );

            let mut json = arguments.clone();
            json.push(String::from("--json"));
            let (code, stdout, stderr) = run_argv(&json);
            assert_eq!(
                code,
                ExitCode::Validation,
                "{description} must exit 2 in JSON mode"
            );
            assert_eq!(
                single_json_object(stdout.as_bytes())["code"],
                "VALIDATION_ERROR",
                "{description} must emit one validation envelope"
            );
            assert!(!stderr.is_empty());
        }
    }

    #[test]
    fn oversized_and_boundary_values_stay_honest() {
        let oversized = "x".repeat(MAX_TOKEN_BYTES + 1);
        let argv = [
            String::from("install"),
            String::from("plan"),
            String::from("--bundle"),
            oversized,
        ];
        let (code, stdout, stderr) = run_argv(&argv);
        assert_eq!(code, ExitCode::Validation);
        assert!(stdout.is_empty());
        assert!(stderr.contains("--bundle"));

        let boundary = "y".repeat(MAX_TOKEN_BYTES);
        let argv = [
            String::from("install"),
            String::from("plan"),
            String::from("--bundle"),
            boundary,
            String::from("--out"),
            String::from("plan.json"),
        ];
        let (code, stdout, stderr) = run_argv(&argv);
        // Exactly at the bound is accepted by the bound itself, so the form is
        // then composed for real. It probes before it writes, so on a host whose
        // prerequisite matrix blocks the run the refusal is `NotReady` and names
        // the unsatisfied prerequisite; where the matrix passes it refuses the
        // relative bundle root with the validation code. Either way it must not
        // invent a plan for a path an operator never named acceptably.
        assert!(stdout.is_empty(), "a refused plan must print no payload");
        assert!(!stderr.is_empty(), "a refused plan must state why");
        match code {
            ExitCode::Validation => assert!(
                stderr.contains("--bundle"),
                "a validation refusal must name the option it rejected"
            ),
            ExitCode::NotReady => assert!(
                stderr.contains("prerequisite"),
                "the only NotReady for this form is the host prerequisite matrix"
            ),
            other => panic!("the boundary bundle path answered {other:?}"),
        }

        // A missing required option is the same validation code as a bad flag.
        let argv = [String::from("support-bundle"), String::from("--redact")];
        let (code, _, stderr) = run_argv(&argv);
        assert_eq!(code, ExitCode::Validation);
        assert!(stderr.contains("--out"));
    }

    #[test]
    fn implemented_verbs_keep_their_behaviour() {
        let bare: Vec<String> = Vec::new();
        assert_eq!(parse(&bare).command(), &Command::Help);

        let (code, stdout, stderr) = run_argv(&[String::from("--help")]);
        assert_eq!(code, ExitCode::Success);
        assert!(stdout.contains("Usage: axiom <command> [options]"));
        assert!(stdout.contains("2  validation"));
        assert!(stderr.is_empty());

        let (code, stdout, stderr) = run_argv(&[String::from("version"), String::from("--json")]);
        assert_eq!(code, ExitCode::Success);
        assert_eq!(single_json_object(stdout.as_bytes())["component"], "axiom");
        assert!(stderr.is_empty());

        let (code, stdout, _) = run_argv(&[
            String::from("version"),
            String::from("--all"),
            String::from("--json"),
        ]);
        assert_eq!(code, ExitCode::Success);
        assert_eq!(
            single_json_object(stdout.as_bytes())["components"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );

        let (code, stdout, _) = run_argv(&[String::from("version"), String::from("--all")]);
        assert_eq!(code, ExitCode::Success);
        assert_eq!(stdout.lines().count(), 2);
    }

    #[test]
    fn the_drift_guard_notices_a_missing_and_an_extra_command() {
        let declared = declared_commands();
        let lines: Vec<&str> = USAGE.lines().collect();

        let mut missing = lines.clone();
        missing.retain(|line| !line.contains("migrate status"));
        assert_ne!(
            parse_usage_commands(&missing.join("\n")),
            declared,
            "dropping a command from the usage text must be noticed"
        );

        let mut extra = lines.clone();
        let index = extra
            .iter()
            .position(|line| line.trim_end() == "Commands:")
            .expect("USAGE has a Commands: block")
            + 1;
        extra.insert(
            index,
            "  frobnicate --now  a command the dispatcher does not know",
        );
        assert_ne!(
            parse_usage_commands(&extra.join("\n")),
            declared,
            "adding an undeclared command to the usage text must be noticed"
        );

        // The unmodified text must still match, so the guard is not vacuous.
        assert_eq!(parse_usage_commands(USAGE), declared);
    }

    /// Payloads the composed `axiom install` tests assemble, with every digest
    /// computed from the bytes rather than written down.
    const CLI_GRAPHD: &[u8] = b"the axiom-graphd binary payload (cli binding)";
    const CLI_MCP: &[u8] = b"the axiom-mcp wheel payload (cli binding)";
    const CLI_SKILL: &[u8] = b"# Axiom skill instructions (cli binding)\n";
    const CLI_SKILL_PATH: &str = "instructions/axiom.md";
    const CLI_GRAPHD_ARTIFACT: &str = "bin/axiom-graphd";
    const CLI_MCP_ARTIFACT: &str = "python/axiom_mcp-0.0.0.dev0-py3-none-any.whl";
    const CLI_VERSION: &str = "0.0.0-dev";
    const CLI_CREATED_AT: &str = "2026-09-20T00:00:00Z";

    /// Write one three-component bundle tree the composed forms can plan from.
    fn cli_bundle() -> (tempfile::TempDir, String) {
        use crate::install::plan::{
            ArtifactKind, BundleComponent, BundleManifest, BUNDLE_MANIFEST_FILE,
            BUNDLE_SCHEMA_VERSION,
        };
        use crate::skills::install::{DeclaredEntry, SkillBundle, MANIFEST_FILE};

        let host = host_identifier();
        let directory = tempfile::TempDir::new().expect("bundle tempdir");
        let root = directory.path();
        let component =
            |name: &str, artifact: &str, kind: ArtifactKind, payload: &[u8]| BundleComponent {
                component: name.to_string(),
                version: CLI_VERSION.to_string(),
                host: host.clone(),
                artifact: artifact.to_string(),
                kind,
                sha256: graph_export::sha256_hex(payload),
                size_bytes: payload.len() as u64,
                permissions: vec!["read".to_string()],
                service: None,
                network_access: Vec::new(),
            };
        let manifest = BundleManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            bundle_id: "axiom-core".to_string(),
            channel: "stable".to_string(),
            created_at: CLI_CREATED_AT.to_string(),
            components: vec![
                component(
                    "axiom-graphd",
                    CLI_GRAPHD_ARTIFACT,
                    ArtifactKind::Binary,
                    CLI_GRAPHD,
                ),
                component("axiom-mcp", CLI_MCP_ARTIFACT, ArtifactKind::Python, CLI_MCP),
            ],
        };
        for (artifact, payload) in [
            (CLI_GRAPHD_ARTIFACT, CLI_GRAPHD),
            (CLI_MCP_ARTIFACT, CLI_MCP),
        ] {
            let path = root.join(artifact);
            std::fs::create_dir_all(path.parent().expect("payload parent"))
                .expect("payload directory");
            std::fs::write(&path, payload).expect("core payload");
        }
        std::fs::write(
            root.join(BUNDLE_MANIFEST_FILE),
            serde_json::to_vec(&manifest).expect("manifest json"),
        )
        .expect("core manifest written");

        let skills_root = root.join(SKILLS_DIRECTORY);
        let payload_root = skills_root.join(SKILLS_PAYLOAD_DIRECTORY);
        std::fs::create_dir_all(payload_root.join("instructions")).expect("skills directory");
        let entry = DeclaredEntry::new(
            CLI_SKILL_PATH,
            "instruction",
            graph_export::sha256_hex(CLI_SKILL),
            CLI_SKILL.len() as u64,
        );
        let skills = SkillBundle::new(CLI_VERSION, "a".repeat(40), "b".repeat(40), vec![entry]);
        std::fs::write(
            skills_root.join(MANIFEST_FILE),
            skills.manifest_bytes().expect("skills manifest"),
        )
        .expect("skills manifest written");
        std::fs::write(payload_root.join(CLI_SKILL_PATH), CLI_SKILL).expect("skill payload");

        let path = root.to_string_lossy().into_owned();
        (directory, path)
    }

    /// The composed operator surface: plan, apply, re-run, and refuse.
    #[test]
    fn composed_install_plans_applies_and_re_runs_idempotently() {
        use crate::install::ecosystem::{
            EcosystemProbe, PrerequisiteDeclaration, PrerequisiteObservation, PrerequisiteStatus,
            SatisfiedProbe, INSTALL_ORDER,
        };

        /// Reports one declared row undecided, so the plan must refuse it.
        struct RefusingProbe;

        impl EcosystemProbe for RefusingProbe {
            fn observe(&self, row: &PrerequisiteDeclaration) -> PrerequisiteObservation {
                if row.component == "axiom-mcp" && row.class.as_str() == "interpreter" {
                    return PrerequisiteObservation {
                        status: PrerequisiteStatus::Unknown,
                        observed: "the cli fixture could not decide this row".to_string(),
                    };
                }
                SatisfiedProbe.observe(row)
            }
        }

        let (_bundle_dir, bundle_root) = cli_bundle();
        let install_dir = tempfile::TempDir::new().expect("install tempdir");
        let out_dir = tempfile::TempDir::new().expect("plan tempdir");
        let install_root = install_dir.path().to_string_lossy().into_owned();
        let plan_file = out_dir.path().join("install-plan.json");
        let plan_file_arg = plan_file.to_string_lossy().into_owned();

        // Clause 3: one plan covering all three components in contract order,
        // behind one digest, written to the file the operator named.
        let text = plan_with_probe(
            &SatisfiedProbe,
            &bundle_root,
            Some(&plan_file_arg),
            false,
            &install_root,
            "install-cli-0001",
            CLI_CREATED_AT,
        )
        .expect("the composed plan succeeds");
        assert!(
            text.contains("axiom install plan install-cli-0001"),
            "{text}"
        );
        assert!(text.contains(&plan_file_arg), "{text}");

        let document: EcosystemPlan =
            serde_json::from_slice(&std::fs::read(&plan_file).expect("the plan file was written"))
                .expect("the plan file is one ecosystem plan");
        assert_eq!(
            document.install_order,
            INSTALL_ORDER
                .iter()
                .map(|component| (*component).to_string())
                .collect::<Vec<String>>(),
            "one plan covers every component in contract order"
        );
        let digest = document.plan_digest.clone();
        assert_eq!(digest.len(), 64, "one 64-hex approval digest");

        // Machine-readable mode is still one JSON object on stdout.
        let envelope = plan_with_probe(
            &SatisfiedProbe,
            &bundle_root,
            Some(&plan_file_arg),
            true,
            &install_root,
            "install-cli-0002",
            CLI_CREATED_AT,
        )
        .expect("the composed plan succeeds in JSON mode");
        let value = single_json_object(envelope.as_bytes());
        assert_eq!(value["status"], "planned");
        assert_eq!(value["plan_digest"].as_str().map(str::len), Some(64));

        // Clause 4: the approved plan installs, and a re-run rewrites nothing.
        let applied = apply_plan_document(
            &document,
            &digest,
            false,
            "ecosystem-cli-0001",
            CLI_CREATED_AT,
        )
        .expect("the approved plan applies");
        assert!(applied.contains("status=installed"), "{applied}");

        let child = embedded_core_plan(&document.component_plans[0]).expect("embedded plan");
        let destination = child.components[0].destination.clone();
        let installed = std::fs::read(&destination).expect("the planned payload is installed");
        assert_eq!(
            installed, CLI_GRAPHD,
            "the planned bytes landed at the planned path"
        );

        let re_run = apply_plan_document(
            &document,
            &digest,
            false,
            "ecosystem-cli-0002",
            CLI_CREATED_AT,
        )
        .expect("the re-run reports already-installed");
        assert!(re_run.contains("status=already-installed"), "{re_run}");
        assert_eq!(
            std::fs::read(&destination).expect("still installed"),
            installed,
            "the re-run rewrote nothing"
        );

        // Clauses 1 and 2: a blocking prerequisite refuses before a byte is
        // written and names the row it refused.
        let refused_plan = out_dir.path().join("refused-plan.json");
        let refused_arg = refused_plan.to_string_lossy().into_owned();
        let refusal = plan_with_probe(
            &RefusingProbe,
            &bundle_root,
            Some(&refused_arg),
            false,
            &install_root,
            "install-cli-0003",
            CLI_CREATED_AT,
        )
        .expect_err("an undecided prerequisite must refuse");
        assert_eq!(refusal.exit_code(), ExitCode::NotReady);
        assert!(
            refusal.to_string().contains("axiom-mcp/interpreter"),
            "{refusal}"
        );
        assert!(
            !refused_plan.exists(),
            "a refused plan must not write the file the operator named"
        );

        // A stale or wrong approval digest never mutates the host.
        let stale = apply_plan_document(
            &document,
            &"c".repeat(64),
            false,
            "ecosystem-cli-0003",
            CLI_CREATED_AT,
        )
        .expect_err("a wrong approval digest must refuse");
        assert_eq!(stale.exit_code(), ExitCode::Authorization);
        assert!(stale.to_string().contains("not approved"), "{stale}");

        // Supplying `--plan` without `--approve-digest` is not approval.
        let unapproved = apply_installation(&plan_file_arg, None, false)
            .expect_err("an unbound apply must refuse");
        assert_eq!(unapproved.exit_code(), ExitCode::Authorization);
        assert!(
            unapproved.to_string().contains("not approval"),
            "{unapproved}"
        );
    }
}
