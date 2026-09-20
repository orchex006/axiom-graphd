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

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::redact;
use serde::{Deserialize, Serialize};

pub use graph_core::error::ExitCode;

use crate::hosts::detect::HostKind;
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

/// Why the `install` forms are reachable but do no work yet.
const NOT_READY_INSTALL: &str = "the `crate::install` planner/apply slices are unit tested, but installing from the documented entrypoint is not composed in this build (task I-003 exposes the argv surface only)";
/// Why the `service` forms are reachable but do no work yet.
const NOT_READY_SERVICE: &str = "the `crate::service` adapters are unit tested, but installing or controlling an OS service from the documented entrypoint is not composed in this build (task I-003 exposes the argv surface only)";
/// Why the `bootstrap` forms are reachable but do no work yet.
const NOT_READY_BOOTSTRAP: &str = "the `crate::bootstrap` engine is unit tested, but bootstrapping a solution from the documented entrypoint is not composed in this build (task I-003 exposes the argv surface only)";
/// Why the `host` forms are reachable but do no work yet.
const NOT_READY_HOSTS: &str = "the `crate::hosts` detector is unit tested, but configuring a host client from the documented entrypoint is not composed in this build (task I-003 exposes the argv surface only)";
/// Why the `skills` forms are reachable but do no work yet.
const NOT_READY_SKILLS: &str = "the `crate::skills` engine is unit tested, but checking or updating skills from the documented entrypoint is not composed in this build (task I-003 exposes the argv surface only)";
/// Why the `specs` forms are reachable but do no work yet.
const NOT_READY_SPECS: &str = "the managed specification bundle slice is not composed into the `axiom` entrypoint in this build (task I-003 exposes the argv surface only)";
/// Why the `update` forms are reachable but do no work yet.
const NOT_READY_UPDATE: &str = "the `crate::update` engine is unit tested, but checking, applying or rolling back an update from the documented entrypoint is not composed in this build (task I-003 exposes the argv surface only)";
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
        not_ready: Some(NOT_READY_INSTALL),
    },
    FormSpec {
        verb: "install",
        subcommands: &["apply"],
        options: &[OPT_PLAN, OPT_APPROVE_DIGEST],
        not_ready: Some(NOT_READY_INSTALL),
    },
    FormSpec {
        verb: "service",
        subcommands: &["install"],
        options: &[OPT_COMPONENT, OPT_USER],
        not_ready: Some(NOT_READY_SERVICE),
    },
    FormSpec {
        verb: "service",
        subcommands: &["start"],
        options: &[OPT_COMPONENT],
        not_ready: Some(NOT_READY_SERVICE),
    },
    FormSpec {
        verb: "service",
        subcommands: &["stop"],
        options: &[OPT_COMPONENT],
        not_ready: Some(NOT_READY_SERVICE),
    },
    FormSpec {
        verb: "service",
        subcommands: &["status"],
        options: &[OPT_COMPONENT],
        not_ready: Some(NOT_READY_SERVICE),
    },
    FormSpec {
        verb: "service",
        subcommands: &["uninstall"],
        options: &[OPT_COMPONENT],
        not_ready: Some(NOT_READY_SERVICE),
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
        not_ready: Some(NOT_READY_UPDATE),
    },
    FormSpec {
        verb: "update",
        subcommands: &["plan"],
        options: &[OPT_TO, OPT_OUT],
        not_ready: Some(NOT_READY_UPDATE),
    },
    FormSpec {
        verb: "update",
        subcommands: &["apply"],
        options: &[OPT_PLAN, OPT_APPROVE_DIGEST],
        not_ready: Some(NOT_READY_UPDATE),
    },
    FormSpec {
        verb: "update",
        subcommands: &["rollback"],
        options: &[OPT_TRANSACTION],
        not_ready: Some(NOT_READY_UPDATE),
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
  update plan [--to <target>] [--out <file>]  plan a core update
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
    "install",
    "service",
    "bootstrap",
    "host",
    "skills",
    "specs",
    "update",
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

    match form.not_ready {
        Some(reason) => Ok(Command::Slice { form, reason }),
        None => match form.verb {
            "version" => Ok(Command::Version {
                all: seen.contains(&"--all"),
            }),
            "help" => Ok(Command::Help),
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
    }
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
            } else {
                assert_eq!(code, ExitCode::Success, "{} must succeed", form.path());
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

        // Exactly at the bound is accepted by the bound itself, so the form is
        // then honestly reported as unbuilt instead of rejected.
        let boundary = "y".repeat(MAX_TOKEN_BYTES);
        let argv = [
            String::from("install"),
            String::from("plan"),
            String::from("--bundle"),
            boundary,
            String::from("--out"),
            String::from("plan.json"),
        ];
        let (code, _, _) = run_argv(&argv);
        assert_eq!(code, ExitCode::NotReady);

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
}
