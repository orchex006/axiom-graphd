//! The `axiom` command line: argv in, one JSON object out (task E-001).
//!
//! `docs/16-CLI-AND-CONTROL-API.md` fixes the shape of this layer: every command
//! has `--help`, machine-readable mode writes exactly one JSON object to stdout
//! with diagnostics on stderr, and invalid flags are an error rather than
//! silently ignored. Exit codes are the frozen table of section 6, rendered from
//! [`ExitCode`] so help text and process status cannot drift apart.
//!
//! Commands that belong to later installation work packages are recognised and
//! report [`ErrorCode::NotReady`] with an explicit reason, so an unimplemented
//! documented command is never misreported as a typo.

use std::io::Write;

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::redact;
use serde::{Deserialize, Serialize};

pub use graph_core::error::ExitCode;

use crate::version::VersionReport;

/// Exit code that a successful command returns.
pub const SUCCESS: ExitCode = ExitCode::Success;

/// Usage text without the exit-code table.
pub const USAGE: &str = "\
axiom - Axiom installation, bootstrap and operations CLI

Usage: axiom <command> [options]

Commands:
  version [--all] [--json]   print component and build versions
  help, --help               print this help

Options:
  --all     report every component of this core release
  --json    write exactly one JSON object to stdout; diagnostics go to stderr

Exit codes:
";

/// Top-level verbs of `docs/16-CLI-AND-CONTROL-API.md` section 4 that a later
/// installation work package implements. Recognising them here keeps the
/// distinction between "not built yet" and "not a command" honest.
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
    /// A documented command of a later work package; not built yet.
    Pending {
        /// The documented verb that is not implemented by this build.
        verb: String,
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
    let rejected = |message: String| Invocation {
        command: Command::Rejected {
            error: AxiomError::new(ErrorCode::ValidationError, message),
        },
        json,
    };

    let mut positionals: Vec<&str> = Vec::new();
    let mut unknown_options: Vec<String> = Vec::new();
    let mut all = false;
    for argument in arguments {
        match argument.as_str() {
            "--json" => {}
            "--all" => all = true,
            "--help" | "-h" => positionals.push("help"),
            "--version" | "-V" => positionals.push("version"),
            other if other.starts_with('-') => unknown_options.push(String::from(other)),
            other => positionals.push(other),
        }
    }

    let command = if let Some(verb) = positionals.first().copied() {
        if PENDING_VERBS.contains(&verb) {
            Command::Pending {
                verb: String::from(verb),
            }
        } else if let Some(option) = unknown_options.first() {
            return rejected(format!("unrecognised option: {option}"));
        } else {
            match positionals.as_slice() {
                ["help"] => Command::Help,
                ["version"] => Command::Version { all },
                [other] => return rejected(format!("unrecognised command: {other}")),
                _ => return rejected(String::from("expected exactly one command")),
            }
        }
    } else if let Some(option) = unknown_options.first() {
        return rejected(format!("unrecognised option: {option}"));
    } else {
        Command::Help
    };

    if all && !matches!(command, Command::Version { .. }) {
        return rejected(String::from("--all is only valid for the version command"));
    }
    Invocation { command, json }
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
                AxiomError::new(ErrorCode::Internal, "the version report is not serialisable")
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
        Command::Pending { verb } => Err(AxiomError::new(
            ErrorCode::NotReady,
            format!(
                "the {verb} command is not implemented by this build; it belongs to a later installation work package"
            ),
        )),
    }
}
