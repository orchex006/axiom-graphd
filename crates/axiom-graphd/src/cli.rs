//! Foreground command line: argv in, one JSON object out (tasks B-001, B-002).
//!
//! docs/16-CLI-AND-CONTROL-API.md section 1 fixes the shape of this layer:
//! every command has `--help`, machine-readable mode writes exactly one JSON
//! object to stdout with diagnostics on stderr, invalid flags are an error
//! rather than silently ignored, argument paths arrive as argv (never as an
//! interpolated shell string), and exit codes are the frozen table from
//! section 6.
//!
//! Commands that belong to later work packages report [`ErrorCode::NotReady`]
//! with an explicit reason instead of pretending to succeed. `serve` still
//! takes the single-owner instance lock first, so the lock contract is exercised
//! end to end before the reconcile loop exists.

use std::io::Write;
use std::path::PathBuf;

use graph_core::config::ServiceConfig;
use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{AxiomHome, PathEnvironment};

pub use graph_core::error::ExitCode;

use crate::instance_lock::DaemonLock;
use crate::telemetry::Telemetry;
use crate::version::VersionOutput;

/// Exit code that a successful command returns.
pub const SUCCESS: ExitCode = ExitCode::Success;

/// Usage text without the exit-code table.
pub const USAGE: &str = "\
axiom-graphd - Axiom graph engine daemon

Usage: axiom-graphd <command> [options]

Commands:
  serve [--registry <path>] [--json]   run the foreground daemon
  version [--json]                     print component, build and runtime versions
  doctor [--json]                      print diagnostics (never repairs automatically)
  help, --help                         print this help

Options:
  --json    write exactly one JSON object to stdout; diagnostics go to stderr

Exit codes:
";

/// The frozen exit-code table, rendered from [`ExitCode`] itself.
///
/// The table is generated from the same value that produces the process exit
/// status, so `--help` can never drift from the enforced contract.
#[must_use]
pub fn exit_code_table() -> String {
    let mut table = String::new();
    for code in ExitCode::all() {
        table.push_str(&format!("  {}  {}\n", code.as_i32(), code.meaning()));
    }
    table
}

/// The frozen exit list in the exact token order of `axiom-specs`
/// `docs/16-CLI-AND-CONTROL-API.md` section 6, for the CLI reference document.
///
/// The string is generated from [`ExitCode::all()`] so the specification line
/// and the enforced exit status stay one artefact; `docs/CLI-EXIT-CODES.md`
/// quotes it verbatim.
#[must_use]
pub fn exit_code_summary() -> String {
    ExitCode::all()
        .iter()
        .map(|code| format!("{} {}", code.as_i32(), code.meaning()))
        .collect::<Vec<_>>()
        .join(", ")
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
    /// Run the foreground daemon.
    Serve {
        /// Explicit `--registry <path>` value.
        registry: Option<PathBuf>,
    },
    /// Print version and build information.
    Version,
    /// Print diagnostics.
    Doctor,
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
    let mut registry: Option<PathBuf> = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        match argument {
            "--json" => {}
            "--help" | "-h" => positionals.push("help"),
            "--version" | "-V" => positionals.push("version"),
            "--registry" => {
                let Some(value) = arguments.get(index + 1) else {
                    return rejected(String::from("--registry requires a path argument"));
                };
                if value.starts_with('-') {
                    return rejected(String::from("--registry requires a path argument"));
                }
                registry = Some(PathBuf::from(value));
                index += 1;
            }
            other if other.starts_with('-') => {
                return rejected(format!("unrecognised option: {other}"));
            }
            other => positionals.push(other),
        }
        index += 1;
    }

    let registry_supplied = registry.is_some();
    let command = match positionals.as_slice() {
        [] => Command::Help,
        ["help"] => Command::Help,
        ["version"] => Command::Version,
        ["doctor"] => Command::Doctor,
        ["serve"] => Command::Serve { registry },
        [other] => {
            return rejected(format!("unrecognised command: {other}"));
        }
        _ => {
            return rejected(String::from("expected exactly one command"));
        }
    };
    if registry_supplied && !matches!(command, Command::Serve { .. }) {
        return rejected(String::from(
            "--registry is only valid for the serve command",
        ));
    }
    Invocation { command, json }
}

/// Execute an invocation, writing stdout and diagnostics through the injected
/// sinks and returning the process exit code.
pub fn run(invocation: &Invocation, stdout: &mut dyn Write, telemetry: &mut Telemetry) -> ExitCode {
    match execute(invocation.command(), telemetry) {
        Ok(payload) => {
            let _ = writeln!(stdout, "{payload}");
            SUCCESS
        }
        Err(error) => report_failure(&error, invocation.json(), stdout, telemetry),
    }
}

/// Report a failure: the error envelope on stdout in JSON mode, a redacted
/// diagnostic on stderr always.
pub fn report_failure(
    error: &AxiomError,
    json: bool,
    stdout: &mut dyn Write,
    telemetry: &mut Telemetry,
) -> ExitCode {
    let _ = telemetry.record_error("axiom-graphd", error);
    if json {
        if let Ok(line) = error.to_json() {
            let _ = writeln!(stdout, "{line}");
        }
    }
    error.exit_code()
}

fn execute(command: &Command, telemetry: &mut Telemetry) -> Result<String, AxiomError> {
    match command {
        Command::Help => Ok(usage()),
        Command::Rejected { error } => Err(error.clone()),
        Command::Version => {
            let output = VersionOutput::current();
            serde_json::to_string(&output)
                .map_err(|_| AxiomError::new(ErrorCode::Internal, "the version report is not serialisable"))
        }
        Command::Doctor => Err(AxiomError::new(
            ErrorCode::NotReady,
            "doctor has no status sources in this build; the diagnostic inventory is implemented by a later work package",
        )),
        Command::Serve { registry } => {
            let home = AxiomHome::resolve(&PathEnvironment::for_current_process())?;
            home.verify_destination()?;
            let config = ServiceConfig::load(registry.as_deref())?;
            let lock = DaemonLock::acquire(&home, config.daemon().instance_id())?;
            let _ = telemetry.record(
                graph_core::config::LogLevel::Info,
                "daemon",
                "instance lock acquired; the reconcile worker loop is not part of this work package",
            );
            drop(lock);
            Err(AxiomError::new(
                ErrorCode::NotReady,
                "the reconcile worker loop is not part of this work package; the foreground daemon cannot serve yet",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{LevelFilter, LogLevel};
    use graph_core::error::exit_code_for;

    fn sink_telemetry() -> Telemetry {
        Telemetry::new(
            Box::new(std::io::sink()),
            LevelFilter::at_least(LogLevel::Info),
            120,
        )
    }

    fn argv(arguments: &[&str]) -> Vec<String> {
        arguments.iter().map(|value| String::from(*value)).collect()
    }

    #[test]
    fn commands_are_parsed_from_argv() {
        assert!(matches!(parse(&argv(&[])).command(), Command::Help));
        assert!(matches!(parse(&argv(&["help"])).command(), Command::Help));
        assert!(matches!(parse(&argv(&["--help"])).command(), Command::Help));
        assert!(matches!(
            parse(&argv(&["version", "--json"])).command(),
            Command::Version
        ));
        assert!(parse(&argv(&["version", "--json"])).json());
        assert!(!parse(&argv(&["--version"])).json());
        assert!(matches!(
            parse(&argv(&["doctor"])).command(),
            Command::Doctor
        ));
        assert!(matches!(
            parse(&argv(&["serve"])).command(),
            Command::Serve { registry: None }
        ));
        let serve = parse(&argv(&[
            "serve",
            "--json",
            "--registry",
            "cfg\\registry.json",
        ]));
        match serve.command() {
            Command::Serve { registry } => {
                assert_eq!(
                    registry.as_deref(),
                    Some(std::path::Path::new("cfg\\registry.json"))
                );
            }
            other => panic!("expected serve, got {other:?}"),
        }
        assert!(serve.json());
    }

    #[test]
    fn invalid_arguments_are_rejected_with_the_validation_exit_code() {
        for arguments in [
            vec!["--nope"],
            vec!["frobnicate"],
            vec!["version", "extra"],
            vec!["--registry"],
            vec!["version", "--registry", "x"],
            vec!["serve", "--registry"],
        ] {
            let invocation = parse(&argv(&arguments));
            match invocation.command() {
                Command::Rejected { error } => {
                    assert_eq!(error.code(), ErrorCode::ValidationError);
                    assert_eq!(error.exit_code(), ExitCode::Validation);
                }
                other => panic!("{arguments:?} must be rejected, got {other:?}"),
            }
        }
    }

    #[test]
    fn machine_readable_stdout_is_exactly_one_json_object() {
        let mut stdout: Vec<u8> = Vec::new();
        let mut telemetry = sink_telemetry();
        let invocation = parse(&argv(&["version", "--json"]));
        let code = run(&invocation, &mut stdout, &mut telemetry);
        assert_eq!(code, ExitCode::Success);
        let text = String::from_utf8(stdout).expect("utf-8");
        assert_eq!(text.lines().count(), 1, "stdout must be one line: {text}");
        let value: serde_json::Value = serde_json::from_str(text.trim()).expect("one JSON object");
        assert_eq!(value["component"], serde_json::Value::from("axiom-graphd"));
    }

    #[test]
    fn json_mode_error_output_has_no_diagnostic_prose() {
        let mut stdout: Vec<u8> = Vec::new();
        let mut telemetry = sink_telemetry();
        let invocation = parse(&argv(&["--nope", "--json"]));
        let code = run(&invocation, &mut stdout, &mut telemetry);
        assert_eq!(code, ExitCode::Validation);
        let text = String::from_utf8(stdout).expect("utf-8");
        assert_eq!(text.lines().count(), 1);
        let value: serde_json::Value = serde_json::from_str(text.trim()).expect("one JSON object");
        assert_eq!(value["code"], serde_json::Value::from("VALIDATION_ERROR"));
        assert!(!text.contains("src/"));
    }

    #[test]
    fn text_mode_errors_keep_stdout_empty() {
        let mut stdout: Vec<u8> = Vec::new();
        let mut telemetry = sink_telemetry();
        let invocation = parse(&argv(&["--nope"]));
        let code = run(&invocation, &mut stdout, &mut telemetry);
        assert_eq!(code, ExitCode::Validation);
        assert!(
            stdout.is_empty(),
            "diagnostics must not reach stdout in text mode"
        );
    }

    #[test]
    fn help_documents_the_frozen_exit_code_table() {
        let mut stdout: Vec<u8> = Vec::new();
        let mut telemetry = sink_telemetry();
        let invocation = parse(&argv(&["help"]));
        assert_eq!(
            run(&invocation, &mut stdout, &mut telemetry),
            ExitCode::Success
        );
        let text = String::from_utf8(stdout).expect("utf-8");
        for code in ExitCode::all() {
            let expected = format!("  {}  ", code.as_i32());
            assert!(text.contains(&expected), "help is missing {code}");
            assert!(
                text.contains(code.meaning()),
                "help is missing {code} meaning"
            );
        }
        assert!(!text.contains("  1  "), "exit code 1 stays unassigned");
    }

    /// The CLI reference document is part of the contract, not a copy of it:
    /// it is compiled into the test binary and checked against the generated
    /// table, so editing one side without the other fails the build.
    const CLI_EXIT_CODES_DOC: &str = include_str!("../../../docs/CLI-EXIT-CODES.md");

    #[test]
    fn cli_exit_code_doc_matches_the_frozen_contract() {
        let doc = CLI_EXIT_CODES_DOC;
        assert!(
            doc.contains("<!-- BEGIN GENERATED EXIT CODES -->")
                && doc.contains("<!-- END GENERATED EXIT CODES -->"),
            "the exit-code table must stay inside its generated markers"
        );
        for code in ExitCode::all() {
            let row = format!("| {} | {} |", code.as_i32(), code.meaning());
            assert!(doc.contains(&row), "exit-code doc is missing `{row}`");
        }
        assert!(
            doc.contains("| 1 | (unassigned) |"),
            "exit code 1 must stay documented as unassigned"
        );
        assert!(
            !doc.contains("| 1 | success |"),
            "exit code 1 must never be assigned"
        );
        for code in ErrorCode::all() {
            let row = format!("| {} | {} |", code.as_str(), exit_code_for(*code).as_i32());
            assert!(doc.contains(&row), "error-code doc is missing `{row}`");
        }
        let summary = exit_code_summary();
        assert!(
            doc.contains(&summary),
            "exit-code doc is missing the generated summary line:\n{summary}"
        );
    }
}
