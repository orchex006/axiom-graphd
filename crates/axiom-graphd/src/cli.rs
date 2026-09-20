//! Foreground command line: argv in, one JSON object out (tasks B-001, B-002, H-001).
//!
//! docs/16-CLI-AND-CONTROL-API.md section 1 fixes the shape of this layer:
//! every command has `--help`, machine-readable mode writes exactly one JSON
//! object to stdout with diagnostics on stderr, invalid flags are an error
//! rather than silently ignored, argument paths arrive as argv (never as an
//! interpolated shell string), and exit codes are the frozen table from
//! section 6.
//!
//! Task H-001 wires the operator slices that own a module under
//! [`crate::commands`] into this surface. Each wired verb parses its own
//! options strictly, is listed by `--help`, and answers [`ErrorCode::NotReady`]
//! with a stated reason while its production behaviour is still unbuilt, so an
//! unbuilt slice is never reported as an empty success. `serve` still takes the
//! single-owner instance lock first, so the lock contract is exercised end to
//! end before the reconcile loop exists.

use std::io::Write;
use std::path::PathBuf;

use graph_core::config::ServiceConfig;
use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{AxiomHome, PathEnvironment};

pub use graph_core::error::ExitCode;

use crate::commands::{changed, doctor, query, queue, reconcile, solution, update};
use crate::instance_lock::DaemonLock;
use crate::telemetry::Telemetry;
use crate::version::VersionOutput;

/// Exit code that a successful command returns.
pub const SUCCESS: ExitCode = ExitCode::Success;

/// One operator slice that owns a module under `crates/axiom-graphd/src/commands/`.
///
/// The table is the argv surface of the slices wired by task H-001. The tests
/// below check it against `commands/mod.rs`, so a slice can never be declared
/// in one place and reachable from the other only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorSlice {
    /// Module name inside `crates/axiom-graphd/src/commands/`.
    pub module: &'static str,
    /// The argv verb that reaches the slice.
    pub verb: &'static str,
    /// The argv forms the verb accepts, as printed by `--help`.
    pub forms: &'static [&'static str],
    /// Why the slice cannot complete production work in this build.
    pub not_ready: &'static str,
}

/// Every operator slice reachable from argv, in `--help` order.
pub const OPERATOR_SLICES: &[OperatorSlice] = &[
    OperatorSlice {
        module: "changed",
        verb: "changed",
        forms: &[
            "changed --solution <id> --project <project> --path <repo-relative> --reason <manual|git|tool|reconcile> [--json]",
            "changed --solution <id> --from-json <changes.json> [--json]",
        ],
        not_ready: "the verified change-hint path has no open store binding in this build; the store binding is implemented by a later work package",
    },
    OperatorSlice {
        module: "queue",
        verb: "queue",
        forms: &[
            "queue list --solution <id> [--limit <n>] [--json]",
            "queue retry --job <id> [--json]",
            "queue cancel --job <id> [--json]",
        ],
        not_ready: "the operational queue has no open store in this build; the queue reader is implemented by a later work package",
    },
    OperatorSlice {
        module: "solution",
        verb: "solution",
        forms: &[
            "solution register --config <solution.yaml> [--bindings <bindings.json>] (--dry-run|--apply) [--json]",
            "solution list [--solution <id>] [--json]",
            "solution remove --solution <id> (--dry-run|--apply) [--json]",
        ],
        not_ready: "solution administration needs the user-owned registry write path that a later work package adds; this build writes no registry",
    },
    OperatorSlice {
        module: "doctor",
        verb: "doctor",
        forms: &["doctor [--solution <id>] [--json]"],
        not_ready: "doctor has no status sources in this build; the diagnostic inventory is implemented by a later work package",
    },
    OperatorSlice {
        module: "reconcile",
        verb: "reconcile",
        forms: &[
            "reconcile --solution <id> --scope dirty [--wait] [--timeout <ms|Ns>] [--json]",
            "reconcile --solution <id> --scope project --project <project> [--json]",
            "reconcile --solution <id> --scope full [--json]",
        ],
        not_ready: "the reconcile plan has no queue writer in this build; the queue writer is implemented by a later work package",
    },
    OperatorSlice {
        module: "query",
        verb: "query",
        forms: &[
            "query context --solution <id> (--symbol <name>|--node-id <id>) [--max-bytes <n>] [--max-nodes <n>] [--depth <n>] [--json]",
            "query impact --solution <id> (--symbol <name>|--node-id <id>) [--max-bytes <n>] [--max-nodes <n>] [--depth <n>] [--json]",
        ],
        not_ready: "bounded context and impact have no pinned snapshot source in this build; the snapshot binding is implemented by a later work package",
    },
    OperatorSlice {
        module: "update",
        verb: "update",
        forms: &[
            "update check [--json]",
            "update apply --plan <plan.json> [--approve-digest <sha256>] [--json]",
        ],
        not_ready: "delegated update apply has no trusted axiom CLI path in this build; the delegated launch is implemented by a later work package",
    },
];

/// Every verb `parse` accepts, in the order [`USAGE`] presents them.
///
/// This is the declared surface of the CLI: the CLI reference document and
/// `tools/check-doc-status.py` read this list, so a verb that is accepted but
/// undocumented, or documented but not accepted, is caught without either side
/// guessing at the parser's internal shape. The unit test
/// `accepted_verbs_match_the_parser_in_both_directions` proves the declaration
/// agrees with `parse`.
pub const ACCEPTED_VERBS: &[&str] = &[
    "help",
    "version",
    "serve",
    "doctor",
    "status",
    "solution",
    "changed",
    "reconcile",
    "queue",
    "query",
    "update",
];

/// Compile-time link from every operator slice to a real item of its module.
///
/// Deleting a `pub mod` from `commands/mod.rs` while its verb stays in argv
/// therefore fails to compile instead of leaving a stale verb behind.
#[must_use]
pub fn slice_links() -> Vec<(&'static str, String)> {
    vec![
        ("changed", changed::MAX_HINTS_PER_REQUEST.to_string()),
        ("queue", queue::DEFAULT_LIST_LIMIT.to_string()),
        ("solution", solution::MAX_SOLUTIONS.to_string()),
        ("doctor", String::from(doctor::REASON_CATALOG_MISSING)),
        ("reconcile", reconcile::DEFAULT_TIMEOUT_MS.to_string()),
        ("query", query::DEFAULT_MAX_BYTES.to_string()),
        ("update", String::from(update::AXIOM_PROGRAM)),
    ]
}

/// Why `status` is not ready: it is a verb of this surface with no owning module.
const REASON_STATUS_NOT_READY: &str =
    "status has no open store in this build; the status reader is implemented by a later work package";

/// Usage text without the operator-slice forms and the exit-code table.
pub const USAGE: &str = "\
axiom-graphd - Axiom graph engine daemon

Usage: axiom-graphd <command> [options]

Commands:
  serve [--registry <path>] [--json]   run the foreground daemon
  version [--json]                     print component, build and runtime versions
  doctor [--solution <id>] [--json]    print diagnostics (never repairs automatically)
  status --solution <id> [--json]      print queue, freshness and coverage state
  solution register|list|remove ...    administer the solution registry
  changed ...                          accept explicit changed-file hints
  reconcile ...                        request a bounded reconcile
  queue list|retry|cancel ...          inspect and steer the operational queue
  query context|impact ...             bounded context and impact over a pinned snapshot
  update check|apply ...               delegate to the trusted axiom CLI
  help, --help                         print this help

Options:
  --json    write exactly one JSON object to stdout; diagnostics go to stderr

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

/// Full usage text: [`USAGE`], the wired operator-slice forms, then the
/// generated exit-code table.
#[must_use]
pub fn usage() -> String {
    let mut text = String::from(USAGE);
    text.push_str("Operator slices (task H-001):\n");
    for slice in OPERATOR_SLICES {
        text.push_str(&format!("  {}\n", slice.verb));
        for form in slice.forms {
            text.push_str(&format!("      {form}\n"));
        }
    }
    text.push_str("\nExit codes:\n");
    text.push_str(&exit_code_table());
    text
}

/// Plan/apply mode for the mutating registry and update verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanMode {
    /// Validate and report only.
    DryRun,
    /// Persist the change.
    Apply,
}

/// Reconcile scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Reconcile the dirty closure.
    Dirty,
    /// Reconcile one explicit project.
    Project,
    /// Reconcile the whole solution.
    Full,
}

/// Symbol selector for the query verbs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// Select by symbol name.
    Symbol(String),
    /// Select by node id.
    NodeId(String),
}

/// Bounded query limits, already validated against the query module bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueryLimits {
    /// Maximum response bytes, when the caller set one.
    pub max_bytes: Option<usize>,
    /// Maximum node count, when the caller set one.
    pub max_nodes: Option<usize>,
    /// Traversal depth, when the caller set one.
    pub depth: Option<u32>,
}

/// Solution registry administration (task B-084).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolutionCommand {
    /// `solution register`.
    Register {
        /// Portable solution configuration path.
        config: PathBuf,
        /// Optional local bindings document.
        bindings: Option<PathBuf>,
        /// Plan or apply.
        mode: PlanMode,
    },
    /// `solution list`.
    List {
        /// Optional single-solution scope.
        solution: Option<String>,
    },
    /// `solution remove`.
    Remove {
        /// Solution to stop tracking.
        solution: String,
        /// Plan or apply.
        mode: PlanMode,
    },
}

/// Changed-file hints (task B-032).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangedCommand {
    /// One explicit hint.
    Hint {
        /// Solution id.
        solution: String,
        /// Project id inside the solution.
        project: String,
        /// Repository-relative forward-slash path.
        path: String,
        /// One of the changed module's known reasons.
        reason: String,
    },
    /// A bounded batch document.
    Batch {
        /// Solution id.
        solution: String,
        /// Hint document path.
        from_json: PathBuf,
    },
}

/// The bounded reconcile request (task B-086).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileCommand {
    /// One reconcile request.
    Request {
        /// Solution id.
        solution: String,
        /// Dirty, project or full.
        scope: Scope,
        /// Required with [`Scope::Project`], rejected otherwise.
        project: Option<String>,
        /// Whether the caller asked for the bounded publication barrier.
        wait: bool,
        /// Bounded wait budget in milliseconds.
        timeout_ms: Option<u64>,
    },
}

/// Operational queue verbs (task B-043).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueCommand {
    /// `queue list`.
    List {
        /// Solution id.
        solution: String,
        /// Page size, within the queue module bounds.
        limit: Option<usize>,
    },
    /// `queue retry`.
    Retry {
        /// Job id.
        job: String,
    },
    /// `queue cancel`.
    Cancel {
        /// Job id.
        job: String,
    },
}

/// Bounded query verbs (task B-087).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryCommand {
    /// Contract context projection.
    Context {
        /// Solution id.
        solution: String,
        /// Symbol or node-id selector.
        selector: Selector,
        /// Bounded limits.
        limits: QueryLimits,
    },
    /// Bounded reverse impact.
    Impact {
        /// Solution id.
        solution: String,
        /// Symbol or node-id selector.
        selector: Selector,
        /// Bounded limits.
        limits: QueryLimits,
    },
}

/// Delegated update verbs (task B-092).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateCommand {
    /// `update check`.
    Check,
    /// `update apply`.
    Apply {
        /// Canonical plan path.
        plan: PathBuf,
        /// Approval digest bound to that exact plan.
        approve_digest: Option<String>,
    },
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
    /// Print diagnostics for the whole instance or one solution.
    Doctor {
        /// Optional solution scope.
        solution: Option<String>,
    },
    /// Print the operational status of one solution.
    Status {
        /// Solution id.
        solution: String,
    },
    /// Solution registry administration (task B-084).
    Solution(SolutionCommand),
    /// Explicit changed-file hints (task B-032).
    Changed(ChangedCommand),
    /// Bounded reconcile request (task B-086).
    Reconcile(ReconcileCommand),
    /// Operational queue verbs (task B-043).
    Queue(QueueCommand),
    /// Bounded context and impact (task B-087).
    Query(QueryCommand),
    /// Delegated update verbs (task B-092).
    Update(UpdateCommand),
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

/// Value-less switches accepted anywhere on the command line.
const FLAGS: &[&str] = &[
    "--json",
    "--help",
    "-h",
    "--version",
    "-V",
    "--dry-run",
    "--apply",
    "--wait",
];

/// Every option that takes a value, across all wired verbs.
///
/// An option outside this table is rejected as an unrecognised flag instead of
/// being silently ignored, which is the section 1 contract.
const KNOWN_OPTIONS: &[&str] = &[
    "--registry",
    "--solution",
    "--project",
    "--path",
    "--reason",
    "--from-json",
    "--limit",
    "--job",
    "--config",
    "--bindings",
    "--scope",
    "--timeout",
    "--symbol",
    "--node-id",
    "--max-bytes",
    "--max-nodes",
    "--depth",
    "--plan",
    "--approve-digest",
];

/// Positionals and options left after the first pass over argv.
///
/// Options are stored as `(name, value)`; value-less switches keep an empty
/// value so an unexpected flag is reported by [`Tokens::finish`] like any other.
struct Tokens {
    positionals: Vec<String>,
    options: Vec<(String, String)>,
}

impl Tokens {
    /// Remove and return the first value for `name`.
    fn take(&mut self, name: &str) -> Option<String> {
        let position = self.options.iter().position(|(key, _)| key == name);
        position.map(|index| self.options.remove(index).1)
    }

    /// Remove `name` as a value-less switch, reporting whether it was present.
    fn flag(&mut self, name: &str) -> bool {
        self.take(name).is_some()
    }

    /// Remove and return the next positional word.
    fn next_word(&mut self, context: &str) -> Result<String, AxiomError> {
        if self.positionals.is_empty() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                format!("{context} requires a subcommand"),
            ));
        }
        Ok(self.positionals.remove(0))
    }

    /// Require a named option.
    fn required(&mut self, name: &str, context: &str) -> Result<String, AxiomError> {
        self.take(name).ok_or_else(|| {
            AxiomError::new(
                ErrorCode::ValidationError,
                format!("{context} requires {name}"),
            )
        })
    }

    /// Reject any option or positional the verb did not consume.
    fn finish(&self, context: &str) -> Result<(), AxiomError> {
        if let Some((name, _)) = self.options.first() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                format!("{context} does not accept the option {name}"),
            ));
        }
        if let Some(word) = self.positionals.first() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                format!("{context} does not accept the argument {word}"),
            ));
        }
        Ok(())
    }

    /// Parse an optional bounded `usize` option.
    fn optional_bounded_usize(
        &mut self,
        name: &str,
        context: &str,
        minimum: usize,
        maximum: usize,
    ) -> Result<Option<usize>, AxiomError> {
        let Some(value) = self.take(name) else {
            return Ok(None);
        };
        let parsed = value.parse::<usize>().map_err(|_| {
            AxiomError::new(
                ErrorCode::ValidationError,
                format!("{name} for {context} must be an integer, got {value}"),
            )
        })?;
        if !(minimum..=maximum).contains(&parsed) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                format!(
                    "{name} for {context} must be between {minimum} and {maximum}, got {value}"
                ),
            ));
        }
        Ok(Some(parsed))
    }

    /// Parse an optional bounded `u32` option.
    fn optional_bounded_u32(
        &mut self,
        name: &str,
        context: &str,
        minimum: u32,
        maximum: u32,
    ) -> Result<Option<u32>, AxiomError> {
        let Some(value) = self.take(name) else {
            return Ok(None);
        };
        let parsed = value.parse::<u32>().map_err(|_| {
            AxiomError::new(
                ErrorCode::ValidationError,
                format!("{name} for {context} must be an integer, got {value}"),
            )
        })?;
        if !(minimum..=maximum).contains(&parsed) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                format!(
                    "{name} for {context} must be between {minimum} and {maximum}, got {value}"
                ),
            ));
        }
        Ok(Some(parsed))
    }
}

/// Parse argv (without the program name).
///
/// Parsing never fails: rejected arguments become [`Command::Rejected`] so the
/// caller still knows whether `--json` was requested and can emit the error
/// envelope on stdout.
#[must_use]
pub fn parse(arguments: &[String]) -> Invocation {
    // `--json` is read from the whole line first: a rejection later in the
    // line must still emit the machine-readable envelope, because the caller
    // asked for it.
    let mut json = arguments
        .iter()
        .any(|argument| argument.as_str() == "--json");
    let mut help = false;
    let mut version_flag = false;
    let mut positionals: Vec<String> = Vec::new();
    let mut options: Vec<(String, String)> = Vec::new();
    let mut rejection: Option<String> = None;

    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if FLAGS.contains(&argument) {
            match argument {
                "--json" => json = true,
                "--help" | "-h" => help = true,
                "--version" | "-V" => version_flag = true,
                switch => options.push((String::from(switch), String::new())),
            }
        } else if argument.starts_with('-') && argument.len() > 1 {
            if !KNOWN_OPTIONS.contains(&argument) {
                rejection = Some(format!("unrecognised option: {argument}"));
                break;
            }
            let Some(value) = arguments.get(index + 1) else {
                rejection = Some(format!("{argument} requires a value"));
                break;
            };
            if value.starts_with('-') && value.len() > 1 {
                rejection = Some(format!("{argument} requires a value"));
                break;
            }
            options.push((String::from(argument), value.clone()));
            index += 1;
        } else {
            positionals.push(String::from(argument));
        }
        index += 1;
    }

    if let Some(message) = rejection {
        return rejected_invocation(message, json);
    }
    if help {
        return Invocation {
            command: Command::Help,
            json,
        };
    }
    if positionals.is_empty() {
        return Invocation {
            command: if version_flag {
                Command::Version
            } else {
                Command::Help
            },
            json,
        };
    }

    let mut tokens = Tokens {
        positionals,
        options,
    };
    let verb = tokens.positionals.remove(0);
    match parse_verb(verb.as_str(), &mut tokens) {
        Ok(command) => Invocation { command, json },
        Err(error) => Invocation {
            command: Command::Rejected { error },
            json,
        },
    }
}

/// Build a rejected invocation carrying the section 1 validation code.
fn rejected_invocation(message: String, json: bool) -> Invocation {
    Invocation {
        command: Command::Rejected {
            error: AxiomError::new(ErrorCode::ValidationError, message),
        },
        json,
    }
}

/// Resolve one verb and its options.
fn parse_verb(verb: &str, tokens: &mut Tokens) -> Result<Command, AxiomError> {
    match verb {
        "help" => {
            tokens.finish("the help command")?;
            Ok(Command::Help)
        }
        "version" => {
            tokens.finish("the version command")?;
            Ok(Command::Version)
        }
        "serve" => {
            let registry = tokens.take("--registry").map(PathBuf::from);
            tokens.finish("the serve command")?;
            Ok(Command::Serve { registry })
        }
        "doctor" => {
            let solution = tokens.take("--solution");
            if let Some(value) = &solution {
                validate_identifier(value, "--solution", "the doctor command")?;
            }
            tokens.finish("the doctor command")?;
            Ok(Command::Doctor { solution })
        }
        "status" => {
            let solution = tokens.required("--solution", "the status command")?;
            validate_identifier(&solution, "--solution", "the status command")?;
            tokens.finish("the status command")?;
            Ok(Command::Status { solution })
        }
        "solution" => parse_solution(tokens),
        "changed" => parse_changed(tokens),
        "reconcile" => parse_reconcile(tokens),
        "queue" => parse_queue(tokens),
        "query" => parse_query(tokens),
        "update" => parse_update(tokens),
        other => Err(AxiomError::new(
            ErrorCode::ValidationError,
            format!("unrecognised command: {other}"),
        )),
    }
}

/// Reject an empty or whitespace-bearing identifier.
fn validate_identifier(value: &str, option: &str, context: &str) -> Result<(), AxiomError> {
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            format!("{option} for {context} must be a non-empty identifier without whitespace, got `{value}`"),
        ));
    }
    Ok(())
}

/// Enforce the section 8 repository-relative forward-slash path convention.
fn validate_relative_path(value: &str, option: &str, context: &str) -> Result<(), AxiomError> {
    let absolute =
        value.starts_with('/') || value.starts_with('\\') || value.as_bytes().get(1) == Some(&b':');
    let escaping = value.split('/').any(|segment| segment == "..");
    if value.is_empty() || absolute || escaping || value.contains('\\') {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            format!("{option} for {context} must be a repository-relative forward-slash path, got {value}"),
        ));
    }
    Ok(())
}

/// Require exactly one of `--dry-run` and `--apply`.
fn take_plan_mode(tokens: &mut Tokens, context: &str) -> Result<PlanMode, AxiomError> {
    let dry_run = tokens.flag("--dry-run");
    let apply = tokens.flag("--apply");
    match (dry_run, apply) {
        (true, false) => Ok(PlanMode::DryRun),
        (false, true) => Ok(PlanMode::Apply),
        (false, false) => Err(AxiomError::new(
            ErrorCode::ValidationError,
            format!("{context} requires exactly one of --dry-run or --apply"),
        )),
        (true, true) => Err(AxiomError::new(
            ErrorCode::ValidationError,
            format!("{context} accepts only one of --dry-run or --apply"),
        )),
    }
}

/// `solution register|list|remove`.
fn parse_solution(tokens: &mut Tokens) -> Result<Command, AxiomError> {
    let sub = tokens.next_word("the solution command")?;
    match sub.as_str() {
        "register" => {
            let config = tokens.required("--config", "solution register")?;
            let bindings = tokens.take("--bindings");
            let mode = take_plan_mode(tokens, "solution register")?;
            tokens.finish("solution register")?;
            Ok(Command::Solution(SolutionCommand::Register {
                config: PathBuf::from(config),
                bindings: bindings.map(PathBuf::from),
                mode,
            }))
        }
        "list" => {
            let solution = tokens.take("--solution");
            if let Some(value) = &solution {
                validate_identifier(value, "--solution", "solution list")?;
            }
            tokens.finish("solution list")?;
            Ok(Command::Solution(SolutionCommand::List { solution }))
        }
        "remove" => {
            let solution = tokens.required("--solution", "solution remove")?;
            validate_identifier(&solution, "--solution", "solution remove")?;
            let mode = take_plan_mode(tokens, "solution remove")?;
            tokens.finish("solution remove")?;
            Ok(Command::Solution(SolutionCommand::Remove {
                solution,
                mode,
            }))
        }
        other => Err(AxiomError::new(
            ErrorCode::ValidationError,
            format!("solution does not accept the subcommand {other}"),
        )),
    }
}

/// `changed --solution ... --project ... --path ... --reason ...` or `--from-json`.
fn parse_changed(tokens: &mut Tokens) -> Result<Command, AxiomError> {
    let context = "the changed command";
    let solution = tokens.required("--solution", context)?;
    validate_identifier(&solution, "--solution", context)?;
    if let Some(from_json) = tokens.take("--from-json") {
        tokens.finish("changed --from-json")?;
        return Ok(Command::Changed(ChangedCommand::Batch {
            solution,
            from_json: PathBuf::from(from_json),
        }));
    }
    let project = tokens.required("--project", context)?;
    validate_identifier(&project, "--project", context)?;
    let path = tokens.required("--path", context)?;
    validate_relative_path(&path, "--path", context)?;
    let reason = tokens.required("--reason", context)?;
    if !changed::is_known_reason(&reason) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            format!(
                "--reason for {context} must be one of {}, got {reason}",
                changed::REASONS.join(", ")
            ),
        ));
    }
    tokens.finish(context)?;
    Ok(Command::Changed(ChangedCommand::Hint {
        solution,
        project,
        path,
        reason,
    }))
}

/// Parse a bounded wait budget in milliseconds, seconds or a bare millisecond count.
fn parse_timeout_ms(value: &str) -> Result<u64, AxiomError> {
    let context = "the reconcile command";
    let (digits, multiplier) = if let Some(rest) = value.strip_suffix("ms") {
        (rest, 1_u64)
    } else if let Some(rest) = value.strip_suffix('s') {
        (rest, 1000_u64)
    } else {
        (value, 1_u64)
    };
    let number = digits.parse::<u64>().map_err(|_| {
        AxiomError::new(
            ErrorCode::ValidationError,
            format!("--timeout for {context} must be milliseconds, seconds or a plain millisecond count, got {value}"),
        )
    })?;
    let millis = number.saturating_mul(multiplier);
    if !(reconcile::MIN_TIMEOUT_MS..=reconcile::MAX_TIMEOUT_MS).contains(&millis) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            format!(
                "--timeout for {context} must be between {}ms and {}ms, got {value}",
                reconcile::MIN_TIMEOUT_MS,
                reconcile::MAX_TIMEOUT_MS
            ),
        ));
    }
    Ok(millis)
}

/// `reconcile --solution ... --scope dirty|project|full`.
fn parse_reconcile(tokens: &mut Tokens) -> Result<Command, AxiomError> {
    let context = "the reconcile command";
    let solution = tokens.required("--solution", context)?;
    validate_identifier(&solution, "--solution", context)?;
    let scope_word = tokens.required("--scope", context)?;
    let scope = match scope_word.as_str() {
        "dirty" => Scope::Dirty,
        "project" => Scope::Project,
        "full" => Scope::Full,
        other => {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                format!("--scope for {context} must be one of dirty, project, full, got {other}"),
            ))
        }
    };
    let project = tokens.take("--project");
    if let Some(value) = &project {
        validate_identifier(value, "--project", context)?;
    }
    match (scope, project.is_some()) {
        (Scope::Project, false) => {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                String::from("reconcile --scope project requires --project"),
            ))
        }
        (Scope::Dirty | Scope::Full, true) => {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                String::from("reconcile --project is only valid with --scope project"),
            ))
        }
        _ => {}
    }
    let wait = tokens.flag("--wait");
    let timeout_ms = match tokens.take("--timeout") {
        Some(value) => Some(parse_timeout_ms(&value)?),
        None => None,
    };
    tokens.finish(context)?;
    Ok(Command::Reconcile(ReconcileCommand::Request {
        solution,
        scope,
        project,
        wait,
        timeout_ms,
    }))
}

/// `queue list|retry|cancel`.
fn parse_queue(tokens: &mut Tokens) -> Result<Command, AxiomError> {
    let sub = tokens.next_word("the queue command")?;
    match sub.as_str() {
        "list" => {
            let context = "queue list";
            let solution = tokens.required("--solution", context)?;
            validate_identifier(&solution, "--solution", context)?;
            let limit =
                tokens.optional_bounded_usize("--limit", context, 1, queue::MAX_LIST_LIMIT)?;
            tokens.finish(context)?;
            Ok(Command::Queue(QueueCommand::List { solution, limit }))
        }
        "retry" | "cancel" => {
            let context = "the queue command";
            let job = tokens.required("--job", context)?;
            validate_identifier(&job, "--job", context)?;
            tokens.finish(context)?;
            if sub == "retry" {
                Ok(Command::Queue(QueueCommand::Retry { job }))
            } else {
                Ok(Command::Queue(QueueCommand::Cancel { job }))
            }
        }
        other => Err(AxiomError::new(
            ErrorCode::ValidationError,
            format!("queue does not accept the subcommand {other}"),
        )),
    }
}

/// Reject a digest that is not 64 lowercase hexadecimal characters.
fn validate_digest(value: &str, context: &str) -> Result<(), AxiomError> {
    let shaped = value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character));
    if !shaped {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            format!("--approve-digest for {context} must be 64 lowercase hexadecimal characters, got {value}"),
        ));
    }
    Ok(())
}

/// `query context|impact`.
fn parse_query(tokens: &mut Tokens) -> Result<Command, AxiomError> {
    let sub = tokens.next_word("the query command")?;
    let context = match sub.as_str() {
        "context" => "query context",
        "impact" => "query impact",
        other => {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                format!("query does not accept the subcommand {other}"),
            ))
        }
    };
    let solution = tokens.required("--solution", context)?;
    validate_identifier(&solution, "--solution", context)?;
    let symbol = tokens.take("--symbol");
    let node_id = tokens.take("--node-id");
    let selector = match (symbol, node_id) {
        (Some(_), Some(_)) => {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                format!("{context} accepts only one of --symbol or --node-id"),
            ))
        }
        (Some(value), None) => {
            validate_identifier(&value, "--symbol", context)?;
            Selector::Symbol(value)
        }
        (None, Some(value)) => {
            validate_identifier(&value, "--node-id", context)?;
            Selector::NodeId(value)
        }
        (None, None) => {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                format!("{context} requires --symbol or --node-id"),
            ))
        }
    };
    let limits = QueryLimits {
        max_bytes: tokens.optional_bounded_usize(
            "--max-bytes",
            context,
            query::MIN_MAX_BYTES,
            query::MAX_MAX_BYTES,
        )?,
        max_nodes: tokens.optional_bounded_usize(
            "--max-nodes",
            context,
            1,
            query::MAX_MAX_NODES,
        )?,
        depth: tokens.optional_bounded_u32("--depth", context, 1, query::MAX_DEPTH)?,
    };
    tokens.finish(context)?;
    Ok(match sub.as_str() {
        "context" => Command::Query(QueryCommand::Context {
            solution,
            selector,
            limits,
        }),
        _ => Command::Query(QueryCommand::Impact {
            solution,
            selector,
            limits,
        }),
    })
}

/// `update check|apply`.
fn parse_update(tokens: &mut Tokens) -> Result<Command, AxiomError> {
    let sub = tokens.next_word("the update command")?;
    match sub.as_str() {
        "check" => {
            tokens.finish("update check")?;
            Ok(Command::Update(UpdateCommand::Check))
        }
        "apply" => {
            let context = "update apply";
            let plan = tokens.required("--plan", context)?;
            let approve_digest = tokens.take("--approve-digest");
            if let Some(value) = &approve_digest {
                validate_digest(value, context)?;
            }
            tokens.finish(context)?;
            Ok(Command::Update(UpdateCommand::Apply {
                plan: PathBuf::from(plan),
                approve_digest,
            }))
        }
        other => Err(AxiomError::new(
            ErrorCode::ValidationError,
            format!("update does not accept the subcommand {other}"),
        )),
    }
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

/// The stated reason a wired slice cannot finish production work yet.
fn slice_reason(module: &str) -> &'static str {
    for slice in OPERATOR_SLICES {
        if slice.module == module {
            return slice.not_ready;
        }
    }
    "this command has no production wiring in this build"
}

/// Build the `NotReady` error for a wired slice.
fn not_ready(module: &str) -> AxiomError {
    AxiomError::new(ErrorCode::NotReady, slice_reason(module))
}

fn execute(command: &Command, telemetry: &mut Telemetry) -> Result<String, AxiomError> {
    match command {
        Command::Help => Ok(usage()),
        Command::Rejected { error } => Err(error.clone()),
        Command::Version => {
            let output = VersionOutput::current();
            serde_json::to_string(&output).map_err(|_| {
                AxiomError::new(
                    ErrorCode::Internal,
                    "the version report is not serialisable",
                )
            })
        }
        Command::Doctor { .. } => Err(not_ready("doctor")),
        Command::Status { .. } => Err(AxiomError::new(
            ErrorCode::NotReady,
            REASON_STATUS_NOT_READY,
        )),
        Command::Solution(_) => Err(not_ready("solution")),
        Command::Changed(_) => Err(not_ready("changed")),
        Command::Reconcile(_) => Err(not_ready("reconcile")),
        Command::Queue(_) => Err(not_ready("queue")),
        Command::Query(_) => Err(not_ready("query")),
        Command::Update(_) => Err(not_ready("update")),
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

    /// One representative, valid argv per wired slice.
    fn wired_argv() -> Vec<Vec<String>> {
        vec![
            argv(&[
                "changed",
                "--solution",
                "demo-solution",
                "--project",
                "auth-api",
                "--path",
                "src/Auth.Api/AuthController.cs",
                "--reason",
                "manual",
                "--json",
            ]),
            argv(&[
                "changed",
                "--solution",
                "demo-solution",
                "--from-json",
                "changes.json",
                "--json",
            ]),
            argv(&[
                "queue",
                "list",
                "--solution",
                "demo-solution",
                "--limit",
                "50",
                "--json",
            ]),
            argv(&["queue", "retry", "--job", "job-1", "--json"]),
            argv(&["queue", "cancel", "--job", "job-1", "--json"]),
            argv(&[
                "solution",
                "register",
                "--config",
                "solution.yaml",
                "--bindings",
                "bindings.json",
                "--dry-run",
                "--json",
            ]),
            argv(&["solution", "list", "--json"]),
            argv(&[
                "solution",
                "remove",
                "--solution",
                "demo-solution",
                "--apply",
                "--json",
            ]),
            argv(&["doctor", "--solution", "demo-solution", "--json"]),
            argv(&["status", "--solution", "demo-solution", "--json"]),
            argv(&[
                "reconcile",
                "--solution",
                "demo-solution",
                "--scope",
                "dirty",
                "--wait",
                "--timeout",
                "30s",
                "--json",
            ]),
            argv(&[
                "reconcile",
                "--solution",
                "demo-solution",
                "--scope",
                "project",
                "--project",
                "auth-api",
                "--json",
            ]),
            argv(&[
                "query",
                "context",
                "--solution",
                "demo-solution",
                "--symbol",
                "AuthService",
                "--max-bytes",
                "8192",
                "--json",
            ]),
            argv(&[
                "query",
                "impact",
                "--solution",
                "demo-solution",
                "--node-id",
                "node-1",
                "--depth",
                "2",
                "--json",
            ]),
            argv(&["update", "check", "--json"]),
            argv(&["update", "apply", "--plan", "plan.json", "--json"]),
        ]
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
            parse(&argv(&["--version"])).command(),
            Command::Version
        ));
        assert!(matches!(
            parse(&argv(&["doctor"])).command(),
            Command::Doctor { solution: None }
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
    fn wired_options_land_in_the_parsed_command() {
        let invocation = parse(&argv(&[
            "query",
            "impact",
            "--solution",
            "demo",
            "--node-id",
            "node-1",
            "--depth",
            "3",
            "--max-bytes",
            "4096",
        ]));
        match invocation.command() {
            Command::Query(QueryCommand::Impact {
                solution,
                selector,
                limits,
            }) => {
                assert_eq!(solution, "demo");
                assert_eq!(selector, &Selector::NodeId(String::from("node-1")));
                assert_eq!(limits.depth, Some(3));
                assert_eq!(limits.max_bytes, Some(4096));
                assert_eq!(limits.max_nodes, None);
            }
            other => panic!("expected query impact, got {other:?}"),
        }

        let invocation = parse(&argv(&[
            "reconcile",
            "--solution",
            "demo",
            "--scope",
            "dirty",
            "--wait",
            "--timeout",
            "30s",
        ]));
        match invocation.command() {
            Command::Reconcile(ReconcileCommand::Request {
                scope,
                project,
                wait,
                timeout_ms,
                ..
            }) => {
                assert_eq!(scope, &Scope::Dirty);
                assert!(project.is_none());
                assert!(wait);
                assert_eq!(timeout_ms, &Some(30_000));
            }
            other => panic!("expected reconcile, got {other:?}"),
        }

        let invocation = parse(&argv(&[
            "solution",
            "remove",
            "--solution",
            "demo",
            "--dry-run",
        ]));
        match invocation.command() {
            Command::Solution(SolutionCommand::Remove { solution, mode }) => {
                assert_eq!(solution, "demo");
                assert_eq!(mode, &PlanMode::DryRun);
            }
            other => panic!("expected solution remove, got {other:?}"),
        }
    }

    #[test]
    fn every_wired_verb_accepts_help() {
        for arguments in [
            vec!["serve", "--help"],
            vec!["doctor", "--help"],
            vec!["status", "--help"],
            vec!["solution", "--help"],
            vec!["changed", "--help"],
            vec!["reconcile", "--help"],
            vec!["queue", "list", "--help"],
            vec!["query", "context", "--help"],
            vec!["update", "--help"],
        ] {
            assert!(
                matches!(parse(&argv(&arguments)).command(), Command::Help),
                "{arguments:?} must print help"
            );
        }
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
            vec!["status"],
            vec!["status", "--solution"],
            vec!["doctor", "--solution"],
            vec!["solution"],
            vec!["solution", "bogus"],
            vec!["solution", "register", "--config", "x"],
            vec![
                "solution",
                "register",
                "--config",
                "x",
                "--dry-run",
                "--apply",
            ],
            vec!["solution", "list", "--dry-run"],
            vec!["queue"],
            vec!["queue", "list"],
            vec!["queue", "list", "--solution", "s", "--limit", "0"],
            vec!["queue", "list", "--solution", "s", "--limit", "501"],
            vec!["queue", "list", "--solution", "s", "--limit", "many"],
            vec!["queue", "retry"],
            vec!["queue", "bogus", "--job", "j"],
            vec![
                "changed",
                "--solution",
                "s",
                "--from-json",
                "x",
                "--project",
                "p",
            ],
            vec![
                "changed",
                "--solution",
                "s",
                "--project",
                "p",
                "--path",
                "/abs/x.cs",
                "--reason",
                "manual",
            ],
            vec![
                "changed",
                "--solution",
                "s",
                "--project",
                "p",
                "--path",
                "C:/abs/x.cs",
                "--reason",
                "manual",
            ],
            vec![
                "changed",
                "--solution",
                "s",
                "--project",
                "p",
                "--path",
                "a\\b.cs",
                "--reason",
                "manual",
            ],
            vec![
                "changed",
                "--solution",
                "s",
                "--project",
                "p",
                "--path",
                "../x.cs",
                "--reason",
                "manual",
            ],
            vec![
                "changed",
                "--solution",
                "s",
                "--project",
                "p",
                "--path",
                "a/b.cs",
                "--reason",
                "guess",
            ],
            vec![
                "reconcile",
                "--solution",
                "s",
                "--scope",
                "dirty",
                "--project",
                "p",
            ],
            vec!["reconcile", "--solution", "s", "--scope", "project"],
            vec!["reconcile", "--solution", "s", "--scope", "bogus"],
            vec![
                "reconcile",
                "--solution",
                "s",
                "--scope",
                "dirty",
                "--timeout",
                "99",
            ],
            vec![
                "reconcile",
                "--solution",
                "s",
                "--scope",
                "dirty",
                "--timeout",
                "1h",
            ],
            vec!["query", "context", "--solution", "s"],
            vec![
                "query",
                "context",
                "--solution",
                "s",
                "--symbol",
                "a",
                "--node-id",
                "b",
            ],
            vec![
                "query",
                "context",
                "--solution",
                "s",
                "--symbol",
                "a",
                "--max-bytes",
                "1024",
            ],
            vec![
                "query",
                "context",
                "--solution",
                "s",
                "--symbol",
                "a",
                "--max-nodes",
                "0",
            ],
            vec![
                "query",
                "context",
                "--solution",
                "s",
                "--symbol",
                "a",
                "--depth",
                "7",
            ],
            vec![
                "query",
                "context",
                "--solution",
                "s",
                "--symbol",
                "a",
                "--max-bytes",
                "nope",
            ],
            vec!["update"],
            vec!["update", "bogus"],
            vec!["update", "apply"],
            vec![
                "update",
                "apply",
                "--plan",
                "p.json",
                "--approve-digest",
                "zz",
            ],
            vec!["update", "check", "--plan", "p.json"],
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
    fn boundary_values_are_accepted() {
        for arguments in [
            vec!["queue", "list", "--solution", "s", "--limit", "1"],
            vec!["queue", "list", "--solution", "s", "--limit", "500"],
            vec![
                "reconcile",
                "--solution",
                "s",
                "--scope",
                "dirty",
                "--timeout",
                "100",
            ],
            vec![
                "reconcile",
                "--solution",
                "s",
                "--scope",
                "dirty",
                "--timeout",
                "100ms",
            ],
            vec![
                "reconcile",
                "--solution",
                "s",
                "--scope",
                "dirty",
                "--timeout",
                "3600s",
            ],
            vec![
                "query",
                "context",
                "--solution",
                "s",
                "--symbol",
                "a",
                "--max-bytes",
                "2048",
            ],
            vec![
                "query",
                "context",
                "--solution",
                "s",
                "--symbol",
                "a",
                "--max-bytes",
                "1048576",
            ],
            vec![
                "query",
                "context",
                "--solution",
                "s",
                "--symbol",
                "a",
                "--max-nodes",
                "4096",
            ],
            vec![
                "query",
                "context",
                "--solution",
                "s",
                "--symbol",
                "a",
                "--depth",
                "6",
            ],
            vec![
                "update",
                "apply",
                "--plan",
                "plan.json",
                "--approve-digest",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ],
        ] {
            let invocation = parse(&argv(&arguments));
            assert!(
                !matches!(invocation.command(), Command::Rejected { .. }),
                "{arguments:?} must be accepted, got {:?}",
                invocation.command()
            );
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
    fn text_mode_wired_slices_keep_stdout_empty() {
        for arguments in wired_argv() {
            let text_arguments: Vec<String> = arguments
                .iter()
                .filter(|argument| argument.as_str() != "--json")
                .cloned()
                .collect();
            let invocation = parse(&text_arguments);
            let mut stdout: Vec<u8> = Vec::new();
            let mut telemetry = sink_telemetry();
            let code = run(&invocation, &mut stdout, &mut telemetry);
            assert_eq!(code, ExitCode::NotReady, "{}", arguments.join(" "));
            assert!(
                stdout.is_empty(),
                "{} must keep stdout empty in text mode",
                arguments.join(" ")
            );
        }
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

    #[test]
    fn operator_slices_are_listed_in_help() {
        let text = usage();
        for slice in OPERATOR_SLICES {
            let heading = format!("  {}\n", slice.verb);
            assert!(
                text.contains(&heading),
                "help omits the {} verb",
                slice.module
            );
            for form in slice.forms {
                assert!(
                    text.contains(form),
                    "help omits the {} form `{form}`",
                    slice.module
                );
            }
        }
    }

    /// The declaration list under `commands/` is the source of truth for the
    /// wired slice set: dropping a `pub mod` while its verb stays in argv, or
    /// adding a verb with no module behind it, fails this test.
    const COMMANDS_MOD: &str = include_str!("commands/mod.rs");

    fn declared_command_modules() -> Vec<String> {
        COMMANDS_MOD
            .lines()
            .filter_map(|line| line.trim().strip_prefix("pub mod "))
            .filter_map(|rest| rest.strip_suffix(';'))
            .map(|name| name.trim().to_string())
            .collect()
    }

    #[test]
    fn slice_wiring_matches_commands_mod() {
        let mut declared = declared_command_modules();
        declared.sort();

        let mut wired: Vec<String> = OPERATOR_SLICES
            .iter()
            .map(|slice| String::from(slice.module))
            .collect();
        wired.sort();
        assert_eq!(
            declared, wired,
            "every `pub mod` under commands/ must be reachable from argv, and every wired verb must own a module"
        );

        let mut linked: Vec<String> = slice_links()
            .iter()
            .map(|(module, _)| String::from(*module))
            .collect();
        linked.sort();
        assert_eq!(
            declared, linked,
            "every wired slice must link to a real item of its module"
        );
        for (module, probe) in slice_links() {
            assert!(
                !probe.is_empty(),
                "{module} must link to a non-empty module item"
            );
        }
    }

    /// The declared verb list is the authority the CLI reference document is
    /// checked against, so it has to agree with the parser in both directions:
    /// every declared verb is recognised, and every verb this build does not
    /// implement is still rejected as unrecognised rather than half-accepted.
    #[test]
    fn accepted_verbs_match_the_parser_in_both_directions() {
        for verb in ACCEPTED_VERBS {
            let invocation = parse(&argv(&[*verb]));
            if let Command::Rejected { error } = invocation.command() {
                assert!(
                    error.message() != format!("unrecognised command: {verb}"),
                    "{verb} is declared accepted but `parse` rejects it as unrecognised"
                );
            }
        }
        for verb in [
            "frobnicate",
            "migrate",
            "checkpoint",
            "snapshot",
            "install",
            "bootstrap",
            "service",
        ] {
            assert!(
                !ACCEPTED_VERBS.contains(&verb),
                "{verb} must not be declared accepted"
            );
            let invocation = parse(&argv(&[verb]));
            let Command::Rejected { error } = invocation.command() else {
                panic!("{verb} must be rejected, got {:?}", invocation.command());
            };
            assert_eq!(
                error.message(),
                format!("unrecognised command: {verb}"),
                "{verb} must be rejected as an unrecognised command"
            );
        }
        for slice in OPERATOR_SLICES {
            assert!(
                ACCEPTED_VERBS.contains(&slice.verb),
                "slice verb {} is missing from ACCEPTED_VERBS",
                slice.verb
            );
        }
        let mut declared: Vec<&str> = ACCEPTED_VERBS.to_vec();
        declared.sort_unstable();
        declared.dedup();
        assert_eq!(
            declared.len(),
            ACCEPTED_VERBS.len(),
            "ACCEPTED_VERBS declares a verb twice"
        );
    }

    #[test]
    fn wired_slices_answer_not_ready_instead_of_empty_success() {
        let expected = ErrorCode::NotReady.as_str();
        for arguments in wired_argv() {
            let invocation = parse(&arguments);
            assert!(
                !matches!(invocation.command(), Command::Rejected { .. }),
                "{} must parse, got {:?}",
                arguments.join(" "),
                invocation.command()
            );
            let mut stdout: Vec<u8> = Vec::new();
            let mut telemetry = sink_telemetry();
            let code = run(&invocation, &mut stdout, &mut telemetry);
            assert_eq!(
                code,
                ExitCode::NotReady,
                "{} must be NotReady",
                arguments.join(" ")
            );
            let text = String::from_utf8(stdout).expect("utf-8");
            assert_eq!(
                text.lines().count(),
                1,
                "{} must write one JSON object",
                arguments.join(" ")
            );
            let value: serde_json::Value =
                serde_json::from_str(text.trim()).expect("one JSON object");
            assert_eq!(value["code"], serde_json::Value::from(expected));
            let message = value["message"].as_str().unwrap_or_default();
            assert!(
                message.contains("later work package"),
                "{} must state why it is unbuilt, got `{message}`",
                arguments.join(" ")
            );
        }
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
