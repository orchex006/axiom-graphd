//! Foreground command line: argv in, one JSON object out (tasks B-001, B-002, H-001).
//!
//! docs/16-CLI-AND-CONTROL-API.md section 1 fixes the shape of this layer:
//! every command has `--help`, machine-readable mode writes exactly one JSON
//! object to stdout with diagnostics on stderr, invalid flags are an error
//! rather than silently ignored, argument paths arrive as argv (never as an
//! interpolated shell string), and exit codes are the frozen table from
//! section 6.
//!
//! Task H-001 wired the operator slices that own a module under
//! [`crate::commands`] into this surface. Each verb parses its own options
//! strictly and is listed by `--help`. Task H-002 binds the ones that name a
//! real production path: `serve` runs the bounded reconcile worker loop, and
//! `solution`, `queue`, `reconcile`, `status`, `doctor` and `query` open the
//! shared instance store through [`crate::runtime`]. A verb that is still
//! unwired (`changed`, `update`) answers [`ErrorCode::NotReady`] with its stated
//! reason, so an unbuilt slice is never reported as an empty success.

use std::io::Write;
use std::path::{Path, PathBuf};

use graph_core::config::ServiceConfig;
use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{AxiomHome, PathEnvironment};
use graph_store::open::Store;

pub use graph_core::error::ExitCode;

use crate::commands::{changed, doctor, query, queue, reconcile, render, solution, update};
use crate::runtime;
use crate::serve;
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
    /// Why the slice cannot complete production work, empty once it is wired.
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
        not_ready: "",
    },
    OperatorSlice {
        module: "solution",
        verb: "solution",
        forms: &[
            "solution register --config <solution.yaml> [--bindings <bindings.json>] (--dry-run|--apply) [--json]",
            "solution list [--solution <id>] [--json]",
            "solution remove --solution <id> (--dry-run|--apply) [--json]",
        ],
        not_ready: "",
    },
    OperatorSlice {
        module: "doctor",
        verb: "doctor",
        forms: &["doctor [--solution <id>] [--json]"],
        not_ready: "",
    },
    OperatorSlice {
        module: "reconcile",
        verb: "reconcile",
        forms: &[
            "reconcile --solution <id> --scope dirty [--wait] [--timeout <ms|Ns>] [--json]",
            "reconcile --solution <id> --scope project --project <project> [--json]",
            "reconcile --solution <id> --scope full [--json]",
        ],
        not_ready: "",
    },
    OperatorSlice {
        module: "query",
        verb: "query",
        forms: &[
            "query context --solution <id> (--symbol <name>|--node-id <id>) [--max-bytes <n>] [--max-nodes <n>] [--depth <n>] [--json]",
            "query impact --solution <id> (--symbol <name>|--node-id <id>) [--max-bytes <n>] [--max-nodes <n>] [--depth <n>] [--json]",
        ],
        not_ready: "",
    },
    OperatorSlice {
        module: "render",
        verb: "render",
        forms: &[
            "render --solution <id> [--project <project>]... --out <dir> [--json]",
        ],
        not_ready: "",
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
    "render",
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
        ("render", render::SCHEMA_VERSION.to_string()),
        ("update", String::from(update::AXIOM_PROGRAM)),
    ]
}

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
  render --solution <id> --out <dir>   render a published generation as a diagram
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

/// One parsed `render` invocation (task H-005).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderCommand {
    /// Solution whose published generations are rendered.
    pub solution: String,
    /// Projects to render; empty means every registered project.
    pub projects: Vec<String>,
    /// Directory the `result.html`, `summary.json` and `graph.mmd` artifacts are
    /// written to.
    pub out: PathBuf,
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
    /// Deterministic diagram of one published generation (task H-005).
    Render(RenderCommand),
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
    "--out",
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

    /// Remove and return every value recorded for `name`, in argv order.
    fn take_all(&mut self, name: &str) -> Vec<String> {
        let mut values = Vec::new();
        while let Some(index) = self.options.iter().position(|(key, _)| key == name) {
            values.push(self.options.remove(index).1);
        }
        values
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
        "render" => parse_render(tokens),
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

/// The stated reason a slice that is still unwired cannot finish production work.
///
/// A wired slice has an empty reason, because it no longer has a not-ready path.
fn slice_reason(module: &str) -> Option<&'static str> {
    OPERATOR_SLICES
        .iter()
        .find(|slice| slice.module == module && !slice.not_ready.is_empty())
        .map(|slice| slice.not_ready)
}

/// Build the `NotReady` error for a slice that is still unwired.
fn not_ready(module: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::NotReady,
        slice_reason(module).unwrap_or("this command has no production wiring in this build"),
    )
}

/// The shared operator opening: the home plus the instance store it names.
struct OperatorContext {
    home: AxiomHome,
    store: Store,
}

/// Open the instance store the foreground daemon and the operator verbs share.
///
/// The home is resolved and verified, the service config is loaded from the
/// documented default source, the store is opened at the one instance database
/// path and the shipped migrations are applied. No verb invents a second
/// database path.
fn open_operator() -> Result<OperatorContext, AxiomError> {
    let home = AxiomHome::resolve(&PathEnvironment::for_current_process())?;
    home.verify_destination()?;
    let config = ServiceConfig::load(None)?;
    let mut store = runtime::open_store(&config, &home)?;
    graph_store::migrations::apply(store.connection_mut())?;
    Ok(OperatorContext { home, store })
}

/// Serialise one operator report as exactly one JSON object.
fn report_json<T: serde::Serialize>(value: &T) -> Result<String, AxiomError> {
    serde_json::to_string(value).map_err(|error| {
        AxiomError::new(
            ErrorCode::Internal,
            format!("the operator report is not serialisable: {error}"),
        )
    })
}

/// Read one JSON document from an argv-named path.
fn read_document(path: &Path, label: &str) -> Result<serde_json::Value, AxiomError> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        AxiomError::new(ErrorCode::NotFound, format!("{label} could not be read"))
            .with_detail("path", path.to_string_lossy())
            .with_detail("io", error.to_string())
    })?;
    serde_json::from_str(&text).map_err(|error| {
        AxiomError::new(
            ErrorCode::ConfigInvalid,
            format!("{label} is not valid JSON"),
        )
        .with_detail("path", path.to_string_lossy())
        .with_detail("parse", error.to_string())
    })
}

/// Run one bounded foreground reconcile pass over every registered solution.
fn serve_command(registry: Option<&Path>, telemetry: &mut Telemetry) -> Result<String, AxiomError> {
    let config = ServiceConfig::load(registry)?;
    let report = serve::serve(&config, telemetry)?;
    report_json(&report)
}

/// Read the status report of one registered solution.
fn status_command(solution: &str) -> Result<String, AxiomError> {
    let context = open_operator()?;
    let report = doctor::status(context.store.connection(), solution)?;
    report_json(&report)
}

/// Read the doctor report for one solution, or one report per registered solution.
fn doctor_command(solution: Option<&str>) -> Result<String, AxiomError> {
    let context = open_operator()?;
    // This build plans a stat-based inventory on every pass; it binds no
    // continuous filesystem watcher, and reporting `native` would overstate it.
    let watcher = doctor::WatcherHealth::degraded(
        doctor::WatcherMode::Polling,
        "no continuous filesystem watcher is bound in this build; each pass plans a stat-based inventory",
    );
    match solution {
        Some(solution_id) => {
            let report = doctor::report(context.store.connection(), solution_id, watcher)?;
            report_json(&report)
        }
        None => {
            let solutions = runtime::solutions(context.store.connection())?;
            let mut reports = Vec::with_capacity(solutions.len());
            for row in &solutions {
                reports.push(doctor::report(
                    context.store.connection(),
                    &row.id,
                    watcher.clone(),
                )?);
            }
            report_json(&reports)
        }
    }
}

/// Administer the solution registry.
fn solution_command(command: &SolutionCommand) -> Result<String, AxiomError> {
    let mut context = open_operator()?;
    match command {
        SolutionCommand::Register {
            config,
            bindings,
            mode,
        } => {
            let document = read_document(config, "the solution configuration")?;
            let declaration = solution::parse_config(&document)?;
            let table = match bindings {
                Some(path) => {
                    let text = std::fs::read_to_string(path).map_err(|error| {
                        AxiomError::new(
                            ErrorCode::NotFound,
                            "the bindings document could not be read",
                        )
                        .with_detail("rule", "bindings-document-missing")
                        .with_detail("path", path.to_string_lossy())
                        .with_detail("io", error.to_string())
                    })?;
                    changed::BindingsDocument::parse(&text)?
                }
                None => runtime::load_bindings(&context.home)?,
            };
            let dry_run = matches!(mode, PlanMode::DryRun);
            let plan =
                solution::plan_register(context.store.connection(), &declaration, &table, dry_run)?;
            if dry_run {
                report_json(&plan)
            } else {
                let record =
                    solution::apply_register(context.store.connection_mut(), &plan, &declaration)?;
                report_json(&record)
            }
        }
        SolutionCommand::List { solution: only } => {
            let authorized: Option<Vec<String>> = only.as_ref().map(|id| vec![id.clone()]);
            let records = solution::list(context.store.connection(), authorized.as_deref())?;
            report_json(&records)
        }
        SolutionCommand::Remove {
            solution: solution_id,
            mode,
        } => {
            let dry_run = matches!(mode, PlanMode::DryRun);
            let plan = solution::plan_remove(context.store.connection(), solution_id, dry_run)?;
            if dry_run {
                report_json(&plan)
            } else {
                let report = solution::apply_remove(context.store.connection_mut(), &plan)?;
                report_json(&report)
            }
        }
    }
}

/// Inspect and steer the operational queue.
fn queue_command(command: &QueueCommand) -> Result<String, AxiomError> {
    let context = open_operator()?;
    let gate = queue::RegistrationGate::registered(context.store.connection());
    match command {
        QueueCommand::List { solution, limit } => {
            let page = queue::list(
                context.store.connection(),
                &gate,
                solution,
                limit.unwrap_or(queue::DEFAULT_LIST_LIMIT),
            )?;
            report_json(&page)
        }
        QueueCommand::Retry { job } => {
            let mutation = queue::retry(
                context.store.connection(),
                &gate,
                job,
                &graph_store::migrations::utc_timestamp(),
            )?;
            report_json(&mutation)
        }
        QueueCommand::Cancel { job } => {
            let mutation = queue::cancel(context.store.connection(), &gate, job)?;
            report_json(&mutation)
        }
    }
}

/// Record a bounded reconcile request and run the same bounded pass the daemon runs.
fn reconcile_command(
    command: &ReconcileCommand,
    telemetry: &mut Telemetry,
) -> Result<String, AxiomError> {
    let ReconcileCommand::Request {
        solution,
        scope,
        project,
        wait,
        timeout_ms,
    } = command;
    let scope = match scope {
        Scope::Dirty => reconcile::ReconcileScope::Dirty,
        Scope::Project => reconcile::ReconcileScope::Project,
        Scope::Full => reconcile::ReconcileScope::Full,
    };
    let mut request = reconcile::ReconcileRequest::new(scope);
    if let Some(project) = project {
        request = request.with_project(project.clone());
    }
    request = request.with_wait(*wait);
    if let Some(timeout_ms) = timeout_ms {
        request = request.with_timeout_ms(*timeout_ms);
    }
    request.validate()?;

    let context = open_operator()?;
    let row = runtime::solution(context.store.connection(), solution)?;
    let plan = reconcile::plan(context.store.connection(), solution, &request)?;
    runtime::enqueue_job(
        context.store.connection(),
        &plan.job_id,
        solution,
        &plan.kind,
        &plan.scope_key,
        row.event_seq,
    )?;

    // The one-shot worker runs the same bounded pass the daemon runs, under the
    // same instance lock, so a `--wait` request is satisfied by the pass itself
    // rather than by polling a queue the caller cannot observe.
    let config = ServiceConfig::load(None)?;
    let report = serve::reconcile(&config, solution, project.as_deref(), telemetry)?;
    let budget = reconcile::WaitBudget::for_request(&request);
    reconcile::enforce_wait(&budget, true)?;
    report_json(&report)
}

/// Read a bounded context or impact projection from a pinned snapshot.
fn query_command(command: &QueryCommand) -> Result<String, AxiomError> {
    let context = open_operator()?;
    let (solution, selector, parsed) = match command {
        QueryCommand::Context {
            solution,
            selector,
            limits,
        }
        | QueryCommand::Impact {
            solution,
            selector,
            limits,
        } => (solution, selector, limits),
    };
    let limits = query::QueryLimits::new(
        parsed.max_bytes.unwrap_or(query::DEFAULT_MAX_BYTES),
        parsed.max_nodes.unwrap_or(query::DEFAULT_MAX_NODES),
        parsed.depth.unwrap_or(query::DEFAULT_DEPTH),
    );
    let subject = match selector {
        Selector::Symbol(name) => name,
        Selector::NodeId(node_id) => node_id,
    };
    let projects = runtime::projects(context.store.connection(), solution)?;
    if projects.is_empty() {
        return Err(AxiomError::new(
            ErrorCode::NotFound,
            "this solution has no registered project",
        )
        .with_detail("rule", solution::REASON_SOLUTION_NOT_FOUND)
        .with_detail("solution_id", solution));
    }
    // Each project pins its own published generation. The answer comes from the
    // first project, in id order, that can answer the subject; the last error is
    // reported when no project can, so a miss never becomes an empty success.
    let mut last_error = None;
    for project in &projects {
        let root = match serve::resolve_one_project(&context.home, project) {
            Ok(root) => root,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let snapshot = match serve::load_snapshot(solution, project, &root) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let projection = match command {
            QueryCommand::Context { .. } => query::context(solution, &snapshot, subject, limits),
            QueryCommand::Impact { .. } => query::impact(solution, &snapshot, subject, limits),
        };
        match projection {
            Ok(projection) => return projection.render_json(),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        AxiomError::new(ErrorCode::NotFound, "no registered project could be read")
    }))
}

/// `render --solution <id> [--project <project>]... --out <dir>`.
fn parse_render(tokens: &mut Tokens) -> Result<Command, AxiomError> {
    const CONTEXT: &str = "the render command";
    let solution = tokens.required("--solution", CONTEXT)?;
    validate_identifier(&solution, "--solution", CONTEXT)?;
    let projects = tokens.take_all("--project");
    for project in &projects {
        validate_identifier(project, "--project", CONTEXT)?;
    }
    let out = tokens.required("--out", CONTEXT)?;
    if out.trim().is_empty() {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            format!("--out for {CONTEXT} must be a non-empty directory path"),
        ));
    }
    tokens.finish(CONTEXT)?;
    Ok(Command::Render(RenderCommand {
        solution,
        projects,
        out: PathBuf::from(out),
    }))
}

/// Render a deterministic diagram of one solution's published generations.
fn render_command(command: &RenderCommand) -> Result<String, AxiomError> {
    let context = open_operator()?;
    runtime::solution(context.store.connection(), &command.solution)?;
    let registered = runtime::projects(context.store.connection(), &command.solution)?;
    let selected: Vec<runtime::ProjectRow> = if command.projects.is_empty() {
        registered
    } else {
        let mut selected = Vec::with_capacity(command.projects.len());
        for id in &command.projects {
            match registered.iter().find(|project| &project.id == id) {
                Some(project) => selected.push(project.clone()),
                None => {
                    return Err(AxiomError::new(
                        ErrorCode::NotFound,
                        "a selected project is not a member of this solution",
                    )
                    .with_detail("rule", reconcile::REASON_PROJECT_NOT_FOUND)
                    .with_detail("solution_id", command.solution.clone())
                    .with_detail("project_id", id.clone()))
                }
            }
        }
        selected
    };
    if selected.is_empty() {
        return Err(AxiomError::new(
            ErrorCode::NotFound,
            "this solution has no registered project",
        )
        .with_detail("rule", render::REASON_NO_PROJECT)
        .with_detail("solution_id", command.solution.clone()));
    }

    // Each project is read through the frozen reader under the store's shared
    // lock, and the store's own publication row is compared with the generation
    // that was actually read. Freshness is only claimed when every project's
    // recorded generation agrees with the rendered one.
    let mut graphs = Vec::with_capacity(selected.len());
    let mut latest_published: Vec<String> = Vec::with_capacity(selected.len());
    let mut compared = true;
    for project in &selected {
        let root = serve::resolve_one_project(&context.home, project)?;
        let snapshot = serve::load_snapshot(&command.solution, project, &root)?;
        match runtime::latest_published(context.store.connection(), &project.id)? {
            Some((generation, _)) => {
                compared = compared && generation == snapshot.generation_id();
                latest_published.push(generation);
            }
            None => compared = false,
        }
        graphs.push(render::ProjectGraph::new(project.id.clone(), snapshot));
    }
    let status = doctor::status(context.store.connection(), &command.solution)?;
    let freshness = render::FreshnessInput::new(
        usize::try_from(status.dirty_files).unwrap_or(usize::MAX),
        latest_published,
        if compared {
            render::VerificationMode::InventoryHash
        } else {
            render::VerificationMode::None
        },
    );
    let diagram = render::build_diagram(&command.solution, &graphs, &freshness)?;
    let report = render::write_diagram(&diagram, &command.out)?;
    report_json(&report)
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
        Command::Serve { registry } => serve_command(registry.as_deref(), telemetry),
        Command::Doctor { solution } => doctor_command(solution.as_deref()),
        Command::Status { solution } => status_command(solution),
        Command::Solution(command) => solution_command(command),
        Command::Reconcile(command) => reconcile_command(command, telemetry),
        Command::Queue(command) => queue_command(command),
        Command::Query(command) => query_command(command),
        Command::Render(command) => render_command(command),
        // Still unwired: no production binding reaches these from argv yet.
        Command::Changed(_) => Err(not_ready("changed")),
        Command::Update(_) => Err(not_ready("update")),
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

    /// One representative, valid argv per slice H-002 wired to a real binding.
    fn wired_argv() -> Vec<Vec<String>> {
        vec![
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
            argv(&[
                "render",
                "--solution",
                "demo-solution",
                "--project",
                "auth-api",
                "--out",
                "out",
                "--json",
            ]),
        ]
    }

    /// One representative, valid argv per slice that is still unwired, in slice
    /// order. These keep answering the reason their slice declares.
    fn unwired_argv() -> Vec<Vec<String>> {
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
            vec!["render", "--help"],
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
    fn text_mode_unwired_slices_keep_stdout_empty() {
        for arguments in unwired_argv() {
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

    /// H-002 wired `serve`, `solution`, `queue`, `reconcile`, `status`, `doctor`
    /// and `query` to real bindings, so none of them may still answer the stub:
    /// every slice whose reason is empty is wired, and the unwired slices are
    /// exactly the ones that still declare a reason.
    #[test]
    fn wired_slices_declare_no_reason_and_unwired_slices_still_do() {
        let declared: Vec<&str> = OPERATOR_SLICES
            .iter()
            .filter(|slice| !slice.not_ready.is_empty())
            .map(|slice| slice.module)
            .collect();
        assert_eq!(
            declared,
            vec!["changed", "update"],
            "only the slices with no production binding may declare a reason"
        );
        for slice in OPERATOR_SLICES
            .iter()
            .filter(|slice| slice.not_ready.is_empty())
        {
            assert_eq!(
                slice_reason(slice.module),
                None,
                "{} is wired and must have no not-ready path",
                slice.module
            );
        }
    }

    /// The two argv fixtures must agree with the declaration above, so a slice
    /// cannot be listed as wired in one place and left answering a stub in the
    /// other. The live behaviour of a wired verb needs an instance home, so this
    /// test stops at parsing and dispatch classification; the end-to-end run is
    /// the H-002 manual evidence rather than a unit test that would write into
    /// the developer's own `AXIOM_HOME`.
    #[test]
    fn wired_and_unwired_argv_match_the_declared_wiring() {
        for arguments in wired_argv() {
            let verb = arguments.first().expect("a verb");
            assert_eq!(slice_reason(verb), None, "{verb} must be wired");
            assert!(
                !matches!(parse(&arguments).command(), Command::Rejected { .. }),
                "{} must parse",
                arguments.join(" ")
            );
        }
        for arguments in unwired_argv() {
            let verb = arguments.first().expect("a verb");
            assert!(
                slice_reason(verb).is_some(),
                "{verb} must still declare why it cannot finish"
            );
        }
    }

    #[test]
    fn unwired_slices_answer_not_ready_instead_of_empty_success() {
        let expected = ErrorCode::NotReady.as_str();
        for arguments in unwired_argv() {
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
                message.contains("later work package") || message.contains("no production wiring"),
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
