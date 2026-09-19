//! Claude Code MCP and policy fragments (task E-028).
//!
//! Claude Code reads MCP servers from JSON and discovers its instructions from
//! `CLAUDE.md` (S20, S12). Its native schema names the transport explicitly -
//! `type` plus `url` for a remote server, `type` plus `command`/`args` for a
//! stdio server - which is why this adapter renders a `type`/`url` object where
//! the Codex adapter renders `url` + `bearer_token_env_var` and the Gemini
//! adapter renders `httpUrl` (`25-HOST-ADAPTERS-AND-HOOKS.md` section 5). A
//! field that belongs to another host (`httpUrl`, `serverUrl`, `sseUrl`,
//! `bearer_token_env_var`) is refused instead of being accepted as an unknown
//! key, so a copy-pasted block fails validation here rather than producing a
//! server Claude Code ignores.
//!
//! ## Config scope and instruction discovery travel together
//!
//! Two scopes are planned for, and each scope owns both a config file and an
//! instruction file:
//!
//! | Scope | config | instruction |
//! | --- | --- | --- |
//! | `user` | `<home>/.claude.json` | `<home>/.claude/CLAUDE.md` |
//! | `project` | `<project>/.mcp.json` | `<project>/CLAUDE.md` |
//!
//! [`ClaudePaths::scope_files`] returns the pair, so a plan cannot write a
//! project-scoped server while claiming a user-scoped instruction file. An
//! unrecognised scope is refused ([`RULE_UNSUPPORTED_SCOPE`]) rather than mapped
//! to a default, matching `25-HOST-ADAPTERS-AND-HOOKS.md` section 4.
//!
//! ## Existing permissions are never widened
//!
//! Claude Code enforces tool permissions from `permissions.allow` and
//! `permissions.deny`. This adapter never writes that object, and
//! [`assert_permissions_not_widened`] refuses a request that would add a new
//! allow entry, so installing an MCP server cannot silently grant itself tools.
//! The merge touches only `mcpServers`, so an existing `permissions` object, an
//! existing `hooks` object and every unknown top-level key survive unchanged.
//!
//! ## JSON is merged by value
//!
//! JSON has no comments, so the only thing a rewrite can lose is whitespace and
//! key order. This module therefore parses with the workspace's one JSON codec
//! (`serde_json`, the dependency `crate::plan` also uses) and re-serialises;
//! `serde_json::Map` keeps keys in sorted order, so a document this adapter
//! rewrites is normalised to sorted keys and two-space indentation. That
//! normalisation is a recorded limitation, not a preservation guarantee.
//!
//! Nothing here reads or writes a real `~/.claude.json` or `<project>/.mcp.json`:
//! [`ClaudePlan::apply`] is a pure function of text the caller already holds.

use std::path::Path;

use graph_core::error::{AxiomError, ErrorCode};
use serde_json::{json, Map, Value};

use crate::bootstrap::markers;

/// Directory under the user home that holds Claude Code state.
pub const CLAUDE_DIR: &str = ".claude";
/// User-scope MCP configuration file, directly under the user home (S20).
pub const CLAUDE_USER_CONFIG_FILE: &str = ".claude.json";
/// Settings file under [`CLAUDE_DIR`] that carries permissions and hooks.
pub const CLAUDE_SETTINGS_FILE: &str = "settings.json";
/// Project-scope MCP configuration file (S20).
pub const CLAUDE_PROJECT_CONFIG_FILE: &str = ".mcp.json";
/// Project instruction file Claude Code discovers (S12).
pub const CLAUDE_INSTRUCTION_FILE: &str = "CLAUDE.md";
/// Object that holds MCP servers in both scopes.
pub const MCP_SERVERS_KEY: &str = "mcpServers";
/// Object that carries the tool allow and deny lists.
pub const PERMISSIONS_KEY: &str = "permissions";
/// Allow list inside [`PERMISSIONS_KEY`].
pub const ALLOW_KEY: &str = "allow";
/// Default managed MCP server name.
pub const MANAGED_SERVER: &str = "axiom-graphd";
/// Native `type` value for a remote (Streamable HTTP) server.
pub const HTTP_TRANSPORT: &str = "http";
/// Native `type` value for a locally launched server.
pub const STDIO_TRANSPORT: &str = "stdio";

/// Largest configuration document this module will parse.
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
/// Largest number of servers accepted in one document.
pub const MAX_SERVERS: usize = 512;
/// Largest accepted string value.
pub const MAX_VALUE_BYTES: usize = 4096;
/// Largest accepted argv.
pub const MAX_ARGS: usize = 64;

/// Refusal: the document is not the JSON object this schema expects.
pub const RULE_UNSUPPORTED_SYNTAX: &str = "json-unsupported-syntax";
/// Refusal: a scope this adapter does not plan for.
pub const RULE_UNSUPPORTED_SCOPE: &str = "unsupported-scope";
/// Refusal: a field outside the native Claude MCP schema.
pub const RULE_UNKNOWN_FIELD: &str = "unknown-field";
/// Refusal: a transport field belonging to another host's schema.
pub const RULE_UNSUPPORTED_TRANSPORT_FIELD: &str = "unsupported-transport-field";
/// Refusal: the declared transport is missing its address.
pub const RULE_TRANSPORT_MISSING: &str = "transport-missing";
/// Refusal: both the HTTP and the stdio transport are declared.
pub const RULE_TRANSPORT_CONFLICT: &str = "transport-conflict";
/// Refusal: a `type` this adapter does not plan for.
pub const RULE_TRANSPORT_UNSUPPORTED: &str = "transport-unsupported";
/// Refusal: a credential value written literally.
pub const RULE_CREDENTIAL_LITERAL: &str = "credential-literal-refused";
/// Refusal: a credential in the URL query string.
pub const RULE_CREDENTIAL_IN_URL: &str = "credential-in-url-refused";
/// Refusal: non-loopback plaintext HTTP.
pub const RULE_INSECURE_TRANSPORT: &str = "insecure-transport-refused";
/// Refusal: a relative stdio command.
pub const RULE_STDIO_COMMAND_NOT_ABSOLUTE: &str = "stdio-command-not-absolute";
/// Refusal: a stdio command with shell metacharacters.
pub const RULE_STDIO_COMMAND_HAS_SHELL: &str = "stdio-command-has-shell-metacharacters";
/// Refusal: a request that would grant a new tool permission.
pub const RULE_PERMISSION_WIDENING: &str = "permission-widening-refused";
/// Refusal: a document or rendered entry larger than the bound.
pub const RULE_OUTPUT_TOO_LARGE: &str = "output-too-large";
/// Refusal: a path that is not an absolute, control-free host path.
pub const RULE_UNSAFE_PATH: &str = "unsafe-path";
/// Refusal: an insert plan meets a document that already declares the server.
pub const RULE_SERVER_ALREADY_PRESENT: &str = "server-already-present";

/// Fields the native Claude MCP entry uses.
pub const SUPPORTED_FIELDS: [&str; 5] = ["type", "url", "command", "args", "env"];

/// Transport fields that belong to another host's schema and must never be
/// silently accepted here.
pub const FOREIGN_TRANSPORT_FIELDS: [&str; 4] =
    ["httpUrl", "serverUrl", "sseUrl", "bearer_token_env_var"];

/// Query-string names that mean a credential was placed in the URL.
const CREDENTIAL_QUERY_NAMES: [&str; 4] = ["token", "apikey", "api_key", "password"];

fn refuse(rule: &str, message: impl AsRef<str>) -> AxiomError {
    AxiomError::new(ErrorCode::ValidationError, message).with_detail("rule", rule)
}

/// The Claude Code configuration scopes this adapter plans for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudeScope {
    /// User scope: the home config file and the home instruction file.
    User,
    /// Project scope: the project config file and the project instruction file.
    Project,
}

impl ClaudeScope {
    /// Every scope this adapter accepts, in wire order.
    pub const ALL: [ClaudeScope; 2] = [Self::User, Self::Project];

    /// The stable wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
        }
    }

    /// Parse a wire spelling, refusing anything this adapter does not plan for.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "project" => Some(Self::Project),
            _ => None,
        }
    }
}

/// The config and instruction file one scope owns, as a pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeScopeFiles {
    /// The scope these two paths belong to.
    pub scope: ClaudeScope,
    /// Absolute path of the MCP configuration file.
    pub config_file: String,
    /// Absolute path of the instruction file Claude Code discovers.
    pub instruction_file: String,
}

/// Absolute paths this adapter plans for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudePaths {
    home: String,
    project: String,
}

impl ClaudePaths {
    /// Bind the two absolute roots.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with [`RULE_UNSAFE_PATH`] when either root
    /// is relative, empty, oversized or holds a control character.
    pub fn resolve(home: &str, project: &str) -> Result<Self, AxiomError> {
        for root in [home, project] {
            if !is_safe_root(root) {
                return Err(
                    refuse(RULE_UNSAFE_PATH, "a root must be an absolute host path")
                        .with_detail("portable_path", root),
                );
            }
        }
        Ok(Self {
            home: home.trim_end_matches(['/', '\\']).to_owned(),
            project: project.trim_end_matches(['/', '\\']).to_owned(),
        })
    }

    /// The resolved user home.
    #[must_use]
    pub fn home(&self) -> &str {
        &self.home
    }

    /// The resolved project root.
    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }

    /// The user-scope MCP configuration file.
    #[must_use]
    pub fn user_config_file(&self) -> String {
        format!("{}/{}", self.home, CLAUDE_USER_CONFIG_FILE)
    }

    /// The settings file that carries permissions and hooks.
    #[must_use]
    pub fn settings_file(&self) -> String {
        format!("{}/{}/{}", self.home, CLAUDE_DIR, CLAUDE_SETTINGS_FILE)
    }

    /// The user-scope instruction file.
    #[must_use]
    pub fn user_instruction_file(&self) -> String {
        format!("{}/{}/{}", self.home, CLAUDE_DIR, CLAUDE_INSTRUCTION_FILE)
    }

    /// The project-scope MCP configuration file.
    #[must_use]
    pub fn project_config_file(&self) -> String {
        format!("{}/{}", self.project, CLAUDE_PROJECT_CONFIG_FILE)
    }

    /// The project-scope instruction file.
    #[must_use]
    pub fn project_instruction_file(&self) -> String {
        format!("{}/{}", self.project, CLAUDE_INSTRUCTION_FILE)
    }

    /// The config file of one scope.
    #[must_use]
    pub fn config_file(&self, scope: ClaudeScope) -> String {
        match scope {
            ClaudeScope::User => self.user_config_file(),
            ClaudeScope::Project => self.project_config_file(),
        }
    }

    /// The instruction file of one scope.
    #[must_use]
    pub fn instruction_file(&self, scope: ClaudeScope) -> String {
        match scope {
            ClaudeScope::User => self.user_instruction_file(),
            ClaudeScope::Project => self.project_instruction_file(),
        }
    }

    /// The config and instruction file one scope owns, as one value.
    ///
    /// This is the pairing the plan uses, so a config file can never be written
    /// under a scope whose instruction file was discovered somewhere else.
    #[must_use]
    pub fn scope_files(&self, scope: ClaudeScope) -> ClaudeScopeFiles {
        ClaudeScopeFiles {
            scope,
            config_file: self.config_file(scope),
            instruction_file: self.instruction_file(scope),
        }
    }
}

fn is_safe_root(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 4096
        && !trimmed.chars().any(char::is_control)
        && Path::new(trimmed).is_absolute()
}

/// The native Claude Code MCP transports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaudeTransport {
    /// Remote server: `type = "http"` plus `url`.
    Http {
        /// Endpoint URL.
        url: String,
    },
    /// Local server: `type = "stdio"` plus `command` and `args`.
    Stdio {
        /// Program to launch.
        command: String,
        /// Arguments passed to the program.
        args: Vec<String>,
    },
}

impl ClaudeTransport {
    /// The `type` value this transport renders.
    #[must_use]
    pub const fn declared_type(&self) -> &'static str {
        match self {
            Self::Http { .. } => HTTP_TRANSPORT,
            Self::Stdio { .. } => STDIO_TRANSPORT,
        }
    }
}

/// Validate a remote MCP URL.
pub fn validate_url(url: &str, violations: &mut Vec<String>) {
    if url.trim().is_empty() || url.len() > MAX_VALUE_BYTES || url.chars().any(char::is_control) {
        violations.push("invalid-url".to_owned());
        return;
    }
    if url.contains(char::is_whitespace) {
        violations.push("invalid-url".to_owned());
    }
    let lowered = url.trim().to_ascii_lowercase();
    for name in CREDENTIAL_QUERY_NAMES {
        if lowered.contains(&format!("{name}=")) {
            violations.push(RULE_CREDENTIAL_IN_URL.to_owned());
        }
    }
    if let Some(rest) = lowered
        .strip_prefix("http://")
        .or_else(|| lowered.strip_prefix("https://"))
    {
        let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if lowered.starts_with("http://") && !is_loopback(host) {
            violations.push(RULE_INSECURE_TRANSPORT.to_owned());
        }
    } else {
        violations.push("invalid-url".to_owned());
    }
}

fn is_loopback(host: &str) -> bool {
    let bare = host.split('@').next_back().unwrap_or(host);
    let bare = bare.split(':').next().unwrap_or(bare);
    matches!(bare, "127.0.0.1" | "localhost" | "[::1]" | "::1")
}

/// One managed Claude Code MCP server entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeServer {
    /// Server key under `mcpServers`.
    pub name: String,
    /// Declared transport.
    pub transport: ClaudeTransport,
}

impl ClaudeServer {
    /// A remote server with the native `type`/`url` shape.
    #[must_use]
    pub fn http(name: &str, url: &str) -> Self {
        Self {
            name: name.to_owned(),
            transport: ClaudeTransport::Http {
                url: url.to_owned(),
            },
        }
    }

    /// A stdio server with the native `type`/`command`/`args` shape.
    #[must_use]
    pub fn stdio(name: &str, command: &str, args: Vec<String>) -> Self {
        Self {
            name: name.to_owned(),
            transport: ClaudeTransport::Stdio {
                command: command.to_owned(),
                args,
            },
        }
    }

    /// Validate the entry against the documented native schema.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with the rule of the first violation.
    pub fn validate(&self) -> Result<(), AxiomError> {
        let mut violations = Vec::new();
        if self.name.trim().is_empty()
            || !self
                .name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        {
            violations.push("invalid-server-name".to_owned());
        }
        match &self.transport {
            ClaudeTransport::Http { url } => validate_url(url, &mut violations),
            ClaudeTransport::Stdio { command, args } => {
                if command.trim().is_empty() || !Path::new(command).is_absolute() {
                    violations.push(RULE_STDIO_COMMAND_NOT_ABSOLUTE.to_owned());
                }
                if command.contains(' ') || command.contains('"') {
                    violations.push(RULE_STDIO_COMMAND_HAS_SHELL.to_owned());
                }
                if args.len() > MAX_ARGS {
                    violations.push(RULE_OUTPUT_TOO_LARGE.to_owned());
                }
                for arg in args {
                    if arg.len() > MAX_VALUE_BYTES {
                        violations.push(RULE_OUTPUT_TOO_LARGE.to_owned());
                    }
                }
            }
        }
        if violations.is_empty() {
            return Ok(());
        }
        Err(refuse(
            violations.first().expect("a violation").as_str(),
            "the server entry does not satisfy the native Claude MCP schema",
        )
        .with_detail("observed", violations.join(","))
        .with_detail("component", self.name.clone()))
    }

    /// Read an entry out of a document, validating it against that schema.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with [`RULE_UNSUPPORTED_TRANSPORT_FIELD`]
    /// when the entry uses another host's field, [`RULE_UNKNOWN_FIELD`] for any
    /// other unknown key, [`RULE_TRANSPORT_UNSUPPORTED`] for a `type` this
    /// adapter does not plan for, and the [`Self::validate`] rules otherwise.
    pub fn from_json(name: &str, entry: &Value) -> Result<Self, AxiomError> {
        let Some(object) = entry.as_object() else {
            return Err(refuse(
                RULE_UNSUPPORTED_SYNTAX,
                "the server entry is not a JSON object",
            )
            .with_detail("component", name.to_owned()));
        };
        let mut foreign = Vec::new();
        let mut unknown = Vec::new();
        for key in object.keys() {
            if FOREIGN_TRANSPORT_FIELDS.contains(&key.as_str()) {
                foreign.push(key.clone());
            } else if !SUPPORTED_FIELDS.contains(&key.as_str()) {
                unknown.push(key.clone());
            }
        }
        if !foreign.is_empty() {
            return Err(refuse(
                RULE_UNSUPPORTED_TRANSPORT_FIELD,
                "the entry uses a transport field that belongs to another host's schema",
            )
            .with_detail("config_key", foreign.join(","))
            .with_detail("component", name.to_owned()));
        }
        if !unknown.is_empty() {
            return Err(refuse(
                RULE_UNKNOWN_FIELD,
                "the entry uses a field outside the native Claude MCP schema",
            )
            .with_detail("config_key", unknown.join(","))
            .with_detail("component", name.to_owned()));
        }
        let declared = object.get("type").and_then(Value::as_str);
        let url = object.get("url").and_then(Value::as_str);
        let command = object.get("command").and_then(Value::as_str);
        if url.is_some() && command.is_some() {
            return Err(refuse(
                RULE_TRANSPORT_CONFLICT,
                "the entry declares both a remote and a local transport",
            )
            .with_detail("component", name.to_owned()));
        }
        let server = match declared {
            None => {
                return Err(refuse(
                    RULE_TRANSPORT_MISSING,
                    "the entry declares no transport type",
                )
                .with_detail("component", name.to_owned()));
            }
            Some(HTTP_TRANSPORT) => {
                let Some(url) = url else {
                    return Err(refuse(
                        RULE_TRANSPORT_MISSING,
                        "the entry declares the http transport without a url",
                    )
                    .with_detail("component", name.to_owned()));
                };
                Self::http(name, url)
            }
            Some(STDIO_TRANSPORT) => {
                let Some(command) = command else {
                    return Err(refuse(
                        RULE_TRANSPORT_MISSING,
                        "the entry declares the stdio transport without a command",
                    )
                    .with_detail("component", name.to_owned()));
                };
                let mut args = Vec::new();
                if let Some(list) = object.get("args") {
                    let Some(list) = list.as_array() else {
                        return Err(refuse(
                            RULE_UNSUPPORTED_SYNTAX,
                            "args must be an array of strings",
                        )
                        .with_detail("component", name.to_owned()));
                    };
                    for value in list {
                        let Some(text) = value.as_str() else {
                            return Err(refuse(
                                RULE_UNSUPPORTED_SYNTAX,
                                "args must be an array of strings",
                            )
                            .with_detail("component", name.to_owned()));
                        };
                        args.push(text.to_owned());
                    }
                }
                Self::stdio(name, command, args)
            }
            Some(other) => {
                return Err(refuse(
                    RULE_TRANSPORT_UNSUPPORTED,
                    "the entry declares a transport type this adapter does not plan for",
                )
                .with_detail("actual", other.to_owned())
                .with_detail("component", name.to_owned()));
            }
        };
        server.validate()?;
        Ok(server)
    }

    /// The entry as the JSON value the plan writes.
    #[must_use]
    pub fn render_json(&self) -> Value {
        match &self.transport {
            ClaudeTransport::Http { url } => {
                json!({ "type": HTTP_TRANSPORT, "url": url })
            }
            ClaudeTransport::Stdio { command, args } => {
                json!({ "type": STDIO_TRANSPORT, "command": command, "args": args })
            }
        }
    }

    /// The entry as the exact text the plan places, for review.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`] when the value cannot be re-encoded; a constant
    /// object of bounded scalars cannot reach this.
    pub fn render_pretty(&self) -> Result<String, AxiomError> {
        let text = serde_json::to_string_pretty(&self.render_json()).map_err(|_| {
            AxiomError::new(
                ErrorCode::Internal,
                "the entry cannot be re-encoded as JSON",
            )
        })?;
        if text.len() > MAX_VALUE_BYTES * 4 {
            return Err(refuse(
                RULE_OUTPUT_TOO_LARGE,
                "the rendered entry is too large",
            ));
        }
        Ok(text)
    }
}

/// Resolve a wire scope, refusing one this adapter does not plan for.
///
/// # Errors
/// [`ErrorCode::ValidationError`] with [`RULE_UNSUPPORTED_SCOPE`].
pub fn resolve_scope(value: &str) -> Result<ClaudeScope, AxiomError> {
    ClaudeScope::from_wire(value).ok_or_else(|| {
        refuse(
            RULE_UNSUPPORTED_SCOPE,
            "the requested scope is not one this adapter plans for",
        )
        .with_detail("actual", value.to_owned())
        .with_detail(
            "expected",
            ClaudeScope::ALL
                .iter()
                .map(|scope| scope.wire())
                .collect::<Vec<_>>()
                .join(","),
        )
    })
}

fn parse_document(text: &str) -> Result<Map<String, Value>, AxiomError> {
    if text.len() > MAX_CONFIG_BYTES {
        return Err(refuse(
            RULE_OUTPUT_TOO_LARGE,
            "the configuration document is larger than this adapter will parse",
        )
        .with_detail("observed", text.len().to_string()));
    }
    if text.trim().is_empty() {
        return Ok(Map::new());
    }
    let value: Value = serde_json::from_str(text).map_err(|error| {
        refuse(
            RULE_UNSUPPORTED_SYNTAX,
            "the configuration document is not valid JSON",
        )
        .with_detail("observed", error.to_string())
    })?;
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(refuse(
            RULE_UNSUPPORTED_SYNTAX,
            "the configuration document must be a JSON object",
        )),
    }
}

fn managed_present(object: &Map<String, Value>, name: &str) -> bool {
    object
        .get(MCP_SERVERS_KEY)
        .and_then(Value::as_object)
        .is_some_and(|servers| servers.contains_key(name))
}

/// Whether the merge inserts a new entry or replaces the managed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanAction {
    /// Add the server to a document that does not declare it.
    Insert,
    /// Replace only the managed server's value.
    Replace,
}

/// The reviewed Claude Code change: one `mcpServers` entry plus the instruction
/// fragment, for exactly one scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudePlan {
    paths: ClaudePaths,
    scope: ClaudeScope,
    server: ClaudeServer,
    action: PlanAction,
}

impl ClaudePlan {
    /// Build a plan, validating the server and the existing document.
    ///
    /// `existing` is the current config file for `scope` when the caller has
    /// one. A document that already declares the managed server is validated
    /// too, so an entry this adapter does not understand is refused instead of
    /// replaced.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with the rule of the first violation.
    pub fn plan(
        paths: ClaudePaths,
        scope: ClaudeScope,
        server: ClaudeServer,
        existing: Option<&str>,
    ) -> Result<Self, AxiomError> {
        server.validate()?;
        let action = match existing {
            None => PlanAction::Insert,
            Some(text) => {
                let object = parse_document(text)?;
                match object.get(MCP_SERVERS_KEY) {
                    None => PlanAction::Insert,
                    Some(Value::Object(servers)) => {
                        if servers.len() > MAX_SERVERS {
                            return Err(refuse(
                                RULE_OUTPUT_TOO_LARGE,
                                "the document already holds the maximum number of MCP servers",
                            ));
                        }
                        match servers.get(&server.name) {
                            None => PlanAction::Insert,
                            Some(entry) => {
                                ClaudeServer::from_json(&server.name, entry)?;
                                PlanAction::Replace
                            }
                        }
                    }
                    Some(_) => {
                        return Err(refuse(
                            RULE_UNSUPPORTED_SYNTAX,
                            "mcpServers must be a JSON object",
                        ));
                    }
                }
            }
        };
        Ok(Self {
            paths,
            scope,
            server,
            action,
        })
    }

    /// The planned action.
    #[must_use]
    pub const fn action(&self) -> PlanAction {
        self.action
    }

    /// The managed server entry.
    #[must_use]
    pub const fn server(&self) -> &ClaudeServer {
        &self.server
    }

    /// The scope this plan targets.
    #[must_use]
    pub const fn scope(&self) -> ClaudeScope {
        self.scope
    }

    /// The absolute paths this plan was built from.
    #[must_use]
    pub const fn paths(&self) -> &ClaudePaths {
        &self.paths
    }

    /// The config file this plan writes, paired with the planned scope.
    #[must_use]
    pub fn target_file(&self) -> String {
        self.paths.config_file(self.scope)
    }

    /// The instruction file Claude Code discovers for the planned scope.
    #[must_use]
    pub fn instruction_file(&self) -> String {
        self.paths.instruction_file(self.scope)
    }

    /// The managed instruction fragment for the scope's instruction file.
    ///
    /// The fragment carries the same managed-block markers bootstrap owns
    /// (`bootstrap::markers`), so there is one marker vocabulary in this
    /// repository and a human's surrounding text stays outside the block.
    #[must_use]
    pub fn instruction_fragment(&self) -> String {
        format!(
            "{begin}\n## Axiom Graph\n\nRead `.axiom/agent/POLICY.md` before changing this repository,\nand use the `{server}` MCP server for graph queries.\n{end}\n",
            begin = markers::BEGIN_MARKER,
            end = markers::END_MARKER,
            server = self.server.name,
        )
    }

    /// Apply the plan to `existing`, returning the merged document.
    ///
    /// Only `mcpServers` is touched. Every other top-level key - including
    /// `permissions` and `hooks` - is carried through by value.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with [`RULE_SERVER_ALREADY_PRESENT`] when
    /// an insert plan meets a document that declares the server,
    /// [`RULE_UNSUPPORTED_SYNTAX`] for a document outside this schema, and
    /// [`RULE_OUTPUT_TOO_LARGE`] for a document past the bound.
    pub fn apply(&self, existing: &str) -> Result<String, AxiomError> {
        let mut object = parse_document(existing)?;
        if self.action == PlanAction::Insert && managed_present(&object, &self.server.name) {
            return Err(refuse(
                RULE_SERVER_ALREADY_PRESENT,
                "the document already declares the managed server",
            )
            .with_detail("component", self.server.name.clone()));
        }
        let declared = object
            .get(MCP_SERVERS_KEY)
            .and_then(Value::as_object)
            .map_or(0, |servers| servers.len());
        if declared >= MAX_SERVERS && !managed_present(&object, &self.server.name) {
            return Err(refuse(
                RULE_OUTPUT_TOO_LARGE,
                "the document already holds the maximum number of MCP servers",
            ));
        }
        if !object.contains_key(MCP_SERVERS_KEY) {
            object.insert(MCP_SERVERS_KEY.to_owned(), Value::Object(Map::new()));
        }
        let servers = match object.get_mut(MCP_SERVERS_KEY) {
            Some(Value::Object(servers)) => servers,
            _ => {
                return Err(refuse(
                    RULE_UNSUPPORTED_SYNTAX,
                    "mcpServers must be a JSON object",
                ));
            }
        };
        servers.insert(self.server.name.clone(), self.server.render_json());
        let mut text = serde_json::to_string_pretty(&Value::Object(object)).map_err(|_| {
            AxiomError::new(
                ErrorCode::Internal,
                "the merged document cannot be re-encoded as JSON",
            )
        })?;
        text.push('\n');
        if text.len() > MAX_CONFIG_BYTES {
            return Err(refuse(
                RULE_OUTPUT_TOO_LARGE,
                "the merged document is larger than this adapter will write",
            ));
        }
        Ok(text)
    }
}

/// Refuse a request that would add a tool permission the document does not hold.
///
/// MCP installation must never widen Claude Code's `permissions.allow`; this is
/// the guard the install path calls before it writes anything.
///
/// # Errors
/// [`ErrorCode::ValidationError`] with [`RULE_PERMISSION_WIDENING`] when a
/// requested entry is not already granted, or [`RULE_UNSUPPORTED_SYNTAX`] when
/// `existing` is not a JSON object.
pub fn assert_permissions_not_widened(
    existing: &str,
    requested_allow: &[String],
) -> Result<(), AxiomError> {
    let object = parse_document(existing)?;
    let granted: Vec<&str> = object
        .get(PERMISSIONS_KEY)
        .and_then(|value| value.get(ALLOW_KEY))
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let additions: Vec<&str> = requested_allow
        .iter()
        .filter(|entry| !granted.contains(&entry.as_str()))
        .map(String::as_str)
        .collect();
    if additions.is_empty() {
        return Ok(());
    }
    Err(refuse(
        RULE_PERMISSION_WIDENING,
        "the request would grant a permission the existing configuration does not hold",
    )
    .with_detail("observed", additions.join(","))
    .with_detail("config_key", ALLOW_KEY))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(error: &AxiomError) -> String {
        error
            .details()
            .get("rule")
            .cloned()
            .unwrap_or_else(|| "<none>".to_owned())
    }

    fn paths() -> ClaudePaths {
        ClaudePaths::resolve("/home/billy", "/home/billy/projects/demo").expect("safe roots")
    }

    fn managed() -> ClaudeServer {
        ClaudeServer::http(MANAGED_SERVER, "http://127.0.0.1:8766/mcp")
    }

    const EXISTING: &str = r#"{
  "hooks": { "Stop": [] },
  "mcpServers": {
    "other": { "type": "stdio", "command": "/usr/local/bin/other", "args": ["--serve"] }
  },
  "permissions": { "allow": ["Read"], "deny": ["Bash(rm:*)"] },
  "unknownTopLevel": 7
}"#;

    fn with_managed() -> String {
        r#"{
  "mcpServers": {
    "axiom-graphd": { "type": "http", "url": "http://127.0.0.1:1/old" },
    "other": { "type": "stdio", "command": "/usr/local/bin/other", "args": ["--serve"] }
  },
  "permissions": { "allow": ["Read"] }
}
"#
        .to_owned()
    }

    fn parse(text: &str) -> Value {
        serde_json::from_str(text).expect("a parsed document")
    }

    #[test]
    fn the_two_scopes_pair_a_config_file_with_an_instruction_file() {
        let paths = paths();
        let user = paths.scope_files(ClaudeScope::User);
        assert_eq!(user.config_file, "/home/billy/.claude.json");
        assert_eq!(user.instruction_file, "/home/billy/.claude/CLAUDE.md");
        let project = paths.scope_files(ClaudeScope::Project);
        assert_eq!(project.config_file, "/home/billy/projects/demo/.mcp.json");
        assert_eq!(
            project.instruction_file,
            "/home/billy/projects/demo/CLAUDE.md"
        );
        assert_eq!(paths.settings_file(), "/home/billy/.claude/settings.json");

        let plan =
            ClaudePlan::plan(paths.clone(), ClaudeScope::Project, managed(), None).expect("a plan");
        assert_eq!(plan.target_file(), project.config_file);
        assert_eq!(plan.instruction_file(), project.instruction_file);
        let user_plan =
            ClaudePlan::plan(paths, ClaudeScope::User, managed(), None).expect("a plan");
        assert_eq!(user_plan.target_file(), user.config_file);
        assert_eq!(user_plan.instruction_file(), user.instruction_file);
    }

    #[test]
    fn appending_preserves_every_other_server_and_the_permissions_object() {
        let plan = ClaudePlan::plan(paths(), ClaudeScope::Project, managed(), Some(EXISTING))
            .expect("a plan");
        assert_eq!(plan.action(), PlanAction::Insert);
        let planned = plan.apply(EXISTING).expect("a merged document");
        assert!(planned.ends_with('\n'));

        let before = parse(EXISTING);
        let after = parse(&planned);
        assert_eq!(after["permissions"], before["permissions"]);
        assert_eq!(after["hooks"], before["hooks"]);
        assert_eq!(after["unknownTopLevel"], Value::from(7));
        assert_eq!(after["mcpServers"]["other"], before["mcpServers"]["other"]);
        assert_eq!(
            after["mcpServers"]["axiom-graphd"],
            serde_json::json!({ "type": "http", "url": "http://127.0.0.1:8766/mcp" })
        );
    }

    #[test]
    fn replacing_the_managed_entry_changes_only_that_entry() {
        let existing = with_managed();
        let plan = ClaudePlan::plan(paths(), ClaudeScope::Project, managed(), Some(&existing))
            .expect("a plan");
        assert_eq!(plan.action(), PlanAction::Replace);
        let planned = plan.apply(&existing).expect("a merged document");
        assert!(!planned.contains("127.0.0.1:1/old"));
        let before = parse(&existing);
        let after = parse(&planned);
        assert_eq!(after["permissions"], before["permissions"]);
        assert_eq!(after["mcpServers"]["other"], before["mcpServers"]["other"]);
        assert_eq!(
            after["mcpServers"]["axiom-graphd"]["url"],
            Value::from("http://127.0.0.1:8766/mcp")
        );
        assert_eq!(
            after["mcpServers"].as_object().expect("servers").len(),
            before["mcpServers"].as_object().expect("servers").len()
        );
    }

    #[test]
    fn a_foreign_transport_field_fails_validation() {
        for (key, value) in [
            ("httpUrl", "http://127.0.0.1:8766/mcp"),
            ("serverUrl", "http://127.0.0.1:8766/mcp"),
            ("sseUrl", "http://127.0.0.1:8766/sse"),
            ("bearer_token_env_var", "AXIOM_MCP_TOKEN"),
        ] {
            let entry = serde_json::json!({
                "type": HTTP_TRANSPORT,
                "url": "http://127.0.0.1:8766/mcp",
                key: value,
            });
            let error = ClaudeServer::from_json(MANAGED_SERVER, &entry)
                .expect_err("a foreign field is refused");
            assert_eq!(rule(&error), RULE_UNSUPPORTED_TRANSPORT_FIELD);
            assert_eq!(
                error.details().get("config_key").map(String::as_str),
                Some(key)
            );
        }

        let unknown = serde_json::json!({ "type": HTTP_TRANSPORT, "url": "http://127.0.0.1:1/mcp", "foo": 1 });
        let error = ClaudeServer::from_json(MANAGED_SERVER, &unknown)
            .expect_err("an unknown field is refused");
        assert_eq!(rule(&error), RULE_UNKNOWN_FIELD);

        let typeless = serde_json::json!({ "url": "http://127.0.0.1:1/mcp" });
        let error = ClaudeServer::from_json(MANAGED_SERVER, &typeless)
            .expect_err("a transport-less entry is refused");
        assert_eq!(rule(&error), RULE_TRANSPORT_MISSING);

        let conflict = serde_json::json!({
            "type": HTTP_TRANSPORT,
            "url": "http://127.0.0.1:1/mcp",
            "command": "/bin/x",
        });
        let error = ClaudeServer::from_json(MANAGED_SERVER, &conflict)
            .expect_err("two transports are refused");
        assert_eq!(rule(&error), RULE_TRANSPORT_CONFLICT);

        let legacy = serde_json::json!({ "type": "sse", "url": "http://127.0.0.1:1/sse" });
        let error = ClaudeServer::from_json(MANAGED_SERVER, &legacy)
            .expect_err("a transport this adapter does not plan for is refused");
        assert_eq!(rule(&error), RULE_TRANSPORT_UNSUPPORTED);
    }

    #[test]
    fn an_unsupported_scope_is_refused() {
        assert_eq!(resolve_scope("user").expect("user"), ClaudeScope::User);
        assert_eq!(
            resolve_scope("project").expect("project"),
            ClaudeScope::Project
        );
        for value in ["local", "global", "", "USER"] {
            let error = resolve_scope(value).expect_err("an unknown scope is refused");
            assert_eq!(rule(&error), RULE_UNSUPPORTED_SCOPE, "scope: {value}");
        }
    }

    #[test]
    fn a_permission_the_document_does_not_hold_is_refused() {
        assert!(assert_permissions_not_widened(EXISTING, &[]).is_ok());
        assert!(assert_permissions_not_widened(EXISTING, &["Read".to_owned()]).is_ok());
        let error =
            assert_permissions_not_widened(EXISTING, &["Read".to_owned(), "Bash".to_owned()])
                .expect_err("a new grant is refused");
        assert_eq!(rule(&error), RULE_PERMISSION_WIDENING);
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("Bash")
        );
        assert!(assert_permissions_not_widened("{}", &[]).is_ok());
        let error = assert_permissions_not_widened("not json", &["Read".to_owned()])
            .expect_err("a non-JSON document is refused rather than guessed");
        assert_eq!(rule(&error), RULE_UNSUPPORTED_SYNTAX);
    }

    #[test]
    fn a_literal_credential_or_a_credential_url_is_refused() {
        let mut violations = Vec::new();
        validate_url("http://127.0.0.1:8766/mcp?token=abc", &mut violations);
        assert!(violations.contains(&RULE_CREDENTIAL_IN_URL.to_owned()));

        violations.clear();
        validate_url("http://gateway.example/mcp", &mut violations);
        assert!(violations.contains(&RULE_INSECURE_TRANSPORT.to_owned()));

        violations.clear();
        validate_url("ftp://gateway.example/mcp", &mut violations);
        assert!(violations.contains(&"invalid-url".to_owned()));

        assert!(managed().validate().is_ok());
        assert!(
            ClaudeServer::http(MANAGED_SERVER, "https://gateway.example/mcp")
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn a_stdio_entry_requires_an_absolute_shell_free_command() {
        let relative = ClaudeServer::stdio(MANAGED_SERVER, "axiom-graphd", vec![]);
        assert_eq!(
            rule(
                &relative
                    .validate()
                    .expect_err("a relative command is refused")
            ),
            RULE_STDIO_COMMAND_NOT_ABSOLUTE
        );
        let shellish = ClaudeServer::stdio(MANAGED_SERVER, "/bin/sh -c \"x\"", vec![]);
        assert_eq!(
            rule(&shellish.validate().expect_err("a shell command is refused")),
            RULE_STDIO_COMMAND_HAS_SHELL
        );
        let stdio = ClaudeServer::stdio(
            MANAGED_SERVER,
            "/usr/local/bin/axiom-graphd",
            vec!["mcp".to_owned(), "--scope".to_owned(), "demo".to_owned()],
        );
        assert!(stdio.validate().is_ok());
        let entry = stdio.render_json();
        assert_eq!(entry["type"], Value::from(STDIO_TRANSPORT));
        assert_eq!(
            ClaudeServer::from_json(MANAGED_SERVER, &entry).expect("a round trip"),
            stdio
        );
    }

    #[test]
    fn a_document_outside_the_schema_is_refused_rather_than_guessed() {
        for text in ["[1, 2]", "\"text\"", "{ \"mcpServers\": [] }", "{ broken"] {
            let error = ClaudePlan::plan(paths(), ClaudeScope::Project, managed(), Some(text))
                .expect_err("an unusable document is refused");
            assert_eq!(rule(&error), RULE_UNSUPPORTED_SYNTAX, "text: {text}");
        }
        let oversized = format!("{{\"padding\": \"{}\"}}", "x".repeat(MAX_CONFIG_BYTES));
        let error = ClaudePlan::plan(paths(), ClaudeScope::Project, managed(), Some(&oversized))
            .expect_err("an oversized document is refused");
        assert_eq!(rule(&error), RULE_OUTPUT_TOO_LARGE);
    }

    #[test]
    fn an_insert_plan_refuses_a_document_that_already_declares_the_server() {
        let plan = ClaudePlan::plan(paths(), ClaudeScope::User, managed(), None).expect("a plan");
        assert_eq!(plan.action(), PlanAction::Insert);
        let existing = with_managed();
        let error = plan
            .apply(&existing)
            .expect_err("an already-declared server is refused on insert");
        assert_eq!(rule(&error), RULE_SERVER_ALREADY_PRESENT);
    }

    #[test]
    fn the_instruction_fragment_uses_the_managed_block_markers() {
        let plan =
            ClaudePlan::plan(paths(), ClaudeScope::Project, managed(), None).expect("a plan");
        let fragment = plan.instruction_fragment();
        assert!(fragment.starts_with(markers::BEGIN_MARKER));
        assert!(fragment.trim_end().ends_with(markers::END_MARKER));
        assert!(fragment.contains(MANAGED_SERVER));
    }
}
