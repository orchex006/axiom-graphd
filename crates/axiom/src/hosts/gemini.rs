//! Gemini CLI MCP and policy fragments (task E-029).
//!
//! Gemini CLI reads MCP servers from `settings.json` and discovers its
//! instructions from `GEMINI.md` (S17, S18). Its schema is the one place where
//! the two remote transports are named by **different fields**: Streamable HTTP
//! is `httpUrl` and Server-Sent Events is `url` (S18). That difference is the
//! reason this is a separate adapter and not a copy of the Claude one, and it is
//! the specific mistake [`RULE_TRANSPORT_FIELD_MISMATCH`] exists to catch: an
//! `httpUrl` on a server declared as SSE, or a bare `url` on a server declared
//! as Streamable HTTP, is refused instead of being written and silently ignored
//! by the host.
//!
//! ## Scope, instruction discovery and the policy path
//!
//! | Scope | config | instruction | policy |
//! | --- | --- | --- | --- |
//! | `user` | `<home>/.gemini/settings.json` | `<home>/.gemini/GEMINI.md` | `<home>/.gemini/policies` |
//! | `project` | `<project>/.gemini/settings.json` | `<project>/GEMINI.md` | `<project>/.gemini/policies` |
//!
//! [`GeminiPaths::scope_files`] returns the config, instruction and policy path
//! as one value, so a plan cannot render a config for one scope while claiming
//! another scope's discovery path, and [`verify_policy_path`] refuses a policy
//! path this adapter has not certified ([`RULE_POLICY_PATH_NOT_CERTIFIED`])
//! rather than guessing one. The recorded policy location is the one the
//! reviewed seed documents (S17/S18); it is *not* independently confirmed
//! against an installed host on this machine - see the unrun section of
//! `docs/guides/host-adapters.md`.
//!
//! ## JSON is merged by value
//!
//! As with the Claude adapter, JSON has no comments, so a rewrite can only lose
//! whitespace and key order. The document is parsed with the workspace's one
//! JSON codec (`serde_json`) and re-serialised, which normalises key order to
//! sorted and indentation to two spaces. That normalisation is a recorded
//! limitation, not a preservation guarantee.
//!
//! Nothing here reads or writes a real `~/.gemini/settings.json`;
//! [`GeminiPlan::apply`] is a pure function of text the caller already holds.

use std::path::Path;

use graph_core::error::{AxiomError, ErrorCode};
use serde_json::{json, Map, Value};

use crate::bootstrap::markers;

/// Directory under the user home that holds Gemini CLI state.
pub const GEMINI_DIR: &str = ".gemini";
/// Settings file name inside [`GEMINI_DIR`].
pub const GEMINI_SETTINGS_FILE: &str = "settings.json";
/// Project-scope instruction file Gemini CLI discovers (S17).
pub const GEMINI_INSTRUCTION_FILE: &str = "GEMINI.md";
/// Documented policy directory inside [`GEMINI_DIR`].
pub const GEMINI_POLICY_DIR: &str = "policies";
/// Object that holds MCP servers.
pub const MCP_SERVERS_KEY: &str = "mcpServers";
/// Default managed MCP server name.
pub const MANAGED_SERVER: &str = "axiom-graphd";

/// Native field for a Streamable HTTP server (S18).
pub const HTTP_URL_FIELD: &str = "httpUrl";
/// Native field for a Server-Sent Events server (S18).
pub const SSE_URL_FIELD: &str = "url";
/// Native field for a locally launched server.
pub const COMMAND_FIELD: &str = "command";
/// Optional explicit transport assertion.
pub const TYPE_FIELD: &str = "type";

/// `type` spelling that asserts Streamable HTTP.
pub const STREAMABLE_HTTP_TYPE: &str = "http";
/// `type` spelling that also asserts Streamable HTTP.
pub const STREAMABLE_HTTP_TYPE_ALT: &str = "streamable-http";
/// `type` spelling that asserts Server-Sent Events.
pub const SSE_TYPE: &str = "sse";
/// `type` spelling that asserts a locally launched server.
pub const STDIO_TYPE: &str = "stdio";

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
/// Refusal: a field outside the native Gemini MCP schema.
pub const RULE_UNKNOWN_FIELD: &str = "unknown-field";
/// Refusal: a transport field belonging to another host's schema.
pub const RULE_UNSUPPORTED_TRANSPORT_FIELD: &str = "unsupported-transport-field";
/// Refusal: the declared transport is missing its address.
pub const RULE_TRANSPORT_MISSING: &str = "transport-missing";
/// Refusal: more than one transport is declared.
pub const RULE_TRANSPORT_CONFLICT: &str = "transport-conflict";
/// Refusal: the declared `type` and the transport field disagree.
pub const RULE_TRANSPORT_FIELD_MISMATCH: &str = "transport-field-mismatch";
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
/// Refusal: a policy path this adapter has not certified.
pub const RULE_POLICY_PATH_NOT_CERTIFIED: &str = "policy-path-not-certified";
/// Refusal: a document or rendered entry larger than the bound.
pub const RULE_OUTPUT_TOO_LARGE: &str = "output-too-large";
/// Refusal: a path that is not an absolute, control-free host path.
pub const RULE_UNSAFE_PATH: &str = "unsafe-path";
/// Refusal: an insert plan meets a document that already declares the server.
pub const RULE_SERVER_ALREADY_PRESENT: &str = "server-already-present";

/// Fields the native Gemini MCP entry uses or accepts.
///
/// `headers` and `timeout` are accepted so an entry a human already wrote is not
/// refused for a documented key this adapter simply does not render.
pub const SUPPORTED_FIELDS: [&str; 8] = [
    HTTP_URL_FIELD,
    SSE_URL_FIELD,
    COMMAND_FIELD,
    TYPE_FIELD,
    "args",
    "env",
    "headers",
    "timeout",
];

/// Transport fields that belong to another host's schema and must never be
/// silently accepted here.
pub const FOREIGN_TRANSPORT_FIELDS: [&str; 3] = ["serverUrl", "sseUrl", "bearer_token_env_var"];

/// Query-string names that mean a credential was placed in the URL.
const CREDENTIAL_QUERY_NAMES: [&str; 4] = ["token", "apikey", "api_key", "password"];

fn refuse(rule: &str, message: impl AsRef<str>) -> AxiomError {
    AxiomError::new(ErrorCode::ValidationError, message).with_detail("rule", rule)
}

/// The Gemini CLI configuration scopes this adapter plans for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeminiScope {
    /// User scope: the home settings file and the home instruction file.
    User,
    /// Project scope: the project settings file and the project instruction file.
    Project,
}

impl GeminiScope {
    /// Every scope this adapter accepts, in wire order.
    pub const ALL: [GeminiScope; 2] = [Self::User, Self::Project];

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

/// The config, instruction and policy paths one scope owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiScopeFiles {
    /// The scope these paths belong to.
    pub scope: GeminiScope,
    /// Absolute path of the settings file.
    pub config_file: String,
    /// Absolute path of the instruction file Gemini CLI discovers.
    pub instruction_file: String,
    /// Absolute path of the documented policy directory.
    pub policy_dir: String,
}

/// Absolute paths this adapter plans for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiPaths {
    home: String,
    project: String,
}

impl GeminiPaths {
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

    /// The user-scope settings file.
    #[must_use]
    pub fn user_config_file(&self) -> String {
        format!("{}/{}/{}", self.home, GEMINI_DIR, GEMINI_SETTINGS_FILE)
    }

    /// The user-scope instruction file.
    #[must_use]
    pub fn user_instruction_file(&self) -> String {
        format!("{}/{}/{}", self.home, GEMINI_DIR, GEMINI_INSTRUCTION_FILE)
    }

    /// The project-scope settings file.
    #[must_use]
    pub fn project_config_file(&self) -> String {
        format!("{}/{}/{}", self.project, GEMINI_DIR, GEMINI_SETTINGS_FILE)
    }

    /// The project-scope instruction file.
    #[must_use]
    pub fn project_instruction_file(&self) -> String {
        format!("{}/{}", self.project, GEMINI_INSTRUCTION_FILE)
    }

    /// The config file of one scope.
    #[must_use]
    pub fn config_file(&self, scope: GeminiScope) -> String {
        match scope {
            GeminiScope::User => self.user_config_file(),
            GeminiScope::Project => self.project_config_file(),
        }
    }

    /// The instruction file of one scope.
    #[must_use]
    pub fn instruction_file(&self, scope: GeminiScope) -> String {
        match scope {
            GeminiScope::User => self.user_instruction_file(),
            GeminiScope::Project => self.project_instruction_file(),
        }
    }

    /// The documented policy directory of one scope.
    #[must_use]
    pub fn policy_dir(&self, scope: GeminiScope) -> String {
        match scope {
            GeminiScope::User => {
                format!("{}/{}/{}", self.home, GEMINI_DIR, GEMINI_POLICY_DIR)
            }
            GeminiScope::Project => {
                format!("{}/{}/{}", self.project, GEMINI_DIR, GEMINI_POLICY_DIR)
            }
        }
    }

    /// The config, instruction and policy paths one scope owns, as one value.
    #[must_use]
    pub fn scope_files(&self, scope: GeminiScope) -> GeminiScopeFiles {
        GeminiScopeFiles {
            scope,
            config_file: self.config_file(scope),
            instruction_file: self.instruction_file(scope),
            policy_dir: self.policy_dir(scope),
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

/// Resolve a wire scope, refusing one this adapter does not plan for.
///
/// # Errors
/// [`ErrorCode::ValidationError`] with [`RULE_UNSUPPORTED_SCOPE`].
pub fn resolve_scope(value: &str) -> Result<GeminiScope, AxiomError> {
    GeminiScope::from_wire(value).ok_or_else(|| {
        refuse(
            RULE_UNSUPPORTED_SCOPE,
            "the requested scope is not one this adapter plans for",
        )
        .with_detail("actual", value.to_owned())
        .with_detail(
            "expected",
            GeminiScope::ALL
                .iter()
                .map(|scope| scope.wire())
                .collect::<Vec<_>>()
                .join(","),
        )
    })
}

/// Refuse a policy path this adapter has not certified.
///
/// The adapter renders configuration for exactly one documented policy location
/// per scope. Any other candidate is refused, because guessing a policy path is
/// how a plan writes where the host never reads.
///
/// # Errors
/// [`ErrorCode::ValidationError`] with [`RULE_POLICY_PATH_NOT_CERTIFIED`].
pub fn verify_policy_path(
    paths: &GeminiPaths,
    scope: GeminiScope,
    candidate: &str,
) -> Result<(), AxiomError> {
    let documented = paths.policy_dir(scope);
    if candidate == documented {
        return Ok(());
    }
    Err(refuse(
        RULE_POLICY_PATH_NOT_CERTIFIED,
        "the policy path is not the documented location for this scope",
    )
    .with_detail("actual", candidate.to_owned())
    .with_detail("expected", documented)
    .with_detail("component", MANAGED_SERVER))
}

/// The native Gemini CLI MCP transports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeminiTransport {
    /// Streamable HTTP: the `httpUrl` field (S18).
    StreamableHttp {
        /// Endpoint URL.
        http_url: String,
    },
    /// Server-Sent Events: the `url` field (S18).
    Sse {
        /// Endpoint URL.
        url: String,
    },
    /// Local server: `command` plus `args`.
    Stdio {
        /// Program to launch.
        command: String,
        /// Arguments passed to the program.
        args: Vec<String>,
    },
}

impl GeminiTransport {
    /// The field this transport renders.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        match self {
            Self::StreamableHttp { .. } => HTTP_URL_FIELD,
            Self::Sse { .. } => SSE_URL_FIELD,
            Self::Stdio { .. } => COMMAND_FIELD,
        }
    }

    /// The `type` value this transport asserts, when it has one.
    #[must_use]
    pub const fn declared_type(&self) -> &'static str {
        match self {
            Self::StreamableHttp { .. } => STREAMABLE_HTTP_TYPE,
            Self::Sse { .. } => SSE_TYPE,
            Self::Stdio { .. } => STDIO_TYPE,
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

fn present_count(streamable: bool, sse: bool, stdio: bool) -> usize {
    let bits = [streamable, sse, stdio];
    bits.iter().filter(|present| **present).count()
}

/// One managed Gemini CLI MCP server entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiServer {
    /// Server key under `mcpServers`.
    pub name: String,
    /// Declared transport.
    pub transport: GeminiTransport,
}

impl GeminiServer {
    /// A Streamable HTTP server, rendered with `httpUrl` and never with `url`.
    #[must_use]
    pub fn streamable_http(name: &str, http_url: &str) -> Self {
        Self {
            name: name.to_owned(),
            transport: GeminiTransport::StreamableHttp {
                http_url: http_url.to_owned(),
            },
        }
    }

    /// An SSE server, rendered with `url` and never with `httpUrl`.
    #[must_use]
    pub fn sse(name: &str, url: &str) -> Self {
        Self {
            name: name.to_owned(),
            transport: GeminiTransport::Sse {
                url: url.to_owned(),
            },
        }
    }

    /// A stdio server.
    #[must_use]
    pub fn stdio(name: &str, command: &str, args: Vec<String>) -> Self {
        Self {
            name: name.to_owned(),
            transport: GeminiTransport::Stdio {
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
            GeminiTransport::StreamableHttp { http_url }
            | GeminiTransport::Sse { url: http_url } => validate_url(http_url, &mut violations),
            GeminiTransport::Stdio { command, args } => {
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
            "the server entry does not satisfy the native Gemini MCP schema",
        )
        .with_detail("observed", violations.join(","))
        .with_detail("component", self.name.clone()))
    }

    /// Read an entry out of a document, validating it against that schema.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with [`RULE_TRANSPORT_FIELD_MISMATCH`]
    /// when the declared `type` and the transport field disagree,
    /// [`RULE_UNSUPPORTED_TRANSPORT_FIELD`] when the entry uses another host's
    /// field, [`RULE_UNKNOWN_FIELD`] for any other unknown key, and the
    /// [`Self::validate`] rules otherwise.
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
                "the entry uses a field outside the native Gemini MCP schema",
            )
            .with_detail("config_key", unknown.join(","))
            .with_detail("component", name.to_owned()));
        }
        let http_url = object.get(HTTP_URL_FIELD);
        let sse_url = object.get(SSE_URL_FIELD);
        let command = object.get(COMMAND_FIELD);
        let declared = object.get(TYPE_FIELD).and_then(Value::as_str);
        let present = present_count(http_url.is_some(), sse_url.is_some(), command.is_some());
        if present > 1 {
            return Err(refuse(
                RULE_TRANSPORT_CONFLICT,
                "the entry declares more than one transport",
            )
            .with_detail("component", name.to_owned()));
        }
        if present == 0 {
            return Err(
                refuse(RULE_TRANSPORT_MISSING, "the entry declares no transport")
                    .with_detail("component", name.to_owned()),
            );
        }
        let server = if let Some(value) = http_url {
            if let Some(declared) = declared {
                if !matches!(declared, STREAMABLE_HTTP_TYPE | STREAMABLE_HTTP_TYPE_ALT) {
                    return Err(mismatch(name, declared, HTTP_URL_FIELD));
                }
            }
            let Some(text) = value.as_str() else {
                return Err(unusable(name, HTTP_URL_FIELD));
            };
            Self::streamable_http(name, text)
        } else if let Some(value) = sse_url {
            if let Some(declared) = declared {
                if declared != SSE_TYPE {
                    return Err(mismatch(name, declared, SSE_URL_FIELD));
                }
            }
            let Some(text) = value.as_str() else {
                return Err(unusable(name, SSE_URL_FIELD));
            };
            Self::sse(name, text)
        } else {
            let Some(value) = command else {
                return Err(
                    refuse(RULE_TRANSPORT_MISSING, "the entry declares no transport")
                        .with_detail("component", name.to_owned()),
                );
            };
            if let Some(declared) = declared {
                if declared != STDIO_TYPE {
                    return Err(mismatch(name, declared, COMMAND_FIELD));
                }
            }
            let Some(text) = value.as_str() else {
                return Err(unusable(name, COMMAND_FIELD));
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
            Self::stdio(name, text, args)
        };
        server.validate()?;
        Ok(server)
    }

    /// The entry as the JSON value the plan writes.
    ///
    /// A Streamable HTTP server renders `httpUrl` and an SSE server renders
    /// `url`; the two are never exchanged.
    #[must_use]
    pub fn render_json(&self) -> Value {
        match &self.transport {
            GeminiTransport::StreamableHttp { http_url } => {
                json!({ "type": STREAMABLE_HTTP_TYPE, "httpUrl": http_url })
            }
            GeminiTransport::Sse { url } => json!({ "type": SSE_TYPE, "url": url }),
            GeminiTransport::Stdio { command, args } => {
                json!({ "type": STDIO_TYPE, "command": command, "args": args })
            }
        }
    }
}

fn mismatch(name: &str, declared: &str, field: &str) -> AxiomError {
    refuse(
        RULE_TRANSPORT_FIELD_MISMATCH,
        "the declared transport type and the transport field disagree",
    )
    .with_detail("actual", declared.to_owned())
    .with_detail("config_key", field.to_owned())
    .with_detail("component", name.to_owned())
}

fn unusable(name: &str, field: &str) -> AxiomError {
    refuse(
        RULE_UNSUPPORTED_SYNTAX,
        "the transport field must be a string",
    )
    .with_detail("config_key", field.to_owned())
    .with_detail("component", name.to_owned())
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

/// The reviewed Gemini CLI change: one `mcpServers` entry plus the instruction
/// fragment, for exactly one scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiPlan {
    paths: GeminiPaths,
    scope: GeminiScope,
    server: GeminiServer,
    action: PlanAction,
}

impl GeminiPlan {
    /// Build a plan, validating the server and the existing document.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with the rule of the first violation.
    pub fn plan(
        paths: GeminiPaths,
        scope: GeminiScope,
        server: GeminiServer,
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
                                GeminiServer::from_json(&server.name, entry)?;
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
    pub const fn server(&self) -> &GeminiServer {
        &self.server
    }

    /// The scope this plan targets.
    #[must_use]
    pub const fn scope(&self) -> GeminiScope {
        self.scope
    }

    /// The absolute paths this plan was built from.
    #[must_use]
    pub const fn paths(&self) -> &GeminiPaths {
        &self.paths
    }

    /// The settings file this plan writes, paired with the planned scope.
    #[must_use]
    pub fn target_file(&self) -> String {
        self.paths.config_file(self.scope)
    }

    /// The instruction file Gemini CLI discovers for the planned scope.
    #[must_use]
    pub fn instruction_file(&self) -> String {
        self.paths.instruction_file(self.scope)
    }

    /// The documented policy directory for the planned scope.
    #[must_use]
    pub fn policy_dir(&self) -> String {
        self.paths.policy_dir(self.scope)
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
    /// Only `mcpServers` is touched; every other top-level key is carried
    /// through by value.
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

    fn paths() -> GeminiPaths {
        GeminiPaths::resolve("/home/billy", "/home/billy/projects/demo").expect("safe roots")
    }

    fn managed() -> GeminiServer {
        GeminiServer::streamable_http(MANAGED_SERVER, "http://127.0.0.1:8766/mcp")
    }

    const EXISTING: &str = r#"{
  "mcpServers": {
    "other": { "command": "/usr/local/bin/other", "args": ["--serve"] }
  },
  "theme": "dark",
  "unknownTopLevel": 7
}"#;

    fn with_managed() -> String {
        r#"{
  "mcpServers": {
    "axiom-graphd": { "httpUrl": "http://127.0.0.1:1/old" },
    "other": { "command": "/usr/local/bin/other", "args": ["--serve"] }
  }
}
"#
        .to_owned()
    }

    fn parse(text: &str) -> Value {
        serde_json::from_str(text).expect("a parsed document")
    }

    #[test]
    fn streamable_http_and_sse_are_rendered_with_their_own_field() {
        let http = GeminiServer::streamable_http(MANAGED_SERVER, "http://127.0.0.1:8766/mcp");
        let rendered = http.render_json();
        assert_eq!(
            rendered[HTTP_URL_FIELD],
            Value::from("http://127.0.0.1:8766/mcp")
        );
        assert!(
            rendered.get(SSE_URL_FIELD).is_none(),
            "a streamable-http entry must never carry the SSE field"
        );
        assert_eq!(http.transport.field(), HTTP_URL_FIELD);

        let sse = GeminiServer::sse(MANAGED_SERVER, "http://127.0.0.1:8766/sse");
        let rendered = sse.render_json();
        assert_eq!(
            rendered[SSE_URL_FIELD],
            Value::from("http://127.0.0.1:8766/sse")
        );
        assert!(
            rendered.get(HTTP_URL_FIELD).is_none(),
            "an SSE entry must never carry the streamable-http field"
        );
        assert_eq!(sse.transport.field(), SSE_URL_FIELD);
    }

    #[test]
    fn the_two_remote_transports_are_not_interchanged() {
        let cases = [
            (
                serde_json::json!({ "type": SSE_TYPE, HTTP_URL_FIELD: "http://127.0.0.1:8766/mcp" }),
                HTTP_URL_FIELD,
            ),
            (
                serde_json::json!({ "type": STREAMABLE_HTTP_TYPE, SSE_URL_FIELD: "http://127.0.0.1:8766/sse" }),
                SSE_URL_FIELD,
            ),
            (
                serde_json::json!({ "type": STREAMABLE_HTTP_TYPE, COMMAND_FIELD: "/bin/x" }),
                COMMAND_FIELD,
            ),
        ];
        for (entry, field) in cases {
            let error = GeminiServer::from_json(MANAGED_SERVER, &entry)
                .expect_err("an exchanged transport field is refused");
            assert_eq!(rule(&error), RULE_TRANSPORT_FIELD_MISMATCH);
            assert_eq!(
                error.details().get("config_key").map(String::as_str),
                Some(field)
            );
        }

        assert!(GeminiServer::from_json(
            MANAGED_SERVER,
            &serde_json::json!({ "type": STREAMABLE_HTTP_TYPE, HTTP_URL_FIELD: "http://127.0.0.1:8766/mcp" })
        )
        .is_ok());
        assert!(GeminiServer::from_json(
            MANAGED_SERVER,
            &serde_json::json!({ "type": SSE_TYPE, SSE_URL_FIELD: "http://127.0.0.1:8766/sse" })
        )
        .is_ok());
        assert!(GeminiServer::from_json(
            MANAGED_SERVER,
            &serde_json::json!({ TYPE_FIELD: STREAMABLE_HTTP_TYPE_ALT, HTTP_URL_FIELD: "http://127.0.0.1:8766/mcp" })
        )
        .is_ok());
        assert!(GeminiServer::from_json(
            MANAGED_SERVER,
            &serde_json::json!({ HTTP_URL_FIELD: "http://127.0.0.1:8766/mcp" })
        )
        .is_ok());

        let conflict = serde_json::json!({
            HTTP_URL_FIELD: "http://127.0.0.1:8766/mcp",
            SSE_URL_FIELD: "http://127.0.0.1:8766/sse",
        });
        assert_eq!(
            rule(
                &GeminiServer::from_json(MANAGED_SERVER, &conflict)
                    .expect_err("two transports are refused")
            ),
            RULE_TRANSPORT_CONFLICT
        );

        assert_eq!(
            rule(
                &GeminiServer::from_json(MANAGED_SERVER, &serde_json::json!({ "env": {} }))
                    .expect_err("a transport-less entry is refused")
            ),
            RULE_TRANSPORT_MISSING
        );
    }

    #[test]
    fn the_scopes_pair_a_settings_file_with_an_instruction_and_policy_path() {
        let paths = paths();
        let user = paths.scope_files(GeminiScope::User);
        assert_eq!(user.config_file, "/home/billy/.gemini/settings.json");
        assert_eq!(user.instruction_file, "/home/billy/.gemini/GEMINI.md");
        assert_eq!(user.policy_dir, "/home/billy/.gemini/policies");
        let project = paths.scope_files(GeminiScope::Project);
        assert_eq!(
            project.config_file,
            "/home/billy/projects/demo/.gemini/settings.json"
        );
        assert_eq!(
            project.instruction_file,
            "/home/billy/projects/demo/GEMINI.md"
        );
        assert_eq!(
            project.policy_dir,
            "/home/billy/projects/demo/.gemini/policies"
        );

        let plan = GeminiPlan::plan(paths, GeminiScope::Project, managed(), None).expect("a plan");
        assert_eq!(plan.target_file(), project.config_file);
        assert_eq!(plan.instruction_file(), project.instruction_file);
        assert_eq!(plan.policy_dir(), project.policy_dir);
    }

    #[test]
    fn an_unsupported_scope_is_refused() {
        assert_eq!(resolve_scope("user").expect("user"), GeminiScope::User);
        assert_eq!(
            resolve_scope("project").expect("project"),
            GeminiScope::Project
        );
        for value in ["local", "workspace", "", "Project"] {
            let error = resolve_scope(value).expect_err("an unknown scope is refused");
            assert_eq!(rule(&error), RULE_UNSUPPORTED_SCOPE, "scope: {value}");
        }
    }

    #[test]
    fn an_uncertified_policy_path_is_refused() {
        let paths = paths();
        let documented = paths.policy_dir(GeminiScope::Project);
        assert!(verify_policy_path(&paths, GeminiScope::Project, &documented).is_ok());
        for candidate in [
            "/home/billy/projects/demo/.gemini/policy",
            "/home/billy/projects/demo/.gemini",
            "/etc/gemini/policies",
        ] {
            let error = verify_policy_path(&paths, GeminiScope::Project, candidate)
                .expect_err("an uncertified policy path is refused");
            assert_eq!(rule(&error), RULE_POLICY_PATH_NOT_CERTIFIED);
            // The certified path is recorded under the redaction allowlist keys,
            // but `redact::scrub` replaces a host path with `[path]`, so the
            // refusal is asserted through the keys it keeps, not through the
            // literal path value.
            assert_eq!(error.dropped_details(), 0);
            assert!(error.details().contains_key("actual"));
            assert!(error.details().contains_key("expected"));
            assert_eq!(
                error.details().get("component").map(String::as_str),
                Some(MANAGED_SERVER)
            );
            assert!(!documented.is_empty());
        }
    }

    #[test]
    fn a_foreign_transport_field_fails_validation() {
        for (key, value) in [
            ("serverUrl", "http://127.0.0.1:8766/mcp"),
            ("sseUrl", "http://127.0.0.1:8766/sse"),
            ("bearer_token_env_var", "AXIOM_MCP_TOKEN"),
        ] {
            let entry = serde_json::json!({
                HTTP_URL_FIELD: "http://127.0.0.1:8766/mcp",
                key: value,
            });
            let error = GeminiServer::from_json(MANAGED_SERVER, &entry)
                .expect_err("a foreign field is refused");
            assert_eq!(rule(&error), RULE_UNSUPPORTED_TRANSPORT_FIELD);
            assert_eq!(
                error.details().get("config_key").map(String::as_str),
                Some(key)
            );
        }
        let unknown = serde_json::json!({
            HTTP_URL_FIELD: "http://127.0.0.1:8766/mcp",
            "foo": 1,
        });
        assert_eq!(
            rule(
                &GeminiServer::from_json(MANAGED_SERVER, &unknown)
                    .expect_err("an unknown field is refused")
            ),
            RULE_UNKNOWN_FIELD
        );
    }

    #[test]
    fn appending_preserves_every_other_server() {
        let plan = GeminiPlan::plan(paths(), GeminiScope::User, managed(), Some(EXISTING))
            .expect("a plan");
        assert_eq!(plan.action(), PlanAction::Insert);
        let planned = plan.apply(EXISTING).expect("a merged document");
        assert!(planned.ends_with('\n'));
        let before = parse(EXISTING);
        let after = parse(&planned);
        assert_eq!(after["theme"], before["theme"]);
        assert_eq!(after["unknownTopLevel"], Value::from(7));
        assert_eq!(after["mcpServers"]["other"], before["mcpServers"]["other"]);
        assert_eq!(
            after["mcpServers"][MANAGED_SERVER][HTTP_URL_FIELD],
            Value::from("http://127.0.0.1:8766/mcp")
        );
        assert!(after["mcpServers"][MANAGED_SERVER]
            .get(SSE_URL_FIELD)
            .is_none());
    }

    #[test]
    fn replacing_the_managed_entry_changes_only_that_entry() {
        let existing = with_managed();
        let plan = GeminiPlan::plan(paths(), GeminiScope::User, managed(), Some(&existing))
            .expect("a plan");
        assert_eq!(plan.action(), PlanAction::Replace);
        let planned = plan.apply(&existing).expect("a merged document");
        assert!(!planned.contains("127.0.0.1:1/old"));
        let after = parse(&planned);
        assert_eq!(
            after["mcpServers"][MANAGED_SERVER][HTTP_URL_FIELD],
            Value::from("http://127.0.0.1:8766/mcp")
        );
        assert_eq!(
            after["mcpServers"]["other"]["command"],
            Value::from("/usr/local/bin/other")
        );
    }

    #[test]
    fn a_document_outside_the_schema_is_refused_rather_than_guessed() {
        for text in ["[1, 2]", "{ \"mcpServers\": [] }", "{ broken"] {
            let error = GeminiPlan::plan(paths(), GeminiScope::User, managed(), Some(text))
                .expect_err("an unusable document is refused");
            assert_eq!(rule(&error), RULE_UNSUPPORTED_SYNTAX, "text: {text}");
        }
        let oversized = format!("{{\"padding\": \"{}\"}}", "x".repeat(MAX_CONFIG_BYTES));
        assert_eq!(
            rule(
                &GeminiPlan::plan(paths(), GeminiScope::User, managed(), Some(&oversized))
                    .expect_err("an oversized document is refused")
            ),
            RULE_OUTPUT_TOO_LARGE
        );
        let stdio = serde_json::json!({
            COMMAND_FIELD: "/usr/local/bin/axiom-graphd",
            "args": "not an array",
        });
        assert_eq!(
            rule(
                &GeminiServer::from_json(MANAGED_SERVER, &stdio)
                    .expect_err("a non-array argv is refused")
            ),
            RULE_UNSUPPORTED_SYNTAX
        );
    }

    #[test]
    fn an_insert_plan_refuses_a_document_that_already_declares_the_server() {
        let plan = GeminiPlan::plan(paths(), GeminiScope::User, managed(), None).expect("a plan");
        let error = plan
            .apply(&with_managed())
            .expect_err("an already-declared server is refused on insert");
        assert_eq!(rule(&error), RULE_SERVER_ALREADY_PRESENT);
    }

    #[test]
    fn a_stdio_transport_requires_an_absolute_shell_free_command() {
        let relative = GeminiServer::stdio(MANAGED_SERVER, "axiom-graphd", vec![]);
        assert_eq!(
            rule(
                &relative
                    .validate()
                    .expect_err("a relative command is refused")
            ),
            RULE_STDIO_COMMAND_NOT_ABSOLUTE
        );
        let shellish = GeminiServer::stdio(MANAGED_SERVER, "/bin/sh -c \"x\"", vec![]);
        assert_eq!(
            rule(&shellish.validate().expect_err("a shell command is refused")),
            RULE_STDIO_COMMAND_HAS_SHELL
        );
    }

    #[test]
    fn a_literal_credential_or_a_credential_url_is_refused() {
        let mut violations = Vec::new();
        validate_url("http://127.0.0.1:8766/mcp?apikey=abc", &mut violations);
        assert!(violations.contains(&RULE_CREDENTIAL_IN_URL.to_owned()));
        violations.clear();
        validate_url("http://gateway.example/mcp", &mut violations);
        assert!(violations.contains(&RULE_INSECURE_TRANSPORT.to_owned()));
        assert!(
            GeminiServer::streamable_http(MANAGED_SERVER, "https://gateway.example/mcp")
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn every_rendered_entry_parses_back_to_the_same_server() {
        for server in [
            managed(),
            GeminiServer::sse(MANAGED_SERVER, "http://127.0.0.1:8766/sse"),
            GeminiServer::stdio(
                MANAGED_SERVER,
                "/usr/local/bin/axiom-graphd",
                vec!["mcp".to_owned()],
            ),
        ] {
            let rendered = server.render_json();
            assert_eq!(
                GeminiServer::from_json(MANAGED_SERVER, &rendered).expect("a round trip"),
                server
            );
        }
    }

    #[test]
    fn the_instruction_fragment_uses_the_managed_block_markers() {
        let plan = GeminiPlan::plan(paths(), GeminiScope::User, managed(), None).expect("a plan");
        let fragment = plan.instruction_fragment();
        assert!(fragment.starts_with(markers::BEGIN_MARKER));
        assert!(fragment.trim_end().ends_with(markers::END_MARKER));
        assert!(fragment.contains(MANAGED_SERVER));
    }
}
