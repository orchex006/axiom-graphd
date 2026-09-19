//! Antigravity (AGY) MCP and rule/skill location fragments (task E-030).
//!
//! AGY reads MCP servers from a JSON object whose *remote endpoint field is
//! `serverUrl`* (S15). That is a third spelling again - neither the Codex `url`,
//! nor the Gemini `httpUrl` - and S15 records explicitly that the Gemini field
//! is **not** a substitute here. So a `httpUrl`, a bare `url`, an `sseUrl` or a
//! Codex `bearer_token_env_var` is refused ([`RULE_UNSUPPORTED_TRANSPORT_FIELD`])
//! rather than accepted, because a plan that writes the wrong field produces a
//! server AGY never reads while reporting success.
//!
//! ## Locations are version-checked, and a deprecated path is never guessed
//!
//! AGY ships IDE and CLI surfaces whose configuration and path layout differ by
//! version, and it documents skills at `.agents/skills` with a *legacy* `.agent`
//! compatibility layout (S13) plus workspace/global rule locations (S14). This
//! adapter therefore will not pick a location on its own authority:
//!
//! * [`AgyVersionGate::certify`] requires a detected [`HostVersion`] and refuses
//!   when the host reports no parseable version ([`RULE_VERSION_UNCONFIRMED`]) or
//!   a version below the floor the caller declares ([`RULE_VERSION_BELOW_FLOOR`]).
//! * [`certify_skills_dir`] returns the active `.agents/skills` location, and
//!   refuses the legacy `.agent` location as [`RULE_DEPRECATED_PATH_REFUSED`]
//!   *with the active path named in the refusal* instead of translating the
//!   request into the deprecated layout. A version older than the declared floor
//!   is reported as such, never written to through the legacy path.
//!
//! The AGY MCP *config file path* is documented per surface (S15) and is **not**
//! certified by the reviewed seeds for this machine, so this adapter carries no
//! config-file path at all: [`AgyPlan::apply`] is a pure merge over a document the
//! caller already holds, and [`AgyPlan`] exposes the certified skills and rules
//! locations but deliberately no `target_file`.
//!
//! ## JSON is merged by value
//!
//! As with the Claude and Gemini adapters, JSON has no comments, so a rewrite can
//! only lose whitespace and key order. The document is parsed with the
//! workspace's one JSON codec (`serde_json`) and re-serialised, which normalises
//! key order to sorted and indentation to two spaces. That normalisation is a
//! recorded limitation, not a preservation guarantee.
//!
//! Nothing here reads or writes a real AGY installation:
//! [`AgyPlan::apply`] is a pure function of text the caller already holds.

use std::path::Path;

use graph_core::error::{AxiomError, ErrorCode};
use serde_json::{json, Map, Value};

use crate::bootstrap::markers;
use crate::hosts::detect::HostVersion;

/// Documented AGY directory that holds the active skills and rules (S13, S14).
pub const AGY_AGENTS_DIR: &str = ".agents";
/// Documented AGY skills directory name (S13).
pub const AGY_SKILLS_DIR: &str = "skills";
/// Documented AGY rules directory name (S14).
pub const AGY_RULES_DIR: &str = "rules";
/// Documented *legacy* AGY directory the `.agents` layout replaced (S13).
pub const AGY_LEGACY_DIR: &str = ".agent";
/// Object that holds MCP servers.
pub const MCP_SERVERS_KEY: &str = "mcpServers";
/// Native remote-endpoint field for AGY (S15).
pub const SERVER_URL_FIELD: &str = "serverUrl";
/// Native stdio field for AGY.
pub const COMMAND_FIELD: &str = "command";
/// Native declared-transport field, when the host requires one.
pub const TYPE_FIELD: &str = "type";
/// Default managed MCP server name.
pub const MANAGED_SERVER: &str = "axiom-graphd";
/// The AGY MCP entry schema revision this adapter renders.
///
/// This is *this adapter's* schema revision (one `mcpServers` object whose remote
/// field is `serverUrl`), not a field written into the host config.
pub const AGY_MCP_SCHEMA_VERSION: u32 = 1;

/// Largest configuration document this module will parse.
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
/// Largest accepted number of declared MCP servers.
pub const MAX_SERVERS: usize = 512;
/// Largest accepted string value inside the subset.
pub const MAX_VALUE_BYTES: usize = 4096;
/// Largest accepted argument count.
pub const MAX_ARGS: usize = 64;

/// Refusal: the document is outside the bounded JSON subset.
pub const RULE_UNSUPPORTED_SYNTAX: &str = "json-unsupported-syntax";
/// Refusal: a scope this adapter does not plan for.
pub const RULE_UNSUPPORTED_SCOPE: &str = "unsupported-scope";
/// Refusal: a field outside the documented AGY server schema.
pub const RULE_UNKNOWN_FIELD: &str = "unknown-field";
/// Refusal: a transport field belonging to another host's schema.
pub const RULE_UNSUPPORTED_TRANSPORT_FIELD: &str = "unsupported-transport-field";
/// Refusal: neither `serverUrl` nor `command` is present.
pub const RULE_TRANSPORT_MISSING: &str = "transport-missing";
/// Refusal: both the remote and the stdio transport are declared.
pub const RULE_TRANSPORT_CONFLICT: &str = "transport-conflict";
/// Refusal: a credential value was written literally instead of referenced.
pub const RULE_CREDENTIAL_LITERAL: &str = "credential-literal-refused";
/// Refusal: the URL carries a credential in its query string.
pub const RULE_CREDENTIAL_IN_URL: &str = "credential-in-url-refused";
/// Refusal: a non-loopback plaintext HTTP endpoint.
pub const RULE_INSECURE_TRANSPORT: &str = "insecure-transport-refused";
/// Refusal: the stdio program is not an absolute path.
pub const RULE_STDIO_COMMAND_NOT_ABSOLUTE: &str = "stdio-command-not-absolute";
/// Refusal: the stdio program carries shell metacharacters.
pub const RULE_STDIO_COMMAND_HAS_SHELL: &str = "stdio-command-has-shell-metacharacters";
/// Refusal: a document or entry larger than the bound.
pub const RULE_OUTPUT_TOO_LARGE: &str = "output-too-large";
/// Refusal: a path that is not an absolute, control-free host path.
pub const RULE_UNSAFE_PATH: &str = "unsafe-path";
/// Refusal: the document already declares the managed server on an insert plan.
pub const RULE_SERVER_ALREADY_PRESENT: &str = "server-already-present";
/// Refusal: a deprecated AGY location was requested instead of the active one.
pub const RULE_DEPRECATED_PATH_REFUSED: &str = "deprecated-path-refused";
/// Refusal: the detected host version is below the declared floor.
pub const RULE_VERSION_BELOW_FLOOR: &str = "version-below-floor";
/// Refusal: no parseable detected version, so no location is certified.
pub const RULE_VERSION_UNCONFIRMED: &str = "version-unconfirmed";
/// Refusal: a location this adapter has not certified.
pub const RULE_LOCATION_NOT_CERTIFIED: &str = "location-not-certified";

/// Fields AGY supports inside one `mcpServers` entry.
pub const SUPPORTED_FIELDS: [&str; 4] = ["serverUrl", "command", "args", "type"];

/// Transport fields that belong to another host's schema and must never be
/// silently accepted here.
pub const FOREIGN_TRANSPORT_FIELDS: [&str; 4] =
    ["httpUrl", "url", "sseUrl", "bearer_token_env_var"];

/// Query-string names that mean a credential was placed in the URL.
const CREDENTIAL_QUERY_NAMES: [&str; 4] = ["token", "apikey", "api_key", "password"];

/// Field names that mean a credential was written literally into the entry.
const CREDENTIAL_FIELD_NAMES: [&str; 5] = ["token", "apikey", "api_key", "password", "secret"];

fn refuse(rule: &str, message: impl AsRef<str>) -> AxiomError {
    AxiomError::new(ErrorCode::ValidationError, message).with_detail("rule", rule)
}
/// The AGY configuration scopes this adapter plans for (S14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgyScope {
    /// Workspace scope: the layout rooted at the project directory.
    Workspace,
    /// Global scope: the layout rooted at the user home.
    Global,
}

impl AgyScope {
    /// Every scope this adapter accepts, in wire order.
    pub const ALL: [AgyScope; 2] = [Self::Workspace, Self::Global];

    /// The stable wire spelling.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Global => "global",
        }
    }

    /// Parse a wire spelling, refusing anything this adapter does not plan for.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "workspace" => Some(Self::Workspace),
            "global" => Some(Self::Global),
            _ => None,
        }
    }
}

/// The skills and rules locations one scope owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgyScopeFiles {
    /// The scope these locations belong to.
    pub scope: AgyScope,
    /// Absolute path of the active skills directory.
    pub skills_dir: String,
    /// Absolute path of the active rules directory.
    pub rules_dir: String,
}

/// Absolute roots this adapter plans for.
///
/// Two roots exist because AGY documents a workspace layout and a global layout
/// (S14); nothing else is inferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgyPaths {
    home: String,
    workspace: String,
}

impl AgyPaths {
    /// Bind the two absolute roots.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with [`RULE_UNSAFE_PATH`] when either root
    /// is relative, empty, oversized or holds a control character.
    pub fn resolve(home: &str, workspace: &str) -> Result<Self, AxiomError> {
        for root in [home, workspace] {
            if !is_safe_root(root) {
                return Err(
                    refuse(RULE_UNSAFE_PATH, "a root must be an absolute host path")
                        .with_detail("portable_path", root),
                );
            }
        }
        Ok(Self {
            home: home.trim_end_matches(['/', '\\']).to_owned(),
            workspace: workspace.trim_end_matches(['/', '\\']).to_owned(),
        })
    }

    /// The resolved user home.
    #[must_use]
    pub fn home(&self) -> &str {
        &self.home
    }

    /// The resolved workspace root.
    #[must_use]
    pub fn workspace(&self) -> &str {
        &self.workspace
    }

    /// The root a scope is laid out under.
    #[must_use]
    pub fn root(&self, scope: AgyScope) -> &str {
        match scope {
            AgyScope::Workspace => &self.workspace,
            AgyScope::Global => &self.home,
        }
    }

    /// The active skills directory of one scope (S13).
    #[must_use]
    pub fn skills_dir(&self, scope: AgyScope) -> String {
        format!("{}/{}/{}", self.root(scope), AGY_AGENTS_DIR, AGY_SKILLS_DIR)
    }

    /// The *deprecated* legacy skills directory of one scope (S13).
    ///
    /// Exposed so a refusal can name it; never returned as a certified location.
    #[must_use]
    pub fn legacy_skills_dir(&self, scope: AgyScope) -> String {
        format!("{}/{}", self.root(scope), AGY_LEGACY_DIR)
    }

    /// The active rules directory of one scope (S14).
    #[must_use]
    pub fn rules_dir(&self, scope: AgyScope) -> String {
        format!("{}/{}/{}", self.root(scope), AGY_AGENTS_DIR, AGY_RULES_DIR)
    }

    /// The skills and rules locations one scope owns, as one value.
    ///
    /// Returning them together is what stops a plan from certifying a skills
    /// directory for one scope while claiming another scope's rules directory.
    #[must_use]
    pub fn scope_files(&self, scope: AgyScope) -> AgyScopeFiles {
        AgyScopeFiles {
            scope,
            skills_dir: self.skills_dir(scope),
            rules_dir: self.rules_dir(scope),
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
pub fn resolve_scope(value: &str) -> Result<AgyScope, AxiomError> {
    AgyScope::from_wire(value).ok_or_else(|| {
        refuse(
            RULE_UNSUPPORTED_SCOPE,
            "the requested scope is not one this adapter plans for",
        )
        .with_detail("actual", value.to_owned())
        .with_detail(
            "expected",
            AgyScope::ALL
                .iter()
                .map(|scope| scope.wire())
                .collect::<Vec<_>>()
                .join(","),
        )
    })
}

/// The version gate every AGY plan passes through.
///
/// AGY's path layout and per-surface configuration change between versions, so a
/// plan carries the version the host actually reported and the floor the caller
/// declares. A version that was never parsed, or one below the floor, refuses the
/// plan instead of letting a deprecated location be chosen by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgyVersionGate {
    detected: HostVersion,
    required: HostVersion,
}

impl AgyVersionGate {
    /// Certify the detected version against the declared floor.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with [`RULE_VERSION_UNCONFIRMED`] when the
    /// host reported no parseable version, and with [`RULE_VERSION_BELOW_FLOOR`]
    /// when the detected version is below `required`.
    pub fn certify(
        detected: Option<&HostVersion>,
        required: &HostVersion,
    ) -> Result<Self, AxiomError> {
        let Some(detected) = detected else {
            return Err(refuse(
                RULE_VERSION_UNCONFIRMED,
                "the AGY host version was not detected, so no location is certified",
            )
            .with_detail("required_version", required.render())
            .with_detail("component", MANAGED_SERVER));
        };
        if !detected.at_least(required) {
            return Err(refuse(
                RULE_VERSION_BELOW_FLOOR,
                "the detected AGY version is below the layout floor this plan requires",
            )
            .with_detail("version", detected.render())
            .with_detail("required_version", required.render())
            .with_detail("component", MANAGED_SERVER));
        }
        Ok(Self {
            detected: detected.clone(),
            required: required.clone(),
        })
    }

    /// The version the host reported.
    #[must_use]
    pub const fn detected(&self) -> &HostVersion {
        &self.detected
    }

    /// The floor this plan requires.
    #[must_use]
    pub const fn required(&self) -> &HostVersion {
        &self.required
    }

    /// The AGY MCP schema revision this adapter renders.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        AGY_MCP_SCHEMA_VERSION
    }
}

/// Certify the active skills directory, refusing the deprecated legacy layout.
///
/// # Errors
/// [`ErrorCode::ValidationError`] with [`RULE_DEPRECATED_PATH_REFUSED`] when the
/// candidate is the legacy `.agent` directory (the active path is named in the
/// refusal), and [`RULE_LOCATION_NOT_CERTIFIED`] for any other candidate.
pub fn certify_skills_dir(
    paths: &AgyPaths,
    scope: AgyScope,
    candidate: &str,
) -> Result<String, AxiomError> {
    let active = paths.skills_dir(scope);
    if candidate == active {
        return Ok(active);
    }
    if candidate == paths.legacy_skills_dir(scope) {
        return Err(refuse(
            RULE_DEPRECATED_PATH_REFUSED,
            "the requested skills location is the deprecated AGY layout",
        )
        .with_detail("actual", candidate.to_owned())
        .with_detail("expected", active)
        .with_detail("component", MANAGED_SERVER));
    }
    Err(refuse(
        RULE_LOCATION_NOT_CERTIFIED,
        "the requested skills location is not one this adapter certifies",
    )
    .with_detail("actual", candidate.to_owned())
    .with_detail("expected", active)
    .with_detail("component", MANAGED_SERVER))
}

/// Certify the active rules directory.
///
/// # Errors
/// [`ErrorCode::ValidationError`] with [`RULE_LOCATION_NOT_CERTIFIED`] for any
/// candidate that is not the documented workspace/global rule location (S14).
pub fn certify_rules_dir(
    paths: &AgyPaths,
    scope: AgyScope,
    candidate: &str,
) -> Result<String, AxiomError> {
    let active = paths.rules_dir(scope);
    if candidate == active {
        return Ok(active);
    }
    Err(refuse(
        RULE_LOCATION_NOT_CERTIFIED,
        "the requested rules location is not one this adapter certifies",
    )
    .with_detail("actual", candidate.to_owned())
    .with_detail("expected", active)
    .with_detail("component", MANAGED_SERVER))
}
/// Refusal: the declared `type` and the transport field disagree.
pub const RULE_TRANSPORT_FIELD_MISMATCH: &str = "transport-field-mismatch";

/// `type` spellings AGY accepts for the `serverUrl` transport.
const REMOTE_TYPES: [&str; 2] = ["http", "streamable-http"];
/// `type` spelling AGY accepts for the `command` transport.
const STDIO_TYPE: &str = "stdio";

/// The native AGY MCP transports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgyTransport {
    /// Remote endpoint: the `serverUrl` field (S15).
    ServerUrl {
        /// Endpoint URL.
        server_url: String,
    },
    /// Local server: `command` plus `args`.
    Stdio {
        /// Program to launch.
        command: String,
        /// Arguments passed to the program.
        args: Vec<String>,
    },
}

impl AgyTransport {
    /// The field this transport renders.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        match self {
            Self::ServerUrl { .. } => SERVER_URL_FIELD,
            Self::Stdio { .. } => COMMAND_FIELD,
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

/// One managed AGY MCP server entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgyServer {
    /// Server key under `mcpServers`.
    pub name: String,
    /// Declared transport.
    pub transport: AgyTransport,
}

impl AgyServer {
    /// A remote server, rendered with `serverUrl` and never with `httpUrl`.
    #[must_use]
    pub fn server_url(name: &str, server_url: &str) -> Self {
        Self {
            name: name.to_owned(),
            transport: AgyTransport::ServerUrl {
                server_url: server_url.to_owned(),
            },
        }
    }

    /// A stdio server.
    #[must_use]
    pub fn stdio(name: &str, command: &str, args: Vec<String>) -> Self {
        Self {
            name: name.to_owned(),
            transport: AgyTransport::Stdio {
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
            AgyTransport::ServerUrl { server_url } => {
                validate_url(server_url, &mut violations);
            }
            AgyTransport::Stdio { command, args } => {
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
            "the server entry does not satisfy the native AGY MCP schema",
        )
        .with_detail("observed", violations.join(","))
        .with_detail("component", self.name.clone()))
    }

    /// Read an entry out of a document, validating it against that schema.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with [`RULE_UNSUPPORTED_TRANSPORT_FIELD`]
    /// when the entry uses another host's field, [`RULE_CREDENTIAL_LITERAL`] when
    /// it carries a credential field, [`RULE_UNKNOWN_FIELD`] for any other
    /// unknown key, and the [`Self::validate`] rules otherwise.
    pub fn from_json(name: &str, entry: &Value) -> Result<Self, AxiomError> {
        let Some(object) = entry.as_object() else {
            return Err(refuse(
                RULE_UNSUPPORTED_SYNTAX,
                "the server entry is not a JSON object",
            )
            .with_detail("component", name.to_owned()));
        };
        let mut foreign = Vec::new();
        let mut credentials = Vec::new();
        let mut unknown = Vec::new();
        for key in object.keys() {
            let lowered = key.to_ascii_lowercase();
            if FOREIGN_TRANSPORT_FIELDS.contains(&key.as_str()) {
                foreign.push(key.clone());
            } else if !SUPPORTED_FIELDS.contains(&key.as_str()) {
                if CREDENTIAL_FIELD_NAMES.contains(&lowered.as_str()) {
                    credentials.push(key.clone());
                } else {
                    unknown.push(key.clone());
                }
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
        if !credentials.is_empty() {
            return Err(refuse(
                RULE_CREDENTIAL_LITERAL,
                "the entry carries a literal credential field",
            )
            .with_detail("config_key", credentials.join(","))
            .with_detail("component", name.to_owned()));
        }
        if !unknown.is_empty() {
            return Err(refuse(
                RULE_UNKNOWN_FIELD,
                "the entry uses a field outside the native AGY MCP schema",
            )
            .with_detail("config_key", unknown.join(","))
            .with_detail("component", name.to_owned()));
        }
        let server_url = object.get(SERVER_URL_FIELD);
        let command = object.get(COMMAND_FIELD);
        let declared = object.get(TYPE_FIELD).and_then(Value::as_str);
        let present = match (server_url.is_some(), command.is_some()) {
            (true, true) => 2,
            (true, false) | (false, true) => 1,
            (false, false) => 0,
        };
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
        let server = if let Some(value) = server_url {
            if let Some(declared) = declared {
                if !REMOTE_TYPES.contains(&declared) {
                    return Err(mismatch(name, declared, SERVER_URL_FIELD));
                }
            }
            let Some(text) = value.as_str() else {
                return Err(unusable(name, SERVER_URL_FIELD));
            };
            Self::server_url(name, text)
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
    /// The remote transport renders `serverUrl` and nothing else; the Codex
    /// `url`, the Gemini `httpUrl` and an SSE `url` are never exchanged for it.
    #[must_use]
    pub fn render_json(&self) -> Value {
        match &self.transport {
            AgyTransport::ServerUrl { server_url } => json!({ "serverUrl": server_url }),
            AgyTransport::Stdio { command, args } => {
                json!({ "command": command, "args": args })
            }
        }
    }

    /// The entry rendered as a JSON document, bounded by [`MAX_CONFIG_BYTES`].
    ///
    /// # Errors
    /// [`ErrorCode::Internal`] when the entry cannot be re-encoded, and
    /// [`RULE_OUTPUT_TOO_LARGE`] when the rendering exceeds the bound.
    pub fn render_pretty(&self) -> Result<String, AxiomError> {
        let mut text = serde_json::to_string_pretty(&self.render_json()).map_err(|_| {
            AxiomError::new(
                ErrorCode::Internal,
                "the server entry cannot be re-encoded as JSON",
            )
        })?;
        text.push('\n');
        if text.len() > MAX_CONFIG_BYTES {
            return Err(refuse(
                RULE_OUTPUT_TOO_LARGE,
                "the rendered entry is larger than this adapter will write",
            ));
        }
        Ok(text)
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

/// The reviewed AGY change: one `mcpServers` entry plus the instruction fragment,
/// for exactly one scope, gated on a certified host version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgyPlan {
    paths: AgyPaths,
    scope: AgyScope,
    server: AgyServer,
    gate: AgyVersionGate,
    action: PlanAction,
}

impl AgyPlan {
    /// Build a plan, certifying the version, the server and the existing document.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with the rule of the first violation:
    /// [`RULE_VERSION_UNCONFIRMED`] or [`RULE_VERSION_BELOW_FLOOR`] from
    /// [`AgyVersionGate::certify`], then the [`AgyServer::validate`] rules.
    pub fn plan(
        paths: AgyPaths,
        scope: AgyScope,
        server: AgyServer,
        gate: AgyVersionGate,
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
                                AgyServer::from_json(&server.name, entry)?;
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
            gate,
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
    pub const fn server(&self) -> &AgyServer {
        &self.server
    }

    /// The scope this plan targets.
    #[must_use]
    pub const fn scope(&self) -> AgyScope {
        self.scope
    }

    /// The absolute roots this plan was built from.
    #[must_use]
    pub const fn paths(&self) -> &AgyPaths {
        &self.paths
    }

    /// The certified version gate this plan passed.
    #[must_use]
    pub const fn gate(&self) -> &AgyVersionGate {
        &self.gate
    }

    /// The AGY MCP schema revision this plan renders.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.gate.schema_version()
    }

    /// The certified skills directory for the planned scope.
    #[must_use]
    pub fn skills_dir(&self) -> String {
        self.paths.skills_dir(self.scope)
    }

    /// The certified rules directory for the planned scope.
    #[must_use]
    pub fn rules_dir(&self) -> String {
        self.paths.rules_dir(self.scope)
    }

    /// The scoped skills and rules locations, as one value.
    #[must_use]
    pub fn scope_files(&self) -> AgyScopeFiles {
        self.paths.scope_files(self.scope)
    }

    /// The managed instruction fragment for the scope's rule file.
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
    /// through by value. There is deliberately no `target_file`: the AGY MCP
    /// config path is per surface and is not certified by the reviewed seeds, so
    /// the caller owns where this returned document is written.
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

    fn version(major: u64, minor: u64, patch: u64) -> HostVersion {
        HostVersion {
            major,
            minor,
            patch,
            prerelease: None,
        }
    }

    fn paths() -> AgyPaths {
        AgyPaths::resolve("/home/billy", "/home/billy/projects/demo").expect("safe roots")
    }

    fn gate() -> AgyVersionGate {
        AgyVersionGate::certify(Some(&version(1, 5, 0)), &version(1, 5, 0)).expect("certified")
    }

    fn managed() -> AgyServer {
        AgyServer::server_url(MANAGED_SERVER, "http://127.0.0.1:8766/mcp")
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
    "axiom-graphd": { "serverUrl": "http://127.0.0.1:1/old" },
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
    fn a_host_below_the_declared_floor_is_refused() {
        let error = AgyVersionGate::certify(Some(&version(1, 4, 9)), &version(1, 5, 0))
            .expect_err("a host below the floor is refused");
        assert_eq!(rule(&error), RULE_VERSION_BELOW_FLOOR);
        assert_eq!(
            error.details().get("version").map(String::as_str),
            Some("1.4.9")
        );
        assert_eq!(
            error.details().get("required_version").map(String::as_str),
            Some("1.5.0")
        );
    }

    #[test]
    fn a_host_at_the_floor_is_certified() {
        let certified = AgyVersionGate::certify(Some(&version(1, 5, 0)), &version(1, 5, 0))
            .expect("the floor itself passes");
        assert_eq!(certified.detected().render(), "1.5.0");
        assert_eq!(certified.required().render(), "1.5.0");
        assert_eq!(certified.schema_version(), AGY_MCP_SCHEMA_VERSION);
    }

    #[test]
    fn an_unparsed_host_version_cannot_certify_a_location() {
        let error = AgyVersionGate::certify(None, &version(1, 5, 0))
            .expect_err("an undetected version is refused");
        assert_eq!(rule(&error), RULE_VERSION_UNCONFIRMED);
        assert_eq!(error.dropped_details(), 0);
    }

    #[test]
    fn the_deprecated_legacy_skills_path_is_refused_not_translated() {
        let paths = paths();
        let active = paths.skills_dir(AgyScope::Workspace);
        assert_eq!(
            certify_skills_dir(&paths, AgyScope::Workspace, &active).expect("the active path"),
            active
        );
        let legacy = paths.legacy_skills_dir(AgyScope::Workspace);
        assert_eq!(legacy, "/home/billy/projects/demo/.agent");
        let error = certify_skills_dir(&paths, AgyScope::Workspace, &legacy)
            .expect_err("the legacy layout is refused");
        assert_eq!(rule(&error), RULE_DEPRECATED_PATH_REFUSED);
        assert_eq!(error.dropped_details(), 0);
    }

    #[test]
    fn an_uncertified_skills_or_rules_path_is_refused() {
        let paths = paths();
        for candidate in [
            "/home/billy/projects/demo/.agents",
            "/home/billy/.agents/skills",
            "/etc/agents/skills",
        ] {
            let error = certify_skills_dir(&paths, AgyScope::Workspace, candidate)
                .expect_err("an uncertified skills path is refused");
            assert_eq!(rule(&error), RULE_LOCATION_NOT_CERTIFIED, "{candidate}");
        }
        let active = paths.rules_dir(AgyScope::Workspace);
        assert_eq!(
            certify_rules_dir(&paths, AgyScope::Workspace, &active).expect("the active rules path"),
            active
        );
        let error = certify_rules_dir(&paths, AgyScope::Workspace, "/home/billy/.agents/rules")
            .expect_err("a rules path from another scope is refused");
        assert_eq!(rule(&error), RULE_LOCATION_NOT_CERTIFIED);
    }

    #[test]
    fn the_scopes_pair_a_skills_dir_with_a_rules_dir() {
        let paths = paths();
        let workspace = paths.scope_files(AgyScope::Workspace);
        assert_eq!(
            workspace.skills_dir,
            "/home/billy/projects/demo/.agents/skills"
        );
        assert_eq!(
            workspace.rules_dir,
            "/home/billy/projects/demo/.agents/rules"
        );
        let global = paths.scope_files(AgyScope::Global);
        assert_eq!(global.skills_dir, "/home/billy/.agents/skills");
        assert_eq!(global.rules_dir, "/home/billy/.agents/rules");

        let plan = AgyPlan::plan(paths, AgyScope::Global, managed(), gate(), None).expect("a plan");
        assert_eq!(plan.scope_files(), global);
        assert_eq!(plan.skills_dir(), global.skills_dir);
        assert_eq!(plan.rules_dir(), global.rules_dir);
        assert_eq!(plan.schema_version(), AGY_MCP_SCHEMA_VERSION);
    }

    #[test]
    fn an_unsupported_scope_is_refused() {
        assert_eq!(
            resolve_scope("workspace").expect("workspace"),
            AgyScope::Workspace
        );
        assert_eq!(resolve_scope("global").expect("global"), AgyScope::Global);
        for value in ["user", "project", "", "Global"] {
            let error = resolve_scope(value).expect_err("an unknown scope is refused");
            assert_eq!(rule(&error), RULE_UNSUPPORTED_SCOPE, "scope: {value}");
        }
    }

    #[test]
    fn the_remote_transport_renders_server_url_and_never_http_url() {
        let rendered = managed().render_json();
        assert_eq!(
            rendered[SERVER_URL_FIELD],
            Value::from("http://127.0.0.1:8766/mcp")
        );
        assert!(rendered.get("httpUrl").is_none());
        assert!(rendered.get("url").is_none());
        assert_eq!(managed().transport.field(), SERVER_URL_FIELD);
    }

    #[test]
    fn a_foreign_transport_field_is_refused() {
        for (key, value) in [
            ("httpUrl", "http://127.0.0.1:8766/mcp"),
            ("url", "http://127.0.0.1:8766/sse"),
            ("sseUrl", "http://127.0.0.1:8766/sse"),
            ("bearer_token_env_var", "AXIOM_MCP_TOKEN"),
        ] {
            // A bare identifier key in `json!` stringifies to its own name
            // rather than interpolating, so the object is built explicitly.
            let mut object = Map::new();
            object.insert(key.to_owned(), Value::from(value));
            let entry = Value::Object(object);
            let error = AgyServer::from_json(MANAGED_SERVER, &entry)
                .expect_err("a foreign transport field is refused");
            assert_eq!(rule(&error), RULE_UNSUPPORTED_TRANSPORT_FIELD, "{key}");
        }
    }

    #[test]
    fn every_rendered_entry_parses_back_to_the_same_server() {
        for server in [
            managed(),
            AgyServer::stdio(
                MANAGED_SERVER,
                "/usr/local/bin/axiom-graphd",
                vec!["mcp".to_owned()],
            ),
        ] {
            let rendered = server.render_json();
            assert_eq!(
                AgyServer::from_json(MANAGED_SERVER, &rendered).expect("a round trip"),
                server
            );
        }
    }

    #[test]
    fn a_literal_credential_or_an_in_url_credential_is_refused() {
        let entry = serde_json::json!({ "serverUrl": "http://127.0.0.1:8766/mcp?token=abc" });
        let error = AgyServer::from_json(MANAGED_SERVER, &entry)
            .expect_err("a credential in the URL is refused");
        assert_eq!(rule(&error), RULE_CREDENTIAL_IN_URL);

        let entry =
            serde_json::json!({ "serverUrl": "http://127.0.0.1:8766/mcp", "api_key": "abc" });
        let error = AgyServer::from_json(MANAGED_SERVER, &entry)
            .expect_err("a literal credential field is refused");
        assert_eq!(rule(&error), RULE_CREDENTIAL_LITERAL);
    }

    #[test]
    fn an_insecure_non_loopback_url_is_refused() {
        let error = AgyServer::server_url(MANAGED_SERVER, "http://10.0.0.5:8766/mcp")
            .validate()
            .expect_err("plaintext HTTP to a remote host is refused");
        assert_eq!(rule(&error), RULE_INSECURE_TRANSPORT);
    }

    #[test]
    fn a_plan_inserts_then_replaces_without_touching_other_servers() {
        let insert = AgyPlan::plan(
            paths(),
            AgyScope::Workspace,
            managed(),
            gate(),
            Some(EXISTING),
        )
        .expect("an insert plan");
        assert_eq!(insert.action(), PlanAction::Insert);
        let merged = insert.apply(EXISTING).expect("a merged document");
        let parsed = parse(&merged);
        assert_eq!(
            parsed["mcpServers"]["axiom-graphd"][SERVER_URL_FIELD],
            Value::from("http://127.0.0.1:8766/mcp")
        );
        assert_eq!(
            parsed["mcpServers"]["other"]["command"],
            Value::from("/usr/local/bin/other")
        );
        assert_eq!(parsed["theme"], Value::from("dark"));
        assert_eq!(parsed["unknownTopLevel"], Value::from(7));

        let replaced = AgyPlan::plan(
            paths(),
            AgyScope::Workspace,
            AgyServer::server_url(MANAGED_SERVER, "http://127.0.0.1:9999/mcp"),
            gate(),
            Some(&merged),
        )
        .expect("a replace plan");
        assert_eq!(replaced.action(), PlanAction::Replace);
        let updated = replaced.apply(&merged).expect("an updated document");
        let parsed = parse(&updated);
        assert_eq!(
            parsed["mcpServers"]["axiom-graphd"][SERVER_URL_FIELD],
            Value::from("http://127.0.0.1:9999/mcp")
        );
        assert_eq!(
            parsed["mcpServers"]["other"]["command"],
            Value::from("/usr/local/bin/other")
        );
    }

    #[test]
    fn an_insert_refuses_a_document_that_already_declares_the_server() {
        let plan =
            AgyPlan::plan(paths(), AgyScope::Workspace, managed(), gate(), None).expect("a plan");
        assert_eq!(plan.action(), PlanAction::Insert);
        let existing = with_managed();
        let error = plan
            .apply(&existing)
            .expect_err("an already-declared server is refused on insert");
        assert_eq!(rule(&error), RULE_SERVER_ALREADY_PRESENT);
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let entry = serde_json::json!({ "serverUrl": "http://127.0.0.1:8766/mcp", "retries": 3 });
        let error =
            AgyServer::from_json(MANAGED_SERVER, &entry).expect_err("an unknown field is refused");
        assert_eq!(rule(&error), RULE_UNKNOWN_FIELD);
    }

    #[test]
    fn an_entry_without_a_transport_is_refused() {
        let entry = serde_json::json!({ "type": "http" });
        let error = AgyServer::from_json(MANAGED_SERVER, &entry)
            .expect_err("a transport-less entry is refused");
        assert_eq!(rule(&error), RULE_TRANSPORT_MISSING);
    }

    #[test]
    fn an_oversized_document_is_refused() {
        let oversized = " ".repeat(MAX_CONFIG_BYTES + 1);
        let error = AgyPlan::plan(
            paths(),
            AgyScope::Workspace,
            managed(),
            gate(),
            Some(&oversized),
        )
        .expect_err("an oversized document is refused");
        assert_eq!(rule(&error), RULE_OUTPUT_TOO_LARGE);
    }

    #[test]
    fn the_instruction_fragment_uses_the_managed_block_markers() {
        let plan =
            AgyPlan::plan(paths(), AgyScope::Global, managed(), gate(), None).expect("a plan");
        let fragment = plan.instruction_fragment();
        assert!(fragment.starts_with(markers::BEGIN_MARKER));
        assert!(fragment.trim_end().ends_with(markers::END_MARKER));
        assert!(fragment.contains(MANAGED_SERVER));
    }

    #[test]
    fn an_unsafe_root_is_refused() {
        for root in ["relative/path", "", "/home/billy/\u{7}bad"] {
            let error = AgyPaths::resolve(root, "/home/billy/projects/demo")
                .expect_err("an unsafe root is refused");
            assert_eq!(rule(&error), RULE_UNSAFE_PATH, "root: {root}");
        }
    }
}
