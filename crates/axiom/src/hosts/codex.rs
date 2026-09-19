//! Codex MCP and instruction fragments (task E-027).
//!
//! Codex reads its MCP servers from TOML (`~/.codex/config.toml`) and its
//! instructions from `AGENTS.md`. `docs/21-INSTALLATION.md` section F pins the
//! rule for both: the configured MCP entry must preserve existing servers and use
//! an env/credential reference, and template examples must be rendered through a
//! certified adapter, never blind-overwritten.
//!
//! ## Why this is a TOML validator and not a TOML writer
//!
//! Re-rendering the whole document would drop the comments, ordering and
//! formatting a human owns, so this module never round-trips a config file. It
//! parses a **bounded subset** of TOML far enough to (a) refuse a document whose
//! target table uses a field Codex does not support and (b) find the exact byte
//! span of the one table it owns. The planned result is then either a span
//! replacement or an append, so every other byte - every other server, every
//! comment - survives unchanged.
//!
//! Unsupported syntax (`[[table]]`, inline tables, floats, multi-line strings,
//! unknown escapes) is refused with [`RULE_UNSUPPORTED_SYNTAX`] rather than
//! guessed at, because guessing is how a config file loses a human's work.
//!
//! ## Transport fields are not interchangeable
//!
//! Codex's documented HTTP MCP shape is `url` plus `bearer_token_env_var` (source
//! S10). A field from another host (`httpUrl`, `serverUrl`, `type`, `sseUrl`) is
//! refused with [`RULE_UNSUPPORTED_TRANSPORT_FIELD`] instead of being accepted as
//! an unknown key, so a copy-pasted Gemini or Antigravity block fails validation
//! here rather than silently producing a server Codex will ignore.
//!
//! Nothing in this module writes to a host: [`CodexPlan::apply`] is a pure
//! byte-to-byte transformation of a document the caller already holds.

use std::collections::BTreeMap;
use std::path::Path;

use graph_core::error::{AxiomError, ErrorCode};

use crate::bootstrap::markers;

/// Directory under the user home that holds the Codex configuration.
pub const CODEX_DIR: &str = ".codex";
/// Codex configuration file inside [`CODEX_DIR`].
pub const CODEX_CONFIG_FILE: &str = "config.toml";
/// Instruction file Codex discovers in a project (source S09).
pub const CODEX_INSTRUCTION_FILE: &str = "AGENTS.md";
/// Default managed MCP server name.
pub const MANAGED_SERVER: &str = "axiom-graphd";
/// Table prefix every MCP server lives under.
pub const MCP_TABLE_PREFIX: &str = "mcp_servers.";

/// Largest configuration document this module will parse.
pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
/// Largest single rendered server block.
pub const MAX_BLOCK_BYTES: usize = 4 * 1024;
/// Largest accepted string value inside the subset.
pub const MAX_VALUE_BYTES: usize = 4096;
/// Largest accepted environment-variable name.
pub const MAX_ENV_VAR_BYTES: usize = 128;

/// Refusal: the document uses TOML this bounded subset will not guess at.
pub const RULE_UNSUPPORTED_SYNTAX: &str = "toml-unsupported-syntax";
/// Refusal: a field outside the documented Codex server schema.
pub const RULE_UNKNOWN_FIELD: &str = "unknown-field";
/// Refusal: a transport field belonging to another host's schema.
pub const RULE_UNSUPPORTED_TRANSPORT_FIELD: &str = "unsupported-transport-field";
/// Refusal: neither `url` nor `command` is present.
pub const RULE_TRANSPORT_MISSING: &str = "transport-missing";
/// Refusal: both the HTTP and the stdio transport are declared.
pub const RULE_TRANSPORT_CONFLICT: &str = "transport-conflict";
/// Refusal: a credential value was written literally instead of referenced.
pub const RULE_CREDENTIAL_LITERAL: &str = "credential-literal-refused";
/// Refusal: the URL carries a credential in its query string.
pub const RULE_CREDENTIAL_IN_URL: &str = "credential-in-url-refused";
/// Refusal: a non-loopback plaintext HTTP endpoint.
pub const RULE_INSECURE_TRANSPORT: &str = "insecure-transport-refused";
/// Refusal: the same key appears twice in one table.
pub const RULE_DUPLICATE_KEY: &str = "toml-duplicate-key";
/// Refusal: a document or block larger than the bound.
pub const RULE_OUTPUT_TOO_LARGE: &str = "output-too-large";
/// Refusal: a path that is not an absolute, control-free host path.
pub const RULE_UNSAFE_PATH: &str = "unsafe-path";
/// Refusal: the existing on-disk table uses a field Codex does not support.
pub const RULE_EXISTING_TABLE_UNSUPPORTED: &str = "existing-table-unsupported";

/// Fields Codex supports inside `[mcp_servers.<name>]`.
pub const SUPPORTED_FIELDS: [&str; 6] = [
    "url",
    "bearer_token_env_var",
    "command",
    "args",
    "env",
    "enabled",
];

/// Transport fields that belong to another host's schema and must never be
/// silently accepted here.
pub const FOREIGN_TRANSPORT_FIELDS: [&str; 4] = ["httpUrl", "serverUrl", "sseUrl", "type"];

/// Query-string names that mean a credential was placed in the URL.
const CREDENTIAL_QUERY_NAMES: [&str; 4] = ["token", "apikey", "api_key", "password"];

fn refuse(rule: &str, message: impl AsRef<str>) -> AxiomError {
    AxiomError::new(ErrorCode::ValidationError, message).with_detail("rule", rule)
}

/// Absolute paths this adapter plans for.
///
/// Only two paths exist for Codex, and both are recorded in the plan so a reviewer
/// sees exactly what would be touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexPaths {
    /// Absolute user home.
    home: String,
    /// Absolute project root.
    project: String,
}

impl CodexPaths {
    /// Bind the two absolute roots.
    ///
    /// # Errors
    /// [`RULE_UNSAFE_PATH`] when either root is relative, empty, oversized or
    /// contains control characters.
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

    /// `~/.codex/config.toml`, rendered with `/` separators.
    #[must_use]
    pub fn config_file(&self) -> String {
        format!("{}/{CODEX_DIR}/{CODEX_CONFIG_FILE}", self.home)
    }

    /// `<project>/AGENTS.md`.
    #[must_use]
    pub fn instruction_file(&self) -> String {
        format!("{}/{CODEX_INSTRUCTION_FILE}", self.project)
    }

    /// User home this plan is bound to.
    #[must_use]
    pub fn home(&self) -> &str {
        &self.home
    }

    /// Project root this plan is bound to.
    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }
}

fn is_safe_root(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed.len() <= 4096
        && !trimmed.chars().any(char::is_control)
        && Path::new(trimmed).is_absolute()
}

/// The documented Codex MCP transports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexTransport {
    /// Streamable HTTP: `url` plus an optional `bearer_token_env_var` reference.
    Http {
        /// Endpoint URL.
        url: String,
        /// Environment variable that carries the bearer token, never the token.
        bearer_token_env_var: Option<String>,
    },
    /// stdio: a program launched with argv.
    Stdio {
        /// Program to launch.
        command: String,
        /// Arguments passed to the program.
        args: Vec<String>,
    },
}

/// One managed Codex MCP server entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexServer {
    /// Server name under `[mcp_servers.<name>]`.
    pub name: String,
    /// Declared transport.
    pub transport: CodexTransport,
}

impl CodexServer {
    /// A streamable-HTTP server with an env-var credential reference.
    ///
    /// # Errors
    /// [`RULE_UNSAFE_PATH`]-style validation failures are reported by
    /// [`Self::validate`], not here; this constructor only builds the value.
    #[must_use]
    pub fn http(name: &str, url: &str, bearer_token_env_var: Option<&str>) -> Self {
        Self {
            name: name.to_owned(),
            transport: CodexTransport::Http {
                url: url.to_owned(),
                bearer_token_env_var: bearer_token_env_var.map(str::to_owned),
            },
        }
    }

    /// A stdio server.
    #[must_use]
    pub fn stdio(name: &str, command: &str, args: Vec<String>) -> Self {
        Self {
            name: name.to_owned(),
            transport: CodexTransport::Stdio {
                command: command.to_owned(),
                args,
            },
        }
    }

    /// Validate the server against the documented Codex schema.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with a named `rule` detailing every
    /// violation found.
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
            CodexTransport::Http {
                url,
                bearer_token_env_var,
            } => {
                validate_url(url, &mut violations);
                if let Some(name) = bearer_token_env_var {
                    validate_env_var(name, &mut violations);
                }
            }
            CodexTransport::Stdio { command, args } => {
                if command.trim().is_empty() || !Path::new(command).is_absolute() {
                    violations.push("stdio-command-not-absolute".to_owned());
                }
                if command.contains(' ') || command.contains('"') {
                    violations.push("stdio-command-has-shell-metacharacters".to_owned());
                }
                for arg in args {
                    if arg.len() > MAX_VALUE_BYTES {
                        violations.push("stdio-arg-too-large".to_owned());
                    }
                }
            }
        }
        if violations.is_empty() {
            return Ok(());
        }
        Err(refuse(
            violations.first().expect("a violation").as_str(),
            "the server entry does not satisfy the documented Codex MCP schema",
        )
        .with_detail("observed", violations.join(","))
        .with_detail("component", self.name.clone()))
    }

    /// Render this server as the exact TOML block the plan will place.
    #[must_use]
    pub fn render_block(&self) -> String {
        let mut block = format!("[mcp_servers.{}]\n", self.name);
        match &self.transport {
            CodexTransport::Http {
                url,
                bearer_token_env_var,
            } => {
                block.push_str(&format!("url = \"{}\"\n", escape_toml(url)));
                if let Some(name) = bearer_token_env_var {
                    block.push_str(&format!(
                        "bearer_token_env_var = \"{}\"\n",
                        escape_toml(name)
                    ));
                }
            }
            CodexTransport::Stdio { command, args } => {
                block.push_str(&format!("command = \"{}\"\n", escape_toml(command)));
                if !args.is_empty() {
                    let rendered: Vec<String> = args
                        .iter()
                        .map(|arg| format!("\"{}\"", escape_toml(arg)))
                        .collect();
                    block.push_str(&format!("args = [{}]\n", rendered.join(", ")));
                }
            }
        }
        block
    }
}

/// Validate a Codex `url` value.
pub fn validate_url(url: &str, violations: &mut Vec<String>) {
    if url.trim().is_empty() || url.len() > MAX_VALUE_BYTES || url.chars().any(char::is_control) {
        violations.push("invalid-url".to_owned());
        return;
    }
    if url.contains(char::is_whitespace) {
        violations.push("invalid-url".to_owned());
    }
    let trimmed = url.trim();
    let lowered = trimmed.to_ascii_lowercase();
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
        let insecure = lowered.starts_with("http://") && !is_loopback(host);
        if insecure {
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

/// Validate a `bearer_token_env_var` reference: a name, never the token itself.
pub fn validate_env_var(name: &str, violations: &mut Vec<String>) {
    let mut chars = name.chars();
    let shape_ok = name.len() <= MAX_ENV_VAR_BYTES
        && matches!(chars.next(), Some(first) if first.is_ascii_alphabetic() || first == '_')
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
    if !shape_ok {
        violations.push(RULE_CREDENTIAL_LITERAL.to_owned());
    }
}

fn escape_toml(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// A value inside the bounded TOML subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TomlValue {
    /// Basic or literal string.
    Str(String),
    /// Integer literal.
    Integer(i64),
    /// Boolean literal.
    Bool(bool),
    /// Inline single-line array of strings.
    StrList(Vec<String>),
}

impl TomlValue {
    /// The string value, when this is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(value) => Some(value),
            _ => None,
        }
    }

    /// The string-list value, when this is an array of strings.
    #[must_use]
    pub fn as_str_list(&self) -> Option<&[String]> {
        match self {
            Self::StrList(values) => Some(values),
            _ => None,
        }
    }

    /// The integer value, when this is an integer.
    #[must_use]
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    /// The boolean value, when this is a boolean.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }
}

/// One parsed table of the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TomlTable {
    /// Dotted header without brackets; empty for the implicit root table.
    pub header: String,
    /// Entries in the order the document declares them.
    pub entries: BTreeMap<String, TomlValue>,
}

/// A parsed TOML document plus the byte span of each table.
///
/// The original text is retained so a planned edit can be expressed as the
/// smallest byte range, and every other byte of a human's file survives.
#[derive(Debug, Clone)]
pub struct CodexDocument {
    text: String,
    tables: Vec<TomlTable>,
    spans: Vec<(usize, usize)>,
}

impl CodexDocument {
    /// Parse the bounded subset.
    ///
    /// # Errors
    /// [`RULE_OUTPUT_TOO_LARGE`] when the document exceeds [`MAX_CONFIG_BYTES`];
    /// [`RULE_UNSUPPORTED_SYNTAX`] for TOML outside the subset;
    /// [`RULE_DUPLICATE_KEY`] for a repeated key inside one table.
    pub fn parse(text: &str) -> Result<Self, AxiomError> {
        if text.len() > MAX_CONFIG_BYTES {
            return Err(refuse(
                RULE_OUTPUT_TOO_LARGE,
                "the configuration document is larger than this adapter will parse",
            )
            .with_detail("observed", text.len().to_string()));
        }
        let mut tables: Vec<TomlTable> = vec![TomlTable {
            header: String::new(),
            entries: BTreeMap::new(),
        }];
        let mut spans: Vec<(usize, usize)> = vec![(0, text.len())];
        let mut current = 0usize;

        for (line_start, raw) in line_offsets(text) {
            let line = strip_comment(raw);
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(header) = table_header(trimmed)? {
                if let Some(span) = spans.get_mut(current) {
                    if current > 0 {
                        span.1 = line_start;
                    }
                }
                tables.push(TomlTable {
                    header: header.clone(),
                    entries: BTreeMap::new(),
                });
                spans.push((line_start, text.len()));
                current = tables.len() - 1;
                continue;
            }
            let (key, value) = parse_entry(trimmed)?;
            let table = tables.get_mut(current).expect("the current table exists");
            if table.entries.insert(key.clone(), value).is_some() {
                return Err(refuse(
                    RULE_DUPLICATE_KEY,
                    "the same key is declared twice in one table",
                )
                .with_detail("config_key", key)
                .with_detail("table", table.header.clone()));
            }
        }
        // The implicit root table keeps only the span before any explicit header.
        if tables.len() > 1 {
            let first_header_start = spans.get(1).map_or(text.len(), |span| span.0);
            if let Some(first) = spans.first_mut() {
                first.1 = first_header_start;
            }
        }
        Ok(Self {
            text: text.to_owned(),
            tables,
            spans,
        })
    }

    /// The whole parsed text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Every table with the given dotted header.
    #[must_use]
    pub fn table(&self, header: &str) -> Option<&TomlTable> {
        self.tables.iter().find(|table| table.header == header)
    }

    /// Dotted header of one MCP server entry.
    #[must_use]
    pub fn server_header(name: &str) -> String {
        format!("{MCP_TABLE_PREFIX}{name}")
    }

    /// Every `[mcp_servers.<name>]` table, in document order.
    #[must_use]
    pub fn servers(&self) -> Vec<&TomlTable> {
        self.tables
            .iter()
            .filter(|table| table.header.starts_with(MCP_TABLE_PREFIX))
            .collect()
    }

    /// The table for one MCP server, when the document declares it.
    #[must_use]
    pub fn server(&self, name: &str) -> Option<&TomlTable> {
        self.table(&Self::server_header(name))
    }

    /// Byte span of the table with `header`, header line included.
    #[must_use]
    pub fn span_of(&self, header: &str) -> Option<(usize, usize)> {
        self.tables
            .iter()
            .position(|table| table.header == header)
            .and_then(|index| self.spans.get(index).copied())
    }
}

/// Split `text` into `(byte offset of line start, line)` pairs.
fn line_offsets(text: &str) -> Vec<(usize, &str)> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    for (index, ch) in text.char_indices() {
        if ch == '\n' {
            lines.push((start, &text[start..index]));
            start = index + 1;
        }
    }
    if start < text.len() {
        lines.push((start, &text[start..]));
    }
    lines
}

/// Drop a trailing comment, honouring quoted strings.
fn strip_comment(line: &str) -> &str {
    let mut basic = false;
    let mut literal = false;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if basic => escaped = true,
            '"' if !literal => basic = !basic,
            '\'' if !basic => literal = !literal,
            '#' if !basic && !literal => return &line[..index],
            _ => {}
        }
    }
    line
}

fn table_header(trimmed: &str) -> Result<Option<String>, AxiomError> {
    let Some(rest) = trimmed.strip_prefix('[') else {
        return Ok(None);
    };
    if rest.starts_with('[') {
        return Err(refuse(
            RULE_UNSUPPORTED_SYNTAX,
            "arrays of tables are outside this bounded TOML subset",
        )
        .with_detail("observed", trimmed));
    }
    let Some(header) = rest.strip_suffix(']') else {
        return Err(refuse(
            RULE_UNSUPPORTED_SYNTAX,
            "an unterminated table header is outside this bounded TOML subset",
        )
        .with_detail("observed", trimmed));
    };
    if !is_valid_header(header) {
        return Err(refuse(
            RULE_UNSUPPORTED_SYNTAX,
            "the table header is not a bounded dotted key",
        )
        .with_detail("table", header));
    }
    Ok(Some(header.to_owned()))
}

fn is_valid_header(header: &str) -> bool {
    if header.is_empty() || header.len() > 256 || header.chars().any(char::is_control) {
        return false;
    }
    header.split('.').all(|segment| {
        if segment.len() >= 2 && segment.starts_with('"') && segment.ends_with('"') {
            let inner = &segment[1..segment.len() - 1];
            !inner.is_empty() && !inner.contains('"')
        } else {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        }
    })
}

fn parse_entry(trimmed: &str) -> Result<(String, TomlValue), AxiomError> {
    let Some(equals) = split_on_equals(trimmed) else {
        return Err(refuse(
            RULE_UNSUPPORTED_SYNTAX,
            "a line that is neither a table header nor a key/value pair",
        )
        .with_detail("observed", trimmed));
    };
    let key = trimmed[..equals].trim().to_owned();
    if !is_valid_key(&key) {
        return Err(
            refuse(RULE_UNSUPPORTED_SYNTAX, "the key is not a bounded key")
                .with_detail("config_key", key),
        );
    }
    let value_text = trimmed[equals + 1..].trim();
    let value = parse_value(value_text)?;
    Ok((unquote_key(&key), value))
}

fn split_on_equals(line: &str) -> Option<usize> {
    let mut basic = false;
    let mut literal = false;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if basic => escaped = true,
            '"' if !literal => basic = !basic,
            '\'' if !basic => literal = !literal,
            '=' if !basic && !literal => return Some(index),
            _ => {}
        }
    }
    None
}

fn is_valid_key(key: &str) -> bool {
    if key.len() >= 2 && key.starts_with('"') && key.ends_with('"') {
        let inner = &key[1..key.len() - 1];
        return !inner.is_empty() && !inner.contains('"') && !inner.chars().any(char::is_control);
    }
    !key.is_empty()
        && key.len() <= 128
        && key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn unquote_key(key: &str) -> String {
    if key.len() >= 2 && key.starts_with('"') && key.ends_with('"') {
        key[1..key.len() - 1].to_owned()
    } else {
        key.to_owned()
    }
}

fn parse_value(text: &str) -> Result<TomlValue, AxiomError> {
    if text.is_empty() {
        return Err(refuse(RULE_UNSUPPORTED_SYNTAX, "a key with no value"));
    }
    if text.starts_with("\"\"\"") || text.starts_with("'''") {
        return Err(refuse(
            RULE_UNSUPPORTED_SYNTAX,
            "a multi-line string is outside this bounded TOML subset",
        ));
    }
    if let Some(inner) = text.strip_prefix('[') {
        let Some(inner) = inner.strip_suffix(']') else {
            return Err(refuse(
                RULE_UNSUPPORTED_SYNTAX,
                "a multi-line or unterminated array is outside this bounded TOML subset",
            ));
        };
        if inner.trim().is_empty() {
            return Ok(TomlValue::StrList(Vec::new()));
        }
        let mut values = Vec::new();
        for element in split_array(inner)? {
            let element = element.trim();
            if element.starts_with('{') {
                return Err(refuse(
                    RULE_UNSUPPORTED_SYNTAX,
                    "inline tables are outside this bounded TOML subset",
                ));
            }
            values.push(parse_value(element)?.as_str().map_or_else(
                || {
                    Err(refuse(
                        RULE_UNSUPPORTED_SYNTAX,
                        "only string arrays are supported",
                    ))
                },
                |value| Ok(value.to_owned()),
            )?);
        }
        return Ok(TomlValue::StrList(values));
    }
    if let Some(inner) = text.strip_prefix('"') {
        let Some(inner) = inner.strip_suffix('"') else {
            return Err(refuse(
                RULE_UNSUPPORTED_SYNTAX,
                "an unterminated string is outside this bounded TOML subset",
            ));
        };
        let value = unescape_basic(inner)?;
        if value.len() > MAX_VALUE_BYTES {
            return Err(refuse(RULE_OUTPUT_TOO_LARGE, "a string value is too large"));
        }
        return Ok(TomlValue::Str(value));
    }
    if let Some(inner) = text.strip_prefix('\'') {
        let Some(inner) = inner.strip_suffix('\'') else {
            return Err(refuse(
                RULE_UNSUPPORTED_SYNTAX,
                "an unterminated literal string is outside this bounded TOML subset",
            ));
        };
        if inner.len() > MAX_VALUE_BYTES {
            return Err(refuse(RULE_OUTPUT_TOO_LARGE, "a string value is too large"));
        }
        return Ok(TomlValue::Str(inner.to_owned()));
    }
    match text {
        "true" => return Ok(TomlValue::Bool(true)),
        "false" => return Ok(TomlValue::Bool(false)),
        _ => {}
    }
    let digits = text.strip_prefix('-').unwrap_or(text);
    if !digits.is_empty() && digits.len() <= 19 && digits.chars().all(|ch| ch.is_ascii_digit()) {
        let Ok(value) = text.parse::<i64>() else {
            return Err(refuse(
                RULE_UNSUPPORTED_SYNTAX,
                "the integer is outside the accepted range",
            ));
        };
        return Ok(TomlValue::Integer(value));
    }
    Err(refuse(
        RULE_UNSUPPORTED_SYNTAX,
        "the value is outside this bounded TOML subset",
    )
    .with_detail("actual", text))
}

fn split_array(inner: &str) -> Result<Vec<&str>, AxiomError> {
    let mut elements = Vec::new();
    let mut basic = false;
    let mut literal = false;
    let mut escaped = false;
    let mut start = 0usize;
    for (index, ch) in inner.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if basic => escaped = true,
            '"' if !literal => basic = !basic,
            '\'' if !basic => literal = !literal,
            ',' if !basic && !literal => {
                elements.push(&inner[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if basic || literal {
        return Err(refuse(
            RULE_UNSUPPORTED_SYNTAX,
            "an unterminated string inside an array",
        ));
    }
    elements.push(&inner[start..]);
    Ok(elements)
}

fn unescape_basic(inner: &str) -> Result<String, AxiomError> {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let Some(next) = chars.next() else {
            return Err(refuse(
                RULE_UNSUPPORTED_SYNTAX,
                "a trailing escape inside a string",
            ));
        };
        match next {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            _ => {
                return Err(refuse(
                    RULE_UNSUPPORTED_SYNTAX,
                    "an escape this bounded TOML subset does not support",
                )
                .with_detail("actual", format!("\\{next}")));
            }
        }
    }
    Ok(out)
}

impl CodexServer {
    /// Read a server entry out of an existing table, validating it against the
    /// documented Codex schema.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with `rule` set to
    /// [`RULE_UNSUPPORTED_TRANSPORT_FIELD`] when a field belongs to another
    /// host's schema, [`RULE_UNKNOWN_FIELD`] for any other unknown key,
    /// [`RULE_TRANSPORT_CONFLICT`]/[`RULE_TRANSPORT_MISSING`] for an unusable
    /// transport pair, and the [`Self::validate`] rules for bad values.
    pub fn from_table(name: &str, table: &TomlTable) -> Result<Self, AxiomError> {
        let mut foreign = Vec::new();
        let mut unknown = Vec::new();
        for key in table.entries.keys() {
            if FOREIGN_TRANSPORT_FIELDS.contains(&key.as_str()) {
                foreign.push(key.clone());
            } else if !SUPPORTED_FIELDS.contains(&key.as_str()) {
                unknown.push(key.clone());
            }
        }
        if !foreign.is_empty() {
            return Err(refuse(
                RULE_UNSUPPORTED_TRANSPORT_FIELD,
                "the table uses a transport field that belongs to another host's schema",
            )
            .with_detail("config_key", foreign.join(","))
            .with_detail("table", table.header.clone()));
        }
        if !unknown.is_empty() {
            return Err(refuse(
                RULE_UNKNOWN_FIELD,
                "the table uses a field outside the documented Codex MCP schema",
            )
            .with_detail("config_key", unknown.join(","))
            .with_detail("table", table.header.clone()));
        }

        let url = table.entries.get("url").and_then(TomlValue::as_str);
        let env = table
            .entries
            .get("bearer_token_env_var")
            .and_then(TomlValue::as_str);
        let command = table.entries.get("command").and_then(TomlValue::as_str);
        let args = table
            .entries
            .get("args")
            .and_then(TomlValue::as_str_list)
            .unwrap_or(&[])
            .to_vec();
        let transport = match (url, command) {
            (Some(_), Some(_)) => {
                return Err(refuse(
                    RULE_TRANSPORT_CONFLICT,
                    "the table declares both the HTTP and the stdio transport",
                )
                .with_detail("table", table.header.clone()));
            }
            (Some(url), None) => CodexTransport::Http {
                url: url.to_owned(),
                bearer_token_env_var: env.map(str::to_owned),
            },
            (None, Some(command)) => CodexTransport::Stdio {
                command: command.to_owned(),
                args,
            },
            (None, None) => {
                return Err(refuse(
                    RULE_TRANSPORT_MISSING,
                    "the table declares neither `url` nor `command`",
                )
                .with_detail("table", table.header.clone()));
            }
        };
        let server = Self {
            name: name.to_owned(),
            transport,
        };
        server.validate()?;
        Ok(server)
    }
}

/// Refusal: an append plan was applied to a document that already declares the
/// managed table, which would duplicate a server entry.
pub const RULE_TABLE_ALREADY_PRESENT: &str = "table-already-present";

/// What a plan will do to the existing document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanAction {
    /// Append the managed block, keeping the whole document as a prefix.
    Append,
    /// Replace only the byte span of the managed table.
    Replace,
}

/// The reviewed Codex change: one server block plus the instruction fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexPlan {
    paths: CodexPaths,
    server: CodexServer,
    action: PlanAction,
}

impl CodexPlan {
    /// Build a plan, validating the server and the existing document.
    ///
    /// `existing` is the current `config.toml` when the caller has one. A
    /// document that already declares the managed server is validated too, so a
    /// table this adapter does not understand is refused instead of replaced.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with the rule of the first violation.
    pub fn plan(
        paths: CodexPaths,
        server: CodexServer,
        existing: Option<&str>,
    ) -> Result<Self, AxiomError> {
        server.validate()?;
        let action = match existing {
            None => PlanAction::Append,
            Some(text) => {
                let document = CodexDocument::parse(text)?;
                if let Some(table) = document.server(&server.name) {
                    CodexServer::from_table(&server.name, table)?;
                    PlanAction::Replace
                } else {
                    PlanAction::Append
                }
            }
        };
        Ok(Self {
            paths,
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
    pub const fn server(&self) -> &CodexServer {
        &self.server
    }

    /// The two absolute paths this plan targets.
    #[must_use]
    pub const fn paths(&self) -> &CodexPaths {
        &self.paths
    }

    /// The exact TOML block that will be written.
    #[must_use]
    pub fn render_block(&self) -> String {
        self.server.render_block()
    }

    /// The managed instruction fragment for `AGENTS.md`.
    ///
    /// The fragment carries the same managed-block markers bootstrap owns
    /// (`bootstrap::markers`), so there is exactly one marker vocabulary in this
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

    /// Apply the plan to `existing`, returning the planned document.
    ///
    /// This is a pure byte transformation: only the managed table's own span is
    /// replaced, or the managed block is appended while the whole existing
    /// document stays an exact prefix. Every other server and every comment is
    /// preserved byte for byte.
    ///
    /// # Errors
    /// [`RULE_OUTPUT_TOO_LARGE`] for an oversized block;
    /// [`RULE_TABLE_ALREADY_PRESENT`] when an append plan meets a document that
    /// already declares the table; [`RULE_UNSUPPORTED_SYNTAX`] when the document
    /// is outside the bounded subset.
    pub fn apply(&self, existing: &str) -> Result<String, AxiomError> {
        let block = self.server.render_block();
        if block.len() > MAX_BLOCK_BYTES {
            return Err(refuse(
                RULE_OUTPUT_TOO_LARGE,
                "the rendered block is too large",
            ));
        }
        let document = CodexDocument::parse(existing)?;
        match self.action {
            PlanAction::Append => {
                if document.server(&self.server.name).is_some() {
                    return Err(refuse(
                        RULE_TABLE_ALREADY_PRESENT,
                        "the document already declares the managed table",
                    )
                    .with_detail("table", CodexDocument::server_header(&self.server.name)));
                }
                let mut out = existing.to_owned();
                if !out.is_empty() {
                    if !out.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push('\n');
                }
                out.push_str(&block);
                Ok(out)
            }
            PlanAction::Replace => {
                let header = CodexDocument::server_header(&self.server.name);
                let Some((start, end)) = document.span_of(&header) else {
                    return Err(refuse(
                        RULE_TABLE_ALREADY_PRESENT,
                        "the managed table is absent from the document being replaced",
                    )
                    .with_detail("table", header));
                };
                let mut out = String::with_capacity(existing.len() + block.len());
                out.push_str(&existing[..start]);
                out.push_str(&block);
                out.push_str(&existing[end..]);
                Ok(out)
            }
        }
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

    fn paths() -> CodexPaths {
        CodexPaths::resolve("/home/billy", "/home/billy/projects/demo").expect("safe roots")
    }

    fn managed() -> CodexServer {
        CodexServer::http(
            MANAGED_SERVER,
            "http://127.0.0.1:8766/mcp",
            Some("AXIOM_MCP_TOKEN"),
        )
    }

    const EXISTING: &str = "# Human comment\n\
[features]\n\
web_search = false\n\
\n\
[mcp_servers.other]\n\
command = \"/usr/local/bin/other\"\n\
args = [\"--serve\"]\n\
";

    #[test]
    fn appending_preserves_every_other_server_and_the_whole_document() {
        let plan = CodexPlan::plan(paths(), managed(), Some(EXISTING)).expect("a plan");
        assert_eq!(plan.action(), PlanAction::Append);
        let planned = plan.apply(EXISTING).expect("an applied document");
        assert!(
            planned.starts_with(EXISTING.trim_end_matches('\n')),
            "the existing document stays an exact prefix"
        );
        assert!(planned.contains("[features]\nweb_search = false\n"));
        assert!(planned.contains(
            "[mcp_servers.other]\ncommand = \"/usr/local/bin/other\"\nargs = [\"--serve\"]\n"
        ));
        assert!(planned.contains("# Human comment"));
        assert!(planned.ends_with("[mcp_servers.axiom-graphd]\nurl = \"http://127.0.0.1:8766/mcp\"\nbearer_token_env_var = \"AXIOM_MCP_TOKEN\"\n"));
        assert_eq!(plan.paths().config_file(), "/home/billy/.codex/config.toml");
        assert_eq!(
            plan.paths().instruction_file(),
            "/home/billy/projects/demo/AGENTS.md"
        );
    }

    #[test]
    fn replacing_the_managed_table_moves_nothing_else() {
        let with_managed = format!(
            "{EXISTING}\n[mcp_servers.axiom-graphd]\nurl = \"http://127.0.0.1:1/old\"\n\n[history]\npersistence = \"none\"\n"
        );
        let plan = CodexPlan::plan(paths(), managed(), Some(&with_managed)).expect("a plan");
        assert_eq!(plan.action(), PlanAction::Replace);
        let planned = plan.apply(&with_managed).expect("an applied document");
        let before = &with_managed[..with_managed
            .find("[mcp_servers.axiom-graphd]")
            .expect("a span")];
        assert!(planned.starts_with(before), "the prefix is untouched");
        assert!(planned.ends_with("[history]\npersistence = \"none\"\n"));
        assert!(planned.contains(
            "[mcp_servers.other]\ncommand = \"/usr/local/bin/other\"\nargs = [\"--serve\"]\n"
        ));
        assert!(!planned.contains("http://127.0.0.1:1/old"));
        assert_eq!(planned.matches("[mcp_servers.").count(), 2);
    }

    #[test]
    fn a_foreign_transport_field_fails_validation() {
        for (key, value) in [
            ("httpUrl", "\"http://127.0.0.1:8766/mcp\""),
            ("serverUrl", "\"http://127.0.0.1:8766/mcp\""),
            ("sseUrl", "\"http://127.0.0.1:8766/sse\""),
            ("type", "\"http\""),
        ] {
            let document =
                CodexDocument::parse(&format!("[mcp_servers.axiom-graphd]\n{key} = {value}\n"))
                    .expect("a parsed document");
            let table = document.server(MANAGED_SERVER).expect("the table");
            let error = CodexServer::from_table(MANAGED_SERVER, table)
                .expect_err("a foreign field is refused");
            assert_eq!(rule(&error), RULE_UNSUPPORTED_TRANSPORT_FIELD);
            assert_eq!(
                error.details().get("config_key").map(String::as_str),
                Some(key)
            );
        }

        let unknown = CodexDocument::parse("[mcp_servers.axiom-graphd]\nfoo = 1\n")
            .expect("a parsed document");
        let error = CodexServer::from_table(
            MANAGED_SERVER,
            unknown.server(MANAGED_SERVER).expect("the table"),
        )
        .expect_err("an unknown field is refused");
        assert_eq!(rule(&error), RULE_UNKNOWN_FIELD);

        let conflict =
            "[mcp_servers.axiom-graphd]\nurl = \"https://host/mcp\"\ncommand = \"/bin/x\"\n";
        let document = CodexDocument::parse(conflict).expect("a parsed document");
        let error = CodexServer::from_table(
            MANAGED_SERVER,
            document.server(MANAGED_SERVER).expect("the table"),
        )
        .expect_err("two transports are refused");
        assert_eq!(rule(&error), RULE_TRANSPORT_CONFLICT);

        let missing = "[mcp_servers.axiom-graphd]\nenabled = true\n";
        let document = CodexDocument::parse(missing).expect("a parsed document");
        let error = CodexServer::from_table(
            MANAGED_SERVER,
            document.server(MANAGED_SERVER).expect("the table"),
        )
        .expect_err("a transport-less table is refused");
        assert_eq!(rule(&error), RULE_TRANSPORT_MISSING);
    }

    #[test]
    fn a_plan_refuses_an_existing_table_it_does_not_understand() {
        let text = "[mcp_servers.axiom-graphd]\nhttpUrl = \"http://127.0.0.1:8766/mcp\"\n";
        let error = CodexPlan::plan(paths(), managed(), Some(text))
            .expect_err("an unrecognised existing table is refused");
        assert_eq!(rule(&error), RULE_UNSUPPORTED_TRANSPORT_FIELD);
    }

    #[test]
    fn a_literal_credential_or_a_credential_url_is_refused() {
        let literal = CodexServer::http(
            MANAGED_SERVER,
            "https://gateway.example/mcp",
            Some("sk-live-abcdefghijklmnop"),
        );
        let error = literal.validate().expect_err("a literal token is refused");
        assert_eq!(rule(&error), RULE_CREDENTIAL_LITERAL);

        let in_url = CodexServer::http(
            MANAGED_SERVER,
            "https://gateway.example/mcp?token=abc",
            Some("AXIOM_MCP_TOKEN"),
        );
        let error = in_url
            .validate()
            .expect_err("a token in the URL is refused");
        assert_eq!(rule(&error), RULE_CREDENTIAL_IN_URL);

        let plaintext = CodexServer::http(
            MANAGED_SERVER,
            "http://gateway.example/mcp",
            Some("AXIOM_MCP_TOKEN"),
        );
        let error = plaintext
            .validate()
            .expect_err("plaintext remote HTTP is refused");
        assert_eq!(rule(&error), RULE_INSECURE_TRANSPORT);

        assert!(managed().validate().is_ok());
        assert!(CodexServer::http(
            MANAGED_SERVER,
            "https://gateway.example/mcp",
            Some("AXIOM_MCP_TOKEN")
        )
        .validate()
        .is_ok());
    }

    #[test]
    fn a_stdio_transport_requires_an_absolute_shell_free_command() {
        let relative = CodexServer::stdio(MANAGED_SERVER, "axiom-graphd", vec![]);
        assert_eq!(
            rule(
                &relative
                    .validate()
                    .expect_err("a relative command is refused")
            ),
            "stdio-command-not-absolute"
        );
        let shellish = CodexServer::stdio(MANAGED_SERVER, "/bin/sh -c \"x\"", vec![]);
        assert_eq!(
            rule(&shellish.validate().expect_err("a shell command is refused")),
            "stdio-command-has-shell-metacharacters"
        );
        let stdio = CodexServer::stdio(
            MANAGED_SERVER,
            "/usr/local/bin/axiom-graphd",
            vec!["mcp".to_owned(), "--scope".to_owned(), "demo".to_owned()],
        );
        assert!(stdio.validate().is_ok());
        assert_eq!(
            stdio.render_block(),
            "[mcp_servers.axiom-graphd]\ncommand = \"/usr/local/bin/axiom-graphd\"\nargs = [\"mcp\", \"--scope\", \"demo\"]\n"
        );
    }

    #[test]
    fn unsupported_toml_is_refused_rather_than_guessed() {
        for text in [
            "[[mcp_servers.axiom-graphd]]\nurl = \"x\"\n",
            "[mcp_servers.axiom-graphd]\nenv = { PATH = \"/bin\" }\n",
            "[mcp_servers.axiom-graphd]\nstartup_timeout_sec = 1.5\n",
            "[mcp_servers.axiom-graphd]\nurl = \"\"\"multi\"\"\"\n",
            "not a key value pair\n",
        ] {
            let error = CodexDocument::parse(text).expect_err("unsupported TOML is refused");
            assert_eq!(rule(&error), RULE_UNSUPPORTED_SYNTAX, "text: {text}");
        }
        let duplicate = "[mcp_servers.axiom-graphd]\nurl = \"a\"\nurl = \"b\"\n";
        assert_eq!(
            rule(&CodexDocument::parse(duplicate).expect_err("a duplicate key is refused")),
            RULE_DUPLICATE_KEY
        );
        let oversized = format!(
            "[mcp_servers.axiom-graphd]\nurl = \"{}\"\n",
            "x".repeat(MAX_VALUE_BYTES + 1)
        );
        assert_eq!(
            rule(&CodexDocument::parse(&oversized).expect_err("a huge value is refused")),
            RULE_OUTPUT_TOO_LARGE
        );
        let huge_document = "x".repeat(MAX_CONFIG_BYTES + 1);
        assert_eq!(
            rule(&CodexDocument::parse(&huge_document).expect_err("a huge document is refused")),
            RULE_OUTPUT_TOO_LARGE
        );
    }

    #[test]
    fn a_rendered_block_parses_back_to_the_same_server() {
        for server in [
            managed(),
            CodexServer::stdio(MANAGED_SERVER, "/usr/local/bin/axiom-graphd", vec![]),
        ] {
            let rendered = server.render_block();
            let document = CodexDocument::parse(&rendered).expect("the block parses back");
            let table = document.server(MANAGED_SERVER).expect("the table");
            let parsed = CodexServer::from_table(MANAGED_SERVER, table).expect("a server");
            assert_eq!(parsed, server);
            assert!(rendered.len() <= MAX_BLOCK_BYTES);
        }
    }

    #[test]
    fn an_append_plan_refuses_a_document_that_already_has_the_table() {
        let plan = CodexPlan::plan(paths(), managed(), None).expect("a plan");
        assert_eq!(plan.action(), PlanAction::Append);
        let error = plan
            .apply(&format!(
                "{EXISTING}\n[mcp_servers.axiom-graphd]\nurl = \"https://x/mcp\"\n"
            ))
            .expect_err("a duplicate table is refused");
        assert_eq!(rule(&error), RULE_TABLE_ALREADY_PRESENT);
    }

    #[test]
    fn a_plan_refuses_roots_that_are_not_absolute_and_safe() {
        for (home, project) in [
            ("", "/home/billy/projects/demo"),
            ("relative/home", "/home/billy/projects/demo"),
            ("/home/billy", "  "),
        ] {
            let error = CodexPaths::resolve(home, project).expect_err("an unsafe root is refused");
            assert_eq!(rule(&error), RULE_UNSAFE_PATH);
        }
    }

    #[test]
    fn the_instruction_fragment_uses_the_managed_block_markers() {
        let plan = CodexPlan::plan(paths(), managed(), None).expect("a plan");
        let fragment = plan.instruction_fragment();
        assert!(fragment.starts_with(markers::BEGIN_MARKER));
        assert!(fragment.trim_end().ends_with(markers::END_MARKER));
        assert!(fragment.contains("axiom-graphd"));
        assert!(fragment.len() <= MAX_BLOCK_BYTES);
    }

    #[test]
    fn toml_values_are_read_by_shape() {
        let document = CodexDocument::parse(
            "[top]\nflag = true\nport = 8766\nname = \"demo\"\nlist = [\"a\", 'b']\nempty = []\n",
        )
        .expect("a parsed document");
        let top = document.table("top").expect("the table");
        assert_eq!(
            top.entries.get("flag").and_then(TomlValue::as_bool),
            Some(true)
        );
        assert_eq!(
            top.entries.get("port").and_then(TomlValue::as_integer),
            Some(8766)
        );
        assert_eq!(
            top.entries.get("name").and_then(TomlValue::as_str),
            Some("demo")
        );
        assert_eq!(
            top.entries.get("list").and_then(TomlValue::as_str_list),
            Some(["a".to_owned(), "b".to_owned()].as_slice())
        );
        assert_eq!(
            top.entries.get("empty").and_then(TomlValue::as_str_list),
            Some([].as_slice())
        );
        assert_eq!(document.span_of("top").map(|(start, _)| start), Some(0));
        assert!(document.servers().is_empty());
    }
}
