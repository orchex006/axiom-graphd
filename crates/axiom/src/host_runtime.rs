//! Reviewable host configuration and bounded native MCP round trips.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

use graph_core::error::{AxiomError, ErrorCode};
use graph_export::sha256_hex;
use serde_json::{json, Value};

use crate::hosts::{antigravity, claude, codex, detect, gemini, verify};
use crate::operator_runtime::{self as io, Request};

fn command() -> Result<PathBuf, AxiomError> {
    let path = std::env::var_os("AXIOM_MCP_COMMAND")
        .map(PathBuf::from)
        .unwrap_or(io::install_root()?.join(if cfg!(windows) {
            "venv/Scripts/axiom-mcp.exe"
        } else {
            "venv/bin/axiom-mcp"
        }));
    io::no_links(&path)?;
    if !path.is_absolute() || !path.is_file() {
        return Err(io::error(
            ErrorCode::NotFound,
            "mcp-command-unavailable",
            "select an installed absolute MCP executable before configuring or verifying",
        ));
    }
    Ok(path)
}

fn args() -> Result<Vec<String>, AxiomError> {
    let values: Vec<String> = match std::env::var("AXIOM_MCP_ARGS") {
        Ok(raw) => serde_json::from_str(&raw).map_err(|_| {
            io::error(
                ErrorCode::ValidationError,
                "mcp-argv",
                "MCP arguments must be a JSON array of strings",
            )
        })?,
        Err(_) => vec!["--stdio".to_owned()],
    };
    if values.len() > 64 || values.iter().any(|v| v.len() > 4096 || v.contains('\0')) {
        return Err(io::error(
            ErrorCode::ValidationError,
            "mcp-argv-limit",
            "the MCP argv exceeds the bounded input limit",
        ));
    }
    Ok(values)
}

fn config_path(host: detect::HostKind, project: &Path) -> PathBuf {
    project.join(match host {
        detect::HostKind::Codex => ".codex/config.toml",
        detect::HostKind::Claude => ".mcp.json",
        detect::HostKind::Gemini => ".gemini/settings.json",
        detect::HostKind::Antigravity => ".agent/mcp_config.json",
    })
}

fn selected(request: &Request) -> Result<detect::HostKind, AxiomError> {
    detect::HostKind::from_wire(io::required_argument(request, "--host")?).ok_or_else(|| {
        io::error(
            ErrorCode::ValidationError,
            "host-identity",
            "the selected agent host is not declared",
        )
    })
}

fn preview(request: &Request) -> Result<Value, AxiomError> {
    let host = selected(request)?;
    let project = std::env::current_dir().map_err(|_| {
        io::error(
            ErrorCode::NotFound,
            "project-unavailable",
            "the current project directory is unavailable",
        )
    })?;
    let project = std::fs::canonicalize(project).map_err(|_| {
        io::error(
            ErrorCode::NotFound,
            "project-unavailable",
            "the project directory cannot be resolved",
        )
    })?;
    let target = config_path(host, &project);
    io::no_links(&target)?;
    let before = if target.exists() {
        Some(io::read(&target)?)
    } else {
        None
    };
    let existing = before
        .as_ref()
        .map(|v| std::str::from_utf8(v))
        .transpose()
        .map_err(|_| {
            io::error(
                ErrorCode::ValidationError,
                "host-config-encoding",
                "the current host configuration is not UTF-8",
            )
        })?;
    let executable = command()?.to_string_lossy().into_owned();
    let argv = args()?;
    let root = project.to_str().ok_or_else(|| {
        io::error(
            ErrorCode::ValidationError,
            "project-encoding",
            "the project path cannot be represented",
        )
    })?;
    let after = match host {
        detect::HostKind::Codex => {
            let plan = codex::CodexPlan::plan(
                codex::CodexPaths::resolve(root, root)?,
                codex::CodexServer::stdio(verify::MANAGED_SERVER, &executable, argv),
                existing,
            )?;
            plan.apply(existing.unwrap_or_default())?
        }
        detect::HostKind::Claude => {
            let plan = claude::ClaudePlan::plan(
                claude::ClaudePaths::resolve(root, root)?,
                claude::ClaudeScope::Project,
                claude::ClaudeServer::stdio(verify::MANAGED_SERVER, &executable, argv),
                existing,
            )?;
            plan.apply(existing.unwrap_or("{}"))?
        }
        detect::HostKind::Gemini => {
            let plan = gemini::GeminiPlan::plan(
                gemini::GeminiPaths::resolve(root, root)?,
                gemini::GeminiScope::Project,
                gemini::GeminiServer::stdio(verify::MANAGED_SERVER, &executable, argv),
                existing,
            )?;
            plan.apply(existing.unwrap_or("{}"))?
        }
        detect::HostKind::Antigravity => {
            let detected =
                detect::detect_host(&detect::LocalHostProbe::for_current_process(), host);
            let floor=std::env::var("AXIOM_AGY_LAYOUT_FLOOR").ok().and_then(|v|detect::HostVersion::parse(&v)).ok_or_else(||io::error(ErrorCode::ValidationError,"agy-layout-unconfirmed","a reviewed AGY layout/version floor is required before rendering its workspace configuration"))?;
            let gate = antigravity::AgyVersionGate::certify(detected.version.as_ref(), &floor)?;
            let plan = antigravity::AgyPlan::plan(
                antigravity::AgyPaths::resolve(root, root)?,
                antigravity::AgyScope::Workspace,
                antigravity::AgyServer::stdio(verify::MANAGED_SERVER, &executable, argv),
                gate,
                existing,
            )?;
            plan.apply(existing.unwrap_or("{}"))?
        }
    };
    io::seal(
        json!({"kind":"host-config","host":host.wire(),"scope":"project","project":project,"target":target,"before_sha256":before.as_ref().map(|v|sha256_hex(v)),"after":after,"after_sha256":sha256_hex(after.as_bytes()),"mcp_command":executable,"mcp_args":args()?,"host_runtime_verified":false}),
    )
}

struct Peer {
    child: Child,
    input: ChildStdin,
    replies: mpsc::Receiver<String>,
    next_id: u64,
}
struct Transport(Mutex<Peer>);

impl Drop for Transport {
    fn drop(&mut self) {
        if let Ok(peer) = self.0.get_mut() {
            let _ = peer.child.kill();
            let _ = peer.child.wait();
        }
    }
}

impl verify::HostTransport for Transport {
    fn request(&self, method: &str, params_json: &str) -> verify::RpcResponse {
        let Ok(mut peer) = self.0.lock() else {
            return verify::RpcResponse::transport_failure("peer lock unavailable");
        };
        peer.next_id += 1;
        let id = peer.next_id;
        let mut params: Value = serde_json::from_str(params_json).unwrap_or_else(|_| json!({}));
        if method == "initialize" {
            params = json!({"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"axiom","version":crate::version::CORE_VERSION}});
        }
        if method == "tools/call" {
            if let Ok(solution) = std::env::var("AXIOM_MCP_SOLUTION") {
                params["arguments"]["solution_id"] = json!(solution);
            }
        }
        let message =
            json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}).to_string() + "\n";
        if peer
            .input
            .write_all(message.as_bytes())
            .and_then(|()| peer.input.flush())
            .is_err()
        {
            return verify::RpcResponse::transport_failure(
                "the configured MCP process did not accept the request",
            );
        }
        let deadline = Instant::now() + Duration::from_millis(verify::REQUEST_TIMEOUT_MS);
        loop {
            let Some(wait) = deadline.checked_duration_since(Instant::now()) else {
                return verify::RpcResponse::transport_failure("MCP request deadline exceeded");
            };
            match peer.replies.recv_timeout(wait) {
                Ok(body) => {
                    let parsed: Value = match serde_json::from_str(&body) {
                        Ok(v) => v,
                        Err(_) => {
                            return verify::RpcResponse::transport_failure(
                                "MCP returned malformed JSON",
                            )
                        }
                    };
                    if parsed["id"] != id {
                        continue;
                    }
                    if method == "initialize" && parsed.get("result").is_some() {
                        let _=peer.input.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\",\"params\":{}}\n");
                        let _ = peer.input.flush();
                    }
                    return verify::RpcResponse::new(200, &body);
                }
                Err(_) => {
                    return verify::RpcResponse::transport_failure(
                        "MCP request timed out or its stream closed",
                    )
                }
            }
        }
    }
}

fn verify(request: &Request) -> Result<Value, AxiomError> {
    let host = selected(request)?;
    let target = config_path(
        host,
        &std::env::current_dir().map_err(|_| {
            io::error(
                ErrorCode::NotFound,
                "project-unavailable",
                "the project directory is unavailable",
            )
        })?,
    );
    let config = io::read(&target)?;
    let program = command()?;
    let arguments = args()?;
    let text = std::str::from_utf8(&config).map_err(|_| {
        io::error(
            ErrorCode::ValidationError,
            "host-config-encoding",
            "the applied host configuration is not UTF-8",
        )
    })?;
    let expected = program.to_string_lossy();
    let matches = if host == detect::HostKind::Codex {
        let document = codex::CodexDocument::parse(text)?;
        let table = document.server(verify::MANAGED_SERVER).ok_or_else(|| {
            io::error(
                ErrorCode::NotFound,
                "host-server-missing",
                "the host has no managed MCP entry",
            )
        })?;
        codex::CodexServer::from_table(verify::MANAGED_SERVER, table)?
            == codex::CodexServer::stdio(verify::MANAGED_SERVER, &expected, arguments.clone())
    } else {
        let document: Value = serde_json::from_str(text).map_err(|_| {
            io::error(
                ErrorCode::ValidationError,
                "host-config-json",
                "the applied host configuration is invalid",
            )
        })?;
        document["mcpServers"][verify::MANAGED_SERVER]["command"] == expected.as_ref()
            && document["mcpServers"][verify::MANAGED_SERVER]["args"] == json!(arguments)
    };
    if !matches {
        return Err(io::error(
            ErrorCode::Conflict,
            "host-config-peer-mismatch",
            "the MCP command/argv does not match the applied host configuration",
        ));
    }
    let mut child = Command::new(&program)
        .args(&arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| {
            io::error(
                ErrorCode::NotFound,
                "mcp-launch",
                "the configured MCP process could not be launched",
            )
        })?;
    let input = child.stdin.take().ok_or_else(|| {
        io::error(
            ErrorCode::Internal,
            "mcp-input",
            "the MCP input stream is unavailable",
        )
    })?;
    let output = child.stdout.take().ok_or_else(|| {
        io::error(
            ErrorCode::Internal,
            "mcp-output",
            "the MCP output stream is unavailable",
        )
    })?;
    let (tx, rx) = mpsc::sync_channel(16);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(output);
        loop {
            let mut line = Vec::new();
            match reader
                .by_ref()
                .take(verify::MAX_BODY_BYTES as u64 + 1)
                .read_until(b'\n', &mut line)
            {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if line.len() > verify::MAX_BODY_BYTES {
                        let _ = tx.send("oversized".to_owned());
                        break;
                    }
                    if tx
                        .send(String::from_utf8_lossy(&line).into_owned())
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    let transport = Transport(Mutex::new(Peer {
        child,
        input,
        replies: rx,
        next_id: 0,
    }));
    let expectations = verify::VerifyExpectations {
        server_name: "axiom-mcp".to_owned(),
        tool: verify::TEST_QUERY_TOOL.to_owned(),
        test_query: std::env::var("AXIOM_MCP_QUERY")
            .unwrap_or_else(|_| "SELECT node_id FROM nodes LIMIT 1".to_owned()),
        min_records: 1,
    };
    let report = verify::verify_mcp(&transport, &expectations)?;
    if !report.is_integrated() {
        return Err(report.refusal()?);
    }
    Ok(
        json!({"host":host.wire(),"verification_scope":"configured-gateway-round-trip","host_runtime_verified":false,"config_sha256":sha256_hex(&config),"mcp":report.render_json()}),
    )
}

/// Preview, apply or verify a real project-scoped host configuration.
pub fn run(request: &Request) -> Result<Value, AxiomError> {
    if request.form == "host verify" {
        return verify(request);
    }
    if let Some(path) = io::argument(request, "--plan") {
        if request.flags.contains("--dry-run") {
            return Err(io::error(
                ErrorCode::ValidationError,
                "host-apply-mode",
                "--dry-run cannot apply a --plan",
            ));
        }
        let plan = io::read_json(Path::new(path))?;
        io::approved(&plan, io::argument(request, "--approve-digest"))?;
        if plan["kind"] != "host-config" || plan["host"] != selected(request)?.wire() {
            return Err(io::error(
                ErrorCode::Forbidden,
                "host-plan-scope",
                "the plan belongs to another host",
            ));
        }
        let fresh = preview(request)?;
        if fresh["project"] == plan["project"]
            && fresh["target"] == plan["target"]
            && fresh["mcp_command"] == plan["mcp_command"]
            && fresh["mcp_args"] == plan["mcp_args"]
            && fresh["before_sha256"] == plan["after_sha256"]
        {
            return Ok(
                json!({"status":"already-configured","host":plan["host"],"host_runtime_verified":false}),
            );
        }
        if fresh != plan {
            return Err(io::error(
                ErrorCode::Conflict,
                "host-plan-stale",
                "the host configuration or MCP command changed after planning",
            ));
        }
        let target = PathBuf::from(plan["target"].as_str().unwrap_or_default());
        let lock_root = io::install_root()?;
        io::no_links(&lock_root)?;
        std::fs::create_dir_all(&lock_root).map_err(|_| {
            io::error(
                ErrorCode::Forbidden,
                "host-lock-root",
                "the private lock directory cannot be created",
            )
        })?;
        let _guard = crate::install::ecosystem_uninstall::maintenance_lock(&lock_root)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|_| {
                io::error(
                    ErrorCode::Forbidden,
                    "host-config-directory",
                    "the host configuration directory cannot be created",
                )
            })?;
        }
        let mut temporary = tempfile::NamedTempFile::new_in(
            target.parent().unwrap_or(Path::new(".")),
        )
        .map_err(|_| {
            io::error(
                ErrorCode::Internal,
                "host-config-stage",
                "the host configuration cannot be staged",
            )
        })?;
        temporary
            .write_all(plan["after"].as_str().unwrap_or_default().as_bytes())
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|_| {
                io::error(
                    ErrorCode::Internal,
                    "host-config-write",
                    "the staged configuration cannot be synchronized",
                )
            })?;
        axiom_platform::atomic_file::replace(temporary.path(), &target).map_err(|_| {
            io::error(
                ErrorCode::Conflict,
                "host-config-replace",
                "the existing configuration could not be atomically replaced",
            )
        })?;
        return Ok(
            json!({"status":"applied","host":plan["host"],"scope":"project","config_sha256":plan["after_sha256"],"host_runtime_verified":false}),
        );
    }
    io::emit(request, preview(request)?)
}
