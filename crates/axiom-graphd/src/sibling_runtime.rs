//! Delegate updates to the same-release sibling executable, never PATH or a shell.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use graph_core::error::{AxiomError, ErrorCode};
use serde_json::Value;

use crate::cli::UpdateCommand;

fn error(code: ErrorCode, rule: &str) -> AxiomError {
    AxiomError::new(code, rule).with_detail("rule", rule)
}

fn launch(program: &std::path::Path, args: &[String], seconds: u64) -> Result<Value, AxiomError> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| error(ErrorCode::NotFound, "trusted-sibling-launch"))?;
    let output = child
        .stdout
        .take()
        .ok_or_else(|| error(ErrorCode::Internal, "sibling-output"))?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = output.take(1024 * 1024 + 1).read_to_end(&mut bytes);
        let _ = tx.send(bytes);
    });
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| error(ErrorCode::Internal, "sibling-status"))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error(
                ErrorCode::WorktreeBusy,
                "sibling-timeout-state-unknown",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let bytes = rx
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| error(ErrorCode::Internal, "sibling-output-timeout"))?;
    if bytes.len() > 1024 * 1024 {
        return Err(error(ErrorCode::ValidationError, "sibling-output-limit"));
    }
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| error(ErrorCode::ValidationError, "sibling-output-json"))?;
    if !status.success() {
        let code = match status.code() {
            Some(2) => ErrorCode::ValidationError,
            Some(3) => ErrorCode::NotFound,
            Some(4) => ErrorCode::NotReady,
            Some(5) => ErrorCode::Forbidden,
            Some(6) => ErrorCode::Conflict,
            Some(9) => ErrorCode::IncompatibleInput,
            _ => ErrorCode::Internal,
        };
        return Err(error(code, "trusted-sibling-refused")
            .with_detail("sibling_code", value["code"].as_str().unwrap_or("unknown")));
    }
    Ok(value)
}

/// Execute an approved update through the installed sibling's own unchanged verifier.
pub fn run(command: &UpdateCommand) -> Result<Value, AxiomError> {
    let own =
        std::env::current_exe().map_err(|_| error(ErrorCode::NotFound, "current-executable"))?;
    let sibling = own.with_file_name(if cfg!(windows) { "axiom.exe" } else { "axiom" });
    axiom_platform::atomic_file::reject_links(&sibling)
        .map_err(|_| error(ErrorCode::Forbidden, "unsafe-sibling"))?;
    let version = launch(&sibling, &["version".to_owned(), "--json".to_owned()], 10)?;
    if version["component"] != "axiom"
        || version["version"] != env!("CARGO_PKG_VERSION")
        || version["build_revision"] != crate::version::BUILD_REVISION
        || version["control_api"] != crate::version::CONTROL_API_VERSION
    {
        return Err(error(ErrorCode::IncompatibleInput, "sibling-core-identity"));
    }
    let mut args = vec!["update".to_owned()];
    match command {
        UpdateCommand::Check => args.push("check".to_owned()),
        UpdateCommand::Apply {
            plan,
            approve_digest,
        } => {
            let approval = approve_digest
                .as_deref()
                .ok_or_else(|| error(ErrorCode::Forbidden, "update-approval-required"))?;
            axiom_platform::atomic_file::reject_links(plan)
                .map_err(|_| error(ErrorCode::Forbidden, "unsafe-update-plan"))?;
            let raw = std::fs::read(plan)
                .map_err(|_| error(ErrorCode::NotFound, "update-plan-missing"))?;
            if raw.len() > 16 * 1024 * 1024 {
                return Err(error(ErrorCode::ValidationError, "update-plan-limit"));
            }
            let document: Value = serde_json::from_slice(&raw)
                .map_err(|_| error(ErrorCode::ValidationError, "update-plan-json"))?;
            if document["plan_digest"].as_str() != Some(approval) {
                return Err(error(ErrorCode::Forbidden, "update-approval-stale"));
            }
            args.extend([
                "apply".to_owned(),
                "--plan".to_owned(),
                plan.to_string_lossy().into_owned(),
                "--approve-digest".to_owned(),
                approval.to_owned(),
            ]);
            // The sibling re-verifies the entire plan, hashes, trust and approval
            // before mutation; this adapter never invents a configured trust root.
        }
    }
    args.push("--json".to_owned());
    launch(&sibling, &args, 120)
}
