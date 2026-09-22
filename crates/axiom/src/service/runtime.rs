//! Concrete per-user service composition for the installed core.

use std::path::{Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::PathEnvironment;
use serde_json::{json, Value};

use super::{control, macos, owned_state, startup, Consent, ServiceExec, SysExec};

/// Run a service verb against state owned by `root`.
pub fn run(action: &str, component: &str, user: bool, root: &Path) -> Result<Value, AxiomError> {
    let _guard = if action == "status" {
        None
    } else {
        Some(crate::install::ecosystem_uninstall::maintenance_lock(root)?)
    };
    run_with_exec(action, component, user, root, &SysExec)
}

/// Injectable runtime seam used by tests; the production entrypoint uses [`SysExec`].
pub fn run_with_exec(
    action: &str,
    component: &str,
    user: bool,
    root: &Path,
    exec: &impl ServiceExec,
) -> Result<Value, AxiomError> {
    let (uid, home) = current_identity()?;
    let identity = macos::LaunchdIdentity::new(uid)?;
    match action {
        "install" => {
            if !user {
                return Err(AxiomError::new(
                    ErrorCode::Forbidden,
                    "service install requires explicit --user",
                ));
            }
            let executable = active_graphd(root)?;
            let request = macos::MacosServiceRequest::new(
                component,
                &executable,
                root.to_string_lossy(),
                root.to_string_lossy(),
                home.to_string_lossy(),
            );
            let agent = macos::plan_agent(&request)?;
            // A label is global to the GUI domain. Refuse before writing when
            // anything already owns the canonical label, even at another path.
            let existing_label =
                exec.run(&macos::status_operation_for_user(&agent.label, identity)?)?;
            if existing_label.code == 0 && owned_state::read_with_home(root, uid, &home).is_err() {
                return Err(AxiomError::new(
                    ErrorCode::Conflict,
                    "the canonical LaunchAgent label is already registered",
                ));
            }
            if std::fs::symlink_metadata(&agent.plist_path).is_ok() {
                let existing = owned_state::read_with_home(root, uid, &home).map_err(|_| {
                    AxiomError::new(
                        ErrorCode::Conflict,
                        "existing LaunchAgent definition is not owned by this install",
                    )
                })?;
                if existing.installed.definition_path != agent.plist_path {
                    return Err(AxiomError::new(
                        ErrorCode::Conflict,
                        "existing LaunchAgent definition belongs to another component",
                    ));
                }
            }
            let registration = startup::StartupRegistration::for_agent_with_identity(
                &agent,
                &home.to_string_lossy(),
                identity,
            )?;
            let outcome = startup::ensure_registered(
                &registration,
                Consent::explicit(),
                &startup::BackendSupport::available(),
                &startup::SysDefinitions,
                exec,
            )?;
            if let Some(installed) = outcome.installed() {
                let bytes = std::fs::read(&installed.definition_path).map_err(io)?;
                let state = owned_state::OwnedServiceState::new(
                    installed.clone(),
                    uid,
                    graph_export::sha256_hex(&bytes),
                    graph_export::sha256_hex(&std::fs::read(root.join("current")).map_err(io)?),
                )?;
                if let Err(error) = owned_state::write(root, &state) {
                    let _ =
                        startup::remove_registered(&registration, &startup::SysDefinitions, exec);
                    return Err(error);
                }
            }
            Ok(serde_json::to_value(outcome).map_err(|_| {
                AxiomError::new(ErrorCode::Internal, "service result serialization failed")
            })?)
        }
        "start" | "stop" | "status" => {
            let state = owned_state::read_with_home(root, uid, &home)?;
            if state.generation
                != graph_export::sha256_hex(&std::fs::read(root.join("current")).map_err(io)?)
            {
                return Err(AxiomError::new(
                    ErrorCode::Conflict,
                    "owned service state names a different active generation",
                ));
            }
            if state.installed.component != component {
                return Err(AxiomError::new(
                    ErrorCode::Forbidden,
                    "service component is not owned by this state",
                ));
            }
            let action = control::ControlAction::parse(action)?;
            let ownership = control::ServiceOwnership::claim(
                &state.installed,
                &control::ControlRoots::new(root.to_string_lossy(), home.to_string_lossy()),
            )?;
            let operation = match action {
                control::ControlAction::Start => {
                    macos::kickstart_operation(&ownership.owned_name, identity)?
                }
                control::ControlAction::Stop => {
                    macos::kill_operation(&ownership.owned_name, identity)?
                }
                control::ControlAction::Status => {
                    macos::status_operation_for_user(&ownership.owned_name, identity)?
                }
            };
            let output = exec.run(&operation)?;
            if output.code != 0 {
                return Err(AxiomError::new(
                    ErrorCode::Internal,
                    "launchctl refused service control",
                )
                .with_detail("code", output.code.to_string())
                .with_detail("stderr", output.stderr));
            }
            Ok(
                json!({"component": component, "action": action.as_str(), "code": output.code, "stdout": output.stdout, "stderr": output.stderr}),
            )
        }
        "uninstall" => remove_with_exec(root, exec),
        _ => Err(AxiomError::new(
            ErrorCode::ValidationError,
            "unknown service action",
        )),
    }
}

/// Remove the owned registration, without touching a foreign service.
pub fn remove(root: &Path) -> Result<(), AxiomError> {
    remove_with_exec(root, &SysExec).map(|_| ())
}

fn remove_with_exec(root: &Path, exec: &impl ServiceExec) -> Result<Value, AxiomError> {
    let (uid, home) = current_identity()?;
    let state = match owned_state::read_record(root, uid, &home) {
        Ok(state) => state,
        Err(error) if error.code() == ErrorCode::NotFound => {
            let label = macos::agent_label("axiom-graphd")?;
            let plist = home
                .join("Library/LaunchAgents")
                .join(format!("{label}.plist"));
            let status = exec.run(&macos::status_operation_for_user(
                &label,
                macos::LaunchdIdentity::new(uid)?,
            )?)?;
            if plist.exists() || status.code == 0 {
                return Err(AxiomError::new(
                    ErrorCode::Conflict,
                    "missing service state cannot authorize an existing LaunchAgent",
                ));
            }
            if status.code != 113 {
                return Err(AxiomError::new(
                    ErrorCode::Internal,
                    "launchctl could not verify absent service",
                )
                .with_detail("code", status.code.to_string()));
            }
            return Ok(json!({"already_removed": {"component":"axiom-graphd"}}));
        }
        Err(error) => return Err(error),
    };
    let definition_missing = match std::fs::read(&state.installed.definition_path) {
        Ok(bytes) if graph_export::sha256_hex(&bytes) == state.definition_sha256 => false,
        Ok(_) => {
            return Err(AxiomError::new(
                ErrorCode::Conflict,
                "owned service definition changed",
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => return Err(io(error)),
    };
    let identity = macos::LaunchdIdentity::new(uid)?;
    let agent = macos::LaunchAgent {
        component: state.installed.component.clone(),
        label: state.installed.task_name.clone(),
        mechanism: state.installed.mechanism,
        scope: state.installed.scope,
        trigger: super::StartupTrigger::Logon,
        restart: state.installed.restart,
        executable: String::new(),
        args: vec![],
        working_directory: root.to_string_lossy().into_owned(),
        log_file: state.installed.log_file.clone(),
        plist_path: state.installed.definition_path.clone(),
        plist: std::fs::read_to_string(&state.installed.definition_path).unwrap_or_default(),
    };
    let registration = startup::StartupRegistration::for_agent_with_identity(
        &agent,
        &home.to_string_lossy(),
        identity,
    )?;
    if definition_missing {
        let status = exec.run(&macos::status_operation_for_user(&agent.label, identity)?)?;
        if status.code == 0 {
            let operation = macos::bootout_target_operation(&agent.label, identity)?;
            let output = exec.run(&operation)?;
            if output.code != 0 {
                return Err(AxiomError::new(
                    ErrorCode::Internal,
                    "launchctl refused owned service bootout",
                ));
            }
        } else if status.code != 113 {
            return Err(AxiomError::new(
                ErrorCode::Internal,
                "launchctl could not verify missing owned service",
            ));
        }
    }
    let outcome = if std::path::Path::new(&state.installed.definition_path).exists() {
        startup::remove_registered(&registration, &startup::SysDefinitions, exec)?
    } else {
        startup::RemovalOutcome::AlreadyRemoved {
            component: state.installed.component.clone(),
            mechanism: state.installed.mechanism,
        }
    };
    let path = owned_state::state_path(root);
    std::fs::remove_file(path).map_err(io)?;
    serde_json::to_value(outcome)
        .map_err(|_| AxiomError::new(ErrorCode::Internal, "service result serialization failed"))
}

fn active_graphd(root: &Path) -> Result<String, AxiomError> {
    let pointer = root.join("current");
    let value: Value = serde_json::from_slice(&std::fs::read(&pointer).map_err(io)?)
        .map_err(|_| AxiomError::new(ErrorCode::ConfigInvalid, "active core pointer is invalid"))?;
    if value.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err(AxiomError::new(
            ErrorCode::ConfigInvalid,
            "active core pointer schema is unsupported",
        ));
    }
    let activated = value
        .get("activated")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            AxiomError::new(
                ErrorCode::ConfigInvalid,
                "active core pointer has no activated artifacts",
            )
        })?;
    let matches: Vec<&Value> = activated
        .iter()
        .filter(|item| {
            item.get("artifact")
                .and_then(Value::as_str)
                .and_then(|path| Path::new(path).file_name())
                .and_then(|name| name.to_str())
                == Some("axiom-graphd")
        })
        .collect();
    if matches.len() != 1 {
        return Err(AxiomError::new(
            ErrorCode::ConfigInvalid,
            "active core pointer does not identify one graph daemon executable",
        ));
    }
    let artifact = matches[0];
    let destination = artifact
        .get("destination")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AxiomError::new(
                ErrorCode::ConfigInvalid,
                "activated graph daemon has no destination",
            )
        })?;
    let expected = artifact
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AxiomError::new(
                ErrorCode::ConfigInvalid,
                "activated graph daemon has no digest",
            )
        })?;
    let path = PathBuf::from(destination);
    if std::fs::symlink_metadata(&path)
        .map_err(io)?
        .file_type()
        .is_symlink()
    {
        return Err(AxiomError::new(
            ErrorCode::Forbidden,
            "activated graph daemon symlink is refused",
        ));
    }
    let canonical_root = root.canonicalize().map_err(io)?;
    let canonical = path.canonicalize().map_err(io)?;
    if !canonical.starts_with(canonical_root.join("versions")) || !canonical.is_file() {
        return Err(AxiomError::new(
            ErrorCode::Forbidden,
            "active core executable escapes versions root",
        ));
    }
    if graph_export::sha256_hex(&std::fs::read(&canonical).map_err(io)?) != expected {
        return Err(AxiomError::new(
            ErrorCode::Conflict,
            "activated graph daemon digest changed",
        ));
    }
    Ok(canonical.to_string_lossy().into_owned())
}

fn current_identity() -> Result<(u32, PathBuf), AxiomError> {
    let output = std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .map_err(io)?;
    let uid = std::str::from_utf8(&output.stdout)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .ok_or_else(|| AxiomError::new(ErrorCode::Internal, "could not read effective user id"))?;
    let home = PathEnvironment::for_current_process()
        .home_dir
        .ok_or_else(|| {
            AxiomError::new(
                ErrorCode::ConfigInvalid,
                "HOME is required for per-user service management",
            )
        })?;
    Ok((uid, PathBuf::from(home)))
}
fn io(error: std::io::Error) -> AxiomError {
    let code = if error.kind() == std::io::ErrorKind::NotFound {
        ErrorCode::NotFound
    } else {
        ErrorCode::Internal
    };
    AxiomError::new(code, "service runtime I/O failed").with_detail("observed", error.to_string())
}

#[cfg(test)]
mod tests {
    use super::active_graphd;
    use graph_export::sha256_hex;
    use std::fs;

    fn pointer(destination: &std::path::Path, digest: &str) -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "plan_id": "plan",
            "plan_digest": "a".repeat(64),
            "transaction_id": "tx",
            "applied_at": "2026-09-22T00:00:00Z",
            "activated": [{
                "component": "axiom-graphd",
                "version": "1.0.0",
                "artifact": "bin/axiom-graphd",
                "sha256": digest,
                "destination": destination,
                "already_present": false
            }]
        })
    }

    #[test]
    fn activated_pointer_selects_and_hash_verifies_the_daemon_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("install");
        let binary = root.join("versions/core/1.0.0/axiom-graphd");
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        fs::write(&binary, b"daemon").unwrap();
        let value = pointer(&binary, &sha256_hex(b"daemon"));
        fs::write(root.join("current"), serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            active_graphd(&root).unwrap(),
            binary.canonicalize().unwrap().to_string_lossy()
        );
    }

    #[test]
    fn activated_pointer_refuses_a_digest_mismatch_or_non_unique_daemon() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("install");
        let binary = root.join("versions/core/1.0.0/axiom-graphd");
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        fs::write(&binary, b"daemon").unwrap();
        let bad = pointer(&binary, &"0".repeat(64));
        fs::write(root.join("current"), serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(active_graphd(&root).is_err());
    }
}
