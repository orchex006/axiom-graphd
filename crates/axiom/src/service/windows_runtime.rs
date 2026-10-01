//! Public Windows `axiom service` verbs over the owned per-user Task Scheduler adapter.

use std::io::Write;
use std::path::{Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};
use serde_json::{json, Value};

use super::{control, startup, windows, windows_state, Consent, ServiceExec, SysExec};

/// Task Scheduler imports UTF-16 XML with a BOM. The shared startup lifecycle
/// compares decoded definitions as text; this Windows ledger encodes at the
/// filesystem boundary and never replaces an existing unowned file.
struct WindowsDefinitions;

impl startup::DefinitionLedger for WindowsDefinitions {
    fn read(&self, path: &str) -> Result<Option<String>, AxiomError> {
        let path = Path::new(path);
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io(error)),
        };
        if path.is_symlink() || !bytes.starts_with(&[0xff, 0xfe]) || bytes.len() % 2 != 0 {
            return Err(refuse(
                ErrorCode::Forbidden,
                "linked or malformed Windows task definition",
            ));
        }
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let text = String::from_utf16(&units).map_err(|_| {
            refuse(
                ErrorCode::ValidationError,
                "Windows task definition is not UTF-16",
            )
        })?;
        Ok(Some(text))
    }

    fn write(&self, path: &str, text: &str) -> Result<(), AxiomError> {
        let path = Path::new(path);
        if path.exists() || path.is_symlink() {
            return Err(refuse(
                ErrorCode::Conflict,
                "Windows task definition is already occupied",
            ));
        }
        let mut bytes = vec![0xff, 0xfe];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(io)?;
        file.write_all(&bytes).map_err(io)?;
        file.sync_all().map_err(io)
    }

    fn remove(&self, path: &str) -> Result<(), AxiomError> {
        let path = Path::new(path);
        if path.is_symlink() {
            return Err(refuse(
                ErrorCode::Forbidden,
                "linked Windows task definition",
            ));
        }
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io(error)),
        }
    }
}

fn io(error: std::io::Error) -> AxiomError {
    let code = if error.kind() == std::io::ErrorKind::NotFound {
        ErrorCode::NotFound
    } else {
        ErrorCode::Internal
    };
    AxiomError::new(code, "Windows service runtime I/O failed")
        .with_detail("observed", error.to_string())
}

fn refuse(code: ErrorCode, message: &str) -> AxiomError {
    AxiomError::new(code, message)
}

fn home(root: &Path) -> Result<PathBuf, AxiomError> {
    if !root.is_absolute()
        || root.file_name().and_then(|n| n.to_str()) != Some("ecosystem")
        || root
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            != Some("installs")
    {
        return Err(refuse(
            ErrorCode::ValidationError,
            "service root is not one ecosystem install",
        ));
    }
    let home = root
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| refuse(ErrorCode::ValidationError, "service root has no Axiom home"))?;
    for path in [home, root.parent().unwrap(), root] {
        let metadata = std::fs::symlink_metadata(path).map_err(io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(refuse(
                ErrorCode::Forbidden,
                "linked or non-directory service root",
            ));
        }
    }
    Ok(home.to_path_buf())
}

fn generation(root: &Path) -> Result<String, AxiomError> {
    Ok(graph_export::sha256_hex(
        &std::fs::read(root.join("current")).map_err(io)?,
    ))
}

/// Read the real token user's SID using a program/argv boundary. The second
/// CSV field is the SID; the localized display name is never interpreted.
fn current_sid() -> Result<String, AxiomError> {
    let system_root = std::env::var_os("SystemRoot").ok_or_else(|| {
        refuse(
            ErrorCode::ConfigInvalid,
            "SystemRoot is required for user identity",
        )
    })?;
    let program = Path::new(&system_root).join("System32/whoami.exe");
    if !program.is_file() || program.is_symlink() {
        return Err(refuse(
            ErrorCode::ConfigInvalid,
            "native user identity program is unavailable",
        ));
    }
    let output = std::process::Command::new(&program)
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .map_err(io)?;
    if !output.status.success() {
        return Err(refuse(
            ErrorCode::Internal,
            "native user identity command failed",
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let found: Vec<&str> = text
        .split([',', '"', '\r', '\n', ' ', '\t'])
        .filter(|part| windows::valid_user_sid(part))
        .collect();
    if found.len() != 1 {
        return Err(refuse(
            ErrorCode::Internal,
            "native user SID is missing or ambiguous",
        ));
    }
    Ok(found[0].to_owned())
}

fn task_status(exec: &impl ServiceExec, name: &str) -> Result<Option<Value>, AxiomError> {
    let output = exec.run(&windows::status_operation(name)?)?;
    match output.code {
        0 => Ok(Some(
            json!({"code":0,"stdout":output.stdout,"stderr":output.stderr}),
        )),
        1 => Ok(None),
        code => Err(refuse(
            ErrorCode::Internal,
            "Task Scheduler status could not be verified",
        )
        .with_detail("code", code.to_string())),
    }
}

fn registered_fingerprint(
    exec: &impl ServiceExec,
    name: &str,
) -> Result<Option<String>, AxiomError> {
    let output = exec.run(&windows::export_operation(name)?)?;
    match output.code {
        0 if !output.stdout.is_empty() && !output.stdout.contains('\u{fffd}') => {
            Ok(Some(graph_export::sha256_hex(output.stdout.as_bytes())))
        }
        0 => Err(refuse(
            ErrorCode::ConfigInvalid,
            "registered Windows task XML could not be read without loss",
        )),
        1 => Ok(None),
        code => Err(refuse(
            ErrorCode::Internal,
            "Task Scheduler XML could not be verified",
        )
        .with_detail("code", code.to_string())),
    }
}

fn verify_registered(
    state: &windows_state::WindowsOwnedState,
    exec: &impl ServiceExec,
) -> Result<(), AxiomError> {
    if registered_fingerprint(exec, &state.installed.task_name)?.as_deref()
        != Some(&state.registered_sha256)
    {
        return Err(refuse(
            ErrorCode::Conflict,
            "registered Windows task differs from its owned definition",
        ));
    }
    Ok(())
}

fn rollback_new_registration(
    registration: &startup::StartupRegistration,
    task_name: &str,
    had_state: bool,
    exec: &impl ServiceExec,
    cause: AxiomError,
) -> AxiomError {
    let cleanup = if had_state {
        windows::uninstall_operation(task_name).and_then(|operation| {
            let output = exec.run(&operation)?;
            if output.code == 0 {
                Ok(())
            } else {
                Err(refuse(
                    ErrorCode::Internal,
                    "Task Scheduler refused rollback of a new registration",
                ))
            }
        })
    } else {
        startup::remove_registered(registration, &WindowsDefinitions, exec).map(|_| ())
    };
    match cleanup {
        Ok(()) => cause,
        Err(error) => refuse(
            ErrorCode::Internal,
            "Windows service registration failed and rollback is incomplete",
        )
        .with_detail("original", cause.to_string())
        .with_detail("cleanup", error.to_string()),
    }
}

fn checked_state(
    root: &Path,
    sid: &str,
    home: &Path,
) -> Result<windows_state::WindowsOwnedState, AxiomError> {
    let state = windows_state::read_with_definition(root, sid, home)?;
    if state.generation != generation(root)? {
        return Err(refuse(
            ErrorCode::Conflict,
            "owned Windows service targets a stale core generation",
        ));
    }
    Ok(state)
}

fn install(
    component: &str,
    user: bool,
    root: &Path,
    home: &Path,
    sid: &str,
    exec: &impl ServiceExec,
) -> Result<Value, AxiomError> {
    if !user {
        return Err(refuse(
            ErrorCode::Forbidden,
            "service install requires explicit --user",
        ));
    }
    let executable = super::runtime::active_graphd(root)?;
    let request = windows::WindowsServiceRequest::new(
        component,
        &executable,
        root.to_string_lossy(),
        root.to_string_lossy(),
    )
    .with_user_sid(sid)
    .with_args(vec![
        "serve".to_owned(),
        "--axiom-home".to_owned(),
        home.to_string_lossy().into_owned(),
    ]);
    let definition = windows::plan_task(&request)?;
    let registration =
        startup::StartupRegistration::for_task(&definition, &root.to_string_lossy())?;
    let record_path = windows_state::state_path(root);
    let prior = if record_path.exists() || record_path.is_symlink() {
        Some(checked_state(root, sid, home)?)
    } else {
        None
    };
    if let Some(state) = &prior {
        if state.installed != registration.installed_service()
            || startup::DefinitionLedger::read(&WindowsDefinitions, &definition.definition_path)?
                != Some(definition.xml.clone())
        {
            return Err(refuse(
                ErrorCode::Conflict,
                "owned Windows service definition differs from the planned generation",
            ));
        }
    }
    let observed = match task_status(exec, &definition.task_name) {
        Ok(status) => status,
        Err(error) if error.code() == ErrorCode::Internal && prior.is_none() => {
            let fallback = startup::ensure_registered(
                &registration,
                Consent::explicit(),
                &startup::BackendSupport::unsupported("scheduler-unavailable", error.to_string()),
                &WindowsDefinitions,
                exec,
            )?;
            return serde_json::to_value(fallback).map_err(|_| {
                refuse(
                    ErrorCode::Internal,
                    "service fallback result serialization failed",
                )
            });
        }
        Err(error) => return Err(error),
    };
    if observed.is_some() && prior.is_none() {
        return Err(refuse(
            ErrorCode::Conflict,
            "an unowned Windows task already has the canonical name",
        ));
    }
    if observed.is_some() {
        if let Some(state) = &prior {
            verify_registered(state, exec)?;
        }
    }
    if prior.is_none()
        && (Path::new(&definition.definition_path).exists()
            || Path::new(&definition.definition_path).is_symlink())
    {
        return Err(refuse(
            ErrorCode::Conflict,
            "an unowned Windows task definition already exists",
        ));
    }
    let service_dir = root.join("service");
    match std::fs::symlink_metadata(&service_dir) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
            return Err(refuse(
                ErrorCode::Forbidden,
                "linked or foreign service definition directory",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&service_dir).map_err(io)?;
        }
        Err(error) => return Err(io(error)),
    }
    let outcome = startup::ensure_registered(
        &registration,
        Consent::explicit(),
        &if observed.is_some() {
            startup::BackendSupport::registered()
        } else {
            startup::BackendSupport::available()
        },
        &WindowsDefinitions,
        exec,
    );
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            if prior.is_none()
                && matches!(task_status(exec, &definition.task_name), Ok(None))
                && matches!(
                    startup::DefinitionLedger::read(
                        &WindowsDefinitions,
                        &definition.definition_path
                    ),
                    Ok(Some(ref text)) if text == &definition.xml
                )
            {
                startup::DefinitionLedger::remove(
                    &WindowsDefinitions,
                    &definition.definition_path,
                )?;
            }
            return Err(error);
        }
    };
    let freshly_registered = matches!(&outcome, startup::RegistrationOutcome::Registered(_));
    let fingerprint = match registered_fingerprint(exec, &definition.task_name) {
        Ok(Some(value)) => value,
        Ok(None) => {
            let error = refuse(
                ErrorCode::Conflict,
                "registered Windows task vanished before ownership was recorded",
            );
            return Err(if freshly_registered {
                rollback_new_registration(
                    &registration,
                    &definition.task_name,
                    prior.is_some(),
                    exec,
                    error,
                )
            } else {
                error
            });
        }
        Err(error) => {
            return Err(if freshly_registered {
                rollback_new_registration(
                    &registration,
                    &definition.task_name,
                    prior.is_some(),
                    exec,
                    error,
                )
            } else {
                error
            });
        }
    };
    if prior.is_none() {
        let Some(installed) = outcome.installed() else {
            return Err(refuse(
                ErrorCode::Internal,
                "Windows service registration has no owned state",
            ));
        };
        let state = (|| {
            let bytes = std::fs::read(&installed.definition_path).map_err(io)?;
            windows_state::WindowsOwnedState::new(
                installed.clone(),
                sid.to_owned(),
                graph_export::sha256_hex(&bytes),
                fingerprint,
                generation(root)?,
            )
        })();
        let written = state.and_then(|state| windows_state::write(root, &state));
        if let Err(error) = written {
            return Err(rollback_new_registration(
                &registration,
                &definition.task_name,
                false,
                exec,
                error,
            ));
        }
    } else if prior
        .as_ref()
        .is_some_and(|state| state.registered_sha256 != fingerprint)
    {
        return Err(refuse(
            ErrorCode::Conflict,
            "repaired Windows task differs from owned registration",
        ));
    }
    serde_json::to_value(outcome)
        .map_err(|_| refuse(ErrorCode::Internal, "service result serialization failed"))
}

pub fn run_with_identity(
    action: &str,
    component: &str,
    user: bool,
    root: &Path,
    sid: &str,
    exec: &impl ServiceExec,
) -> Result<Value, AxiomError> {
    if component != "axiom-graphd" {
        return Err(refuse(
            ErrorCode::ValidationError,
            "this service is not a graph daemon",
        ));
    }
    if !windows::valid_user_sid(sid) {
        return Err(refuse(
            ErrorCode::Forbidden,
            "current Windows token SID is invalid",
        ));
    }
    let home = home(root)?;
    match action {
        "install" => install(component, user, root, &home, sid, exec),
        "start" | "stop" | "status" => {
            let state = checked_state(root, sid, &home)?;
            verify_registered(&state, exec)?;
            let ownership = control::ServiceOwnership::claim(
                &state.installed,
                &control::ControlRoots::new(root.to_string_lossy(), home.to_string_lossy()),
            )?;
            let action = control::ControlAction::parse(action)?;
            let operation = control::plan_control(&ownership, action)?;
            let output = exec.run(&operation.operations[0])?;
            if output.code != 0 {
                return Err(refuse(
                    ErrorCode::Internal,
                    "Task Scheduler refused owned service control",
                )
                .with_detail("code", output.code.to_string())
                .with_detail("stderr", output.stderr));
            }
            Ok(json!({"component":component,"action":action.as_str(),
                      "code":output.code,"stdout":output.stdout,"stderr":output.stderr}))
        }
        "uninstall" => remove_with_identity(root, sid, exec),
        _ => Err(refuse(ErrorCode::ValidationError, "unknown service action")),
    }
}

pub fn run_with_exec(
    action: &str,
    component: &str,
    user: bool,
    root: &Path,
    exec: &impl ServiceExec,
) -> Result<Value, AxiomError> {
    let sid = current_sid()?;
    run_with_identity(action, component, user, root, &sid, exec)
}

fn remove_with_identity(
    root: &Path,
    sid: &str,
    exec: &impl ServiceExec,
) -> Result<Value, AxiomError> {
    let home = home(root)?;
    let name = windows::task_name("axiom-graphd")?;
    let path = windows_state::state_path(root);
    if !path.exists() && !path.is_symlink() {
        if task_status(exec, &name)?.is_some() {
            return Err(refuse(
                ErrorCode::Conflict,
                "missing ownership cannot remove an existing Windows task",
            ));
        }
        return Ok(json!({"already_removed":{"component":"axiom-graphd"}}));
    }
    let state = windows_state::read_record(root, sid, &home)?;
    if state.generation != generation(root)? {
        return Err(refuse(
            ErrorCode::Conflict,
            "owned Windows service targets a stale core generation",
        ));
    }
    let definition = Path::new(&state.installed.definition_path);
    let bytes = match std::fs::read(definition) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(io(error)),
    };
    if bytes
        .as_ref()
        .is_some_and(|body| graph_export::sha256_hex(body) != state.definition_sha256)
    {
        return Err(refuse(
            ErrorCode::Conflict,
            "owned Windows task definition changed",
        ));
    }
    let present = task_status(exec, &name)?.is_some();
    if present {
        verify_registered(&state, exec)?;
    }
    if present {
        // A stopped task returns a non-zero `/end`; deleting its exact owned
        // name is still safe and removes the per-user registration.
        let _ = exec.run(&windows::stop_operation(&name)?);
        let deleted = exec.run(&windows::uninstall_operation(&name)?)?;
        if deleted.code != 0 {
            return Err(refuse(
                ErrorCode::Internal,
                "Task Scheduler refused owned service removal",
            )
            .with_detail("code", deleted.code.to_string()));
        }
    }
    if bytes.is_some() {
        std::fs::remove_file(definition).map_err(io)?;
    }
    std::fs::remove_file(path).map_err(io)?;
    Ok(json!({"component":"axiom-graphd","removed":present,"definition_removed":bytes.is_some()}))
}

pub fn remove_with_exec(root: &Path, exec: &impl ServiceExec) -> Result<Value, AxiomError> {
    let sid = current_sid()?;
    remove_with_identity(root, &sid, exec)
}

pub fn remove(root: &Path) -> Result<(), AxiomError> {
    remove_with_exec(root, &SysExec).map(|_| ())
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::service::{ServiceOperation, ServiceOutput};

    const SID: &str = "S-1-5-21-100-200-300-1001";

    #[derive(Default)]
    struct Scheduler {
        registered: Cell<bool>,
        tampered: Cell<bool>,
        fail_register: Cell<bool>,
        fail_export: Cell<bool>,
        unavailable: Cell<bool>,
        actions: RefCell<Vec<String>>,
    }

    impl ServiceExec for Scheduler {
        fn run(&self, operation: &ServiceOperation) -> Result<ServiceOutput, AxiomError> {
            self.actions
                .borrow_mut()
                .push(operation.description.clone());
            if self.unavailable.get() {
                return Err(AxiomError::new(
                    ErrorCode::Internal,
                    "scheduler unavailable",
                ));
            }
            let (code, stdout) = match operation.description.as_str() {
                "status" if self.registered.get() => (0, "Ready"),
                "status" => (1, ""),
                "export" if self.registered.get() && self.tampered.get() => {
                    (0, "<Task>foreign</Task>")
                }
                "export" if self.registered.get() && self.fail_export.get() => (1, ""),
                "export" if self.registered.get() => (0, "<Task>owned</Task>"),
                "export" => (1, ""),
                "register" if self.fail_register.get() => (1, ""),
                "register" => {
                    self.registered.set(true);
                    (0, "registered")
                }
                "uninstall" => {
                    self.registered.set(false);
                    (0, "removed")
                }
                "start" | "stop" if self.registered.get() => (0, "controlled"),
                _ => (1, ""),
            };
            Ok(ServiceOutput {
                code,
                stdout: stdout.to_owned(),
                stderr: String::new(),
            })
        }
    }

    fn installed_root(temp: &Path) -> PathBuf {
        let root = temp.join("home/installs/ecosystem");
        let binary = root.join("versions/0.1.2/bin/axiom-graphd");
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, b"daemon").unwrap();
        std::fs::write(
            root.join("current"),
            serde_json::to_vec(&json!({
                "schema_version":1,
                "activated":[{
                    "artifact":"bin/axiom-graphd",
                    "component":"axiom-graphd",
                    "destination":binary,
                    "sha256":graph_export::sha256_hex(b"daemon")
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        root
    }

    #[test]
    fn public_verbs_keep_one_sid_definition_and_scheduler_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let root = installed_root(temporary.path());
        let sentinel = temporary.path().join("home/user-data.txt");
        std::fs::write(&sentinel, b"human").unwrap();
        let scheduler = Scheduler::default();
        let install =
            || run_with_identity("install", "axiom-graphd", true, &root, SID, &scheduler).unwrap();
        assert!(install().get("registered").is_some());
        let state_path = windows_state::state_path(&root);
        let definition = root.join("service/axiom-graphd.task.xml");
        let original = std::fs::read(&definition).unwrap();
        assert!(original.starts_with(&[0xff, 0xfe]));
        assert!(String::from_utf16(
            &original[2..]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>()
        )
        .unwrap()
        .contains("--axiom-home"));
        let state = std::fs::read(&state_path).unwrap();
        assert!(install().get("already_registered").is_some());
        assert_eq!(std::fs::read(&state_path).unwrap(), state);
        assert_eq!(std::fs::read(&definition).unwrap(), original);
        for action in ["start", "status", "stop"] {
            assert_eq!(
                run_with_identity(action, "axiom-graphd", false, &root, SID, &scheduler).unwrap()
                    ["code"],
                0
            );
        }
        assert_eq!(
            run_with_identity(
                "status",
                "axiom-graphd",
                false,
                &root,
                "S-1-5-21-100-200-300-1002",
                &scheduler
            )
            .unwrap_err()
            .code(),
            ErrorCode::Forbidden
        );
        scheduler.tampered.set(true);
        assert_eq!(
            run_with_identity("start", "axiom-graphd", false, &root, SID, &scheduler)
                .unwrap_err()
                .code(),
            ErrorCode::Conflict
        );
        scheduler.tampered.set(false);
        std::fs::write(&definition, [original.as_slice(), b" "].concat()).unwrap();
        assert_eq!(
            run_with_identity("status", "axiom-graphd", false, &root, SID, &scheduler)
                .unwrap_err()
                .code(),
            ErrorCode::Conflict
        );
        std::fs::write(&definition, &original).unwrap();
        let pointer = root.join("current");
        let original_pointer = std::fs::read(&pointer).unwrap();
        std::fs::write(&pointer, [original_pointer.as_slice(), b" "].concat()).unwrap();
        assert_eq!(
            run_with_identity("status", "axiom-graphd", false, &root, SID, &scheduler)
                .unwrap_err()
                .code(),
            ErrorCode::Conflict
        );
        std::fs::write(&pointer, original_pointer).unwrap();
        run_with_identity("uninstall", "axiom-graphd", false, &root, SID, &scheduler).unwrap();
        assert!(!state_path.exists() && !definition.exists());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"human");
        assert!(
            run_with_identity("uninstall", "axiom-graphd", false, &root, SID, &scheduler)
                .unwrap()
                .get("already_removed")
                .is_some()
        );
    }

    #[test]
    fn foreign_task_and_unowned_definition_are_never_replaced() {
        let temporary = tempfile::tempdir().unwrap();
        let root = installed_root(temporary.path());
        let scheduler = Scheduler::default();
        scheduler.registered.set(true);
        assert_eq!(
            run_with_identity("install", "axiom-graphd", true, &root, SID, &scheduler)
                .unwrap_err()
                .code(),
            ErrorCode::Conflict
        );
        assert!(!windows_state::state_path(&root).exists());
        assert!(!root.join("service/axiom-graphd.task.xml").exists());
        scheduler.registered.set(false);
        std::fs::create_dir_all(root.join("service")).unwrap();
        std::fs::write(root.join("service/axiom-graphd.task.xml"), b"human").unwrap();
        assert_eq!(
            run_with_identity("install", "axiom-graphd", true, &root, SID, &scheduler)
                .unwrap_err()
                .code(),
            ErrorCode::Conflict
        );
        assert_eq!(
            std::fs::read(root.join("service/axiom-graphd.task.xml")).unwrap(),
            b"human"
        );
    }

    #[test]
    fn unsupported_scheduler_falls_back_without_creating_a_definition() {
        let temporary = tempfile::tempdir().unwrap();
        let root = installed_root(temporary.path());
        let scheduler = Scheduler::default();
        scheduler.unavailable.set(true);
        let outcome =
            run_with_identity("install", "axiom-graphd", true, &root, SID, &scheduler).unwrap();
        assert!(outcome.get("foreground").is_some());
        assert!(!windows_state::state_path(&root).exists());
        assert!(!root.join("service/axiom-graphd.task.xml").exists());
    }

    #[test]
    fn refused_scheduler_registration_leaves_no_owned_task_or_definition() {
        let temporary = tempfile::tempdir().unwrap();
        let root = installed_root(temporary.path());
        let scheduler = Scheduler::default();
        scheduler.fail_register.set(true);
        assert!(
            run_with_identity("install", "axiom-graphd", true, &root, SID, &scheduler).is_err()
        );
        assert!(!scheduler.registered.get());
        assert!(!windows_state::state_path(&root).exists());
        assert!(!root.join("service/axiom-graphd.task.xml").exists());
    }

    #[test]
    fn failed_post_registration_verification_removes_the_new_task() {
        let temporary = tempfile::tempdir().unwrap();
        let root = installed_root(temporary.path());
        let scheduler = Scheduler::default();
        scheduler.fail_export.set(true);
        assert!(
            run_with_identity("install", "axiom-graphd", true, &root, SID, &scheduler).is_err()
        );
        assert!(!scheduler.registered.get());
        assert!(!windows_state::state_path(&root).exists());
        assert!(!root.join("service/axiom-graphd.task.xml").exists());
    }

    #[test]
    fn update_and_rollback_rebind_the_owned_task_to_each_exact_generation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = installed_root(temporary.path());
        let scheduler = Scheduler::default();
        let pointer = root.join("current");
        let original_pointer = std::fs::read(&pointer).unwrap();
        let state_path = windows_state::state_path(&root);
        run_with_identity("install", "axiom-graphd", true, &root, SID, &scheduler).unwrap();
        let a = windows_state::read_record(&root, SID, &temporary.path().join("home")).unwrap();
        remove_with_identity(&root, SID, &scheduler).unwrap();
        assert!(!scheduler.registered.get() && !state_path.exists());

        let next = root.join("versions/0.1.3/bin/axiom-graphd");
        std::fs::create_dir_all(next.parent().unwrap()).unwrap();
        std::fs::write(&next, b"daemon-b").unwrap();
        std::fs::write(
            &pointer,
            serde_json::to_vec(&json!({
                "schema_version":1,
                "activated":[{
                    "artifact":"bin/axiom-graphd",
                    "component":"axiom-graphd",
                    "destination":next,
                    "sha256":graph_export::sha256_hex(b"daemon-b")
                }]
            }))
            .unwrap(),
        )
        .unwrap();
        run_with_identity("install", "axiom-graphd", true, &root, SID, &scheduler).unwrap();
        let b = windows_state::read_record(&root, SID, &temporary.path().join("home")).unwrap();
        assert_ne!(a.generation, b.generation);
        assert_ne!(a.definition_sha256, b.definition_sha256);
        assert!(scheduler.registered.get());

        remove_with_identity(&root, SID, &scheduler).unwrap();
        std::fs::write(&pointer, original_pointer).unwrap();
        run_with_identity("install", "axiom-graphd", true, &root, SID, &scheduler).unwrap();
        let restored =
            windows_state::read_record(&root, SID, &temporary.path().join("home")).unwrap();
        assert_eq!(restored.generation, a.generation);
        assert_eq!(restored.definition_sha256, a.definition_sha256);
        assert!(scheduler.registered.get());
        remove_with_identity(&root, SID, &scheduler).unwrap();
        assert!(!scheduler.registered.get() && !state_path.exists());
    }
}
