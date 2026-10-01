//! Engine-owned Windows service identity, separate from the macOS LaunchAgent state.

use std::path::{Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};
use serde::{Deserialize, Serialize};

use super::control::{ControlRoots, ServiceOwnership};
use super::{owned_state, windows, InstalledService};
use crate::discovery::ServiceKind;
use crate::install::plan::InstallScope;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsOwnedState {
    pub schema_version: u32,
    pub installed: InstalledService,
    pub user_sid: String,
    pub definition_sha256: String,
    pub registered_sha256: String,
    pub generation: String,
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn refuse(message: &str) -> AxiomError {
    AxiomError::new(ErrorCode::Forbidden, message)
}

fn io(error: std::io::Error) -> AxiomError {
    let code = if error.kind() == std::io::ErrorKind::NotFound {
        ErrorCode::NotFound
    } else {
        ErrorCode::Internal
    };
    AxiomError::new(code, "Windows service state I/O failed")
        .with_detail("observed", error.to_string())
}

impl WindowsOwnedState {
    pub fn new(
        installed: InstalledService,
        user_sid: String,
        definition_sha256: String,
        registered_sha256: String,
        generation: String,
    ) -> Result<Self, AxiomError> {
        let state = Self {
            schema_version: 1,
            installed,
            user_sid,
            definition_sha256,
            registered_sha256,
            generation,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<(), AxiomError> {
        if self.schema_version != 1
            || !windows::valid_user_sid(&self.user_sid)
            || !digest(&self.definition_sha256)
            || !digest(&self.registered_sha256)
            || !digest(&self.generation)
            || self.installed.component != "axiom-graphd"
            || self.installed.mechanism != ServiceKind::PerUserStartup
            || self.installed.scope != InstallScope::PerUser
        {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "invalid Windows owned service state",
            ));
        }
        Ok(())
    }
}

#[must_use]
pub fn state_path(root: &Path) -> PathBuf {
    owned_state::state_path(root)
}

pub fn write(root: &Path, state: &WindowsOwnedState) -> Result<(), AxiomError> {
    state.validate()?;
    if !root.is_absolute()
        || std::fs::symlink_metadata(root)
            .map_err(io)?
            .file_type()
            .is_symlink()
    {
        return Err(refuse("unsafe Windows service install root"));
    }
    let path = state_path(root);
    let parent = path
        .parent()
        .ok_or_else(|| refuse("service state has no parent"))?;
    std::fs::create_dir_all(parent).map_err(io)?;
    if std::fs::symlink_metadata(parent)
        .map_err(io)?
        .file_type()
        .is_symlink()
        || path.exists()
        || path.is_symlink()
    {
        return Err(refuse(
            "Windows service state path is linked or already owned",
        ));
    }
    let bytes = serde_json::to_vec(state)
        .map_err(|_| AxiomError::new(ErrorCode::Internal, "service state serialization failed"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(io)?;
    use std::io::Write;
    temporary.write_all(&bytes).map_err(io)?;
    temporary.as_file().sync_all().map_err(io)?;
    temporary
        .persist_noclobber(&path)
        .map_err(|error| io(error.error))?;
    Ok(())
}

/// Verify the state and exact canonical task definition path, allowing an
/// absent definition only so a trusted uninstall can repair interrupted state.
pub fn read_record(
    root: &Path,
    current_sid: &str,
    home: &Path,
) -> Result<WindowsOwnedState, AxiomError> {
    if !root.is_absolute()
        || std::fs::symlink_metadata(root)
            .map_err(io)?
            .file_type()
            .is_symlink()
    {
        return Err(refuse("unsafe Windows service install root"));
    }
    let path = state_path(root);
    if std::fs::symlink_metadata(&path)
        .map_err(io)?
        .file_type()
        .is_symlink()
    {
        return Err(refuse("linked Windows service state"));
    }
    let bytes = std::fs::read(&path).map_err(io)?;
    if bytes.len() > 64 * 1024 {
        return Err(refuse("Windows service state exceeds its byte bound"));
    }
    let state: WindowsOwnedState = serde_json::from_slice(&bytes).map_err(|_| {
        AxiomError::new(
            ErrorCode::ValidationError,
            "Windows service state is malformed",
        )
    })?;
    state.validate()?;
    if state.user_sid != current_sid {
        return Err(refuse("Windows service state belongs to another user"));
    }
    if root != home.join("installs/ecosystem") {
        return Err(refuse("Windows service root differs from Axiom home"));
    }
    let expected = root.join("service/axiom-graphd.task.xml");
    if Path::new(&state.installed.definition_path) != expected {
        return Err(refuse(
            "Windows service definition is not the exact owned task path",
        ));
    }
    for candidate in [root.join("service"), expected.clone()] {
        match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(refuse("linked Windows service definition"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && candidate == expected => {
            }
            Err(error) => return Err(io(error)),
        }
    }
    ServiceOwnership::claim(
        &state.installed,
        &ControlRoots::new(root.to_string_lossy(), home.to_string_lossy()),
    )?;
    Ok(state)
}

pub fn read_with_definition(
    root: &Path,
    current_sid: &str,
    home: &Path,
) -> Result<WindowsOwnedState, AxiomError> {
    let state = read_record(root, current_sid, home)?;
    let bytes = std::fs::read(&state.installed.definition_path).map_err(io)?;
    if graph_export::sha256_hex(&bytes) != state.definition_sha256 {
        return Err(AxiomError::new(
            ErrorCode::Conflict,
            "owned Windows task definition changed",
        ));
    }
    Ok(state)
}
