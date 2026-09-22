//! Persisted, engine-owned macOS service identity.
use super::InstalledService;
use crate::service::control::{ControlRoots, ServiceOwnership};
use graph_core::error::{AxiomError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const STATE_RELATIVE: &str = "state/service-v1.json";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedServiceState {
    pub schema_version: u32,
    pub installed: InstalledService,
    pub launchd_user_id: u32,
    pub definition_sha256: String,
    pub generation: String,
}
impl OwnedServiceState {
    pub fn new(
        installed: InstalledService,
        launchd_user_id: u32,
        definition_sha256: String,
        generation: String,
    ) -> Result<Self, AxiomError> {
        let state = Self {
            schema_version: 1,
            installed,
            launchd_user_id,
            definition_sha256,
            generation,
        };
        state.validate()?;
        Ok(state)
    }
    pub fn validate(&self) -> Result<(), AxiomError> {
        if self.schema_version != 1
            || self.launchd_user_id == 0
            || !digest(&self.definition_sha256)
            || !digest(&self.generation)
        {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "invalid owned service state",
            ));
        }
        Ok(())
    }
}
pub fn state_path(root: &Path) -> PathBuf {
    root.join(STATE_RELATIVE)
}
pub fn write(root: &Path, state: &OwnedServiceState) -> Result<(), AxiomError> {
    state.validate()?;
    verify_root(root)?;
    let path = state_path(root);
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "state file symlink refused",
            ));
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| AxiomError::new(ErrorCode::Internal, "state path has no parent"))?;
    std::fs::create_dir_all(parent).map_err(io)?;
    if std::fs::symlink_metadata(parent)
        .map_err(io)?
        .file_type()
        .is_symlink()
    {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "state directory symlink refused",
        ));
    }
    let bytes = serde_json::to_vec(state)
        .map_err(|_| AxiomError::new(ErrorCode::Internal, "state serialization failed"))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(io)?;
    use std::io::Write;
    temp.write_all(&bytes).map_err(io)?;
    temp.as_file().sync_all().map_err(io)?;
    temp.persist(&path).map_err(|e| io(e.error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
    }
    Ok(())
}
pub fn read_record(
    root: &Path,
    current_uid: u32,
    home: &Path,
) -> Result<OwnedServiceState, AxiomError> {
    verify_root(root)?;
    let path = state_path(root);
    if std::fs::symlink_metadata(&path)
        .map_err(io)?
        .file_type()
        .is_symlink()
    {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "state file symlink refused",
        ));
    }
    let state: OwnedServiceState = serde_json::from_slice(&std::fs::read(path).map_err(io)?)
        .map_err(|_| {
            AxiomError::new(
                ErrorCode::ValidationError,
                "owned service state is malformed",
            )
        })?;
    state.validate()?;
    if state.launchd_user_id != current_uid {
        return Err(AxiomError::new(
            ErrorCode::Forbidden,
            "owned service state belongs to another user",
        ));
    }
    let expected_definition = home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("com.axiom.{}.plist", state.installed.component));
    if Path::new(&state.installed.definition_path) != expected_definition {
        return Err(AxiomError::new(
            ErrorCode::Forbidden,
            "owned service definition is not the exact canonical LaunchAgent path",
        ));
    }
    for path in [
        home.to_path_buf(),
        home.join("Library"),
        home.join("Library/LaunchAgents"),
        expected_definition.clone(),
    ] {
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error)
                if path == expected_definition && error.kind() == std::io::ErrorKind::NotFound =>
            {
                continue
            }
            Err(error) => return Err(io(error)),
        };
        if metadata.file_type().is_symlink() {
            return Err(AxiomError::new(
                ErrorCode::Forbidden,
                "owned service definition symlink is refused",
            ));
        }
    }
    ServiceOwnership::claim(
        &state.installed,
        &ControlRoots::new(
            root.to_string_lossy().into_owned(),
            home.to_string_lossy().into_owned(),
        ),
    )?;
    Ok(state)
}

/// Read an owned record and verify the currently present definition bytes.
pub fn read_with_home(
    root: &Path,
    current_uid: u32,
    home: &Path,
) -> Result<OwnedServiceState, AxiomError> {
    let state = read_record(root, current_uid, home)?;
    let bytes = std::fs::read(&state.installed.definition_path).map_err(io)?;
    if graph_export::sha256_hex(&bytes) != state.definition_sha256 {
        return Err(AxiomError::new(
            ErrorCode::Conflict,
            "owned service definition changed",
        ));
    }
    Ok(state)
}
fn verify_root(root: &Path) -> Result<(), AxiomError> {
    if !root.is_absolute()
        || std::fs::symlink_metadata(root)
            .map_err(io)?
            .file_type()
            .is_symlink()
    {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "unsafe install root",
        ));
    }
    Ok(())
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn io(e: std::io::Error) -> AxiomError {
    AxiomError::new(
        if e.kind() == std::io::ErrorKind::NotFound {
            ErrorCode::NotFound
        } else {
            ErrorCode::Internal
        },
        "owned service state I/O failed",
    )
    .with_detail("observed", e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::ServiceKind;
    use crate::install::plan::InstallScope;
    use crate::service::RestartPolicy;

    fn state(root: &Path, home: &Path, uid: u32) -> OwnedServiceState {
        let definition = home.join("Library/LaunchAgents/com.axiom.axiom-graphd.plist");
        std::fs::create_dir_all(definition.parent().unwrap()).unwrap();
        std::fs::write(&definition, b"plist").unwrap();
        let installed = InstalledService {
            component: "axiom-graphd".into(),
            task_name: "com.axiom.axiom-graphd".into(),
            mechanism: ServiceKind::LaunchAgent,
            scope: InstallScope::PerUser,
            definition_path: definition.to_string_lossy().into_owned(),
            log_file: root.join("logs/a.log").to_string_lossy().into_owned(),
            restart: RestartPolicy::never(),
        };
        OwnedServiceState::new(
            installed,
            uid,
            graph_export::sha256_hex(b"plist"),
            "a".repeat(64),
        )
        .unwrap()
    }
    #[test]
    fn round_trip_is_private_and_validated() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("install");
        let home = temp.path().join("home");
        std::fs::create_dir_all(&root).unwrap();
        let expected = state(&root, &home, 501);
        write(&root, &expected).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(state_path(&root))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert_eq!(read_with_home(&root, 501, &home).unwrap(), expected);
        assert!(read_with_home(&root, 502, &home).is_err());
        std::fs::write(&expected.installed.definition_path, b"changed").unwrap();
        assert!(read_with_home(&root, 501, &home).is_err());
    }
    #[test]
    fn malformed_uppercase_and_symlink_roots_refuse() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("install");
        let home = temp.path().join("home");
        std::fs::create_dir_all(&root).unwrap();
        let mut value = state(&root, &home, 501);
        value.definition_sha256 = "A".repeat(64);
        assert!(write(&root, &value).is_err());
        std::fs::create_dir_all(root.join("state")).unwrap();
        std::fs::write(state_path(&root), b"{\"schema_version\":2}").unwrap();
        assert!(read_with_home(&root, 501, &home).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_state_file_is_never_read_or_replaced() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("install");
        let home = temp.path().join("home");
        std::fs::create_dir_all(root.join("state")).unwrap();
        let target = temp.path().join("foreign.json");
        std::fs::write(&target, b"foreign").unwrap();
        symlink(&target, state_path(&root)).unwrap();
        let value = state(&root, &home, 501);
        assert!(write(&root, &value).is_err());
        assert!(read_with_home(&root, 501, &home).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"foreign");
    }
}
