//! Native replacement that never removes the previous file before the swap.

use std::path::Path;

/// Inspect every existing ancestor and reject symbolic links and Windows junctions.
pub fn reject_links(path: &Path) -> std::io::Result<()> {
    let mut current = std::path::PathBuf::new();
    for part in path.components() {
        current.push(part);
        if matches!(part, std::path::Component::Prefix(_)) {
            continue;
        }
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                let linked = metadata.file_type().is_symlink();
                #[cfg(windows)]
                let linked = {
                    use std::os::windows::fs::MetadataExt;
                    linked || metadata.file_attributes() & 0x400 != 0
                };
                if linked {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "managed path contains a link or junction",
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Replace a file atomically on the same volume, preserving it on failure.
pub fn replace(source: &Path, target: &Path) -> std::io::Result<()> {
    #[cfg(not(windows))]
    {
        std::fs::rename(source, target)
    }
    #[cfg(windows)]
    {
        windows_replace(source, target)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn windows_replace(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let target: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    // Both buffers are NUL-terminated and stay alive for this synchronous call.
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_existing_bytes_and_preserves_previous_on_failure() {
        let root = tempfile::tempdir().expect("temporary root");
        let target = root.path().join("current");
        let source = root.path().join("next");
        std::fs::write(&target, b"A").expect("old pointer");
        std::fs::write(&source, b"B").expect("new pointer");
        replace(&source, &target).expect("atomic replacement");
        assert_eq!(std::fs::read(&target).expect("pointer"), b"B");
        assert!(replace(&source, &target).is_err());
        assert_eq!(std::fs::read(&target).expect("retained pointer"), b"B");
    }
}
