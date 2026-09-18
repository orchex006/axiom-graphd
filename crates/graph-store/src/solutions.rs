//! Persisting solution instance registration (task B-012).
//!
//! docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md section 2 gives `solutions` a
//! `workspace_instance_id` that is unique. The daemon binds one local worktree
//! and profile to one stable instance key, and that key decides where mutable
//! state lives (`instances/<key>/index.sqlite`). Two worktrees, or two profiles
//! over the same worktree, therefore never share a database: the key is a
//! digest of the normalised worktree root and the profile, so absolute paths
//! never appear in the identifier and a re-registration of the same worktree is
//! stable across separator spelling, a trailing separator and, on a
//! case-insensitive host, letter case.

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{is_absolute_host_path, is_portable_id};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// Prefix of a generated instance key, which makes it readable in a path.
pub const INSTANCE_KEY_PREFIX: &str = "inst-";
/// Hex characters of the digest kept in an instance key.
pub const INSTANCE_KEY_DIGEST_CHARS: usize = 32;

/// How the host treats letter case in a worktree path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathFlavor {
    /// Case-sensitive paths (POSIX default).
    CaseSensitive,
    /// Case-insensitive paths (Windows default).
    CaseInsensitive,
}

impl PathFlavor {
    /// The flavour of the host this binary runs on.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(windows) {
            Self::CaseInsensitive
        } else {
            Self::CaseSensitive
        }
    }
}

/// Facts needed to register a solution instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolutionRegistration {
    profile: String,
    worktree_root: String,
    config_hash: String,
}

impl SolutionRegistration {
    /// Register `profile` over the absolute `worktree_root`.
    #[must_use]
    pub fn new(
        profile: impl Into<String>,
        worktree_root: impl Into<String>,
        config_hash: impl Into<String>,
    ) -> Self {
        Self {
            profile: profile.into(),
            worktree_root: worktree_root.into(),
            config_hash: config_hash.into(),
        }
    }

    /// Profile name.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Absolute worktree root.
    #[must_use]
    pub fn worktree_root(&self) -> &str {
        &self.worktree_root
    }

    /// Validated configuration digest.
    #[must_use]
    pub fn config_hash(&self) -> &str {
        &self.config_hash
    }
}

/// The persisted registration of one solution instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolutionRecord {
    solution_id: String,
    workspace_instance_id: String,
    profile: String,
    config_hash: String,
    event_seq: i64,
    full_scan_required: bool,
}

impl SolutionRecord {
    /// `solutions.id`, equal to the instance key for a local registration.
    #[must_use]
    pub fn solution_id(&self) -> &str {
        &self.solution_id
    }

    /// Stable local instance key.
    #[must_use]
    pub fn workspace_instance_id(&self) -> &str {
        &self.workspace_instance_id
    }

    /// Profile bound to the instance.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Configuration digest last registered.
    #[must_use]
    pub fn config_hash(&self) -> &str {
        &self.config_hash
    }

    /// Durable event sequence; unchanged by re-registration.
    #[must_use]
    pub const fn event_seq(&self) -> i64 {
        self.event_seq
    }

    /// Whether the next startup must run a complete inventory scan.
    #[must_use]
    pub const fn full_scan_required(&self) -> bool {
        self.full_scan_required
    }
}

/// Derive the stable instance key for a worktree and profile.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] for a non-portable profile.
/// - [`ErrorCode::ConfigInvalid`] for a relative root, a control character or a
///   `.`/`..` traversal segment.
pub fn instance_key(
    profile: &str,
    worktree_root: &str,
    flavour: PathFlavor,
) -> Result<String, AxiomError> {
    validate_profile(profile)?;
    validate_worktree_root(worktree_root)?;
    let normalised = normalise_root(worktree_root, flavour);
    let mut hasher = Sha256::new();
    hasher.update(profile.as_bytes());
    hasher.update(b"\n");
    hasher.update(normalised.as_bytes());
    let digest = hasher.finalize();
    let hex = to_hex(&digest);
    Ok(format!(
        "{INSTANCE_KEY_PREFIX}{}",
        &hex[..INSTANCE_KEY_DIGEST_CHARS]
    ))
}

/// State path a registered instance owns, relative to `AXIOM_HOME`.
///
/// # Errors
/// Returns [`ErrorCode::ValidationError`] for a non-portable instance key.
pub fn state_relative_path(instance_key: &str) -> Result<String, AxiomError> {
    if !is_portable_id(instance_key) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "instance key must be a portable Axiom identifier",
        ));
    }
    Ok(format!("instances/{instance_key}/index.sqlite"))
}

/// Register the solution instance, creating it on first use.
///
/// Re-registering the same worktree and profile keeps the original
/// `solutions.id`, `event_seq` and `full_scan_required`; only a changed
/// configuration digest is updated.
///
/// # Errors
/// - The validation errors of [`instance_key`].
/// - [`ErrorCode::ValidationError`] for an empty configuration digest.
/// - [`ErrorCode::Internal`] for a storage failure.
pub fn register(
    connection: &mut Connection,
    registration: &SolutionRegistration,
    flavour: PathFlavor,
) -> Result<SolutionRecord, AxiomError> {
    if registration.config_hash().trim().is_empty() {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "configuration digest must not be empty",
        ));
    }
    if registration.config_hash().chars().any(char::is_control) {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "configuration digest contains control characters",
        ));
    }
    let key = instance_key(
        registration.profile(),
        registration.worktree_root(),
        flavour,
    )?;
    let transaction = connection.transaction().map_err(|error| {
        AxiomError::new(
            ErrorCode::Internal,
            format!("solution registration transaction failed: {error}"),
        )
    })?;
    let existing = transaction
        .query_row(
            "SELECT id, config_hash, event_seq, full_scan_required FROM solutions WHERE workspace_instance_id = ?1",
            [&key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                format!("solution registration lookup failed: {error}"),
            )
        })?;

    let record = match existing {
        Some((solution_id, stored_hash, event_seq, full_scan_required)) => {
            if stored_hash != registration.config_hash() {
                transaction
                    .execute(
                        "UPDATE solutions SET config_hash = ?1 WHERE id = ?2",
                        rusqlite::params![registration.config_hash(), solution_id],
                    )
                    .map_err(|error| {
                        AxiomError::new(
                            ErrorCode::Internal,
                            format!("solution registration update failed: {error}"),
                        )
                    })?;
            }
            SolutionRecord {
                solution_id,
                workspace_instance_id: key.clone(),
                profile: registration.profile().to_string(),
                config_hash: registration.config_hash().to_string(),
                event_seq,
                full_scan_required: full_scan_required != 0,
            }
        }
        None => {
            transaction
                .execute(
                    "INSERT INTO solutions(id, workspace_instance_id, profile, config_hash, event_seq, full_scan_required) VALUES(?1, ?2, ?3, ?4, 0, 1)",
                    rusqlite::params![key, key, registration.profile(), registration.config_hash()],
                )
                .map_err(|error| {
                    AxiomError::new(
                        ErrorCode::Internal,
                        format!("solution registration insert failed: {error}"),
                    )
                })?;
            SolutionRecord {
                solution_id: key.clone(),
                workspace_instance_id: key,
                profile: registration.profile().to_string(),
                config_hash: registration.config_hash().to_string(),
                event_seq: 0,
                full_scan_required: true,
            }
        }
    };
    transaction.commit().map_err(|error| {
        AxiomError::new(
            ErrorCode::Internal,
            format!("solution registration commit failed: {error}"),
        )
    })?;
    Ok(record)
}

fn validate_profile(profile: &str) -> Result<(), AxiomError> {
    if is_portable_id(profile) {
        return Ok(());
    }
    Err(AxiomError::new(
        ErrorCode::ValidationError,
        "profile must be a portable Axiom identifier",
    ))
}

fn validate_worktree_root(root: &str) -> Result<(), AxiomError> {
    if !is_absolute_host_path(root) {
        return Err(AxiomError::new(
            ErrorCode::ConfigInvalid,
            "worktree root must be an absolute local path",
        ));
    }
    if root.chars().any(char::is_control) {
        return Err(AxiomError::new(
            ErrorCode::ConfigInvalid,
            "worktree root contains control characters",
        ));
    }
    if root
        .split(['/', '\\'])
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(AxiomError::new(
            ErrorCode::ConfigInvalid,
            "worktree root contains a relative traversal segment",
        ));
    }
    Ok(())
}

/// Separator- and (optionally) case-normalised absolute path.
fn normalise_root(root: &str, flavour: PathFlavor) -> String {
    let prefix = if root.starts_with("//") || root.starts_with(r"\\") {
        "//"
    } else if root.starts_with('/') || root.starts_with('\\') {
        "/"
    } else {
        ""
    };
    let mut joined = String::new();
    for segment in root.split(['/', '\\']) {
        if segment.is_empty() {
            continue;
        }
        if !joined.is_empty() {
            joined.push('/');
        }
        joined.push_str(segment);
    }
    let normalised = format!("{prefix}{joined}");
    match flavour {
        PathFlavor::CaseInsensitive => normalised.to_ascii_lowercase(),
        PathFlavor::CaseSensitive => normalised,
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::memory_store;

    fn row_count(connection: &Connection) -> i64 {
        connection
            .query_row("SELECT COUNT(*) FROM solutions", [], |row| row.get(0))
            .expect("count solutions")
    }

    #[test]
    fn registration_is_stable_and_separates_worktrees() {
        let mut connection = memory_store();
        let registration = SolutionRegistration::new("default", r"D:\Work\Repo", "hash-a");
        let first = register(&mut connection, &registration, PathFlavor::CaseInsensitive)
            .expect("first registration");
        assert!(first
            .workspace_instance_id()
            .starts_with(INSTANCE_KEY_PREFIX));
        assert!(first.full_scan_required());
        assert_eq!(first.event_seq(), 0);

        let again = register(&mut connection, &registration, PathFlavor::CaseInsensitive)
            .expect("re-registration");
        assert_eq!(again.workspace_instance_id(), first.workspace_instance_id());
        assert_eq!(again.solution_id(), first.solution_id());
        assert_eq!(row_count(&connection), 1);

        // Separator spelling, a trailing separator and letter case are the same
        // instance on a case-insensitive host.
        let respelled = SolutionRegistration::new("default", "d:/work/repo/", "hash-a");
        let third = register(&mut connection, &respelled, PathFlavor::CaseInsensitive)
            .expect("respelled registration");
        assert_eq!(third.workspace_instance_id(), first.workspace_instance_id());
        assert_eq!(row_count(&connection), 1);

        // A different worktree gets its own key and its own mutable state path.
        let other = SolutionRegistration::new("default", r"D:\Work\Other", "hash-a");
        let fourth =
            register(&mut connection, &other, PathFlavor::CaseInsensitive).expect("other worktree");
        assert_ne!(
            fourth.workspace_instance_id(),
            first.workspace_instance_id()
        );
        assert_ne!(
            state_relative_path(fourth.workspace_instance_id()).expect("other state path"),
            state_relative_path(first.workspace_instance_id()).expect("first state path")
        );
        assert_eq!(row_count(&connection), 2);

        // A new configuration digest updates the row without moving the instance.
        let reconfigured = SolutionRegistration::new("default", r"D:\Work\Repo", "hash-b");
        let fifth = register(&mut connection, &reconfigured, PathFlavor::CaseInsensitive)
            .expect("reconfigured registration");
        assert_eq!(fifth.workspace_instance_id(), first.workspace_instance_id());
        assert_eq!(fifth.config_hash(), "hash-b");
        assert_eq!(row_count(&connection), 2);
    }

    #[test]
    fn unsafe_roots_and_profiles_are_refused() {
        let mut connection = memory_store();
        let relative = SolutionRegistration::new("default", "work/repo", "hash-a");
        assert_eq!(
            register(&mut connection, &relative, PathFlavor::CaseInsensitive)
                .expect_err("relative root")
                .code(),
            ErrorCode::ConfigInvalid
        );
        let traversal = SolutionRegistration::new("default", r"D:\Work\..\Repo", "hash-a");
        assert_eq!(
            register(&mut connection, &traversal, PathFlavor::CaseInsensitive)
                .expect_err("traversal root")
                .code(),
            ErrorCode::ConfigInvalid
        );
        assert_eq!(
            instance_key("Default", r"D:\Work\Repo", PathFlavor::CaseInsensitive)
                .expect_err("non-portable profile")
                .code(),
            ErrorCode::ValidationError
        );
        let empty_hash = SolutionRegistration::new("default", r"D:\Work\Repo", "  ");
        assert_eq!(
            register(&mut connection, &empty_hash, PathFlavor::CaseInsensitive)
                .expect_err("empty digest")
                .code(),
            ErrorCode::ValidationError
        );
        assert_eq!(row_count(&connection), 0);
    }
}
