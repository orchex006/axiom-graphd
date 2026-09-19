//! Scoped local service credentials for one installation (task E-007).
//!
//! `docs/21-INSTALLATION.md` section D keeps the registry configuration outside
//! Git under an owner-only ACL, and section E starts the gateway only "after
//! scoped credentials are set". `docs/23-SECURITY-AND-TRUST.md` requires a
//! loopback-only control surface with token audiences and scopes, and
//! `docs/16-CLI-AND-CONTROL-API.md` section 7 requires that the administration
//! surface cannot be reached from an ordinary read token.
//!
//! This module mints the two credentials one installation needs and nothing
//! else. It does not define a second authentication contract: the audiences and
//! scopes it emits are the frozen vocabulary of `axiom_graphd::control::auth`
//! (task B-083), so a credential written here is accepted by the daemon token
//! registry and refused exactly where that contract refuses it. The regression
//! test below asserts that agreement against the real registry rather than
//! restating it in prose.
//!
//! ## Two audiences, both restrictive (AC1)
//!
//! | Role | Audience | Scopes | Never |
//! |---|---|---|---|
//! | MCP gateway | `mcp` | `read` | `reconcile`, `checkpoint-write`, `verify`, `admin` |
//! | local service | `control-api` | `read`, `reconcile`, `checkpoint-write`, `verify` | `admin` |
//!
//! The `mcp` audience is read-only in the frozen contract and neither audience
//! reaches the administration surface, which only `administrator` does. The
//! scope table is a constant that never lists `admin`, and
//! [`CredentialIndex::validate`] refuses a document that carries it, so the two
//! credentials cannot be swapped for each other surface and neither can be
//! promoted.
//!
//! ## A secret cannot reach Git or a diagnostic bundle (AC1)
//!
//! The boundary is structural rather than a promise made in prose:
//!
//! * [`GeneratedCredentials`] is deliberately **not** `Serialize`. The only
//!   serialisable rendering of a credential set is [`CredentialIndex`], which
//!   carries a token id, an audience, scopes, a file name and a SHA-256 digest,
//!   and has no field a secret could be written into.
//! * [`store_credentials`] refuses to write under any directory that has a
//!   `.git` ancestor ([`is_inside_git_worktree`]), so credential material is
//!   never created inside a working tree that could commit it.
//! * [`GeneratedCredential::render`] is the only rendering that contains the
//!   secret. It is a `key=value` block whose `token` line the `graph-core`
//!   export scrubber already recognises, so a credential that reaches a support
//!   bundle is redacted instead of copied.
//! * [`Secret`] renders as `[redacted]` under `Debug`, never serialises, and
//!   overwrites its bytes when it is dropped.
//!
//! ## Entropy is injected
//!
//! Generation reads its randomness through [`EntropySource`], the same way the
//! planner reads its clock through [`crate::install::plan::PlanContext`]: the
//! production [`OsEntropy`] reads the operating system CSPRNG and a test
//! supplies a deterministic source, so generation is reproducible under test
//! without making the production path weak. A source that returns too few
//! distinct bytes is refused instead of being written out as a credential.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{is_absolute_host_path, is_portable_id};
use serde::{Deserialize, Serialize};

use crate::install::apply::InstallFs;
use crate::install::plan::{under, InstallPlan, InstallScope};

/// Component whose presence mints the MCP gateway credential.
pub const MCP_COMPONENT: &str = "axiom-mcp";

/// Component whose presence mints the local service credential.
pub const DAEMON_COMPONENT: &str = "axiom-graphd";

/// Directory under the install root that holds credential material.
pub const CREDENTIALS_DIRECTORY: &str = "credentials";

/// File that records the credential index (digests only) beside the credentials.
pub const CREDENTIAL_INDEX_FILE: &str = "credentials.json";

/// `schema_version` of the credential index this build writes.
pub const CREDENTIAL_INDEX_SCHEMA_VERSION: u64 = 1;

/// Suffix of one credential file; there is one file per role.
pub const CREDENTIAL_FILE_SUFFIX: &str = ".token";

/// Bytes of operating-system entropy in one generated secret.
pub const SECRET_BYTES: usize = 32;

/// Shortest secret this module accepts, in bytes.
pub const MIN_SECRET_BYTES: usize = 32;

/// Fewest distinct byte values a secret must contain to be accepted.
///
/// A correct CSPRNG output has all sixteen byte values about equally often, so
/// this never refuses a real draw; it refuses a source that is stuck, all-zero
/// or otherwise not random.
pub const MIN_DISTINCT_BYTES: usize = 8;

/// Upper bound on a presented token, mirrored from the frozen control contract.
pub const MAX_TOKEN_BYTES: usize = 512;

/// Scopes the MCP gateway credential carries.
pub const MCP_SCOPES: &[&str] = &["read"];

/// Scopes the local service credential carries.
pub const SERVICE_SCOPES: &[&str] = &["read", "reconcile", "checkpoint-write", "verify"];

/// Reason recorded when no component of the plan needs a credential.
pub const REASON_EMPTY_CREDENTIAL_SET: &str = "empty-credential-set";
/// Reason recorded when one role would be minted or registered twice.
pub const REASON_DUPLICATE_ROLE: &str = "duplicate-role";
/// Reason recorded when a credential would carry the administration scope.
pub const REASON_ADMIN_NOT_DELEGABLE: &str = "admin-not-delegable";
/// Reason recorded when credential material would live inside a Git worktree.
pub const REASON_INSIDE_GIT_WORKTREE: &str = "credential-inside-git-worktree";
/// Reason recorded when the operating system random source is unusable.
pub const REASON_ENTROPY_UNAVAILABLE: &str = "entropy-unavailable";
/// Reason recorded when a secret is shorter than [`MIN_SECRET_BYTES`].
pub const REASON_SECRET_TOO_SHORT: &str = "secret-too-short";
/// Reason recorded when a secret has too few distinct byte values.
pub const REASON_SECRET_DEGENERATE: &str = "secret-degenerate";

/// One credential an installation mints.
///
/// The role, not the caller, decides the audience and the scope set, so a
/// caller cannot ask for a credential that reaches a surface the role does not
/// own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CredentialRole {
    /// The MCP gateway credential: read-only, audience `mcp`.
    Mcp,
    /// The local service credential: audience `control-api`.
    Daemon,
}

impl CredentialRole {
    /// Every role, in the order a credential set reports them.
    #[must_use]
    pub const fn all() -> &'static [CredentialRole] {
        &[CredentialRole::Mcp, CredentialRole::Daemon]
    }

    /// Stable spelling, used in token ids and file names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mcp => "mcp",
            Self::Daemon => "daemon",
        }
    }

    /// The audience this role is minted for, as the frozen contract spells it.
    #[must_use]
    pub const fn audience(self) -> &'static str {
        match self {
            Self::Mcp => "mcp",
            Self::Daemon => "control-api",
        }
    }

    /// The scopes this role carries. Never contains `admin`.
    #[must_use]
    pub const fn scopes(self) -> &'static [&'static str] {
        match self {
            Self::Mcp => MCP_SCOPES,
            Self::Daemon => SERVICE_SCOPES,
        }
    }

    /// The component whose installation mints this role.
    #[must_use]
    pub const fn component(self) -> &'static str {
        match self {
            Self::Mcp => MCP_COMPONENT,
            Self::Daemon => DAEMON_COMPONENT,
        }
    }

    /// The audience spellings a credential index may carry.
    #[must_use]
    pub fn from_audience(audience: &str) -> Option<Self> {
        Self::all()
            .iter()
            .copied()
            .find(|role| role.audience() == audience)
    }
}

/// A generated secret.
///
/// It is not `Serialize` and its `Debug` rendering is a placeholder, so a
/// secret cannot reach a document or a log record through this type. The string
/// it holds is overwritten when it is dropped; the workspace denies `unsafe`,
/// so this is a best-effort overwrite of the buffer rather than a guaranteed
/// zeroization of every copy, and it is documented as such.
pub struct Secret {
    hex: String,
}

impl Secret {
    /// Build a secret from freshly drawn entropy.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] with [`REASON_SECRET_TOO_SHORT`] when
    /// fewer than [`MIN_SECRET_BYTES`] bytes were drawn, and with
    /// [`REASON_SECRET_DEGENERATE`] when the draw has fewer than
    /// [`MIN_DISTINCT_BYTES`] distinct byte values.
    pub fn from_entropy(bytes: &[u8]) -> Result<Self, AxiomError> {
        if bytes.len() < MIN_SECRET_BYTES {
            return Err(refuse(
                REASON_SECRET_TOO_SHORT,
                &bytes.len().to_string(),
                "a secret must be at least the minimum length",
            ));
        }
        let distinct = bytes.iter().copied().collect::<BTreeSet<u8>>().len();
        if distinct < MIN_DISTINCT_BYTES {
            return Err(refuse(
                REASON_SECRET_DEGENERATE,
                &distinct.to_string(),
                "the drawn secret is not random enough to be a credential",
            ));
        }
        Ok(Self { hex: hex(bytes) })
    }

    /// Length of the presented secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hex.len()
    }

    /// Whether the secret is empty. It never is; the pair keeps `len` honest.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hex.is_empty()
    }

    /// The secret exactly as a client presents it.
    ///
    /// Deliberately narrow: [`GeneratedCredential::render`] is the only place
    /// in this module that calls it, and the value it returns is written to one
    /// owner-only file and nowhere else.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.hex
    }

    /// SHA-256 of the presented secret: the only value the index records.
    #[must_use]
    pub fn digest(&self) -> String {
        graph_export::sha256_hex(self.hex.as_bytes())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([redacted])")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        let zeros = "0".repeat(self.hex.len());
        self.hex.replace_range(.., &zeros);
    }
}

/// The operating-system random source a credential generator reads.
pub trait EntropySource {
    /// Fill `out` with cryptographically strong random bytes.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`] with [`REASON_ENTROPY_UNAVAILABLE`] when the
    /// operating system random source cannot be reached. A source must never
    /// fill `out` with a constant to satisfy this call.
    fn fill(&self, out: &mut [u8]) -> Result<(), AxiomError>;
}

/// The production entropy source: the operating system CSPRNG.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&self, out: &mut [u8]) -> Result<(), AxiomError> {
        getrandom::fill(out).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the operating system random source is unavailable",
            )
            .with_detail("rule", REASON_ENTROPY_UNAVAILABLE)
            .with_detail("actual", error.to_string())
        })
    }
}

/// Caller-supplied inputs of one credential generation.
///
/// The timestamp and the token id prefix are injected, so two generations over
/// the same plan differ only in their secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialContext {
    /// RFC 3339 instant the credentials were issued.
    pub issued_at: String,
    /// Prefix of every token id; the caller owns uniqueness.
    pub token_id_prefix: String,
}

impl CredentialContext {
    /// A context for one prefix and one instant.
    #[must_use]
    pub fn new(token_id_prefix: impl Into<String>, issued_at: impl Into<String>) -> Self {
        Self {
            issued_at: issued_at.into(),
            token_id_prefix: token_id_prefix.into(),
        }
    }
}

/// One generated credential. See [`Secret`] for why this type is not
/// serialisable.
#[derive(Debug)]
pub struct GeneratedCredential {
    /// Role this credential was minted for.
    pub role: CredentialRole,
    /// Token id, safe to record and to log.
    pub token_id: String,
    /// Audience, always [`CredentialRole::audience`] of `role`.
    pub audience: String,
    /// Scopes, always [`CredentialRole::scopes`] of `role`.
    pub scopes: Vec<String>,
    /// The secret. Private: only [`GeneratedCredential::render`] reads it.
    secret: Secret,
}

impl GeneratedCredential {
    /// The secret, for a caller that must write it to its owner-only file.
    #[must_use]
    pub fn secret(&self) -> &Secret {
        &self.secret
    }

    /// File name of this credential inside the credentials directory.
    #[must_use]
    pub fn file_name(&self) -> String {
        format!("{}{}", self.role.as_str(), CREDENTIAL_FILE_SUFFIX)
    }

    /// Absolute path this credential is written at, under `directory`.
    #[must_use]
    pub fn path(&self, directory: &str) -> String {
        under(directory, &[&self.file_name()])
    }

    /// The credential file body: the only rendering that contains the secret.
    ///
    /// The `token` line is a `key=value` assignment whose key the `graph-core`
    /// export scrubber treats as sensitive, so this body is redacted if it ever
    /// reaches a support bundle.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "role={}\naudience={}\nscopes={}\ntoken={}\n",
            self.role.as_str(),
            self.audience,
            self.scopes.join(","),
            self.secret.expose()
        )
    }
}

/// One credential as the index records it: no secret, only its digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRecord {
    /// Role the credential was minted for, from [`CredentialRole::all`].
    pub role: String,
    /// Token id.
    pub token_id: String,
    /// Audience from the frozen control contract.
    pub audience: String,
    /// Scopes from the frozen control contract.
    pub scopes: Vec<String>,
    /// SHA-256 of the presented secret.
    pub sha256: String,
    /// Absolute path of the credential file.
    pub file: String,
}

/// The serialisable record of one credential set.
///
/// It carries digests rather than secrets, and [`CredentialIndex::validate`]
/// refuses a document that has been edited to grant the administration scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialIndex {
    /// Document schema version; must equal [`CREDENTIAL_INDEX_SCHEMA_VERSION`].
    pub schema_version: u64,
    /// Plan the credentials were minted for.
    pub plan_id: String,
    /// RFC 3339 instant the credentials were issued.
    pub issued_at: String,
    /// Scope the install owns the credential files in.
    pub scope: InstallScope,
    /// Always `true`: the credentials directory is the owner's alone.
    pub owner_only: bool,
    /// Absolute credentials directory.
    pub directory: String,
    /// One record per credential, in role order.
    pub records: Vec<CredentialRecord>,
}

impl CredentialIndex {
    /// Validate the document against the credential contract.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] when the schema version or a digest is
    /// wrong or the record set is empty; [`ErrorCode::Conflict`] with
    /// [`REASON_DUPLICATE_ROLE`] when one role is registered twice;
    /// [`ErrorCode::Forbidden`] with [`REASON_ADMIN_NOT_DELEGABLE`] when a
    /// record carries the administration scope or an unknown audience.
    pub fn validate(&self) -> Result<(), AxiomError> {
        if self.schema_version != CREDENTIAL_INDEX_SCHEMA_VERSION {
            return Err(refuse(
                "schema_version",
                &self.schema_version.to_string(),
                "the credential index schema version is not the one this build writes",
            ));
        }
        if self.records.is_empty() {
            return Err(refuse(
                REASON_EMPTY_CREDENTIAL_SET,
                "0",
                "a credential set must mint at least one credential",
            ));
        }
        let mut roles: BTreeSet<&str> = BTreeSet::new();
        let mut ids: BTreeSet<&str> = BTreeSet::new();
        for record in &self.records {
            if record.scopes.iter().any(|scope| scope == "admin") {
                return Err(AxiomError::new(
                    ErrorCode::Forbidden,
                    "the administration scope cannot be delegated to a service credential",
                )
                .with_detail("rule", REASON_ADMIN_NOT_DELEGABLE)
                .with_detail("token_id", &record.token_id)
                .with_detail("audience", &record.audience));
            }
            let role = CredentialRole::all()
                .iter()
                .copied()
                .find(|role| role.as_str() == record.role)
                .ok_or_else(|| {
                    refuse(
                        "role",
                        &record.role,
                        "the credential index names a role this build cannot mint",
                    )
                })?;
            if record.audience != role.audience() {
                return Err(AxiomError::new(
                    ErrorCode::Forbidden,
                    "a credential audience must be the one its role is minted for",
                )
                .with_detail("rule", "audience")
                .with_detail("observed", &record.audience)
                .with_detail("expected", role.audience()));
            }
            if !crate::install::plan::is_digest(&record.sha256) {
                return Err(refuse(
                    "sha256",
                    &record.sha256,
                    "a credential record must carry a lowercase 64-hex digest",
                ));
            }
            if !roles.insert(record.role.as_str()) || !ids.insert(record.token_id.as_str()) {
                return Err(AxiomError::new(
                    ErrorCode::Conflict,
                    "one credential role is registered twice",
                )
                .with_detail("rule", REASON_DUPLICATE_ROLE)
                .with_detail("token_id", &record.token_id));
            }
        }
        Ok(())
    }

    /// The index as one JSON object.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`] when the document cannot be serialised.
    pub fn to_json(&self) -> Result<String, AxiomError> {
        serde_json::to_string(self).map_err(|error| {
            AxiomError::new(
                ErrorCode::Internal,
                "the credential index is not serialisable",
            )
            .with_detail("observed", error.to_string())
        })
    }

    /// The human-reviewable rendering of one credential set.
    #[must_use]
    pub fn text(&self) -> String {
        let mut text = format!(
            "credentials {} (plan {}, scope {}, issued {})\n",
            self.directory,
            self.plan_id,
            self.scope.as_str(),
            self.issued_at
        );
        for record in &self.records {
            text.push_str(&format!(
                "{} token_id={} audience={} scopes={} sha256={}\n",
                record.file,
                record.token_id,
                record.audience,
                record.scopes.join(","),
                record.sha256
            ));
        }
        text
    }
}

/// One generated credential set.
///
/// Not `Serialize` on purpose: [`GeneratedCredentials::index`] is the document a
/// caller may write, and it holds no secret.
#[derive(Debug)]
pub struct GeneratedCredentials {
    /// Plan the credentials were minted for.
    pub plan_id: String,
    /// RFC 3339 instant the credentials were issued.
    pub issued_at: String,
    /// Scope the install owns the credential files in.
    pub scope: InstallScope,
    /// Absolute credentials directory this set is written under.
    pub directory: String,
    /// The credentials, in role order.
    pub credentials: Vec<GeneratedCredential>,
}

impl GeneratedCredentials {
    /// The digest-only document that records this set.
    #[must_use]
    pub fn index(&self) -> CredentialIndex {
        CredentialIndex {
            schema_version: CREDENTIAL_INDEX_SCHEMA_VERSION,
            plan_id: self.plan_id.clone(),
            issued_at: self.issued_at.clone(),
            scope: self.scope,
            owner_only: true,
            directory: self.directory.clone(),
            records: self
                .credentials
                .iter()
                .map(|credential| CredentialRecord {
                    role: credential.role.as_str().to_string(),
                    token_id: credential.token_id.clone(),
                    audience: credential.audience.clone(),
                    scopes: credential.scopes.clone(),
                    sha256: credential.secret().digest(),
                    file: credential.path(&self.directory),
                })
                .collect(),
        }
    }

    /// Look one role up.
    #[must_use]
    pub fn role(&self, role: CredentialRole) -> Option<&GeneratedCredential> {
        self.credentials
            .iter()
            .find(|credential| credential.role == role)
    }

    /// Number of credentials in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.credentials.len()
    }

    /// Whether the set is empty. A generated set never is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    /// Patterns a diagnostic bundle must exclude, relative to the install root.
    ///
    /// The exclusion is the second line of defence behind `Secret` never being
    /// serialisable: a bundle builder that walks the install root must skip
    /// these, and the credential file body is scrubbed if it does not.
    #[must_use]
    pub fn diagnostic_exclusions(&self) -> Vec<String> {
        vec![
            CREDENTIALS_DIRECTORY.to_string(),
            format!("{CREDENTIALS_DIRECTORY}/**"),
        ]
    }
}

/// What one credential store wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCredentials {
    /// Absolute credentials directory.
    pub directory: String,
    /// Absolute path of the digest-only index.
    pub index_file: String,
    /// Absolute path of each credential file, in role order.
    pub files: Vec<String>,
    /// The index that was written.
    pub index: CredentialIndex,
}

/// The roles one plan needs: a role is minted only when its component is
/// installed.
#[must_use]
pub fn roles_for_plan(plan: &InstallPlan) -> Vec<CredentialRole> {
    CredentialRole::all()
        .iter()
        .copied()
        .filter(|role| {
            plan.components
                .iter()
                .any(|component| component.component == role.component())
        })
        .collect()
}

/// Whether `path` is inside a Git worktree.
///
/// Walking the ancestors rather than assuming a layout is what makes this true
/// for a linked worktree, whose `.git` is a file rather than a directory, and
/// for a checkout nested under another repository. The empty ancestor is
/// skipped so the check never falls back to the process working directory.
#[must_use]
pub fn is_inside_git_worktree(path: &str) -> bool {
    Path::new(path)
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .any(|ancestor| ancestor.join(".git").exists())
}

/// The credentials directory of one install root.
#[must_use]
pub fn credentials_directory(install_root: &str) -> String {
    under(install_root, &[CREDENTIALS_DIRECTORY])
}

/// Mint the credentials one plan needs.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] when the plan, the context or the drawn
///   secret violates the contract, or when the plan installs no component that
///   needs a credential ([`REASON_EMPTY_CREDENTIAL_SET`]).
/// - [`ErrorCode::Forbidden`] with [`REASON_INSIDE_GIT_WORKTREE`] when the plan
///   targets an install root inside a Git worktree, so a secret cannot be
///   destined for a directory that could be committed.
/// - [`ErrorCode::Internal`] with [`REASON_ENTROPY_UNAVAILABLE`] when the
///   entropy source cannot be read.
pub fn generate_credentials(
    plan: &InstallPlan,
    context: &CredentialContext,
    entropy: &dyn EntropySource,
) -> Result<GeneratedCredentials, AxiomError> {
    plan.validate()?;
    if context.issued_at.trim().is_empty() {
        return Err(refuse(
            "issued_at",
            &context.issued_at,
            "a credential set needs the instant it was issued at",
        ));
    }
    if !is_portable_id(&context.token_id_prefix) {
        return Err(refuse(
            "token_id_prefix",
            &context.token_id_prefix,
            "a token id prefix must be a portable identifier",
        ));
    }
    if is_inside_git_worktree(&plan.target.install_root) {
        return Err(AxiomError::new(
            ErrorCode::Forbidden,
            "credential material must not be created inside a Git worktree",
        )
        .with_detail("rule", REASON_INSIDE_GIT_WORKTREE)
        .with_detail("observed", &plan.target.install_root));
    }
    let roles = roles_for_plan(plan);
    if roles.is_empty() {
        return Err(refuse(
            REASON_EMPTY_CREDENTIAL_SET,
            "0",
            "no installed component needs a credential",
        ));
    }
    let mut credentials: Vec<GeneratedCredential> = Vec::new();
    for role in roles {
        let mut bytes = [0u8; SECRET_BYTES];
        entropy.fill(&mut bytes)?;
        let secret = Secret::from_entropy(&bytes)?;
        bytes.fill(0);
        credentials.push(GeneratedCredential {
            token_id: format!("{}-{}", context.token_id_prefix, role.as_str()),
            audience: role.audience().to_string(),
            scopes: role
                .scopes()
                .iter()
                .map(|scope| (*scope).to_string())
                .collect(),
            role,
            secret,
        });
    }
    let generated = GeneratedCredentials {
        plan_id: plan.plan_id.clone(),
        issued_at: context.issued_at.clone(),
        scope: plan.target.scope,
        directory: credentials_directory(&plan.target.install_root),
        credentials,
    };
    generated.index().validate()?;
    Ok(generated)
}

/// Write one generated set under `install_root`.
///
/// The credential files and the digest-only index are the only things written.
/// Nothing here can create a directory outside the install root, and the store
/// refuses an install root inside a Git worktree.
///
/// # Errors
/// - [`ErrorCode::ValidationError`] when the install root is not an absolute
///   host path, when the set is empty, or when the set was generated for
///   another install root.
/// - [`ErrorCode::Forbidden`] with [`REASON_INSIDE_GIT_WORKTREE`].
/// - The [`InstallFs`] error when a file cannot be created or written.
pub fn store_credentials(
    install_root: &str,
    generated: &GeneratedCredentials,
    fs: &impl InstallFs,
) -> Result<StoredCredentials, AxiomError> {
    if !is_absolute_host_path(install_root) {
        return Err(refuse(
            "install_root",
            install_root,
            "credentials are written under an absolute install root",
        ));
    }
    if is_inside_git_worktree(install_root) {
        return Err(AxiomError::new(
            ErrorCode::Forbidden,
            "credential material must not be created inside a Git worktree",
        )
        .with_detail("rule", REASON_INSIDE_GIT_WORKTREE)
        .with_detail("observed", install_root));
    }
    if generated.is_empty() {
        return Err(refuse(
            REASON_EMPTY_CREDENTIAL_SET,
            "0",
            "a credential set must mint at least one credential",
        ));
    }
    let directory = credentials_directory(install_root);
    if generated.directory != directory {
        return Err(refuse(
            "credentials_directory",
            &generated.directory,
            "credentials are written only where the plan puts them",
        ));
    }
    generated.index().validate()?;
    fs.create_dir_all(&directory)?;
    let mut files: Vec<String> = Vec::new();
    for credential in &generated.credentials {
        let path = credential.path(&directory);
        fs.write(&path, credential.render().as_bytes())?;
        files.push(path);
    }
    let index = generated.index();
    let index_file = under(&directory, &[CREDENTIAL_INDEX_FILE]);
    let mut bytes = index.to_json()?;
    bytes.push('\n');
    fs.write(&index_file, bytes.as_bytes())?;
    Ok(StoredCredentials {
        directory,
        index_file,
        files,
        index,
    })
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// A refusal this module records under a `rule` detail.
fn refuse(rule: &str, observed: &str, message: &str) -> AxiomError {
    AxiomError::new(ErrorCode::ValidationError, message)
        .with_detail("rule", rule)
        .with_detail("observed", observed)
}

#[cfg(test)]
mod tests {
    //! Credential tests (task E-007 AC2).
    //!
    //! The positive path mints both credentials and proves the daemon control
    //! contract accepts them. The negative and boundary cases prove that a
    //! stuck or unavailable entropy source, a draw shorter than the minimum, a
    //! credential destined for a Git worktree, a credential set generated for
    //! another install root, an index edited to grant `admin`, and a support
    //! bundle rendering are all refused. The production [`OsEntropy`] is
    //! exercised for real, so the operating system CSPRNG path is covered and
    //! not only its test double.

    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    use axiom_graphd::control::auth::{
        Audience, ControlToken, Scope, TokenRegistry, REASON_ADMIN_NOT_DELEGABLE,
        REASON_AUDIENCE_NOT_ACCEPTED, REASON_SCOPE_MISSING,
    };
    use graph_core::error::ErrorCode;
    use graph_core::redact::scrub_for_export;
    use graph_export::sha256_hex;
    use tempfile::TempDir;

    use super::*;
    use crate::install::plan::{
        plan_install, ArtifactKind, BundleComponent, BundleManifest, DryRun, PlanContext,
        BUNDLE_SCHEMA_VERSION,
    };

    /// The install root every deterministic test uses; outside any repository.
    const ROOT: &str = "/tmp/axiom-home";

    /// An entropy source that returns a fresh, non-degenerate ramp per draw.
    ///
    /// The seed advances on every call, so a set of two credentials draws two
    /// different secrets from one source, exactly as the production source does.
    struct RampEntropy {
        next: Cell<u8>,
    }

    impl RampEntropy {
        fn new(seed: u8) -> Self {
            Self {
                next: Cell::new(seed),
            }
        }
    }

    impl EntropySource for RampEntropy {
        fn fill(&self, out: &mut [u8]) -> Result<(), AxiomError> {
            let seed = self.next.get();
            self.next.set(seed.wrapping_add(0x40));
            for (index, slot) in out.iter_mut().enumerate() {
                *slot = seed.wrapping_add(index as u8);
            }
            Ok(())
        }
    }

    /// An entropy source that is stuck: whatever the length, it returns zeros.
    struct ZeroEntropy;

    impl EntropySource for ZeroEntropy {
        fn fill(&self, out: &mut [u8]) -> Result<(), AxiomError> {
            out.fill(0);
            Ok(())
        }
    }

    /// An entropy source that cannot be read at all.
    struct BrokenEntropy;

    impl EntropySource for BrokenEntropy {
        fn fill(&self, _out: &mut [u8]) -> Result<(), AxiomError> {
            Err(AxiomError::new(
                ErrorCode::Internal,
                "the operating system random source is unavailable",
            )
            .with_detail("rule", REASON_ENTROPY_UNAVAILABLE))
        }
    }

    /// An in-memory [`InstallFs`] that records every mutation it is asked for.
    #[derive(Default)]
    struct MemoryFs {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        dirs: RefCell<Vec<String>>,
    }

    impl MemoryFs {
        fn get(&self, path: &str) -> Option<Vec<u8>> {
            self.files.borrow().get(path).cloned()
        }
    }

    impl InstallFs for MemoryFs {
        fn exists(&self, path: &str) -> bool {
            self.files.borrow().contains_key(path)
        }

        fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
            self.get(path).ok_or_else(|| {
                AxiomError::new(ErrorCode::NotFound, "the record could not be read")
                    .with_detail("rule", "staged_read")
                    .with_detail("observed", path)
            })
        }

        fn create_dir_all(&self, path: &str) -> Result<(), AxiomError> {
            self.dirs.borrow_mut().push(path.to_string());
            Ok(())
        }

        fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError> {
            self.files
                .borrow_mut()
                .insert(path.to_string(), bytes.to_vec());
            Ok(())
        }

        fn rename(&self, from: &str, to: &str) -> Result<(), AxiomError> {
            let bytes = self.read(from)?;
            self.files.borrow_mut().remove(from);
            self.files.borrow_mut().insert(to.to_string(), bytes);
            Ok(())
        }
    }

    /// The artifact kind and bundle path one component is declared with.
    fn artifact_for(component: &str) -> (ArtifactKind, String) {
        if component == MCP_COMPONENT {
            (
                ArtifactKind::Python,
                format!("python/{component}-0.0.0.dev0-py3-none-any.whl"),
            )
        } else {
            (ArtifactKind::Binary, format!("bin/{component}"))
        }
    }

    /// One bundle manifest declaring exactly `components`.
    fn manifest(components: &[&str]) -> BundleManifest {
        BundleManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            bundle_id: "axiom-core".to_string(),
            channel: "stable".to_string(),
            created_at: "2026-09-19T00:00:00Z".to_string(),
            components: components
                .iter()
                .map(|component| {
                    let (kind, artifact) = artifact_for(component);
                    BundleComponent {
                        component: (*component).to_string(),
                        version: "0.0.0-dev".to_string(),
                        host: "linux-x64".to_string(),
                        artifact,
                        kind,
                        sha256: sha256_hex(component.as_bytes()),
                        size_bytes: 4096,
                        permissions: vec!["read".to_string()],
                        service: None,
                        network_access: Vec::new(),
                    }
                })
                .collect(),
        }
    }

    /// One dry-run plan over `components` at `install_root`.
    fn plan_for(install_root: &str, components: &[&str]) -> InstallPlan {
        plan_install(
            &manifest(components),
            &sha256_hex(b"the exact manifest bytes"),
            "/tmp/axiom-bundle",
            &PlanContext::per_user(
                "install-20260919-0001",
                "2026-09-19T00:00:00Z",
                "linux-x64",
                install_root,
            ),
            DryRun::new(),
        )
        .expect("the fixture bundle plans")
    }

    /// One credential set over both credential-bearing components.
    fn generated() -> GeneratedCredentials {
        generate_credentials(
            &plan_for(ROOT, &[DAEMON_COMPONENT, MCP_COMPONENT]),
            &CredentialContext::new("install-20260919-0001", "2026-09-19T00:00:00Z"),
            &RampEntropy::new(0x11),
        )
        .expect("the fixture plan mints credentials")
    }

    #[test]
    fn the_two_credentials_have_separate_restrictive_audiences() {
        let generated = generated();
        assert_eq!(generated.len(), 2);
        let mcp = generated.role(CredentialRole::Mcp).expect("mcp credential");
        let service = generated
            .role(CredentialRole::Daemon)
            .expect("service credential");

        assert_eq!(mcp.audience, "mcp");
        assert_eq!(mcp.scopes, vec!["read".to_string()]);
        assert_eq!(mcp.token_id, "install-20260919-0001-mcp");
        assert_eq!(service.audience, "control-api");
        assert_eq!(service.token_id, "install-20260919-0001-daemon");
        assert_eq!(
            service.scopes,
            vec![
                "read".to_string(),
                "reconcile".to_string(),
                "checkpoint-write".to_string(),
                "verify".to_string()
            ]
        );

        // The audiences are separate and neither carries the admin scope.
        assert_ne!(mcp.audience, service.audience);
        for credential in &generated.credentials {
            assert!(!credential.scopes.iter().any(|scope| scope == "admin"));
            assert!(!credential.token_id.is_empty());
        }
        // One ramp source draws two different secrets.
        assert_ne!(mcp.secret().expose(), service.secret().expose());
        assert_eq!(mcp.file_name(), "mcp.token");
        assert_eq!(service.file_name(), "daemon.token");
        assert_eq!(generated.directory, credentials_directory(ROOT));
        assert_eq!(generated.scope, InstallScope::PerUser);
    }

    #[test]
    fn a_plan_that_installs_only_the_gateway_mints_only_its_credential() {
        let plan = plan_for(ROOT, &[MCP_COMPONENT]);
        assert_eq!(roles_for_plan(&plan), vec![CredentialRole::Mcp]);
        let generated = generate_credentials(
            &plan,
            &CredentialContext::new("gs", "2026-09-19T00:00:00Z"),
            &RampEntropy::new(0x42),
        )
        .expect("one credential");
        assert_eq!(generated.len(), 1);
        assert!(generated.role(CredentialRole::Daemon).is_none());
        assert!(!generated.is_empty());
    }

    #[test]
    fn generated_credentials_agree_with_the_frozen_control_contract() {
        let generated = generated();
        let mcp = generated.role(CredentialRole::Mcp).expect("mcp credential");
        let service = generated
            .role(CredentialRole::Daemon)
            .expect("service credential");

        // The wire vocabulary is the frozen one, not a second spelling.
        assert_eq!(Audience::parse(&mcp.audience), Some(Audience::Mcp));
        assert_eq!(
            Audience::parse(&service.audience),
            Some(Audience::ControlApi)
        );
        assert_eq!(Audience::Mcp.wire(), mcp.audience);
        assert_eq!(Audience::ControlApi.wire(), service.audience);
        assert!(Audience::Mcp.is_read_only());
        for scope in mcp.scopes.iter().chain(service.scopes.iter()) {
            assert!(Scope::parse(scope).is_some(), "unknown scope {scope}");
        }

        // Both credentials load into the daemon registry and authenticate.
        let mut registry = TokenRegistry::new();
        registry
            .insert(
                ControlToken::new(
                    &mcp.token_id,
                    mcp.secret().expose(),
                    Audience::Mcp,
                    mcp.scopes.iter().filter_map(|scope| Scope::parse(scope)),
                )
                .expect("the mcp credential is a control token"),
            )
            .expect("the mcp credential registers");
        registry
            .insert(
                ControlToken::new(
                    &service.token_id,
                    service.secret().expose(),
                    Audience::ControlApi,
                    service
                        .scopes
                        .iter()
                        .filter_map(|scope| Scope::parse(scope)),
                )
                .expect("the service credential is a control token"),
            )
            .expect("the service credential registers");
        assert_eq!(registry.len(), 2);

        let reader = registry
            .authorize(mcp.secret().expose(), Scope::Read, "demo-solution")
            .expect("the mcp credential reads");
        assert_eq!(reader.audience(), Audience::Mcp);
        let writer = registry
            .authorize(
                service.secret().expose(),
                Scope::CheckpointWrite,
                "demo-solution",
            )
            .expect("the service credential writes a checkpoint");
        assert_eq!(writer.audience(), Audience::ControlApi);
        assert!(!writer.is_administration());

        // The secrets the index records are the digests the registry holds.
        let index = generated.index();
        index.validate().expect("the index is valid");
        for record in &index.records {
            let credential = generated
                .credentials
                .iter()
                .find(|credential| credential.role.as_str() == record.role)
                .expect("a generated credential");
            assert_eq!(record.sha256, credential.secret().digest());
        }
    }

    #[test]
    fn neither_credential_can_be_promoted_or_swapped_for_the_other_surface() {
        let generated = generated();
        let mcp = generated.role(CredentialRole::Mcp).expect("mcp credential");
        let service = generated
            .role(CredentialRole::Daemon)
            .expect("service credential");

        let mut registry = TokenRegistry::new();
        registry
            .insert(
                ControlToken::new(
                    &mcp.token_id,
                    mcp.secret().expose(),
                    Audience::Mcp,
                    [Scope::Read],
                )
                .expect("mcp token"),
            )
            .expect("register");
        registry
            .insert(
                ControlToken::new(
                    &service.token_id,
                    service.secret().expose(),
                    Audience::ControlApi,
                    service
                        .scopes
                        .iter()
                        .filter_map(|scope| Scope::parse(scope)),
                )
                .expect("service token"),
            )
            .expect("register");

        // The read-only credential cannot carry a mutating scope.
        let error = registry
            .authorize(mcp.secret().expose(), Scope::Reconcile, "demo-solution")
            .expect_err("a gateway token must not reconcile");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_SCOPE_MISSING)
        );
        // Neither credential reaches the administration surface.
        for secret in [mcp.secret().expose(), service.secret().expose()] {
            let error = registry
                .authorize_mutation(secret, Scope::Admin)
                .expect_err("no service credential administers");
            assert_eq!(error.code(), ErrorCode::Forbidden);
            assert_eq!(
                error.details().get("rule").map(String::as_str),
                Some(REASON_AUDIENCE_NOT_ACCEPTED)
            );
        }
        // The frozen contract refuses to represent the escalation at all.
        let error = ControlToken::new(
            "promoted-gateway",
            mcp.secret().expose(),
            Audience::Mcp,
            [Scope::Admin],
        )
        .expect_err("the admin scope is not delegable to mcp");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_ADMIN_NOT_DELEGABLE)
        );
    }

    #[test]
    fn an_entropy_source_that_is_stuck_or_unavailable_is_refused() {
        let plan = plan_for(ROOT, &[DAEMON_COMPONENT]);
        let context = CredentialContext::new("gs", "2026-09-19T00:00:00Z");

        // Boundary: a draw of the right length that is not random at all.
        let error = generate_credentials(&plan, &context, &ZeroEntropy)
            .expect_err("an all-zero draw is not a credential");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_SECRET_DEGENERATE)
        );

        // Negative: an entropy source that cannot be read fails closed.
        let error = generate_credentials(&plan, &context, &BrokenEntropy)
            .expect_err("an unavailable source mints nothing");
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_ENTROPY_UNAVAILABLE)
        );
    }

    #[test]
    fn a_draw_shorter_than_the_minimum_is_refused() {
        let error = Secret::from_entropy(&[0xa5; MIN_SECRET_BYTES - 1])
            .expect_err("a short draw is not a secret");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_SECRET_TOO_SHORT)
        );

        // Boundary: exactly the minimum length, with enough distinct bytes, is
        // accepted, and its rendering is the hex of the drawn bytes.
        let bytes: Vec<u8> = (0..MIN_SECRET_BYTES as u8).collect();
        let secret = Secret::from_entropy(&bytes).expect("the minimum length is enough");
        assert_eq!(secret.len(), MIN_SECRET_BYTES * 2);
        assert!(secret.expose().starts_with("00010203"));
        assert_eq!(secret.digest(), sha256_hex(secret.expose().as_bytes()));
        assert_eq!(secret.digest().len(), 64);
        assert!(!secret.is_empty());

        // The digest is stable and a changed secret has a different one.
        let other = Secret::from_entropy(&(1..=MIN_SECRET_BYTES as u8).collect::<Vec<u8>>())
            .expect("a shifted draw is a secret");
        assert_ne!(secret.digest(), other.digest());
    }

    #[test]
    fn an_invalid_context_is_refused() {
        let plan = plan_for(ROOT, &[DAEMON_COMPONENT]);
        let entropy = RampEntropy::new(0x11);

        let error = generate_credentials(&plan, &CredentialContext::new("gs", ""), &entropy)
            .expect_err("a credential set needs an instant");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("issued_at")
        );

        let error = generate_credentials(
            &plan,
            &CredentialContext::new("not a portable id", "2026-09-19T00:00:00Z"),
            &entropy,
        )
        .expect_err("a token id prefix must be portable");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("token_id_prefix")
        );
    }

    #[test]
    fn credential_material_is_refused_inside_a_git_worktree() {
        // A real fixture: a temporary directory that contains `.git`.
        let fixture = TempDir::new().expect("a temporary directory");
        let repository = fixture.path().join("repo");
        std::fs::create_dir_all(repository.join(".git")).expect("the fixture git directory");
        let inside = repository.join("home");
        std::fs::create_dir_all(&inside).expect("the fixture install root");
        let inside = inside.to_string_lossy().into_owned();
        assert!(is_inside_git_worktree(&inside));

        // This working tree is one too, so the check is exercised against the
        // repository the crate is built from, not only against a fixture.
        assert!(is_inside_git_worktree(env!("CARGO_MANIFEST_DIR")));

        // Generation is refused before a secret is even drawn.
        let plan = plan_for(&inside, &[DAEMON_COMPONENT]);
        let error = generate_credentials(
            &plan,
            &CredentialContext::new("gs", "2026-09-19T00:00:00Z"),
            &RampEntropy::new(0x11),
        )
        .expect_err("credentials must not be destined for a repository");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_INSIDE_GIT_WORKTREE)
        );

        // Storing is refused as well, and writes nothing at all.
        let generated = generated();
        let fs = MemoryFs::default();
        let error = store_credentials(&inside, &generated, &fs)
            .expect_err("the store must not write into a repository");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_INSIDE_GIT_WORKTREE)
        );
        assert!(fs.files.borrow().is_empty());
        assert!(fs.dirs.borrow().is_empty());

        // A sibling directory outside the repository is accepted.
        let outside = fixture.path().join("elsewhere");
        std::fs::create_dir_all(&outside).expect("the fixture home");
        assert!(!is_inside_git_worktree(&outside.to_string_lossy()));
    }

    #[test]
    fn the_index_records_a_digest_and_never_the_secret() {
        let generated = generated();
        let fs = MemoryFs::default();
        let stored = store_credentials(ROOT, &generated, &fs).expect("the fixture set stores");

        assert_eq!(stored.files.len(), 2);
        assert_eq!(stored.directory, credentials_directory(ROOT));
        assert!(stored.index_file.ends_with("credentials.json"));
        assert_eq!(fs.dirs.borrow().len(), 1);

        let index = stored.index.to_json().expect("the index serialises");
        let mcp = generated.role(CredentialRole::Mcp).expect("mcp credential");
        // The digest is recorded; no secret is.
        assert!(index.contains(&mcp.secret().digest()));
        for credential in &generated.credentials {
            assert!(!index.contains(credential.secret().expose()));
        }
        assert!(index.contains("control-api"));
        assert!(!index.contains("admin"));

        // The on-disk index is the same document, newline terminated.
        let written = fs
            .get(&stored.index_file)
            .expect("the index was written to the store");
        assert_eq!(
            String::from_utf8(written.clone()).expect("utf-8"),
            format!("{index}\n")
        );

        // Each credential file carries the secret, keyed so a scrubber
        // recognises it, and nothing carries the other credential's secret.
        let mcp_file = fs
            .get(&mcp.path(&stored.directory))
            .expect("the mcp credential was written");
        let mcp_file = String::from_utf8(mcp_file).expect("utf-8");
        assert!(mcp_file.contains(&format!("token={}", mcp.secret().expose())));
        assert!(mcp_file.contains("role=mcp"));
        assert!(mcp_file.contains("audience=mcp"));
        let service = generated
            .role(CredentialRole::Daemon)
            .expect("service credential");
        assert!(!mcp_file.contains(service.secret().expose()));

        // The human rendering names the files and never a secret.
        let text = stored.index.text();
        assert!(text.contains("mcp.token"));
        assert!(text.contains("daemon.token"));
        assert!(!text.contains(mcp.secret().expose()));
    }

    #[test]
    fn a_support_bundle_rendering_of_a_credential_is_redacted() {
        let generated = generated();
        let mcp = generated.role(CredentialRole::Mcp).expect("mcp credential");
        let secret = mcp.secret().expose();

        let scrubbed = scrub_for_export(&mcp.render());
        assert!(
            !scrubbed.contains(secret),
            "the export scrubber must not carry the secret"
        );
        assert!(scrubbed.contains("token=[redacted]"));
        // The exclusion list is declared for a bundle that walks the install
        // root instead of rendering a file body.
        assert_eq!(
            generated.diagnostic_exclusions(),
            vec!["credentials".to_string(), "credentials/**".to_string()]
        );
    }

    #[test]
    fn debug_output_never_prints_a_secret_or_a_plain_text_digest() {
        let generated = generated();
        let mcp = generated.role(CredentialRole::Mcp).expect("mcp credential");
        let secret = mcp.secret().expose();

        let secret_debug = format!("{:?}", mcp.secret());
        assert_eq!(secret_debug, "Secret([redacted])");
        assert!(!secret_debug.contains(secret));

        let credential_debug = format!("{mcp:?}");
        assert!(!credential_debug.contains(secret));

        let set_debug = format!("{generated:?}");
        assert!(!set_debug.contains(secret));
        for credential in &generated.credentials {
            assert!(!set_debug.contains(credential.secret().expose()));
        }
    }

    #[test]
    fn an_index_edited_to_grant_admin_or_a_second_role_is_refused() {
        let generated = generated();

        let mut index = generated.index();
        index.records[0].scopes.push("admin".to_string());
        let error = index.validate().expect_err("admin is not delegable");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_ADMIN_NOT_DELEGABLE)
        );

        // An audience that is not the role own is refused.
        let mut index = generated.index();
        index.records[0].audience = "administrator".to_string();
        let error = index.validate().expect_err("an audience cannot be swapped");
        assert_eq!(error.code(), ErrorCode::Forbidden);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("audience")
        );

        // A role this build cannot mint is refused.
        let mut index = generated.index();
        index.records[0].role = "root".to_string();
        let error = index.validate().expect_err("an unknown role is refused");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("role")
        );

        // A digest that is not a digest is refused.
        let mut index = generated.index();
        index.records[0].sha256 = "not-a-digest".to_string();
        let error = index.validate().expect_err("a record needs a digest");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("sha256")
        );

        // One role registered twice is a conflict, not a silent overwrite.
        let mut index = generated.index();
        let duplicate = index.records[0].clone();
        index.records.push(duplicate);
        let error = index.validate().expect_err("a duplicate role conflicts");
        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_DUPLICATE_ROLE)
        );

        // An empty set is refused rather than reported as a valid install.
        let mut index = generated.index();
        index.records.clear();
        let error = index.validate().expect_err("an empty set is refused");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_EMPTY_CREDENTIAL_SET)
        );

        // A schema version from another build is refused.
        let mut index = generated.index();
        index.schema_version = CREDENTIAL_INDEX_SCHEMA_VERSION + 1;
        let error = index.validate().expect_err("the schema version is pinned");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("schema_version")
        );
    }

    #[test]
    fn a_set_generated_for_another_install_root_is_refused_by_the_store() {
        let generated = generated();
        let fs = MemoryFs::default();
        let error = store_credentials("/tmp/another-home", &generated, &fs)
            .expect_err("the store writes only where the plan puts it");
        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("credentials_directory")
        );
        assert!(fs.files.borrow().is_empty());

        let error = store_credentials("relative/home", &generated, &MemoryFs::default())
            .expect_err("an install root is absolute");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some("install_root")
        );
    }

    #[test]
    fn a_plan_without_a_credential_bearing_component_mints_nothing() {
        let plan = plan_for(ROOT, &["axiom"]);
        assert!(roles_for_plan(&plan).is_empty());
        let error = generate_credentials(
            &plan,
            &CredentialContext::new("gs", "2026-09-19T00:00:00Z"),
            &RampEntropy::new(0x11),
        )
        .expect_err("no component needs a credential");
        assert_eq!(
            error.details().get("rule").map(String::as_str),
            Some(REASON_EMPTY_CREDENTIAL_SET)
        );
    }

    #[test]
    fn the_role_component_names_are_installable_components() {
        for role in CredentialRole::all() {
            assert!(
                crate::install::plan::COMPONENTS.contains(&role.component()),
                "{} is not an installable component",
                role.component()
            );
            assert_eq!(CredentialRole::from_audience(role.audience()), Some(*role));
        }
        assert_eq!(CredentialRole::from_audience("administrator"), None);
        assert_eq!(CredentialRole::all().len(), 2);
        assert_eq!(CredentialRole::Mcp.as_str(), "mcp");
        assert_eq!(CredentialRole::Daemon.as_str(), "daemon");
    }

    #[test]
    fn the_production_entropy_source_returns_fresh_secrets() {
        // Real operating system entropy, so the production path is covered and
        // not only its test double. A host with no random source would fail
        // here; the native platform evidence for such a host is recorded as
        // not_run by the task evidence rather than invented.
        let mut first_bytes = [0u8; SECRET_BYTES];
        OsEntropy
            .fill(&mut first_bytes)
            .expect("the operating system random source");
        let first = Secret::from_entropy(&first_bytes).expect("a real draw is a secret");

        let mut second_bytes = [0u8; SECRET_BYTES];
        OsEntropy
            .fill(&mut second_bytes)
            .expect("the operating system random source");
        let second = Secret::from_entropy(&second_bytes).expect("a real draw is a secret");

        assert_ne!(first.expose(), second.expose());
        assert_eq!(first.len(), SECRET_BYTES * 2);
        assert_eq!(first.digest().len(), 64);
    }
}
