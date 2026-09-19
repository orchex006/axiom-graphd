//! Safe native executable replacement (task V2-023).
//!
//! `docs/20-VERSION-CHECK-UPDATE-RELEASE.md` section 6 fixes the order of one
//! update transaction, and the step this module owns is the one that actually
//! moves bytes over a *running* installation: stop the affected processes,
//! re-assert the verified artifact and the compatibility selection, persist a
//! rollback journal, then exchange the destination in one rename. The card for
//! this slice is `tasks/V2/V2-023.md`.
//!
//! Four rules are the reason this is a module of its own rather than a few lines
//! inside [`crate::update::rust_binary`]:
//!
//! * the replacement is refused while a process still holds the destination
//!   open, so the caller must stop the affected processes first; a refusal is a
//!   conflict the caller may retry, never a half-written executable;
//! * the compatibility decision is not re-invented here. The plan calls
//!   [`crate::update::resolve`] so "newer" is never assumed to be compatible, and
//!   a release that is no newer than the installed one is refused too;
//! * the previous bytes are journalled *before* the first byte moves, together
//!   with their digest, so [`rollback_native_apply`] can restore exactly the
//!   bytes that were there and can refuse to restore anything else;
//! * there is no destructive fallback. When a native boundary cannot be observed
//!   the module records that fact instead of assuming the safe answer, and it
//!   never deletes or truncates the destination: the only mutation of the
//!   installed executable is the staged rename.
//!
//! The native boundaries themselves are not re-implemented here. The link
//! boundary, the open-handle check, the byte-exactness check, the native path
//! limit and the same-filesystem rule all come from
//! [`axiom_platform::filesystem`], the module task V2-015 landed for exactly this
//! purpose.
//!
//! Nothing here opens a socket, spawns a process or touches a real filesystem:
//! the destination is observed through an injected [`FilesystemProbe`] and an
//! injected [`InUseProbe`], and every mutation goes through the injected
//! [`ActivationFs`] that [`crate::update::rust_binary`] already defines. The
//! tests drive in-memory doubles, so no test needs a running image, a real lock
//! or a release key.

use std::path::{Path, PathBuf};
use std::slice;

use axiom_platform::filesystem::{
    check_open_handle_replacement, check_replacement, is_within_root, EntryFacts, FilesystemProbe,
    HandleCheck, ReplacementRequest,
};
use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{is_absolute_host_path, validate_portable_relative_path};
use graph_export::sha256_hex;
use serde::{Deserialize, Serialize};

use crate::install::plan::is_digest;
use crate::install::verify::VerifiedArtifact;
use crate::update::resolve::{self, ComponentRelease, Constraints, ResolvedAction, ResolvedUpdate};
use crate::update::rust_binary::ActivationFs;

/// Components that share the one core release and may be replaced here.
pub const COMPONENTS: [&str; 2] = ["axiom-graphd", "axiom"];

/// Suffix of the temporary sibling that receives the staged bytes.
pub const STAGE_TEMP_SUFFIX: &str = ".axiom-staged";

/// Suffix of the sibling that keeps the bytes the journal points at.
pub const BACKUP_SUFFIX: &str = ".axiom-backup";

/// File name of the rollback journal inside the install root.
pub const JOURNAL_FILE: &str = "native-apply-journal.json";

/// Schema version of the journal this build writes and accepts.
pub const JOURNAL_SCHEMA_VERSION: u64 = 1;

/// Upper bound on a journal document this build will parse.
pub const MAX_JOURNAL_BYTES: usize = 64 * 1024;

/// Every refusal rule this module can raise, with its stable spelling.
pub const REFUSAL_RULES: [&str; 26] = [
    "already-current",
    "artifact-digest-mismatch",
    "backup-digest-mismatch",
    "backup-missing",
    "bytes-digest-mismatch",
    "component-mismatch",
    "destination-in-use",
    "destination-missing",
    "destination-not-absolute",
    "destination-outside-install-root",
    "host-mismatch",
    "invalid-digest",
    "journal-component-mismatch",
    "journal-has-no-backup",
    "journal-missing",
    "journal-schema-unsupported",
    "journal-too-large",
    "journal-unreadable",
    "missing-revision",
    "missing-target-version",
    "missing-version",
    "restore-digest-mismatch",
    "source-equals-destination",
    "unknown-component",
    "unsafe-portable-path",
    "version-mismatch",
];

/// One refusal of this module, with its named rule.
fn refuse(rule: &str, message: &str) -> AxiomError {
    AxiomError::new(ErrorCode::ValidationError, message).with_detail("rule", rule)
}

/// One refusal caused by current state, which a later retry may clear.
fn conflict(rule: &str, message: &str, observed: &str) -> AxiomError {
    AxiomError::new(ErrorCode::Conflict, message)
        .with_detail("rule", rule)
        .with_detail("observed", observed)
        .with_retryable(true)
}
/// One ordered phase of a native replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApplyPhase {
    /// The replacement bytes and the verified artifact are re-asserted.
    Verify,
    /// The rollback journal is persisted before the first byte moves.
    Journal,
    /// Affected processes are observed and the destination must not be in use.
    Fence,
    /// The signed bytes are staged into a temporary sibling.
    Stage,
    /// The temporary sibling replaces the destination in one rename.
    Cutover,
}

impl ApplyPhase {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::Journal => "journal",
            Self::Fence => "fence",
            Self::Stage => "stage",
            Self::Cutover => "cutover",
        }
    }
}

/// Every phase of one replacement, in the order it runs.
pub const APPLY_PHASES: [ApplyPhase; 5] = [
    ApplyPhase::Verify,
    ApplyPhase::Journal,
    ApplyPhase::Fence,
    ApplyPhase::Stage,
    ApplyPhase::Cutover,
];

/// What one in-use observation reported about the destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InUse {
    /// Nothing holds the destination open.
    Idle,
    /// A process holds the destination open, with the observation that showed it.
    Busy {
        /// The native observation, kept verbatim for the refusal report.
        fact: String,
    },
    /// The host cannot enumerate open handles, so "not in use" was not proven.
    Unobservable,
}

impl InUse {
    /// Stable wire spelling.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Busy { .. } => "busy",
            Self::Unobservable => "unobservable",
        }
    }
}

/// The narrow in-use boundary a native replacement needs.
pub trait InUseProbe {
    /// Observe whether `destination` is held open by another process.
    ///
    /// # Errors
    ///
    /// Fails when the destination cannot be observed for a reason other than
    /// "it does not exist yet"; a missing destination is reported as
    /// [`InUse::Idle`], because there is nothing there to hold open.
    fn observe(&self, destination: &Path) -> Result<InUse, AxiomError>;
}

/// The real host: the platform probe, with the gap it has recorded.
///
/// [`axiom_platform::filesystem::NativeFilesystemProbe`] cannot enumerate open
/// handles through `std`, so `check_open_handle_replacement` answers
/// [`HandleCheck::Unobservable`] on a real machine. This adapter reports that
/// fact rather than upgrading it to [`InUse::Idle`]: an unproven answer must not
/// read as a proven one.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeInUseProbe<P: FilesystemProbe> {
    probe: P,
}

impl<P: FilesystemProbe> NativeInUseProbe<P> {
    /// Bind the in-use observation to one filesystem probe.
    #[must_use]
    pub const fn new(probe: P) -> Self {
        Self { probe }
    }
}

impl<P: FilesystemProbe> InUseProbe for NativeInUseProbe<P> {
    fn observe(&self, destination: &Path) -> Result<InUse, AxiomError> {
        let facts: EntryFacts = match self.probe.entry_facts(destination) {
            Ok(facts) => facts,
            Err(error) if error.code() == ErrorCode::NotFound => return Ok(InUse::Idle),
            Err(error) => return Err(error),
        };
        match check_open_handle_replacement(&facts) {
            Ok(HandleCheck::Clear) => Ok(InUse::Idle),
            Ok(HandleCheck::Unobservable) => Ok(InUse::Unobservable),
            Err(held) if held.code() == ErrorCode::Conflict => Ok(InUse::Busy {
                fact: held.message().to_string(),
            }),
            Err(other) => Err(other),
        }
    }
}

/// The paths one native replacement is expressed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeApplyTarget {
    destination_root: String,
    portable_path: String,
    source_path: PathBuf,
    destination_path: PathBuf,
}

impl NativeApplyTarget {
    /// Bind one install root, one portable spelling and the two host paths.
    #[must_use]
    pub fn new(
        destination_root: &str,
        portable_path: &str,
        source_path: &Path,
        destination_path: &Path,
    ) -> Self {
        Self {
            destination_root: destination_root.to_string(),
            portable_path: portable_path.to_string(),
            source_path: source_path.to_path_buf(),
            destination_path: destination_path.to_path_buf(),
        }
    }

    /// Absolute root the destination must stay inside.
    #[must_use]
    pub fn destination_root(&self) -> &str {
        &self.destination_root
    }

    /// Portable relative spelling of the destination.
    #[must_use]
    pub fn portable_path(&self) -> &str {
        &self.portable_path
    }

    /// Where the staged bytes come from.
    #[must_use]
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    /// The installed executable being replaced.
    #[must_use]
    pub fn destination_path(&self) -> &Path {
        &self.destination_path
    }
}
/// The artifact identity one replacement moves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeApplyIdentity {
    /// Component, from [`COMPONENTS`].
    pub component: String,
    /// Host the artifact was verified for.
    pub host: String,
    /// Version of the verified artifact.
    pub version: String,
    /// Version the compatibility set selected.
    pub target_version: String,
    /// Revision the release was built from.
    pub revision: String,
    /// Lowercase 64-hex digest the replacement bytes must have.
    pub expected_sha256: String,
    /// Version installed before this replacement, when one is recorded.
    pub installed_version: Option<String>,
}

/// One native replacement that has already passed every static check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeApplyRequest {
    identity: NativeApplyIdentity,
    target: NativeApplyTarget,
}

impl NativeApplyRequest {
    /// Bind one replacement to its identity and its paths.
    ///
    /// # Errors
    ///
    /// Refuses a component outside [`COMPONENTS`], an unusable version, a
    /// missing revision, a digest that is not a lowercase 64-hex digest, a
    /// destination that is not absolute, a destination that leaves its install
    /// root, a portable spelling that violates the portability policy, and a
    /// staging source that is the destination itself. Every one of these is a
    /// refusal before any byte moves, so a rejected request never leaves partial
    /// state behind.
    pub fn new(
        identity: NativeApplyIdentity,
        target: NativeApplyTarget,
    ) -> Result<Self, AxiomError> {
        if !COMPONENTS.contains(&identity.component.as_str()) {
            return Err(refuse(
                "unknown-component",
                "the component is not part of the one core release",
            ));
        }
        if identity.version.trim().is_empty() {
            return Err(refuse(
                "missing-version",
                "the verified artifact does not name a version",
            ));
        }
        if identity.target_version.trim().is_empty() {
            return Err(refuse(
                "missing-target-version",
                "the resolved target does not name a version",
            ));
        }
        if identity.revision.trim().is_empty() {
            return Err(refuse(
                "missing-revision",
                "the release does not name the revision it was built from",
            ));
        }
        if !is_digest(&identity.expected_sha256) {
            return Err(refuse(
                "invalid-digest",
                "the trusted digest is not a lowercase 64-hex digest",
            ));
        }
        let destination = target.destination_path.display().to_string();
        if !is_absolute_host_path(&destination) {
            return Err(refuse(
                "destination-not-absolute",
                "the destination is not an absolute host path",
            ));
        }
        if !is_within_root(target.destination_root(), &destination) {
            return Err(refuse(
                "destination-outside-install-root",
                "the destination leaves the install root it was reviewed for",
            ));
        }
        validate_portable_relative_path(target.portable_path())
            .map_err(|error| refuse("unsafe-portable-path", error.message()))?;
        if target.source_path() == target.destination_path() {
            return Err(refuse(
                "source-equals-destination",
                "the staging source is the destination itself",
            ));
        }
        Ok(Self { identity, target })
    }

    /// The approved artifact identity.
    #[must_use]
    pub fn identity(&self) -> &NativeApplyIdentity {
        &self.identity
    }

    /// The paths this replacement is expressed in.
    #[must_use]
    pub fn target(&self) -> &NativeApplyTarget {
        &self.target
    }

    /// Component being replaced.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.identity.component
    }

    /// Version of the verified artifact.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.identity.version
    }

    /// Version the compatibility set selected.
    #[must_use]
    pub fn target_version(&self) -> &str {
        &self.identity.target_version
    }

    /// Revision the release was built from.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.identity.revision
    }

    /// Digest the replacement bytes must have.
    #[must_use]
    pub fn expected_sha256(&self) -> &str {
        &self.identity.expected_sha256
    }

    /// Version installed before this replacement, when one is recorded.
    #[must_use]
    pub fn installed_version(&self) -> Option<&str> {
        self.identity.installed_version.as_deref()
    }
}
/// The reviewed native replacement one call may perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeApplyPlan {
    request: NativeApplyRequest,
    resolved: ResolvedUpdate,
    approval: VerifiedArtifact,
}

impl NativeApplyPlan {
    /// The validated replacement to perform.
    #[must_use]
    pub fn request(&self) -> &NativeApplyRequest {
        &self.request
    }

    /// The compatibility selection this replacement was reviewed against.
    #[must_use]
    pub fn resolved(&self) -> &ResolvedUpdate {
        &self.resolved
    }

    /// The verified-artifact proof this replacement is bound to.
    #[must_use]
    pub fn approval(&self) -> &VerifiedArtifact {
        &self.approval
    }
}

/// Build the one reviewed native replacement from a verified artifact.
///
/// The `approval` argument is a [`VerifiedArtifact`], which only
/// [`crate::install::verify::verify_artifact`] produces, so a caller cannot reach
/// this function with bytes whose signature, host and digest were never checked.
///
/// # Errors
///
/// Refuses a proof and a release that describe different components, a proof
/// verified for another host, a digest that is not a lowercase 64-hex digest, a
/// proof that is not the payload the release declares, a release without a
/// revision, a release the compatibility set does not accept (the named `rule`
/// of [`crate::update::resolve`] is preserved), a release that is no newer than
/// the installed one, a proof that is not the version the compatibility set
/// selected, and every refusal [`NativeApplyRequest::new`] raises.
pub fn plan_native_apply(
    host: &str,
    approval: &VerifiedArtifact,
    release: &ComponentRelease,
    constraints: &Constraints,
    installed_version: Option<&str>,
    target: NativeApplyTarget,
) -> Result<NativeApplyPlan, AxiomError> {
    if approval.component != release.component {
        return Err(refuse(
            "component-mismatch",
            "the verified artifact belongs to another component than the release",
        ));
    }
    if approval.host != host {
        return Err(refuse(
            "host-mismatch",
            "the verified artifact was not verified for this host",
        ));
    }
    if !is_digest(&approval.sha256) || !is_digest(&release.artifact_sha256) {
        return Err(refuse(
            "invalid-digest",
            "the trusted digest is not a lowercase 64-hex digest",
        ));
    }
    if approval.sha256 != release.artifact_sha256 {
        return Err(refuse(
            "artifact-digest-mismatch",
            "the verified artifact is not the payload the release declares",
        ));
    }
    if release.revision.trim().is_empty() {
        return Err(refuse(
            "missing-revision",
            "the release does not name the revision it was built from",
        ));
    }
    let resolved = resolve::resolve(slice::from_ref(release), constraints, installed_version)?;
    if resolved.action == ResolvedAction::Noop {
        return Err(refuse(
            "already-current",
            "the selected release is no newer than the installed one",
        ));
    }
    if approval.version != resolved.target_version {
        return Err(refuse(
            "version-mismatch",
            "the verified artifact is not the version the compatibility set selected",
        ));
    }
    let identity = NativeApplyIdentity {
        component: release.component.clone(),
        host: host.to_string(),
        version: approval.version.clone(),
        target_version: resolved.target_version.clone(),
        revision: release.revision.clone(),
        expected_sha256: release.artifact_sha256.clone(),
        installed_version: resolved.installed_version.clone(),
    };
    Ok(NativeApplyPlan {
        request: NativeApplyRequest::new(identity, target)?,
        resolved,
        approval: approval.clone(),
    })
}
/// One step a rollback would reverse, with its stable wire spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalAction {
    /// The affected processes were stopped and the destination was not in use.
    Stop,
    /// The previous bytes were copied to the journalled backup path.
    Backup,
    /// The replacement bytes were staged into a temporary sibling.
    Stage,
    /// The temporary sibling was renamed over the destination.
    Cutover,
}

impl JournalAction {
    /// Stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "stop",
            Self::Backup => "backup",
            Self::Stage => "stage",
            Self::Cutover => "cutover",
        }
    }
}

/// The rollback journal persisted before the first byte moves.
///
/// The document is written *before* the destination is touched, so a crash
/// between the two leaves a journal that still describes the pre-replacement
/// bytes. It records the digest of those bytes as well as their location, so
/// [`rollback_native_apply`] refuses to restore a backup that is not the one it
/// recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackJournal {
    /// Schema version of this document.
    pub schema_version: u64,
    /// Component being replaced.
    pub component: String,
    /// Version of the verified artifact that was applied.
    pub version: String,
    /// Version the compatibility set selected.
    pub target_version: String,
    /// Revision the release was built from.
    pub revision: String,
    /// Absolute root the destination stays inside.
    pub destination_root: String,
    /// Portable relative spelling of the destination.
    pub portable_path: String,
    /// Absolute path of the destination.
    pub destination_path: String,
    /// Where the previous bytes were copied, when there were any.
    pub backup_path: Option<String>,
    /// Digest of the bytes the destination held before the replacement.
    pub destination_sha256_before: Option<String>,
    /// The steps this replacement performs, in order.
    pub actions: Vec<JournalAction>,
}

/// The journal path for one install root.
#[must_use]
pub fn journal_path(destination_root: &str) -> String {
    let root = destination_root.trim_end_matches('/');
    format!("{root}/{JOURNAL_FILE}")
}

/// What one completed native replacement did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeApplyOutcome {
    /// Schema version of this record.
    pub schema_version: u64,
    /// Component that was replaced.
    pub component: String,
    /// Version of the verified artifact that was applied.
    pub version: String,
    /// Version the compatibility set selected.
    pub target_version: String,
    /// Revision the release was built from.
    pub revision: String,
    /// Digest of the bytes that were installed.
    pub sha256: String,
    /// Number of bytes that were installed.
    pub bytes: u64,
    /// Absolute path that was replaced.
    pub destination: String,
    /// Portable relative spelling of the destination.
    pub portable_path: String,
    /// What the in-use observation could report.
    pub handles: String,
    /// Where the rollback journal was persisted.
    pub journal: String,
    /// The phases that ran, in order.
    pub phases: Vec<String>,
}

impl NativeApplyOutcome {
    /// Component that was replaced.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    /// Digest of the bytes that were installed.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Number of bytes that were installed.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// What the in-use observation could report.
    #[must_use]
    pub fn handles(&self) -> &str {
        &self.handles
    }

    /// Where the rollback journal was persisted.
    #[must_use]
    pub fn journal(&self) -> &str {
        &self.journal
    }

    /// The phases that ran, in order.
    #[must_use]
    pub fn phases(&self) -> &[String] {
        &self.phases
    }
}
/// Replace one installed executable with the reviewed artifact.
///
/// The phases run in the fixed order of [`APPLY_PHASES`]: the bytes are matched
/// against the verified digest, the journal and its backup are persisted, the
/// destination is checked for a held handle, the signed bytes are staged into a
/// temporary sibling and every native boundary of that replacement is checked,
/// and only then does one rename exchange the destination.
///
/// # Errors
///
/// Refuses replacement bytes that are not the verified artifact, a destination
/// that does not exist (a fresh install is [`crate::update::rust_binary`]'s job,
/// not a replacement), a destination that is still held open (a retryable
/// [`ErrorCode::Conflict`]), a journal that exceeds its bound, and the typed
/// error of the first [`axiom_platform::filesystem`] boundary that refuses the
/// staged replacement. Nothing destructive happens before a refusal, and the
/// only mutation of the destination is the final rename.
pub fn native_apply(
    plan: &NativeApplyPlan,
    bytes: &[u8],
    journal_path: &str,
    probe: &dyn FilesystemProbe,
    in_use: &dyn InUseProbe,
    fs: &dyn ActivationFs,
) -> Result<NativeApplyOutcome, AxiomError> {
    let mut phases: Vec<String> = Vec::with_capacity(APPLY_PHASES.len());
    let request = plan.request();
    let root = request.target().destination_root();
    let destination = request.target().destination_path().display().to_string();

    // Verify: the bytes must be the artifact whose signature was checked.
    phases.push(ApplyPhase::Verify.as_str().to_string());
    let observed = sha256_hex(bytes);
    if observed != request.expected_sha256() {
        return Err(refuse(
            "bytes-digest-mismatch",
            "the replacement bytes are not the artifact the release declares",
        ));
    }

    // Journal: the previous bytes and their digest are on disk before the
    // destination is touched, so a crash here is still recoverable.
    phases.push(ApplyPhase::Journal.as_str().to_string());
    if !fs.exists(&destination) {
        return Err(refuse(
            "destination-missing",
            "there is no installed executable to replace",
        ));
    }
    let previous = fs.read(&destination)?;
    let previous_sha256 = sha256_hex(&previous);
    let backup = format!("{destination}{BACKUP_SUFFIX}");
    fs.write(&backup, &previous)?;
    let journal = RollbackJournal {
        schema_version: JOURNAL_SCHEMA_VERSION,
        component: request.component().to_string(),
        version: request.version().to_string(),
        target_version: request.target_version().to_string(),
        revision: request.revision().to_string(),
        destination_root: root.to_string(),
        portable_path: request.target().portable_path().to_string(),
        destination_path: destination.clone(),
        backup_path: Some(backup),
        destination_sha256_before: Some(previous_sha256),
        actions: vec![
            JournalAction::Stop,
            JournalAction::Backup,
            JournalAction::Stage,
            JournalAction::Cutover,
        ],
    };
    let encoded = serde_json::to_vec(&journal).map_err(|error| {
        AxiomError::new(
            ErrorCode::Internal,
            format!("the rollback journal could not be encoded: {error}"),
        )
    })?;
    if encoded.len() > MAX_JOURNAL_BYTES {
        return Err(refuse(
            "journal-too-large",
            "the rollback journal exceeds the accepted bound",
        ));
    }
    fs.write(journal_path, &encoded)?;

    // Fence: the affected processes must already be gone.
    phases.push(ApplyPhase::Fence.as_str().to_string());
    let handles = match in_use.observe(request.target().destination_path())? {
        InUse::Idle => HandleCheck::Clear,
        InUse::Busy { fact } => {
            return Err(conflict(
                "destination-in-use",
                "the destination is still held open; stop the affected processes first",
                &fact,
            ));
        }
        InUse::Unobservable => HandleCheck::Unobservable,
    };

    // Stage: write the temporary sibling and check every native boundary of the
    // replacement against what was actually written.
    phases.push(ApplyPhase::Stage.as_str().to_string());
    let staged_path = format!("{destination}{STAGE_TEMP_SUFFIX}");
    fs.write(&staged_path, bytes)?;
    let staged = fs.read(&staged_path)?;
    let replacement = ReplacementRequest::new(
        request.target().source_path(),
        request.target().destination_path(),
        root,
        request.target().portable_path(),
        bytes,
        &staged,
    );
    check_replacement(&replacement, probe)?;

    // Cutover: one rename exchanges the destination.
    phases.push(ApplyPhase::Cutover.as_str().to_string());
    fs.rename(&staged_path, &destination)?;

    Ok(NativeApplyOutcome {
        schema_version: JOURNAL_SCHEMA_VERSION,
        component: request.component().to_string(),
        version: request.version().to_string(),
        target_version: request.target_version().to_string(),
        revision: request.revision().to_string(),
        sha256: observed,
        bytes: bytes.len() as u64,
        destination,
        portable_path: request.target().portable_path().to_string(),
        handles: handles.as_str().to_string(),
        journal: journal_path.to_string(),
        phases,
    })
}
/// What one rollback restored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackOutcome {
    component: String,
    destination_path: String,
    restored_sha256: String,
    bytes: u64,
}

impl RollbackOutcome {
    /// Component that was restored.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    /// Absolute path that was restored.
    #[must_use]
    pub fn destination_path(&self) -> &str {
        &self.destination_path
    }

    /// Digest of the bytes the destination now holds.
    #[must_use]
    pub fn restored_sha256(&self) -> &str {
        &self.restored_sha256
    }

    /// Number of bytes that were restored.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// Restore the bytes a journal recorded, and only those bytes.
///
/// # Errors
///
/// Refuses a missing, oversized, unparsable or differently-versioned journal, a
/// journal that belongs to another component, a journal that recorded no bytes,
/// a backup that is gone, a backup whose digest is not the one the journal
/// recorded, and a destination that does not hold the restored bytes. The digest
/// check is what makes this fail closed: an edited backup is refused instead of
/// being written over the installed executable.
pub fn rollback_native_apply(
    journal_path: &str,
    component: &str,
    fs: &dyn ActivationFs,
) -> Result<RollbackOutcome, AxiomError> {
    let encoded = fs.read(journal_path).map_err(|error| {
        if error.code() == ErrorCode::NotFound {
            refuse(
                "journal-missing",
                "there is no rollback journal to restore from",
            )
        } else {
            error
        }
    })?;
    if encoded.len() > MAX_JOURNAL_BYTES {
        return Err(refuse(
            "journal-too-large",
            "the rollback journal exceeds the accepted bound",
        ));
    }
    let journal: RollbackJournal = serde_json::from_slice(&encoded).map_err(|_error| {
        refuse(
            "journal-unreadable",
            "the rollback journal could not be parsed",
        )
    })?;
    if journal.schema_version != JOURNAL_SCHEMA_VERSION {
        return Err(refuse(
            "journal-schema-unsupported",
            "the rollback journal has another schema version",
        ));
    }
    if journal.component != component {
        return Err(refuse(
            "journal-component-mismatch",
            "the rollback journal belongs to another component",
        ));
    }
    let (Some(backup), Some(expected)) = (
        journal.backup_path.as_deref(),
        journal.destination_sha256_before.as_deref(),
    ) else {
        return Err(refuse(
            "journal-has-no-backup",
            "the rollback journal recorded no bytes to restore",
        ));
    };
    let bytes = fs.read(backup).map_err(|error| {
        if error.code() == ErrorCode::NotFound {
            refuse("backup-missing", "the journalled backup is gone")
        } else {
            error
        }
    })?;
    let observed = sha256_hex(&bytes);
    if observed != expected {
        return Err(refuse(
            "backup-digest-mismatch",
            "the journalled backup is not the bytes the journal recorded",
        ));
    }
    fs.write(&journal.destination_path, &bytes)?;
    let restored = sha256_hex(&fs.read(&journal.destination_path)?);
    if restored != expected {
        return Err(refuse(
            "restore-digest-mismatch",
            "the destination does not hold the restored bytes",
        ));
    }
    Ok(RollbackOutcome {
        component: journal.component,
        destination_path: journal.destination_path,
        restored_sha256: restored,
        bytes: bytes.len() as u64,
    })
}
#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::path::Path;

    use axiom_platform::filesystem::{EntryFacts, FilesystemProbe, StorageLocation, SymlinkKind};
    use graph_core::error::{AxiomError, ErrorCode};
    use graph_export::sha256_hex;

    use super::{
        journal_path, native_apply, plan_native_apply, rollback_native_apply, InUse, InUseProbe,
        NativeApplyIdentity, NativeApplyRequest, NativeApplyTarget, NativeInUseProbe,
        RollbackJournal, APPLY_PHASES, REFUSAL_RULES, STAGE_TEMP_SUFFIX,
    };
    use crate::install::verify::VerifiedArtifact;
    use crate::update::resolve::{ComponentRelease, Constraints};
    use crate::update::rust_binary::ActivationFs;

    const ROOT: &str = "/srv/axiom/install";
    const PORTABLE: &str = "axiom-graphd/bin/axiom-graphd";
    const DEST: &str = "/srv/axiom/install/axiom-graphd/bin/axiom-graphd";
    const SOURCE: &str = "/srv/axiom/staging/axiom-graphd";
    const HOST: &str = "linux-x64";
    const JOURNAL: &str = "/srv/axiom/install/native-apply-journal.json";
    const BACKUP: &str = "/srv/axiom/install/axiom-graphd/bin/axiom-graphd.axiom-backup";

    /// A stable 40-hex revision, which is what the compatibility contract needs.
    fn revision() -> String {
        "a".repeat(40)
    }

    /// A stable lowercase 64-hex digest.
    fn digest(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
    }

    fn rule(error: &AxiomError) -> String {
        error
            .details()
            .get("rule")
            .cloned()
            .unwrap_or_else(|| "<none>".to_string())
    }

    fn verified(version: &str, sha256: &str) -> VerifiedArtifact {
        VerifiedArtifact {
            component: "axiom-graphd".to_string(),
            version: version.to_string(),
            host: HOST.to_string(),
            artifact: PORTABLE.to_string(),
            sha256: sha256.to_string(),
            size_bytes: 12,
            key_id: "root-1".to_string(),
        }
    }

    fn release(version: &str, sha256: &str, revision: &str, channel: &str) -> ComponentRelease {
        ComponentRelease {
            component: "axiom-graphd".to_string(),
            version: version.to_string(),
            revision: revision.to_string(),
            channel: channel.to_string(),
            spec_version: "2.0.0".to_string(),
            graph_schema: 3,
            control_api: 5,
            queue_schema: 2,
            artifact_sha256: sha256.to_string(),
            published_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn constraints() -> Constraints {
        Constraints {
            component: "axiom-graphd".to_string(),
            channel: "stable".to_string(),
            graph_schema_major: 3,
            control_api: 5,
            queue_schema: 2,
            spec_version: "2.0.0".to_string(),
        }
    }

    fn target(root: &str, portable: &str, destination: &str, source: &str) -> NativeApplyTarget {
        NativeApplyTarget::new(root, portable, Path::new(source), Path::new(destination))
    }

    fn identity(component: &str, version: &str, sha256: &str) -> NativeApplyIdentity {
        NativeApplyIdentity {
            component: component.to_string(),
            host: HOST.to_string(),
            version: version.to_string(),
            target_version: version.to_string(),
            revision: revision(),
            expected_sha256: sha256.to_string(),
            installed_version: Some("1.0.0".to_string()),
        }
    }

    /// An in-memory [`ActivationFs`] that also records the order of its writes.
    #[derive(Debug, Default)]
    struct MemFs {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        log: RefCell<Vec<String>>,
    }

    impl MemFs {
        fn with(entries: &[(&str, &[u8])]) -> Self {
            let fs = Self::default();
            for (path, bytes) in entries {
                fs.files
                    .borrow_mut()
                    .insert((*path).to_string(), bytes.to_vec());
            }
            fs
        }

        fn get(&self, path: &str) -> Option<Vec<u8>> {
            self.files.borrow().get(path).cloned()
        }

        fn ops(&self) -> Vec<String> {
            self.log.borrow().clone()
        }
    }

    impl ActivationFs for MemFs {
        fn exists(&self, path: &str) -> bool {
            self.files.borrow().contains_key(path)
        }

        fn read(&self, path: &str) -> Result<Vec<u8>, AxiomError> {
            self.files.borrow().get(path).cloned().ok_or_else(|| {
                AxiomError::new(ErrorCode::NotFound, format!("no such file: {path}"))
            })
        }

        fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError> {
            self.log.borrow_mut().push(format!("write {path}"));
            self.files
                .borrow_mut()
                .insert(path.to_string(), bytes.to_vec());
            Ok(())
        }

        fn rename(&self, from: &str, to: &str) -> Result<(), AxiomError> {
            self.log.borrow_mut().push(format!("rename {from}->{to}"));
            let bytes = self.files.borrow_mut().remove(from).ok_or_else(|| {
                AxiomError::new(ErrorCode::NotFound, format!("no such file: {from}"))
            })?;
            self.files.borrow_mut().insert(to.to_string(), bytes);
            Ok(())
        }
    }

    /// A probe that reports one fixed native observation for every path.
    #[derive(Debug, Clone, Copy)]
    struct FixedProbe {
        handles: Option<u32>,
        max_units: Option<usize>,
        units: usize,
        long_paths: bool,
        link: bool,
    }

    impl FixedProbe {
        fn clear() -> Self {
            Self {
                handles: Some(0),
                max_units: None,
                units: 0,
                long_paths: true,
                link: false,
            }
        }

        fn unobservable() -> Self {
            Self {
                handles: None,
                ..Self::clear()
            }
        }

        fn held() -> Self {
            Self {
                handles: Some(3),
                ..Self::clear()
            }
        }

        fn long_path() -> Self {
            Self {
                max_units: Some(10),
                units: 40,
                long_paths: false,
                ..Self::clear()
            }
        }

        fn escaping_link() -> Self {
            Self {
                link: true,
                ..Self::clear()
            }
        }
    }

    impl FilesystemProbe for FixedProbe {
        fn entry_facts(&self, _path: &Path) -> Result<EntryFacts, AxiomError> {
            let storage = StorageLocation::Local { volume_id: 7 };
            if self.link {
                return Ok(EntryFacts::link(
                    SymlinkKind::Junction,
                    Some("/elsewhere/axiom-graphd".to_string()),
                    storage,
                ));
            }
            let facts = EntryFacts::regular(storage);
            Ok(match self.handles {
                Some(handles) => facts.with_open_handles(handles),
                None => facts,
            })
        }

        fn storage_location(&self, _path: &Path) -> StorageLocation {
            StorageLocation::Local { volume_id: 7 }
        }

        fn max_path_units(&self) -> Option<usize> {
            self.max_units
        }

        fn path_units(&self, _path: &Path) -> usize {
            self.units
        }

        fn long_paths_enabled(&self, _path: &Path) -> bool {
            self.long_paths
        }
    }

    /// A probe that reports one fixed in-use verdict for every destination.
    #[derive(Debug, Clone)]
    struct FixedInUse(InUse);

    impl InUseProbe for FixedInUse {
        fn observe(&self, _destination: &Path) -> Result<InUse, AxiomError> {
            Ok(self.0.clone())
        }
    }

    fn reviewed_plan(sha256: &str) -> super::NativeApplyPlan {
        plan_native_apply(
            HOST,
            &verified("1.1.0", sha256),
            &release("1.1.0", sha256, &revision(), "stable"),
            &constraints(),
            Some("1.0.0"),
            target(ROOT, PORTABLE, DEST, SOURCE),
        )
        .expect("the reviewed plan is accepted")
    }

    fn journal_document(
        component: &str,
        schema_version: u64,
        backup: Option<&str>,
        before: Option<&str>,
    ) -> Vec<u8> {
        let journal = RollbackJournal {
            schema_version,
            component: component.to_string(),
            version: "1.1.0".to_string(),
            target_version: "1.1.0".to_string(),
            revision: revision(),
            destination_root: ROOT.to_string(),
            portable_path: PORTABLE.to_string(),
            destination_path: DEST.to_string(),
            backup_path: backup.map(str::to_string),
            destination_sha256_before: before.map(str::to_string),
            actions: vec![super::JournalAction::Stop, super::JournalAction::Cutover],
        };
        serde_json::to_vec(&journal).expect("the journal encodes")
    }
    #[test]
    fn replaces_an_installed_executable_and_journals_the_previous_bytes() {
        let previous = b"old image".to_vec();
        let replacement = b"new image bytes".to_vec();
        let sha256 = sha256_hex(&replacement);
        let fs = MemFs::with(&[(DEST, previous.as_slice())]);
        let journal = journal_path(ROOT);

        let outcome = native_apply(
            &reviewed_plan(&sha256),
            &replacement,
            &journal,
            &FixedProbe::clear(),
            &NativeInUseProbe::new(FixedProbe::clear()),
            &fs,
        )
        .expect("the replacement succeeds");

        assert_eq!(outcome.component(), "axiom-graphd");
        assert_eq!(outcome.sha256(), sha256);
        assert_eq!(outcome.bytes(), replacement.len() as u64);
        assert_eq!(outcome.handles(), "clear");
        assert_eq!(outcome.journal(), journal);
        let phases: Vec<&str> = outcome.phases().iter().map(String::as_str).collect();
        assert_eq!(phases, ["verify", "journal", "fence", "stage", "cutover"]);
        assert_eq!(fs.get(DEST).as_deref(), Some(replacement.as_slice()));

        let backup = format!("{DEST}.axiom-backup");
        assert_eq!(fs.get(&backup).as_deref(), Some(previous.as_slice()));
        let encoded = fs.get(&journal).expect("the journal was persisted");
        let parsed: RollbackJournal = serde_json::from_slice(&encoded).expect("the journal parses");
        assert_eq!(
            parsed.destination_sha256_before.as_deref(),
            Some(sha256_hex(&previous).as_str())
        );
        assert_eq!(parsed.backup_path.as_deref(), Some(backup.as_str()));
    }

    #[test]
    fn the_journal_is_persisted_before_the_first_byte_of_the_destination_moves() {
        let previous = b"old image".to_vec();
        let replacement = b"new image bytes".to_vec();
        let sha256 = sha256_hex(&replacement);
        let fs = MemFs::with(&[(DEST, previous.as_slice())]);
        let journal = journal_path(ROOT);

        native_apply(
            &reviewed_plan(&sha256),
            &replacement,
            &journal,
            &FixedProbe::clear(),
            &FixedInUse(InUse::Idle),
            &fs,
        )
        .expect("the replacement succeeds");

        let ops = fs.ops();
        let journal_write = ops
            .iter()
            .position(|op| op.contains(super::JOURNAL_FILE))
            .expect("the journal write was recorded");
        let stage_write = ops
            .iter()
            .position(|op| op.contains(STAGE_TEMP_SUFFIX))
            .expect("the staged write was recorded");
        let cutover = ops
            .iter()
            .position(|op| op.starts_with("rename "))
            .expect("the cutover rename was recorded");
        assert!(journal_write < stage_write, "journal before stage");
        assert!(stage_write < cutover, "stage before cutover");
        assert_eq!(ops.len(), 4, "backup, journal, stage and rename only");
    }

    #[test]
    fn records_unobservable_handles_instead_of_claiming_a_clear_destination() {
        let previous = b"old image".to_vec();
        let replacement = b"new image bytes".to_vec();
        let sha256 = sha256_hex(&replacement);
        let fs = MemFs::with(&[(DEST, previous.as_slice())]);

        let outcome = native_apply(
            &reviewed_plan(&sha256),
            &replacement,
            &journal_path(ROOT),
            &FixedProbe::unobservable(),
            &NativeInUseProbe::new(FixedProbe::unobservable()),
            &fs,
        )
        .expect("an unobservable handle count does not block the atomic rename");

        assert_eq!(outcome.handles(), "unobservable");
        assert_eq!(fs.get(DEST).as_deref(), Some(replacement.as_slice()));
    }

    #[test]
    fn the_native_in_use_probe_reports_a_held_destination_as_busy() {
        let observed = NativeInUseProbe::new(FixedProbe::held())
            .observe(Path::new(DEST))
            .expect("the observation succeeds");
        assert_eq!(observed.as_str(), "busy");
        let InUse::Busy { fact } = observed else {
            panic!("a held destination must be reported as busy");
        };
        assert!(
            fact.contains("held open"),
            "the native observation is kept: {fact}"
        );
    }

    #[test]
    fn refuses_a_destination_that_is_still_held_open() {
        let previous = b"old image".to_vec();
        let replacement = b"new image bytes".to_vec();
        let sha256 = sha256_hex(&replacement);
        let fs = MemFs::with(&[(DEST, previous.as_slice())]);

        let error = native_apply(
            &reviewed_plan(&sha256),
            &replacement,
            &journal_path(ROOT),
            &FixedProbe::clear(),
            &NativeInUseProbe::new(FixedProbe::held()),
            &fs,
        )
        .expect_err("an in-use destination is refused");

        assert_eq!(error.code(), ErrorCode::Conflict);
        assert_eq!(rule(&error), "destination-in-use");
        assert!(error.retryable());
        assert_eq!(
            error.details().get("observed").map(String::as_str),
            Some("the destination is held open by another process")
        );
        assert_eq!(fs.get(DEST).as_deref(), Some(previous.as_slice()));
        assert!(!fs.exists(&format!("{DEST}{STAGE_TEMP_SUFFIX}")));
    }

    #[test]
    fn refuses_replacement_bytes_that_are_not_the_verified_artifact() {
        let previous = b"old image".to_vec();
        let sha256 = sha256_hex(b"new image bytes");
        let fs = MemFs::with(&[(DEST, previous.as_slice())]);

        let error = native_apply(
            &reviewed_plan(&sha256),
            b"a different payload",
            &journal_path(ROOT),
            &FixedProbe::clear(),
            &FixedInUse(InUse::Idle),
            &fs,
        )
        .expect_err("bytes that are not the artifact are refused");

        assert_eq!(rule(&error), "bytes-digest-mismatch");
        assert_eq!(fs.get(DEST).as_deref(), Some(previous.as_slice()));
        assert!(!fs.exists(&journal_path(ROOT)), "no journal was written");
    }

    #[test]
    fn refuses_a_replacement_when_no_executable_is_installed() {
        let replacement = b"new image bytes".to_vec();
        let sha256 = sha256_hex(&replacement);
        let fs = MemFs::default();

        let error = native_apply(
            &reviewed_plan(&sha256),
            &replacement,
            &journal_path(ROOT),
            &FixedProbe::clear(),
            &FixedInUse(InUse::Idle),
            &fs,
        )
        .expect_err("a fresh install belongs to the activation path");

        assert_eq!(rule(&error), "destination-missing");
        assert!(!fs.exists(&format!("{DEST}.axiom-backup")));
    }

    #[test]
    fn refuses_a_destination_that_escapes_its_install_root_through_a_link() {
        let previous = b"old image".to_vec();
        let replacement = b"new image bytes".to_vec();
        let sha256 = sha256_hex(&replacement);
        let fs = MemFs::with(&[(DEST, previous.as_slice())]);

        let error = native_apply(
            &reviewed_plan(&sha256),
            &replacement,
            &journal_path(ROOT),
            &FixedProbe::escaping_link(),
            &FixedInUse(InUse::Idle),
            &fs,
        )
        .expect_err("a link that leaves the root is refused");

        assert_eq!(error.code(), ErrorCode::UnsafePortablePath);
        assert_eq!(
            fs.get(DEST).as_deref(),
            Some(previous.as_slice()),
            "the destination is untouched after a refused boundary"
        );
        assert!(
            fs.ops().iter().all(|op| !op.starts_with("rename ")),
            "a refused boundary never reaches the cutover"
        );
    }

    #[test]
    fn refuses_a_replacement_whose_path_exceeds_the_native_limit() {
        let previous = b"old image".to_vec();
        let replacement = b"new image bytes".to_vec();
        let sha256 = sha256_hex(&replacement);
        let fs = MemFs::with(&[(DEST, previous.as_slice())]);

        let error = native_apply(
            &reviewed_plan(&sha256),
            &replacement,
            &journal_path(ROOT),
            &FixedProbe::long_path(),
            &FixedInUse(InUse::Idle),
            &fs,
        )
        .expect_err("a path past the native limit is refused");

        assert_eq!(error.code(), ErrorCode::ValidationError);
        assert_eq!(error.details().get("limit").map(String::as_str), Some("10"));
        assert_eq!(fs.get(DEST).as_deref(), Some(previous.as_slice()));
    }
    #[test]
    fn refuses_a_component_that_is_not_part_of_the_core_release() {
        let error = NativeApplyRequest::new(
            identity("skills", "1.1.0", &digest(1)),
            target(ROOT, PORTABLE, DEST, SOURCE),
        )
        .expect_err("only core components are replaced natively");
        assert_eq!(rule(&error), "unknown-component");
    }

    #[test]
    fn refuses_a_destination_outside_the_install_root() {
        let error = NativeApplyRequest::new(
            identity("axiom-graphd", "1.1.0", &digest(1)),
            target(ROOT, PORTABLE, "/etc/axiom-graphd", SOURCE),
        )
        .expect_err("a destination outside the root is refused");
        assert_eq!(rule(&error), "destination-outside-install-root");
    }

    #[test]
    fn refuses_a_non_absolute_destination() {
        let error = NativeApplyRequest::new(
            identity("axiom-graphd", "1.1.0", &digest(1)),
            target(ROOT, PORTABLE, "axiom-graphd/bin/axiom-graphd", SOURCE),
        )
        .expect_err("a relative destination is refused");
        assert_eq!(rule(&error), "destination-not-absolute");
    }

    #[test]
    fn refuses_a_portable_spelling_that_is_not_portable() {
        let error = NativeApplyRequest::new(
            identity("axiom-graphd", "1.1.0", &digest(1)),
            target(ROOT, "axiom-graphd\\bin\\axiom-graphd", DEST, SOURCE),
        )
        .expect_err("a backslash spelling is refused");
        assert_eq!(rule(&error), "unsafe-portable-path");
    }

    #[test]
    fn refuses_a_staging_source_that_is_the_destination_itself() {
        let error = NativeApplyRequest::new(
            identity("axiom-graphd", "1.1.0", &digest(1)),
            target(ROOT, PORTABLE, DEST, DEST),
        )
        .expect_err("the source must not be the destination");
        assert_eq!(rule(&error), "source-equals-destination");
    }

    #[test]
    fn refuses_an_unusable_digest_and_an_unusable_version() {
        let bad_digest = NativeApplyRequest::new(
            identity("axiom-graphd", "1.1.0", "not-a-digest"),
            target(ROOT, PORTABLE, DEST, SOURCE),
        )
        .expect_err("a digest that is not a digest is refused");
        assert_eq!(rule(&bad_digest), "invalid-digest");

        let no_version = NativeApplyRequest::new(
            identity("axiom-graphd", "  ", &digest(1)),
            target(ROOT, PORTABLE, DEST, SOURCE),
        )
        .expect_err("an empty version is refused");
        assert_eq!(rule(&no_version), "missing-version");
    }

    #[test]
    fn refuses_a_proof_and_a_release_that_describe_different_components() {
        let sha256 = digest(2);
        let mut approval = verified("1.1.0", &sha256);
        approval.component = "axiom".to_string();
        let error = plan_native_apply(
            HOST,
            &approval,
            &release("1.1.0", &sha256, &revision(), "stable"),
            &constraints(),
            Some("1.0.0"),
            target(ROOT, PORTABLE, DEST, SOURCE),
        )
        .expect_err("a mismatched component is refused");
        assert_eq!(rule(&error), "component-mismatch");
    }

    #[test]
    fn refuses_a_proof_verified_for_another_host() {
        let sha256 = digest(2);
        let error = plan_native_apply(
            "windows-x64",
            &verified("1.1.0", &sha256),
            &release("1.1.0", &sha256, &revision(), "stable"),
            &constraints(),
            Some("1.0.0"),
            target(ROOT, PORTABLE, DEST, SOURCE),
        )
        .expect_err("a proof for another host is refused");
        assert_eq!(rule(&error), "host-mismatch");
    }

    #[test]
    fn refuses_a_proof_that_is_not_the_payload_the_release_declares() {
        let error = plan_native_apply(
            HOST,
            &verified("1.1.0", &digest(3)),
            &release("1.1.0", &digest(4), &revision(), "stable"),
            &constraints(),
            Some("1.0.0"),
            target(ROOT, PORTABLE, DEST, SOURCE),
        )
        .expect_err("a mismatched artifact digest is refused");
        assert_eq!(rule(&error), "artifact-digest-mismatch");
    }

    #[test]
    fn refuses_an_incompatible_release_through_the_compatibility_contract() {
        let sha256 = digest(5);
        // A prerelease candidate is never selected on the stable channel, so the
        // compatibility set refuses it instead of this module assuming newer is
        // compatible.
        let error = plan_native_apply(
            HOST,
            &verified("1.1.0-rc.1", &sha256),
            &release("1.1.0-rc.1", &sha256, &revision(), "prerelease"),
            &constraints(),
            Some("1.0.0"),
            target(ROOT, PORTABLE, DEST, SOURCE),
        )
        .expect_err("an incompatible release is refused");
        assert_eq!(rule(&error), "no_compatible_release");
    }

    #[test]
    fn refuses_a_release_that_is_no_newer_than_the_installed_one() {
        let sha256 = digest(6);
        let error = plan_native_apply(
            HOST,
            &verified("1.0.0", &sha256),
            &release("1.0.0", &sha256, &revision(), "stable"),
            &constraints(),
            Some("1.0.0"),
            target(ROOT, PORTABLE, DEST, SOURCE),
        )
        .expect_err("an already-current release is refused");
        assert_eq!(rule(&error), "already-current");
    }

    #[test]
    fn refuses_a_release_that_is_older_than_the_installed_one() {
        let sha256 = digest(7);
        let error = plan_native_apply(
            HOST,
            &verified("0.9.0", &sha256),
            &release("0.9.0", &sha256, &revision(), "stable"),
            &constraints(),
            Some("1.0.0"),
            target(ROOT, PORTABLE, DEST, SOURCE),
        )
        .expect_err("a downgrade is refused");
        assert_eq!(rule(&error), "no_compatible_release");
    }

    #[test]
    fn refuses_a_release_without_a_revision() {
        let sha256 = digest(8);
        let error = plan_native_apply(
            HOST,
            &verified("1.1.0", &sha256),
            &release("1.1.0", &sha256, "", "stable"),
            &constraints(),
            Some("1.0.0"),
            target(ROOT, PORTABLE, DEST, SOURCE),
        )
        .expect_err("a release without a revision is refused");
        assert_eq!(rule(&error), "missing-revision");
    }
    #[test]
    fn rolls_back_to_the_bytes_the_journal_recorded() {
        let previous = b"old image".to_vec();
        let replacement = b"new image bytes".to_vec();
        let sha256 = sha256_hex(&replacement);
        let fs = MemFs::with(&[(DEST, previous.as_slice())]);
        let journal = journal_path(ROOT);
        native_apply(
            &reviewed_plan(&sha256),
            &replacement,
            &journal,
            &FixedProbe::clear(),
            &FixedInUse(InUse::Idle),
            &fs,
        )
        .expect("the replacement succeeds");

        let outcome =
            rollback_native_apply(&journal, "axiom-graphd", &fs).expect("the rollback succeeds");

        assert_eq!(outcome.component(), "axiom-graphd");
        assert_eq!(outcome.destination_path(), DEST);
        assert_eq!(outcome.restored_sha256(), sha256_hex(&previous));
        assert_eq!(outcome.bytes(), previous.len() as u64);
        assert_eq!(fs.get(DEST).as_deref(), Some(previous.as_slice()));
    }

    #[test]
    fn refuses_a_journal_that_is_missing_unreadable_or_of_another_schema() {
        let empty = MemFs::default();
        let missing = rollback_native_apply(JOURNAL, "axiom-graphd", &empty)
            .expect_err("a missing journal is refused");
        assert_eq!(rule(&missing), "journal-missing");

        let unreadable = MemFs::with(&[(JOURNAL, b"not json".as_slice())]);
        let error = rollback_native_apply(JOURNAL, "axiom-graphd", &unreadable)
            .expect_err("an unreadable journal is refused");
        assert_eq!(rule(&error), "journal-unreadable");

        let document = journal_document("axiom-graphd", 2, Some(BACKUP), Some(&digest(9)));
        let schema = MemFs::with(&[(JOURNAL, document.as_slice())]);
        let error = rollback_native_apply(JOURNAL, "axiom-graphd", &schema)
            .expect_err("another schema version is refused");
        assert_eq!(rule(&error), "journal-schema-unsupported");
    }

    #[test]
    fn refuses_a_journal_that_belongs_to_another_component() {
        let document = journal_document("axiom", 1, Some(BACKUP), Some(&digest(9)));
        let fs = MemFs::with(&[
            (JOURNAL, document.as_slice()),
            (BACKUP, b"old image".as_slice()),
        ]);
        let error = rollback_native_apply(JOURNAL, "axiom-graphd", &fs)
            .expect_err("another component's journal is refused");
        assert_eq!(rule(&error), "journal-component-mismatch");
    }

    #[test]
    fn refuses_a_journal_that_recorded_no_backup() {
        let document = journal_document("axiom-graphd", 1, None, None);
        let fs = MemFs::with(&[(JOURNAL, document.as_slice())]);
        let error = rollback_native_apply(JOURNAL, "axiom-graphd", &fs)
            .expect_err("a journal without a backup is refused");
        assert_eq!(rule(&error), "journal-has-no-backup");
    }

    #[test]
    fn refuses_a_backup_that_is_gone_or_does_not_match_the_journal() {
        let document = journal_document("axiom-graphd", 1, Some(BACKUP), Some(&digest(9)));
        let gone = MemFs::with(&[(JOURNAL, document.as_slice())]);
        let error = rollback_native_apply(JOURNAL, "axiom-graphd", &gone)
            .expect_err("a missing backup is refused");
        assert_eq!(rule(&error), "backup-missing");

        let tampered = MemFs::with(&[
            (JOURNAL, document.as_slice()),
            (BACKUP, b"tampered image".as_slice()),
        ]);
        let error = rollback_native_apply(JOURNAL, "axiom-graphd", &tampered)
            .expect_err("a backup that is not the recorded bytes is refused");
        assert_eq!(rule(&error), "backup-digest-mismatch");
        assert_eq!(
            tampered.get(BACKUP).as_deref(),
            Some(b"tampered image".as_slice()),
            "a refused rollback writes nothing"
        );
    }

    #[test]
    fn refuses_an_oversized_journal() {
        let oversized = vec![b' '; super::MAX_JOURNAL_BYTES + 1];
        let fs = MemFs::with(&[(JOURNAL, oversized.as_slice())]);
        let error = rollback_native_apply(JOURNAL, "axiom-graphd", &fs)
            .expect_err("an oversized journal is refused");
        assert_eq!(rule(&error), "journal-too-large");
    }

    #[test]
    fn every_phase_and_rule_has_a_distinct_stable_spelling() {
        let mut phases: Vec<&str> = APPLY_PHASES.iter().map(|phase| phase.as_str()).collect();
        phases.sort_unstable();
        phases.dedup();
        assert_eq!(phases, ["cutover", "fence", "journal", "stage", "verify"]);

        let mut rules = REFUSAL_RULES.to_vec();
        rules.sort_unstable();
        rules.dedup();
        assert_eq!(rules.len(), REFUSAL_RULES.len(), "rules must be distinct");
        for entry in REFUSAL_RULES {
            assert!(
                !entry.is_empty()
                    && entry
                        .chars()
                        .all(|character| character.is_ascii_lowercase() || character == '-'),
                "unstable rule spelling: {entry}"
            );
            assert!(
                !entry.starts_with('-') && !entry.ends_with('-'),
                "unstable rule spelling: {entry}"
            );
        }
    }
}
