//! Deterministic, ownership-aware migration plan (V2-010).
//!
//! [`crate::discover`] decides *whether* a V1 to V2 migration may run. This
//! module turns that decision into one reviewable plan and refuses to apply a
//! plan whose inputs moved underneath it. It implements
//! `migrations/V1-TO-V2.md` sections 2 and 3 and
//! `contracts/cross-platform-v2.md` CP-03:
//!
//! - the plan inventories the exact source hashes it was built from, so it is a
//!   statement about immutable bytes rather than about a directory listing;
//! - the plan digest is an *approval binding*, not publisher authentication, so
//!   the caller must echo the digest it reviewed;
//! - application is refused when a source changed, appeared or disappeared, when
//!   the plan carries an unresolved conflict, when the plan expired, or when the
//!   approved digest is not this plan's digest;
//! - human-owned text is carried as preserved text with a proven ownership hash
//!   or an explicit human review, and is never rewritten on an assertion.
//!
//! As in the discovery half, this module performs no filesystem access: the
//! adapter supplies the observed hashes and the module returns the writes a
//! caller may perform, so "no destination writes" is structural.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;

use axiom_platform::{PathKey, PathKeyError};
use graph_core::error::{AxiomError, ErrorCode};
use sha2::{Digest, Sha256};

use crate::discover::{DiscoveryDecision, ERR_MIGRATION_CONFLICT, LEGACY_MARKERS};

/// Schema version of the plan this module builds.
pub const PLAN_SCHEMA_VERSION: u32 = 1;

/// Stable code: the plan's inputs are no longer the bytes it recorded.
pub const ERR_STALE_PLAN: &str = "MIGRATION_PLAN_STALE";
/// Stable code: the digest the caller approved is not this plan's digest.
pub const ERR_PLAN_APPROVAL: &str = "MIGRATION_PLAN_APPROVAL_MISMATCH";
/// Stable code: a recorded hash is not a lowercase SHA-256 hex digest.
pub const ERR_PLAN_HASH: &str = "MIGRATION_PLAN_INVALID_HASH";
/// Stable code: one path appears twice in one plan section.
pub const ERR_PLAN_DUPLICATE: &str = "MIGRATION_PLAN_DUPLICATE_PATH";
/// Stable code: the plan was refused as a plan, before anything was compared.
pub const ERR_PLAN_INVALID: &str = "MIGRATION_PLAN_INVALID";
/// Stable code: the plan is past its declared expiry.
pub const ERR_PLAN_EXPIRED: &str = "MIGRATION_PLAN_EXPIRED";
/// Stable code: a change is not derivable from the plan's own sources.
pub const ERR_PLAN_UNRESOLVED: &str = "MIGRATION_PLAN_UNRESOLVED_CHANGE";

/// Building, approving and applying a plan writes no destination bytes.
pub const PLAN_WRITES_NOTHING: bool = true;

/// One validated SHA-256 content hash: lowercase hex, exactly 64 characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentHash(String);

impl ContentHash {
    /// Validate one observed hash.
    ///
    /// # Errors
    /// [`PlanError::InvalidHash`] when the value is not 64 lowercase hex
    /// characters, which includes the placeholder spellings a hand-edited plan
    /// tends to carry.
    pub fn parse(value: &str) -> Result<Self, PlanError> {
        let valid = value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !valid {
            return Err(PlanError::InvalidHash {
                path: None,
                value: value.to_string(),
            });
        }
        Ok(Self(value.to_string()))
    }

    /// The digest of a byte sequence, as the lowercase hex this type accepts.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut text = String::with_capacity(64);
        for byte in digest {
            let _ = write!(text, "{byte:02x}");
        }
        Self(text)
    }

    /// The exact recorded spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One source artifact and the exact hash the adapter observed for it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceArtifact {
    path: PathKey,
    sha256: ContentHash,
    size_bytes: u64,
}

impl SourceArtifact {
    /// Record one observed source file.
    ///
    /// # Errors
    /// [`PlanError::UnsafePath`] when `path` is not a portable repository-relative
    /// path, and [`PlanError::InvalidHash`] when `sha256` is not a SHA-256 hex
    /// digest. Both refuse instead of rewriting the value.
    pub fn new(path: &str, sha256: &str, size_bytes: u64) -> Result<Self, PlanError> {
        let key = PathKey::new(path).map_err(PlanError::UnsafePath)?;
        let hash = ContentHash::parse(sha256).map_err(|_| PlanError::InvalidHash {
            path: Some(path.to_string()),
            value: sha256.to_string(),
        })?;
        Ok(Self {
            path: key,
            sha256: hash,
            size_bytes,
        })
    }

    /// The exact source spelling.
    #[must_use]
    pub fn path(&self) -> &str {
        self.path.as_str()
    }

    /// The content hash the plan was built from.
    #[must_use]
    pub fn sha256(&self) -> &ContentHash {
        &self.sha256
    }

    /// Observed size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

/// What the plan will do to one destination path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeAction {
    /// The destination does not exist yet.
    Create,
    /// The destination exists and Axiom owns it.
    Replace,
    /// A derived artifact is rebuilt from the sources rather than copied.
    Regenerate,
}

impl ChangeAction {
    /// Stable spelling used in plans, diagnostics and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Replace => "replace",
            Self::Regenerate => "regenerate",
        }
    }
}

impl fmt::Display for ChangeAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Who owns the destination bytes the plan is about to touch.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DestinationOwnership {
    /// Axiom owns the destination. `previous_sha256` is present exactly when the
    /// destination already exists, which is what distinguishes a create from a
    /// replace instead of trusting the caller's word.
    Managed {
        /// Hash of the bytes found at the destination, when there are any.
        previous_sha256: Option<ContentHash>,
    },
    /// The human owns the destination. The plan records it as preserved text
    /// instead of changing it.
    HumanOwned,
}

/// One planned destination change.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DestinationChange {
    path: PathKey,
    action: ChangeAction,
    source: Option<PathKey>,
    ownership: DestinationOwnership,
}

impl DestinationChange {
    /// Record one planned change.
    ///
    /// # Errors
    /// [`PlanError::UnsafePath`] for a spelling that is not portable, and
    /// [`PlanError::UnresolvedChange`] for a shape that cannot be applied: a
    /// `Create`/`Replace` must name a source, a `Regenerate` must not, a
    /// human-owned destination is never changed, a `Create` must not claim
    /// previous bytes, and a `Replace` must record them.
    pub fn new(
        path: &str,
        action: ChangeAction,
        source: Option<&str>,
        ownership: DestinationOwnership,
    ) -> Result<Self, PlanError> {
        let key = PathKey::new(path).map_err(PlanError::UnsafePath)?;
        let source = match source {
            Some(value) => Some(PathKey::new(value).map_err(PlanError::UnsafePath)?),
            None => None,
        };
        let change = Self {
            path: key,
            action,
            source,
            ownership,
        };
        change.validate_shape()?;
        Ok(change)
    }

    fn validate_shape(&self) -> Result<(), PlanError> {
        let refuse = |rule: &'static str| {
            Err(PlanError::UnresolvedChange {
                path: self.path.as_str().to_string(),
                rule,
            })
        };
        match &self.ownership {
            DestinationOwnership::HumanOwned => refuse("human-owned-destination"),
            DestinationOwnership::Managed { previous_sha256 } => match self.action {
                ChangeAction::Regenerate => {
                    if self.source.is_some() {
                        refuse("regenerate-takes-no-source")
                    } else {
                        Ok(())
                    }
                }
                ChangeAction::Create => {
                    if self.source.is_none() {
                        refuse("create-needs-a-source")
                    } else if previous_sha256.is_some() {
                        refuse("create-claims-previous-bytes")
                    } else {
                        Ok(())
                    }
                }
                ChangeAction::Replace => {
                    if self.source.is_none() {
                        refuse("replace-needs-a-source")
                    } else if previous_sha256.is_none() {
                        refuse("replace-without-previous-bytes")
                    } else {
                        Ok(())
                    }
                }
            },
        }
    }

    /// The exact destination spelling.
    #[must_use]
    pub fn path(&self) -> &str {
        self.path.as_str()
    }

    /// What will be done to the destination.
    #[must_use]
    pub const fn action(&self) -> ChangeAction {
        self.action
    }

    /// The source the destination bytes come from, when they come from one.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.source.as_ref().map(PathKey::as_str)
    }

    /// Who owns the destination.
    #[must_use]
    pub fn ownership(&self) -> &DestinationOwnership {
        &self.ownership
    }
}

/// Why human text may be moved at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OwnershipProof {
    /// A proven ownership hash from the marker pair, as V1-TO-V2 section 3 requires.
    ProvenHash,
    /// An explicit human review decision recorded in the plan.
    ExplicitHumanReview,
}

impl OwnershipProof {
    /// Stable spelling used in plans, diagnostics and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProvenHash => "proven-ownership-hash",
            Self::ExplicitHumanReview => "explicit-human-review",
        }
    }
}

/// Human text the migration must not lose.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PreservedText {
    path: PathKey,
    sha256: ContentHash,
    proof: OwnershipProof,
    begin_marker: String,
    end_marker: String,
}

impl PreservedText {
    /// Record one preserved block of human text.
    ///
    /// # Errors
    /// [`PlanError::UnsafePath`] for a spelling that is not portable, and
    /// [`PlanError::InvalidHash`] when the recorded ownership hash is not a
    /// SHA-256 hex digest: a preserved block without a proven hash is exactly the
    /// case V1-TO-V2 section 3 leaves to a human.
    pub fn new(
        path: &str,
        sha256: &str,
        proof: OwnershipProof,
        begin_marker: &str,
        end_marker: &str,
    ) -> Result<Self, PlanError> {
        let key = PathKey::new(path).map_err(PlanError::UnsafePath)?;
        let hash = ContentHash::parse(sha256).map_err(|_| PlanError::InvalidHash {
            path: Some(path.to_string()),
            value: sha256.to_string(),
        })?;
        Ok(Self {
            path: key,
            sha256: hash,
            proof,
            begin_marker: begin_marker.to_string(),
            end_marker: end_marker.to_string(),
        })
    }

    /// The exact spelling of the file the human text lives in.
    #[must_use]
    pub fn path(&self) -> &str {
        self.path.as_str()
    }

    /// Hash of the preserved bytes.
    #[must_use]
    pub fn sha256(&self) -> &ContentHash {
        &self.sha256
    }

    /// Why the text may be moved.
    #[must_use]
    pub const fn proof(&self) -> OwnershipProof {
        self.proof
    }

    /// The recorded begin marker.
    #[must_use]
    pub fn begin_marker(&self) -> &str {
        &self.begin_marker
    }

    /// The recorded end marker.
    #[must_use]
    pub fn end_marker(&self) -> &str {
        &self.end_marker
    }

    /// True when the pair is exactly the legacy template marker pair.
    #[must_use]
    pub fn uses_legacy_markers(&self) -> bool {
        self.begin_marker == LEGACY_MARKERS[0] && self.end_marker == LEGACY_MARKERS[1]
    }
}

/// One unresolved conflict. A plan that carries any is not applicable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlanConflict {
    rule: &'static str,
    path: Option<String>,
    detail: String,
}

impl PlanConflict {
    /// Record one conflict that needs a human decision.
    #[must_use]
    pub fn new(rule: &'static str, path: Option<&str>, detail: &str) -> Self {
        Self {
            rule,
            path: path.map(str::to_string),
            detail: detail.to_string(),
        }
    }

    /// The stable rule name.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        self.rule
    }

    /// The path the conflict is about, when it is about one.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// What was observed.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for PlanConflict {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(path) => write!(formatter, "{}: {} ({path})", self.rule, self.detail),
            None => write!(formatter, "{}: {}", self.rule, self.detail),
        }
    }
}

/// One repository's slice of the migration plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoPlan {
    repo_id: String,
    decision: DiscoveryDecision,
    sources: Vec<SourceArtifact>,
    changes: Vec<DestinationChange>,
    preserved: Vec<PreservedText>,
    conflicts: Vec<PlanConflict>,
}

impl RepoPlan {
    /// Start the plan for one repository under one discovery decision.
    ///
    /// # Errors
    /// [`PlanError::Invalid`] when `repo_id` is not a portable stable id.
    pub fn new(repo_id: &str, decision: DiscoveryDecision) -> Result<Self, PlanError> {
        if !is_portable_id(repo_id) {
            return Err(PlanError::Invalid {
                rule: "repo-id",
                detail: format!("{repo_id:?} is not a portable repository id"),
            });
        }
        Ok(Self {
            repo_id: repo_id.to_string(),
            decision,
            sources: Vec::new(),
            changes: Vec::new(),
            preserved: Vec::new(),
            conflicts: Vec::new(),
        })
    }

    /// The stable repository/solution id.
    #[must_use]
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    /// The discovery decision this slice was built for.
    #[must_use]
    pub fn decision(&self) -> &DiscoveryDecision {
        &self.decision
    }

    /// The inventoried sources, sorted by path.
    #[must_use]
    pub fn sources(&self) -> &[SourceArtifact] {
        &self.sources
    }

    /// The planned destination changes, sorted by path.
    #[must_use]
    pub fn changes(&self) -> &[DestinationChange] {
        &self.changes
    }

    /// The preserved human text, sorted by path.
    #[must_use]
    pub fn preserved(&self) -> &[PreservedText] {
        &self.preserved
    }

    /// The unresolved conflicts, sorted by rule and path.
    #[must_use]
    pub fn conflicts(&self) -> &[PlanConflict] {
        &self.conflicts
    }

    /// Inventory one source artifact.
    ///
    /// # Errors
    /// [`PlanError::DuplicatePath`] when the path is already inventoried: a plan
    /// that names one source twice cannot say which hash proves it.
    pub fn add_source(&mut self, artifact: SourceArtifact) -> Result<(), PlanError> {
        if self.sources.iter().any(|known| known.path == artifact.path) {
            return Err(PlanError::DuplicatePath {
                section: "sources",
                path: artifact.path().to_string(),
            });
        }
        self.sources.push(artifact);
        Ok(())
    }

    /// Add one planned destination change.
    ///
    /// # Errors
    /// [`PlanError::DuplicatePath`] when the destination is already planned, and
    /// [`PlanError::UnresolvedChange`] when the destination already carries
    /// preserved human text. Both refuse rather than pick a winner.
    pub fn add_change(&mut self, change: DestinationChange) -> Result<(), PlanError> {
        if self.changes.iter().any(|known| known.path == change.path) {
            return Err(PlanError::DuplicatePath {
                section: "changes",
                path: change.path().to_string(),
            });
        }
        if self
            .preserved
            .iter()
            .any(|known| known.path.as_str() == change.path())
        {
            return Err(PlanError::UnresolvedChange {
                path: change.path().to_string(),
                rule: "preserved-text-would-be-overwritten",
            });
        }
        self.changes.push(change);
        Ok(())
    }

    /// Record one block of preserved human text.
    ///
    /// # Errors
    /// [`PlanError::DuplicatePath`] when the file already carries preserved text,
    /// and [`PlanError::UnresolvedChange`] when the same path is already planned
    /// for a change.
    pub fn preserve(&mut self, text: PreservedText) -> Result<(), PlanError> {
        if self.preserved.iter().any(|known| known.path == text.path) {
            return Err(PlanError::DuplicatePath {
                section: "preserved",
                path: text.path().to_string(),
            });
        }
        if self.changes.iter().any(|known| known.path() == text.path()) {
            return Err(PlanError::UnresolvedChange {
                path: text.path().to_string(),
                rule: "planned-change-would-overwrite-human-text",
            });
        }
        self.preserved.push(text);
        Ok(())
    }

    /// Record one conflict that needs a human decision.
    pub fn add_conflict(&mut self, conflict: PlanConflict) {
        self.conflicts.push(conflict);
    }

    /// True when this slice found nothing to do and nothing to resolve.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.sources.is_empty() && self.changes.is_empty() && self.conflicts.is_empty()
    }

    /// Sort every section into the one order the plan digest is computed over.
    fn normalize(&mut self) {
        self.sources.sort();
        self.changes.sort();
        self.preserved.sort();
        self.conflicts.sort();
    }

    /// Confirm each change is derivable from this slice's own inventory.
    fn validate(&self) -> Result<(), PlanError> {
        for change in &self.changes {
            if let Some(source) = change.source() {
                if !self.sources.iter().any(|known| known.path() == source) {
                    return Err(PlanError::UnresolvedChange {
                        path: change.path().to_string(),
                        rule: "source-not-inventoried",
                    });
                }
            }
        }
        Ok(())
    }

    /// Refuse when the bytes this slice recorded are no longer the bytes on disk.
    ///
    /// # Errors
    /// [`PlanError::Stale`] when a recorded source is missing or changed, or when
    /// the current listing holds a path the plan never inventoried. A new input is
    /// as much a reason to re-review a plan as a modified one.
    pub fn verify_against(&self, current: &CurrentSources) -> Result<(), PlanError> {
        for source in &self.sources {
            match current.hash_of(&self.repo_id, source.path()) {
                None => {
                    return Err(PlanError::Stale {
                        rule: "source-missing",
                        path: Some(source.path().to_string()),
                        detail: "the plan inventoried a source that is no longer present"
                            .to_string(),
                    })
                }
                Some(hash) if hash != source.sha256() => {
                    return Err(PlanError::Stale {
                        rule: "source-changed",
                        path: Some(source.path().to_string()),
                        detail: format!(
                            "the plan recorded {} but the source now hashes to {hash}",
                            source.sha256()
                        ),
                    })
                }
                Some(_) => {}
            }
        }
        for path in current.paths_of(&self.repo_id) {
            if !self.sources.iter().any(|known| known.path() == path) {
                return Err(PlanError::Stale {
                    rule: "source-appeared",
                    path: Some(path.to_string()),
                    detail: "a source appeared that the plan never inventoried".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// The hashes an adapter observed right now, grouped per repository id.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CurrentSources {
    repositories: BTreeMap<String, BTreeMap<String, ContentHash>>,
}

impl CurrentSources {
    /// An empty observation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one observed source file.
    ///
    /// # Errors
    /// [`PlanError::Invalid`] for a non-portable repository id, and
    /// [`PlanError::UnsafePath`] or [`PlanError::InvalidHash`] for the path and
    /// hash, so an observation cannot smuggle in a spelling the plan could not
    /// carry.
    pub fn observe(&mut self, repo_id: &str, path: &str, sha256: &str) -> Result<(), PlanError> {
        if !is_portable_id(repo_id) {
            return Err(PlanError::Invalid {
                rule: "repo-id",
                detail: format!("{repo_id:?} is not a portable repository id"),
            });
        }
        let key = PathKey::new(path).map_err(PlanError::UnsafePath)?;
        let hash = ContentHash::parse(sha256).map_err(|_| PlanError::InvalidHash {
            path: Some(path.to_string()),
            value: sha256.to_string(),
        })?;
        self.repositories
            .entry(repo_id.to_string())
            .or_default()
            .insert(key.into_string(), hash);
        Ok(())
    }

    /// The hash observed for one repository-relative path.
    #[must_use]
    pub fn hash_of(&self, repo_id: &str, path: &str) -> Option<&ContentHash> {
        self.repositories.get(repo_id)?.get(path)
    }

    /// The paths observed for one repository, sorted.
    #[must_use]
    pub fn paths_of(&self, repo_id: &str) -> Vec<&str> {
        self.repositories
            .get(repo_id)
            .map(|paths| paths.keys().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// The repository ids observed, sorted.
    #[must_use]
    pub fn repositories(&self) -> Vec<&str> {
        self.repositories.keys().map(String::as_str).collect()
    }

    /// How many sources were observed, across every repository.
    #[must_use]
    pub fn len(&self) -> usize {
        self.repositories.values().map(BTreeMap::len).sum()
    }

    /// True when nothing was observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One write a verified plan authorises.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlannedWrite {
    repo_id: String,
    path: String,
    action: ChangeAction,
    source: Option<String>,
}

impl PlannedWrite {
    /// The repository the write belongs to.
    #[must_use]
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    /// The exact destination spelling.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// What will be done to the destination.
    #[must_use]
    pub const fn action(&self) -> ChangeAction {
        self.action
    }

    /// The source the bytes come from, when they come from one.
    #[must_use]
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }
}

/// One reviewable, deterministic V1 to V2 migration plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPlan {
    schema_version: u32,
    solution_id: String,
    created_epoch_seconds: i64,
    expires_epoch_seconds: i64,
    repositories: Vec<RepoPlan>,
    digest: ContentHash,
}

/// Build the one plan for one solution.
///
/// # Errors
/// [`PlanError::Invalid`] for a non-portable solution id, a negative creation
/// time or a non-positive lifetime; [`PlanError::DuplicatePath`] when one
/// repository is planned twice; and whatever [`RepoPlan::validate`] refuses.
pub fn build_plan(
    solution_id: &str,
    created_epoch_seconds: i64,
    ttl_seconds: i64,
    mut repositories: Vec<RepoPlan>,
) -> Result<MigrationPlan, PlanError> {
    if !is_portable_id(solution_id) {
        return Err(PlanError::Invalid {
            rule: "solution-id",
            detail: format!("{solution_id:?} is not a portable solution id"),
        });
    }
    if created_epoch_seconds < 0 {
        return Err(PlanError::Invalid {
            rule: "plan-created",
            detail: format!("{created_epoch_seconds} is not a creation time in seconds"),
        });
    }
    if ttl_seconds <= 0 {
        return Err(PlanError::Invalid {
            rule: "plan-ttl",
            detail: format!("{ttl_seconds} is not a positive plan lifetime"),
        });
    }

    let mut seen: Vec<&str> = Vec::new();
    for repo in &repositories {
        if seen.contains(&repo.repo_id()) {
            return Err(PlanError::DuplicatePath {
                section: "repositories",
                path: repo.repo_id().to_string(),
            });
        }
        seen.push(repo.repo_id());
    }

    repositories.sort_by(|left, right| left.repo_id.cmp(&right.repo_id));
    for repo in &mut repositories {
        repo.normalize();
        repo.validate()?;
    }

    let expires_epoch_seconds = created_epoch_seconds + ttl_seconds;
    let digest = plan_digest(
        solution_id,
        created_epoch_seconds,
        expires_epoch_seconds,
        &repositories,
    );

    Ok(MigrationPlan {
        schema_version: PLAN_SCHEMA_VERSION,
        solution_id: solution_id.to_string(),
        created_epoch_seconds,
        expires_epoch_seconds,
        repositories,
        digest,
    })
}

impl MigrationPlan {
    /// The schema version of this plan.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// The stable solution id the plan was built for.
    #[must_use]
    pub fn solution_id(&self) -> &str {
        &self.solution_id
    }

    /// When the plan was built.
    #[must_use]
    pub const fn created_epoch_seconds(&self) -> i64 {
        self.created_epoch_seconds
    }

    /// When the plan stops being applicable.
    #[must_use]
    pub const fn expires_epoch_seconds(&self) -> i64 {
        self.expires_epoch_seconds
    }

    /// The per-repository slices, sorted by repository id.
    #[must_use]
    pub fn repositories(&self) -> &[RepoPlan] {
        &self.repositories
    }

    /// The digest a reviewer approves.
    #[must_use]
    pub fn digest(&self) -> &ContentHash {
        &self.digest
    }

    /// True when `now_seconds` is at or past the declared expiry.
    #[must_use]
    pub const fn is_expired(&self, now_seconds: i64) -> bool {
        now_seconds >= self.expires_epoch_seconds
    }

    /// Every conflict the plan carries, in plan order.
    #[must_use]
    pub fn conflicts(&self) -> Vec<&PlanConflict> {
        self.repositories
            .iter()
            .flat_map(|repo| repo.conflicts.iter())
            .collect()
    }

    /// How many conflicts the plan carries.
    #[must_use]
    pub fn conflict_count(&self) -> usize {
        self.repositories
            .iter()
            .map(|repo| repo.conflicts.len())
            .sum()
    }

    /// Every source the plan inventoried, as `(repo_id, path, sha256)`.
    #[must_use]
    pub fn source_hashes(&self) -> Vec<(&str, &str, &str)> {
        self.repositories
            .iter()
            .flat_map(|repo| {
                repo.sources
                    .iter()
                    .map(move |source| (repo.repo_id(), source.path(), source.sha256.as_str()))
            })
            .collect()
    }

    /// Confirm a human approved this exact revision of the plan.
    ///
    /// # Errors
    /// [`PlanError::ApprovalMismatch`] when the reviewed digest is not this
    /// plan's digest.
    pub fn approve(&self, reviewed_digest: &str) -> Result<(), PlanError> {
        if reviewed_digest != self.digest.as_str() {
            return Err(PlanError::ApprovalMismatch {
                expected: self.digest.as_str().to_string(),
                supplied: reviewed_digest.to_string(),
            });
        }
        Ok(())
    }

    /// Every write the plan authorises, in plan order.
    #[must_use]
    pub fn planned_writes(&self) -> Vec<PlannedWrite> {
        self.repositories
            .iter()
            .flat_map(|repo| {
                repo.changes.iter().map(move |change| PlannedWrite {
                    repo_id: repo.repo_id().to_string(),
                    path: change.path().to_string(),
                    action: change.action,
                    source: change.source().map(str::to_string),
                })
            })
            .collect()
    }

    /// The writes this plan authorises against the bytes on disk right now.
    ///
    /// The refusals are ordered from the caller's own error to the state's, so the
    /// first message a reviewer sees is the one they can fix.
    ///
    /// # Errors
    /// [`PlanError::ApprovalMismatch`] when the reviewed digest is not this
    /// plan's; [`PlanError::Blocked`] when an unresolved conflict remains;
    /// [`PlanError::Expired`] when the plan is past its expiry; and
    /// [`PlanError::Stale`] when the observed sources differ in any way.
    pub fn apply(
        &self,
        reviewed_digest: &str,
        current: &CurrentSources,
        now_seconds: i64,
    ) -> Result<Vec<PlannedWrite>, PlanError> {
        self.approve(reviewed_digest)?;
        let conflicts = self.conflict_count();
        if conflicts > 0 {
            return Err(PlanError::Blocked { conflicts });
        }
        if self.is_expired(now_seconds) {
            return Err(PlanError::Expired {
                expired_at: self.expires_epoch_seconds,
                now: now_seconds,
            });
        }
        for repo in &self.repositories {
            repo.verify_against(current)?;
        }
        Ok(self.planned_writes())
    }
}

/// Append one length-prefixed field to the canonical plan encoding.
///
/// The encoding is `len:bytes\n`, so no field value can be confused with a
/// separator and two different plans cannot encode to the same bytes.
pub(crate) fn write_field(out: &mut String, value: &str) {
    let _ = writeln!(out, "{}:{}", value.len(), value);
}

/// The canonical digest of a plan's exact contents.
///
/// The digest is an approval binding: it fixes the bytes a reviewer accepted, so
/// a plan rebuilt with different inputs necessarily has a different digest.
fn plan_digest(
    solution_id: &str,
    created_epoch_seconds: i64,
    expires_epoch_seconds: i64,
    repositories: &[RepoPlan],
) -> ContentHash {
    let mut out = String::new();
    write_field(&mut out, "axiom-migration-plan");
    write_field(&mut out, &PLAN_SCHEMA_VERSION.to_string());
    write_field(&mut out, solution_id);
    write_field(&mut out, &created_epoch_seconds.to_string());
    write_field(&mut out, &expires_epoch_seconds.to_string());
    write_field(&mut out, &repositories.len().to_string());
    for repo in repositories {
        write_field(&mut out, "repo");
        write_field(&mut out, repo.repo_id());
        write_field(&mut out, &describe(&repo.decision));

        write_field(&mut out, &repo.sources.len().to_string());
        for source in &repo.sources {
            write_field(&mut out, "source");
            write_field(&mut out, source.path());
            write_field(&mut out, source.sha256().as_str());
            write_field(&mut out, &source.size_bytes().to_string());
        }

        write_field(&mut out, &repo.changes.len().to_string());
        for change in &repo.changes {
            write_field(&mut out, "change");
            write_field(&mut out, change.path());
            write_field(&mut out, change.action().as_str());
            write_field(&mut out, change.source().unwrap_or(""));
            match change.ownership() {
                DestinationOwnership::Managed { previous_sha256 } => {
                    write_field(&mut out, "managed");
                    write_field(
                        &mut out,
                        previous_sha256.as_ref().map_or("", ContentHash::as_str),
                    );
                }
                DestinationOwnership::HumanOwned => {
                    write_field(&mut out, "human-owned");
                    write_field(&mut out, "");
                }
            }
        }

        write_field(&mut out, &repo.preserved.len().to_string());
        for text in &repo.preserved {
            write_field(&mut out, "preserved");
            write_field(&mut out, text.path());
            write_field(&mut out, text.sha256().as_str());
            write_field(&mut out, text.proof().as_str());
            write_field(&mut out, text.begin_marker());
            write_field(&mut out, text.end_marker());
        }

        write_field(&mut out, &repo.conflicts.len().to_string());
        for conflict in &repo.conflicts {
            write_field(&mut out, "conflict");
            write_field(&mut out, conflict.rule());
            write_field(&mut out, conflict.path().unwrap_or(""));
            write_field(&mut out, conflict.detail());
        }
    }
    ContentHash::of_bytes(out.as_bytes())
}

/// The stable spelling of one discovery decision inside the plan digest.
fn describe(decision: &DiscoveryDecision) -> String {
    match decision {
        DiscoveryDecision::Fresh => "fresh".to_string(),
        DiscoveryDecision::Import { source } => format!("import:{}", source.as_str()),
        DiscoveryDecision::Deduplicate { sources, target } => {
            let mut names: Vec<&str> = sources.iter().map(|layout| layout.as_str()).collect();
            names.sort_unstable();
            format!("deduplicate:{}:{}", names.join("+"), target.as_str())
        }
        DiscoveryDecision::AlreadyMigrated {
            axiom,
            legacy_leftovers,
        } => {
            let mut names: Vec<&str> = legacy_leftovers
                .iter()
                .map(|layout| layout.as_str())
                .collect();
            names.sort_unstable();
            format!("already-migrated:{}:{}", axiom.as_str(), names.join("+"))
        }
    }
}

/// True when `value` is a portable lowercase-ASCII slug: non-empty, at most 128
/// characters, and drawn from `[a-z0-9._-]` after a lowercase-or-digit first
/// character. This is the seam `contracts/cross-platform-v2.md` CP-03 shares
/// with the platform path key.
pub(crate) fn is_portable_id(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 {
        return false;
    }
    let first = value.as_bytes()[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    value.as_bytes().iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'.' | b'_' | b'-')
    })
}

/// Why a plan could not be built, approved or applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// A recorded hash is not a lowercase SHA-256 hex digest.
    InvalidHash {
        /// The path the hash belongs to, when it belongs to one.
        path: Option<String>,
        /// The rejected spelling.
        value: String,
    },
    /// One path appears twice in one plan section.
    DuplicatePath {
        /// The plan section that repeated the path.
        section: &'static str,
        /// The repeated path.
        path: String,
    },
    /// The plan was refused as a plan, before anything was compared.
    Invalid {
        /// The stable rule that refused it.
        rule: &'static str,
        /// What was observed.
        detail: String,
    },
    /// The bytes the plan recorded are no longer the bytes on disk.
    Stale {
        /// The stable rule that detected the drift.
        rule: &'static str,
        /// The path that drifted, when one did.
        path: Option<String>,
        /// What was observed.
        detail: String,
    },
    /// An unresolved conflict remains, so the plan is not applicable.
    Blocked {
        /// How many conflicts the plan carries.
        conflicts: usize,
    },
    /// The plan is past its declared expiry.
    Expired {
        /// The instant the plan expired.
        expired_at: i64,
        /// The instant the caller asked to apply it.
        now: i64,
    },
    /// The digest the caller approved is not this plan's digest.
    ApprovalMismatch {
        /// This plan's digest.
        expected: String,
        /// The digest the caller supplied.
        supplied: String,
    },
    /// A change or a preserved block is not derivable from the plan itself.
    UnresolvedChange {
        /// The path in question.
        path: String,
        /// The stable rule that refused it.
        rule: &'static str,
    },
    /// A path is not a portable repository-relative path.
    UnsafePath(PathKeyError),
}

impl PlanError {
    /// The stable wire code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidHash { .. } => ERR_PLAN_HASH,
            Self::DuplicatePath { .. } => ERR_PLAN_DUPLICATE,
            Self::Invalid { .. } => ERR_PLAN_INVALID,
            Self::Stale { .. } => ERR_STALE_PLAN,
            Self::Blocked { .. } => ERR_MIGRATION_CONFLICT,
            Self::Expired { .. } => ERR_PLAN_EXPIRED,
            Self::ApprovalMismatch { .. } => ERR_PLAN_APPROVAL,
            Self::UnresolvedChange { .. } => ERR_PLAN_UNRESOLVED,
            Self::UnsafePath(error) => error.code(),
        }
    }

    /// The shared typed error.
    #[must_use]
    pub fn to_axiom_error(&self) -> AxiomError {
        let code = match self {
            Self::Stale { .. } | Self::Blocked { .. } | Self::Expired { .. } => ErrorCode::Conflict,
            Self::UnsafePath(error) => return error.to_axiom_error(),
            Self::InvalidHash { .. }
            | Self::DuplicatePath { .. }
            | Self::Invalid { .. }
            | Self::ApprovalMismatch { .. }
            | Self::UnresolvedChange { .. } => ErrorCode::ValidationError,
        };
        AxiomError::new(code, self.to_string()).with_detail("plan_error", self.code())
    }
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHash { path, value } => match path {
                Some(path) => write!(
                    formatter,
                    "{ERR_PLAN_HASH}: {path}: {value:?} is not a SHA-256 hex digest"
                ),
                None => write!(
                    formatter,
                    "{ERR_PLAN_HASH}: {value:?} is not a SHA-256 hex digest"
                ),
            },
            Self::DuplicatePath { section, path } => {
                write!(formatter, "{ERR_PLAN_DUPLICATE}: {section}: {path}")
            }
            Self::Invalid { rule, detail } => {
                write!(formatter, "{ERR_PLAN_INVALID}: {rule}: {detail}")
            }
            Self::Stale { rule, path, detail } => match path {
                Some(path) => write!(formatter, "{ERR_STALE_PLAN}: {rule}: {path}: {detail}"),
                None => write!(formatter, "{ERR_STALE_PLAN}: {rule}: {detail}"),
            },
            Self::Blocked { conflicts } => write!(
                formatter,
                "{ERR_MIGRATION_CONFLICT}: {conflicts} unresolved conflict(s) block this plan"
            ),
            Self::Expired { expired_at, now } => write!(
                formatter,
                "{ERR_PLAN_EXPIRED}: plan expired at {expired_at}, applied at {now}"
            ),
            Self::ApprovalMismatch { expected, supplied } => write!(
                formatter,
                "{ERR_PLAN_APPROVAL}: reviewed digest {supplied} is not this plan's digest {expected}"
            ),
            Self::UnresolvedChange { path, rule } => {
                write!(formatter, "{ERR_PLAN_UNRESOLVED}: {rule}: {path}")
            }
            Self::UnsafePath(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for PlanError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::LayoutId;
    use axiom_platform::path_key::ERR_UNSAFE_PORTABLE_PATH;

    fn hex(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn fresh_repo(id: &str) -> RepoPlan {
        RepoPlan::new(id, DiscoveryDecision::Fresh).expect("portable repo id")
    }

    /// A repository slice that replaces one managed destination from one source.
    fn replace_plan(id: &str, destination: &str, source: &str, hash: &str) -> RepoPlan {
        let mut plan = fresh_repo(id);
        plan.add_source(SourceArtifact::new(source, hash, 42).expect("valid source"))
            .expect("unique source");
        plan.add_change(
            DestinationChange::new(
                destination,
                ChangeAction::Replace,
                Some(source),
                DestinationOwnership::Managed {
                    previous_sha256: Some(ContentHash::parse(hash).expect("valid hash")),
                },
            )
            .expect("valid replace"),
        )
        .expect("unique destination");
        plan
    }

    fn current(id: &str, source: &str, hash: &str) -> CurrentSources {
        let mut observed = CurrentSources::new();
        observed
            .observe(id, source, hash)
            .expect("portable observation");
        observed
    }

    #[test]
    fn digest_is_deterministic_and_bound_to_every_input() {
        let repository = replace_plan(
            "sample-repo",
            ".axiom/graph/index.json",
            ".axiom/graph/legacy.json",
            &hex('a'),
        );
        let first = build_plan("sample-solution", 1_000, 3_600, vec![repository.clone()])
            .expect("plan builds");
        let second = build_plan("sample-solution", 1_000, 3_600, vec![repository.clone()])
            .expect("plan builds");
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.schema_version(), PLAN_SCHEMA_VERSION);

        let other_solution = build_plan("other-solution", 1_000, 3_600, vec![repository.clone()])
            .expect("plan builds");
        assert_ne!(first.digest(), other_solution.digest());

        let other_created = build_plan("sample-solution", 1_001, 3_600, vec![repository.clone()])
            .expect("plan builds");
        assert_ne!(first.digest(), other_created.digest());

        let other_ttl = build_plan("sample-solution", 1_000, 3_601, vec![repository.clone()])
            .expect("plan builds");
        assert_ne!(first.digest(), other_ttl.digest());

        let other_hash = replace_plan(
            "sample-repo",
            ".axiom/graph/index.json",
            ".axiom/graph/legacy.json",
            &hex('b'),
        );
        let mutated =
            build_plan("sample-solution", 1_000, 3_600, vec![other_hash]).expect("plan builds");
        assert_ne!(first.digest(), mutated.digest());
    }

    #[test]
    fn legacy_marker_pair_is_recognised() {
        let text = PreservedText::new(
            "AGENTS.md",
            &hex('c'),
            OwnershipProof::ProvenHash,
            LEGACY_MARKERS[0],
            LEGACY_MARKERS[1],
        )
        .expect("preserved text");
        assert!(text.uses_legacy_markers());

        let custom = PreservedText::new(
            "AGENTS.md",
            &hex('c'),
            OwnershipProof::ExplicitHumanReview,
            "<!-- begin -->",
            "<!-- end -->",
        )
        .expect("preserved text");
        assert!(!custom.uses_legacy_markers());
        assert_eq!(custom.proof(), OwnershipProof::ExplicitHumanReview);
        assert_eq!(custom.proof().as_str(), "explicit-human-review");
    }

    #[test]
    fn stale_sources_are_refused_in_three_directions() {
        let hash = hex('a');
        let plan = build_plan(
            "sample-solution",
            1_000,
            3_600,
            vec![replace_plan(
                "sample-repo",
                ".axiom/graph/index.json",
                ".axiom/graph/legacy.json",
                &hash,
            )],
        )
        .expect("plan builds");

        let unchanged = current("sample-repo", ".axiom/graph/legacy.json", &hash);
        assert!(plan
            .apply(plan.digest().as_str(), &unchanged, 1_100)
            .is_ok());

        let changed = current("sample-repo", ".axiom/graph/legacy.json", &hex('b'));
        let refused = plan
            .apply(plan.digest().as_str(), &changed, 1_100)
            .expect_err("a changed source must be refused");
        assert_eq!(refused.code(), ERR_STALE_PLAN);
        assert!(matches!(
            refused,
            PlanError::Stale {
                rule: "source-changed",
                ..
            }
        ));

        let missing = CurrentSources::new();
        let refused = plan
            .apply(plan.digest().as_str(), &missing, 1_100)
            .expect_err("a missing source must be refused");
        assert!(matches!(
            refused,
            PlanError::Stale {
                rule: "source-missing",
                ..
            }
        ));

        let mut appeared = unchanged.clone();
        appeared
            .observe("sample-repo", ".axiom/graph/new.json", &hex('d'))
            .expect("portable observation");
        let refused = plan
            .apply(plan.digest().as_str(), &appeared, 1_100)
            .expect_err("an appeared source must be refused");
        assert!(matches!(
            refused,
            PlanError::Stale {
                rule: "source-appeared",
                ..
            }
        ));
    }

    #[test]
    fn approval_shares_the_digest_of_the_reviewed_revision() {
        let hash = hex('a');
        let plan = build_plan(
            "sample-solution",
            1_000,
            3_600,
            vec![replace_plan(
                "sample-repo",
                ".axiom/graph/index.json",
                ".axiom/graph/legacy.json",
                &hash,
            )],
        )
        .expect("plan builds");
        let observed = current("sample-repo", ".axiom/graph/legacy.json", &hash);

        assert!(plan.approve(plan.digest().as_str()).is_ok());
        let refused = plan
            .apply(&hex('f'), &observed, 1_100)
            .expect_err("a foreign digest must be refused");
        assert_eq!(refused.code(), ERR_PLAN_APPROVAL);
        assert!(matches!(
            refused,
            PlanError::ApprovalMismatch { ref expected, ref supplied }
                if expected == plan.digest().as_str() && supplied == &hex('f')
        ));
    }

    #[test]
    fn an_unresolved_conflict_blocks_application() {
        let hash = hex('a');
        let mut repository = replace_plan(
            "sample-repo",
            ".axiom/graph/index.json",
            ".axiom/graph/legacy.json",
            &hash,
        );
        repository.add_conflict(PlanConflict::new(
            "both-legacy-layouts-differ",
            Some(".agrimap-agent/knowledge/references/graph"),
            "graph and grahp disagree",
        ));
        let plan =
            build_plan("sample-solution", 1_000, 3_600, vec![repository]).expect("plan builds");
        assert_eq!(plan.conflict_count(), 1);
        assert_eq!(plan.conflicts()[0].rule(), "both-legacy-layouts-differ");

        let observed = current("sample-repo", ".axiom/graph/legacy.json", &hash);
        let refused = plan
            .apply(plan.digest().as_str(), &observed, 1_100)
            .expect_err("a conflicted plan must be refused");
        assert_eq!(refused.code(), ERR_MIGRATION_CONFLICT);
        assert!(matches!(refused, PlanError::Blocked { conflicts: 1 }));
    }

    #[test]
    fn expiry_is_refused_at_the_boundary() {
        let hash = hex('a');
        let plan = build_plan(
            "sample-solution",
            1_000,
            100,
            vec![replace_plan(
                "sample-repo",
                ".axiom/graph/index.json",
                ".axiom/graph/legacy.json",
                &hash,
            )],
        )
        .expect("plan builds");
        let observed = current("sample-repo", ".axiom/graph/legacy.json", &hash);

        assert!(!plan.is_expired(1_099));
        assert!(plan.apply(plan.digest().as_str(), &observed, 1_099).is_ok());

        assert!(plan.is_expired(1_100));
        let refused = plan
            .apply(plan.digest().as_str(), &observed, 1_100)
            .expect_err("an expired plan must be refused");
        assert_eq!(refused.code(), ERR_PLAN_EXPIRED);
        assert!(matches!(
            refused,
            PlanError::Expired {
                expired_at: 1_100,
                now: 1_100
            }
        ));
    }

    #[test]
    fn duplicate_paths_are_refused_per_section() {
        let hash = hex('a');
        let mut plan = fresh_repo("sample-repo");

        plan.add_source(
            SourceArtifact::new(".axiom/graph/a.json", &hash, 1).expect("valid source"),
        )
        .expect("first source");
        let refused = plan
            .add_source(SourceArtifact::new(".axiom/graph/a.json", &hash, 1).expect("valid source"))
            .expect_err("one source twice must be refused");
        assert_eq!(refused.code(), ERR_PLAN_DUPLICATE);
        assert!(matches!(
            refused,
            PlanError::DuplicatePath {
                section: "sources",
                ..
            }
        ));

        plan.add_change(
            DestinationChange::new(
                ".axiom/graph/a.json",
                ChangeAction::Regenerate,
                None,
                DestinationOwnership::Managed {
                    previous_sha256: None,
                },
            )
            .expect("valid regenerate"),
        )
        .expect("first change");
        let refused = plan
            .add_change(
                DestinationChange::new(
                    ".axiom/graph/a.json",
                    ChangeAction::Regenerate,
                    None,
                    DestinationOwnership::Managed {
                        previous_sha256: None,
                    },
                )
                .expect("valid regenerate"),
            )
            .expect_err("one destination twice must be refused");
        assert!(matches!(
            refused,
            PlanError::DuplicatePath {
                section: "changes",
                ..
            }
        ));

        plan.preserve(
            PreservedText::new(
                "AGENTS.md",
                &hash,
                OwnershipProof::ProvenHash,
                LEGACY_MARKERS[0],
                LEGACY_MARKERS[1],
            )
            .expect("preserved text"),
        )
        .expect("first preserved block");
        let refused = plan
            .preserve(
                PreservedText::new(
                    "AGENTS.md",
                    &hash,
                    OwnershipProof::ProvenHash,
                    LEGACY_MARKERS[0],
                    LEGACY_MARKERS[1],
                )
                .expect("preserved text"),
            )
            .expect_err("one preserved block twice must be refused");
        assert!(matches!(
            refused,
            PlanError::DuplicatePath {
                section: "preserved",
                ..
            }
        ));

        let refused = build_plan("sample-solution", 1_000, 3_600, vec![plan.clone(), plan])
            .expect_err("one repository twice must be refused");
        assert!(matches!(
            refused,
            PlanError::DuplicatePath {
                section: "repositories",
                ..
            }
        ));
    }

    #[test]
    fn preserved_human_text_is_retained_and_never_overwritten() {
        let hash = hex('a');
        let mut repository = fresh_repo("sample-repo");
        repository
            .preserve(
                PreservedText::new(
                    "AGENTS.md",
                    &hash,
                    OwnershipProof::ProvenHash,
                    LEGACY_MARKERS[0],
                    LEGACY_MARKERS[1],
                )
                .expect("preserved text"),
            )
            .expect("preserved block");

        let refused = repository
            .add_change(
                DestinationChange::new(
                    "AGENTS.md",
                    ChangeAction::Regenerate,
                    None,
                    DestinationOwnership::Managed {
                        previous_sha256: None,
                    },
                )
                .expect("valid regenerate"),
            )
            .expect_err("a planned change must not overwrite human text");
        assert_eq!(refused.code(), ERR_PLAN_UNRESOLVED);
        assert!(matches!(
            refused,
            PlanError::UnresolvedChange {
                rule: "preserved-text-would-be-overwritten",
                ..
            }
        ));

        let plan =
            build_plan("sample-solution", 1_000, 3_600, vec![repository]).expect("plan builds");
        assert_eq!(plan.repositories()[0].preserved().len(), 1);
        assert_eq!(plan.repositories()[0].preserved()[0].path(), "AGENTS.md");

        let without_text = build_plan(
            "sample-solution",
            1_000,
            3_600,
            vec![fresh_repo("sample-repo")],
        )
        .expect("plan builds");
        assert_ne!(
            plan.digest(),
            without_text.digest(),
            "preserved text is part of the approved bytes"
        );
    }

    #[test]
    fn invalid_hashes_and_unsafe_paths_are_refused() {
        let refused = ContentHash::parse("not-a-hash").expect_err("a placeholder is not a hash");
        assert_eq!(refused.code(), ERR_PLAN_HASH);

        let refused = SourceArtifact::new(".axiom/graph/a.json", &hex('a').to_uppercase(), 1)
            .expect_err("uppercase hex is not the canonical digest");
        assert!(matches!(refused, PlanError::InvalidHash { .. }));

        let refused = DestinationChange::new(
            "../escape.json",
            ChangeAction::Regenerate,
            None,
            DestinationOwnership::Managed {
                previous_sha256: None,
            },
        )
        .expect_err("a non-portable destination must be refused");
        assert_eq!(refused.code(), ERR_UNSAFE_PORTABLE_PATH);

        let refused = RepoPlan::new("../escape", DiscoveryDecision::Fresh)
            .expect_err("a non-portable repo id must be refused");
        assert!(matches!(
            refused,
            PlanError::Invalid {
                rule: "repo-id",
                ..
            }
        ));

        let refused = build_plan("Upper Case", 1_000, 3_600, Vec::new())
            .expect_err("a non-portable solution id must be refused");
        assert!(matches!(
            refused,
            PlanError::Invalid {
                rule: "solution-id",
                ..
            }
        ));

        let refused = build_plan("sample-solution", 1_000, 0, Vec::new())
            .expect_err("a non-positive lifetime must be refused");
        assert!(matches!(
            refused,
            PlanError::Invalid {
                rule: "plan-ttl",
                ..
            }
        ));
    }

    #[test]
    fn non_applicable_change_shapes_are_refused() {
        let hash = hex('a');
        let managed = DestinationOwnership::Managed {
            previous_sha256: Some(ContentHash::parse(&hash).expect("valid hash")),
        };

        let refused = DestinationChange::new(
            ".axiom/graph/a.json",
            ChangeAction::Regenerate,
            Some(".axiom/graph/b.json"),
            DestinationOwnership::Managed {
                previous_sha256: None,
            },
        )
        .expect_err("regenerate takes no source");
        assert!(matches!(
            refused,
            PlanError::UnresolvedChange {
                rule: "regenerate-takes-no-source",
                ..
            }
        ));

        let refused = DestinationChange::new(
            ".axiom/graph/a.json",
            ChangeAction::Create,
            None,
            DestinationOwnership::Managed {
                previous_sha256: None,
            },
        )
        .expect_err("create needs a source");
        assert!(matches!(
            refused,
            PlanError::UnresolvedChange {
                rule: "create-needs-a-source",
                ..
            }
        ));

        let refused = DestinationChange::new(
            ".axiom/graph/a.json",
            ChangeAction::Create,
            Some(".axiom/graph/b.json"),
            managed.clone(),
        )
        .expect_err("create must not claim previous bytes");
        assert!(matches!(
            refused,
            PlanError::UnresolvedChange {
                rule: "create-claims-previous-bytes",
                ..
            }
        ));

        let refused = DestinationChange::new(
            ".axiom/graph/a.json",
            ChangeAction::Replace,
            Some(".axiom/graph/b.json"),
            DestinationOwnership::Managed {
                previous_sha256: None,
            },
        )
        .expect_err("replace must record previous bytes");
        assert!(matches!(
            refused,
            PlanError::UnresolvedChange {
                rule: "replace-without-previous-bytes",
                ..
            }
        ));

        let refused = DestinationChange::new(
            ".axiom/graph/a.json",
            ChangeAction::Replace,
            Some(".axiom/graph/b.json"),
            DestinationOwnership::HumanOwned,
        )
        .expect_err("a human-owned destination is never changed");
        assert!(matches!(
            refused,
            PlanError::UnresolvedChange {
                rule: "human-owned-destination",
                ..
            }
        ));

        // A change must be derivable from the slice's own inventory.
        let mut repository = fresh_repo("sample-repo");
        repository
            .add_change(
                DestinationChange::new(
                    ".axiom/graph/a.json",
                    ChangeAction::Replace,
                    Some(".axiom/graph/b.json"),
                    managed,
                )
                .expect("valid replace"),
            )
            .expect("first change");
        let refused = build_plan("sample-solution", 1_000, 3_600, vec![repository])
            .expect_err("a change from an uninventoried source must be refused");
        assert!(matches!(
            refused,
            PlanError::UnresolvedChange {
                rule: "source-not-inventoried",
                ..
            }
        ));
    }

    #[test]
    fn change_before_preserve_is_also_refused() {
        let hash = hex('a');
        let mut repository = replace_plan(
            "sample-repo",
            ".axiom/graph/index.json",
            ".axiom/graph/legacy.json",
            &hash,
        );
        let refused = repository
            .preserve(
                PreservedText::new(
                    ".axiom/graph/index.json",
                    &hash,
                    OwnershipProof::ProvenHash,
                    LEGACY_MARKERS[0],
                    LEGACY_MARKERS[1],
                )
                .expect("preserved text"),
            )
            .expect_err("preserved text must not duplicate a planned change");
        assert!(matches!(
            refused,
            PlanError::UnresolvedChange {
                rule: "planned-change-would-overwrite-human-text",
                ..
            }
        ));
    }

    #[test]
    fn an_empty_plan_is_a_noop_that_applies_to_nothing() {
        let plan = build_plan("sample-solution", 1_000, 3_600, Vec::new()).expect("plan builds");
        assert!(plan.repositories().is_empty());
        assert!(plan.planned_writes().is_empty());
        assert_eq!(plan.conflict_count(), 0);
        assert!(plan.source_hashes().is_empty());

        let writes = plan
            .apply(plan.digest().as_str(), &CurrentSources::new(), 1_000)
            .expect("an empty plan applies to an empty observation");
        assert!(writes.is_empty());

        let repository = fresh_repo("sample-repo");
        assert!(repository.is_noop());
    }

    #[test]
    fn decisions_and_sources_are_visible_in_the_plan() {
        let hash = hex('a');
        let repository = replace_plan(
            "sample-repo",
            ".axiom/graph/index.json",
            ".axiom/graph/legacy.json",
            &hash,
        );
        let plan =
            build_plan("sample-solution", 1_000, 3_600, vec![repository]).expect("plan builds");

        assert_eq!(
            plan.source_hashes(),
            vec![("sample-repo", ".axiom/graph/legacy.json", hash.as_str())]
        );
        let writes = plan.planned_writes();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].repo_id(), "sample-repo");
        assert_eq!(writes[0].path(), ".axiom/graph/index.json");
        assert_eq!(writes[0].action(), ChangeAction::Replace);
        assert_eq!(writes[0].source(), Some(".axiom/graph/legacy.json"));

        // Every decision shape must be describable, and must bind the digest.
        let decisions = [
            DiscoveryDecision::Fresh,
            DiscoveryDecision::Import {
                source: LayoutId::LegacyGraph,
            },
            DiscoveryDecision::Deduplicate {
                sources: vec![LayoutId::LegacyGraph, LayoutId::LegacyMisspelledGraph],
                target: LayoutId::AxiomGraph,
            },
            DiscoveryDecision::AlreadyMigrated {
                axiom: LayoutId::AxiomGraph,
                legacy_leftovers: vec![LayoutId::LegacyMisspelledGraph],
            },
        ];
        let mut digests = Vec::new();
        for decision in decisions {
            let text = describe(&decision);
            assert!(!text.is_empty());
            let slice = RepoPlan::new("sample-repo", decision).expect("portable repo id");
            let plan =
                build_plan("sample-solution", 1_000, 3_600, vec![slice]).expect("plan builds");
            digests.push(plan.digest().clone());
        }
        for (index, digest) in digests.iter().enumerate() {
            assert!(
                digests.iter().skip(index + 1).all(|other| other != digest),
                "each decision must bind the digest on its own"
            );
        }
    }

    #[test]
    fn typed_errors_and_codes_are_stable() {
        let hash = hex('a');
        let plan = build_plan(
            "sample-solution",
            1_000,
            3_600,
            vec![replace_plan(
                "sample-repo",
                ".axiom/graph/index.json",
                ".axiom/graph/legacy.json",
                &hash,
            )],
        )
        .expect("plan builds");

        let typed = PlanError::Stale {
            rule: "source-changed",
            path: Some(".axiom/graph/legacy.json".to_string()),
            detail: "moved".to_string(),
        }
        .to_axiom_error();
        assert_eq!(typed.code(), ErrorCode::Conflict);
        assert_eq!(
            plan.approve(&hex('f')).expect_err("mismatch").code(),
            ERR_PLAN_APPROVAL
        );

        let unsafe_error = PathKey::new("../escape").expect_err("not portable");
        let typed = PlanError::UnsafePath(unsafe_error).to_axiom_error();
        assert_eq!(typed.code(), ErrorCode::UnsafePortablePath);

        let rendered = format!("{}", PlanError::Blocked { conflicts: 3 });
        assert!(rendered.contains(ERR_MIGRATION_CONFLICT));
    }
}
