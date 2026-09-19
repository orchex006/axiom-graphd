//! Idempotence and drift reporting for a managed repository (task E-021).
//!
//! Verification is the read-only half of bootstrap. It answers "is this
//! repository already in the state the last apply left it in, and if not, is the
//! difference something bootstrap owns or something a human owns?" without
//! writing a byte, taking a lock or touching a backup.
//!
//! The distinction the contract cares about is between two kinds of change:
//!
//! * **managed drift** - the bytes *inside* the managed `AGENTS.md` block, or the
//!   canonical policy file, no longer match the ownership manifest (E-017). Those
//!   bytes belong to bootstrap, so the state is
//!   [`RepositoryState::ManagedDrift`] and [`VerifyReport::exit_code`] is
//!   non-zero: the repository is reported, never silently re-owned.
//! * **unrelated human edits** - bytes *outside* the managed block. Bootstrap
//!   never owned them and never reformats them (E-015), so they are listed in
//!   [`RepositoryVerification::human_edits`] and they do **not** make
//!   verification fail. A human may keep editing their own prose around the
//!   block forever.
//!
//! The idempotence half is a re-plan: a repository whose managed block, policy
//! and manifest already equal what this build would write plans as
//! [`ChangeClass::Unchanged`], which is exactly the statement "a second apply
//! writes nothing". A repository that plans as `append` or `replace` is reported
//! as [`RepositoryState::ManagedRefresh`] (a pending template update) and one
//! that has never been bootstrapped as [`RepositoryState::Unbootstrapped`];
//! neither is drift.
//!
//! The boundary this module enforces on itself is
//! [`owns_only_the_managed_span`]: a proposed `AGENTS.md` write may change the
//! managed span or append a first block, and it may never rewrite a byte of the
//! text a human wrote around it. That is what makes the two kinds of change
//! distinguishable at all.

use graph_core::error::{AxiomError, ErrorCode, ExitCode};
use graph_export::sha256_hex;

use super::markers;
use super::ownership::{self, Drift, Ownership};
use super::plan::{
    plan_repository, ChangeClass, RepositoryReader, RepositoryTarget, Templates, AGENTS_PATH,
};
use super::policy;
use super::refuse;
use super::text::{self, SourceText};

/// Stable rule code: a proposed write would change bytes outside the managed
/// block, so bootstrap refuses to call the repository verified.
pub const RULE_VERIFY_OUTSIDE: &str = "verify-outside-content-changed";

/// Stable rule code: the repository cannot be classified at all.
pub const RULE_VERIFY_UNDECIDABLE: &str = "verify-undecidable";

/// What one repository looks like the moment it is verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RepositoryState {
    /// The repository already matches what this build would write, so a second
    /// apply writes nothing.
    Current,
    /// The managed content is intact but a second apply would refresh it in
    /// place, typically because the template version moved on.
    ManagedRefresh,
    /// Bootstrap has never written this repository.
    Unbootstrapped,
    /// The owned content no longer matches the ownership manifest.
    ManagedDrift,
    /// The marker shape or the ownership record cannot be trusted, so bootstrap
    /// refuses to decide whether the content is owned.
    Undecidable,
}

impl RepositoryState {
    /// Stable, greppable string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::ManagedRefresh => "managed-refresh",
            Self::Unbootstrapped => "unbootstrapped",
            Self::ManagedDrift => "managed-drift",
            Self::Undecidable => "undecidable",
        }
    }

    /// Whether this state is drift that must fail a verification run.
    #[must_use]
    pub const fn is_drift(self) -> bool {
        matches!(self, Self::ManagedDrift | Self::Undecidable)
    }

    /// Whether a second apply would write at least one byte.
    #[must_use]
    pub const fn writes_on_reapply(self) -> bool {
        matches!(self, Self::ManagedRefresh | Self::Unbootstrapped)
    }
}
/// One owned artifact whose bytes drifted from the ownership manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriftRecord {
    /// The artifact that drifted: the managed block or the policy path.
    pub artifact: String,
    /// Stable rule code of the drift.
    pub rule: String,
    /// Operator-facing explanation.
    pub message: String,
}

/// Where one repository stands, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryVerification {
    /// Stable identifier of the repository.
    pub repository_id: String,
    /// Display root.
    pub root: String,
    /// The classification.
    pub state: RepositoryState,
    /// The stable rule code, when the state is not a clean one.
    pub rule: Option<String>,
    /// The operator-facing explanation, when the state is not a clean one.
    pub message: Option<String>,
    /// Owned artifacts whose bytes no longer match the manifest.
    pub managed_drift: Vec<DriftRecord>,
    /// Repository-relative paths whose bytes *outside* the owned content changed
    /// since the approved snapshot. Informational: bootstrap does not own them.
    pub human_edits: Vec<String>,
    /// The files a second apply would write, in plan order.
    pub files: Vec<String>,
}

impl RepositoryVerification {
    /// Whether this repository is in the state the last apply left it in, with
    /// no pending managed refresh.
    #[must_use]
    pub fn is_current(&self) -> bool {
        self.state == RepositoryState::Current
    }

    /// Whether this repository is drift that must fail the run.
    #[must_use]
    pub fn is_drift(&self) -> bool {
        self.state.is_drift()
    }

    /// The exit status this one repository alone would produce.
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        if self.state.is_drift() {
            graph_core::error::exit_code_for(ErrorCode::Conflict)
        } else {
            ExitCode::Success
        }
    }

    /// One operator-facing line for this repository.
    #[must_use]
    pub fn render(&self) -> String {
        let mut line = format!(
            "{} {} ({})",
            self.repository_id,
            self.state.as_str(),
            self.root
        );
        if let Some(rule) = &self.rule {
            line.push_str(&format!(" rule={rule}"));
        }
        if !self.human_edits.is_empty() {
            line.push_str(&format!(
                " human-edits-outside-owned-content={}",
                self.human_edits.join(",")
            ));
        }
        line
    }
}

/// The result of verifying a set of repositories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// One entry per repository, in the order they were verified.
    pub repositories: Vec<RepositoryVerification>,
}

impl VerifyReport {
    /// Wrap the per-repository verdicts.
    #[must_use]
    pub const fn new(repositories: Vec<RepositoryVerification>) -> Self {
        Self { repositories }
    }

    /// How many repositories are exactly current.
    #[must_use]
    pub fn current(&self) -> usize {
        self.repositories
            .iter()
            .filter(|repository| repository.is_current())
            .count()
    }

    /// How many repositories a second apply would write.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.repositories
            .iter()
            .filter(|repository| repository.state.writes_on_reapply())
            .count()
    }

    /// How many repositories reported unrelated human edits outside the block.
    #[must_use]
    pub fn with_human_edits(&self) -> usize {
        self.repositories
            .iter()
            .filter(|repository| !repository.human_edits.is_empty())
            .count()
    }

    /// The repositories that drifted, in report order.
    #[must_use]
    pub fn drifted(&self) -> Vec<&RepositoryVerification> {
        self.repositories
            .iter()
            .filter(|repository| repository.is_drift())
            .collect()
    }

    /// Whether every repository passed verification.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.drifted().is_empty()
    }

    /// The aggregate exit status.
    ///
    /// A run with no drift succeeds even when a second apply would write, since
    /// a pending refresh is not drift. A run where every repository drifted
    /// exits with the first drift's status; a run where only some did exits
    /// [`ExitCode::PartialOperation`] (20), so a partial result is never
    /// reported as a whole one.
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        let drifted = self.drifted();
        if drifted.is_empty() {
            return ExitCode::Success;
        }
        if drifted.len() == self.repositories.len() {
            return drifted[0].exit_code();
        }
        ExitCode::PartialOperation
    }

    /// One operator-facing block, one line per repository.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        for repository in &self.repositories {
            out.push_str(&repository.render());
            out.push('\n');
        }
        out
    }
}
/// One repository bound for verification.
///
/// `approved` is the snapshot the approved plan was built from (E-019's
/// `before`). Supplying it lets verification name the *unrelated human edits* -
/// the paths whose bytes outside the owned block changed since approval - while
/// omitting it simply leaves that list empty.
#[derive(Clone, Copy)]
pub struct VerifyTarget<'a> {
    /// Stable identifier of the repository.
    pub repository_id: &'a str,
    /// Display root.
    pub root: &'a str,
    /// The repository as it is now.
    pub reader: &'a dyn RepositoryReader,
    /// The snapshot the approved plan was built from, when it is available.
    pub approved: Option<&'a dyn RepositoryReader>,
}

impl<'a> VerifyTarget<'a> {
    /// Bind one repository to verify.
    #[must_use]
    pub const fn new(
        repository_id: &'a str,
        root: &'a str,
        reader: &'a dyn RepositoryReader,
    ) -> Self {
        Self {
            repository_id,
            root,
            reader,
            approved: None,
        }
    }

    /// Also supply the approved snapshot, for human-edit reporting.
    #[must_use]
    pub const fn with_approved(mut self, approved: &'a dyn RepositoryReader) -> Self {
        self.approved = Some(approved);
        self
    }
}

/// Verify every repository in a bound set.
#[must_use]
pub fn verify_all(targets: &[VerifyTarget<'_>], templates: &Templates) -> VerifyReport {
    VerifyReport::new(
        targets
            .iter()
            .map(|target| verify_target(target, templates))
            .collect(),
    )
}

/// Verify one repository.
///
/// This never writes, so it returns no error: an unreadable host or an
/// unclassifiable repository is reported as [`RepositoryState::Undecidable`]
/// rather than swallowed.
#[must_use]
pub fn verify_repository(
    repository_id: &str,
    root: &str,
    reader: &dyn RepositoryReader,
    templates: &Templates,
) -> RepositoryVerification {
    verify_target(&VerifyTarget::new(repository_id, root, reader), templates)
}

/// Verify one bound repository.
#[must_use]
pub fn verify_target(target: &VerifyTarget<'_>, templates: &Templates) -> RepositoryVerification {
    let mut verification = RepositoryVerification {
        repository_id: target.repository_id.to_owned(),
        root: target.root.to_owned(),
        state: RepositoryState::Current,
        rule: None,
        message: None,
        managed_drift: Vec::new(),
        human_edits: Vec::new(),
        files: Vec::new(),
    };

    let Some(agents_raw) = read(target.reader, AGENTS_PATH, &mut verification) else {
        return verification;
    };
    let Some(ownership_raw) = read(target.reader, ownership::OWNERSHIP_PATH, &mut verification)
    else {
        return verification;
    };
    let Some(policy_raw) = read(target.reader, policy::POLICY_PATH, &mut verification) else {
        return verification;
    };

    let ownership = match ownership_raw.as_deref() {
        Some(bytes) => match Ownership::parse(bytes) {
            Ok(ownership) => Some(ownership),
            // A manifest that does not parse is a refusal in the plan, and the
            // same refusal here.
            Err(error) => return undecidable(verification, rule_of(&error), error.message()),
        },
        None => None,
    };

    record_managed_drift(
        &mut verification,
        ownership.as_ref(),
        agents_raw.as_deref(),
        policy_raw.as_deref(),
    );
    record_human_edits(&mut verification, target, agents_raw.as_deref());

    let plan = match plan_repository(
        &RepositoryTarget::new(target.repository_id, target.root, target.reader),
        templates,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            return undecidable(verification, rule_of(&error), error.message());
        }
    };

    if let Some(refusal) = &plan.refusal {
        // The contract's own decision order decides the classification: a
        // manifest/block/policy mismatch is drift bootstrap owns; anything else
        // (a broken marker shape, an unowned policy file) is a state bootstrap
        // will not judge.
        let state = if refusal.rule.starts_with("ownership-") {
            RepositoryState::ManagedDrift
        } else {
            RepositoryState::Undecidable
        };
        verification.state = state;
        verification.rule = Some(refusal.rule.clone());
        verification.message = Some(refusal.message.clone());
        return verification;
    }

    verification.files = plan.files.iter().map(|file| file.path.clone()).collect();

    // A proposed write may only touch the managed span (or append a first
    // block). If a plan ever proposed anything else, the repository could not be
    // verified as "managed drift vs human edits" and is refused here.
    for file in &plan.files {
        if file.path != AGENTS_PATH {
            continue;
        }
        if let Err(error) =
            owns_only_the_managed_span(agents_raw.as_deref(), &file.bytes, AGENTS_PATH)
        {
            verification.state = RepositoryState::Undecidable;
            verification.rule = Some(RULE_VERIFY_OUTSIDE.to_owned());
            verification.message = Some(error.message().to_owned());
            verification.managed_drift.push(DriftRecord {
                artifact: AGENTS_PATH.to_owned(),
                rule: RULE_VERIFY_OUTSIDE.to_owned(),
                message: error.message().to_owned(),
            });
            return verification;
        }
    }

    verification.state = if plan.change == ChangeClass::Unchanged {
        RepositoryState::Current
    } else if ownership.is_some() {
        RepositoryState::ManagedRefresh
    } else {
        RepositoryState::Unbootstrapped
    };
    verification
}
/// Whether a proposed `AGENTS.md` write changes only the bytes bootstrap owns.
///
/// A file that already has a managed block may only be rewritten at that span; a
/// file without one may only gain the block appended after its existing bytes.
/// Anything else rewrites text a human wrote, which bootstrap never does.
///
/// # Errors
///
/// Returns [`RULE_VERIFY_OUTSIDE`] when the proposed bytes change unowned text.
pub fn owns_only_the_managed_span(
    before: Option<&[u8]>,
    after: &[u8],
    path: &str,
) -> Result<(), AxiomError> {
    let Some(before) = before else {
        // A new file has no unowned bytes to preserve.
        return Ok(());
    };
    let before_text = SourceText::decode(before)?;
    let after_text = SourceText::decode(after)?;
    let preserved = match markers::managed_span(before_text.document()) {
        Ok(Some(span)) => {
            let replacement = markers::managed_span(after_text.document())
                .ok()
                .flatten()
                .and_then(|after_span| after_span.slice(after_text.document()))
                .unwrap_or_default();
            text::replaces_only_span(
                before_text.document(),
                after_text.document(),
                span,
                replacement,
            )
        }
        // An append must keep the whole original document as an exact prefix.
        _ => after_text.document().starts_with(before_text.document()),
    };
    if !preserved {
        return Err(refuse(
            RULE_VERIFY_OUTSIDE,
            format!("{path} would change bytes outside the owned block"),
        )
        .with_detail("portable_path", path)
        .with_detail("expected", sha256_hex(before))
        .with_detail("observed", sha256_hex(after)));
    }
    Ok(())
}

/// The bytes of `document` that are *outside* its managed block.
///
/// Returns `None` when the document has no readable managed block, because there
/// is then no owned span to be outside of.
#[must_use]
fn outside_content(document: &str) -> Option<String> {
    let span = markers::managed_span(document).ok().flatten()?;
    let before = document.get(..span.start)?;
    let after = document.get(span.end..)?;
    Some(format!("{before}\u{0}{after}"))
}

/// Read one repository-relative path, recording a failure to read as an
/// undecidable repository.
fn read(
    reader: &dyn RepositoryReader,
    relative_path: &str,
    verification: &mut RepositoryVerification,
) -> Option<Option<Vec<u8>>> {
    match reader.read(relative_path) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            verification.state = RepositoryState::Undecidable;
            verification.rule = Some(rule_of(&error));
            verification.message = Some(error.message().to_owned());
            None
        }
    }
}

/// Record every owned artifact whose bytes no longer match the manifest.
fn record_managed_drift(
    verification: &mut RepositoryVerification,
    ownership: Option<&Ownership>,
    agents: Option<&[u8]>,
    policy_raw: Option<&[u8]>,
) {
    let Some(ownership) = ownership else {
        return;
    };
    let block = agents
        .and_then(|bytes| SourceText::decode(bytes).ok())
        .and_then(|text| {
            markers::managed_span(text.document())
                .ok()
                .flatten()
                .and_then(|span| span.slice(text.document()).map(str::to_owned))
        });
    let drift = ownership::detect_drift(ownership, block.as_deref(), policy_raw);
    if drift == Drift::None {
        return;
    }
    verification.managed_drift.push(DriftRecord {
        artifact: drift_artifact(drift).to_owned(),
        rule: drift.as_str().to_owned(),
        message: drift.message().to_owned(),
    });
}

/// Record the paths whose unowned bytes changed since the approved snapshot.
fn record_human_edits(
    verification: &mut RepositoryVerification,
    target: &VerifyTarget<'_>,
    agents: Option<&[u8]>,
) {
    let Some(approved) = target.approved else {
        return;
    };
    let Ok(Some(approved_bytes)) = approved.read(AGENTS_PATH) else {
        return;
    };
    let Some(agents) = agents else {
        return;
    };
    let (Ok(before_text), Ok(current_text)) = (
        SourceText::decode(&approved_bytes),
        SourceText::decode(agents),
    ) else {
        return;
    };
    if let (Some(before_outside), Some(current_outside)) = (
        outside_content(before_text.document()),
        outside_content(current_text.document()),
    ) {
        if before_outside != current_outside {
            verification.human_edits.push(AGENTS_PATH.to_owned());
        }
    }
}

/// The artifact a [`Drift`] belongs to.
const fn drift_artifact(drift: Drift) -> &'static str {
    match drift {
        Drift::BlockEdited | Drift::BlockRemoved => "AGENTS.md managed block",
        Drift::PolicyEdited | Drift::PolicyRemoved => policy::POLICY_PATH,
        Drift::None => "owned content",
    }
}

/// The stable rule a bootstrap refusal carries, or this module's own fallback.
fn rule_of(error: &AxiomError) -> String {
    error
        .details()
        .get("rule")
        .cloned()
        .unwrap_or_else(|| RULE_VERIFY_UNDECIDABLE.to_owned())
}

/// Mark a repository undecidable.
fn undecidable(
    mut verification: RepositoryVerification,
    rule: String,
    message: &str,
) -> RepositoryVerification {
    verification.state = RepositoryState::Undecidable;
    verification.rule = Some(rule);
    verification.message = Some(message.to_owned());
    verification
}
#[cfg(test)]
mod tests {
    use super::super::apply::{apply_repository, MemoryBootstrapHost};
    use super::super::plan::MapRepositoryReader;
    use super::super::preconditions::MemoryPreconditionHost;
    use super::super::TEMPLATE_VERSION;
    use super::*;

    use std::path::{Path, PathBuf};

    /// A reader over the files an apply wrote into a memory host.
    struct HostReader<'a> {
        host: &'a MemoryBootstrapHost,
        root: PathBuf,
    }

    impl RepositoryReader for HostReader<'_> {
        fn read(&self, relative_path: &str) -> Result<Option<Vec<u8>>, AxiomError> {
            Ok(self.host.file(&self.root.join(relative_path)))
        }
    }

    fn corpus_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("bootstrap")
    }

    fn templates() -> Templates {
        let root = corpus_root();
        Templates::new(
            std::fs::read_to_string(root.join("templates").join("AGENTS.block.md"))
                .expect("block template"),
            std::fs::read(root.join("templates").join("POLICY.md")).expect("policy template"),
            TEMPLATE_VERSION,
        )
    }

    fn home() -> PathBuf {
        PathBuf::from("/axiom-home")
    }

    /// Apply one human-written repository into the memory host and return the
    /// host so the same repository can be read back and verified.
    fn applied(agents: &str) -> MemoryBootstrapHost {
        let host = MemoryBootstrapHost::new();
        let locks = MemoryPreconditionHost::new();
        locks.add_directory("/repos/demo");
        let mut reader = MapRepositoryReader::new();
        reader.insert(AGENTS_PATH, agents.to_owned());
        let plan = plan_repository(
            &RepositoryTarget::new("demo", "/repos/demo", &reader),
            &templates(),
        )
        .expect("planning one repository");
        let outcome = apply_repository(&plan, &reader, &host, &locks, &home(), "digest-1");
        assert!(outcome.is_success(), "apply succeeds: {outcome:?}");
        host
    }

    fn host_reader(host: &MemoryBootstrapHost) -> HostReader<'_> {
        HostReader {
            host,
            root: PathBuf::from("/repos/demo"),
        }
    }

    fn agents_of(host: &MemoryBootstrapHost) -> Vec<u8> {
        host.file(&PathBuf::from("/repos/demo").join(AGENTS_PATH))
            .expect("AGENTS.md")
    }

    /// Bend the body of the managed block so the manifest no longer matches it,
    /// while leaving the markers themselves intact.
    fn bend_the_block(host: &MemoryBootstrapHost) {
        let tampered = String::from_utf8_lossy(&agents_of(host))
            .replace(".axiom/agent/POLICY.md", ".axiom/agent/POLICY.mdX");
        assert!(
            tampered.contains(".axiom/agent/POLICY.mdX"),
            "the block body must have been edited"
        );
        host.add_file(
            PathBuf::from("/repos/demo").join(AGENTS_PATH),
            tampered.into_bytes(),
        );
    }

    /// AC1 positive: after an apply, a second apply writes nothing. The
    /// repository verifies as exactly current.
    #[test]
    fn a_second_apply_is_a_no_op() {
        let host = applied("# Human\n");
        let reader = host_reader(&host);
        let verification = verify_repository("demo", "/repos/demo", &reader, &templates());

        assert_eq!(verification.state, RepositoryState::Current);
        assert!(verification.is_current());
        assert!(!verification.is_drift());
        assert!(
            verification.files.is_empty(),
            "a current repository proposes no writes: {:?}",
            verification.files
        );
        assert!(verification.managed_drift.is_empty());
        assert_eq!(verification.exit_code(), ExitCode::Success);

        let report = VerifyReport::new(vec![verification]);
        assert!(report.is_clean());
        assert_eq!(report.current(), 1);
        assert_eq!(report.pending(), 0);
        assert_eq!(report.exit_code(), ExitCode::Success);
    }

    /// AC1 positive: a human edit *outside* the managed block is reported as an
    /// unrelated human edit and does not fail verification, while a human edit
    /// *inside* the block is managed drift and does.
    #[test]
    fn managed_drift_and_unrelated_human_edits_are_distinguished() {
        let host = applied("# Human\n");
        // The approved snapshot is frozen: a live reader over the same host
        // would see every later edit and could never supply a baseline.
        let mut approved = MapRepositoryReader::new();
        approved.insert(AGENTS_PATH, agents_of(&host));

        // A human appends prose around the block. Not drift.
        let edited = format!(
            "{}\nMore human notes.\n",
            String::from_utf8_lossy(&agents_of(&host))
        );
        host.add_file(
            PathBuf::from("/repos/demo").join(AGENTS_PATH),
            edited.into_bytes(),
        );

        let reader = host_reader(&host);
        let verification = verify_target(
            &VerifyTarget::new("demo", "/repos/demo", &reader).with_approved(&approved),
            &templates(),
        );
        assert_eq!(
            verification.state,
            RepositoryState::Current,
            "edits outside the owned block are not drift: {verification:?}"
        );
        assert_eq!(
            verification.human_edits,
            vec![AGENTS_PATH.to_owned()],
            "the unowned edit is named as the human edit"
        );
        assert!(verification.managed_drift.is_empty());
        assert!(!verification.is_drift());
        assert_eq!(verification.exit_code(), ExitCode::Success);

        // A human edits inside the block. Drift.
        bend_the_block(&host);
        let reader = host_reader(&host);
        let verification = verify_target(
            &VerifyTarget::new("demo", "/repos/demo", &reader).with_approved(&approved),
            &templates(),
        );
        assert_eq!(verification.state, RepositoryState::ManagedDrift);
        assert_eq!(
            verification.rule.as_deref(),
            Some(ownership::RULE_BLOCK_EDITED)
        );
        assert_eq!(verification.managed_drift.len(), 1);
        assert_eq!(
            verification.managed_drift[0].artifact,
            "AGENTS.md managed block"
        );
        assert!(verification.is_drift());
        assert_eq!(verification.exit_code(), ExitCode::Conflict);
    }

    /// AC1 boundary: an edited policy file is managed drift even though the
    /// managed block is untouched.
    #[test]
    fn an_edited_policy_file_is_managed_drift() {
        let host = applied("# Human\n");
        host.add_file(
            PathBuf::from("/repos/demo").join(policy::POLICY_PATH),
            b"# rewritten by a human\n".to_vec(),
        );
        let reader = host_reader(&host);
        let verification = verify_repository("demo", "/repos/demo", &reader, &templates());

        assert_eq!(verification.state, RepositoryState::ManagedDrift);
        assert_eq!(
            verification.rule.as_deref(),
            Some(ownership::RULE_POLICY_EDITED)
        );
        assert_eq!(verification.managed_drift.len(), 1);
        assert_eq!(verification.managed_drift[0].artifact, policy::POLICY_PATH);
        assert_eq!(verification.exit_code(), ExitCode::Conflict);
    }

    /// AC1 boundary: a marker shape bootstrap cannot parse is undecidable rather
    /// than assumed current or assumed drifted.
    #[test]
    fn a_broken_marker_shape_is_undecidable_and_fails() {
        let mut reader = MapRepositoryReader::new();
        reader.insert(
            AGENTS_PATH,
            format!(
                "{}\nbody\n{}\n{}\nbody\n{}\n",
                markers::BEGIN_MARKER,
                markers::END_MARKER,
                markers::BEGIN_MARKER,
                markers::END_MARKER
            ),
        );
        let verification = verify_repository("demo", "/repos/demo", &reader, &templates());

        assert_eq!(verification.state, RepositoryState::Undecidable);
        assert!(verification.is_drift());
        assert!(verification.rule.is_some());
        assert_eq!(verification.exit_code(), ExitCode::Conflict);
    }

    /// AC1 positive: a repository that has never been bootstrapped is reported
    /// as such, and is not drift.
    #[test]
    fn an_unbootstrapped_repository_is_reported_without_failing() {
        let mut reader = MapRepositoryReader::new();
        reader.insert(AGENTS_PATH, "# Human only\n");
        let verification = verify_repository("demo", "/repos/demo", &reader, &templates());

        assert_eq!(verification.state, RepositoryState::Unbootstrapped);
        assert!(verification.state.writes_on_reapply());
        assert!(!verification.is_drift());
        assert_eq!(verification.exit_code(), ExitCode::Success);
        assert!(
            !verification.files.is_empty(),
            "the first apply would write"
        );
    }

    /// AC2 boundary: an aggregate reports every repository independently, and a
    /// run where only some repositories drifted exits 20 instead of claiming the
    /// whole set passed.
    #[test]
    fn a_partially_drifted_run_reports_each_repository_and_exit_20() {
        let clean_host = applied("# Human\n");
        let drifted_host = applied("# Human\n");
        bend_the_block(&drifted_host);

        let clean_reader = host_reader(&clean_host);
        let drifted_reader = host_reader(&drifted_host);
        let report = verify_all(
            &[
                VerifyTarget::new("clean", "/repos/clean", &clean_reader),
                VerifyTarget::new("drifted", "/repos/drifted", &drifted_reader),
            ],
            &templates(),
        );

        assert_eq!(report.repositories.len(), 2);
        assert!(!report.is_clean());
        assert_eq!(report.drifted().len(), 1);
        assert_eq!(report.current(), 1);
        assert_eq!(report.exit_code(), ExitCode::PartialOperation);
        assert_eq!(report.drifted()[0].repository_id, "drifted");
        assert!(report.render().contains("managed-drift"));
    }

    /// AC2 negative/boundary: a proposed write that would rewrite unowned bytes
    /// is refused, and a pure append of a first block is accepted.
    #[test]
    fn a_write_that_touches_unowned_bytes_is_refused() {
        let begin = markers::BEGIN_MARKER;
        let end = markers::END_MARKER;
        let before = format!("# Head\n\n{begin}\nbody\n{end}\n# Tail\n");

        let replacement = format!("# Head\n\n{begin}\nnew body\n{end}\n# Tail\n");
        assert!(
            owns_only_the_managed_span(
                Some(before.as_bytes()),
                replacement.as_bytes(),
                AGENTS_PATH
            )
            .is_ok(),
            "replacing only the owned span is allowed"
        );

        let tampered = replacement.replace("# Tail", "# Tail edited");
        let error =
            owns_only_the_managed_span(Some(before.as_bytes()), tampered.as_bytes(), AGENTS_PATH)
                .expect_err("an edit outside the block is refused");
        assert_eq!(rule_of(&error), RULE_VERIFY_OUTSIDE);

        let plain = "# Head\n\n# Tail\n";
        let appended = format!("{plain}\n{begin}\nmore\n{end}\n");
        assert!(
            owns_only_the_managed_span(Some(plain.as_bytes()), appended.as_bytes(), AGENTS_PATH)
                .is_ok(),
            "appending a first block keeps the human document as a prefix"
        );

        let rewritten = format!("{begin}\nmore\n{end}\n");
        assert!(
            owns_only_the_managed_span(Some(plain.as_bytes()), rewritten.as_bytes(), AGENTS_PATH)
                .is_err(),
            "dropping the human document is refused"
        );
    }
}
