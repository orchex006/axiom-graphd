//! Safe Git worktree observation (task B-031).
//!
//! Git tells the daemon which files changed without the daemon having to trust
//! the filesystem alone. Observing Git must never mutate the worktree: no
//! `reset`, `stash`, `checkout`, `clean` or `restore`, and no `-c` override that
//! could install a filter driver
//! (`docs/13-SQLITE-QUEUE-AND-RECONCILIATION.md` section 9).
//!
//! `git diff HEAD~1` is not used as the change source because a relative revision
//! covers neither the working tree nor untracked files nor a branch switch. The
//! caller supplies an explicit base and target revision, and the working-tree
//! comparison is a separate `status` observation. Every launch is a program plus
//! argv, never an interpolated shell string (`Development.md`).
//!
//! Which revision the caller should compare is a policy decision outside this
//! module; this module only guarantees that the observation is read-only,
//! explicit and parsed into staged, unstaged, untracked and branch-change inputs.

use std::path::Path;

use crate::portable_relative_path;
use graph_core::error::{AxiomError, ErrorCode};

/// Subcommands this module may run.
const ALLOWED_SUBCOMMANDS: &[&str] = &[
    "status",
    "rev-parse",
    "symbolic-ref",
    "branch",
    "diff",
    "ls-files",
    "log",
    "merge-base",
    "show",
    "describe",
    "for-each-ref",
    "cat-file",
];

/// Subcommands that would mutate the worktree or the repository.
const FORBIDDEN_SUBCOMMANDS: &[&str] = &[
    "reset",
    "stash",
    "checkout",
    "switch",
    "restore",
    "clean",
    "apply",
    "add",
    "commit",
    "merge",
    "rebase",
    "pull",
    "push",
    "fetch",
    "filter-branch",
    "update-ref",
    "gc",
    "prune",
    "config",
    "remote",
    "worktree",
    "submodule",
    "init",
    "clone",
    "tag",
    "am",
    "revert",
    "cherry-pick",
    "repack",
];

/// Argument prefixes that silently change Git behaviour instead of observing it.
const FORBIDDEN_ARGUMENTS: &[&str] = &["-c", "--config", "--exec-path", "--git-dir", "--work-tree"];

/// One read-only Git invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRequest {
    cwd: String,
    args: Vec<String>,
}

impl GitRequest {
    /// Build a validated read-only request.
    ///
    /// # Errors
    /// [`ErrorCode::ValidationError`] when the request is empty, uses a forbidden
    /// subcommand, or asks Git to override its configuration.
    pub fn new(cwd: &Path, args: &[&str]) -> Result<Self, AxiomError> {
        let cwd = cwd.to_string_lossy().into_owned();
        let first = args
            .iter()
            .find(|argument| !argument.starts_with('-'))
            .ok_or_else(|| {
                AxiomError::new(
                    ErrorCode::ValidationError,
                    "a Git request must name a subcommand",
                )
            })?;
        for argument in args {
            if FORBIDDEN_ARGUMENTS.contains(argument) {
                return Err(AxiomError::new(
                    ErrorCode::Forbidden,
                    "the watcher may not override Git configuration",
                )
                .with_detail("argument", *argument));
            }
        }
        if FORBIDDEN_SUBCOMMANDS.contains(first) {
            return Err(AxiomError::new(
                ErrorCode::Forbidden,
                "the watcher may not run a Git subcommand that mutates the worktree",
            )
            .with_detail("subcommand", *first));
        }
        if !ALLOWED_SUBCOMMANDS.contains(first) {
            return Err(AxiomError::new(
                ErrorCode::ValidationError,
                "the Git subcommand is not on the read-only allow-list",
            )
            .with_detail("subcommand", *first));
        }
        if *first == "branch" {
            for argument in args {
                if matches!(
                    *argument,
                    "-d" | "-D"
                        | "-m"
                        | "-M"
                        | "-f"
                        | "--delete"
                        | "--move"
                        | "--force"
                        | "--edit-description"
                ) {
                    return Err(AxiomError::new(
                        ErrorCode::Forbidden,
                        "the watcher may not modify branches",
                    )
                    .with_detail("argument", *argument));
                }
            }
        }
        Ok(Self {
            cwd,
            args: args
                .iter()
                .map(|argument| (*argument).to_string())
                .collect(),
        })
    }

    /// Working directory of the invocation.
    #[must_use]
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// Arguments, excluding the program name.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// The program to launch; always `git`, never an interpolated string.
    #[must_use]
    pub const fn program(&self) -> &'static str {
        "git"
    }
}

/// Result of one Git invocation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GitOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

impl GitOutput {
    /// Record one completed invocation.
    #[must_use]
    pub fn new(status: i32, stdout: impl Into<String>, stderr: impl Into<String>) -> Self {
        Self {
            status,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    /// Exit status.
    #[must_use]
    pub const fn status(&self) -> i32 {
        self.status
    }

    /// Standard output.
    #[must_use]
    pub fn stdout(&self) -> &str {
        &self.stdout
    }

    /// Standard error.
    #[must_use]
    pub fn stderr(&self) -> &str {
        &self.stderr
    }

    /// Whether the invocation succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status == 0
    }
}

/// Executes read-only Git requests.
pub trait GitRunner {
    /// Run one validated request.
    ///
    /// # Errors
    /// [`ErrorCode::Internal`] or [`ErrorCode::NotFound`] when Git itself cannot
    /// be executed; a non-zero exit status is reported in [`GitOutput`].
    fn run(&self, request: &GitRequest) -> Result<GitOutput, AxiomError>;
}

/// One changed path with its Git status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeStatus {
    /// The path was added.
    Added,
    /// The path content or metadata changed.
    Modified,
    /// The path was deleted.
    Deleted,
    /// The path was renamed.
    Renamed,
    /// The path was copied.
    Copied,
    /// The path changed type (for example a file became a symlink).
    TypeChanged,
    /// The path has an unresolved merge conflict.
    Conflicted,
    /// The path is untracked.
    Untracked,
    /// A status character this module does not model.
    Unknown(char),
}

impl ChangeStatus {
    /// Map one porcelain status character.
    #[must_use]
    pub const fn from_char(value: char) -> Self {
        match value {
            'A' => Self::Added,
            'M' => Self::Modified,
            'D' => Self::Deleted,
            'R' => Self::Renamed,
            'C' => Self::Copied,
            'T' => Self::TypeChanged,
            'U' => Self::Conflicted,
            '?' => Self::Untracked,
            other => Self::Unknown(other),
        }
    }

    /// Whether this status carries a previous path.
    #[must_use]
    pub const fn carries_origin(self) -> bool {
        matches!(self, Self::Renamed | Self::Copied)
    }
}

/// One changed path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathChange {
    status: ChangeStatus,
    path: String,
    previous_path: Option<String>,
}

impl PathChange {
    /// Record one change.
    #[must_use]
    pub fn new(
        status: ChangeStatus,
        path: impl Into<String>,
        previous_path: Option<String>,
    ) -> Self {
        Self {
            status,
            path: path.into(),
            previous_path,
        }
    }

    /// Status of the change.
    #[must_use]
    pub const fn status(&self) -> ChangeStatus {
        self.status
    }

    /// Project-relative path after the change.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Path before a rename or copy.
    #[must_use]
    pub fn previous_path(&self) -> Option<&str> {
        self.previous_path.as_deref()
    }
}

/// Identity of the worktree as Git sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeEpoch {
    head: String,
    branch: Option<String>,
}

impl WorktreeEpoch {
    /// Record one observed epoch.
    #[must_use]
    pub fn new(head: impl Into<String>, branch: Option<String>) -> Self {
        Self {
            head: head.into(),
            branch,
        }
    }

    /// Observed `HEAD`.
    #[must_use]
    pub fn head(&self) -> &str {
        &self.head
    }

    /// Branch name, absent when the worktree is detached.
    #[must_use]
    pub fn branch(&self) -> Option<&str> {
        self.branch.as_deref()
    }

    /// Whether the worktree is detached at `HEAD`.
    #[must_use]
    pub const fn is_detached(&self) -> bool {
        self.branch.is_none()
    }

    /// Stable identity string used for epoch comparison and diagnostics.
    #[must_use]
    pub fn identity(&self) -> String {
        format!(
            "{}\u{0}{}",
            self.head,
            self.branch.as_deref().unwrap_or("(detached)")
        )
    }
}

/// How the worktree epoch moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochChange {
    /// Only `HEAD` moved (a commit, a pull, a checkout of the same branch name).
    HeadMoved {
        /// Previous head.
        from: String,
        /// Current head.
        to: String,
    },
    /// Only the branch name changed.
    BranchChanged {
        /// Previous branch, absent when detached.
        from: Option<String>,
        /// Current branch, absent when detached.
        to: Option<String>,
    },
    /// Both `HEAD` and the branch name changed.
    HeadAndBranchChanged,
}

/// Compare two epochs, reporting a change when they differ.
#[must_use]
pub fn epoch_change(previous: &WorktreeEpoch, current: &WorktreeEpoch) -> Option<EpochChange> {
    let head_changed = previous.head() != current.head();
    let branch_changed = previous.branch() != current.branch();
    match (head_changed, branch_changed) {
        (true, true) => Some(EpochChange::HeadAndBranchChanged),
        (true, false) => Some(EpochChange::HeadMoved {
            from: previous.head().to_string(),
            to: current.head().to_string(),
        }),
        (false, true) => Some(EpochChange::BranchChanged {
            from: previous.branch().map(str::to_string),
            to: current.branch().map(str::to_string),
        }),
        (false, false) => None,
    }
}

/// Everything one observation found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeObservation {
    epoch: WorktreeEpoch,
    staged: Vec<PathChange>,
    unstaged: Vec<PathChange>,
    untracked: Vec<PathChange>,
    epoch_change: Option<EpochChange>,
}

impl WorktreeObservation {
    /// Identity of the observed worktree.
    #[must_use]
    pub const fn epoch(&self) -> &WorktreeEpoch {
        &self.epoch
    }

    /// Index-side changes.
    #[must_use]
    pub fn staged(&self) -> &[PathChange] {
        &self.staged
    }

    /// Worktree-side changes.
    #[must_use]
    pub fn unstaged(&self) -> &[PathChange] {
        &self.unstaged
    }

    /// Untracked files.
    #[must_use]
    pub fn untracked(&self) -> &[PathChange] {
        &self.untracked
    }

    /// How the epoch moved relative to the supplied previous epoch.
    #[must_use]
    pub const fn epoch_change(&self) -> Option<&EpochChange> {
        self.epoch_change.as_ref()
    }

    /// Whether a complete rescan is required, which is the case for any epoch
    /// movement because a branch switch or checkout replaces the worktree
    /// wholesale.
    #[must_use]
    pub const fn requires_full_scan(&self) -> bool {
        self.epoch_change.is_some()
    }
}

/// Refuse a relative revision, which cannot describe a working tree.
///
/// # Errors
/// [`ErrorCode::ValidationError`] when the revision is empty, looks like an
/// option, or is a relative revision such as `HEAD~1` or `main^2`.
pub fn validate_revision(revision: &str) -> Result<(), AxiomError> {
    if revision.is_empty() {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "an explicit base or target revision is required",
        ));
    }
    if revision.starts_with('-') {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "a revision must not be an option",
        )
        .with_detail("revision", revision));
    }
    if revision.contains('~') || revision.contains('^') || revision.contains("@{") {
        return Err(AxiomError::new(
            ErrorCode::ValidationError,
            "a relative revision does not cover the working tree; use an explicit base and target",
        )
        .with_detail("revision", revision));
    }
    Ok(())
}

/// Observe the worktree: branch, head, staged, unstaged and untracked changes.
///
/// # Errors
/// - [`ErrorCode::NotReady`] when `HEAD` does not exist (an unborn branch).
/// - [`ErrorCode::Internal`] when a Git invocation fails.
pub fn observe(
    runner: &dyn GitRunner,
    root: &Path,
    previous_epoch: Option<&WorktreeEpoch>,
) -> Result<WorktreeObservation, AxiomError> {
    let head_output = runner.run(&GitRequest::new(root, &["rev-parse", "--verify", "HEAD"])?)?;
    if !head_output.is_success() {
        return Err(AxiomError::new(
            ErrorCode::NotReady,
            "the worktree has no HEAD commit to observe",
        )
        .with_detail("stderr", head_output.stderr()));
    }
    let head = head_output.stdout().trim().to_string();

    let branch_output = runner.run(&GitRequest::new(
        root,
        &["symbolic-ref", "--quiet", "--short", "HEAD"],
    )?)?;
    let branch = if branch_output.is_success() {
        let name = branch_output.stdout().trim().to_string();
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    } else {
        None
    };

    let status_output = runner.run(&GitRequest::new(
        root,
        &[
            "--no-optional-locks",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ],
    )?)?;
    if !status_output.is_success() {
        return Err(AxiomError::new(
            ErrorCode::Internal,
            "git status failed while observing the worktree",
        )
        .with_detail("stderr", status_output.stderr()));
    }

    let epoch = WorktreeEpoch::new(head, branch);
    let change = previous_epoch.and_then(|previous| epoch_change(previous, &epoch));
    let (staged, unstaged, untracked) = parse_porcelain_v1_z(status_output.stdout())?;
    Ok(WorktreeObservation {
        epoch,
        staged,
        unstaged,
        untracked,
        epoch_change: change,
    })
}

/// Changed paths between an explicit base and target revision.
///
/// # Errors
/// [`ErrorCode::ValidationError`] for a relative or option-like revision.
/// [`ErrorCode::Internal`] when Git fails.
pub fn observe_range(
    runner: &dyn GitRunner,
    root: &Path,
    base: &str,
    target: &str,
) -> Result<Vec<PathChange>, AxiomError> {
    validate_revision(base)?;
    validate_revision(target)?;
    let output = runner.run(&GitRequest::new(
        root,
        &[
            "diff",
            "--name-status",
            "--no-renames",
            "-z",
            base,
            target,
            "--",
        ],
    )?)?;
    if !output.is_success() {
        return Err(AxiomError::new(
            ErrorCode::Internal,
            "git diff failed while observing the worktree",
        )
        .with_detail("stderr", output.stderr()));
    }
    parse_name_status_z(output.stdout())
}

/// Staged, unstaged and untracked changes of one observation.
pub type StatusBuckets = (Vec<PathChange>, Vec<PathChange>, Vec<PathChange>);

/// Parse `git status --porcelain=v1 -z` output.
///
/// # Errors
/// [`ErrorCode::Internal`] when a record is truncated or a path is not portable.
pub fn parse_porcelain_v1_z(output: &str) -> Result<StatusBuckets, AxiomError> {
    let mut staged = Vec::new();
    let mut unstaged = Vec::new();
    let mut untracked = Vec::new();
    let mut fields = output.split('\u{0}').filter(|field| !field.is_empty());
    while let Some(field) = fields.next() {
        let (index, worktree, path) = split_status_record(field)?;
        let origin = if index.carries_origin() || worktree.carries_origin() {
            let origin = fields.next().ok_or_else(|| {
                AxiomError::new(
                    ErrorCode::Internal,
                    "a rename record in git status is missing its origin path",
                )
            })?;
            Some(portable_relative_path(origin)?)
        } else {
            None
        };
        let path = portable_relative_path(path)?;
        if index == ChangeStatus::Untracked || worktree == ChangeStatus::Untracked {
            untracked.push(PathChange::new(ChangeStatus::Untracked, path, None));
            continue;
        }
        if !matches!(index, ChangeStatus::Unknown(' ')) {
            staged.push(PathChange::new(index, path.clone(), origin.clone()));
        }
        if !matches!(worktree, ChangeStatus::Unknown(' ')) {
            unstaged.push(PathChange::new(worktree, path, origin));
        }
    }
    Ok((staged, unstaged, untracked))
}

/// Parse `git diff --name-status -z` output.
///
/// # Errors
/// [`ErrorCode::Internal`] for a truncated record or a non-portable path.
pub fn parse_name_status_z(output: &str) -> Result<Vec<PathChange>, AxiomError> {
    let mut changes = Vec::new();
    let mut fields = output.split('\u{0}').filter(|field| !field.is_empty());
    while let Some(field) = fields.next() {
        let (status, path) = field.split_once('\t').ok_or_else(|| {
            AxiomError::new(
                ErrorCode::Internal,
                "a name-status record is missing its path separator",
            )
        })?;
        let status = ChangeStatus::from_char(status.chars().next().unwrap_or('?'));
        let origin = if status.carries_origin() {
            let origin = fields.next().ok_or_else(|| {
                AxiomError::new(
                    ErrorCode::Internal,
                    "a rename record is missing its origin path",
                )
            })?;
            Some(portable_relative_path(origin)?)
        } else {
            None
        };
        changes.push(PathChange::new(
            status,
            portable_relative_path(path)?,
            origin,
        ));
    }
    Ok(changes)
}

fn split_status_record(field: &str) -> Result<(ChangeStatus, ChangeStatus, &str), AxiomError> {
    let mut characters = field.chars();
    let index = characters
        .next()
        .ok_or_else(|| AxiomError::new(ErrorCode::Internal, "an empty git status record"))?;
    let worktree = characters.next().ok_or_else(|| {
        AxiomError::new(
            ErrorCode::Internal,
            "a git status record is missing its worktree column",
        )
    })?;
    let path = characters.as_str();
    if path.is_empty() {
        return Err(AxiomError::new(
            ErrorCode::Internal,
            "a git status record is missing its path",
        ));
    }
    let path = path.strip_prefix(' ').unwrap_or(path);
    Ok((
        ChangeStatus::from_char(index),
        ChangeStatus::from_char(worktree),
        path,
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        epoch_change, observe, observe_range, validate_revision, ChangeStatus, EpochChange,
        GitOutput, GitRequest, GitRunner, PathChange, WorktreeEpoch,
    };
    use graph_core::error::ErrorCode;
    use std::collections::BTreeMap;
    use std::path::Path;

    #[derive(Debug, Default)]
    struct RecordingRunner {
        responses: BTreeMap<String, GitOutput>,
        seen: std::cell::RefCell<Vec<String>>,
    }

    impl RecordingRunner {
        fn with(mut self, args: &[&str], output: GitOutput) -> Self {
            self.responses.insert(args.join(" "), output);
            self
        }
    }

    impl GitRunner for RecordingRunner {
        fn run(&self, request: &GitRequest) -> Result<GitOutput, graph_core::error::AxiomError> {
            let key = request.args().join(" ");
            self.seen.borrow_mut().push(key.clone());
            Ok(self.responses.get(&key).cloned().unwrap_or_default())
        }
    }

    #[test]
    fn staged_unstaged_and_untracked_inputs_are_distinguished() {
        let status = concat!(
            "M  src/Staged.cs\u{0}",
            " M src/Unstaged.cs\u{0}",
            "MM src/Both.cs\u{0}",
            "?? src/Untracked.cs\u{0}",
            "R  src/New.cs\u{0}src/Old.cs\u{0}",
        );
        let runner = RecordingRunner::default()
            .with(
                &["rev-parse", "--verify", "HEAD"],
                GitOutput::new(0, "abc123\n", ""),
            )
            .with(
                &["symbolic-ref", "--quiet", "--short", "HEAD"],
                GitOutput::new(0, "main\n", ""),
            )
            .with(
                &[
                    "--no-optional-locks",
                    "status",
                    "--porcelain=v1",
                    "-z",
                    "--untracked-files=all",
                ],
                GitOutput::new(0, status, ""),
            );
        let observation = observe(&runner, Path::new("D:/repo/Project"), None).expect("observed");

        assert_eq!(observation.epoch().head(), "abc123");
        assert_eq!(observation.epoch().branch(), Some("main"));
        assert!(!observation.epoch().is_detached());
        assert!(observation.epoch_change().is_none());
        assert!(!observation.requires_full_scan());

        let staged: Vec<&str> = observation.staged().iter().map(PathChange::path).collect();
        assert_eq!(staged, vec!["src/Staged.cs", "src/Both.cs", "src/New.cs"]);
        let unstaged: Vec<&str> = observation
            .unstaged()
            .iter()
            .map(PathChange::path)
            .collect();
        assert_eq!(unstaged, vec!["src/Unstaged.cs", "src/Both.cs"]);
        let untracked: Vec<&str> = observation
            .untracked()
            .iter()
            .map(PathChange::path)
            .collect();
        assert_eq!(untracked, vec!["src/Untracked.cs"]);
        let rename = observation
            .staged()
            .iter()
            .find(|change| change.status() == ChangeStatus::Renamed)
            .expect("rename");
        assert_eq!(rename.path(), "src/New.cs");
        assert_eq!(rename.previous_path(), Some("src/Old.cs"));
    }

    #[test]
    fn a_branch_change_is_reported_and_never_acted_on() {
        let runner = RecordingRunner::default()
            .with(
                &["rev-parse", "--verify", "HEAD"],
                GitOutput::new(0, "def456\n", ""),
            )
            .with(
                &["symbolic-ref", "--quiet", "--short", "HEAD"],
                GitOutput::new(0, "feature/x\n", ""),
            )
            .with(
                &[
                    "--no-optional-locks",
                    "status",
                    "--porcelain=v1",
                    "-z",
                    "--untracked-files=all",
                ],
                GitOutput::new(0, "", ""),
            );
        let previous = WorktreeEpoch::new("abc123", Some("main".to_string()));
        let observation =
            observe(&runner, Path::new("D:/repo/Project"), Some(&previous)).expect("observed");
        assert_eq!(
            observation.epoch_change(),
            Some(&EpochChange::HeadAndBranchChanged)
        );
        assert!(
            observation.requires_full_scan(),
            "a branch change replaces the worktree and requires a complete inventory"
        );

        let detached = RecordingRunner::default()
            .with(
                &["rev-parse", "--verify", "HEAD"],
                GitOutput::new(0, "def456\n", ""),
            )
            .with(
                &["symbolic-ref", "--quiet", "--short", "HEAD"],
                GitOutput::new(1, "", "fatal: ref HEAD is not a symbolic ref"),
            )
            .with(
                &[
                    "--no-optional-locks",
                    "status",
                    "--porcelain=v1",
                    "-z",
                    "--untracked-files=all",
                ],
                GitOutput::new(0, "", ""),
            );
        let observation = observe(&detached, Path::new("D:/repo/Project"), None).expect("observed");
        assert!(observation.epoch().is_detached());
        assert_eq!(
            epoch_change(
                &WorktreeEpoch::new("abc123", Some("main".to_string())),
                &WorktreeEpoch::new("abc123", None)
            ),
            Some(EpochChange::BranchChanged {
                from: Some("main".to_string()),
                to: None,
            })
        );
        assert_eq!(
            WorktreeEpoch::new("abc", None).identity(),
            "abc\u{0}(detached)"
        );
    }

    #[test]
    fn destructive_and_configuration_overriding_requests_are_refused() {
        for forbidden in [
            "reset",
            "stash",
            "checkout",
            "clean",
            "restore",
            "update-ref",
        ] {
            let error = GitRequest::new(Path::new("D:/repo"), &[forbidden, "--hard"])
                .expect_err("mutating subcommands are refused");
            assert_eq!(error.code(), ErrorCode::Forbidden, "subcommand {forbidden}");
        }
        assert_eq!(
            GitRequest::new(Path::new("D:/repo"), &["-c", "diff"])
                .expect_err("configuration override refused")
                .code(),
            ErrorCode::Forbidden
        );
        assert_eq!(
            GitRequest::new(Path::new("D:/repo"), &["--stat"])
                .expect_err("a request with no subcommand")
                .code(),
            ErrorCode::ValidationError
        );
        assert_eq!(
            GitRequest::new(
                Path::new("D:/repo"),
                &["diff", "-c", "core.fsmonitor=false"]
            )
            .expect_err("configuration override refused")
            .code(),
            ErrorCode::Forbidden
        );
        assert_eq!(
            GitRequest::new(Path::new("D:/repo"), &["branch", "-D", "main"])
                .expect_err("branch deletion refused")
                .code(),
            ErrorCode::Forbidden
        );
        assert!(GitRequest::new(Path::new("D:/repo"), &["rev-parse", "HEAD"]).is_ok());

        assert_eq!(
            validate_revision("HEAD~1")
                .expect_err("relative revision")
                .code(),
            ErrorCode::ValidationError
        );
        assert_eq!(
            validate_revision("main^2")
                .expect_err("relative revision")
                .code(),
            ErrorCode::ValidationError
        );
        assert!(validate_revision("abc123").is_ok());
        assert!(validate_revision("refs/heads/main").is_ok());

        let runner = RecordingRunner::default();
        let error = observe_range(&runner, Path::new("D:/repo"), "HEAD~1", "HEAD")
            .expect_err("a relative base is refused before Git runs");
        assert_eq!(error.code(), ErrorCode::ValidationError);
    }

    #[test]
    fn explicit_revisions_produce_changed_paths_without_executing_git_mutations() {
        let runner = RecordingRunner::default().with(
            &[
                "diff",
                "--name-status",
                "--no-renames",
                "-z",
                "base-sha",
                "target-sha",
                "--",
            ],
            GitOutput::new(
                0,
                "M\tsrc/App.cs\u{0}A\tsrc/New.cs\u{0}D\tsrc/Gone.cs\u{0}",
                "",
            ),
        );
        let changes = observe_range(&runner, Path::new("D:/repo"), "base-sha", "target-sha")
            .expect("changed paths");
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].status(), ChangeStatus::Modified);
        assert_eq!(changes[1].status(), ChangeStatus::Added);
        assert_eq!(changes[2].status(), ChangeStatus::Deleted);
        assert_eq!(
            runner.seen.borrow().as_slice(),
            ["diff --name-status --no-renames -z base-sha target-sha --"]
        );

        assert_eq!(
            super::parse_name_status_z("M\u{0}broken\u{0}")
                .expect_err("a record without its separator is a defect")
                .code(),
            ErrorCode::Internal
        );
        assert!(super::parse_name_status_z("")
            .expect("empty output")
            .is_empty());
        assert_eq!(
            super::parse_porcelain_v1_z("R  src/new.cs\u{0}")
                .expect_err("a rename without its origin is truncated")
                .code(),
            ErrorCode::Internal
        );
    }
}
