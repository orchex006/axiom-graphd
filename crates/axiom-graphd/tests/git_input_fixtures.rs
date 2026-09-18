//! Fixture-driven regression test for the staged-source Git input classes
//! (task F-009).
//!
//! The scenarios are declared in `fixtures/git/manifest.json`; this test rebuilds
//! each one in a throwaway repository, observes it with the real
//! [`graph_watch::git_observer`] parser, classifies it with the real
//! [`graph_watch::checkpoint_inputs`] classifier and materializes the staged
//! bytes with the real [`axiom_graphd::checkpoint::staged`] materializer.
//!
//! `git` is always launched as a program plus argv. No Bash, WSL, Docker or
//! administrator rights are involved.

use std::path::{Path, PathBuf};
use std::process::Command;

use axiom_graphd::checkpoint::staged::{materialize, IndexSource, REASON_NOT_IN_INDEX};
use graph_core::error::{AxiomError, ErrorCode};
use graph_watch::checkpoint_inputs::{classify, merge_parent_count};
use graph_watch::git_observer::{
    observe, ChangeStatus, GitOutput, GitRequest, GitRunner, PathChange,
};
use tempfile::TempDir;

const AUTHOR_DATE: &str = "2001-02-03T04:05:06+0000";

#[derive(serde::Deserialize)]
struct Manifest {
    scenarios: Vec<Scenario>,
}

#[derive(serde::Deserialize)]
struct Scenario {
    id: String,
    #[serde(default)]
    kind: String,
    must_distinguish: Vec<String>,
    expected: Expected,
}

#[derive(serde::Deserialize)]
struct Expected {
    staged: Vec<Entry>,
    unstaged: Vec<Entry>,
    untracked: Vec<Entry>,
    merge_parents: usize,
    staged_bytes_equal_worktree_bytes: bool,
}

#[derive(Debug, serde::Deserialize, PartialEq, Eq)]
struct Entry {
    path: String,
    status: String,
    #[serde(default)]
    previous_path: Option<String>,
}

/// Runs read-only Git requests the way the daemon would: program plus argv.
struct CommandGitRunner;

impl GitRunner for CommandGitRunner {
    fn run(&self, request: &GitRequest) -> Result<GitOutput, AxiomError> {
        let output = Command::new(request.program())
            .args(request.args())
            .current_dir(request.cwd())
            .output()
            .map_err(|error| {
                AxiomError::new(ErrorCode::Internal, "git could not be launched")
                    .with_detail("cause", error.to_string())
            })?;
        Ok(GitOutput::new(
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ))
    }
}

/// One throwaway repository used to build a scenario.
struct FixtureRepo {
    dir: TempDir,
    home: TempDir,
}

impl FixtureRepo {
    fn new() -> Self {
        let repo = Self {
            dir: TempDir::new().expect("repository directory"),
            home: TempDir::new().expect("isolated home directory"),
        };
        repo.git_ok(&["init", "-q", "-b", "main"]);
        repo.git_ok(&["config", "user.name", "axiom-f009"]);
        repo.git_ok(&["config", "user.email", "f009@example.invalid"]);
        repo
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new("git");
        command
            .arg("-c")
            .arg("core.autocrlf=false")
            .arg("-c")
            .arg("core.safecrlf=false")
            .args(args)
            .current_dir(self.dir.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "axiom-f009")
            .env("GIT_AUTHOR_EMAIL", "f009@example.invalid")
            .env("GIT_COMMITTER_NAME", "axiom-f009")
            .env("GIT_COMMITTER_EMAIL", "f009@example.invalid")
            .env("GIT_AUTHOR_DATE", AUTHOR_DATE)
            .env("GIT_COMMITTER_DATE", AUTHOR_DATE)
            .env("HOME", self.home.path())
            .env("USERPROFILE", self.home.path());
        command
    }

    fn git_ok(&self, args: &[&str]) -> Vec<u8> {
        let output = self.command(args).output().expect("git launch");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.dir.path().join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("fixture directory");
        }
        std::fs::write(path, text).expect("fixture write");
    }

    fn remove(&self, relative: &str) {
        let path = self.dir.path().join(relative);
        if path.exists() {
            std::fs::remove_file(path).expect("fixture removal");
        }
    }

    fn commit_all(&self, message: &str) {
        self.git_ok(&["add", "-A"]);
        self.git_ok(&["commit", "-q", "-m", message]);
    }

    fn observe(&self) -> graph_watch::git_observer::WorktreeObservation {
        observe(&CommandGitRunner, self.dir.path(), None).expect("git observation")
    }

    fn merge_parents(&self) -> usize {
        let object = self.git_ok(&["cat-file", "commit", "HEAD"]);
        merge_parent_count(&String::from_utf8_lossy(&object))
    }
}

fn build(repo: &FixtureRepo, id: &str) {
    match id {
        "partial-staging" => {
            repo.write("src/app.rs", "value = 1\n");
            repo.commit_all("base");
            repo.write("src/app.rs", "value = 2\n");
            repo.git_ok(&["add", "src/app.rs"]);
            repo.write("src/app.rs", "value = 3\n");
        }
        "rename" => {
            repo.write("src/old.rs", "fn kept() {}\n");
            repo.commit_all("base");
            repo.git_ok(&["rm", "-q", "src/old.rs"]);
            repo.write("src/new.rs", "fn kept() {}\n");
            repo.git_ok(&["add", "-A"]);
        }
        "merge" => {
            repo.write("src/base.rs", "fn base() {}\n");
            repo.write("src/left.rs", "fn left() {}\n");
            repo.write("src/right.rs", "fn right() {}\n");
            repo.commit_all("base");
            repo.git_ok(&["checkout", "-q", "-b", "side"]);
            repo.write("src/right.rs", "fn right() { /* side */ }\n");
            repo.commit_all("side");
            repo.git_ok(&["checkout", "-q", "main"]);
            repo.write("src/left.rs", "fn left() { /* main */ }\n");
            repo.commit_all("main");
            repo.git_ok(&["merge", "--no-ff", "-q", "-m", "merge side", "side"]);
        }
        "untracked" => {
            repo.write("src/base.rs", "fn base() {}\n");
            repo.commit_all("base");
            repo.write("notes/new.txt", "not staged\n");
        }
        "rename-without-content-change" => {
            repo.write("src/kept.rs", "fn kept() {}\n");
            repo.commit_all("base");
            repo.git_ok(&["mv", "src/kept.rs", "src/moved.rs"]);
        }
        "staged-then-deleted" => {
            repo.write("src/gone.rs", "fn gone() {}\n");
            repo.commit_all("base");
            repo.write("src/gone.rs", "fn gone() { /* staged */ }\n");
            repo.git_ok(&["add", "src/gone.rs"]);
            repo.remove("src/gone.rs");
        }
        other => panic!("unknown fixture scenario {other}"),
    }
}

fn status_name(status: ChangeStatus) -> &'static str {
    match status {
        ChangeStatus::Added => "added",
        ChangeStatus::Modified => "modified",
        ChangeStatus::Deleted => "deleted",
        ChangeStatus::Renamed => "renamed",
        ChangeStatus::Copied => "copied",
        ChangeStatus::TypeChanged => "type-changed",
        ChangeStatus::Conflicted => "conflicted",
        ChangeStatus::Untracked => "untracked",
        ChangeStatus::Unknown(_) => "unknown",
    }
}

fn entries(changes: &[PathChange]) -> Vec<Entry> {
    changes
        .iter()
        .map(|change| Entry {
            path: change.path().to_owned(),
            status: status_name(change.status()).to_owned(),
            previous_path: change.previous_path().map(str::to_owned),
        })
        .collect()
}

fn class_names(distinctions: &[graph_watch::checkpoint_inputs::Distinction]) -> Vec<String> {
    distinctions
        .iter()
        .map(|distinction| distinction.class().as_str().to_owned())
        .collect()
}

/// The real Git index, read through `git show :path`.
struct RealIndexSource {
    repo: PathBuf,
}

impl IndexSource for RealIndexSource {
    fn index_bytes(&self, path: &str) -> Option<Vec<u8>> {
        let revision = format!(":{path}");
        let output = Command::new("git")
            .args(["-c", "core.autocrlf=false", "show", revision.as_str()])
            .current_dir(&self.repo)
            .output()
            .ok()?;
        if output.status.success() {
            Some(output.stdout)
        } else {
            None
        }
    }

    fn worktree_bytes(&self, path: &str) -> Option<Vec<u8>> {
        std::fs::read(self.repo.join(path)).ok()
    }
}

fn manifest() -> Manifest {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/git/manifest.json");
    let bytes = std::fs::read(&path).unwrap_or_else(|error| {
        panic!("fixture manifest {path:?} is unreadable: {error}");
    });
    serde_json::from_slice(&bytes).expect("fixture manifest is valid JSON")
}

#[test]
fn every_git_input_class_is_distinguished_by_real_git_and_real_code() {
    let manifest = manifest();
    assert_eq!(
        manifest.scenarios.len(),
        6,
        "the corpus declares six scenarios"
    );
    for scenario in &manifest.scenarios {
        let repo = FixtureRepo::new();
        build(&repo, &scenario.id);
        let observation = repo.observe();

        assert_eq!(
            entries(observation.staged()),
            scenario.expected.staged,
            "staged bucket for {}",
            scenario.id
        );
        assert_eq!(
            entries(observation.unstaged()),
            scenario.expected.unstaged,
            "unstaged bucket for {}",
            scenario.id
        );
        assert_eq!(
            entries(observation.untracked()),
            scenario.expected.untracked,
            "untracked bucket for {}",
            scenario.id
        );
        assert_eq!(
            repo.merge_parents(),
            scenario.expected.merge_parents,
            "merge parents for {}",
            scenario.id
        );

        let source = RealIndexSource {
            repo: repo.dir.path().to_path_buf(),
        };
        let compare_path = match scenario.id.as_str() {
            "partial-staging" => Some("src/app.rs"),
            "rename" => Some("src/new.rs"),
            "rename-without-content-change" => Some("src/moved.rs"),
            "staged-then-deleted" => Some("src/gone.rs"),
            _ => None,
        };
        if let Some(path) = compare_path {
            assert_eq!(
                source.index_bytes(path) == source.worktree_bytes(path),
                scenario.expected.staged_bytes_equal_worktree_bytes,
                "index vs worktree bytes for {} ({})",
                scenario.id,
                path
            );
        }

        let distinctions = classify(
            observation.staged(),
            observation.unstaged(),
            observation.untracked(),
            repo.merge_parents(),
        );
        assert_eq!(
            class_names(&distinctions),
            scenario.must_distinguish,
            "distinguished classes for {} ({})",
            scenario.id,
            scenario.kind
        );
        assert!(
            !distinctions.is_empty(),
            "scenario {} must distinguish at least one class",
            scenario.id
        );
    }
}

#[test]
fn staged_materialization_follows_the_index_and_refuses_missing_paths() {
    // Partially staged: the index blob wins over the different worktree bytes.
    let partial = FixtureRepo::new();
    build(&partial, "partial-staging");
    let source = RealIndexSource {
        repo: partial.dir.path().to_path_buf(),
    };
    let staged = source.index_bytes("src/app.rs").expect("staged blob");
    let worktree = source.worktree_bytes("src/app.rs").expect("worktree bytes");
    assert_ne!(
        staged, worktree,
        "the scenario must actually be partially staged"
    );
    let materialized =
        materialize(&source, "HEAD", &["src/app.rs".to_owned()]).expect("materialize");
    assert_eq!(materialized.file("src/app.rs").expect("file").bytes, staged);
    assert_eq!(materialized.index_writes, 0);
    assert!(materialized.assert_read_only().is_ok());

    // Boundary: staged then deleted from the worktree - the index still has it.
    let deleted = FixtureRepo::new();
    build(&deleted, "staged-then-deleted");
    let source = RealIndexSource {
        repo: deleted.dir.path().to_path_buf(),
    };
    assert!(
        source.worktree_bytes("src/gone.rs").is_none(),
        "the worktree path is gone"
    );
    let materialized =
        materialize(&source, "HEAD", &["src/gone.rs".to_owned()]).expect("index bytes survive");
    assert_eq!(materialized.len(), 1);
    assert!(!materialized.is_empty());

    // Boundary: a pure rename keeps the digest and the old path is not in the index.
    let renamed = FixtureRepo::new();
    build(&renamed, "rename-without-content-change");
    let source = RealIndexSource {
        repo: renamed.dir.path().to_path_buf(),
    };
    let old = materialize(&source, "HEAD", &["src/kept.rs".to_owned()]).expect_err("old path gone");
    assert_eq!(old.code(), ErrorCode::NotFound);
    assert_eq!(
        old.details().get("rule").map(String::as_str),
        Some(REASON_NOT_IN_INDEX)
    );
    let moved = materialize(&source, "HEAD", &["src/moved.rs".to_owned()]).expect("new path");
    let kept = source.index_bytes("src/moved.rs").expect("blob");
    assert_eq!(moved.file("src/moved.rs").expect("file").bytes, kept);

    // Negative: an untracked path is never a staged input, even though it exists
    // on disk. The materializer must not fall back to the working tree.
    let untracked = FixtureRepo::new();
    build(&untracked, "untracked");
    let source = RealIndexSource {
        repo: untracked.dir.path().to_path_buf(),
    };
    assert!(source.worktree_bytes("notes/new.txt").is_some());
    let error = materialize(&source, "HEAD", &["notes/new.txt".to_owned()]).expect_err("untracked");
    assert_eq!(error.code(), ErrorCode::NotFound);
    assert_eq!(
        error.details().get("rule").map(String::as_str),
        Some(REASON_NOT_IN_INDEX)
    );
}
