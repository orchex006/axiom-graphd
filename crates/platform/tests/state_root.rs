//! V2-006 - per-user state-root resolution: positive, negative and boundary legs.
//!
//! Two kinds of leg appear here. The real host is exercised through
//! `NativeStateRootProbe` against a real temporary directory, and the
//! non-observable destinations (a link, a non-private directory, a host without
//! ownership observation) are exercised through a scripted probe. The scripted
//! probe counts its calls, so "refused before anything touched the filesystem"
//! is proven rather than asserted.

use std::cell::Cell;
use std::path::{Path, PathBuf};

use axiom_platform::state_root::{
    ensure_state_root, resolve_state_root, DirectoryStatus, NativeStateRootProbe, Ownership,
    StateEnvironment, StatePlatform, StateRootProbe, StateRootSource,
};

/// A probe that reports exactly what a leg needs and counts its calls.
struct ScriptedProbe {
    status: DirectoryStatus,
    ownership: Option<Ownership>,
    canonical: Option<PathBuf>,
    create: Result<(), String>,
    status_calls: Cell<u32>,
    create_calls: Cell<u32>,
}

impl ScriptedProbe {
    fn new(status: DirectoryStatus) -> Self {
        Self {
            status,
            ownership: None,
            canonical: None,
            create: Ok(()),
            status_calls: Cell::new(0),
            create_calls: Cell::new(0),
        }
    }
}

impl StateRootProbe for ScriptedProbe {
    fn status(&self, _path: &Path) -> DirectoryStatus {
        self.status_calls.set(self.status_calls.get() + 1);
        self.status
    }

    fn create_private_dir_all(&self, _path: &Path) -> Result<(), String> {
        self.create_calls.set(self.create_calls.get() + 1);
        self.create.clone()
    }

    fn ownership(&self, _path: &Path) -> Option<Ownership> {
        self.ownership.clone()
    }

    fn canonicalize(&self, _path: &Path) -> Option<PathBuf> {
        self.canonical.clone()
    }
}

/// A temporary directory private to its owner, as a state root must be.
/// `tempfile` creates directories `0o777 & !umask`, so narrow the mode here.
fn private_tempdir() -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("temporary directory");
    make_private(temp.path());
    temp
}

/// Narrow a real directory to `0o700` on Unix; a no-op where modes do not exist.
fn make_private(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("narrow directory to 0700");
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

fn override_env(home: &str) -> StateEnvironment {
    StateEnvironment {
        platform: StatePlatform::Linux,
        axiom_home: Some(home.to_string()),
        ..StateEnvironment::default()
    }
}

// ---------------------------------------------------------- the happy paths

#[test]
fn an_absolute_override_on_local_storage_resolves_to_that_directory() {
    let temp = private_tempdir();
    let environment = override_env(&temp.path().display().to_string());
    let resolved = resolve_state_root(&environment, &NativeStateRootProbe).expect("resolved");
    assert_eq!(resolved.source(), StateRootSource::Override);
    assert_eq!(resolved.status(), DirectoryStatus::Directory);
    assert_eq!(resolved.storage_class().as_str(), "local_disk");
    assert!(resolved.canonicalized());
    assert!(!resolved.bootstrap_created());
    assert_eq!(
        resolved.root(),
        temp.path().canonicalize().expect("canonical")
    );
    // Ownership is either observed as owner-only or not observable at all; the
    // resolution never claims a private root it did not check.
    if let Some(observed) = resolved.ownership() {
        assert!(observed.owner_only, "detail: {}", observed.detail);
    }
}

#[test]
fn the_guard_directory_follows_the_frozen_abi_layout() {
    let temp = private_tempdir();
    let environment = override_env(&temp.path().display().to_string());
    let resolved = resolve_state_root(&environment, &NativeStateRootProbe).expect("resolved");
    assert!(resolved.home().is_ok());
    let guard = resolved
        .solution_guard_dir("inst-1")
        .expect("guard directory");
    assert!(guard.ends_with("instances/inst-1/solution.guard"));
    // A non-portable instance id is refused instead of guessed.
    assert!(resolved.solution_guard_dir("Inst 1").is_err());
    assert!(resolved.solution_guard_dir("").is_err());
}

#[test]
fn a_missing_override_reports_missing_and_bootstrap_creates_it_exactly_once() {
    let temp = private_tempdir();
    let target = temp.path().join("nested").join("state");
    let environment = override_env(&target.display().to_string());

    let error = resolve_state_root(&environment, &NativeStateRootProbe).expect_err("nothing yet");
    assert_eq!(error.envelope().code.as_str(), "UNSAFE_HOME_PATH");
    assert_eq!(
        error.details().get("actual").map(String::as_str),
        Some("missing")
    );
    assert!(!target.exists());

    let bootstrapped = ensure_state_root(&environment, &NativeStateRootProbe).expect("bootstrap");
    assert!(bootstrapped.bootstrap_created());
    assert_eq!(bootstrapped.status(), DirectoryStatus::Directory);
    assert!(target.is_dir());

    let second = ensure_state_root(&environment, &NativeStateRootProbe).expect("idempotent");
    assert!(!second.bootstrap_created(), "second run must not re-create");
}

// ------------------------------------------------- the platform defaults

#[test]
fn the_linux_default_is_xdg_state_home_over_axiom_and_the_home_fallback_matches() {
    let temp = private_tempdir();
    let axiom_dir = temp.path().join("axiom");
    std::fs::create_dir_all(&axiom_dir).expect("create");
    make_private(&axiom_dir);

    let xdg = StateEnvironment {
        platform: StatePlatform::Linux,
        xdg_state_home: Some(temp.path().display().to_string()),
        home_dir: Some(temp.path().display().to_string()),
        ..StateEnvironment::default()
    };
    let resolved = resolve_state_root(&xdg, &NativeStateRootProbe).expect("resolved");
    assert_eq!(resolved.source(), StateRootSource::PlatformDefault);
    assert!(resolved.root().ends_with("axiom"));

    // Without XDG_STATE_HOME the documented `$HOME/.local/state` fallback is used.
    let home_only = StateEnvironment {
        platform: StatePlatform::Linux,
        home_dir: Some(temp.path().display().to_string()),
        ..StateEnvironment::default()
    };
    let fallback = resolve_state_root(&home_only, &ScriptedProbe::new(DirectoryStatus::Directory))
        .expect("resolved");
    assert!(fallback.root().ends_with(".local/state/axiom"));
    assert_eq!(fallback.source(), StateRootSource::PlatformDefault);
}

#[test]
fn the_windows_default_is_local_app_data_and_bootstrap_creates_it() {
    let temp = private_tempdir();
    let environment = StateEnvironment {
        platform: StatePlatform::Windows,
        local_app_data: Some(temp.path().display().to_string()),
        ..StateEnvironment::default()
    };
    let resolved = ensure_state_root(&environment, &NativeStateRootProbe).expect("bootstrap");
    assert_eq!(resolved.source(), StateRootSource::PlatformDefault);
    assert!(resolved.bootstrap_created());
    assert!(resolved.root().ends_with("Axiom"));
    assert!(resolved.root().is_dir());
}

#[test]
fn the_macos_default_is_application_support() {
    let probe = ScriptedProbe::new(DirectoryStatus::Directory);
    let environment = StateEnvironment {
        platform: StatePlatform::MacOs,
        home_dir: Some("/Users/ada".to_string()),
        ..StateEnvironment::default()
    };
    let resolved = resolve_state_root(&environment, &probe).expect("resolved");
    assert_eq!(resolved.source(), StateRootSource::PlatformDefault);
    assert!(resolved
        .root()
        .ends_with("Library/Application Support/Axiom"));
}

// ------------------------------------------------------------- negative legs

#[test]
fn a_relative_override_is_refused_before_any_native_call() {
    let probe = ScriptedProbe::new(DirectoryStatus::Directory);
    let error = resolve_state_root(&override_env("state/axiom"), &probe).expect_err("refused");
    assert_eq!(error.envelope().code.as_str(), "UNSAFE_HOME_PATH");
    assert!(error.message().contains("absolute"));
    assert_eq!(
        probe.status_calls.get(),
        0,
        "no native probe call may happen"
    );
}

#[test]
fn a_shared_or_cloud_override_is_refused_and_the_storage_class_is_named() {
    for (spelling, expected) in [
        ("//fileserver/team/axiom", "network_share"),
        (r"\\?\C:\axiom", "unsupported_device"),
    ] {
        let probe = ScriptedProbe::new(DirectoryStatus::Directory);
        let error = resolve_state_root(&override_env(spelling), &probe).expect_err(spelling);
        assert_eq!(error.envelope().code.as_str(), "UNSAFE_HOME_PATH");
        assert_eq!(
            error.details().get("storage_class").map(String::as_str),
            Some(expected),
            "case {spelling}"
        );
        assert_eq!(probe.status_calls.get(), 0, "case {spelling}");
    }
}

#[test]
fn a_link_or_reparse_point_destination_is_refused() {
    let probe = ScriptedProbe::new(DirectoryStatus::Link);
    let error = resolve_state_root(&override_env("/var/state/axiom"), &probe).expect_err("link");
    assert_eq!(error.envelope().code.as_str(), "UNSAFE_HOME_PATH");
    assert_eq!(
        error.details().get("actual").map(String::as_str),
        Some("link-or-reparse-point")
    );
}

#[test]
fn a_destination_that_is_not_a_directory_is_refused() {
    let probe = ScriptedProbe::new(DirectoryStatus::NotADirectory);
    let error = resolve_state_root(&override_env("/var/state/axiom"), &probe).expect_err("file");
    assert_eq!(
        error.details().get("actual").map(String::as_str),
        Some("not-a-directory")
    );
}

#[test]
fn a_root_that_is_not_private_to_its_owner_is_refused() {
    let mut probe = ScriptedProbe::new(DirectoryStatus::Directory);
    probe.ownership = Some(Ownership {
        owner_only: false,
        detail: "mode 0777".to_string(),
    });
    let error = resolve_state_root(&override_env("/var/state/axiom"), &probe).expect_err("shared");
    assert_eq!(error.envelope().code.as_str(), "CONFIG_INVALID");
    assert!(error.message().contains("private"));
    assert_eq!(
        error.details().get("actual").map(String::as_str),
        Some("mode 0777")
    );
}

#[test]
fn a_host_that_cannot_observe_ownership_records_none_instead_of_claiming_private() {
    let probe = ScriptedProbe::new(DirectoryStatus::Directory);
    let resolution = resolve_state_root(&override_env("/var/state/axiom"), &probe).expect("ok");
    assert!(resolution.ownership().is_none());
    assert!(!resolution.canonicalized());
    assert_eq!(resolution.root().to_string_lossy(), "/var/state/axiom");
}

#[test]
fn a_missing_platform_fact_or_unknown_platform_is_a_config_error() {
    let probe = ScriptedProbe::new(DirectoryStatus::Directory);

    let windows_without_local_app_data = StateEnvironment {
        platform: StatePlatform::Windows,
        ..StateEnvironment::default()
    };
    let error =
        resolve_state_root(&windows_without_local_app_data, &probe).expect_err("no default");
    assert_eq!(error.envelope().code.as_str(), "CONFIG_INVALID");
    assert!(error.message().contains("LOCALAPPDATA"));

    let unknown = StateEnvironment {
        platform: StatePlatform::Unknown,
        ..StateEnvironment::default()
    };
    let error = resolve_state_root(&unknown, &probe).expect_err("unknown platform");
    assert_eq!(error.envelope().code.as_str(), "CONFIG_INVALID");

    assert_eq!(probe.status_calls.get(), 0);
}

// -------------------------------------------------- bootstrap failure bounds

#[test]
fn ensure_never_creates_anything_when_the_destination_is_a_link() {
    let probe = ScriptedProbe::new(DirectoryStatus::Link);
    let error = ensure_state_root(&override_env("/var/state/axiom"), &probe).expect_err("refused");
    assert_eq!(
        error.details().get("actual").map(String::as_str),
        Some("link-or-reparse-point")
    );
    assert_eq!(probe.create_calls.get(), 0, "refuse before create");
}

#[test]
fn a_create_failure_is_reported_with_the_host_reason_verbatim() {
    let mut probe = ScriptedProbe::new(DirectoryStatus::Missing);
    probe.create = Err("disk full".to_string());
    let error = ensure_state_root(&override_env("/var/state/axiom"), &probe).expect_err("failed");
    assert_eq!(error.envelope().code.as_str(), "UNSAFE_HOME_PATH");
    assert_eq!(
        error.details().get("actual").map(String::as_str),
        Some("disk full")
    );
    assert_eq!(probe.create_calls.get(), 1);
}

#[test]
fn creation_is_verified_by_observation_not_by_the_return_value_of_create() {
    // The probe accepts the create call but still reports a missing directory:
    // the oracle is the observation, so resolution must refuse.
    let probe = ScriptedProbe::new(DirectoryStatus::Missing);
    let error = ensure_state_root(&override_env("/var/state/axiom"), &probe).expect_err("refused");
    assert_eq!(error.envelope().code.as_str(), "UNSAFE_HOME_PATH");
    assert_eq!(
        error.details().get("actual").map(String::as_str),
        Some("missing")
    );
    assert_eq!(probe.create_calls.get(), 1);
    assert_eq!(
        probe.status_calls.get(),
        2,
        "resolve, create, resolve again"
    );
}

#[test]
fn a_non_private_override_is_refused_by_the_scripted_host_too() {
    // Same rule as the native leg above, but with a probe whose canonicalize
    // step succeeded: the ownership refusal is independent of canonicalisation.
    let mut probe = ScriptedProbe::new(DirectoryStatus::Directory);
    probe.canonical = Some(PathBuf::from("/private/var/state/axiom"));
    probe.ownership = Some(Ownership {
        owner_only: false,
        detail: "world-writable".to_string(),
    });
    let error = resolve_state_root(&override_env("/var/state/axiom"), &probe).expect_err("shared");
    assert_eq!(error.envelope().code.as_str(), "CONFIG_INVALID");
    assert!(error.message().contains("private"));
}
