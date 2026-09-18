//! Config and dependency fingerprints and their invalidation scope (task B-030).
//!
//! Not every changed file invalidates the same amount of graph. Editing a source
//! file affects that file; editing a project file changes which sources belong
//! to the project; editing a solution file changes which projects belong to the
//! solution; editing a lock file or a shared build props file can change
//! compilation for many projects at once. The watcher must widen the
//! reconciliation scope accordingly, and it must not widen it for the build
//! outputs it already ignores
//! (`docs/15-STATIC-ANALYSIS-COVERAGE.md` section 5).
//!
//! A fingerprint is the digest of the file content. Storing it lets the daemon
//! distinguish a real change from a touch, so an unchanged rewrite does not
//! trigger an expensive rebuild.

use crate::ignore::IgnorePolicy;
use crate::portable_relative_path;
use graph_core::error::AxiomError;

/// Category of a configuration input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigKind {
    /// A project file (`*.csproj`, `*.fsproj`, `*.vbproj`).
    ProjectManifest,
    /// A solution file (`*.sln`, `*.slnx`, `*.slnf`).
    SolutionFile,
    /// A package manifest (`package.json`, `pyproject.toml`).
    PackageManifest,
    /// A dependency lock file.
    PackageLock,
    /// A TypeScript or JavaScript project configuration.
    TypeScriptConfig,
    /// A shared MSBuild props or targets file.
    SharedBuildConfig,
    /// A human architectural annotation under the project.
    Annotation,
    /// Solution-level route or endpoint mapping configuration.
    RouteConfig,
}

impl ConfigKind {
    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProjectManifest => "project_manifest",
            Self::SolutionFile => "solution_file",
            Self::PackageManifest => "package_manifest",
            Self::PackageLock => "package_lock",
            Self::TypeScriptConfig => "typescript_config",
            Self::SharedBuildConfig => "shared_build_config",
            Self::Annotation => "annotation",
            Self::RouteConfig => "route_config",
        }
    }
}

/// How much of the graph one configuration change invalidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvalidationScope {
    /// Only the project that owns the file.
    Project,
    /// Every project in the solution.
    Solution,
    /// The path is not a configuration input; nothing is invalidated.
    None,
}

/// The decision for one candidate configuration path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalidation {
    path: String,
    kind: Option<ConfigKind>,
    scope: InvalidationScope,
    fingerprint: Option<String>,
}

impl Invalidation {
    /// Project-relative path that was classified.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Configuration category, when the path is a configuration input.
    #[must_use]
    pub const fn kind(&self) -> Option<ConfigKind> {
        self.kind
    }

    /// Scope the change invalidates.
    #[must_use]
    pub const fn scope(&self) -> InvalidationScope {
        self.scope
    }

    /// Digest of the new content, present only for a real configuration input.
    #[must_use]
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }
}

/// Classify one project-relative path as a configuration input.
#[must_use]
pub fn classify(path: &str) -> Option<ConfigKind> {
    let path = portable_relative_path(path).ok()?;
    let segments: Vec<&str> = path.split('/').collect();
    let last = segments[segments.len() - 1];
    let lower = last.to_ascii_lowercase();

    if segments[..segments.len() - 1]
        .iter()
        .any(|segment| segment.eq_ignore_ascii_case("annotations"))
    {
        return Some(ConfigKind::Annotation);
    }
    if matches!(
        lower.as_str(),
        "directory.build.props" | "directory.build.targets"
    ) {
        return Some(ConfigKind::SharedBuildConfig);
    }
    if matches!(
        lower.as_str(),
        "directory.packages.props" | "nuget.config" | "packages.lock.json"
    ) {
        return Some(ConfigKind::PackageLock);
    }
    if lower.ends_with(".sln") || lower.ends_with(".slnx") || lower.ends_with(".slnf") {
        return Some(ConfigKind::SolutionFile);
    }
    if lower.ends_with(".csproj") || lower.ends_with(".fsproj") || lower.ends_with(".vbproj") {
        return Some(ConfigKind::ProjectManifest);
    }
    if matches!(
        lower.as_str(),
        "package.json"
            | "pyproject.toml"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "bun.lockb"
    ) {
        if lower.contains("lock") {
            return Some(ConfigKind::PackageLock);
        }
        return Some(ConfigKind::PackageManifest);
    }
    if lower == "tsconfig.json"
        || lower == "jsconfig.json"
        || (lower.starts_with("tsconfig.") && lower.ends_with(".json"))
    {
        return Some(ConfigKind::TypeScriptConfig);
    }
    if matches!(lower.as_str(), "routes.json" | "endpoints.json") {
        return Some(ConfigKind::RouteConfig);
    }
    None
}

/// Scope one configuration change invalidates.
///
/// A solution file and a shared build configuration file affect every project in
/// the solution. A project manifest, a package manifest, a lock file, a
/// TypeScript configuration, an annotation or a route configuration affect only
/// the project that owns the file.
#[must_use]
pub const fn scope_of(kind: ConfigKind) -> InvalidationScope {
    match kind {
        ConfigKind::SolutionFile | ConfigKind::SharedBuildConfig => InvalidationScope::Solution,
        ConfigKind::ProjectManifest
        | ConfigKind::PackageManifest
        | ConfigKind::PackageLock
        | ConfigKind::TypeScriptConfig
        | ConfigKind::Annotation
        | ConfigKind::RouteConfig => InvalidationScope::Project,
    }
}

/// Digest of one configuration file content.
#[must_use]
pub fn content_fingerprint(bytes: &[u8]) -> String {
    crate::inventory::content_digest(bytes)
}

/// Whether a fingerprint differs from the stored one.
#[must_use]
pub fn fingerprint_changed(previous: Option<&str>, current: &str) -> bool {
    match previous {
        Some(previous) => previous != current,
        None => true,
    }
}

/// Classify a changed path and fingerprint it.
///
/// Ignored build outputs are classified before the configuration rules, so a
/// `*.csproj` copied into `obj/` does not invalidate a project
/// (`docs/15-STATIC-ANALYSIS-COVERAGE.md` section 4).
///
/// # Errors
/// [`ErrorCode::ValidationError`] when the path is not a canonical portable
/// relative path.
pub fn invalidate(
    path: &str,
    content: &[u8],
    ignore: &IgnorePolicy,
) -> Result<Invalidation, AxiomError> {
    let path = portable_relative_path(path)?;
    if !ignore.classify(&path)?.is_tracked() {
        return Ok(Invalidation {
            path,
            kind: None,
            scope: InvalidationScope::None,
            fingerprint: None,
        });
    }
    match classify(&path) {
        Some(kind) => Ok(Invalidation {
            path,
            kind: Some(kind),
            scope: scope_of(kind),
            fingerprint: Some(content_fingerprint(content)),
        }),
        None => Ok(Invalidation {
            path,
            kind: None,
            scope: InvalidationScope::None,
            fingerprint: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify, content_fingerprint, fingerprint_changed, invalidate, scope_of, ConfigKind,
        InvalidationScope,
    };
    use crate::ignore::IgnorePolicy;
    use graph_core::error::ErrorCode;

    #[test]
    fn project_configuration_invalidates_only_its_project() {
        let policy = IgnorePolicy::default();
        for (path, kind, scope) in [
            (
                "src/Server/Server.csproj",
                ConfigKind::ProjectManifest,
                InvalidationScope::Project,
            ),
            (
                "web/package.json",
                ConfigKind::PackageManifest,
                InvalidationScope::Project,
            ),
            (
                "web/tsconfig.build.json",
                ConfigKind::TypeScriptConfig,
                InvalidationScope::Project,
            ),
            (
                "src/Server/packages.lock.json",
                ConfigKind::PackageLock,
                InvalidationScope::Project,
            ),
            (
                "src/Server/annotations/domain.json",
                ConfigKind::Annotation,
                InvalidationScope::Project,
            ),
        ] {
            let decision = invalidate(path, b"{ }", &policy).expect("portable");
            assert_eq!(decision.kind(), Some(kind), "path {path}");
            assert_eq!(decision.scope(), scope, "path {path}");
            assert!(decision.fingerprint().is_some());
        }
        assert_eq!(
            scope_of(ConfigKind::SolutionFile),
            InvalidationScope::Solution
        );
    }

    #[test]
    fn solution_and_shared_build_configuration_invalidate_the_solution() {
        let policy = IgnorePolicy::default();
        for path in [
            "App.sln",
            "App.slnx",
            "Directory.Build.props",
            "Directory.Build.targets",
        ] {
            let decision = invalidate(path, b"<Project />", &policy).expect("portable");
            assert_eq!(decision.scope(), InvalidationScope::Solution, "path {path}");
        }
    }

    #[test]
    fn ignored_build_outputs_never_invalidate_anything() {
        let policy = IgnorePolicy::default();
        for path in [
            "obj/Debug/net8.0/Server.csproj",
            "src/bin/Release/Server.csproj",
            "live/tsconfig.json",
        ] {
            let decision = invalidate(path, b"{}", &policy).expect("portable");
            assert_eq!(
                decision.scope(),
                InvalidationScope::None,
                "path {path} is a build output, not a configuration input"
            );
            assert_eq!(decision.kind(), None);
            assert_eq!(decision.fingerprint(), None);
        }
        assert_eq!(classify("src/App.cs"), None);

        let error =
            invalidate("C:/outside/App.sln", b"", &policy).expect_err("absolute paths are refused");
        assert_eq!(error.code(), ErrorCode::ValidationError);
    }

    #[test]
    fn fingerprints_are_stable_and_detect_real_changes() {
        let policy = IgnorePolicy::default();
        let first = invalidate("App.sln", b"solution-v1", &policy).expect("portable");
        let second = invalidate("App.sln", b"solution-v1", &policy).expect("portable");
        let third = invalidate("App.sln", b"solution-v2", &policy).expect("portable");
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_ne!(first.fingerprint(), third.fingerprint());
        assert!(!fingerprint_changed(
            first.fingerprint(),
            second.fingerprint().expect("fingerprint")
        ));
        assert!(fingerprint_changed(
            first.fingerprint(),
            third.fingerprint().expect("fingerprint")
        ));
        assert!(fingerprint_changed(None, "anything"));
        assert_eq!(content_fingerprint(b"").len(), 64);
    }
}
