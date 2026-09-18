//! Regression test for the multiple-project Solution guide (task D-005).
//!
//! `docs/guides/solutions.md` is part of the product, not a copy of it: the
//! worked example is compiled into this test binary and replayed through the
//! real membership surface (`graph_core::solution::validate_membership`), the
//! real portable-path policy (`graph_core::paths`) and the real pinned-catalog
//! vector (`graph_export::catalog`).
//!
//! Positive path: the documented two-repository solution with two projects in
//! one repository is accepted, every id is a portable id, and no value in the
//! portable example is an absolute host path, so the documented bindings stay
//! local. Negative and boundary paths: a nested project claim inside one
//! repository is refused as an ownership conflict, and an absolute project path
//! is refused as an unsafe portable path. The absolute-path scanner is itself
//! exercised against a mutated example, so a future edit that leaks a local
//! binding path into the guide fails the build instead of passing silently.

use graph_core::error::ErrorCode;
use graph_core::paths::{is_absolute_host_path, is_portable_id, validate_project_root_binding};
use graph_core::solution::{validate_membership, ProjectMembership, SolutionMembership};
use graph_export::catalog::{build, pin, CatalogMember, ERR_MEMBER_MISSING};
use graph_export::sha256_hex;
use serde_json::Value;

/// The guide document, compiled in so the documentation cannot drift alone.
const SOLUTIONS_GUIDE: &str = include_str!("../../../docs/guides/solutions.md");

const BEGIN: &str = "<!-- BEGIN SOLUTIONS EXAMPLE -->";
const END: &str = "<!-- END SOLUTIONS EXAMPLE -->";
const JSON_FENCE: &str = "```json";

/// The fenced `json` example between the guide's sentinel markers.
fn example_json() -> String {
    let after_begin = SOLUTIONS_GUIDE
        .split_once(BEGIN)
        .expect("the guide must keep its BEGIN marker")
        .1;
    let block = after_begin
        .split_once(END)
        .expect("the guide must keep its END marker")
        .0;
    let start = block
        .find(JSON_FENCE)
        .expect("the example must be a fenced json block")
        + JSON_FENCE.len();
    let rest = &block[start..];
    let end = rest.find("```").expect("the json fence must be closed");
    rest[..end].trim().to_owned()
}

fn example() -> Value {
    serde_json::from_str(&example_json()).expect("the documented example must be valid JSON")
}

/// Every string in `value` that looks like an absolute machine-local path.
fn absolute_paths(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            if is_absolute_host_path(text) {
                found.push(text.clone());
            }
        }
        Value::Array(items) => {
            for item in items {
                absolute_paths(item, found);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                absolute_paths(item, found);
            }
        }
        _ => {}
    }
}

/// Projects of the example as `(project_id, repo_id, path)`.
fn example_projects(value: &Value) -> Vec<(String, String, String)> {
    value
        .get("projects")
        .and_then(Value::as_array)
        .expect("example projects")
        .iter()
        .map(|project| {
            (
                project
                    .get("project_id")
                    .and_then(Value::as_str)
                    .expect("project_id")
                    .to_owned(),
                project
                    .get("repo_id")
                    .and_then(Value::as_str)
                    .expect("repo_id")
                    .to_owned(),
                project
                    .get("path")
                    .and_then(Value::as_str)
                    .expect("path")
                    .to_owned(),
            )
        })
        .collect()
}

fn membership_from(projects: &[(String, String, String)]) -> SolutionMembership {
    let members = projects
        .iter()
        .map(|(project, repo, path)| {
            ProjectMembership::new(project.clone(), repo.clone(), path.clone())
        })
        .collect();
    SolutionMembership::new("demo-solution", members)
}

/// AC1: the guide shows two repositories, a catalog host and multiple projects
/// per repository, and every id and path it documents satisfies the portable
/// policy the engine enforces.
#[test]
fn solutions_guide_example_is_a_multi_repo_solution_with_local_bindings() {
    let value = example();

    // The example is a solution document, not a path map.
    assert_eq!(value.get("schema_version").and_then(Value::as_u64), Some(2));
    assert_eq!(
        value.get("workspace_layout").and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        value.get("graph_output_root").and_then(Value::as_str),
        Some(".axiom/graph")
    );
    let solution_id = value
        .get("solution_id")
        .and_then(Value::as_str)
        .expect("solution_id");
    assert!(
        is_portable_id(solution_id),
        "{solution_id} must be a portable id"
    );

    // Two repositories, one of them the catalog host.
    let repo_ids: Vec<String> = value
        .get("repositories")
        .and_then(Value::as_array)
        .expect("repositories")
        .iter()
        .map(|repo| {
            let repo_id = repo
                .get("repo_id")
                .and_then(Value::as_str)
                .expect("repo_id")
                .to_owned();
            let binding_key = repo
                .get("binding_key")
                .and_then(Value::as_str)
                .expect("binding_key");
            assert!(is_portable_id(&repo_id), "{repo_id} must be a portable id");
            assert!(
                is_portable_id(binding_key),
                "a binding_key is a logical key, not a path: {binding_key}"
            );
            assert!(
                !is_absolute_host_path(binding_key),
                "a binding_key must never be an absolute path: {binding_key}"
            );
            repo_id
        })
        .collect();
    assert_eq!(repo_ids.len(), 2, "AC1 requires two repositories");
    let catalog_host = value
        .get("catalog_host_repo")
        .and_then(Value::as_str)
        .expect("catalog_host_repo");
    assert!(
        repo_ids.iter().any(|repo| repo == catalog_host),
        "the catalog host {catalog_host} must be one of the member repositories"
    );

    // Multiple projects per repository, all ids and paths valid.
    let projects = example_projects(&value);
    assert!(projects.len() >= 4, "the example documents four projects");
    for repo_id in &repo_ids {
        let count = projects
            .iter()
            .filter(|(_, repo, _)| repo == repo_id)
            .count();
        assert!(count >= 1, "repository {repo_id} must own a project");
    }
    assert!(
        repo_ids.iter().any(|repo_id| projects
            .iter()
            .filter(|(_, repo, _)| repo == repo_id)
            .count()
            >= 2),
        "AC1 requires multiple projects in one repository"
    );
    for (project, repo, path) in &projects {
        assert!(is_portable_id(project), "{project} must be a portable id");
        assert!(
            repo_ids.contains(repo),
            "project {project} names a repository that is not declared"
        );
        validate_project_root_binding(path).unwrap_or_else(|error| {
            panic!("project {project} path {path} is not portable: {error}")
        });
        assert!(
            !is_absolute_host_path(path),
            "a project path must stay repository-relative: {path}"
        );
    }
}

/// AC1, second half: membership is accepted and nothing in the portable
/// example is an absolute host path, so the local binding never leaks into the
/// committed document or the published catalog.
#[test]
fn solutions_guide_membership_is_accepted_and_bindings_stay_local() {
    let value = example();
    let projects = example_projects(&value);
    let report = validate_membership(&membership_from(&projects))
        .expect("the documented membership must be accepted");
    assert_eq!(report.projects(), projects.len());
    assert_eq!(report.repos(), 2);

    let mut offenders = Vec::new();
    absolute_paths(&value, &mut offenders);
    assert!(
        offenders.is_empty(),
        "the portable example must not contain a machine-local path: {offenders:?}"
    );

    // The guide must say where the absolute binding path actually lives.
    assert!(
        SOLUTIONS_GUIDE.contains("AXIOM_HOME/config/registry.json"),
        "the guide must show the machine-local binding store"
    );
    assert!(
        SOLUTIONS_GUIDE.contains("binding_key"),
        "the guide must name the portable binding key"
    );

    // A catalog over the same projects pins one generation per project and
    // carries no local path either.
    let members: Vec<CatalogMember> = projects
        .iter()
        .map(|(project, _, _)| CatalogMember {
            project_id: project.clone(),
            generation_id: sha256_hex(format!("generation-of-{project}").as_bytes()),
            source_fingerprint: format!("fp-{project}"),
        })
        .collect();
    let catalog = build(members).expect("a catalog over the documented projects");
    assert!(catalog.identity_is_self_consistent());
    assert_eq!(catalog.members.len(), projects.len());
    for (project, _, _) in &projects {
        assert!(
            catalog.member(project).is_some(),
            "catalog must pin {project}"
        );
    }
    let catalog_json: Value =
        serde_json::from_str(&serde_json::to_string(&catalog).expect("serialize catalog"))
            .expect("catalog round trip");
    let mut catalog_offenders = Vec::new();
    absolute_paths(&catalog_json, &mut catalog_offenders);
    assert!(
        catalog_offenders.is_empty(),
        "a published catalog must not carry a local path: {catalog_offenders:?}"
    );
}

/// Negative: a project claim nested inside another project's claim in the same
/// repository is an ownership conflict, not a valid multiple-project layout.
#[test]
fn solutions_guide_refuses_a_nested_project_claim_in_one_repository() {
    let value = example();
    let mut projects = example_projects(&value);
    let nested = projects
        .iter_mut()
        .find(|(project, _, _)| project == "proj-portal")
        .expect("proj-portal");
    nested.2 = "src/App/generated".to_owned();

    let error = validate_membership(&membership_from(&projects))
        .expect_err("a nested claim must be refused");
    assert_eq!(error.code(), ErrorCode::Conflict);
    assert_eq!(
        error.details().get("rule").map(String::as_str),
        Some("root-overlap")
    );
}

/// Boundary: a project path that is an absolute machine-local path is refused
/// by the portable-path policy, both on its own and through membership.
#[test]
fn solutions_guide_rejects_an_absolute_project_path() {
    let absolute = r"C:\work\repo-beta";
    let direct = validate_project_root_binding(absolute)
        .expect_err("an absolute project path must be refused");
    assert_eq!(direct.code(), ErrorCode::UnsafePortablePath);

    let value = example();
    let mut projects = example_projects(&value);
    projects
        .iter_mut()
        .find(|(project, _, _)| project == "proj-jobs")
        .expect("proj-jobs")
        .2 = absolute.to_owned();
    let error = validate_membership(&membership_from(&projects))
        .expect_err("membership must refuse an absolute project path");
    assert_eq!(error.code(), ErrorCode::UnsafePortablePath);

    // The scanner the AC1 assertion relies on really does see the leak, so a
    // future edit that writes a host path into the guide fails the test above
    // rather than passing through an inert check.
    let leaked = serde_json::json!({ "projects": [{ "path": absolute }] });
    let mut found = Vec::new();
    absolute_paths(&leaked, &mut found);
    assert_eq!(found, vec![absolute.to_owned()]);
}

/// Boundary: a member that disappears from a two-repository catalog is refused
/// unless it was dropped explicitly, so one repository cannot silently take the
/// other's pinned generation.
#[test]
fn solutions_guide_catalog_refuses_a_vanished_member_across_repos() {
    let projects = example_projects(&example());
    let member = |project: &str| CatalogMember {
        project_id: project.to_owned(),
        generation_id: sha256_hex(format!("generation-of-{project}").as_bytes()),
        source_fingerprint: format!("fp-{project}"),
    };
    let previous = build(
        projects
            .iter()
            .map(|(project, _, _)| member(project))
            .collect(),
    )
    .expect("initial catalog");

    let without_jobs: Vec<CatalogMember> = projects
        .iter()
        .filter(|(project, _, _)| project != "proj-jobs")
        .map(|(project, _, _)| member(project))
        .collect();
    let error = pin(Some(&previous), without_jobs.clone(), &[])
        .expect_err("a vanished member must be refused");
    assert_eq!(error.code, ERR_MEMBER_MISSING);

    let allowed = pin(Some(&previous), without_jobs, &["proj-jobs"]).expect("explicit drop");
    assert_eq!(allowed.members.len(), projects.len() - 1);
    assert!(allowed.member("proj-jobs").is_none());
}
