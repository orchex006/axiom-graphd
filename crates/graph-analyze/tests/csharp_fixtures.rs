//! Fixture-driven regression tests for the C# narrow scan (task F-004).
//!
//! The deliverable is `fixtures/csharp/`: tiny, deterministic C# sources plus a
//! `*.expected.json` manifest per fixture recording exactly what this build must
//! extract and, just as importantly, what it must refuse. These tests are the
//! executable half of those manifests. They drive the real `graph_analyze` APIs
//! and assert both the supported symbols and the explicit unsupported outcomes,
//! so the fixtures cannot drift into wishes the analyser does not satisfy.
//!
//! Negative and boundary coverage (AC2) lives in the `unsupported_dynamic` and
//! `malformed_boundary` fixtures: a dynamic or reflective construct must yield
//! no invented symbol and an explicit `call-dynamic-dispatch` refusal, and a
//! malformed file must report `partial` coverage with diagnostics instead of a
//! silently complete empty result.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use graph_analyze::adapter::Language;
use graph_analyze::calls::{self, CallInput, CallKind, CallSite, DeclaredTarget, TargetKind};
use graph_analyze::csharp::declarations::{self, CsharpAnalysis};
use graph_analyze::types::literal_base_names;
use graph_analyze::{CoverageStatus, Severity};
use serde_json::Value;

/// One declaration flattened to the manifest's shape.
struct Observed {
    kind: String,
    name: String,
    semantic_path: Vec<String>,
    span_text: String,
    key: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn fixture_dir() -> PathBuf {
    repo_root().join("fixtures").join("csharp")
}

fn read_text(path: &PathBuf) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn manifest(stem: &str) -> Value {
    let path = fixture_dir().join(format!("{stem}.expected.json"));
    let text = read_text(&path);
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()))
}

fn string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("expected an array, got {value}"))
        .iter()
        .map(|item| item.as_str().expect("expected a string item").to_string())
        .collect()
}

/// Like `string_list`, but an absent or null section means "none declared".
fn optional_string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().expect("expected a string item").to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn observe(source: &str, analysis: &CsharpAnalysis) -> Vec<Observed> {
    analysis
        .declarations
        .iter()
        .map(|declaration| Observed {
            kind: declaration.kind.as_str().to_string(),
            name: declaration.name.clone(),
            semantic_path: declaration.semantic_path.clone(),
            span_text: declaration
                .span
                .slice(source)
                .unwrap_or_else(|| panic!("declaration span must slice the source"))
                .to_string(),
            key: declaration.key.clone(),
        })
        .collect()
}

fn warning_codes(analysis: &CsharpAnalysis) -> Vec<String> {
    let mut codes: Vec<String> = analysis
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == Severity::Warning)
        .map(|diagnostic| diagnostic.code.clone())
        .collect();
    codes.sort();
    codes.dedup();
    codes
}

/// Assert a fixture manifest against the live analyser.
///
/// Returns the fixture source and the observed declarations so callers can add
/// fixture-specific boundary assertions on top of the shared manifest checks.
fn assert_declaration_manifest(stem: &str) -> (String, Vec<Observed>) {
    let manifest = manifest(stem);
    let name = manifest["fixture"].as_str().expect("fixture name");
    let source = read_text(&fixture_dir().join(name));
    let analysis = declarations::analyze(name, &source);
    let observed = observe(&source, &analysis);

    let coverage = analysis.coverage();
    assert_eq!(
        coverage.status.as_str(),
        manifest["expected_coverage_status"]
            .as_str()
            .expect("expected_coverage_status"),
        "{stem}: coverage status must match the manifest"
    );

    let mut error_codes = analysis.error_codes();
    error_codes.sort();
    assert_eq!(
        error_codes,
        string_list(&manifest["expected_error_codes"]),
        "{stem}: error codes must match the manifest"
    );

    assert_eq!(
        warning_codes(&analysis),
        string_list(&manifest["expected_warning_codes"]),
        "{stem}: warning codes must match the manifest"
    );

    let expected = manifest["expected_declarations"]
        .as_array()
        .expect("expected_declarations array");
    assert_eq!(
        observed.len(),
        expected.len(),
        "{stem}: declaration count must match the manifest"
    );
    for (index, expected) in expected.iter().enumerate() {
        let actual = &observed[index];
        assert_eq!(
            actual.kind,
            expected["kind"].as_str().expect("kind"),
            "{stem}[{index}]: declaration kind"
        );
        assert_eq!(
            actual.name,
            expected["name"].as_str().expect("name"),
            "{stem}[{index}]: declaration name"
        );
        assert_eq!(
            actual.semantic_path,
            string_list(&expected["semantic_path"]),
            "{stem}[{index}]: semantic path"
        );
        assert_eq!(
            actual.span_text,
            expected["span_text"].as_str().expect("span_text"),
            "{stem}[{index}]: span text"
        );
    }

    // Refusing to guess is the behaviour under test: every name the manifest
    // lists as unsupported must be absent from the declarations the scan
    // produced, so a future extractor cannot silently start inventing it.
    for absent in optional_string_list(&manifest["expected_symbol_absence"]) {
        assert!(
            !observed
                .iter()
                .any(|declaration| declaration.name == absent),
            "{stem}: the analyser must not invent a symbol named {absent:?}"
        );
    }

    if let Some(headers) = manifest["inheritance_headers"].as_array() {
        for case in headers {
            let header = case["header"].as_str().expect("header");
            assert!(
                source.contains(header),
                "{stem}: fixture must contain the inherited header {header:?}"
            );
            assert_eq!(
                literal_base_names(Language::CSharp, header),
                string_list(&case["expected_bases"]),
                "{stem}: literal bases of {header:?}"
            );
        }
    }

    let mut method_counts: BTreeMap<String, usize> = BTreeMap::new();
    for declaration in &observed {
        if declaration.kind == "method" {
            *method_counts
                .entry(declaration.semantic_path.join("."))
                .or_default() += 1;
        }
    }
    if let Some(expected_counts) = manifest["expected_method_counts"].as_object() {
        for (path, expected) in expected_counts {
            assert_eq!(
                method_counts.get(path).copied().unwrap_or(0),
                expected.as_u64().expect("method count") as usize,
                "{stem}: method count under {path}"
            );
        }
    }

    if let Some(cases) = manifest["resolution_cases"].as_array() {
        for case in cases {
            assert_resolution_case(stem, case, &observed);
        }
    }

    (source, observed)
}

/// Drive one `resolution_cases` entry through the real call resolver.
///
/// The fixture declares the *shape* of the site; this function builds the
/// `CallInput` from the declarations the scan produced and asserts whether the
/// resolver proves an edge or records an explicit refusal.
fn assert_resolution_case(stem: &str, case: &Value, observed: &[Observed]) {
    let id = case["id"].as_str().expect("resolution case id");
    let kind = case["kind"].as_str().expect("resolution case kind");
    let expect = case["expect"].as_str().expect("resolution case expect");
    let file = format!("{stem}.cs");
    let caller = "App.Core.GreetingHandler";

    let targets: Vec<DeclaredTarget> = observed
        .iter()
        .filter(|declaration| declaration.kind == "method")
        .map(|declaration| {
            let mut qualified = declaration.semantic_path.clone();
            qualified.push(declaration.name.clone());
            DeclaredTarget::new(
                declaration.key.clone(),
                qualified,
                declaration.semantic_path.last().cloned(),
                TargetKind::Method,
            )
        })
        .collect();

    let site = if kind == "dynamic" {
        CallSite::unresolved_kind(file.as_str(), caller, CallKind::Dynamic, 1)
    } else {
        CallSite::literal(
            file.as_str(),
            caller,
            CallKind::Direct,
            string_list(&case["callee"]),
            1,
        )
    };
    let graph = calls::resolve(&CallInput {
        targets,
        implements: Vec::new(),
        sites: vec![site],
    });

    match expect {
        "resolved" => {
            assert!(
                graph.unresolved.is_empty(),
                "{stem}/{id}: expected a proven edge, got refusals {:?}",
                graph.unresolved
            );
            assert_eq!(
                graph.edges.len(),
                1,
                "{stem}/{id}: expected exactly one proven edge"
            );
            let edge = &graph.edges[0];
            assert_eq!(
                edge.kind.as_str(),
                case["edge_kind"].as_str().expect("edge_kind"),
                "{stem}/{id}: edge kind"
            );
            assert_eq!(
                edge.quality.as_str(),
                case["quality"].as_str().expect("quality"),
                "{stem}/{id}: call quality"
            );
        }
        "unresolved" => {
            assert!(
                graph.edges.is_empty(),
                "{stem}/{id}: expected no proven edge, got {:?}",
                graph.edges
            );
            assert_eq!(
                graph.unresolved.len(),
                1,
                "{stem}/{id}: expected exactly one refusal"
            );
            assert_eq!(
                graph.unresolved[0].reason,
                case["reason"].as_str().expect("reason"),
                "{stem}/{id}: refusal reason"
            );
        }
        other => panic!("{stem}/{id}: unknown expectation {other:?}"),
    }
}

/// Supported symbols: every declaration, base name and resolution outcome the
/// fully static fixture promises.
#[test]
fn csharp_static_declarations_match_the_manifest() {
    let (source, observed) = assert_declaration_manifest("declarations_basic");
    assert!(
        observed
            .iter()
            .any(|declaration| declaration.name == "GreetingHandler"),
        "the static fixture must still declare GreetingHandler"
    );
    assert!(
        source.contains("using System.Threading.Tasks;"),
        "fixture drift: the using directives the scan deliberately ignores are gone"
    );
}

/// Negative case: dynamic dispatch, reflection and source-generated members
/// must produce no symbol and no call target, and the resolver must refuse them
/// with an explicit reason rather than guessing.
#[test]
fn csharp_unsupported_constructs_are_refused_not_guessed() {
    let (_, observed) = assert_declaration_manifest("unsupported_dynamic");
    for invented in ["Run", "GetMethod", "CreateInstance", "Activator"] {
        assert!(
            !observed
                .iter()
                .any(|declaration| declaration.name == invented),
            "the dynamic fixture must not yield a declaration named {invented:?}"
        );
    }
    assert_eq!(
        observed.len(),
        5,
        "the scan records only the five literal declarations of the dynamic fixture"
    );
}

/// Boundary case: two partial declarations of one type are recorded literally
/// and are never merged, so they share one identity key while their members
/// keep distinct keys.
#[test]
fn csharp_partial_declarations_are_recorded_but_not_merged() {
    let manifest = manifest("partial_class_boundary");
    let (_, observed) = assert_declaration_manifest("partial_class_boundary");

    let widgets: Vec<&Observed> = observed
        .iter()
        .filter(|declaration| declaration.kind == "class" && declaration.name == "Widget")
        .collect();
    let expected_count = manifest["expected_duplicate_key"]["count"]
        .as_u64()
        .expect("duplicate count") as usize;
    assert_eq!(
        widgets.len(),
        expected_count,
        "both partial declarations are recorded"
    );
    assert_eq!(
        widgets[0].key, widgets[1].key,
        "partial declarations of one type must share one identity key"
    );

    let first = observed
        .iter()
        .find(|declaration| declaration.name == "First")
        .expect("First method");
    let second = observed
        .iter()
        .find(|declaration| declaration.name == "Second")
        .expect("Second method");
    assert_ne!(
        first.key, second.key,
        "distinct members of a partial type must keep distinct keys"
    );
}

/// Negative case: a malformed source must be reported, never silently accepted
/// as an empty complete analysis.
#[test]
fn csharp_malformed_fixture_reports_partial_coverage() {
    let name = "malformed_boundary.cs";
    let source = read_text(&fixture_dir().join(name));
    let analysis = declarations::analyze(name, &source);
    let coverage = analysis.coverage();

    assert_eq!(
        coverage.status,
        CoverageStatus::Partial,
        "a malformed file must not claim complete coverage"
    );
    assert!(!coverage.claims_completeness());
    assert_eq!(coverage.input_files, 1);
    assert_eq!(
        coverage.processed_files, 0,
        "no facts are produced for an unparseable file"
    );

    let codes = analysis.error_codes();
    assert!(
        codes.contains(&"csharp-missing-name"),
        "the nameless class keyword must be reported, got {codes:?}"
    );
    assert!(
        codes.contains(&"csharp-unbalanced-braces"),
        "the unbalanced braces must be reported, got {codes:?}"
    );
}

/// The component-local fixture policy is part of the deliverable, so it is
/// asserted rather than merely documented.
#[test]
fn fixture_readme_records_the_component_local_policy() {
    let readme = read_text(&repo_root().join("fixtures").join("README.md"));
    for phrase in [
        "component-local regression fixtures",
        "not shared contract fixtures",
        "approved spec change",
        "axiom-specs",
    ] {
        assert!(
            readme.contains(phrase),
            "fixtures/README.md must state {phrase:?}"
        );
    }
}
