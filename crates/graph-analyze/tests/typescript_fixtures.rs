//! Fixture-driven regression tests for the TypeScript and Angular adapters
//! (task F-005).
//!
//! The deliverable is `fixtures/typescript/`: tiny, deterministic sources plus a
//! `*.expected.json` manifest per fixture. These tests are the executable half of
//! those manifests and drive the real `graph_analyze` APIs, so a statically
//! resolvable import or a literal HTTP call can never be conflated with a
//! computed or ambiguous shape the build must refuse.
//!
//! Negative and boundary coverage (AC2) lives in the computed and ambiguous
//! import statements, the template-literal / computed / non-literal-verb /
//! non-client HTTP cases, and the truncated declaration fixture: each must be
//! reported with an explicit reason or a diagnostic instead of being guessed,
//! and a truncated file must not be accepted as a silently complete analysis.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use graph_analyze::imports::{self, AliasRule, ImportStatement, PathConfig, Resolution};
use graph_analyze::l3::{angular_http, dotnet_routes::HttpVerb};
use graph_analyze::typescript::declarations;
use graph_analyze::{CoverageStatus, Severity, Span};
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn fixture_dir() -> PathBuf {
    repo_root().join("fixtures").join("typescript")
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

fn rows(value: &Value) -> &Vec<Value> {
    value
        .as_array()
        .expect("expected an array of manifest rows")
}

/// The fixture source a manifest names, plus the manifest itself.
fn fixture_source(manifest_data: &Value) -> (String, String) {
    let name = manifest_data["fixture"]
        .as_str()
        .expect("fixture name")
        .to_string();
    let source = read_text(&fixture_dir().join(&name));
    (name, source)
}

fn path_config(manifest_data: &Value) -> PathConfig {
    let section = &manifest_data["path_config"];
    let mut config = PathConfig::new(string_list(&section["extensions"]));
    let index_names = optional_string_list(&section["index_names"]);
    if !index_names.is_empty() {
        config = config.with_index_names(index_names);
    }
    for alias in rows(&section["aliases"]) {
        config = config.with_alias(AliasRule::new(
            alias["prefix"].as_str().expect("alias prefix").to_string(),
            string_list(&alias["targets"]),
        ));
    }
    config
}

fn known_files(manifest_data: &Value) -> BTreeSet<String> {
    string_list(&manifest_data["known_files"])
        .into_iter()
        .collect()
}

fn statement_of(row: &Value) -> ImportStatement {
    let file = row["file"].as_str().expect("file").to_string();
    let span = Span::new(0, 1);
    match row["specifier"].as_str() {
        Some(specifier) => ImportStatement::literal(file, specifier, span),
        None => ImportStatement::unsupported(file, span),
    }
}

fn resolved_imports(stem: &str) -> (String, String, Vec<Value>, Vec<imports::ResolvedImport>) {
    let manifest_data = manifest(stem);
    let (name, source) = fixture_source(&manifest_data);
    let known = known_files(&manifest_data);
    let config = path_config(&manifest_data);
    let table = rows(&manifest_data["statements"]).clone();
    let statements: Vec<ImportStatement> = table.iter().map(statement_of).collect();
    let resolved = imports::resolve_all(&statements, &known, &config);
    assert_eq!(
        resolved.len(),
        statements.len(),
        "{stem}: resolve_all must preserve the statement order and count"
    );
    (name, source, table, resolved)
}

fn verb_of(text: &str) -> HttpVerb {
    HttpVerb::all()
        .iter()
        .copied()
        .find(|verb| verb.as_str() == text)
        .unwrap_or_else(|| panic!("unknown verb {text:?}"))
}

/// AC1 positive: every statement the manifest marks resolvable resolves to the
/// recorded target through the recorded rule, and no refused statement is ever
/// published as a resolved edge.
#[test]
fn typescript_static_imports_match_the_manifest() {
    let (_name, source, table, resolved) = resolved_imports("imports_module_graph");
    let mut resolved_count = 0_usize;

    for (row, observed) in table.iter().zip(&resolved) {
        let id = row["id"].as_str().expect("id");
        let text = row["statement_text"].as_str().expect("statement_text");
        assert!(
            source.contains(text),
            "{id}: fixture drift, the source no longer contains {text:?}"
        );
        assert_eq!(
            observed.kind.as_str(),
            row["expected_kind"].as_str().expect("expected_kind"),
            "{id}: specifier kind"
        );

        if row["expect"].as_str().expect("expect") != "resolved" {
            continue;
        }
        resolved_count += 1;
        match &observed.resolution {
            Resolution::Resolved {
                target,
                rule,
                quality,
            } => {
                assert_eq!(
                    target,
                    row["target"].as_str().expect("target"),
                    "{id}: target"
                );
                assert_eq!(rule, row["rule"].as_str().expect("rule"), "{id}: rule");
                assert_eq!(
                    quality.as_str(),
                    row["quality"].as_str().expect("quality"),
                    "{id}: quality"
                );
            }
            other => panic!("{id}: expected a resolved import, got {other:?}"),
        }
    }

    assert_eq!(
        resolved_count, 3,
        "three statement shapes must resolve uniquely"
    );
    assert_eq!(
        resolved
            .iter()
            .filter(|item| item.resolution.is_resolved())
            .count(),
        resolved_count,
        "no refused statement may be published as a resolved edge"
    );
}

/// AC1 separation plus AC2 negative: computed specifiers, bare packages, missing
/// targets, escaping specifiers and ambiguous matches are all refused with an
/// explicit reason or candidate set, never collapsed to one guessed target.
#[test]
fn typescript_dynamic_and_ambiguous_imports_are_refused_not_guessed() {
    let (_name, _source, table, resolved) = resolved_imports("imports_module_graph");
    let mut ambiguous = 0_usize;
    let mut unresolved = 0_usize;

    for (row, observed) in table.iter().zip(&resolved) {
        let id = row["id"].as_str().expect("id");
        match row["expect"].as_str().expect("expect") {
            "resolved" => {}
            "ambiguous" => {
                ambiguous += 1;
                match &observed.resolution {
                    Resolution::Ambiguous { candidates, rule } => {
                        assert_eq!(rule, row["rule"].as_str().expect("rule"), "{id}: rule");
                        let mut expected = string_list(&row["candidates"]);
                        expected.sort();
                        let mut actual = candidates.clone();
                        actual.sort();
                        assert_eq!(actual, expected, "{id}: candidate set");
                    }
                    other => panic!("{id}: expected ambiguity, got {other:?}"),
                }
            }
            "unresolved" => {
                unresolved += 1;
                assert_eq!(
                    observed.resolution,
                    Resolution::Unresolved {
                        reason: row["reason"].as_str().expect("reason").to_string()
                    },
                    "{id}: refusal reason"
                );
                assert!(
                    !observed.resolution.is_resolved(),
                    "{id}: a refused statement must not resolve"
                );
            }
            other => panic!("{id}: unknown expectation {other:?}"),
        }
    }

    assert_eq!(ambiguous, 2, "both ambiguous shapes must stay ambiguous");
    assert_eq!(
        unresolved, 5,
        "every dynamic or missing shape must stay unresolved"
    );
}

/// A re-export resolves the literal module path only. The re-exported symbol
/// identity is a documented unsupported case: the resolver returns no symbol
/// field and must never fabricate the re-exported name.
#[test]
fn typescript_re_exports_never_claim_the_reexported_symbol() {
    let manifest_data = manifest("imports_module_graph");
    let (_name, source, table, resolved) = resolved_imports("imports_module_graph");
    assert!(
        source.contains("export { Clock } from './clock';"),
        "fixture drift: the literal re-export is gone"
    );

    let mut checked = 0_usize;
    for (row, observed) in table.iter().zip(&resolved) {
        let Some(symbol) = row["not_claimed_symbol"].as_str() else {
            continue;
        };
        checked += 1;
        let id = row["id"].as_str().expect("id");
        assert!(
            matches!(observed.resolution, Resolution::Resolved { .. }),
            "{id}: the literal re-export module path must still resolve"
        );
        assert!(
            !format!("{observed:?}").contains(symbol),
            "{id}: the re-exported symbol {symbol:?} must not be invented"
        );
    }
    assert_eq!(
        checked, 1,
        "the manifest must declare exactly one re-export symbol case"
    );

    let documented = rows(&manifest_data["not_supported"])
        .iter()
        .any(|entry| entry["id"].as_str() == Some("typescript-reexport-symbol-identity"));
    assert!(
        documented,
        "the unsupported re-export symbol case must be documented in the manifest"
    );
}

/// AC1 positive: literal routes, literal verbs and a literal absolute URL are
/// extracted exactly as the manifest records them.
#[test]
fn angular_literal_http_calls_match_the_manifest() {
    let manifest_data = manifest("services_http");
    let (name, source) = fixture_source(&manifest_data);
    let analysis = angular_http::analyze(&name, &source);

    let expected = rows(&manifest_data["expected_calls"]);
    assert_eq!(
        analysis.calls.len(),
        expected.len(),
        "only the literal calls may be recorded"
    );

    for (row, call) in expected.iter().zip(&analysis.calls) {
        let id = row["route"].as_str().expect("route");
        assert_eq!(
            call.client,
            row["client"].as_str().expect("client"),
            "{id}: client"
        );
        assert_eq!(
            call.method,
            verb_of(row["method"].as_str().expect("method")),
            "{id}: verb"
        );
        assert_eq!(call.route, id, "{id}: route");
        assert_eq!(
            call.absolute_url.as_deref(),
            row["absolute_url"].as_str(),
            "{id}: absolute url"
        );
        assert_eq!(
            call.quality.as_str(),
            row["quality"].as_str().expect("quality"),
            "{id}: quality"
        );
    }

    assert_eq!(
        analysis.calls_for(HttpVerb::Get).len(),
        2,
        "the two literal GET calls must be recorded"
    );
    assert!(
        analysis
            .calls
            .iter()
            .any(|call| !call.base_url_is_runtime()),
        "the literal absolute URL must not need a runtime base"
    );

    let bases = rows(&manifest_data["expected_declared_base_urls"]);
    assert_eq!(analysis.declared_base_urls.len(), bases.len());
    assert_eq!(
        analysis.declared_base_urls[0].value.as_deref(),
        bases[0]["value"].as_str(),
        "the literal base URL must be recorded"
    );
}

/// AC2 negative: every dynamic, ambiguous or non-client HTTP shape is reported
/// with its pattern and reason, produces a diagnostic, and never becomes a call
/// with a guessed route.
#[test]
fn angular_dynamic_http_cases_are_reported_unresolved() {
    let manifest_data = manifest("services_http");
    let (name, source) = fixture_source(&manifest_data);
    let analysis = angular_http::analyze(&name, &source);

    assert!(
        analysis.has_unresolved(),
        "the fixture must exercise refusals"
    );
    let expected = rows(&manifest_data["expected_unresolved"]);
    assert_eq!(
        analysis.unresolved.len(),
        expected.len(),
        "every refused shape must be recorded exactly once"
    );
    for (row, item) in expected.iter().zip(&analysis.unresolved) {
        let pattern = row["pattern"].as_str().expect("pattern");
        assert_eq!(
            item.client,
            row["client"].as_str().expect("client"),
            "{pattern}: client"
        );
        assert_eq!(item.pattern, pattern, "{pattern}: pattern");
        assert_eq!(
            item.reason,
            row["reason"].as_str().expect("reason"),
            "{pattern}: reason"
        );
    }

    for guessed in ["${id}", "urlFor", "verb"] {
        assert!(
            !analysis
                .calls
                .iter()
                .any(|call| call.route.contains(guessed)),
            "a refused shape must not be published as route text containing {guessed:?}"
        );
    }
    assert!(
        !analysis.calls.iter().any(|call| call.route == "x"),
        "the non-client get('/x') shape must not be published as route \"x\""
    );
    assert!(
        !analysis.calls.iter().any(|call| call.client == "map"),
        "a non-client receiver must not become an HTTP call"
    );

    let mut codes: Vec<String> = analysis
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == Severity::Warning)
        .map(|diagnostic| diagnostic.code.clone())
        .collect();
    codes.sort();
    codes.dedup();
    assert_eq!(
        codes,
        string_list(&manifest_data["expected_warning_codes"]),
        "each refused literal-call shape must warn exactly once"
    );
}

/// AC1 positive: explicit, anonymous and computed TypeScript declarations are
/// separated, and no declaration is given a name the source does not carry.
#[test]
fn typescript_declarations_match_the_manifest() {
    let manifest_data = manifest("declarations_shapes");
    let (name, source) = fixture_source(&manifest_data);
    let analysis = declarations::analyze(&name, &source);

    assert!(!analysis.has_errors(), "{:?}", analysis.diagnostics);
    assert_eq!(
        analysis.coverage().status.as_str(),
        manifest_data["expected_coverage_status"]
            .as_str()
            .expect("coverage"),
        "the fully static fixture must claim complete coverage"
    );

    let expected = rows(&manifest_data["expected_declarations"]);
    assert_eq!(analysis.declarations.len(), expected.len());
    for (row, declaration) in expected.iter().zip(&analysis.declarations) {
        assert_eq!(
            declaration.kind.as_str(),
            row["kind"].as_str().expect("kind"),
            "declaration kind"
        );
        assert_eq!(
            declaration.name.as_deref(),
            row["name"].as_str(),
            "declaration name"
        );
        assert_eq!(
            declaration.quality.as_str(),
            row["quality"].as_str().expect("quality"),
            "identity quality"
        );
        assert_eq!(
            declaration.semantic_path,
            string_list(&row["semantic_path"]),
            "semantic path"
        );
    }

    assert_eq!(
        analysis.not_explicit().len(),
        manifest_data["expected_not_explicit"]
            .as_u64()
            .expect("not_explicit") as usize,
        "the anonymous and computed declarations must not claim explicit identity"
    );
    for absent in string_list(&manifest_data["expected_member_absence"]) {
        assert!(
            !analysis
                .declarations
                .iter()
                .any(|declaration| declaration.name.as_deref() == Some(absent.as_str())),
            "class members and destructured bindings must not be named {absent:?}"
        );
    }
}

/// AC2 boundary: a truncated source must be reported as partial coverage with a
/// diagnostic, never accepted as an empty complete analysis.
#[test]
fn typescript_unbalanced_declarations_report_partial_coverage() {
    let manifest_data = manifest("declarations_unbalanced");
    let (name, source) = fixture_source(&manifest_data);
    let analysis = declarations::analyze(&name, &source);
    let coverage = analysis.coverage();

    assert_eq!(
        coverage.status,
        CoverageStatus::Partial,
        "a truncated file must not claim complete coverage"
    );
    assert_eq!(
        coverage.claims_completeness(),
        manifest_data["expected_claims_completeness"]
            .as_bool()
            .expect("claims_completeness")
    );
    assert_eq!(
        coverage.processed_files,
        manifest_data["expected_processed_files"]
            .as_u64()
            .expect("processed_files") as usize
    );
    assert_eq!(
        coverage.input_files,
        manifest_data["expected_input_files"]
            .as_u64()
            .expect("input_files") as usize
    );

    let mut codes = analysis.error_codes();
    codes.sort();
    assert_eq!(
        codes,
        string_list(&manifest_data["expected_error_codes"]),
        "the unbalanced braces must be the recorded error"
    );

    let expected = rows(&manifest_data["expected_declarations"]);
    assert_eq!(
        analysis.declarations.len(),
        expected.len(),
        "the literal declaration before the truncation is still recorded"
    );
    assert_eq!(
        analysis.declarations[0].name.as_deref(),
        expected[0]["name"].as_str()
    );
}

/// Every fixture is deterministic: the same bytes give the same result.
#[test]
fn typescript_fixtures_are_deterministic() {
    let manifest_data = manifest("services_http");
    let (name, source) = fixture_source(&manifest_data);
    let first = angular_http::analyze(&name, &source);
    for _ in 0..3 {
        assert_eq!(angular_http::analyze(&name, &source), first);
    }

    let declarations_manifest = manifest("declarations_shapes");
    let (declaration_name, declaration_source) = fixture_source(&declarations_manifest);
    let first = declarations::analyze(&declaration_name, &declaration_source);
    for _ in 0..3 {
        assert_eq!(
            declarations::analyze(&declaration_name, &declaration_source),
            first
        );
    }

    let (_name, _source, _table, resolved) = resolved_imports("imports_module_graph");
    let (_name_again, _source_again, _table_again, again) =
        resolved_imports("imports_module_graph");
    assert_eq!(resolved, again, "import resolution must be deterministic");
}
