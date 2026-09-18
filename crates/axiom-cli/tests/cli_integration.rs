//! Spawned-process regression tests for the `axiom` CLI (task E-001).
//!
//! AC1 is enforced here rather than asserted in prose: the CLI is built by the
//! same locked workspace as the daemon, reports the frozen
//! `version-report.schema.json` object, and reports exactly the version the
//! daemon half of the core release reports. The negative cases pin the frozen
//! exit table and the "one JSON object on stdout" rule for failures.

use std::process::{Command, Output};

/// The binary under test, located by Cargo for this integration test.
const BIN: &str = env!("CARGO_BIN_EXE_axiom");

/// Exactly the required properties of `version-report.schema.json`, sorted.
const FROZEN_KEYS: [&str; 8] = [
    "build_revision",
    "component",
    "control_api",
    "graph_schema",
    "queue_schema",
    "spec_version",
    "update_status",
    "version",
];

/// The one core version shared by the daemon and the CLI.
const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

fn run(arguments: &[&str]) -> Output {
    Command::new(BIN)
        .args(arguments)
        .output()
        .expect("the axiom binary is built and runnable")
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

/// Parse stdout as exactly one JSON object, as section 1 of
/// `docs/16-CLI-AND-CONTROL-API.md` requires of machine-readable mode.
fn single_json_object(text: &str) -> serde_json::Value {
    let trimmed = text.trim_end_matches(['\n', '\r']);
    assert_eq!(
        trimmed.lines().count(),
        1,
        "stdout must hold exactly one JSON line, got {trimmed:?}"
    );
    serde_json::from_str(trimmed).expect("stdout is one JSON object")
}

fn sorted_keys(value: &serde_json::Value) -> Vec<&str> {
    let mut keys: Vec<&str> = value
        .as_object()
        .expect("a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

#[test]
fn the_cli_reports_the_frozen_object_for_the_core_release() {
    let output = run(&["version", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let value = single_json_object(&stdout_text(&output));
    assert_eq!(sorted_keys(&value), FROZEN_KEYS);
    assert_eq!(value["component"], "axiom");
    assert_eq!(value["version"], CORE_VERSION);
    assert_eq!(value["update_status"], "unconfigured");

    // The daemon half of the same release reports the same core version, so a
    // second version drifting in would fail this test rather than a release.
    let daemon = axiom_graphd::version::VersionOutput::current().report;
    assert_eq!(daemon.component, axiom_graphd::version::COMPONENT);
    assert_eq!(value["version"].as_str(), Some(daemon.version.as_str()));
    assert_eq!(
        value["spec_version"].as_str(),
        Some(daemon.spec_version.as_str())
    );
}

#[test]
fn version_all_reports_both_halves_in_one_object() {
    let output = run(&["version", "--all", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let value = single_json_object(&stdout_text(&output));
    let components = value["components"].as_array().expect("a components array");
    assert_eq!(components.len(), 2);
    let names: Vec<&str> = components
        .iter()
        .map(|report| report["component"].as_str().expect("a component name"))
        .collect();
    assert_eq!(names, vec!["axiom", "axiom-graphd"]);
    for report in components {
        assert_eq!(sorted_keys(report), FROZEN_KEYS);
        assert_eq!(report["version"], CORE_VERSION);
    }
}

#[test]
fn version_all_in_text_mode_prints_one_line_per_component() {
    let output = run(&["version", "--all"]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout_text(&output);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "got {text:?}");
    assert!(lines[0].starts_with("axiom "), "got {:?}", lines[0]);
    assert!(lines[1].starts_with("axiom-graphd "), "got {:?}", lines[1]);
}

#[test]
fn help_prints_the_generated_exit_code_table() {
    let output = run(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    let text = stdout_text(&output);
    assert!(
        text.contains("Usage: axiom <command> [options]"),
        "got {text:?}"
    );
    assert!(text.contains("2  validation"), "got {text:?}");
}

#[test]
fn an_unknown_command_is_rejected_with_one_error_envelope() {
    let output = run(&["frobnicate", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    let value = single_json_object(&stdout_text(&output));
    assert_eq!(value["code"], "VALIDATION_ERROR");
    assert!(value["message"]
        .as_str()
        .expect("a message")
        .contains("frobnicate"));

    // Text mode keeps stdout free of payload and reports on stderr instead.
    let text_output = run(&["frobnicate"]);
    assert_eq!(text_output.status.code(), Some(2));
    assert!(stdout_text(&text_output).is_empty());
    assert!(stderr_text(&text_output).contains("frobnicate"));
}

#[test]
fn all_is_rejected_outside_the_version_command() {
    let output = run(&["--all", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    let value = single_json_object(&stdout_text(&output));
    assert_eq!(value["code"], "VALIDATION_ERROR");
    assert!(value["message"]
        .as_str()
        .expect("a message")
        .contains("--all"));
}

#[test]
fn a_documented_command_of_a_later_package_reports_not_ready() {
    let output = run(&["install", "plan", "--bundle", "b.zip", "--json"]);
    assert_eq!(output.status.code(), Some(4));
    let value = single_json_object(&stdout_text(&output));
    assert_eq!(value["code"], "NOT_READY");
    assert!(value["message"]
        .as_str()
        .expect("a message")
        .contains("install"));
}
