//! Regression test for the native platform matrix (task V2-030).
//!
//! `tests/native/README.md` is the only native-execution record this repository
//! owns. Contract CP-01 requires four release targets (`windows-x64`,
//! `linux-x64`, `macos-x64`, `macos-arm64`) and states that a cross-compile is
//! not native execution, so a row may only be `verified` when a real execution
//! and a real artifact hash back it, and an unperformed target must be
//! `not_run` with a stated reason and no invented digest.
//!
//! The document is compiled into this test binary, so it cannot drift alone.
//! Every rule the document states is re-checked here over the compiled copy and
//! over the committed evidence files the rows name: a `verified` row must carry
//! a command, an exit code, a toolchain identity and a SHA-256 that really
//! appears in its evidence file; a `not_run` row must carry a real reason, must
//! claim no scope, and must carry no digest, toolchain or exit status. The row
//! validator is also exercised against deliberately broken rows, so a green run
//! cannot be vacuous.
//!
//! `tests/native/check_matrix.py` enforces the same rules from the Python side
//! and carries its own negative controls; this test runs it too, and reports it
//! as `not_run` on a host without a Python interpreter rather than pretending it
//! passed.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The native platform matrix document, compiled in so it cannot drift alone.
const NATIVE_MATRIX: &str = include_str!("../../../tests/native/README.md");

const BEGIN: &str = "<!-- BEGIN NATIVE MATRIX -->";
const END: &str = "<!-- END NATIVE MATRIX -->";

/// The matrix columns, in the exact order the document declares them.
const COLUMNS: [&str; 10] = [
    "target",
    "status",
    "scope",
    "execution_identity",
    "command",
    "exit",
    "artifact_sha256",
    "toolchain",
    "evidence",
    "note",
];

/// `compatibility/platform-matrix.json` declares exactly these mandatory
/// targets with `native_execution_required: true`.
const MANDATORY_TARGETS: [&str; 4] = ["windows-x64", "linux-x64", "macos-x64", "macos-arm64"];
const MACOS_TARGETS: [&str; 2] = ["macos-x64", "macos-arm64"];
const MACOS_NOT_RUN_REASON: &str = "no macOS host available in this environment";

const CHECKER: &str = "tests/native/check_matrix.py";
const PYTHON_INTERPRETERS: [&str; 2] = ["python", "python3"];

/// One row of the native matrix.
#[derive(Clone, Debug)]
struct Row {
    target: String,
    status: String,
    scope: String,
    execution_identity: String,
    command: String,
    exit: String,
    artifact_sha256: String,
    toolchain: String,
    evidence: String,
    note: String,
}

/// The repository root, derived from this crate's manifest directory.
fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .parent()
        .expect("repository root")
        .to_path_buf()
}

fn trim_cells(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(|cell| cell.trim().to_owned())
        .collect()
}

fn is_separator(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells.iter().all(|cell| {
            !cell.is_empty()
                && cell
                    .chars()
                    .all(|character| matches!(character, '-' | ':' | ' '))
        })
}

/// Parse the matrix between the two sentinels. A structural problem is an error,
/// never a skipped row.
fn parse_matrix(document: &str) -> Result<Vec<Row>, String> {
    let after_begin = document
        .split_once(BEGIN)
        .ok_or_else(|| format!("the document must keep {BEGIN}"))?
        .1;
    let segment = after_begin
        .split_once(END)
        .ok_or_else(|| format!("the document must keep {END}"))?
        .0;

    let mut rows = Vec::new();
    let mut header_seen = false;
    for line in segment.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let values = trim_cells(line);
        if !header_seen {
            let expected: Vec<String> = COLUMNS.iter().map(|name| (*name).to_owned()).collect();
            if values != expected {
                return Err(format!(
                    "matrix header is {values:?}, expected {expected:?}"
                ));
            }
            header_seen = true;
            continue;
        }
        if is_separator(&values) {
            continue;
        }
        if values.len() != COLUMNS.len() {
            return Err(format!(
                "matrix row has {} cells, expected {}: {line}",
                values.len(),
                COLUMNS.len()
            ));
        }
        rows.push(Row {
            target: values[0].clone(),
            status: values[1].clone(),
            scope: values[2].clone(),
            execution_identity: values[3].clone(),
            command: values[4].clone(),
            exit: values[5].clone(),
            artifact_sha256: values[6].clone(),
            toolchain: values[7].clone(),
            evidence: values[8].clone(),
            note: values[9].clone(),
        });
    }

    if !header_seen {
        return Err("the matrix sentinels enclose no table".to_owned());
    }
    if rows.is_empty() {
        return Err("the matrix table has no data rows".to_owned());
    }
    Ok(rows)
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(is_lower_hex_byte)
}

fn is_lower_hex_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The first 64-character lowercase-hex run in `text`, if any. Used to prove a
/// `not_run` row invents no digest.
fn first_digest(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    if bytes.len() < 64 {
        return None;
    }
    for start in 0..=bytes.len() - 64 {
        let end = start + 64;
        if !bytes[start..end].iter().copied().all(is_lower_hex_byte) {
            continue;
        }
        if !text.is_char_boundary(start) || !text.is_char_boundary(end) {
            continue;
        }
        let open = start == 0 || !is_word_byte(bytes[start - 1]);
        let close = end == bytes.len() || !is_word_byte(bytes[end]);
        if open && close {
            return Some(&text[start..end]);
        }
    }
    None
}

/// True when some line records this exact exit code as `exit: <code>` or
/// `exit = <code>`.
fn records_exit(text: &str, code: &str) -> bool {
    text.lines().any(|line| {
        let Some(rest) = line.trim().strip_prefix("exit") else {
            return false;
        };
        let rest = rest.trim_start();
        match rest.strip_prefix(':').or_else(|| rest.strip_prefix('=')) {
            Some(value) => value.trim() == code,
            None => false,
        }
    })
}

/// Every problem with one row; empty means the row is legitimate.
fn row_problems(row: &Row, root: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let where_ = format!("{} {}", row.target, row.status);

    if !MANDATORY_TARGETS.contains(&row.target.as_str()) {
        problems.push(format!(
            "{where_}: target is not one of the four mandatory targets {MANDATORY_TARGETS:?}"
        ));
    }
    if row.status != "verified" && row.status != "not_run" {
        problems.push(format!("{where_}: status is neither verified nor not_run"));
        return problems;
    }
    if row.scope.is_empty() || row.scope == "-" {
        problems.push(format!("{where_}: scope is empty"));
    }
    if row.command.is_empty() || row.command == "-" {
        problems.push(format!("{where_}: no command is recorded"));
    }
    if row.note.is_empty() || row.note == "-" {
        problems.push(format!(
            "{where_}: no observed result or reason is recorded"
        ));
    }
    if row.evidence.is_empty() || row.evidence == "-" {
        problems.push(format!("{where_}: no evidence file is named"));
        return problems;
    }

    let evidence_path = root.join(row.evidence.replace('/', std::path::MAIN_SEPARATOR_STR));
    let evidence = match std::fs::read_to_string(&evidence_path) {
        Ok(text) => text,
        Err(error) => {
            problems.push(format!(
                "{where_}: evidence file {} is unreadable: {error}",
                row.evidence
            ));
            return problems;
        }
    };

    if row.status == "verified" {
        if row.exit.parse::<u32>().is_err() {
            problems.push(format!(
                "{where_}: verified row has no recorded exit code (exit={})",
                row.exit
            ));
        } else if !records_exit(&evidence, &row.exit) {
            problems.push(format!(
                "{where_}: exit {} is not recorded in {}",
                row.exit, row.evidence
            ));
        }
        if !is_sha256(&row.artifact_sha256) {
            problems.push(format!(
                "{where_}: verified row has no recorded artifact sha256 (artifact_sha256={})",
                row.artifact_sha256
            ));
        } else if !evidence.contains(&row.artifact_sha256) {
            problems.push(format!(
                "{where_}: artifact sha256 {} does not appear in {}",
                row.artifact_sha256, row.evidence
            ));
        }
        if row.toolchain.is_empty() || row.toolchain == "-" {
            problems.push(format!(
                "{where_}: verified row has no recorded toolchain identity"
            ));
        }
        if row.execution_identity.is_empty() || row.execution_identity == "-" {
            problems.push(format!(
                "{where_}: verified row has no observed execution identity"
            ));
        }
        if row.scope == "none" {
            problems.push(format!("{where_}: verified row claims scope 'none'"));
        }
    } else {
        for (column, value) in [
            ("exit", &row.exit),
            ("artifact_sha256", &row.artifact_sha256),
            ("toolchain", &row.toolchain),
            ("execution_identity", &row.execution_identity),
        ] {
            if value != "-" {
                problems.push(format!(
                    "{where_}: not_run row carries a {column} value ({value}); \
                     unperformed work has no digest, toolchain or status"
                ));
            }
        }
        if row.scope != "none" {
            problems.push(format!(
                "{where_}: not_run row claims scope '{}'; an unperformed target covers nothing",
                row.scope
            ));
        }
        for (column, value) in [
            ("note", &row.note),
            ("command", &row.command),
            ("execution_identity", &row.execution_identity),
            ("toolchain", &row.toolchain),
            ("artifact_sha256", &row.artifact_sha256),
        ] {
            if let Some(digest) = first_digest(value) {
                problems.push(format!(
                    "{where_}: not_run row invents a digest in {column} ({digest})"
                ));
            }
        }
        if !evidence.contains(&row.note) {
            problems.push(format!(
                "{where_}: the stated reason does not appear in {}",
                row.evidence
            ));
        }
        if MACOS_TARGETS.contains(&row.target.as_str()) && row.note != MACOS_NOT_RUN_REASON {
            problems.push(format!(
                "{where_}: reason is {:?}, must be {MACOS_NOT_RUN_REASON:?}",
                row.note
            ));
        }
    }

    problems
}

fn matrix_rows() -> Vec<Row> {
    parse_matrix(NATIVE_MATRIX).expect("tests/native/README.md must carry a well-formed matrix")
}

/// AC1: the table is exactly the four mandatory targets - no dropped target, no
/// duplicate and no invented fifth row.
#[test]
fn native_matrix_covers_exactly_the_mandatory_targets() {
    let rows = matrix_rows();
    let mut actual: Vec<&str> = rows.iter().map(|row| row.target.as_str()).collect();
    actual.sort_unstable();
    let mut expected = MANDATORY_TARGETS.to_vec();
    expected.sort_unstable();
    assert_eq!(
        actual, expected,
        "the matrix must list exactly the four mandatory targets"
    );

    let mut deduped = actual.clone();
    deduped.dedup();
    assert_eq!(
        deduped.len(),
        actual.len(),
        "a target must appear in exactly one row"
    );
}

/// AC1: a `verified` row is only legitimate when a real execution and a real
/// artifact hash back it, and both really appear in the committed evidence file.
#[test]
fn native_matrix_verified_rows_are_backed_by_committed_evidence() {
    let root = repository_root();
    let rows = matrix_rows();
    let verified: Vec<&Row> = rows.iter().filter(|row| row.status == "verified").collect();
    assert!(
        !verified.is_empty(),
        "the Windows x64 leg ran on this host, so at least one row must be verified"
    );

    let mut problems = Vec::new();
    for row in &verified {
        problems.extend(row_problems(row, &root));
    }
    assert!(
        problems.is_empty(),
        "verified rows are not backed by real evidence: {problems:#?}"
    );
}

/// AC2: an unperformed target is `not_run` with a real reason and claims
/// nothing else - no digest, no toolchain, no exit status and no scope.
#[test]
fn native_matrix_not_run_rows_state_a_reason_and_claim_nothing_else() {
    let root = repository_root();
    let rows = matrix_rows();
    let not_run: Vec<&Row> = rows.iter().filter(|row| row.status == "not_run").collect();
    assert!(
        !not_run.is_empty(),
        "a host without macOS must record the Apple targets as not_run"
    );

    let mut problems = Vec::new();
    for row in &not_run {
        problems.extend(row_problems(row, &root));
    }
    assert!(
        problems.is_empty(),
        "not_run rows are not honest: {problems:#?}"
    );

    for row in &not_run {
        assert!(
            !row.note.contains("verified"),
            "{}: an unperformed target must not claim verification",
            row.target
        );
    }
}

/// The row validator is not vacuous: each deliberately broken row must be
/// rejected, including a verified row without an execution or hash and a
/// not_run row without a reason.
#[test]
fn native_matrix_row_validator_rejects_broken_rows() {
    let root = repository_root();
    let rows = matrix_rows();
    let verified = rows
        .iter()
        .find(|row| row.status == "verified")
        .expect("a verified row")
        .clone();
    let not_run = rows
        .iter()
        .find(|row| row.status == "not_run")
        .expect("a not_run row")
        .clone();

    let mut no_hash = verified.clone();
    no_hash.artifact_sha256 = "-".to_owned();
    let mut absent_hash = verified.clone();
    absent_hash.artifact_sha256 = "deadbeef".repeat(8);
    let mut no_exit = verified.clone();
    no_exit.exit = "-".to_owned();
    let mut no_toolchain = verified.clone();
    no_toolchain.toolchain = "-".to_owned();
    let mut no_scope = verified.clone();
    no_scope.scope = "none".to_owned();
    let mut no_reason = not_run.clone();
    no_reason.note = "-".to_owned();
    let mut invented_digest = not_run.clone();
    invented_digest.note = format!("{MACOS_NOT_RUN_REASON} {}", "0".repeat(64));
    let mut invented_exit = not_run.clone();
    invented_exit.exit = "0".to_owned();
    let mut wrong_reason = not_run.clone();
    wrong_reason.note = "the host is Windows".to_owned();

    let broken: Vec<(&str, Row)> = vec![
        ("verified row without a hash", no_hash),
        (
            "verified row with a hash the evidence does not contain",
            absent_hash,
        ),
        ("verified row without an exit code", no_exit),
        ("verified row without a toolchain identity", no_toolchain),
        ("verified row claiming no scope", no_scope),
        ("not_run row without a reason", no_reason),
        ("not_run row with an invented digest", invented_digest),
        ("not_run row with an exit status", invented_exit),
        ("macOS row with the wrong reason", wrong_reason),
    ];

    for (label, row) in broken {
        let problems = row_problems(&row, &root);
        assert!(
            !problems.is_empty(),
            "the validator accepted a broken row: {label}"
        );
    }

    assert!(
        row_problems(&verified, &root).is_empty(),
        "the unmodified verified row must stay legitimate"
    );
    assert!(
        row_problems(&not_run, &root).is_empty(),
        "the unmodified not_run row must stay legitimate"
    );
}

/// The parser refuses a malformed document instead of skipping the bad part.
#[test]
fn native_matrix_parser_rejects_malformed_documents() {
    let empty_table = format!("{BEGIN}\n| {} |\n| --- |\n{END}\n", COLUMNS.join(" | "));
    let mutants: [(&str, String); 5] = [
        (
            "the sentinels are removed",
            NATIVE_MATRIX.replace(BEGIN, "").replace(END, ""),
        ),
        (
            "the header is renamed",
            NATIVE_MATRIX.replace(
                "| target | status | scope |",
                "| platform | status | scope |",
            ),
        ),
        (
            "the table has no data rows",
            NATIVE_MATRIX
                .split_once(BEGIN)
                .expect("BEGIN marker")
                .0
                .to_owned()
                + &empty_table
                + NATIVE_MATRIX.split_once(END).expect("END marker").1,
        ),
        (
            "a row gains an extra cell",
            NATIVE_MATRIX.replace(
                "| macos-arm64 | not_run | none | - |",
                "| macos-arm64 | not_run | none | - | extra |",
            ),
        ),
        (
            "a row loses a cell",
            NATIVE_MATRIX.replace(
                "| macos-x64 | not_run | none | - |",
                "| macos-x64 | not_run | none |",
            ),
        ),
    ];

    for (label, document) in mutants {
        assert!(
            document != NATIVE_MATRIX,
            "the self-test mutation did nothing: {label}"
        );
        assert!(
            parse_matrix(&document).is_err(),
            "the parser accepted a malformed document: {label}"
        );
    }

    assert!(
        parse_matrix(NATIVE_MATRIX).is_ok(),
        "the real document must parse"
    );
}

/// Run `tests/native/check_matrix.py` on this host, or report `not_run` when no
/// Python interpreter exists.
fn run_python_checker(args: &[&str]) -> Option<std::process::Output> {
    let root = repository_root();
    for interpreter in PYTHON_INTERPRETERS {
        let attempt = Command::new(interpreter)
            .arg(CHECKER)
            .args(args)
            .current_dir(&root)
            .output();
        match attempt {
            Ok(output) => return Some(output),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("failed to run {interpreter}: {error}"),
        }
    }
    None
}

fn describe(output: &std::process::Output) -> String {
    format!(
        "exit={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The Python checker, which carries its own negative controls, agrees with the
/// compiled document.
#[test]
fn native_matrix_python_checker_agrees_with_the_document() {
    match run_python_checker(&[]) {
        Some(output) => assert!(
            output.status.success(),
            "tests/native/check_matrix.py failed: {}",
            describe(&output)
        ),
        None => eprintln!(
            "NOT_RUN {CHECKER}: no Python interpreter ({}) on this host",
            PYTHON_INTERPRETERS.join(", ")
        ),
    }
}

/// The Python checker's own negative controls must be caught on this host.
#[test]
fn native_matrix_python_checker_negative_controls_are_caught() {
    match run_python_checker(&["--self-test"]) {
        Some(output) => assert!(
            output.status.success(),
            "tests/native/check_matrix.py --self-test failed: {}",
            describe(&output)
        ),
        None => eprintln!("NOT_RUN {CHECKER} --self-test: no Python interpreter on this host"),
    }
}
