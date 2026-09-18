//! Differential QA harness for the frozen update-plan contract (task E-002).
//!
//! This evaluates one document with exactly the rule set the installer uses and
//! prints the verdict `tools/update_plan_contract.py::evaluate` returns, so the
//! Rust half of the contract can be diffed against the specification oracle over
//! the fixture corpus in `axiom-specs/tests/fixtures/update-plan-contract/`.
//!
//! It is a read-only developer tool: it reads one local file and never touches
//! the network, Git, the shell or the plan it is handed.
//!
//! Usage:
//!
//! ```text
//! cargo run --example plan_verify -- [--json] <document.json>
//! ```
//!
//! Exit codes follow the CLI contract: 0 accepted, 2 rejected, 1 usage or IO.

use std::path::PathBuf;
use std::process::ExitCode;

use axiom::plan::evaluate_plan_file;

fn main() -> ExitCode {
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    let as_json = arguments.iter().any(|argument| argument == "--json");
    arguments.retain(|argument| argument != "--json");
    let [path] = arguments.as_slice() else {
        eprintln!("usage: plan_verify [--json] <document.json>");
        return ExitCode::from(1);
    };
    let verdict = match evaluate_plan_file(&PathBuf::from(path)) {
        Ok(verdict) => verdict,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };
    if as_json {
        match verdict.to_json() {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::from(1);
            }
        }
    } else {
        println!("{}", verdict.text_line());
    }
    if verdict.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}
