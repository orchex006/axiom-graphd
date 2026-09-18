//! Read-only installation-discovery harness (task E-003).
//!
//! This runs exactly the discovery layer the `axiom` CLI uses against one
//! `AXIOM_HOME` and prints the report, so the read-only claim of E-003 can be
//! exercised against a real fixture tree and captured as evidence.
//!
//! It is a read-only developer tool: it observes the paths under the supplied
//! home and never creates, writes, renames, deletes, launches or contacts
//! anything.
//!
//! Usage:
//!
//! ```text
//! cargo run --example discovery_probe -- [--json] [--home-dir <dir>] <axiom-home>
//! ```
//!
//! `--home-dir` overrides the user home the per-user definition is derived from,
//! which keeps a fixture tree self-contained instead of reading the real home.
//!
//! Exit codes follow the CLI contract: 0 no findings, 2 findings reported,
//! 1 usage or IO.

use std::process::ExitCode;

use axiom::discovery::{discover, LocalProbe};
use graph_core::paths::PathEnvironment;

fn main() -> ExitCode {
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    let as_json = arguments.iter().any(|argument| argument == "--json");
    arguments.retain(|argument| argument != "--json");

    let mut home_dir = None;
    if let Some(index) = arguments
        .iter()
        .position(|argument| argument == "--home-dir")
    {
        if index + 1 >= arguments.len() {
            eprintln!("usage: discovery_probe [--json] [--home-dir <dir>] <axiom-home>");
            return ExitCode::from(1);
        }
        home_dir = Some(arguments[index + 1].clone());
        arguments.drain(index..=index + 1);
    }

    let [home] = arguments.as_slice() else {
        eprintln!("usage: discovery_probe [--json] [--home-dir <dir>] <axiom-home>");
        return ExitCode::from(1);
    };

    let probe = match home_dir {
        Some(home_dir) => {
            let mut environment = PathEnvironment::for_current_process();
            environment.axiom_home = Some(home.clone());
            environment.home_dir = Some(home_dir);
            LocalProbe::with_environment(environment, None)
        }
        None => LocalProbe::with_home(home.clone()),
    };
    let report = discover(&probe);

    let rendered = if as_json {
        match report.to_json() {
            Ok(json) => json,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::from(1);
            }
        }
    } else {
        report.text()
    };
    println!("{rendered}");

    if report.ok() {
        ExitCode::from(0)
    } else {
        ExitCode::from(2)
    }
}
