//! `axiom` binary entry point.
//!
//! The binary owns process concerns only: read argv, wire stdout/stderr, and map
//! the typed exit code onto the process status. All behaviour lives in the
//! `axiom` library so it can be tested without spawning a process.

use std::io::Write;
use std::process::ExitCode as ProcessExitCode;

use axiom::cli;

fn main() -> ProcessExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let invocation = cli::parse(&arguments);
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let exit_code = cli::run(&invocation, &mut stdout, &mut stderr);
    let _ = stdout.flush();
    let _ = stderr.flush();
    ProcessExitCode::from(exit_status(exit_code))
}

/// Map a frozen Axiom exit code onto a process status.
///
/// The documented table uses only small values, so the conversion cannot fail;
/// an unexpected value becomes `1`, which the table deliberately leaves
/// unassigned and therefore can never be confused with a real diagnostic.
fn exit_status(exit_code: cli::ExitCode) -> u8 {
    u8::try_from(exit_code.as_i32()).unwrap_or(1)
}
