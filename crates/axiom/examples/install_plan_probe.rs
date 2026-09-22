//! Dry-run installation-plan harness (task E-004).
//!
//! This runs exactly the planner the `axiom install plan` command will use
//! against one local bundle directory and prints the reviewable plan, so the
//! dry-run claim of E-004 can be exercised on a real fixture and captured as
//! evidence.
//!
//! It is a read-only developer tool: it reads `bundle.json`, prints a plan and
//! contacts nothing. It has no code path that writes a file, downloads an
//! artifact or launches a service, so running it cannot change the host.
//!
//! Usage:
//!
//! ```text
//! cargo run --example install_plan_probe -- [--json] [--created-at <rfc3339>] \
//!     [--observed <component>=<version>]... --install-root <dir> <bundle-root>
//! ```
//!
//! `--install-root` is required and must be absolute, so the evidence never
//! depends on an ambient `AXIOM_HOME`.
//!
//! Exit codes follow `docs/16-CLI-AND-CONTROL-API.md` section 6: 0 plan
//! produced, 2 the arguments or the plan contract rejected the input, 3 the
//! bundle manifest is missing.

use std::path::Path;
use std::process::ExitCode;

use axiom::install::plan::{
    host_identifier, plan_install, read_bundle_manifest, sealed, DryRun, ObservedComponent,
    PlanContext,
};
use graph_core::error::AxiomError;
use graph_core::redact;

const USAGE: &str = "\
usage: install_plan_probe [--json] [--created-at <rfc3339>] \
[--observed <component>=<version>]... --install-root <dir> <bundle-root>";

/// Default creation time, so two probe runs over one fixture are identical.
const DEFAULT_CREATED_AT: &str = "2026-09-19T00:00:00Z";

fn main() -> ExitCode {
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    let as_json = arguments.iter().any(|argument| argument == "--json");
    arguments.retain(|argument| argument != "--json");

    let mut install_root: Option<String> = None;
    let mut created_at: Option<String> = None;
    let mut observed: Vec<ObservedComponent> = Vec::new();
    let mut positionals: Vec<String> = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].clone();
        match flag.as_str() {
            "--install-root" | "--created-at" | "--observed" => {
                let Some(value) = arguments.get(index + 1).cloned() else {
                    eprintln!("{USAGE}");
                    return ExitCode::from(2);
                };
                match flag.as_str() {
                    "--install-root" => install_root = Some(value),
                    "--created-at" => created_at = Some(value),
                    _ => {
                        let Some((component, version)) = value.split_once('=') else {
                            eprintln!("{USAGE}");
                            return ExitCode::from(2);
                        };
                        observed.push(ObservedComponent {
                            component: component.to_string(),
                            version: version.to_string(),
                        });
                    }
                }
                index += 2;
            }
            other if other.starts_with('-') => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
            other => {
                positionals.push(other.to_string());
                index += 1;
            }
        }
    }

    let [bundle_root] = positionals.as_slice() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let Some(install_root) = install_root else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };

    let (manifest, manifest_sha256) = match read_bundle_manifest(Path::new(bundle_root)) {
        Ok(parsed) => parsed,
        Err(error) => return report(&error),
    };

    let mut context = PlanContext::per_user(
        "install-probe-0001",
        created_at.unwrap_or_else(|| String::from(DEFAULT_CREATED_AT)),
        host_identifier(),
        install_root,
    );
    context.observed = observed;

    let plan = match plan_install(
        &manifest,
        &manifest_sha256,
        bundle_root,
        &context,
        DryRun::new(),
    ) {
        Ok(plan) => plan,
        Err(error) => return report(&error),
    };
    let (value, digest) = match sealed(&plan) {
        Ok(sealed) => sealed,
        Err(error) => return report(&error),
    };

    if as_json {
        match serde_json::to_string(&value) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::from(1);
            }
        }
    } else {
        print!("{}", plan.text());
        println!("plan_digest {digest}");
    }
    ExitCode::SUCCESS
}

/// Report one refusal with its contract exit code.
fn report(error: &AxiomError) -> ExitCode {
    eprintln!("{}", redact::scrub(&error.to_string()));
    ExitCode::from(u8::try_from(error.exit_code().as_i32()).unwrap_or(1))
}
