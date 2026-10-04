//! Native adapters for the public operator engines (K-607).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::{AxiomHome, PathEnvironment};
use graph_export::sha256_hex;
use serde_json::{json, Value};

use crate::bootstrap::{apply, plan, preconditions, verify};

/// One validated invocation, retaining explicit inputs and flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Space-separated public form.
    pub form: String,
    /// Explicit argument values.
    pub values: BTreeMap<String, String>,
    /// Boolean argument flags.
    pub flags: BTreeSet<String>,
}

impl Request {
    fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
    fn required(&self, key: &str) -> Result<&str, AxiomError> {
        self.get(key)
            .ok_or_else(|| error(ErrorCode::ValidationError, "argument-missing", key))
    }
}

pub(crate) fn error(code: ErrorCode, rule: &str, message: &str) -> AxiomError {
    AxiomError::new(code, message).with_detail("rule", rule)
}

pub(crate) fn home() -> Result<AxiomHome, AxiomError> {
    let home = AxiomHome::resolve(&PathEnvironment::for_current_process())?;
    home.verify_destination()?;
    Ok(home)
}

pub(crate) fn install_root() -> Result<PathBuf, AxiomError> {
    Ok(home()?.installs_dir().join("ecosystem"))
}

pub(crate) fn no_links(path: &Path) -> Result<(), AxiomError> {
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part);
        if matches!(part, std::path::Component::Prefix(_)) {
            continue;
        }
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                let linked = metadata.file_type().is_symlink();
                #[cfg(windows)]
                let linked = {
                    use std::os::windows::fs::MetadataExt;
                    linked || metadata.file_attributes() & 0x400 != 0
                };
                if linked {
                    return Err(error(
                        ErrorCode::Forbidden,
                        "unsafe-link",
                        "a managed path contains a link or junction",
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(error(
                    ErrorCode::Forbidden,
                    "path-unreadable",
                    "a managed path cannot be inspected",
                ))
            }
        }
    }
    Ok(())
}

pub(crate) fn read(path: &Path) -> Result<Vec<u8>, AxiomError> {
    no_links(path)?;
    let size = std::fs::metadata(path)
        .map_err(|_| {
            error(
                ErrorCode::NotFound,
                "input-missing",
                "the selected input does not exist",
            )
        })?
        .len();
    if size > 16 * 1024 * 1024 {
        return Err(error(
            ErrorCode::ValidationError,
            "input-too-large",
            "the selected input exceeds the bounded read limit",
        ));
    }
    std::fs::read(path).map_err(|_| {
        error(
            ErrorCode::NotFound,
            "input-unreadable",
            "the selected input cannot be read",
        )
    })
}

pub(crate) fn read_json(path: &Path) -> Result<Value, AxiomError> {
    serde_json::from_slice(&read(path)?).map_err(|_| {
        error(
            ErrorCode::ValidationError,
            "input-json-invalid",
            "the selected input is not valid JSON",
        )
    })
}

pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), AxiomError> {
    use std::io::Write;
    no_links(path)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| {
            error(
                ErrorCode::Forbidden,
                "output-directory",
                "the output directory cannot be created",
            )
        })?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| {
            error(
                ErrorCode::Conflict,
                "output-exists",
                "the output already exists or cannot be exclusively created",
            )
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| {
            error(
                ErrorCode::Internal,
                "output-write",
                "the output could not be written and synchronized",
            )
        })
}

pub(crate) fn seal(mut value: Value) -> Result<Value, AxiomError> {
    value
        .as_object_mut()
        .ok_or_else(|| {
            error(
                ErrorCode::ValidationError,
                "plan-shape",
                "a plan must be an object",
            )
        })?
        .remove("plan_digest");
    let bytes = graph_export::canonical::canonical_value(&value).map_err(|_| {
        error(
            ErrorCode::ValidationError,
            "plan-encoding",
            "the plan cannot be canonically encoded",
        )
    })?;
    value["plan_digest"] = json!(sha256_hex(bytes.as_bytes()));
    Ok(value)
}

pub(crate) fn approved(value: &Value, approval: Option<&str>) -> Result<(), AxiomError> {
    let actual = seal(value.clone())?;
    if actual["plan_digest"] != value["plan_digest"] {
        return Err(error(
            ErrorCode::Conflict,
            "plan-digest-mismatch",
            "the plan changed after planning",
        ));
    }
    if approval != value["plan_digest"].as_str() {
        return Err(error(
            ErrorCode::Forbidden,
            "approval-stale",
            "apply requires approval of this exact plan digest",
        ));
    }
    Ok(())
}

fn output(request: &Request, value: Value) -> Result<Value, AxiomError> {
    if let Some(path) = request.get("--out") {
        let bytes = serde_json::to_vec_pretty(&value).map_err(|_| {
            error(
                ErrorCode::Internal,
                "json-output",
                "the report cannot be encoded",
            )
        })?;
        write_new(Path::new(path), &bytes)?;
    }
    Ok(value)
}

fn canonical_templates(root: &Path) -> Result<plan::Templates, AxiomError> {
    let manifest_path = if root.join("skills-manifest.json").exists() {
        root.join("skills-manifest.json")
    } else {
        root.join("release/skills-manifest.json")
    };
    let manifest = read_json(&manifest_path)?;
    if manifest["component"] != "axiom-skills" {
        return Err(error(
            ErrorCode::ValidationError,
            "template-owner",
            "bootstrap content must come from its canonical skills owner",
        ));
    }
    let files = manifest["files"].as_array().ok_or_else(|| {
        error(
            ErrorCode::ValidationError,
            "skills-manifest",
            "canonical owner manifest has no file declarations",
        )
    })?;
    let declared = |relative: &str| -> Result<Vec<u8>, AxiomError> {
        let entry = files
            .iter()
            .find(|v| v["path"] == relative)
            .ok_or_else(|| {
                error(
                    ErrorCode::ValidationError,
                    "template-undeclared",
                    "the owner manifest does not declare the template input",
                )
            })?;
        let bytes = read(&root.join(relative))?;
        if entry["sha256"] != sha256_hex(&bytes)
            || entry["bytes"].as_u64() != Some(bytes.len() as u64)
        {
            return Err(error(
                ErrorCode::Conflict,
                "template-hash-mismatch",
                "canonical template bytes do not match their owner manifest",
            ));
        }
        Ok(bytes)
    };
    let policy = declared("policy/POLICY.md")?;
    // The pointer block is supplied by the content owner, never hardcoded here.
    let block = declared("templates/bootstrap/AGENTS.block.md")?;
    let declaration: Value =
        serde_json::from_slice(&declared("templates/bootstrap/manifest.json")?).map_err(|_| {
            error(
                ErrorCode::ValidationError,
                "template-manifest",
                "the canonical template manifest is not JSON",
            )
        })?;
    let block_entry = declaration["templates"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["id"] == "agents-block"))
        .ok_or_else(|| {
            error(
                ErrorCode::ValidationError,
                "template-declaration",
                "the owner template declaration has no pointer block",
            )
        })?;
    if block_entry["sha256"] != sha256_hex(&block)
        || block_entry["bytes"].as_u64() != Some(block.len() as u64)
    {
        return Err(error(
            ErrorCode::Conflict,
            "template-block-hash",
            "the canonical pointer block changed from its owner declaration",
        ));
    }
    let version = block_entry["template_version"].as_str().ok_or_else(|| {
        error(
            ErrorCode::ValidationError,
            "template-version",
            "the pointer block has no declared version",
        )
    })?;
    Ok(plan::Templates::new(
        String::from_utf8(block).map_err(|_| {
            error(
                ErrorCode::ValidationError,
                "template-encoding",
                "the pointer block is not UTF-8",
            )
        })?,
        policy,
        version,
    ))
}

fn bundle_root(request: &Request, component: &str) -> Result<PathBuf, AxiomError> {
    request
        .get("--bundle")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os(if component == "skills" {
                "AXIOM_SKILLS_BUNDLE"
            } else {
                "AXIOM_SPECS_BUNDLE"
            })
            .map(PathBuf::from)
        })
        .ok_or_else(|| {
            error(
                ErrorCode::NotFound,
                "bundle-not-configured",
                "select an explicit local component bundle before checking or planning",
            )
        })
}

fn bootstrap(request: &Request) -> Result<Value, AxiomError> {
    let applying = request.form.ends_with("apply");
    let (solution, bundle, parsed) = if applying {
        let value = read_json(Path::new(request.required("--plan")?))?;
        approved(&value, request.get("--approve-digest"))?;
        if value["kind"] != "bootstrap" {
            return Err(error(
                ErrorCode::ValidationError,
                "wrong-plan-kind",
                "this is not a bootstrap plan",
            ));
        }
        (
            value["solution"].as_str().unwrap_or_default().to_string(),
            PathBuf::from(value["bundle"].as_str().unwrap_or_default()),
            Some(value),
        )
    } else {
        (
            request.required("--solution")?.to_string(),
            bundle_root(request, "skills")?,
            None,
        )
    };
    let templates = canonical_templates(&bundle)?;
    let hosts: Vec<String> = if let Some(value) = request.get("--hosts") {
        value
            .split(',')
            .map(|name| {
                crate::hosts::detect::HostKind::from_wire(name)
                    .map(|host| host.wire().to_owned())
                    .ok_or_else(|| {
                        error(
                            ErrorCode::ValidationError,
                            "bootstrap-host-selector",
                            "--hosts contains an undeclared host",
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?
    } else {
        parsed
            .as_ref()
            .and_then(|value| value["hosts"].as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let roots = axiom_graphd::cli::bound_repository_roots(&solution)?;
    let readers: Vec<_> = roots
        .iter()
        .map(|(_, root)| plan::LocalRepositoryReader::new(root))
        .collect();
    let targets: Vec<_> = roots
        .iter()
        .zip(&readers)
        .map(|((id, root), reader)| plan::RepositoryTarget::new(id, root.to_string_lossy(), reader))
        .collect();
    for (_, root) in &roots {
        no_links(root)?;
        for file in [
            plan::AGENTS_PATH,
            crate::bootstrap::policy::POLICY_PATH,
            crate::bootstrap::ownership::OWNERSHIP_PATH,
        ] {
            no_links(&root.join(file))?;
        }
    }
    if request.form == "bootstrap verify" {
        let targets: Vec<_> = roots
            .iter()
            .zip(&readers)
            .map(|((id, root), reader)| {
                verify::VerifyTarget::new(id, root.to_str().unwrap_or_default(), reader)
            })
            .collect();
        let report = verify::verify_all(&targets, &templates);
        if !report.is_clean() || report.pending() > 0 {
            return Err(error(
                ErrorCode::Conflict,
                "bootstrap-drift",
                "registered managed content is absent, pending or changed",
            ));
        }
        return Ok(
            json!({"status":"verified", "solution":solution,"repositories":report.current()}),
        );
    }
    let fresh = plan::plan_all(&targets, &templates)?;
    if let Some(value) = parsed {
        let expected = plan::BootstrapPlan::parse(
            &serde_json::to_vec(&value["engine_plan"]).map_err(|_| {
                error(
                    ErrorCode::ValidationError,
                    "plan-encoding",
                    "invalid bootstrap engine plan",
                )
            })?,
        )?;
        let same_scope = expected.block_template_sha256 == fresh.block_template_sha256
            && expected.policy_template_sha256 == fresh.policy_template_sha256
            && expected.template_version == fresh.template_version
            && expected
                .repositories
                .iter()
                .map(|r| (&r.repository_id, &r.root))
                .eq(fresh
                    .repositories
                    .iter()
                    .map(|r| (&r.repository_id, &r.root)));
        if same_scope
            && fresh
                .repositories
                .iter()
                .all(|r| r.change == plan::ChangeClass::Unchanged)
        {
            return Ok(
                json!({"status":"already-applied","solution":solution,"repositories":fresh.repositories.len(),"plan_digest":value["plan_digest"]}),
            );
        }
        if expected != fresh {
            return Err(error(
                ErrorCode::Conflict,
                "bootstrap-plan-stale",
                "roots, canonical templates or file preconditions changed after approval",
            ));
        }
        let bindings: Vec<_> = roots
            .iter()
            .zip(&readers)
            .map(|((id, _), reader)| apply::ReaderBinding::new(id, reader))
            .collect();
        let report = apply::apply_plan(
            &expected,
            &bindings,
            &apply::LocalBootstrapHost::new(),
            &preconditions::LocalPreconditionHost::new(),
            home()?.root(),
        );
        if !report.failures().is_empty() {
            return Err(error(ErrorCode::Conflict,"bootstrap-apply-refused","one or more repository applications refused; journals and prior bytes are preserved"));
        }
        return Ok(
            json!({"status":"applied","solution":solution,"repositories":report.successes(),"plan_digest":value["plan_digest"]}),
        );
    }
    if !fresh.conflicts().is_empty() {
        return Err(error(
            ErrorCode::Conflict,
            "bootstrap-conflict",
            "a registered repository contains conflicting managed or human-owned content",
        ));
    }
    if request.form == "bootstrap update plan" {
        if request
            .get("--to")
            .is_some_and(|value| value != templates.version && value != "latest-compatible")
        {
            return Err(error(
                ErrorCode::IncompatibleInput,
                "bootstrap-target-version",
                "the selected owner templates are not the requested version",
            ));
        }
        crate::bootstrap::update::require_compatible_template(
            crate::bootstrap::TEMPLATE_VERSION,
            &templates.version,
        )?;
    }
    let value = seal(
        json!({"kind":"bootstrap","solution":solution,"bundle":std::fs::canonicalize(&bundle).map_err(|_| error(ErrorCode::NotFound,"bundle-missing","the template bundle is missing"))?,"engine_plan":fresh,"hosts":hosts,"host_config_scope":"separate-approved-host-plan"}),
    )?;
    output(request, value)
}

/// Dispatch a composed public form to real native engines.
pub fn run(request: &Request) -> Result<Value, AxiomError> {
    if request.form.starts_with("bootstrap ") {
        return bootstrap(request);
    }
    match request.form.as_str() {
        "host detect" => serde_json::to_value(crate::hosts::detect::detect(
            &crate::hosts::detect::LocalHostProbe::for_current_process(),
        ))
        .map_err(|_| {
            error(
                ErrorCode::Internal,
                "host-report",
                "host discovery report cannot be encoded",
            )
        }),
        "doctor" => {
            let report =
                crate::discovery::discover(&crate::discovery::LocalProbe::for_current_process());
            report.validate()?;
            if !report.ok()
                || report
                    .components
                    .iter()
                    .any(|component| component.installed_version.is_none())
            {
                return Err(error(
                    ErrorCode::NotFound,
                    "doctor-findings",
                    "read-only diagnostics found missing or unhealthy installation prerequisites",
                )
                .with_detail("observed", json!({"read_only":true,"missing_components":report.components.iter().filter(|v|v.installed_version.is_none()).map(|v|&v.component).collect::<Vec<_>>(),"finding_count":report.findings.len()}).to_string()));
            }
            serde_json::to_value(report).map_err(|_| {
                error(
                    ErrorCode::Internal,
                    "doctor-report",
                    "diagnostics cannot be encoded",
                )
            })
        }
        "host configure" | "host verify" => super::host_runtime::run(request),
        "skills version"
        | "skills check"
        | "skills update plan"
        | "skills update apply"
        | "specs version"
        | "specs check"
        | "specs update plan"
        | "specs update apply" => super::package_runtime::run(request),
        "support-bundle" => super::support_runtime::run(request),
        _ => Err(error(
            ErrorCode::ValidationError,
            "unknown-operator-form",
            "this operator form is not declared",
        )),
    }
}

pub(crate) fn argument<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request.get(name)
}
pub(crate) fn required_argument<'a>(
    request: &'a Request,
    name: &str,
) -> Result<&'a str, AxiomError> {
    request.required(name)
}
pub(crate) fn emit(request: &Request, value: Value) -> Result<Value, AxiomError> {
    output(request, value)
}
pub(crate) fn source_bundle(request: &Request, component: &str) -> Result<PathBuf, AxiomError> {
    bundle_root(request, component)
}
