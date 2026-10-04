//! Explicit local content bundle checks and approved activation, using the shared installer.

use std::path::{Path, PathBuf};

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::paths::validate_portable_relative_path;
use graph_export::sha256_hex;
use serde_json::{json, Value};

use crate::operator_runtime::{self as io, Request};
use crate::skills::install::{self, DeclaredEntry, PayloadSource, SkillBundle, StagedFile};

struct Source {
    root: PathBuf,
    scopes: Vec<String>,
}

impl PayloadSource for Source {
    fn files(&self) -> Result<Vec<StagedFile>, AxiomError> {
        let mut pending: Vec<_> = self
            .scopes
            .iter()
            .map(|scope| self.root.join(scope))
            .collect();
        let mut paths = std::collections::BTreeSet::new();
        while let Some(path) = pending.pop() {
            io::no_links(&path)?;
            let metadata = std::fs::metadata(&path).map_err(|_| {
                io::error(
                    ErrorCode::NotFound,
                    "payload-missing",
                    "a declared payload scope is missing",
                )
            })?;
            if metadata.is_dir() {
                for item in std::fs::read_dir(&path).map_err(|_| {
                    io::error(
                        ErrorCode::NotFound,
                        "payload-unreadable",
                        "a payload directory cannot be enumerated",
                    )
                })? {
                    pending.push(
                        item.map_err(|_| {
                            io::error(
                                ErrorCode::NotFound,
                                "payload-unreadable",
                                "a payload entry cannot be inspected",
                            )
                        })?
                        .path(),
                    );
                }
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(&self.root)
                    .map_err(|_| {
                        io::error(
                            ErrorCode::Forbidden,
                            "payload-escape",
                            "a payload escaped its selected root",
                        )
                    })?
                    .to_string_lossy()
                    .replace('\\', "/");
                if [
                    "bundle.json",
                    "skills-manifest.json",
                    "specs-manifest.json",
                    "SOURCE-REVISION.txt",
                    "RELEASE-SOURCES.json",
                ]
                .contains(&relative.as_str())
                {
                    continue;
                }
                paths.insert(relative);
            } else {
                return Err(io::error(
                    ErrorCode::Forbidden,
                    "payload-kind",
                    "the payload includes a non-regular entry",
                ));
            }
            if paths.len() + pending.len() > 8192 {
                return Err(io::error(
                    ErrorCode::ValidationError,
                    "payload-count",
                    "the payload exceeds the bounded inventory limit",
                ));
            }
        }
        paths
            .into_iter()
            .map(|path| {
                let bytes = self.read(&path)?;
                Ok(StagedFile {
                    executable: install::is_executable_path(&path),
                    path,
                    size_bytes: bytes.len() as u64,
                    sha256: sha256_hex(&bytes),
                })
            })
            .collect()
    }
    fn read(&self, relative: &str) -> Result<Vec<u8>, AxiomError> {
        validate_portable_relative_path(relative)?;
        io::read(&self.root.join(relative))
    }
}

fn source(root: &Path, component: &str) -> Result<(SkillBundle, Source), AxiomError> {
    io::no_links(root)?;
    let root = std::fs::canonicalize(root).map_err(|_| {
        io::error(
            ErrorCode::NotFound,
            "bundle-missing",
            "the selected local bundle directory is missing",
        )
    })?;
    if root.join("bundle.json").exists() {
        let bundle: SkillBundle = serde_json::from_slice(&io::read(&root.join("bundle.json"))?)
            .map_err(|_| {
                io::error(
                    ErrorCode::ValidationError,
                    "bundle-shape",
                    "the engine bundle declaration is invalid",
                )
            })?;
        if bundle.component != component {
            return Err(io::error(
                ErrorCode::ValidationError,
                "bundle-component",
                "the bundle belongs to another component",
            ));
        }
        bundle.validate()?;
        let payload = if root.join("payload").is_dir() {
            root.join("payload")
        } else {
            root
        };
        return Ok((
            bundle,
            Source {
                root: payload,
                scopes: vec![String::new()],
            },
        ));
    }
    let name = format!("{component}-manifest.json");
    let manifest_path = if root.join(&name).is_file() {
        root.join(&name)
    } else {
        root.join("release").join(&name)
    };
    let manifest = io::read_json(&manifest_path)?;
    let expected_owner = if component == "skills" {
        "axiom-skills"
    } else {
        "axiom-specs"
    };
    if manifest["component"] != expected_owner && manifest["component"] != component {
        return Err(io::error(
            ErrorCode::ValidationError,
            "bundle-owner",
            "the owner manifest belongs to another component",
        ));
    }
    let version = manifest["component_version"]
        .as_str()
        .or_else(|| manifest["version"].as_str())
        .ok_or_else(|| {
            io::error(
                ErrorCode::ValidationError,
                "bundle-version",
                "the owner manifest has no declared version",
            )
        })?;
    let revision = manifest["source_revision"]
        .as_str()
        .or_else(|| manifest["revision"].as_str())
        .map(str::to_owned)
        .or_else(|| {
            io::read_json(&root.join("RELEASE-SOURCES.json"))
                .ok()
                .and_then(|v| v["source_revision"].as_str().map(str::to_owned))
        })
        .or_else(|| {
            std::process::Command::new("git")
                .args(["-C"])
                .arg(&root)
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|v| v.trim().to_owned())
        })
        .ok_or_else(|| {
            io::error(
                ErrorCode::ValidationError,
                "bundle-revision",
                "the owner bundle has no immutable source revision",
            )
        })?;
    let spec_revision = manifest["spec_revision"].as_str().ok_or_else(|| {
        io::error(
            ErrorCode::ValidationError,
            "bundle-spec-pin",
            "the bundle has no immutable specification pin",
        )
    })?;
    let entries = manifest["files"]
        .as_array()
        .ok_or_else(|| {
            io::error(
                ErrorCode::ValidationError,
                "bundle-files",
                "the owner manifest declares no files",
            )
        })?
        .iter()
        .map(|entry| {
            let path = entry["path"].as_str().ok_or_else(|| {
                io::error(
                    ErrorCode::ValidationError,
                    "bundle-path",
                    "a file declaration has no path",
                )
            })?;
            let mut declared = DeclaredEntry::new(
                path,
                if install::is_executable_path(path) {
                    "script"
                } else {
                    "asset"
                },
                entry["sha256"].as_str().unwrap_or_default(),
                entry["bytes"].as_u64().unwrap_or(u64::MAX),
            );
            declared.capabilities = entry["capabilities"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            Ok(declared)
        })
        .collect::<Result<Vec<_>, AxiomError>>()?;
    let mut bundle = SkillBundle::new(version, revision, spec_revision, entries);
    bundle.component = component.to_owned();
    bundle.validate()?;
    let scopes = manifest["install_policy"]["declared_scope"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![String::new()]);
    for scope in &scopes {
        if !scope.is_empty() {
            validate_portable_relative_path(scope)?;
        }
    }
    Ok((bundle, Source { root, scopes }))
}

fn pointer(component: &str) -> Result<Option<Value>, AxiomError> {
    let root = io::install_root()?;
    let path = root.join(component).join("current");
    io::no_links(&path)?;
    if !path.exists() {
        return Ok(None);
    }
    let value = io::read_json(&path)?;
    if value["component"] != component {
        return Err(io::error(
            ErrorCode::Conflict,
            "pointer-component",
            "the installed pointer belongs to another component",
        ));
    }
    let version = value["version"].as_str().unwrap_or_default();
    if value["directory"] != format!("{component}/{version}") {
        return Err(io::error(
            ErrorCode::Conflict,
            "pointer-directory",
            "the installed pointer has an unsafe directory",
        ));
    }
    let directory = value["directory"].as_str().unwrap_or_default();
    validate_portable_relative_path(directory)?;
    let manifest_bytes = io::read(&root.join(directory).join("bundle.json"))?;
    if value["manifest_sha256"] != sha256_hex(&manifest_bytes) {
        return Err(io::error(
            ErrorCode::Conflict,
            "installed-manifest-changed",
            "the installed declaration differs from activation",
        ));
    }
    let manifest: SkillBundle = serde_json::from_slice(&manifest_bytes).map_err(|_| {
        io::error(
            ErrorCode::Conflict,
            "installed-manifest-invalid",
            "the installed declaration is invalid",
        )
    })?;
    let content = Source {
        root: root.join(directory),
        scopes: vec![String::new()],
    };
    install::plan_install(&manifest, &content)?;
    Ok(Some(value))
}

fn plan(request: &Request, component: &str) -> Result<Value, AxiomError> {
    let root = io::source_bundle(request, component)?;
    let (bundle, content) = source(&root, component)?;
    install::plan_install(&bundle, &content)?;
    let target = io::required_argument(request, "--to")?;
    if target != bundle.version && target != "latest-compatible" {
        return Err(io::error(
            ErrorCode::IncompatibleInput,
            "target-version",
            "the explicit bundle is not the requested version",
        ));
    }
    let before = pointer(component)?;
    if before
        .as_ref()
        .is_some_and(|v| v["version"] == bundle.version && v["revision"] != bundle.revision)
    {
        return Err(io::error(
            ErrorCode::Conflict,
            "version-content-reuse",
            "an installed version cannot be reused for different content",
        ));
    }
    let value = io::seal(
        json!({"kind":"content-update","component":component,"root":io::install_root()?,"source":content.root,"scopes":content.scopes,"bundle":bundle,"before":before}),
    )?;
    io::emit(request, value)
}

/// Check or activate a reviewed skills/specs bundle through the shared installer.
pub fn run(request: &Request) -> Result<Value, AxiomError> {
    let component = if request.form.starts_with("skills ") {
        "skills"
    } else {
        "specs"
    };
    if request.form.ends_with("version") {
        let installed = pointer(component)?;
        let pin: Value =
            serde_json::from_str(include_str!("../../../spec.lock.json")).map_err(|_| {
                io::error(
                    ErrorCode::Internal,
                    "compiled-pin",
                    "the compiled specification pin is invalid",
                )
            })?;
        return Ok(
            json!({"component":component,"installed":installed,"compiled_spec_version":pin["spec_version"],"compiled_spec_revision":pin["spec_revision"]}),
        );
    }
    if request.form.ends_with("check") {
        let before = pointer(component)?;
        let root = io::source_bundle(request, component)?;
        let (candidate, content) = source(&root, component)?;
        install::plan_install(&candidate, &content)?;
        return Ok(
            json!({"component":component,"read_only":true,"installed":before,"available_version":candidate.version,"available_revision":candidate.revision,"source":"explicit-local-bundle","status":"checked"}),
        );
    }
    if request.form.ends_with("plan") {
        return plan(request, component);
    }
    let value = io::read_json(Path::new(io::required_argument(request, "--plan")?))?;
    io::approved(&value, io::argument(request, "--approve-digest"))?;
    if value["kind"] != "content-update"
        || value["component"] != component
        || value["root"] != json!(io::install_root()?)
    {
        return Err(io::error(
            ErrorCode::Forbidden,
            "plan-scope",
            "the plan belongs to another component or install root",
        ));
    }
    let root = io::install_root()?;
    io::no_links(&root)?;
    std::fs::create_dir_all(&root).map_err(|_| {
        io::error(
            ErrorCode::Forbidden,
            "package-lock-root",
            "the private install directory cannot be created",
        )
    })?;
    let _guard = crate::install::ecosystem_uninstall::maintenance_lock(&root)?;
    let current = pointer(component)?;
    let requested: SkillBundle = serde_json::from_value(value["bundle"].clone()).map_err(|_| {
        io::error(
            ErrorCode::ValidationError,
            "plan-bundle",
            "the approved bundle declaration is malformed",
        )
    })?;
    if requested.component != component {
        return Err(io::error(
            ErrorCode::Forbidden,
            "plan-component",
            "the bundle belongs to another component",
        ));
    }
    let requested_hash = sha256_hex(&requested.manifest_bytes()?);
    if current
        .as_ref()
        .is_some_and(|v| v["manifest_sha256"] == requested_hash)
    {
        return Ok(
            json!({"status":"already-installed","component":component,"version":requested.version}),
        );
    }
    if json!(current) != value["before"] {
        return Err(io::error(
            ErrorCode::Conflict,
            "installed-state-changed",
            "the installed generation changed after approval",
        ));
    }
    let bundle: SkillBundle = serde_json::from_value(value["bundle"].clone()).map_err(|_| {
        io::error(
            ErrorCode::ValidationError,
            "plan-bundle",
            "the approved bundle declaration is malformed",
        )
    })?;
    if bundle.component != component {
        return Err(io::error(
            ErrorCode::Forbidden,
            "plan-component",
            "the plan bundle belongs to another component",
        ));
    }
    let scopes: Vec<String> = serde_json::from_value(value["scopes"].clone()).map_err(|_| {
        io::error(
            ErrorCode::ValidationError,
            "plan-scopes",
            "the payload scopes are malformed",
        )
    })?;
    for scope in &scopes {
        if !scope.is_empty() {
            validate_portable_relative_path(scope)?;
        }
    }
    let content = Source {
        root: PathBuf::from(value["source"].as_str().unwrap_or_default()),
        scopes,
    };
    let engine = install::plan_install(&bundle, &content)?;
    io::no_links(&root.join(&engine.directory))?;
    if value["before"]["manifest_sha256"] == sha256_hex(&bundle.manifest_bytes()?) {
        return Ok(
            json!({"status":"already-installed","component":component,"version":bundle.version}),
        );
    }
    let transaction = root.join(component).join("transactions").join(format!(
        "{}.json",
        value["plan_digest"].as_str().unwrap_or_default()
    ));
    io::write_new(
        &transaction,
        &serde_json::to_vec(&value).map_err(|_| {
            io::error(
                ErrorCode::Internal,
                "transaction-encoding",
                "the activation receipt cannot be encoded",
            )
        })?,
    )?;
    let result = install::install(&engine, &content, &install::LocalInstallFs::new(&root))?;
    Ok(
        json!({"status":"applied","component":component,"version":result.version,"directory":result.directory,"manifest_sha256":result.manifest_sha256,"pointer":result.pointer,"previous_generation_retained":true,"plan_digest":value["plan_digest"]}),
    )
}
