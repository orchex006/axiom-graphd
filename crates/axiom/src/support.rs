//! The redacted support bundle (task E-047).
//!
//! `axiom-specs/tasks/E/E-047.md` AC1 fixes the shape of this module:
//!
//! > Diagnostic archive excludes secrets/source bodies and arbitrary paths; user
//! > can inspect the bundle manifest before sharing.
//!
//! `SOURCE-OF-TRUST.md` (nothing secret in Git/argv/logs) and the redaction-only
//! path rule of `graph_core::redact` (CP-03) make the rest mechanical: a bundle is
//! an *allowlisted* set of named diagnostics, every name and every byte is
//! validated and scrubbed before a manifest exists, and the manifest is readable
//! on its own so an operator can decide what to share.
//!
//! Three refusals carry the whole contract:
//!
//! * a name that is an absolute, UNC or traversing path is refused, so the archive
//!   can never reach an arbitrary file on the host;
//! * a name outside [`ALLOWED_ENTRIES`] is refused, so a credential file
//!   (`id_rsa`, `.env`, ...) cannot be pulled in by naming it;
//! * content carrying a source-body or private-key signature is refused, so the
//!   bundle cannot become a code or credential exfiltration channel.
//!
//! Nothing is written until [`SupportBundle::write`] is called, and the only
//! writes it can perform are the manifest plus the diagnostics it already
//! validated and scrubbed. There is deliberately no function here that reads an
//! arbitrary path, uploads a bundle or contacts the network.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use graph_core::error::{AxiomError, ErrorCode};
use graph_core::redact;
use graph_export::sha256_hex;

/// Diagnostics a support bundle may contain, and the complete set of names it may
/// use.
///
/// The list is an allowlist on purpose: "include whatever file the caller names"
/// is exactly the shape that leaks `~/.ssh/id_rsa`, so a name that is not here is
/// refused rather than resolved.
pub const ALLOWED_ENTRIES: [&str; 8] = [
    "config-summary.json",
    "doctor.json",
    "health.json",
    "install-log.txt",
    "policy.json",
    "queue-depth.json",
    "update-journal.txt",
    "versions.json",
];

/// Most entries one bundle may hold.
pub const MAX_ENTRIES: usize = ALLOWED_ENTRIES.len();

/// Largest single diagnostic, after scrubbing.
pub const MAX_ENTRY_BYTES: usize = 256 * 1024;

/// Largest whole bundle, after scrubbing.
pub const MAX_BUNDLE_BYTES: usize = 1024 * 1024;

/// Signatures that mean "this is source code, not a diagnostic".
const SOURCE_BODY_SIGNATURES: [&str; 6] = [
    "#include <",
    "<?php",
    "def main(",
    "fn main(",
    "import os",
    "use std::",
];

/// Marker that means "this is credential material, not a diagnostic".
const PRIVATE_KEY_MARKER: &str = "PRIVATE KEY";

/// The note every rendered manifest carries, so a reader knows the manifest is
/// the artifact to inspect before sharing.
pub const MANIFEST_NOTE: &str = "inspect this manifest before sharing: it lists every entry, its size, its SHA256 and whether it was redacted";

/// One diagnostic offered to a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Entry name, from [`ALLOWED_ENTRIES`].
    pub name: String,
    /// Entry body. It is scrubbed before it is hashed or written.
    pub content: String,
}

impl Diagnostic {
    /// A named diagnostic.
    #[must_use]
    pub fn new(name: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            content: content.into(),
        }
    }
}

/// One manifest entry: what will be shared, never the bytes themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleEntry {
    /// Entry name.
    pub name: String,
    /// Size of the scrubbed body in bytes.
    pub size_bytes: u64,
    /// Lowercase 64-hex digest of the scrubbed body.
    pub sha256: String,
    /// Whether scrubbing changed the body before it was hashed.
    pub redacted: bool,
}

/// The host facts a bundle records about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSummary {
    /// Core version the reporting host runs.
    pub version: String,
    /// Build revision the reporting host runs.
    pub revision: String,
    /// Operating system, e.g. `windows` or `linux`.
    pub platform: String,
    /// Architecture, e.g. `x86_64`.
    pub arch: String,
}

impl BundleSummary {
    /// The summary for this build's core version, revision and target.
    #[must_use]
    pub fn current() -> Self {
        Self {
            version: crate::version::CORE_VERSION.to_string(),
            revision: crate::version::BUILD_REVISION.to_string(),
            platform: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
        }
    }
}

/// What a bundle will contain, computed before any byte is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleManifest {
    /// Component that produced the bundle.
    pub component: &'static str,
    /// Host facts.
    pub summary: BundleSummary,
    /// Every entry, in the order it will be written.
    pub entries: Vec<BundleEntry>,
    /// Total scrubbed size of every entry.
    pub total_bytes: u64,
    /// Whether any entry was redacted.
    pub any_redacted: bool,
}

impl BundleManifest {
    /// Number of entries that were redacted.
    #[must_use]
    pub fn redacted_count(&self) -> usize {
        self.entries.iter().filter(|entry| entry.redacted).count()
    }

    /// The manifest as the text an operator inspects before sharing.
    ///
    /// It carries names, sizes and digests only, never a body, so rendering it can
    /// not leak the content it describes.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "support bundle manifest");
        let _ = writeln!(out, "component: {}", self.component);
        let _ = writeln!(out, "version: {}", self.summary.version);
        let _ = writeln!(out, "revision: {}", self.summary.revision);
        let _ = writeln!(
            out,
            "platform: {}/{}",
            self.summary.platform, self.summary.arch
        );
        let _ = writeln!(out, "entries: {}", self.entries.len());
        let _ = writeln!(out, "total_bytes: {}", self.total_bytes);
        let _ = writeln!(out, "redacted_entries: {}", self.redacted_count());
        for entry in &self.entries {
            let _ = writeln!(
                out,
                "entry: {} {} {} redacted={}",
                entry.name, entry.size_bytes, entry.sha256, entry.redacted
            );
        }
        let _ = writeln!(out, "note: {MANIFEST_NOTE}");
        out
    }
}

/// A validated, scrubbed bundle: the manifest plus the bodies it describes.
///
/// Nothing is written until [`SupportBundle::write`] is called, so an operator can
/// inspect [`SupportBundle::manifest`] first and abandon the bundle without ever
/// touching the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportBundle {
    manifest: BundleManifest,
    entries: Vec<(String, String)>,
}

impl SupportBundle {
    /// The manifest, safe to show a user before they share the bundle.
    #[must_use]
    pub fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }

    /// The rendered manifest text.
    #[must_use]
    pub fn render_manifest(&self) -> String {
        self.manifest.render()
    }

    /// Write the manifest and every entry under `dir`.
    ///
    /// Returns the relative paths written, manifest first.
    ///
    /// # Errors
    ///
    /// Refuses a destination that is not a portable relative directory, or fails
    /// when the filesystem surface fails.
    pub fn write(&self, fs: &dyn SupportFs, dir: &str) -> Result<Vec<String>, AxiomError> {
        if dir.is_empty()
            || redact::looks_like_absolute_path(dir)
            || dir.contains("..")
            || dir.contains('\\')
        {
            return Err(refuse("destination_not_portable", dir));
        }
        fs.create_dir(dir)?;
        let manifest_path = format!("{dir}/manifest.txt");
        fs.write(&manifest_path, self.render_manifest().as_bytes())?;
        let mut written = vec![manifest_path];
        for (name, body) in &self.entries {
            let path = format!("{dir}/{name}");
            fs.write(&path, body.as_bytes())?;
            written.push(path);
        }
        Ok(written)
    }
}

/// Validate, scrub and describe a bundle without writing anything.
///
/// # Errors
///
/// Refuses an entry name that is not portable or not allowlisted, content that
/// carries source or credential material, a duplicate name, an entry past
/// [`MAX_ENTRY_BYTES`], a bundle past [`MAX_BUNDLE_BYTES`], and more than
/// [`MAX_ENTRIES`] entries.
pub fn build(summary: &BundleSummary, inputs: &[Diagnostic]) -> Result<SupportBundle, AxiomError> {
    if inputs.len() > MAX_ENTRIES {
        return Err(
            refuse("too_many_entries", &inputs.len().to_string())
                .with_detail("limit", MAX_ENTRIES.to_string()),
        );
    }

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut entries = Vec::with_capacity(inputs.len());
    let mut bodies = Vec::with_capacity(inputs.len());
    let mut total_bytes: u64 = 0;
    let mut any_redacted = false;

    for input in inputs {
        validate_name(&input.name)?;
        if !seen.insert(input.name.as_str()) {
            return Err(refuse("duplicate_entry_name", &input.name));
        }
        validate_content(&input.name, &input.content)?;

        let scrubbed = redact::scrub(&input.content);
        if scrubbed.len() > MAX_ENTRY_BYTES {
            return Err(refuse("entry_too_large", &input.name)
                .with_detail("limit", MAX_ENTRY_BYTES.to_string())
                .with_detail("actual", scrubbed.len().to_string()));
        }
        total_bytes += scrubbed.len() as u64;
        if total_bytes > MAX_BUNDLE_BYTES as u64 {
            return Err(refuse("bundle_too_large", &input.name)
                .with_detail("limit", MAX_BUNDLE_BYTES.to_string())
                .with_detail("actual", total_bytes.to_string()));
        }

        let redacted = scrubbed != input.content;
        any_redacted |= redacted;
        entries.push(BundleEntry {
            name: input.name.clone(),
            size_bytes: scrubbed.len() as u64,
            sha256: sha256_hex(scrubbed.as_bytes()),
            redacted,
        });
        bodies.push((input.name.clone(), scrubbed));
    }

    Ok(SupportBundle {
        manifest: BundleManifest {
            component: crate::version::CORE_COMPONENT,
            summary: summary.clone(),
            entries,
            total_bytes,
            any_redacted,
        },
        entries: bodies,
    })
}

/// Refuse a name that is not a portable relative path, then one that is not an
/// allowlisted diagnostic.
fn validate_name(name: &str) -> Result<(), AxiomError> {
    let portable = !name.is_empty()
        && !redact::looks_like_absolute_path(name)
        && !name.contains("..")
        && !name.contains('/')
        && !name.contains('\\');
    if !portable {
        return Err(refuse("entry_name_not_portable", name));
    }
    if !ALLOWED_ENTRIES.contains(&name) {
        return Err(refuse("entry_name_not_allowed", name));
    }
    Ok(())
}

/// Refuse content that is source code or credential material rather than a
/// diagnostic.
fn validate_content(name: &str, content: &str) -> Result<(), AxiomError> {
    if content.contains(PRIVATE_KEY_MARKER) {
        return Err(refuse("credential_material_refused", name));
    }
    if SOURCE_BODY_SIGNATURES
        .iter()
        .any(|signature| content.contains(signature))
    {
        return Err(refuse("source_body_refused", name));
    }
    Ok(())
}

/// The one refusal shape of this module.
fn refuse(rule: &str, observed: &str) -> AxiomError {
    AxiomError::new(
        ErrorCode::ValidationError,
        "the support bundle violates the support bundle contract",
    )
    .with_detail("rule", rule)
    .with_detail("observed", observed)
}

/// The mutation surface of one bundle destination.
///
/// The trait is the whole surface on purpose: a bundle cannot delete, truncate,
/// rename or walk a directory, so a caller-supplied double or a hostile fixture
/// cannot make [`SupportBundle::write`] do more than create one directory and
/// write the files its manifest already lists.
pub trait SupportFs {
    /// Create the destination directory.
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be created.
    fn create_dir(&self, path: &str) -> Result<(), AxiomError>;
    /// Write one file.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be written.
    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError>;
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use super::*;

    fn summary() -> BundleSummary {
        BundleSummary {
            version: "0.0.0-dev".to_string(),
            revision: "test-revision".to_string(),
            platform: "windows".to_string(),
            arch: "x86_64".to_string(),
        }
    }

    fn rule_of(error: &AxiomError) -> Option<&str> {
        error.details().get("rule").map(String::as_str)
    }

    fn detail(error: &AxiomError, key: &str) -> Option<&str> {
        error.details().get(key).map(String::as_str)
    }

    #[derive(Default)]
    struct MemoryFs {
        dirs: RefCell<BTreeSet<String>>,
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        fail_write: RefCell<Option<String>>,
    }

    impl MemoryFs {
        fn get(&self, path: &str) -> Option<String> {
            self.files
                .borrow()
                .get(path)
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        }

        fn paths(&self) -> Vec<String> {
            self.files.borrow().keys().cloned().collect()
        }
    }

    impl SupportFs for MemoryFs {
        fn create_dir(&self, path: &str) -> Result<(), AxiomError> {
            self.dirs.borrow_mut().insert(path.to_string());
            Ok(())
        }

        fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError> {
            let failure = self.fail_write.borrow().clone();
            if let Some(needle) = failure {
                if path.contains(&needle) {
                    return Err(AxiomError::new(
                        ErrorCode::Internal,
                        "the fixture write failed",
                    )
                    .with_detail("observed", path));
                }
            }
            self.files
                .borrow_mut()
                .insert(path.to_string(), bytes.to_vec());
            Ok(())
        }
    }

    #[test]
    fn allowed_diagnostics_are_bundled_hashed_and_described() {
        let inputs = [
            Diagnostic::new("versions.json", "{\"core\":\"0.0.0-dev\"}"),
            Diagnostic::new("doctor.json", "{\"verdict\":\"healthy\"}"),
        ];
        let bundle = build(&summary(), &inputs).expect("build");

        let manifest = bundle.manifest();
        assert_eq!(manifest.component, "axiom-graphd");
        assert_eq!(manifest.summary, summary());
        assert_eq!(manifest.entries.len(), 2);
        assert!(!manifest.any_redacted);
        assert_eq!(manifest.redacted_count(), 0);

        let versions = &manifest.entries[0];
        assert_eq!(versions.name, "versions.json");
        assert_eq!(versions.size_bytes, inputs[0].content.len() as u64);
        assert_eq!(versions.sha256, sha256_hex(inputs[0].content.as_bytes()));
        assert!(!versions.redacted);
        assert_eq!(
            manifest.total_bytes,
            (inputs[0].content.len() + inputs[1].content.len()) as u64
        );
    }

    #[test]
    fn the_manifest_is_inspectable_before_anything_is_written() {
        let inputs = [Diagnostic::new("health.json", "{\"status\":\"ok\"}")];
        let bundle = build(&summary(), &inputs).expect("build");
        let fs = MemoryFs::default();

        let rendered = bundle.render_manifest();
        assert!(rendered.contains(MANIFEST_NOTE));
        assert!(rendered.contains("health.json"));
        assert!(rendered.contains("platform: windows/x86_64"));
        assert!(rendered.contains("redacted_entries: 0"));

        assert!(fs.paths().is_empty(), "nothing may be written by build");
        assert!(fs.dirs.borrow().is_empty());
    }

    #[test]
    fn secrets_in_content_are_scrubbed_flagged_and_never_rendered() {
        let inputs = [Diagnostic::new("install-log.txt", "token=abc123\ninstalled")];
        let bundle = build(&summary(), &inputs).expect("build");
        let entry = &bundle.manifest().entries[0];

        assert!(entry.redacted);
        assert!(bundle.manifest().any_redacted);
        assert_eq!(bundle.manifest().redacted_count(), 1);
        assert!(!bundle.render_manifest().contains("abc123"));
        assert_eq!(
            entry.sha256,
            sha256_hex("token=[redacted]\ninstalled".as_bytes())
        );

        let fs = MemoryFs::default();
        bundle.write(&fs, "bundle").expect("write");
        let body = fs.get("bundle/install-log.txt").expect("entry written");
        assert!(!body.contains("abc123"));
        assert!(body.contains(redact::REDACTED));
    }

    #[test]
    fn a_host_path_in_content_becomes_a_path_marker() {
        let inputs = [Diagnostic::new(
            "config-summary.json",
            "installed_at C:\\Axiom\\bin\\axiom.exe",
        )];
        let bundle = build(&summary(), &inputs).expect("build");

        assert!(bundle.manifest().entries[0].redacted);
        let fs = MemoryFs::default();
        bundle.write(&fs, "bundle").expect("write");
        let body = fs.get("bundle/config-summary.json").expect("written");
        assert!(!body.contains("Axiom\\bin"));
        assert!(body.contains(redact::REDACTED_PATH));
    }

    #[test]
    fn an_absolute_entry_name_is_refused_and_the_path_is_not_echoed() {
        let inputs = [Diagnostic::new(
            "C:\\Users\\owner\\.ssh\\id_rsa",
            "irrelevant",
        )];
        let error = build(&summary(), &inputs).expect_err("must refuse");
        assert_eq!(rule_of(&error), Some("entry_name_not_portable"));
        let observed = detail(&error, "observed").unwrap_or_default();
        assert!(!observed.contains("Users"), "observed was {observed}");
    }

    #[test]
    fn a_traversing_entry_name_is_refused() {
        for name in ["../health.json", "sub/health.json", "sub\\health.json", ""] {
            let inputs = [Diagnostic::new(name, "body")];
            let error = build(&summary(), &inputs).expect_err("must refuse");
            assert_eq!(
                rule_of(&error),
                Some("entry_name_not_portable"),
                "name {name}"
            );
        }
    }

    #[test]
    fn a_name_outside_the_allowlist_is_refused() {
        for name in ["id_rsa", ".env", "credentials.json", "axiom.db"] {
            let inputs = [Diagnostic::new(name, "body")];
            let error = build(&summary(), &inputs).expect_err("must refuse");
            assert_eq!(
                rule_of(&error),
                Some("entry_name_not_allowed"),
                "name {name}"
            );
            assert_eq!(detail(&error, "observed"), Some(name));
        }
    }

    #[test]
    fn source_bodies_are_refused() {
        for content in [
            "fn main() { println!(\"hi\"); }",
            "use std::collections::BTreeMap;\n",
            "#include <stdio.h>\n",
        ] {
            let inputs = [Diagnostic::new("install-log.txt", content)];
            let error = build(&summary(), &inputs).expect_err("must refuse");
            assert_eq!(rule_of(&error), Some("source_body_refused"));
        }
    }

    #[test]
    fn private_key_material_is_refused() {
        let inputs = [Diagnostic::new(
            "install-log.txt",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA",
        )];
        let error = build(&summary(), &inputs).expect_err("must refuse");
        assert_eq!(rule_of(&error), Some("credential_material_refused"));
    }

    #[test]
    fn every_allowed_name_is_accepted_and_the_cap_is_the_allowlist() {
        let body = "{\"ok\":true}";
        let inputs: Vec<Diagnostic> = ALLOWED_ENTRIES
            .iter()
            .map(|name| Diagnostic::new(*name, body))
            .collect();
        assert_eq!(inputs.len(), MAX_ENTRIES);

        let bundle = build(&summary(), &inputs).expect("every allowed name is accepted");
        assert_eq!(bundle.manifest().entries.len(), MAX_ENTRIES);
        assert_eq!(
            bundle.manifest().total_bytes,
            (MAX_ENTRIES * body.len()) as u64
        );
    }

    #[test]
    fn an_entry_past_the_byte_limit_is_refused_at_the_boundary() {
        let exact = "a".repeat(MAX_ENTRY_BYTES);
        let bundle = build(
            &summary(),
            &[Diagnostic::new("install-log.txt", exact.clone())],
        )
        .expect("exactly the limit is accepted");
        assert_eq!(
            bundle.manifest().entries[0].size_bytes,
            MAX_ENTRY_BYTES as u64
        );

        let over = "a".repeat(MAX_ENTRY_BYTES + 1);
        let error = build(&summary(), &[Diagnostic::new("install-log.txt", over)])
            .expect_err("one byte over must be refused");
        assert_eq!(rule_of(&error), Some("entry_too_large"));
        assert_eq!(detail(&error, "limit"), Some("262144"));
        assert_eq!(detail(&error, "observed"), Some("install-log.txt"));
    }

    #[test]
    fn a_bundle_past_the_total_limit_is_refused() {
        let big = "a".repeat(MAX_ENTRY_BYTES);
        let inputs: Vec<Diagnostic> = ALLOWED_ENTRIES
            .iter()
            .take(5)
            .map(|name| Diagnostic::new(*name, big.clone()))
            .collect();

        let error = build(&summary(), &inputs).expect_err("must refuse");
        assert_eq!(rule_of(&error), Some("bundle_too_large"));
        assert_eq!(detail(&error, "limit"), Some("1048576"));
    }

    #[test]
    fn more_entries_than_the_cap_is_refused() {
        let mut inputs: Vec<Diagnostic> = ALLOWED_ENTRIES
            .iter()
            .map(|name| Diagnostic::new(*name, "{}"))
            .collect();
        inputs.push(Diagnostic::new(ALLOWED_ENTRIES[0], "{}"));

        let error = build(&summary(), &inputs).expect_err("must refuse");
        assert_eq!(rule_of(&error), Some("too_many_entries"));
        assert_eq!(detail(&error, "limit"), Some("8"));
    }

    #[test]
    fn a_duplicate_entry_name_is_refused() {
        let inputs = [
            Diagnostic::new("health.json", "{}"),
            Diagnostic::new("health.json", "{\"status\":\"ok\"}"),
        ];
        let error = build(&summary(), &inputs).expect_err("must refuse");
        assert_eq!(rule_of(&error), Some("duplicate_entry_name"));
        assert_eq!(detail(&error, "observed"), Some("health.json"));
    }

    #[test]
    fn write_creates_the_manifest_first_then_every_validated_entry() {
        let inputs = [
            Diagnostic::new("config-summary.json", "{\"home\":\"portable\"}"),
            Diagnostic::new("doctor.json", "{\"verdict\":\"healthy\"}"),
        ];
        let bundle = build(&summary(), &inputs).expect("build");
        let fs = MemoryFs::default();

        let written = bundle.write(&fs, "out").expect("write");
        assert_eq!(
            written,
            vec![
                "out/manifest.txt".to_string(),
                "out/config-summary.json".to_string(),
                "out/doctor.json".to_string(),
            ]
        );
        assert_eq!(fs.get("out/manifest.txt"), Some(bundle.render_manifest()));
        assert_eq!(
            fs.get("out/doctor.json").as_deref(),
            Some("{\"verdict\":\"healthy\"}")
        );
        assert!(fs.dirs.borrow().contains("out"));
    }

    #[test]
    fn write_refuses_a_destination_that_is_not_a_portable_directory() {
        let bundle = build(&summary(), &[Diagnostic::new("health.json", "{}")]).expect("build");
        let fs = MemoryFs::default();

        for dir in ["C:\\out", "../out", "", "sub\\out", "\\\\server\\share"] {
            let error = bundle.write(&fs, dir).expect_err("must refuse");
            assert_eq!(
                rule_of(&error),
                Some("destination_not_portable"),
                "dir {dir}"
            );
        }
        assert!(fs.paths().is_empty());
    }

    #[test]
    fn a_filesystem_failure_surfaces_and_no_entry_past_it_is_written() {
        let inputs = [
            Diagnostic::new("health.json", "{}"),
            Diagnostic::new("doctor.json", "{}"),
        ];
        let bundle = build(&summary(), &inputs).expect("build");
        let fs = MemoryFs::default();
        *fs.fail_write.borrow_mut() = Some("doctor.json".to_string());

        let error = bundle.write(&fs, "out").expect_err("must fail");
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(detail(&error, "observed"), Some("out/doctor.json"));
        assert_eq!(
            fs.paths(),
            vec![
                "out/health.json".to_string(),
                "out/manifest.txt".to_string(),
            ]
        );
    }

    #[test]
    fn the_summary_is_this_build_and_there_is_no_separate_bootstrap_component() {
        let current = BundleSummary::current();
        assert_eq!(current.version, crate::version::CORE_VERSION);
        assert_eq!(current.revision, crate::version::BUILD_REVISION);
        assert_eq!(current.platform, std::env::consts::OS);
        assert_eq!(current.arch, std::env::consts::ARCH);
        assert_eq!(crate::version::CORE_COMPONENT, "axiom-graphd");
        assert!(!crate::version::COMPONENTS.contains(&"axiom-bootstrap"));
    }
}
