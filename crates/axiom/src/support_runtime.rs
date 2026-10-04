//! Native, create-only ZIP support artifacts containing scrubbed diagnostics.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

use graph_core::error::{AxiomError, ErrorCode};
use serde_json::json;

use crate::operator_runtime::{self as io, Request};
use crate::support::{self, Diagnostic, SupportFs};

struct Collector(RefCell<BTreeMap<String, Vec<u8>>>);
impl SupportFs for Collector {
    fn create_dir(&self, _: &str) -> Result<(), AxiomError> {
        Ok(())
    }
    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), AxiomError> {
        if self
            .0
            .borrow_mut()
            .insert(path.to_owned(), bytes.to_vec())
            .is_some()
        {
            return Err(io::error(
                ErrorCode::Conflict,
                "support-entry-duplicate",
                "a support entry was repeated",
            ));
        }
        Ok(())
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320_u32 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
fn u16le(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn u32le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn zip(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut directory = Vec::new();
    for (path, body) in files {
        let name = path.strip_prefix("bundle/").unwrap_or(path).as_bytes();
        let crc = crc32(body);
        let offset = out.len() as u32;
        u32le(&mut out, 0x04034b50);
        u16le(&mut out, 20);
        u16le(&mut out, 0);
        u16le(&mut out, 0);
        u16le(&mut out, 0);
        u16le(&mut out, 33);
        u32le(&mut out, crc);
        u32le(&mut out, body.len() as u32);
        u32le(&mut out, body.len() as u32);
        u16le(&mut out, name.len() as u16);
        u16le(&mut out, 0);
        out.extend_from_slice(name);
        out.extend_from_slice(body);
        u32le(&mut directory, 0x02014b50);
        u16le(&mut directory, 20);
        u16le(&mut directory, 20);
        u16le(&mut directory, 0);
        u16le(&mut directory, 0);
        u16le(&mut directory, 0);
        u16le(&mut directory, 33);
        u32le(&mut directory, crc);
        u32le(&mut directory, body.len() as u32);
        u32le(&mut directory, body.len() as u32);
        u16le(&mut directory, name.len() as u16);
        u16le(&mut directory, 0);
        u16le(&mut directory, 0);
        u16le(&mut directory, 0);
        u16le(&mut directory, 0);
        u32le(&mut directory, 0);
        u32le(&mut directory, offset);
        directory.extend_from_slice(name);
    }
    let offset = out.len() as u32;
    let size = directory.len() as u32;
    out.extend(directory);
    u32le(&mut out, 0x06054b50);
    u16le(&mut out, 0);
    u16le(&mut out, 0);
    u16le(&mut out, files.len() as u16);
    u16le(&mut out, files.len() as u16);
    u32le(&mut out, size);
    u32le(&mut out, offset);
    u16le(&mut out, 0);
    out
}

/// Gather only actual allowlisted summaries and write an exclusively created ZIP.
pub fn run(request: &Request) -> Result<serde_json::Value, AxiomError> {
    let doctor = crate::discovery::discover(&crate::discovery::LocalProbe::for_current_process());
    doctor.validate()?;
    let diagnostics = vec![
        Diagnostic::new("doctor.json", doctor.to_json()?),
        Diagnostic::new(
            "versions.json",
            crate::version::VersionReport::cli().to_json()?,
        ),
        Diagnostic::new(
            "health.json",
            json!({"healthy":doctor.ok(),"source":"actual-read-only-discovery"}).to_string(),
        ),
    ];
    let bundle = support::build(&support::BundleSummary::current(), &diagnostics)?;
    let collector = Collector(RefCell::new(BTreeMap::new()));
    bundle.write(&collector, "bundle")?;
    let bytes = zip(&collector.0.borrow());
    io::write_new(Path::new(io::required_argument(request, "--out")?), &bytes)?;
    Ok(
        json!({"status":"written","redacted":true,"entries":bundle.manifest().entries.len()+1,"archive_sha256":graph_export::sha256_hex(&bytes),"source_revision":crate::version::BUILD_REVISION}),
    )
}
