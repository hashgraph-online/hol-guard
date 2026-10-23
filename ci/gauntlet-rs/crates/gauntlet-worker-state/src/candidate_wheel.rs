//! Inert, bounded verification of the wheel nested inside a candidate ZIP.
//! No wheel entry is extracted, imported, installed or executed here.

use crate::candidate_archive::CandidateArchiveDeclaration;
use gauntlet_contracts::canonicalize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::io::{Cursor, Read};
use zip::{CompressionMethod, ZipArchive};

const MAX_WHEEL: usize = 256 * 1024 * 1024;
const MAX_ENTRY: u64 = 128 * 1024 * 1024;
const MAX_TOTAL: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 20_000;
const MAX_METADATA: u64 = 128 * 1024;
const MAX_MANIFEST: u64 = 8192;
const NATIVE: &str = "codex_plugin_scanner/_native/hol-guard-runtime";
const RUNTIME: &str = "codex_plugin_scanner/_native/runtime-manifest.json";
const COMPLETION: &str = "codex_plugin_scanner/guard/runtime/contained_completion.py";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateWheelError {
    WheelLimit,
    InvalidZip,
    UnsafeEntry,
    MissingIdentity,
    MetadataMismatch,
    RuntimeMismatch,
    NativeMismatch,
}

impl fmt::Display for CandidateWheelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WheelLimit => "nested wheel exceeds fixed byte or entry limits",
            Self::InvalidZip => "nested wheel ZIP is unreadable",
            Self::UnsafeEntry => "nested wheel contains an unsafe path or object",
            Self::MissingIdentity => "single distribution and native identity required",
            Self::MetadataMismatch => "wheel distribution metadata differs from declaration",
            Self::RuntimeMismatch => "native runtime manifest differs from declaration",
            Self::NativeMismatch => "native executable bytes differ from declaration",
        })
    }
}

impl std::error::Error for CandidateWheelError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateWheelProof {
    pub entries: usize,
    pub uncompressed_bytes: u64,
    pub entry_tree_sha256: String,
    pub distribution: String,
    pub native_bytes: u64,
    pub native_sha256: String,
    pub contained_completion_present: bool,
}

fn valid_entry_name(name: &str, raw: &[u8]) -> bool {
    !name.is_empty()
        && name.as_bytes() == raw
        && !name.starts_with('/')
        && !name.contains('\\')
        && !name.chars().any(char::is_control)
        && !name.ends_with('/')
        && !name
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        && (name.starts_with("codex_plugin_scanner/") || distribution_dir(name).is_some())
}

fn distribution_dir(name: &str) -> Option<&str> {
    let (head, _) = name.split_once('/')?;
    let version = head
        .strip_prefix("hol_guard-")?
        .strip_suffix(".dist-info")?;
    if version.is_empty()
        || !version
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'.'))
    {
        return None;
    }
    Some(head)
}

fn read_bounded(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    name: &str,
    limit: u64,
) -> Result<Vec<u8>, CandidateWheelError> {
    let file = archive
        .by_name(name)
        .map_err(|_| CandidateWheelError::MissingIdentity)?;
    if file.size() > limit {
        return Err(CandidateWheelError::WheelLimit);
    }
    let mut bytes = Vec::with_capacity(file.size() as usize);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CandidateWheelError::InvalidZip)?;
    if bytes.len() as u64 > limit {
        return Err(CandidateWheelError::WheelLimit);
    }
    Ok(bytes)
}

fn metadata_matches(raw: &[u8], version: &str) -> bool {
    let Ok(text) = std::str::from_utf8(raw) else {
        return false;
    };
    let mut name = None;
    let mut found_version = None;
    let mut last_identity = false;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if last_identity {
                return false;
            }
            continue;
        }
        last_identity = false;
        let Some((key, value)) = line.split_once(':') else {
            return false;
        };
        if key.eq_ignore_ascii_case("Name") {
            if name.replace(value.trim()).is_some() {
                return false;
            }
            last_identity = true;
        } else if key.eq_ignore_ascii_case("Version") {
            if found_version.replace(value.trim()).is_some() {
                return false;
            }
            last_identity = true;
        }
    }
    name == Some("hol-guard") && found_version == Some(version)
}

pub fn inspect_candidate_wheel(
    raw: &[u8],
    declaration: &CandidateArchiveDeclaration,
) -> Result<CandidateWheelProof, CandidateWheelError> {
    if raw.is_empty() || raw.len() > MAX_WHEEL {
        return Err(CandidateWheelError::WheelLimit);
    }
    if format!("{:x}", Sha256::digest(raw)) != declaration.wheel_sha256 {
        return Err(CandidateWheelError::NativeMismatch);
    }
    let mut archive =
        ZipArchive::new(Cursor::new(raw)).map_err(|_| CandidateWheelError::InvalidZip)?;
    if archive.is_empty() || archive.len() > MAX_ENTRIES {
        return Err(CandidateWheelError::WheelLimit);
    }
    let mut names = BTreeSet::new();
    let mut distributions = BTreeSet::new();
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .map_err(|_| CandidateWheelError::InvalidZip)?;
        let name = file.name();
        if !valid_entry_name(name, file.name_raw())
            || !names.insert(name.to_owned())
            || file
                .unix_mode()
                .is_some_and(|mode| !matches!(mode & 0o170000, 0 | 0o100000))
            || !matches!(
                file.compression(),
                CompressionMethod::Stored | CompressionMethod::Deflated
            )
        {
            return Err(CandidateWheelError::UnsafeEntry);
        }
        if let Some(directory) = distribution_dir(name) {
            distributions.insert(directory.to_owned());
        }
        if file.size() > MAX_ENTRY {
            return Err(CandidateWheelError::WheelLimit);
        }
        total = total
            .checked_add(file.size())
            .ok_or(CandidateWheelError::WheelLimit)?;
        if total > MAX_TOTAL {
            return Err(CandidateWheelError::WheelLimit);
        }
    }
    if distributions.len() != 1 || !names.contains(NATIVE) || !names.contains(RUNTIME) {
        return Err(CandidateWheelError::MissingIdentity);
    }
    let distribution = distributions
        .into_iter()
        .next()
        .ok_or(CandidateWheelError::MissingIdentity)?;
    if distribution != format!("hol_guard-{}.dist-info", declaration.version) {
        return Err(CandidateWheelError::MetadataMismatch);
    }
    let metadata_name = format!("{distribution}/METADATA");
    if !names.contains(&metadata_name) {
        return Err(CandidateWheelError::MissingIdentity);
    }
    let metadata = read_bounded(&mut archive, &metadata_name, MAX_METADATA)?;
    if !metadata_matches(&metadata, &declaration.version) {
        return Err(CandidateWheelError::MetadataMismatch);
    }
    let runtime = read_bounded(&mut archive, RUNTIME, MAX_MANIFEST)?;
    canonicalize(&runtime).map_err(|_| CandidateWheelError::RuntimeMismatch)?;
    let manifest: Value =
        serde_json::from_slice(&runtime).map_err(|_| CandidateWheelError::RuntimeMismatch)?;
    if manifest["schema"] != "hol-guard-native-runtime.v1"
        || manifest["source_sha"] != declaration.source_sha
        || manifest["package_version"] != declaration.version
        || manifest["runtime_sha256"] != declaration.native_sha256_claim
        || manifest["platform_tag"] != "linux_aarch64"
        || manifest["target"] != "aarch64-unknown-linux-gnu"
    {
        return Err(CandidateWheelError::RuntimeMismatch);
    }
    let mut native = archive
        .by_name(NATIVE)
        .map_err(|_| CandidateWheelError::MissingIdentity)?;
    let native_expected_size = native.size();
    let mut digest = Sha256::new();
    let mut native_bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let n = native
            .read(&mut buffer)
            .map_err(|_| CandidateWheelError::InvalidZip)?;
        if n == 0 {
            break;
        }
        native_bytes = native_bytes
            .checked_add(n as u64)
            .ok_or(CandidateWheelError::WheelLimit)?;
        if native_bytes > MAX_ENTRY {
            return Err(CandidateWheelError::WheelLimit);
        }
        digest.update(&buffer[..n]);
    }
    let native_sha256 = format!("{:x}", digest.finalize());
    if native_bytes != native_expected_size
        || manifest["runtime_size"] != native_bytes
        || native_sha256 != declaration.native_sha256_claim
    {
        return Err(CandidateWheelError::NativeMismatch);
    }
    drop(native);
    let mut tree = Sha256::new();
    let mut decoded = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|_| CandidateWheelError::InvalidZip)?;
        tree.update((entry.name().len() as u64).to_be_bytes());
        tree.update(entry.name().as_bytes());
        tree.update(entry.size().to_be_bytes());
        let expected = entry.size();
        let mut read_bytes = 0_u64;
        loop {
            let n = entry
                .read(&mut buffer)
                .map_err(|_| CandidateWheelError::InvalidZip)?;
            if n == 0 {
                break;
            }
            read_bytes = read_bytes
                .checked_add(n as u64)
                .ok_or(CandidateWheelError::WheelLimit)?;
            decoded = decoded
                .checked_add(n as u64)
                .ok_or(CandidateWheelError::WheelLimit)?;
            if read_bytes > MAX_ENTRY || decoded > MAX_TOTAL {
                return Err(CandidateWheelError::WheelLimit);
            }
            tree.update(&buffer[..n]);
        }
        if read_bytes != expected {
            return Err(CandidateWheelError::InvalidZip);
        }
    }
    if decoded != total {
        return Err(CandidateWheelError::InvalidZip);
    }
    Ok(CandidateWheelProof {
        entries: archive.len(),
        uncompressed_bytes: total,
        entry_tree_sha256: format!("{:x}", tree.finalize()),
        distribution,
        native_bytes,
        native_sha256,
        contained_completion_present: names.contains(COMPLETION),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use zip::{write::SimpleFileOptions, ZipWriter};

    const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VERSION: &str = "3.50.0a5";

    fn wheel(
        native: &[u8],
        manifest_source: &str,
        metadata_version: &str,
        claimed_native: &str,
        extra: Option<&str>,
    ) -> Vec<u8> {
        let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        writer.start_file(NATIVE, options).unwrap();
        writer.write_all(native).unwrap();
        writer.start_file(RUNTIME, options).unwrap();
        writer
            .write_all(
                serde_json::to_string(&json!({
                    "schema":"hol-guard-native-runtime.v1",
                    "source_sha":manifest_source,
                    "package_version":VERSION,
                    "runtime_sha256":claimed_native,
                    "runtime_size":native.len(),
                    "platform_tag":"linux_aarch64",
                    "target":"aarch64-unknown-linux-gnu",
                }))
                .unwrap()
                .as_bytes(),
            )
            .unwrap();
        writer
            .start_file("hol_guard-3.50.0a5.dist-info/METADATA", options)
            .unwrap();
        writer
            .write_all(
                format!("Metadata-Version: 2.4\nName: hol-guard\nVersion: {metadata_version}\n\n")
                    .as_bytes(),
            )
            .unwrap();
        if let Some(name) = extra {
            writer.start_file(name, options).unwrap();
            writer.write_all(b"extra").unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn declaration(raw: &[u8], native_sha: &str) -> CandidateArchiveDeclaration {
        CandidateArchiveDeclaration {
            source_sha: SOURCE.to_owned(),
            version: VERSION.to_owned(),
            wheel: "hol_guard-3.50.0a5-py3-none-linux_aarch64.whl".to_owned(),
            wheel_sha256: format!("{:x}", Sha256::digest(raw)),
            native_sha256_claim: native_sha.to_owned(),
            wheel_bytes: raw.len() as u64,
        }
    }

    #[test]
    fn checks_native_bytes_runtime_manifest_and_distribution_metadata() {
        let native = b"inert native fixture";
        let digest = format!("{:x}", Sha256::digest(native));
        let raw = wheel(native, SOURCE, VERSION, &digest, None);
        let proof = inspect_candidate_wheel(&raw, &declaration(&raw, &digest)).unwrap();
        assert_eq!(proof.entries, 3);
        assert_eq!(proof.native_bytes, native.len() as u64);
        assert_eq!(proof.native_sha256, digest);
        assert!(!proof.contained_completion_present);
        let with_completion = wheel(native, SOURCE, VERSION, &digest, Some(COMPLETION));
        let proof =
            inspect_candidate_wheel(&with_completion, &declaration(&with_completion, &digest))
                .unwrap();
        assert!(proof.contained_completion_present);
    }

    #[test]
    fn refuses_wrong_nested_source_metadata_and_native_bytes() {
        let native = b"inert native fixture";
        let digest = format!("{:x}", Sha256::digest(native));
        let source_bad = wheel(native, &"c".repeat(40), VERSION, &digest, None);
        assert_eq!(
            inspect_candidate_wheel(&source_bad, &declaration(&source_bad, &digest)),
            Err(CandidateWheelError::RuntimeMismatch)
        );
        let metadata_bad = wheel(native, SOURCE, "3.49.0", &digest, None);
        assert_eq!(
            inspect_candidate_wheel(&metadata_bad, &declaration(&metadata_bad, &digest)),
            Err(CandidateWheelError::MetadataMismatch)
        );
        let native_bad = wheel(b"changed", SOURCE, VERSION, &digest, None);
        assert_eq!(
            inspect_candidate_wheel(&native_bad, &declaration(&native_bad, &digest)),
            Err(CandidateWheelError::NativeMismatch)
        );
        let path_bad = wheel(
            native,
            SOURCE,
            VERSION,
            &digest,
            Some("codex_plugin_scanner/../escape"),
        );
        assert_eq!(
            inspect_candidate_wheel(&path_bad, &declaration(&path_bad, &digest)),
            Err(CandidateWheelError::UnsafeEntry)
        );
    }
}
