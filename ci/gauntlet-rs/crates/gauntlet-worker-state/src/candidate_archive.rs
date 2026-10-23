//! Bounded, data-only inspection of a two-entry ARM64 candidate bundle.
//! This never extracts or executes the wheel and does not verify native bytes.

use gauntlet_contracts::{canonicalize, is_git_sha};
use gauntlet_evidence::valid_package_version;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{Read, Seek};
use zip::{CompressionMethod, ZipArchive};

const MAX_WHEEL: u64 = 256 * 1024 * 1024;
const MAX_TOTAL: u64 = 257 * 1024 * 1024;
const MAX_MANIFEST: u64 = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateArchiveError {
    InvalidIdentity,
    InvalidZip,
    WrongEntries,
    Oversized,
    InvalidManifest,
    WrongIdentity,
    WheelMismatch,
}

impl fmt::Display for CandidateArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidIdentity => "expected source commit and version required",
            Self::InvalidZip => "candidate bundle is not a readable ZIP archive",
            Self::WrongEntries => "bounded two-file artifact required",
            Self::Oversized => "candidate bundle entry exceeds its byte limit",
            Self::InvalidManifest => "candidate artifact declaration is invalid",
            Self::WrongIdentity => "candidate source, wheel or version differs",
            Self::WheelMismatch => "wheel bytes differ from artifact declaration",
        })
    }
}

impl std::error::Error for CandidateArchiveError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateArchiveDeclaration {
    pub source_sha: String,
    pub version: String,
    pub wheel: String,
    pub wheel_sha256: String,
    pub native_sha256_claim: String,
    pub wheel_bytes: u64,
}

fn lower_hex(raw: &str, len: usize) -> bool {
    raw.len() == len
        && raw
            .bytes()
            .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
}

fn wheel_name(value: &str) -> bool {
    let Some(middle) = value
        .strip_prefix("hol_guard-")
        .and_then(|name| name.strip_suffix("-py3-none-linux_aarch64.whl"))
    else {
        return false;
    };
    !middle.is_empty()
        && middle
            .bytes()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'.'))
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, CandidateArchiveError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(CandidateArchiveError::InvalidManifest)
}

pub fn inspect_candidate_archive<R: Read + Seek>(
    reader: R,
    expected_source: &str,
    expected_version: &str,
) -> Result<CandidateArchiveDeclaration, CandidateArchiveError> {
    if !is_git_sha(expected_source) || !valid_package_version(expected_version) {
        return Err(CandidateArchiveError::InvalidIdentity);
    }
    let mut archive = ZipArchive::new(reader).map_err(|_| CandidateArchiveError::InvalidZip)?;
    if archive.len() != 2 {
        return Err(CandidateArchiveError::WrongEntries);
    }
    let mut names = Vec::with_capacity(2);
    let mut total = 0_u64;
    for index in 0..2 {
        let file = archive
            .by_index(index)
            .map_err(|_| CandidateArchiveError::InvalidZip)?;
        if !matches!(
            file.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        ) {
            return Err(CandidateArchiveError::WrongEntries);
        }
        let size = file.size();
        if size > MAX_WHEEL || file.compressed_size() > MAX_WHEEL {
            return Err(CandidateArchiveError::Oversized);
        }
        total = total
            .checked_add(size)
            .ok_or(CandidateArchiveError::Oversized)?;
        if total > MAX_TOTAL {
            return Err(CandidateArchiveError::Oversized);
        }
        names.push((file.name().to_owned(), size));
    }
    if names[0].0 == names[1].0
        || names
            .iter()
            .filter(|(name, _)| name == "artifact.json")
            .count()
            != 1
        || names
            .iter()
            .find(|(name, _)| name == "artifact.json")
            .is_none_or(|(_, size)| *size > MAX_MANIFEST)
    {
        return Err(CandidateArchiveError::WrongEntries);
    }
    let mut manifest = Vec::new();
    archive
        .by_name("artifact.json")
        .map_err(|_| CandidateArchiveError::InvalidZip)?
        .take(MAX_MANIFEST + 1)
        .read_to_end(&mut manifest)
        .map_err(|_| CandidateArchiveError::InvalidZip)?;
    if manifest.len() as u64 > MAX_MANIFEST {
        return Err(CandidateArchiveError::Oversized);
    }
    canonicalize(&manifest).map_err(|_| CandidateArchiveError::InvalidManifest)?;
    let data: Value =
        serde_json::from_slice(&manifest).map_err(|_| CandidateArchiveError::InvalidManifest)?;
    let object = data
        .as_object()
        .ok_or(CandidateArchiveError::InvalidManifest)?;
    if object.len() != 6
        || ![
            "schema",
            "source_sha",
            "version",
            "wheel",
            "wheel_sha256",
            "native_sha256",
        ]
        .iter()
        .all(|key| object.contains_key(*key))
        || required_string(&data, "schema")? != "hol-gauntlet-pr-artifact.v1"
    {
        return Err(CandidateArchiveError::InvalidManifest);
    }
    let source_sha = required_string(&data, "source_sha")?;
    let version = required_string(&data, "version")?;
    let wheel = required_string(&data, "wheel")?;
    let wheel_sha256 = required_string(&data, "wheel_sha256")?;
    let native_sha256 = required_string(&data, "native_sha256")?;
    if source_sha != expected_source || version != expected_version || !wheel_name(wheel) {
        return Err(CandidateArchiveError::WrongIdentity);
    }
    if !lower_hex(wheel_sha256, 64) || !lower_hex(native_sha256, 64) {
        return Err(CandidateArchiveError::InvalidManifest);
    }
    let wheel_bytes = names
        .iter()
        .find(|(name, _)| name == wheel)
        .map(|(_, size)| *size)
        .ok_or(CandidateArchiveError::WrongEntries)?;
    let mut entry = archive
        .by_name(wheel)
        .map_err(|_| CandidateArchiveError::InvalidZip)?;
    let mut digest = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let n = entry
            .read(&mut buffer)
            .map_err(|_| CandidateArchiveError::InvalidZip)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .ok_or(CandidateArchiveError::Oversized)?;
        if count > MAX_WHEEL {
            return Err(CandidateArchiveError::Oversized);
        }
        digest.update(&buffer[..n]);
    }
    if count != wheel_bytes || format!("{:x}", digest.finalize()) != wheel_sha256 {
        return Err(CandidateArchiveError::WheelMismatch);
    }
    Ok(CandidateArchiveDeclaration {
        source_sha: source_sha.to_owned(),
        version: version.to_owned(),
        wheel: wheel.to_owned(),
        wheel_sha256: wheel_sha256.to_owned(),
        native_sha256_claim: native_sha256.to_owned(),
        wheel_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Cursor, Write};
    use zip::{write::SimpleFileOptions, ZipWriter};

    const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VERSION: &str = "3.50.0a5";
    const WHEEL: &str = "hol_guard-3.50.0a5-py3-none-linux_aarch64.whl";

    fn archive(manifest: &[u8], wheel: &[u8], extra: bool) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        writer.start_file("artifact.json", options).unwrap();
        writer.write_all(manifest).unwrap();
        writer.start_file(WHEEL, options).unwrap();
        writer.write_all(wheel).unwrap();
        if extra {
            writer.start_file("surplus.txt", options).unwrap();
            writer.write_all(b"surplus").unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn manifest(wheel: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema":"hol-gauntlet-pr-artifact.v1",
            "source_sha":SOURCE,
            "version":VERSION,
            "wheel":WHEEL,
            "wheel_sha256":format!("{:x}", Sha256::digest(wheel)),
            "native_sha256":"b".repeat(64),
        }))
        .unwrap()
    }

    #[test]
    fn accepts_two_entry_alpha_bundle_and_streams_wheel_hash() {
        let wheel = b"bounded inert wheel fixture";
        let raw = archive(&manifest(wheel), wheel, false);
        let result = inspect_candidate_archive(Cursor::new(raw), SOURCE, VERSION).unwrap();
        assert_eq!(result.wheel, WHEEL);
        assert_eq!(result.wheel_bytes, wheel.len() as u64);
        assert_eq!(result.native_sha256_claim, "b".repeat(64));
    }

    #[test]
    fn refuses_wrong_source_version_extra_entry_and_changed_wheel() {
        let wheel = b"bounded inert wheel fixture";
        let raw = archive(&manifest(wheel), wheel, false);
        assert_eq!(
            inspect_candidate_archive(Cursor::new(&raw), &"c".repeat(40), VERSION),
            Err(CandidateArchiveError::WrongIdentity)
        );
        assert_eq!(
            inspect_candidate_archive(Cursor::new(&raw), SOURCE, "3.49.0"),
            Err(CandidateArchiveError::WrongIdentity)
        );
        assert_eq!(
            inspect_candidate_archive(
                Cursor::new(archive(&manifest(wheel), wheel, true)),
                SOURCE,
                VERSION
            ),
            Err(CandidateArchiveError::WrongEntries)
        );
        assert_eq!(
            inspect_candidate_archive(
                Cursor::new(archive(&manifest(wheel), b"changed", false)),
                SOURCE,
                VERSION
            ),
            Err(CandidateArchiveError::WheelMismatch)
        );
    }

    #[test]
    fn refuses_duplicate_manifest_keys_before_interpretation() {
        let wheel = b"wheel";
        let first = String::from_utf8(manifest(wheel)).unwrap();
        let duplicate = first.replacen("\"schema\":", "\"schema\":\"changed\",\"schema\":", 1);
        assert_eq!(
            inspect_candidate_archive(
                Cursor::new(archive(duplicate.as_bytes(), wheel, false)),
                SOURCE,
                VERSION
            ),
            Err(CandidateArchiveError::InvalidManifest)
        );
    }
}
