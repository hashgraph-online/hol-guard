//! Inert installed Guard version metadata, after independent prefix custody.

use crate::crypto::is_sha256;
use crate::public_files::PublicRootReader;
use crate::{EvidenceError, Result};
use gauntlet_contracts::{canonicalize, is_git_sha};
use regex::Regex;
use serde_json::Value;
use std::path::Path;
use std::sync::OnceLock;

const RUNTIME_MANIFEST: &str =
    "lib/python3.12/site-packages/codex_plugin_scanner/_native/runtime-manifest.json";

pub fn valid_package_version(version: &str) -> bool {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    version.len() <= 64
        && PATTERN
            .get_or_init(|| {
                Regex::new(
                    r"^[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+|\.post[0-9]+|\.dev[0-9]+)?$",
                )
                .expect("fixed package version pattern")
            })
            .is_match(version)
}

/// Compare only bounded, no-symlink installed metadata with independent pins.
/// The caller must separately verify the entire root-owned prefix inventory.
pub fn verify_installed_version_metadata(
    prefix: &Path,
    version: &str,
    source_sha: &str,
    native_sha256: &str,
) -> Result<String> {
    if !valid_package_version(version) || !is_git_sha(source_sha) || !is_sha256(native_sha256) {
        return Err(EvidenceError::Invalid(
            "invalid installed version identity pin",
        ));
    }
    let reader = PublicRootReader::open(prefix)?;
    let raw = reader.read_file(RUNTIME_MANIFEST, 8192)?;
    let canonical = canonicalize(&raw)
        .map_err(|_| EvidenceError::Invalid("invalid installed runtime manifest"))?;
    let manifest: Value = serde_json::from_slice(&canonical)
        .map_err(|_| EvidenceError::Invalid("invalid installed runtime manifest"))?;
    if !manifest.is_object()
        || manifest["package_version"] != version
        || manifest["source_sha"] != source_sha
        || manifest["runtime_sha256"] != native_sha256
    {
        return Err(EvidenceError::Invalid(
            "installed metadata differs from outside pins",
        ));
    }
    Ok(version.to_owned())
}
