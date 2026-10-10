//! Canonical path components and digest records for skill-directory identity.
//!
//! These reproduce the historical Python spellings exactly: NFC components,
//! full Unicode case folding for collision checks, CPython-compatible
//! canonical JSON records, and the incomplete-state hash.

use std::ffi::OsStr;

use guard_contracts::{SkillDirectoryFailureV1, SKILL_DIRECTORY_IDENTITY_SCHEMA};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

pub(crate) type Failure = SkillDirectoryFailureV1;

const RECORD_ERROR: &str = "native_skill_directory_identity_record_invalid";

/// Validate one raw path component and return its NFC spelling.
pub(crate) fn canonical_component(raw: &OsStr) -> Result<String, Failure> {
    let text = raw.to_str().ok_or(Failure::InvalidPathEncoding)?;
    canonical_text_component(text)
}

pub(crate) fn canonical_text_component(text: &str) -> Result<String, Failure> {
    let normalized: String = text.nfc().collect();
    if matches!(normalized.as_str(), "" | "." | "..")
        || normalized.contains('/')
        || normalized.contains('\\')
    {
        return Err(Failure::InvalidRelativePath);
    }
    Ok(normalized)
}

/// Join already-raw components into the canonical `/`-separated spelling.
pub(crate) fn canonical_relative_path<'a>(
    parts: impl IntoIterator<Item = &'a OsStr>,
) -> Result<String, Failure> {
    let mut canonical = Vec::new();
    for part in parts {
        canonical.push(canonical_component(part)?);
    }
    Ok(canonical.join("/"))
}

/// Full Unicode case folding, the equivalent of Python `str.casefold()`.
pub(crate) fn casefold(text: &str) -> String {
    caseless::default_case_fold_str(text)
}

/// Feed one canonical JSON record plus a newline into `digest`.
pub(crate) fn update_digest(digest: &mut Sha256, record: &Value) -> Result<(), Failure> {
    let mut encoded = Vec::new();
    guard_contracts::write_canonical_json_with_limit(
        record,
        &mut encoded,
        usize::MAX,
        RECORD_ERROR,
    )
    .map_err(|_| Failure::UnreadableEntry)?;
    digest.update(&encoded);
    digest.update(b"\n");
    Ok(())
}

pub(crate) fn sha256_label(digest: Sha256) -> String {
    format!("sha256:{}", hex::encode(digest.finalize()))
}

/// Stable, explicitly non-reusable state hash for an incomplete identity.
pub(crate) fn incomplete_state_hash(
    reason: Failure,
    primary_content_hash: Option<&str>,
    entry_count: u64,
    total_bytes: u64,
) -> String {
    incomplete_state_hash_for_label(
        reason.as_str(),
        primary_content_hash,
        entry_count,
        total_bytes,
    )
}

/// The state-hash material keyed by the reason's wire spelling. Also used to
/// pin the constant the Python transport reports when the runtime is absent.
pub(crate) fn incomplete_state_hash_for_label(
    reason: &str,
    primary_content_hash: Option<&str>,
    entry_count: u64,
    total_bytes: u64,
) -> String {
    let material = json!({
        "schema": SKILL_DIRECTORY_IDENTITY_SCHEMA,
        "status": "incomplete",
        "reason": reason,
        "primaryContentHash": primary_content_hash,
        "entryCount": entry_count,
        "totalBytes": total_bytes,
    });
    let mut encoded = Vec::new();
    // The material is a fixed-shape object of strings and integers.
    let encodable = guard_contracts::write_canonical_json_with_limit(
        &material,
        &mut encoded,
        usize::MAX,
        RECORD_ERROR,
    );
    debug_assert!(encodable.is_ok());
    let mut digest = Sha256::new();
    digest.update(&encoded);
    sha256_label(digest)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    use super::*;

    #[test]
    fn components_are_nfc_and_reject_separators() {
        assert_eq!(
            canonical_component(OsStr::new("cafe\u{301}")).unwrap(),
            "caf\u{e9}"
        );
        for bad in ["", ".", "..", "a/b", "a\\b"] {
            assert_eq!(
                canonical_component(OsStr::new(bad)).unwrap_err(),
                Failure::InvalidRelativePath,
                "{bad:?}"
            );
        }
        let invalid = OsString::from_vec(vec![0x66, 0x80, 0x6f]);
        assert_eq!(
            canonical_component(&invalid).unwrap_err(),
            Failure::InvalidPathEncoding
        );
    }

    #[test]
    fn casefold_is_full_unicode_folding() {
        assert_eq!(casefold("Stra\u{df}e"), "strasse");
        assert_eq!(casefold("STRASSE"), "strasse");
    }

    #[test]
    fn relative_path_joins_canonical_components() {
        let parts = [OsStr::new("a"), OsStr::new("cafe\u{301}")];
        assert_eq!(canonical_relative_path(parts).unwrap(), "a/caf\u{e9}");
    }
}
