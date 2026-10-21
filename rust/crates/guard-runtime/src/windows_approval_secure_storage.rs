#![forbid(unsafe_code)]

//! Windows secure storage for approval metadata and workspace replay state.
//!
//! Credential Manager is used only for a small current anchor. The bounded
//! value is DPAPI-protected and stored as one content-addressed ciphertext
//! file under the already private state directory.

use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const STORE_SCHEMA: &str = "guard-native-approval-windows-secure-state.v1";
const STORE_VERSION: u16 = 2;
const STORE_DIRECTORY: &str = "approval-secure-state-v1";
const BLOB_PREFIX: &str = "blob-";
const BLOB_SUFFIX: &str = ".bin";
const MAX_BLOB_BYTES: usize = 1024 * 1024;
const MAX_GC_ENTRIES: usize = 256;
const MAX_DPAPI_OVERHEAD: usize = 16 * 1024;
const ENTROPY_DOMAIN: &[u8] = b"hol-guard-native-approval-dpapi-v1\0";
const SCOPE_DOMAIN: &[u8] = b"hol-guard-native-approval-file-scope-v1\0";
const CIPHERTEXT_DOMAIN: &[u8] = b"hol-guard-native-approval-ciphertext-v1\0";
const INVALID: &str = "native_approval_secure_state_invalid";
const UNAVAILABLE: &str = "native_approval_secure_state_unavailable";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    schema: String,
    version: u16,
    sequence: u64,
    ciphertext_digest: String,
    ciphertext_len: u64,
    plaintext_len: u64,
}

const FRAME_VERSION: u8 = 1;
const FRAME_LENGTH_BYTES: usize = 4;

fn invalid() -> String {
    INVALID.to_owned()
}

fn unavailable() -> String {
    UNAVAILABLE.to_owned()
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn map_storage_error(error: std::io::Error) -> String {
    if matches!(
        error.kind(),
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput
    ) {
        invalid()
    } else {
        unavailable()
    }
}

fn map_private_error(error: String) -> String {
    if error.ends_with("_invalid")
        || error.ends_with("_not_private")
        || error.ends_with("_outside_user_profile")
    {
        invalid()
    } else {
        unavailable()
    }
}

fn target_for_anchor(account: &str) -> String {
    format!("org.hashgraphonline.hol-guard.native-approval.v1.anchor.{account}")
}

fn target_for_device(account: &str) -> String {
    format!("org.hashgraphonline.hol-guard.native-approval.v1.device.{account}")
}

fn entropy_for(account: &str) -> Vec<u8> {
    let mut entropy = Vec::with_capacity(ENTROPY_DOMAIN.len() + account.len());
    entropy.extend_from_slice(ENTROPY_DOMAIN);
    entropy.extend_from_slice(account.as_bytes());
    entropy
}

fn scope_digest(account: &str) -> String {
    let mut framed = Vec::with_capacity(SCOPE_DOMAIN.len() + account.len());
    framed.extend_from_slice(SCOPE_DOMAIN);
    framed.extend_from_slice(account.as_bytes());
    digest_bytes(&framed)
}

fn ciphertext_digest(ciphertext: &[u8]) -> String {
    let mut framed = Vec::with_capacity(CIPHERTEXT_DOMAIN.len() + ciphertext.len());
    framed.extend_from_slice(CIPHERTEXT_DOMAIN);
    framed.extend_from_slice(ciphertext);
    digest_bytes(&framed)
}

fn maximum_ciphertext_bytes(max_bytes: usize) -> Option<usize> {
    max_bytes
        .checked_add(MAX_DPAPI_OVERHEAD)
        .filter(|maximum| *maximum <= MAX_BLOB_BYTES)
}

fn next_frame_part<'a>(bytes: &'a [u8], offset: &mut usize) -> Result<&'a [u8], String> {
    let end = (*offset)
        .checked_add(FRAME_LENGTH_BYTES)
        .ok_or_else(invalid)?;
    let length = u32::from_le_bytes(
        bytes
            .get(*offset..end)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    );
    *offset = end;
    let length = usize::try_from(length).map_err(|_| invalid())?;
    let end = (*offset).checked_add(length).ok_or_else(invalid)?;
    let part = bytes.get(*offset..end).ok_or_else(invalid)?;
    *offset = end;
    Ok(part)
}

fn anchor_bytes(anchor: &Anchor) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(anchor).map_err(|_| invalid())?;
    canonical_json_bytes(&value).map_err(|_| invalid())
}

fn validate_anchor(anchor: &Anchor, max_bytes: usize) -> Result<(), String> {
    let maximum_ciphertext = maximum_ciphertext_bytes(max_bytes).ok_or_else(invalid)?;
    if anchor.schema != STORE_SCHEMA
        || anchor.version != STORE_VERSION
        || anchor.sequence == 0
        || !valid_digest(&anchor.ciphertext_digest)
        || anchor.ciphertext_len == 0
        || usize::try_from(anchor.ciphertext_len)
            .ok()
            .is_none_or(|length| length > maximum_ciphertext)
        || usize::try_from(anchor.plaintext_len)
            .ok()
            .is_none_or(|length| length > max_bytes)
    {
        return Err(invalid());
    }
    Ok(())
}

fn decode_anchor(bytes: &[u8], max_bytes: usize) -> Result<Anchor, String> {
    let value = crate::strict_json_value(bytes).map_err(|_| invalid())?;
    if canonical_json_bytes(&value).map_err(|_| invalid())? != bytes {
        return Err(invalid());
    }
    let anchor: Anchor = serde_json::from_value(value).map_err(|_| invalid())?;
    validate_anchor(&anchor, max_bytes)?;
    Ok(anchor)
}

fn read_anchor(account: &str, max_bytes: usize) -> Result<Option<(Anchor, Vec<u8>)>, String> {
    let Some(bytes) = guard_runtime_windows_process::credential_read(&target_for_anchor(account))
        .map_err(map_storage_error)?
    else {
        return Ok(None);
    };
    let anchor = decode_anchor(&bytes, max_bytes)?;
    Ok(Some((anchor, bytes)))
}

fn store_paths(
    state_base: &Path,
    account: &str,
    create: bool,
) -> Result<(PathBuf, PathBuf), String> {
    super::super::super::validate_private_directory(state_base).map_err(map_private_error)?;
    let private_root = crate::resident_state::private_root_for_state_base(state_base)
        .map_err(map_private_error)?;
    let state_base =
        crate::resident_state::ensure_private_directory_under(state_base, &private_root, false)
            .map_err(map_private_error)?;
    let directory = crate::resident_state::ensure_private_directory_under(
        &state_base.join(STORE_DIRECTORY),
        &private_root,
        create,
    )
    .map_err(map_private_error)?;
    let scope = crate::resident_state::ensure_private_directory_under(
        &directory.join(scope_digest(account)),
        &private_root,
        create,
    )
    .map_err(map_private_error)?;
    Ok((scope, private_root))
}

fn blob_path(scope: &Path, digest: &str) -> PathBuf {
    scope.join(format!("{BLOB_PREFIX}{digest}{BLOB_SUFFIX}"))
}

fn read_blob(path: &Path, maximum: usize, private_root: &Path) -> Result<Vec<u8>, String> {
    let Some(file) = crate::resident_state::open_private_read(
        path,
        maximum as u64,
        "approval_secure_state",
        private_root,
    )
    .map_err(map_private_error)?
    else {
        return Err(unavailable());
    };
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(invalid());
    }
    Ok(bytes)
}

fn persist_blob(path: &Path, ciphertext: &[u8], private_root: &Path) -> Result<(), String> {
    super::super::super::policy_store_persistence::persist_private_bytes(
        path,
        ciphertext,
        ciphertext.len() as u64,
        "approval_secure_state",
        private_root,
    )
    .map_err(|_| unavailable())
}

fn validate_existing_blob(
    path: &Path,
    digest: &str,
    expected_len: usize,
    maximum: usize,
    private_root: &Path,
) -> Result<bool, String> {
    let Some(file) = crate::resident_state::open_private_read(
        path,
        maximum as u64,
        "approval_secure_state",
        private_root,
    )
    .map_err(map_private_error)?
    else {
        return Ok(false);
    };
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() != expected_len || ciphertext_digest(&bytes) != digest {
        return Err(invalid());
    }
    Ok(true)
}

fn decode_value(
    mut plaintext: Vec<u8>,
    account: &str,
    max_bytes: usize,
    expected_len: u64,
) -> Result<String, String> {
    let result = (|| {
        if plaintext.first().copied() != Some(FRAME_VERSION) {
            return Err(invalid());
        }
        let mut offset = 1;
        let schema = next_frame_part(&plaintext, &mut offset)?;
        let encoded_account = next_frame_part(&plaintext, &mut offset)?;
        let encoded_value = next_frame_part(&plaintext, &mut offset)?;
        if offset != plaintext.len()
            || schema != STORE_SCHEMA.as_bytes()
            || encoded_account != account.as_bytes()
            || encoded_value.len() > max_bytes
            || encoded_value.len() as u64 != expected_len
        {
            return Err(invalid());
        }
        let value = String::from_utf8(encoded_value.to_vec()).map_err(|_| invalid())?;
        Ok(value.trim().to_owned())
    })();
    guard_runtime_windows_process::secure_zero(&mut plaintext);
    result
}

fn encode_value(account: &str, value: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    let maximum_ciphertext = maximum_ciphertext_bytes(max_bytes).ok_or_else(invalid)?;
    if value.len() > max_bytes
        || u32::try_from(STORE_SCHEMA.len()).is_err()
        || u32::try_from(account.len()).is_err()
        || u32::try_from(value.len()).is_err()
    {
        return Err(invalid());
    }
    let parts = [
        STORE_SCHEMA.as_bytes(),
        account.as_bytes(),
        value.as_bytes(),
    ];
    let frame_len = parts
        .iter()
        .try_fold(FRAME_VERSION as usize, |length, part| {
            length
                .checked_add(FRAME_LENGTH_BYTES)
                .and_then(|length| length.checked_add(part.len()))
        })
        .ok_or_else(invalid)?;
    if frame_len > maximum_ciphertext {
        return Err(invalid());
    }
    let mut encoded = Vec::with_capacity(frame_len);
    encoded.push(FRAME_VERSION);
    for part in parts {
        encoded.extend_from_slice(&(part.len() as u32).to_le_bytes());
        encoded.extend_from_slice(part);
    }
    Ok(encoded)
}

fn garbage_collect(scope: &Path, private_root: &Path, current_digest: &str) {
    // Production writers hold approval_enrollment's transition lock. The
    // current anchor was read back successfully before this best-effort pass;
    // a failed cleanup leaves an orphan, never the current blob missing.
    let Ok(binding) = crate::resident_state::bind_windows_existing_directory(scope, private_root)
    else {
        return;
    };
    let Ok(entries) = fs::read_dir(binding.path()) else {
        return;
    };
    for entry in entries.flatten().take(MAX_GC_ENTRIES) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(digest) = name
            .strip_prefix(BLOB_PREFIX)
            .and_then(|name| name.strip_suffix(BLOB_SUFFIX))
        else {
            continue;
        };
        if valid_digest(digest) && digest != current_digest {
            let _ = crate::resident_state::remove_windows_private_file(&entry.path(), private_root);
        }
    }
}

fn anchor_write_committed(
    write_result: Result<(), String>,
    authoritative: Result<Option<(Anchor, Vec<u8>)>, String>,
    expected_bytes: &[u8],
) -> Result<(), String> {
    let authoritative = authoritative?;
    let committed = authoritative
        .as_ref()
        .is_some_and(|(_, current_bytes)| current_bytes == expected_bytes);
    if !committed {
        return Err(unavailable());
    }
    // CredWriteW may report an error after the durable value is visible. The
    // exact readback, not the API result, is the commit authority.
    let _ = write_result;
    Ok(())
}

pub(super) fn read_direct(account: &str, max_bytes: usize) -> Result<Option<String>, String> {
    let Some(bytes) = guard_runtime_windows_process::credential_read(&target_for_device(account))
        .map_err(map_storage_error)?
    else {
        return Ok(None);
    };
    let value = match String::from_utf8(bytes) {
        Ok(value) => value,
        Err(error) => {
            let mut bytes = error.into_bytes();
            guard_runtime_windows_process::secure_zero(&mut bytes);
            return Err(invalid());
        }
    };
    if value.len() > max_bytes {
        let mut bytes = value.into_bytes();
        guard_runtime_windows_process::secure_zero(&mut bytes);
        return Err(invalid());
    }
    let trimmed = value.trim().to_owned();
    let mut bytes = value.into_bytes();
    guard_runtime_windows_process::secure_zero(&mut bytes);
    Ok(Some(trimmed))
}

pub(super) fn write_direct(account: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    if value.len() > max_bytes {
        return Err(invalid());
    }
    guard_runtime_windows_process::credential_write(&target_for_device(account), value.as_bytes())
        .map_err(map_storage_error)
}

pub(super) fn read(
    state_base: &Path,
    account: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    super::super::super::validate_private_directory(state_base).map_err(map_private_error)?;
    let Some((anchor, _anchor_bytes)) = read_anchor(account, max_bytes)? else {
        return Ok(None);
    };
    let maximum_ciphertext = maximum_ciphertext_bytes(max_bytes).ok_or_else(invalid)?;
    let (scope, private_root) = store_paths(state_base, account, false)?;
    let path = blob_path(&scope, &anchor.ciphertext_digest);
    let ciphertext = read_blob(&path, maximum_ciphertext, &private_root)?;
    if ciphertext.len() as u64 != anchor.ciphertext_len
        || ciphertext_digest(&ciphertext) != anchor.ciphertext_digest
    {
        return Err(invalid());
    }
    let plaintext =
        guard_runtime_windows_process::dpapi_unprotect(&ciphertext, &entropy_for(account))
            .map_err(|_| unavailable())?;
    decode_value(plaintext, account, max_bytes, anchor.plaintext_len).map(Some)
}

pub(super) fn write(
    state_base: &Path,
    account: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), String> {
    super::super::super::validate_private_directory(state_base).map_err(map_private_error)?;
    let previous = read_anchor(account, max_bytes)?;
    let sequence = previous.as_ref().map_or(Ok(1), |(anchor, _)| {
        anchor.sequence.checked_add(1).ok_or_else(invalid)
    })?;
    let mut plaintext = encode_value(account, value, max_bytes)?;
    let ciphertext =
        guard_runtime_windows_process::dpapi_protect(&plaintext, &entropy_for(account))
            .map_err(|_| unavailable());
    guard_runtime_windows_process::secure_zero(&mut plaintext);
    let ciphertext = ciphertext?;
    let maximum_ciphertext = maximum_ciphertext_bytes(max_bytes).ok_or_else(invalid)?;
    if ciphertext.is_empty() || ciphertext.len() > maximum_ciphertext {
        return Err(invalid());
    }
    let digest = ciphertext_digest(&ciphertext);
    let (scope, private_root) = store_paths(state_base, account, true)?;
    let path = blob_path(&scope, &digest);
    if !validate_existing_blob(
        &path,
        &digest,
        ciphertext.len(),
        maximum_ciphertext,
        &private_root,
    )? {
        persist_blob(&path, &ciphertext, &private_root)?;
    }
    let anchor = Anchor {
        schema: STORE_SCHEMA.to_owned(),
        version: STORE_VERSION,
        sequence,
        ciphertext_digest: digest.clone(),
        ciphertext_len: ciphertext.len() as u64,
        plaintext_len: value.len() as u64,
    };
    let bytes = anchor_bytes(&anchor)?;
    let write_result =
        guard_runtime_windows_process::credential_write(&target_for_anchor(account), &bytes);

    // A CredWrite result is not treated as authoritative until the exact
    // anchor is read back. On an uncertain write, do not claim the old anchor
    // survived and do not retry over an authoritative value we have not read.
    let authoritative = read_anchor(account, max_bytes);
    anchor_write_committed(
        write_result.map_err(map_storage_error),
        authoritative,
        &bytes,
    )?;
    garbage_collect(&scope, &private_root, &digest);
    Ok(())
}

#[cfg(test)]
#[path = "windows_approval_secure_storage_tests.rs"]
mod tests;
