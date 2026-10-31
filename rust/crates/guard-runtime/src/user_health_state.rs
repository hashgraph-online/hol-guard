//! `user-health-state --stdin`: the opted-in user installation's health lease
//! state.
//!
//! The state lives in the user's Guard home and carries the P-256 key the
//! user installation signs its leases with. A read trusts it only when the
//! Guard home and the file belong to the user and no one else may read them,
//! the file held still while read, and every field is well formed: the
//! identifiers, the lease sequence and its digest, the timestamp, and a key
//! whose public half and key id are the ones stored beside it. A write checks
//! the same and replaces the file through a private temporary.
//! `mdm/health_lease` signing, the cadence and the state lock stay in
//! `mdm/user_health.py`.

use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use base64ct::{Base64, Base64Url, Encoding};
use guard_command::attestation_timestamp::parse_attestation_timestamp;
use guard_command::inventory_fingerprints::python_compact_json;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const SCHEMA: &str = "user-health-state.v1";
const STATE_SCHEMA: &str = "hol-guard-user-health-state.v1";
const STATE_NAME: &str = "user-health-state.json";
const MAX_STATE_BYTES: u64 = 512 * 1024;
const MAX_REQUEST_BYTES: u64 = 2 * MAX_STATE_BYTES;
const ACL_INVALID: &str = "user_health_state_acl_invalid";
const STATE_INVALID: &str = "user_health_state_invalid";
const IO_FAILED: &str = "user_health_state_io_failed";
const FIELDS: [&str; 13] = [
    "schemaVersion",
    "enabled",
    "workspaceId",
    "deviceId",
    "machineInstallationId",
    "installationGeneration",
    "sequence",
    "lastLeaseDigest",
    "keyId",
    "publicKeySpki",
    "privateKeyPem",
    "pendingOutbox",
    "updatedAt",
];
/// The DER `SubjectPublicKeyInfo` header of an uncompressed P-256 point: the
/// `id-ecPublicKey` and `prime256v1` identifiers, then a 66-byte bit string.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
// Split so that no PEM frame is ever spelled out in the source.
const PEM_BEGIN: &str = concat!("-----BEGIN PRIVATE", " KEY-----");
const PEM_END: &str = concat!("-----END PRIVATE", " KEY-----");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    guard_home: PathBuf,
    owner_uid: u32,
    #[serde(default)]
    state: Option<Value>,
}

/// A refused request, in the Python exception it is raised as.
struct StateError {
    class: &'static str,
    reason_code: &'static str,
}

fn refused(class: &'static str, reason_code: &'static str) -> StateError {
    StateError { class, reason_code }
}

fn io_failed(_error: io::Error) -> StateError {
    refused("os", IO_FAILED)
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "user-health-state"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "user_health_state_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("user_health_state_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "user_health_state_request_invalid".to_owned())?;
    let response = respond(request)?;
    serde_json::to_vec(&response).map_err(|_| "user_health_state_response_encode_failed".to_owned())
}

fn respond(request: Request) -> Result<Value, String> {
    if request.schema != SCHEMA {
        return Err("user_health_state_request_invalid".to_owned());
    }
    let home = request.guard_home.as_path();
    let outcome = match (request.op.as_str(), request.state) {
        ("read", None) => {
            read_state(home, request.owner_uid).map(|state| json!({"ok": true, "state": state}))
        }
        ("write", Some(state)) => {
            write_state(home, request.owner_uid, &state).map(|()| json!({"ok": true}))
        }
        _ => return Err("user_health_state_request_invalid".to_owned()),
    };
    Ok(outcome.unwrap_or_else(
        |error| json!({"ok": false, "error_class": error.class, "reason_code": error.reason_code}),
    ))
}

/// The stored state, `None` when the Guard home or the file does not exist.
fn read_state(home: &Path, owner_uid: u32) -> Result<Option<Value>, StateError> {
    match fs::symlink_metadata(home) {
        Ok(metadata) if is_private(&metadata, owner_uid, true) => {}
        Ok(_) => return Err(refused("permission", ACL_INVALID)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_failed(error)),
    }
    let mut file = match open_without_following(&home.join(STATE_NAME)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) if is_link_loop(&error) => return Err(refused("permission", ACL_INVALID)),
        Err(error) => return Err(io_failed(error)),
    };
    let before = file.metadata().map_err(io_failed)?;
    if before.len() > MAX_STATE_BYTES || !is_private(&before, owner_uid, false) {
        return Err(refused("permission", ACL_INVALID));
    }
    let mut payload = Vec::new();
    file.by_ref()
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut payload)
        .map_err(io_failed)?;
    let after = file.metadata().map_err(io_failed)?;
    if payload.len() as u64 != before.len() || before.len() != after.len() {
        return Err(refused("value", STATE_INVALID));
    }
    let state: Value =
        serde_json::from_slice(&payload).map_err(|_| refused("value", STATE_INVALID))?;
    if !is_valid_state(&state) {
        return Err(refused("value", STATE_INVALID));
    }
    Ok(Some(state))
}

/// Replace the stored state with `state`, which must be valid on its own.
fn write_state(home: &Path, owner_uid: u32, state: &Value) -> Result<(), StateError> {
    if !is_valid_state(state) {
        return Err(refused("value", STATE_INVALID));
    }
    match fs::symlink_metadata(home) {
        Ok(metadata) if is_private(&metadata, owner_uid, true) => {}
        Ok(_) => return Err(refused("permission", ACL_INVALID)),
        Err(error) => return Err(io_failed(error)),
    }
    let payload = python_compact_json(state);
    if payload.len() as u64 > MAX_STATE_BYTES {
        return Err(refused("value", STATE_INVALID));
    }
    crate::managed_policy_file_trust::replace_restricted_file(
        &home.join(STATE_NAME),
        payload.as_bytes(),
    )
    .map_err(io_failed)
}

fn is_valid_state(state: &Value) -> bool {
    let Some(fields) = state.as_object() else {
        return false;
    };
    if fields.len() != FIELDS.len() || !FIELDS.iter().all(|name| fields.contains_key(*name)) {
        return false;
    }
    let text = |name: &str| fields.get(name).and_then(Value::as_str);
    let Some(sequence) = fields.get("sequence").and_then(Value::as_u64) else {
        return false;
    };
    let digest = fields
        .get("lastLeaseDigest")
        .filter(|value| !value.is_null());
    text("schemaVersion") == Some(STATE_SCHEMA)
        && fields.get("enabled").is_some_and(Value::is_boolean)
        && text("workspaceId").is_some_and(|value| !value.is_empty())
        && text("deviceId").is_some_and(|value| !value.is_empty())
        && text("machineInstallationId").is_some_and(|value| is_lower_hex(value, 32))
        && text("installationGeneration").is_some_and(|value| is_lower_hex(value, 32))
        && (sequence == 0) == digest.is_none()
        && digest.is_none_or(|value| value.as_str().is_some_and(|text| is_lower_hex(text, 64)))
        && text("publicKeySpki").is_some_and(|value| value.chars().count() <= 1024)
        && text("privateKeyPem").is_some_and(|value| value.chars().count() <= 4096)
        && optional_text_within(fields, "pendingOutbox", 400_000)
        && text("updatedAt").is_some_and(|value| parse_attestation_timestamp(value).is_some())
        && keys_agree(fields)
}

fn optional_text_within(fields: &Map<String, Value>, name: &str, limit: usize) -> bool {
    match fields.get(name) {
        Some(Value::Null) => true,
        Some(Value::String(value)) => value.chars().count() <= limit,
        _ => false,
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Whether the private key is a P-256 key whose public half is the stored
/// `publicKeySpki` and whose SHA-256 is the stored `keyId`.
fn keys_agree(fields: &Map<String, Value>) -> bool {
    let text = |name: &str| fields.get(name).and_then(Value::as_str).unwrap_or_default();
    let key_id = text("keyId");
    if key_id.len() != 43 {
        return false;
    }
    let (Some(point), Ok(public_der), Ok(key_digest)) = (
        private_key_point(text("privateKeyPem")),
        Base64::decode_vec(text("publicKeySpki")),
        Base64Url::decode_vec(&format!("{key_id}=")),
    ) else {
        return false;
    };
    let mut expected_der = P256_SPKI_PREFIX.to_vec();
    expected_der.extend_from_slice(&point);
    expected_der == public_der
        && Sha256::digest(public_der.as_slice()).as_slice() == key_digest.as_slice()
}

/// The uncompressed public point of a PKCS#8 P-256 private key.
fn private_key_point(pem: &str) -> Option<Vec<u8>> {
    let body = pem
        .trim()
        .strip_prefix(PEM_BEGIN)?
        .strip_suffix(PEM_END)?
        .split_whitespace()
        .collect::<String>();
    let der = Base64::decode_vec(&body).ok()?;
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &der, &SystemRandom::new())
            .ok()?;
    let point = pair.public_key().as_ref();
    (point.len() == 65 && point[0] == 0x04).then(|| point.to_vec())
}

#[cfg(unix)]
fn open_without_following(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

/// The reparse-point flag opens a link itself, which then reads as no
/// regular file.
#[cfg(windows)]
fn open_without_following(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(unix)]
fn is_link_loop(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_link_loop(_error: &io::Error) -> bool {
    false
}

/// A directory (or a regular file) of the user that no one else may read or
/// write. A link is neither.
#[cfg(unix)]
fn is_private(metadata: &Metadata, owner_uid: u32, directory: bool) -> bool {
    use std::os::unix::fs::MetadataExt;

    let kind = if directory {
        metadata.is_dir()
    } else {
        metadata.is_file()
    };
    kind && metadata.uid() == owner_uid && metadata.mode() & 0o077 == 0
}

/// Windows reports no owner or mode bits here; the Guard home's own ACL is
/// what keeps the state private there.
#[cfg(not(unix))]
fn is_private(metadata: &Metadata, _owner_uid: u32, directory: bool) -> bool {
    if directory {
        metadata.is_dir()
    } else {
        metadata.is_file()
    }
}

#[cfg(test)]
#[path = "user_health_state_tests.rs"]
mod tests;
