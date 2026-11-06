//! `write_command_marker`: signs and publishes the native command-control
//! authority marker, `command-control-authority.v1.json`, in the guard home's
//! native runtime state directory.
//!
//! The caller holds the exclusive control mutation lease and sends the record
//! it decided on, without a MAC, together with the derived verifier key. The
//! record is held to the same shape the Python encoder enforced, signed with
//! the per-schema domain the native reader (`policy_store_command_authority`)
//! verifies, written atomically, and read back byte for byte before the signed
//! record is returned.

use std::path::{Path, PathBuf};

use guard_contracts::{ExtensionControlAuthorityRequestV1, NativeCommandControlAuthorityV1};
use guard_policy_snapshot::canonical_json_bytes;
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha256;

use crate::local_store_read::require_store_path;

pub(super) const MARKER_FILE: &str = "command-control-authority.v1.json";
const STATE_DIRECTORY: &str = "native-runtime";
const MAX_MARKER_BYTES: usize = 4_096;
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const SCHEMAS: [(&str, &[u8]); 3] = [
    (
        "guard.native-command-control-authority.v1",
        b"hol-guard.native-command-control-authority.v1\0",
    ),
    (
        "guard.native-command-control-authority.v2",
        b"hol-guard.native-command-control-authority.v2\0",
    ),
    (
        "guard.native-command-control-authority.v3",
        b"hol-guard.native-command-control-authority.v3\0",
    ),
];
const INVALID: &str = "native_command_control_authority_invalid";
const WRITE_FAILED: &str = "native_command_control_authority_write_failed";
const MISMATCH: &str = "native_command_control_authority_write_mismatch";

pub(super) fn write_command_marker_op(
    request: &ExtensionControlAuthorityRequestV1,
    key: Option<&[u8]>,
) -> Result<Value, String> {
    let key = key.filter(|key| key.len() == 32).ok_or(INVALID)?;
    let record = request.state.as_ref().ok_or(INVALID)?;
    let store_path = require_store_path(&request.store_path, &request.guard_home)
        .map_err(|_| INVALID.to_owned())?;
    let guard_home = store_path.parent().ok_or(INVALID)?.to_owned();
    let (signed, encoded) = sign_marker(record, key)?;
    publish(&guard_home, &encoded)?;
    Ok(json!({ "marker": signed }))
}

/// `encode_authority`: the record with its MAC, and its canonical bytes.
pub(super) fn sign_marker(record: &Value, key: &[u8]) -> Result<(Value, Vec<u8>), String> {
    let mut signed = record.as_object().ok_or(INVALID)?.clone();
    signed.insert("mac".to_owned(), Value::String(ZERO_DIGEST.to_owned()));
    let domain = validate(&signed)?;
    signed.remove("mac");
    let body = canonical_json_bytes(&Value::Object(signed.clone())).map_err(|_| INVALID)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| INVALID)?;
    mac.update(domain);
    mac.update(&body);
    signed.insert(
        "mac".to_owned(),
        Value::String(hex::encode(mac.finalize().into_bytes())),
    );
    let signed = Value::Object(signed);
    let encoded = canonical_json_bytes(&signed).map_err(|_| INVALID)?;
    if encoded.len() > MAX_MARKER_BYTES {
        return Err(INVALID.to_owned());
    }
    Ok((signed, encoded))
}

/// `_validate_record`: the exact field set for the schema, a valid authority
/// binding, and an effective digest present exactly when committed.
fn validate(record: &Map<String, Value>) -> Result<&'static [u8], String> {
    let schema = record
        .get("schema")
        .and_then(Value::as_str)
        .ok_or(INVALID)?;
    let index = SCHEMAS
        .iter()
        .position(|(name, _)| *name == schema)
        .ok_or(INVALID)?;
    let mut fields = vec![
        "schema",
        "epoch",
        "mutation_revision",
        "authority_key_id",
        "recovery",
        "phase",
        "effective_digest",
        "mac",
    ];
    if index >= 1 {
        fields.push("pack_program_digest");
    }
    if index == 2 {
        fields.push("active_security_digest");
    }
    if record.len() != fields.len() || fields.iter().any(|name| !record.contains_key(*name)) {
        return Err(INVALID.to_owned());
    }
    if fields[8..].iter().any(|name| !digest(&record[*name])) {
        return Err(INVALID.to_owned());
    }
    let binding: NativeCommandControlAuthorityV1 = serde_json::from_value(json!({
        "epoch": record["epoch"],
        "mutation_revision": record["mutation_revision"],
        "authority_key_id": record["authority_key_id"],
        "recovery": record["recovery"],
    }))
    .map_err(|_| INVALID.to_owned())?;
    binding.validate().map_err(|_| INVALID.to_owned())?;
    let effective = &record["effective_digest"];
    let phase_ok = match record["phase"].as_str() {
        Some("closed") => effective.is_null(),
        Some("committed") => digest(effective),
        _ => false,
    };
    if !phase_ok || !digest(&record["mac"]) {
        return Err(INVALID.to_owned());
    }
    Ok(SCHEMAS[index].1)
}

fn digest(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn marker_path(guard_home: &Path) -> PathBuf {
    guard_home.join(STATE_DIRECTORY).join(MARKER_FILE)
}

/// `write_private_state` then the read-back the Python writer compared.
pub(super) fn publish(guard_home: &Path, encoded: &[u8]) -> Result<(), String> {
    crate::resident_state::ensure_private_directory_under(
        &guard_home.join(STATE_DIRECTORY),
        guard_home,
        false,
    )
    .map_err(|_| WRITE_FAILED.to_owned())?;
    let path = marker_path(guard_home);
    crate::resident_private_file::write_private(&path, encoded, guard_home)
        .map_err(|_| WRITE_FAILED.to_owned())?;
    let observed =
        crate::resident_private_file::read_private_bytes(&path, guard_home, "command_authority")
            .map_err(|_| MISMATCH.to_owned())?;
    if observed.as_deref() != Some(encoded) {
        return Err(MISMATCH.to_owned());
    }
    Ok(())
}
