//! `write_private_state`: publishes one native-signed authority file into the
//! guard home's native runtime state directory.
//!
//! The business policy source records and the active command-pack security
//! record are signed or verified natively before the caller holds them; only
//! their persistence was left in Python. The caller sends the exact bytes
//! under one of the file names below, and the resident writes them
//! atomically, reads them back, and compares them byte for byte, as the
//! Python writer did. Any other name, an empty payload or one over the file's
//! limit is refused before anything is written.

use std::path::Path;

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::ExtensionControlAuthorityRequestV1;
use serde_json::{json, Value};

use crate::local_store_read::require_store_path;

const STATE_DIRECTORY: &str = "native-runtime";
/// The Python business document limit plus the record envelope.
const MAX_BUSINESS_RECORD_BYTES: u64 = 1_048_576 + 8_192;
pub(super) const FILES: [(&str, u64); 4] = [
    (
        "business-source-authority.v1.json",
        MAX_BUSINESS_RECORD_BYTES,
    ),
    (
        "business-source-prepared.v1.json",
        MAX_BUSINESS_RECORD_BYTES,
    ),
    ("business-source-anchor.v1.json", 4_096),
    ("active-pack-security.v1.json", 262_144),
];
const INVALID: &str = "native_private_state_invalid";
const WRITE_FAILED: &str = "native_private_state_write_failed";
const MISMATCH: &str = "native_private_state_write_mismatch";

pub(super) fn write_private_state_op(
    request: &ExtensionControlAuthorityRequestV1,
) -> Result<Value, String> {
    let state = request
        .state
        .as_ref()
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    if state.len() != 2 {
        return Err(INVALID.to_owned());
    }
    let name = state.get("name").and_then(Value::as_str).ok_or(INVALID)?;
    let encoded = state
        .get("content_b64")
        .and_then(Value::as_str)
        .ok_or(INVALID)?;
    let content = Base64UrlUnpadded::decode_vec(encoded).map_err(|_| INVALID.to_owned())?;
    let store_path = require_store_path(&request.store_path, &request.guard_home)
        .map_err(|_| INVALID.to_owned())?;
    let guard_home = store_path.parent().ok_or(INVALID)?.to_owned();
    publish(&guard_home, name, &content)?;
    Ok(json!({ "written": true }))
}

pub(super) fn publish(guard_home: &Path, name: &str, content: &[u8]) -> Result<(), String> {
    let maximum = FILES
        .iter()
        .find(|(file, _)| *file == name)
        .map(|(_, maximum)| *maximum)
        .ok_or(INVALID)?;
    if content.is_empty() || content.len() as u64 > maximum {
        return Err(INVALID.to_owned());
    }
    let directory = guard_home.join(STATE_DIRECTORY);
    crate::resident_state::ensure_private_directory_under(&directory, guard_home, false)
        .map_err(|_| WRITE_FAILED.to_owned())?;
    let private_root = crate::resident_state::private_root_for_state_base(&directory)
        .map_err(|_| WRITE_FAILED.to_owned())?;
    let path = directory.join(name);
    crate::policy_store::persist_private_bytes(
        &path,
        content,
        maximum,
        "private_state",
        &private_root,
    )
    .map_err(|_| WRITE_FAILED.to_owned())?;
    let observed =
        crate::policy_store::read_private_file(&path, maximum, "private_state", &private_root)
            .map_err(|_| MISMATCH.to_owned())?;
    if observed.as_deref() != Some(content) {
        return Err(MISMATCH.to_owned());
    }
    Ok(())
}
