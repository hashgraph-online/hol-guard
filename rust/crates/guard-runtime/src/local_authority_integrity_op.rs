//! `local-authority-integrity --stdin`: sign and verify the purpose-bound
//! integrity columns that `local_authority_integrity.py` attaches to local
//! approval authority outside policy rows (Codex hook repair and recovery
//! requests, publication inverses and runtime transitions). The runtime's
//! own approval gate and continuation grants already use the same
//! `guard_policy_snapshot::local_authority_integrity` code.
//!
//! - `sign` answers the five integrity columns for `payload` under `key_hex`;
//! - `verify` answers `{status, payload_hash, key_id, message}` for
//!   `payload` and its stored `integrity`, where `key_hex`/`key_id` are
//!   `null` when no key is available.
//!
//! Every stored column must be present and non-empty before anything is
//! compared, so a row missing its key id reads as `missing_integrity`
//! rather than as signed by an unknown key.

use std::io::Read;

use guard_policy_snapshot::local_authority_integrity::{
    sign_local_authority_payload, verify_local_authority_payload,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};

const SCHEMA: &str = "local-authority-integrity.v1";
const MAX_REQUEST_BYTES: u64 = 80 * 1024 * 1024;
const MAX_KEY_BYTES: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    payload: Map<String, Value>,
    purpose: String,
    key_hex: Option<String>,
    key_id: Option<String>,
    #[serde(default)]
    signed_at: Option<String>,
    #[serde(default)]
    integrity: Option<Map<String, Value>>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "local-authority-integrity"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "local_authority_integrity_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("local_authority_integrity_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if request.schema != SCHEMA {
        return Err(invalid());
    }
    let key = match request.key_hex.as_deref() {
        Some(text) if text.len() <= MAX_KEY_BYTES * 2 => {
            Some(hex::decode(text).map_err(|_| invalid())?)
        }
        Some(_) => return Err(invalid()),
        None => None,
    };
    let payload = Value::Object(request.payload);
    let answer = match (
        request.op.as_str(),
        key,
        request.key_id,
        request.signed_at,
        request.integrity,
    ) {
        ("sign", Some(key), Some(key_id), Some(signed_at), None) => {
            let fields =
                sign_local_authority_payload(&payload, &key, &key_id, &request.purpose, &signed_at)
                    .map_err(str::to_owned)?;
            json!({
                "integrity_version": fields.integrity_version,
                "payload_hash": fields.payload_hash,
                "payload_mac": fields.payload_mac,
                "integrity_key_id": fields.integrity_key_id,
                "signed_at": fields.signed_at,
            })
        }
        ("verify", key, key_id, None, Some(integrity)) => verify(
            &payload,
            &integrity,
            key.as_deref(),
            key_id.as_deref(),
            &request.purpose,
        ),
        _ => return Err(invalid()),
    };
    Ok(answer.to_string().into_bytes())
}

fn invalid() -> String {
    "local_authority_integrity_request_invalid".to_owned()
}

fn verify(
    payload: &Value,
    integrity: &Map<String, Value>,
    key: Option<&[u8]>,
    key_id: Option<&str>,
    purpose: &str,
) -> Value {
    let text = |name: &str| {
        integrity
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    };
    let complete = integrity
        .get("integrity_version")
        .and_then(Value::as_i64)
        .is_some()
        && [
            "payload_hash",
            "payload_mac",
            "integrity_key_id",
            "signed_at",
        ]
        .iter()
        .all(|name| text(name).is_some());
    if !complete {
        return json!({
            "status": "missing_integrity",
            "payload_hash": text("payload_hash"),
            "key_id": text("integrity_key_id"),
            "message": "local_authority_integrity_metadata_missing",
        });
    }
    let result = verify_local_authority_payload(
        payload,
        &Value::Object(integrity.clone()),
        key,
        key_id,
        purpose,
    );
    json!({
        "status": result.status,
        "payload_hash": result.payload_hash,
        "key_id": result.key_id,
        "message": result.message,
    })
}

#[cfg(test)]
#[path = "local_authority_integrity_op_tests.rs"]
mod tests;
