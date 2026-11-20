//! The device-key metadata `mdm/device_key.py` keeps in the machine state
//! root, checked the way that module checked it before this one: the schema,
//! a lifecycle state, 32 lowercase hex digits for every generation, a known
//! protection level, a bounded public key, and a state that agrees with its
//! generations. Fields it does not read are ignored, as they were.

use serde_json::{json, Map, Value};

const SCHEMA: &str = "hol-guard-device-key.v1";
const STATES: [&str; 4] = ["pending", "active", "rotation_pending", "revoked"];
const PROTECTION_LEVELS: [&str; 2] = ["hardware-backed", "os-protected"];
const MAX_PUBLIC_KEY_CHARS: usize = 1024;

/// The metadata with only the fields `mdm/device_key.py` reads, or `None`
/// when it is not metadata that module would accept.
pub(super) fn parse(bytes: &[u8]) -> Option<Value> {
    let raw: Value = serde_json::from_slice(bytes).ok()?;
    let raw = raw.as_object()?;
    if raw.get("schemaVersion").and_then(Value::as_str) != Some(SCHEMA) {
        return None;
    }
    let state = raw
        .get("state")
        .and_then(Value::as_str)
        .filter(|state| STATES.contains(state))?;
    let pending = match raw.get("pendingGeneration") {
        None | Some(Value::Null) => None,
        Some(value) => Some(generation_id(value)?),
    };
    let updated_at = non_empty(raw.get("updatedAt"))?;
    let active = generation(raw.get("active"))?;
    let previous = generation(raw.get("previous"))?;
    if state == "active" && (active.is_null() || pending.is_some()) {
        return None;
    }
    if matches!(state, "pending" | "rotation_pending") && pending.is_none() {
        return None;
    }
    Some(json!({
        "schemaVersion": SCHEMA,
        "state": state,
        "active": active,
        "pendingGeneration": pending,
        "previous": previous,
        "updatedAt": updated_at,
    }))
}

/// One key generation, `Value::Null` when there is none, `None` when it is
/// malformed.
fn generation(raw: Option<&Value>) -> Option<Value> {
    let fields: &Map<String, Value> = match raw {
        None | Some(Value::Null) => return Some(Value::Null),
        Some(Value::Object(fields)) => fields,
        Some(_) => return None,
    };
    let id = generation_id(fields.get("generation")?)?;
    let key_id = non_empty(fields.get("keyId"))?;
    let public_key_spki = fields
        .get("publicKeySpki")
        .and_then(Value::as_str)
        .filter(|text| text.chars().count() <= MAX_PUBLIC_KEY_CHARS)?;
    let protection_level = fields
        .get("protectionLevel")
        .and_then(Value::as_str)
        .filter(|level| PROTECTION_LEVELS.contains(level))?;
    let created_at = non_empty(fields.get("createdAt"))?;
    Some(json!({
        "generation": id,
        "keyId": key_id,
        "publicKeySpki": public_key_spki,
        "protectionLevel": protection_level,
        "createdAt": created_at,
    }))
}

fn generation_id(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| {
        text.len() == 32
            && text
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn non_empty(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

#[cfg(test)]
#[path = "device_key_metadata_tests.rs"]
mod tests;
