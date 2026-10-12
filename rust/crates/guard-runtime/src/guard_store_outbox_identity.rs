//! Review outbox identity primitives: payload integrity digest, OAuth subject
//! hash, deterministic Cloud Review correlation ids, and validation of frozen
//! continuation snapshots. Each mirrors the stored-data contract of the
//! Python implementation that wrote the rows these functions authenticate.

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::guard_store_json::py_strip;

const DIGEST_DOMAIN: &[u8] = b"hol-guard-review-event-integrity-v1";
const CORRELATION_NAMESPACE: [u8; 16] = [
    0xe9, 0x27, 0xe1, 0xcf, 0xe2, 0x57, 0x4a, 0xf5, 0xae, 0x66, 0xa8, 0xb6, 0xed, 0xcc, 0x18, 0xf5,
];

fn binding_text(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        other => other.to_string(),
    }
}

/// HMAC-SHA256 over `payload_json`, keyed by the delivery binding
/// `(source, subject_hash, workspace_id, machine_id, installation_id)`.
pub(crate) fn payload_digest(payload_json: &str, binding: [&Value; 5]) -> String {
    let joined = binding
        .iter()
        .map(|value| binding_text(value))
        .collect::<Vec<_>>()
        .join("\0");
    let mut key = DIGEST_DOMAIN.to_vec();
    key.push(0);
    key.extend_from_slice(joined.as_bytes());
    let mut mac = <Hmac<Sha256>>::new_from_slice(&key).expect("hmac accepts any key length");
    mac.update(payload_json.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Convenience over borrowed strings (a fully populated binding).
pub(crate) fn payload_digest_text(payload_json: &str, binding: [&str; 5]) -> String {
    let values = binding.map(|text| Value::String(text.to_owned()));
    payload_digest(
        payload_json,
        [&values[0], &values[1], &values[2], &values[3], &values[4]],
    )
}

/// `sha256(grant_id.strip())` hex, or `None` for a blank grant.
pub(crate) fn oauth_subject_hash(grant_id: &str) -> Option<String> {
    let normalized = py_strip(grant_id);
    if normalized.is_empty() {
        return None;
    }
    Some(hex::encode(Sha256::digest(normalized.as_bytes())))
}

/// `gcr_<uuid5(namespace, local_request_id)>`; blank ids are rejected.
pub(crate) fn correlation_id(local_request_id: &str) -> Option<String> {
    if py_strip(local_request_id).is_empty() {
        return None;
    }
    let mut hasher = Sha1::new();
    hasher.update(CORRELATION_NAMESPACE);
    hasher.update(local_request_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hexed = hex::encode(bytes);
    Some(format!(
        "gcr_{}-{}-{}-{}-{}",
        &hexed[0..8],
        &hexed[8..12],
        &hexed[12..16],
        &hexed[16..20],
        &hexed[20..32]
    ))
}

fn correlation_shaped(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("gcr_") else {
        return false;
    };
    let groups: Vec<&str> = rest.split('-').collect();
    let widths = [8, 4, 4, 4, 12];
    groups.len() == widths.len()
        && groups.iter().zip(widths).all(|(group, width)| {
            group.len() == width
                && group
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn stripped(value: Option<&Value>) -> Option<&str> {
    let text = py_strip(value?.as_str()?);
    (!text.is_empty()).then_some(text)
}

fn optional_text(value: Option<&Value>) -> Result<Option<&str>, ()> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if !py_strip(text).is_empty() => Ok(Some(text)),
        Some(_) => Err(()),
    }
}

/// Canonical frozen continuation snapshot, or `None` for any ambiguous or
/// unsafe shape.
pub(crate) fn validated_continuation_snapshot(value: &Value) -> Option<Map<String, Value>> {
    let object = value.as_object()?;
    const KEYS: [&str; 5] = [
        "capability",
        "correlationId",
        "hookAttached",
        "opaqueTargetId",
        "waitDeadline",
    ];
    if object.len() != KEYS.len() || KEYS.iter().any(|key| !object.contains_key(*key)) {
        return None;
    }
    let correlation = stripped(object.get("correlationId"))?;
    if !correlation_shaped(correlation) {
        return None;
    }
    let capability = stripped(object.get("capability"))?;
    if ![
        "retry-only",
        "session-resume",
        "suspended-response",
        "unsupported",
    ]
    .contains(&capability)
    {
        return None;
    }
    let hook_attached = object.get("hookAttached")?.as_bool()?;
    let target = optional_text(object.get("opaqueTargetId")).ok()?;
    let deadline = optional_text(object.get("waitDeadline")).ok()?;
    if capability == "suspended-response" {
        if !hook_attached || deadline.is_none() || target.is_some() {
            return None;
        }
    } else if hook_attached || deadline.is_some() {
        return None;
    }
    if capability == "session-resume" {
        target?;
    } else if target.is_some() {
        return None;
    }
    let mut out = Map::new();
    out.insert(
        "correlationId".into(),
        Value::String(correlation.to_owned()),
    );
    out.insert("capability".into(), Value::String(capability.to_owned()));
    out.insert("hookAttached".into(), Value::Bool(hook_attached));
    out.insert(
        "opaqueTargetId".into(),
        target.map_or(Value::Null, |t| Value::String(t.to_owned())),
    );
    out.insert(
        "waitDeadline".into(),
        deadline.map_or(Value::Null, |t| Value::String(t.to_owned())),
    );
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlation_id_is_uuid5_shaped() {
        let id = correlation_id("req-1").unwrap();
        assert!(correlation_shaped(&id));
        assert!(correlation_id("  ").is_none());
    }

    #[test]
    fn subject_hash_blank_is_none() {
        assert!(oauth_subject_hash(" ").is_none());
        assert_eq!(oauth_subject_hash("a").unwrap().len(), 64);
    }
}
