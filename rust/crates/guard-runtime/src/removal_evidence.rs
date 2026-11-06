//! `removal-evidence --stdin`: write a managed-removal authorization, check
//! one Python read, or advance the tombstone that records a removal
//! (`mdm/removal.py` before it moved here).
//!
//! Python keeps the privileged context checks: the administrator context, the
//! trusted state root, the authorization file's owner and the active
//! installation binding. A refusal is `{"ok": false, "kind", "error"}`, where
//! `kind` names the Python exception to raise (`value` or `os`); only a
//! malformed request fails the command.

use std::io::{self, Read};
use std::path::PathBuf;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::policy_bundle_time::{from_isoformat, micros_to_utc_isoformat};

#[path = "removal_evidence_files.rs"]
mod files;
#[path = "removal_tombstone.rs"]
mod tombstone;

use files::{private_directory, sync_directory, write_new_private};
use tombstone::record_tombstone;

const SCHEMA: &str = "removal-evidence.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_AUTHORIZATION_BYTES: usize = 16 * 1024;
const MICROS_PER_SECOND: i64 = 1_000_000;
const AUTHORIZATION_LIFETIME_MICROS: i64 = 120 * MICROS_PER_SECOND;
const AUTHORIZATION_WINDOW_MICROS: i64 = 300 * MICROS_PER_SECOND;
const AUTHORIZATION_KEYS: [&str; 10] = [
    "actor",
    "expiresAt",
    "home",
    "installationGeneration",
    "issuedAt",
    "machineInstallationId",
    "nonce",
    "operation",
    "reason",
    "user",
];

/// The Python exception kind and the reason code it carries.
type Refusal = (&'static str, &'static str);
type Answer = Result<Map<String, Value>, Refusal>;

fn value_error(code: &'static str) -> Refusal {
    ("value", code)
}

fn os_error(code: &'static str) -> Refusal {
    ("os", code)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueRequest {
    root: PathBuf,
    name: Option<String>,
    home: String,
    user: String,
    actor: String,
    reason: String,
    machine_installation_id: String,
    installation_generation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckRequest {
    content: String,
    home: String,
    user: String,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "removal-evidence"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "removal_evidence_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("removal_evidence_request_too_large".to_owned());
    }
    let now = now_micros().ok_or_else(|| "removal_evidence_clock_unavailable".to_owned())?;
    let response = match answer(&bytes, now)? {
        Ok(mut fields) => {
            fields.insert("ok".to_owned(), Value::Bool(true));
            Value::Object(fields)
        }
        Err((kind, code)) => json!({"ok": false, "kind": kind, "error": code}),
    };
    serde_json::to_vec(&response).map_err(|_| "removal_evidence_response_encode_failed".to_owned())
}

fn answer(bytes: &[u8], now: i64) -> Result<Answer, String> {
    let Ok(Value::Object(mut request)) = serde_json::from_slice::<Value>(bytes) else {
        return Err(request_invalid());
    };
    if request.remove("schema").as_ref().and_then(Value::as_str) != Some(SCHEMA) {
        return Err(request_invalid());
    }
    let operation = request.remove("op");
    let fields = Value::Object(request);
    Ok(match operation.as_ref().and_then(Value::as_str) {
        Some("issue") => issue(&fields_of(fields)?, now),
        Some("check") => check(&fields_of(fields)?, now),
        Some("tombstone") => record_tombstone(&fields_of(fields)?, now),
        _ => return Err(request_invalid()),
    })
}

fn fields_of<T: DeserializeOwned>(fields: Value) -> Result<T, String> {
    serde_json::from_value(fields).map_err(|_| request_invalid())
}

fn request_invalid() -> String {
    "removal_evidence_request_invalid".to_owned()
}

/// Write a fresh deactivation authorization under `root`.
fn issue(request: &IssueRequest, now: i64) -> Answer {
    validate_actor_reason(&request.actor, &request.reason)?;
    if !is_identifier(&request.machine_installation_id)
        || !is_identifier(&request.installation_generation)
    {
        return Err(value_error("mdm_removal_authorization_invalid"));
    }
    let write_failed = os_error("mdm_removal_authorization_write_failed");
    private_directory(&request.root).map_err(|_| write_failed)?;
    let name = match &request.name {
        Some(name) => name.clone(),
        None => format!("{}-{}.json", request.user, hex::encode(random_bytes(8))),
    };
    if !is_authorization_name(&name) {
        return Err(value_error("mdm_removal_authorization_name_invalid"));
    }
    let issued_at = isoformat(now)?;
    let expires_at = isoformat(now + AUTHORIZATION_LIFETIME_MICROS)?;
    let payload = json!({
        "actor": request.actor,
        "expiresAt": expires_at,
        "home": request.home,
        "installationGeneration": request.installation_generation,
        "issuedAt": issued_at,
        "machineInstallationId": request.machine_installation_id,
        "nonce": URL_SAFE_NO_PAD.encode(random_bytes(24)),
        "operation": "deactivate",
        "reason": request.reason,
        "user": request.user,
    });
    let bytes = python_json_line(&payload)?;
    let target = request.root.join(&name);
    let target_text = target.to_str().ok_or(write_failed)?.to_owned();
    write_new_private(&target, &bytes).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            os_error("mdm_removal_authorization_exists")
        } else {
            write_failed
        }
    })?;
    sync_directory(&request.root).map_err(|_| write_failed)?;
    Ok(fields([
        ("path", Value::String(target_text)),
        ("fingerprint", Value::String(sha256_hex(&bytes))),
        ("issued_at", Value::String(issued_at)),
        ("expires_at", Value::String(expires_at)),
    ]))
}

/// Check the bytes of an authorization Python read from a trusted file.
fn check(request: &CheckRequest, now: i64) -> Answer {
    let invalid = value_error("mdm_removal_authorization_invalid");
    let wrong_scope = value_error("mdm_removal_authorization_wrong_scope");
    let expired = value_error("mdm_removal_authorization_expired");
    let content = STANDARD
        .decode(request.content.as_bytes())
        .map_err(|_| invalid)?;
    if content.len() > MAX_AUTHORIZATION_BYTES {
        return Err(invalid);
    }
    let Ok(Value::Object(payload)) = serde_json::from_slice::<Value>(&content) else {
        return Err(invalid);
    };
    if !has_exact_keys(&payload, AUTHORIZATION_KEYS.iter().copied()) {
        return Err(invalid);
    }
    let text = |key: &str| payload.get(key).and_then(Value::as_str);
    if text("operation") != Some("deactivate") || text("user") != Some(request.user.as_str()) {
        return Err(wrong_scope);
    }
    if text("home") != Some(request.home.as_str()) {
        return Err(wrong_scope);
    }
    let required = |key: &str| text(key).filter(|value| !value.is_empty()).ok_or(invalid);
    let actor = required("actor")?;
    let reason = required("reason")?;
    let machine_installation_id = required("machineInstallationId")?;
    let installation_generation = required("installationGeneration")?;
    required("nonce")?;
    let issued_raw = required("issuedAt")?;
    let expires_raw = required("expiresAt")?;
    if !is_identifier(machine_installation_id) || !is_identifier(installation_generation) {
        return Err(invalid);
    }
    validate_actor_reason(actor, reason)?;
    let (Some(issued), Some(expires)) = (from_isoformat(issued_raw), from_isoformat(expires_raw))
    else {
        return Err(invalid);
    };
    if !issued.is_aware() || !expires.is_aware() {
        return Err(expired);
    }
    let (Some(issued), Some(expires)) = (issued.utc_micros(), expires.utc_micros()) else {
        return Err(expired);
    };
    if issued > now
        || expires <= now
        || expires - issued > AUTHORIZATION_WINDOW_MICROS
        || now - issued > AUTHORIZATION_WINDOW_MICROS
    {
        return Err(expired);
    }
    Ok(fields([
        ("fingerprint", Value::String(sha256_hex(&content))),
        ("actor", Value::String(actor.to_owned())),
        ("reason", Value::String(reason.to_owned())),
        (
            "machine_installation_id",
            Value::String(machine_installation_id.to_owned()),
        ),
        (
            "installation_generation",
            Value::String(installation_generation.to_owned()),
        ),
        ("issued_at", Value::String(issued_raw.to_owned())),
        ("expires_at", Value::String(expires_raw.to_owned())),
    ]))
}

fn has_exact_keys<'a>(object: &Map<String, Value>, keys: impl Iterator<Item = &'a str>) -> bool {
    let mut count = 0;
    for key in keys {
        if !object.contains_key(key) {
            return false;
        }
        count += 1;
    }
    object.len() == count
}

fn validate_actor_reason(actor: &str, reason: &str) -> Result<(), Refusal> {
    let mut characters = actor.chars();
    let actor_is_valid = actor.len() <= 128
        && characters
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
        && characters
            .all(|character| character.is_ascii_alphanumeric() || "@._:-".contains(character));
    if !actor_is_valid {
        return Err(value_error("mdm_removal_authorization_actor_invalid"));
    }
    let length = reason.chars().count();
    if !(1..=256).contains(&length) || reason.chars().any(|character| character < ' ') {
        return Err(value_error("mdm_removal_authorization_reason_invalid"));
    }
    Ok(())
}

fn is_identifier(text: &str) -> bool {
    text.len() == 32 && is_lower_hex(text)
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64 && is_lower_hex(text)
}

fn is_lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// `[A-Za-z0-9_.-]{1,128}\.json`.
fn is_authorization_name(name: &str) -> bool {
    name.strip_suffix(".json").is_some_and(|stem| {
        (1..=128).contains(&stem.len())
            && stem
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    })
}

fn fields<const N: usize>(entries: [(&str, Value); N]) -> Map<String, Value> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

/// `json.dump(value, stream, sort_keys=True)` followed by a newline.
fn python_json_line(value: &Value) -> Result<Vec<u8>, Refusal> {
    let mut bytes = Vec::new();
    guard_contracts::write_python_default_json(value, &mut bytes)
        .map_err(|_| value_error("mdm_removal_evidence_unencodable"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// `datetime.isoformat()` of a UTC instant, as Python's `_now()` spells it.
fn isoformat(micros: i64) -> Result<String, Refusal> {
    micros_to_utc_isoformat(micros, "+00:00")
        .ok_or_else(|| os_error("mdm_removal_clock_unavailable"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn random_bytes(count: usize) -> Vec<u8> {
    crate::encrypted_secret_store::random_bytes(count)
}

fn now_micros() -> Option<i64> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    i64::try_from(micros).ok()
}

#[cfg(test)]
#[path = "removal_evidence_tests.rs"]
mod tests;
