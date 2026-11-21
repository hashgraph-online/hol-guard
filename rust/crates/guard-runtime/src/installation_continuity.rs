//! `installation-continuity --stdin`: parse the protected installation
//! continuity record and decide what a verification of it reports
//! (`mdm/continuity.py` before it moved here).
//!
//! Python keeps the bounded, owner-checked read of the record and the
//! device-key lookup. It sends what it read and what each probe returned, or
//! the exception a probe raised as `{"kind", "error"}` with `kind` one of
//! `permission`, `value` or `os`. Only a malformed request fails the command.
//!
//! `observe-boot` answers this boot's session identifier and uptime
//! (`boot_observation`), or the `lease_continuity_*` code of the probe that
//! failed.

use std::io::Read;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::boot_observation;
use crate::policy_bundle_time::from_isoformat;

const SCHEMA: &str = "installation-continuity.v1";
const RECORD_SCHEMA: &str = "hol-guard-installation-continuity.v1";
const MAX_REQUEST_BYTES: u64 = 256 * 1024;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_BOUNDED_CHARS: usize = 256;
const MAX_TIMESTAMP_CHARS: usize = 64;
const KEY_MISMATCH_ERRORS: [&str; 3] = [
    "device_key_absent",
    "device_key_revoked",
    "device_key_public_mismatch",
];

/// One parsed continuity record, with the field names Python's dataclass uses.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    machine_installation_id: String,
    installation_generation: String,
    generation_created_at: String,
    key_id_at_generation_creation: String,
    last_issued_sequence: u64,
    last_lease_digest: Option<String>,
    last_lease_boot_session_id: Option<String>,
    last_lease_monotonic_uptime_ns: Option<u64>,
    updated_at: String,
    last_lease_key_id: Option<String>,
}

impl Record {
    fn to_value(&self) -> Value {
        json!({
            "machine_installation_id": self.machine_installation_id,
            "installation_generation": self.installation_generation,
            "generation_created_at": self.generation_created_at,
            "key_id_at_generation_creation": self.key_id_at_generation_creation,
            "last_issued_sequence": self.last_issued_sequence,
            "last_lease_digest": self.last_lease_digest,
            "last_lease_boot_session_id": self.last_lease_boot_session_id,
            "last_lease_monotonic_uptime_ns": self.last_lease_monotonic_uptime_ns,
            "updated_at": self.updated_at,
            "last_lease_key_id": self.last_lease_key_id,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParseRequest {
    content: String,
}

/// What a probe returned, or the exception it raised.
#[derive(Deserialize)]
#[serde(untagged)]
enum Probe<T> {
    Value(T),
    Raised { kind: String, error: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyIds {
    ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    boot_session_id: String,
    monotonic_uptime_ns: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyRequest {
    content: String,
    key: Probe<KeyIds>,
    boot: Probe<Observation>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "installation-continuity"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "installation_continuity_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("installation_continuity_request_too_large".to_owned());
    }
    let response = answer(&bytes)?;
    serde_json::to_vec(&response)
        .map_err(|_| "installation_continuity_response_encode_failed".to_owned())
}

fn answer(bytes: &[u8]) -> Result<Value, String> {
    let Ok(Value::Object(mut request)) = serde_json::from_slice::<Value>(bytes) else {
        return Err(request_invalid());
    };
    if request.remove("schema").as_ref().and_then(Value::as_str) != Some(SCHEMA) {
        return Err(request_invalid());
    }
    let operation = request.remove("op");
    let fields = Value::Object(request);
    match operation.as_ref().and_then(Value::as_str) {
        Some("parse") => {
            let request: ParseRequest =
                serde_json::from_value(fields).map_err(|_| request_invalid())?;
            Ok(match parse_record(&decode(&request.content)?) {
                Some(record) => json!({"ok": true, "record": record.to_value()}),
                None => json!({"ok": false, "error": "installation_identity_invalid"}),
            })
        }
        Some("verify") => {
            let request: VerifyRequest =
                serde_json::from_value(fields).map_err(|_| request_invalid())?;
            let content = decode(&request.content)?;
            Ok(verify(&content, &request.key, &request.boot).to_value())
        }
        Some("observe-boot") if fields.as_object().is_some_and(Map::is_empty) => {
            Ok(match boot_observation::observe() {
                Ok(observation) => json!({"ok": true, "boot": observation.to_value()}),
                Err(code) => json!({"ok": false, "error": code}),
            })
        }
        _ => Err(request_invalid()),
    }
}

fn decode(content: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(content).map_err(|_| request_invalid())
}

fn request_invalid() -> String {
    "installation_continuity_request_invalid".to_owned()
}

/// The verification Python turns into a `ContinuityVerification`.
#[derive(Debug, PartialEq, Eq)]
struct Verification {
    state: &'static str,
    identity_reason_code: &'static str,
    lease_reason_code: String,
    record: Option<Record>,
    observed: bool,
}

impl Verification {
    fn without_record(state: &'static str, identity: &'static str, lease: &str) -> Self {
        Self {
            state,
            identity_reason_code: identity,
            lease_reason_code: lease.to_owned(),
            record: None,
            observed: false,
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "ok": true,
            "state": self.state,
            "identity_reason_code": self.identity_reason_code,
            "lease_reason_code": self.lease_reason_code,
            "record": self.record.as_ref().map(Record::to_value),
            "observed": self.observed,
        })
    }
}

fn tampered_invalid() -> Verification {
    Verification::without_record(
        "tampered",
        "installation_identity_invalid",
        "lease_continuity_invalid",
    )
}

fn key_mismatch() -> Verification {
    Verification::without_record(
        "tampered",
        "installation_identity_key_mismatch",
        "lease_continuity_invalid",
    )
}

/// `verify_installation_continuity` once Python has read the record and run
/// both probes. Each refusal matches the `except` clause that caught it there.
fn verify(content: &[u8], key: &Probe<KeyIds>, boot: &Probe<Observation>) -> Verification {
    let Some(record) = parse_record(content) else {
        return tampered_invalid();
    };
    match key {
        Probe::Value(key) if key.ids.contains(&record.key_id_at_generation_creation) => {}
        Probe::Value(_) => return key_mismatch(),
        Probe::Raised { kind, .. } if kind == "permission" => {
            return Verification::without_record(
                "tampered",
                "installation_identity_acl_invalid",
                "lease_continuity_invalid",
            );
        }
        Probe::Raised { kind, error } if kind == "os" => {
            if KEY_MISMATCH_ERRORS.contains(&error.as_str()) {
                return key_mismatch();
            }
            return Verification::without_record(
                "unknown",
                "installation_identity_probe_failed",
                "lease_continuity_probe_failed",
            );
        }
        Probe::Raised { .. } => return tampered_invalid(),
    }
    let observation = match boot {
        Probe::Value(observation) => observation,
        // A `PermissionError` is an `OSError`; only a `ValueError` escapes the
        // probe's own handler.
        Probe::Raised { kind, .. } if kind == "value" => return tampered_invalid(),
        Probe::Raised { error, .. } => {
            let (state, lease) = if error == "lease_continuity_platform_unsupported" {
                ("unsupported", error.as_str())
            } else if error.starts_with("lease_continuity_") {
                ("unknown", error.as_str())
            } else {
                ("unknown", "lease_continuity_probe_failed")
            };
            return Verification {
                state,
                identity_reason_code: "installation_identity_active",
                lease_reason_code: lease.to_owned(),
                record: Some(record),
                observed: false,
            };
        }
    };
    let regressed = record.last_lease_boot_session_id.as_deref()
        == Some(observation.boot_session_id.as_str())
        && record
            .last_lease_monotonic_uptime_ns
            .is_some_and(|uptime| observation.monotonic_uptime_ns < uptime);
    let (state, lease) = if regressed {
        ("tampered", "lease_continuity_monotonic_regression")
    } else if record.last_issued_sequence == u64::MAX {
        ("degraded", "lease_continuity_sequence_exhausted")
    } else if record.last_issued_sequence == 0 {
        ("healthy", "lease_continuity_uninitialized")
    } else {
        ("healthy", "lease_continuity_active")
    };
    Verification {
        state,
        identity_reason_code: "installation_identity_active",
        lease_reason_code: lease.to_owned(),
        record: Some(record),
        observed: true,
    }
}

/// `_parse_record`: `None` wherever Python raised `installation_identity_invalid`.
fn parse_record(payload: &[u8]) -> Option<Record> {
    if payload.len() > MAX_RECORD_BYTES {
        return None;
    }
    let Ok(Value::Object(raw)) = serde_json::from_slice::<Value>(payload) else {
        return None;
    };
    if raw.get("schemaVersion").and_then(Value::as_str) != Some(RECORD_SCHEMA) {
        return None;
    }
    let sequence = raw.get("lastIssuedSequence").and_then(Value::as_u64)?;
    let digest = optional_bounded(&raw, "lastLeaseDigest", Some(64))?;
    let boot_id = optional_bounded(&raw, "lastLeaseBootSessionId", None)?;
    let uptime = match present(&raw, "lastLeaseMonotonicUptimeNs") {
        None => None,
        Some(value) => Some(value.as_u64()?),
    };
    let lease_key_id = optional_bounded(&raw, "lastLeaseKeyId", None)?;
    let lease_fields = [
        digest.is_some(),
        boot_id.is_some(),
        uptime.is_some(),
        lease_key_id.is_some(),
    ];
    // An uninitialized record carries no lease; an issued one carries all of it.
    let issued = sequence > 0;
    if lease_fields.contains(&!issued) {
        return None;
    }
    let key_id = raw
        .get("keyIdAtGenerationCreation")
        .and_then(Value::as_str)
        .filter(|value| is_bounded(value))?;
    Some(Record {
        machine_installation_id: hex(raw.get("machineInstallationId"), 32)?,
        installation_generation: hex(raw.get("installationGeneration"), 32)?,
        generation_created_at: timestamp(raw.get("generationCreatedAt"))?,
        key_id_at_generation_creation: key_id.to_owned(),
        last_issued_sequence: sequence,
        last_lease_digest: digest,
        last_lease_boot_session_id: boot_id,
        last_lease_monotonic_uptime_ns: uptime,
        updated_at: timestamp(raw.get("updatedAt"))?,
        last_lease_key_id: lease_key_id,
    })
}

/// A key's value, with JSON `null` read as absent the way `dict.get` does.
fn present<'a>(raw: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    raw.get(key).filter(|value| !value.is_null())
}

fn is_bounded(value: &str) -> bool {
    !value.is_empty() && value.chars().count() <= MAX_BOUNDED_CHARS
}

/// `_optional_bounded_string`: the outer `None` is a refusal, the inner one
/// an absent value.
fn optional_bounded(
    raw: &Map<String, Value>,
    key: &str,
    hex_length: Option<usize>,
) -> Option<Option<String>> {
    let Some(value) = present(raw, key) else {
        return Some(None);
    };
    let text = value.as_str().filter(|text| is_bounded(text))?;
    match hex_length {
        Some(length) => hex(Some(value), length).map(Some),
        None => Some(Some(text.to_owned())),
    }
}

fn hex(value: Option<&Value>, length: usize) -> Option<String> {
    let text = value?.as_str()?;
    let lower_hex = text
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    (text.len() == length && lower_hex).then(|| text.to_owned())
}

fn timestamp(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?;
    if text.chars().count() > MAX_TIMESTAMP_CHARS || !from_isoformat(text)?.is_aware() {
        return None;
    }
    Some(text.to_owned())
}

#[cfg(test)]
#[path = "installation_continuity_tests.rs"]
mod tests;
