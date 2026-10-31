//! `health-snapshot-binding --stdin`: decide whether a machine health snapshot
//! carried by a lease outbox is canonical, well formed and bound to its lease.
//!
//! The Python lease contract decodes the outbox and checks the lease; this
//! command owns the strict snapshot shape (`mdm/health_snapshot_validation.py`
//! before it moved here). Any refusal is the one answer `valid: false`; only a
//! malformed request fails the command.

use std::io::Read;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[path = "health_snapshot_vocabulary.rs"]
mod vocabulary;

use vocabulary::{
    ASSURANCE_LEVELS, INSTALL_OWNERS, INTEGRITY_REASON_CODES, INTEGRITY_STATES,
    KEY_PROTECTION_LEVELS, REMEDIATION_CLASSES, SUPERVISOR_STATES,
};

const SCHEMA: &str = "health-snapshot-binding.v1";
const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;
// Base64 of the largest snapshot plus the claims, with room to spare.
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_REASON_CODES: usize = 64;
const MAX_TIMESTAMP_BYTES: usize = 64;
// Python refuses to read a longer integer literal (`sys.int_info.default_max_str_digits`).
const MAX_PYTHON_INT_DIGITS: usize = 4300;

const SNAPSHOT_KEYS: [&str; 15] = [
    "schemaVersion",
    "generatedAt",
    "scope",
    "healthy",
    "assuranceLevel",
    "installOwner",
    "platform",
    "architecture",
    "identifiers",
    "product",
    "components",
    "harnessCoverage",
    "continuity",
    "reasonCodes",
    "remediationClass",
];
const IDENTIFIER_KEYS: [&str; 4] = [
    "workspaceId",
    "deviceId",
    "machineInstallationId",
    "installationGeneration",
];
const PRODUCT_KEYS: [&str; 6] = [
    "version",
    "buildId",
    "sourceCommit",
    "packageIdentity",
    "manifestHash",
    "policyHash",
];
const COMPONENT_KEYS: [&str; 12] = [
    "manifest",
    "nativePackage",
    "managedPolicy",
    "ownershipAndAcl",
    "supervisor",
    "deviceKey",
    "harnessCoverage",
    "installationIdentity",
    "leaseContinuity",
    "daemon",
    "commandShadowing",
    "update",
];
const HARNESS_KEYS: [&str; 4] = ["required", "protected", "degraded", "missing"];
const CONTINUITY_KEYS: [&str; 4] = [
    "monotonicUptimeSeconds",
    "sequence",
    "previousLeaseDigest",
    "bootSessionId",
];
const BASIC_COMPONENT_KEYS: [&str; 3] = ["state", "healthy", "reasonCode"];
const DEVICE_KEY_COMPONENT_KEYS: [&str; 4] = ["state", "healthy", "reasonCode", "level"];

/// The lease claims a snapshot has to agree with.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Claims {
    pub(crate) workspace_id: String,
    pub(crate) device_id: String,
    pub(crate) machine_installation_id: String,
    pub(crate) installation_generation: String,
    pub(crate) sequence: u64,
    pub(crate) snapshot_schema_version: String,
    pub(crate) previous_lease_digest: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    snapshot: String,
    claims: Claims,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "health-snapshot-binding"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "health_snapshot_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("health_snapshot_request_too_large".to_owned());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| "health_snapshot_request_invalid".to_owned())?;
    if request.schema != SCHEMA {
        return Err("health_snapshot_request_invalid".to_owned());
    }
    let snapshot = STANDARD
        .decode(request.snapshot.as_bytes())
        .map_err(|_| "health_snapshot_request_invalid".to_owned())?;
    let valid = snapshot_is_bound(&snapshot, &request.claims);
    serde_json::to_vec(&json!({"ok": true, "valid": valid}))
        .map_err(|_| "health_snapshot_response_encode_failed".to_owned())
}

/// Whether `snapshot` is the canonical, well-formed snapshot `claims` sign for.
pub(crate) fn snapshot_is_bound(snapshot: &[u8], claims: &Claims) -> bool {
    let Some(raw) = strict_object(snapshot) else {
        return false;
    };
    let field = |key: &str| raw.get(key).unwrap_or(&Value::Null);
    let (Some(identifiers), Some(product), Some(components), Some(harness), Some(continuity)) = (
        exact_object(field("identifiers"), &IDENTIFIER_KEYS),
        exact_object(field("product"), &PRODUCT_KEYS),
        exact_object(field("components"), &COMPONENT_KEYS),
        exact_object(field("harnessCoverage"), &HARNESS_KEYS),
        exact_object(field("continuity"), &CONTINUITY_KEYS),
    ) else {
        return false;
    };
    has_exact_keys(&raw, &SNAPSHOT_KEYS)
        && field("schemaVersion").as_str() == Some(claims.snapshot_schema_version.as_str())
        && components
            .iter()
            .all(|(name, component)| component_is_valid(name, component))
        && field("generatedAt")
            .as_str()
            .is_some_and(timestamp_is_valid)
        && field("scope").as_str() == Some("machine")
        && field("healthy").is_boolean()
        && one_of(field("assuranceLevel"), &ASSURANCE_LEVELS)
        && one_of(field("installOwner"), &INSTALL_OWNERS)
        && one_of(field("remediationClass"), &REMEDIATION_CLASSES)
        && reason_codes_are_valid(field("reasonCodes"))
        && bounded_string(field("platform"), 64, false)
        && bounded_string(field("architecture"), 64, false)
        && product_is_valid(product)
        && harness
            .values()
            .all(|value| value.is_null() || uint64(value).is_some())
        && continuity_is_valid(continuity)
        && identifiers_match(identifiers, claims)
        && continuity_matches(continuity, claims)
}

/// The snapshot as an object, when its bytes are exactly the canonical JSON
/// the lease contract writes.
fn strict_object(snapshot: &[u8]) -> Option<Map<String, Value>> {
    if snapshot.is_empty() || snapshot.len() > MAX_SNAPSHOT_BYTES {
        return None;
    }
    let raw: Value = serde_json::from_slice(snapshot).ok()?;
    let mut canonical = Vec::with_capacity(snapshot.len());
    guard_contracts::write_canonical_json(&raw, &mut canonical).ok()?;
    if canonical != snapshot {
        return None;
    }
    match raw {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

fn has_exact_keys(map: &Map<String, Value>, expected: &[&str]) -> bool {
    map.len() == expected.len() && expected.iter().all(|key| map.contains_key(*key))
}

fn exact_object<'a>(value: &'a Value, expected: &[&str]) -> Option<&'a Map<String, Value>> {
    value
        .as_object()
        .filter(|map| has_exact_keys(map, expected))
}

fn one_of(value: &Value, allowed: &[&str]) -> bool {
    value.as_str().is_some_and(|text| allowed.contains(&text))
}

fn component_is_valid(name: &str, component: &Value) -> bool {
    let device_key = name == "deviceKey";
    let expected: &[&str] = if device_key {
        &DEVICE_KEY_COMPONENT_KEYS
    } else {
        &BASIC_COMPONENT_KEYS
    };
    let states: &[&str] = if name == "supervisor" {
        &SUPERVISOR_STATES
    } else {
        &INTEGRITY_STATES
    };
    let Some(component) = exact_object(component, expected) else {
        return false;
    };
    let field = |key: &str| component.get(key).unwrap_or(&Value::Null);
    one_of(field("state"), states)
        && field("healthy").is_boolean()
        && one_of(field("reasonCode"), &INTEGRITY_REASON_CODES)
        && (!device_key || one_of(field("level"), &KEY_PROTECTION_LEVELS))
}

/// Known reason codes, at most 64, sorted and without repeats.
fn reason_codes_are_valid(value: &Value) -> bool {
    let Some(items) = value.as_array() else {
        return false;
    };
    items.len() <= MAX_REASON_CODES
        && items
            .iter()
            .all(|item| one_of(item, &INTEGRITY_REASON_CODES))
        && items
            .windows(2)
            .all(|pair| pair[0].as_str() < pair[1].as_str())
}

/// A non-empty string of at most `maximum` UTF-8 bytes, or null when allowed.
fn bounded_string(value: &Value, maximum: usize, nullable: bool) -> bool {
    match value {
        Value::Null => nullable,
        Value::String(text) => !text.is_empty() && text.len() <= maximum,
        _ => false,
    }
}

fn optional_hex64(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }
        _ => false,
    }
}

/// An integer in `0..=u64::MAX`, spelled as JSON spells an integer.
fn uint64(value: &Value) -> Option<u64> {
    let Value::Number(number) = value else {
        return None;
    };
    let raw = number.as_str();
    if raw.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
        return None;
    }
    raw.parse().ok()
}

fn product_is_valid(product: &Map<String, Value>) -> bool {
    let field = |key: &str| product.get(key).unwrap_or(&Value::Null);
    bounded_string(field("version"), 128, false)
        && bounded_string(field("buildId"), 256, true)
        && bounded_string(field("sourceCommit"), 256, true)
        && bounded_string(field("packageIdentity"), 256, false)
        && optional_hex64(field("manifestHash"))
        && optional_hex64(field("policyHash"))
}

fn continuity_is_valid(continuity: &Map<String, Value>) -> bool {
    let field = |key: &str| continuity.get(key).unwrap_or(&Value::Null);
    let sequence = field("sequence");
    uptime_is_valid(field("monotonicUptimeSeconds"))
        && (sequence.is_null() || uint64(sequence).is_some())
        && optional_hex64(field("previousLeaseDigest"))
        && bounded_string(field("bootSessionId"), 256, true)
}

/// Null, a non-negative integer Python will read, or a finite non-negative
/// float (negative zero included, as Python's `< 0` lets it through).
fn uptime_is_valid(value: &Value) -> bool {
    let Value::Number(number) = value else {
        return value.is_null();
    };
    let raw = number.as_str();
    if !raw.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
        return !raw.starts_with('-') && raw.len() <= MAX_PYTHON_INT_DIGITS;
    }
    number
        .as_f64()
        .is_some_and(|seconds| seconds.is_finite() && seconds >= 0.0)
}

fn identifiers_match(identifiers: &Map<String, Value>, claims: &Claims) -> bool {
    [
        ("workspaceId", &claims.workspace_id),
        ("deviceId", &claims.device_id),
        ("machineInstallationId", &claims.machine_installation_id),
        ("installationGeneration", &claims.installation_generation),
    ]
    .into_iter()
    .all(|(key, expected)| identifiers.get(key).and_then(Value::as_str) == Some(expected.as_str()))
}

/// The snapshot names the lease before this one: one sequence back, and the
/// same previous digest (or none for the first lease).
fn continuity_matches(continuity: &Map<String, Value>, claims: &Claims) -> bool {
    let sequence = continuity.get("sequence").and_then(uint64);
    let previous = continuity
        .get("previousLeaseDigest")
        .unwrap_or(&Value::Null);
    let previous_matches = match &claims.previous_lease_digest {
        Some(expected) => previous.as_str() == Some(expected.as_str()),
        None => previous.is_null(),
    };
    claims
        .sequence
        .checked_sub(1)
        .is_some_and(|expected| sequence == Some(expected))
        && previous_matches
}

/// `YYYY-MM-DDTHH:MM:SS[.fraction]Z` naming a real UTC instant, as Python's
/// `datetime.fromisoformat` reads it: ASCII digits, any fraction length, and
/// no leap second or hour 24.
fn timestamp_is_valid(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes.len() > MAX_TIMESTAMP_BYTES || bytes.last() != Some(&b'Z') {
        return false;
    }
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if separators
        .iter()
        .any(|(index, byte)| bytes[*index] != *byte)
    {
        return false;
    }
    let fraction = &bytes[19..bytes.len() - 1];
    if !fraction.is_empty()
        && (fraction.len() < 2
            || fraction[0] != b'.'
            || !fraction[1..].iter().all(u8::is_ascii_digit))
    {
        return false;
    }
    let number = |start: usize, end: usize| -> Option<u32> {
        bytes[start..end].iter().try_fold(0_u32, |total, byte| {
            byte.is_ascii_digit()
                .then(|| total * 10 + u32::from(byte - b'0'))
        })
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    year >= 1
        && (1..=12).contains(&month)
        && day >= 1
        && day <= days_in_month(year, month)
        && hour <= 23
        && minute <= 59
        && second <= 59
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[cfg(test)]
#[path = "health_snapshot_binding_tests.rs"]
mod tests;
