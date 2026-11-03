//! `network-status-validation --stdin`: strict validation of the daemon's
//! `guard.network-status.v1` payload before `hol-guard network status`
//! presents it as protection truth, answering its privacy-safe projection.
//!
//! The request is `{schema, status, now_epoch_ms}`. The answer is
//! `{"status": projection}` with the projection's keys in presentation order,
//! or `{"error": message}` naming the first check the payload failed.
//! Nothing here reads the host: `now_epoch_ms` is the caller's clock.

use std::io::Read;

use serde::Deserialize;
use serde_json::{json, Map, Number, Value};

const SCHEMA: &str = "network-status-validation.v1";
const STATUS_SCHEMA: &str = "guard.network-status.v1";
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_IDENTIFIER_CHARS: usize = 128;

const PLATFORMS: [&str; 4] = ["linux", "macos", "windows", "kubernetes"];
/// Enforcement grades, weakest first; the index is the grade's rank.
const GRADES: [&str; 7] = [
    "unavailable",
    "observe",
    "deny-all",
    "proxy-only",
    "tcp-ip-destination-enforced",
    "udp-dns-destination-enforced",
    "destination-enforced",
];
const RECOVERY_PHASES: [&str; 4] = ["healthy", "degraded", "recovering", "unavailable"];
const NETWORK_ACTIONS: [&str; 3] = ["deny", "approve", "allow"];

const HEADER_FIELDS: [&str; 7] = [
    "schema",
    "host_platform",
    "effective_grade",
    "independently_observed_grade",
    "protection_active",
    "independently_observed",
    "reason_code",
];
const BACKEND_FLAGS: [&str; 7] = [
    "supported",
    "installed",
    "verified",
    "active",
    "observed",
    "production_ready",
    "requires_privilege",
];
const BACKEND_FIELDS: [&str; 13] = [
    "backend_id",
    "platform",
    "supported",
    "installed",
    "verified",
    "active",
    "observed",
    "advertised_maximum_grade",
    "effective_grade",
    "production_ready",
    "requires_privilege",
    "reason_code",
    "reference_reason_code",
];
const SUPERVISOR_FIELDS: [&str; 9] = [
    "phase",
    "backend_id",
    "backend_digest",
    "effective_grade",
    "healthy_until_epoch_ms",
    "retry_attempt",
    "next_retry_seconds",
    "permits_enforcement",
    "independently_observed",
];

type Checked<T> = Result<T, &'static str>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    status: Value,
    now_epoch_ms: u64,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "network-status-validation"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "network_status_validation_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("network_status_validation_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "network_status_validation_request_invalid".to_owned())?;
    if request.schema != SCHEMA {
        return Err("network_status_validation_request_invalid".to_owned());
    }
    let answer = match validate(&request.status, request.now_epoch_ms) {
        Ok(projection) => format!("{{\"status\":{projection}}}"),
        Err(message) => json!({ "error": message }).to_string(),
    };
    Ok(answer.into_bytes())
}

/// The ordered projection of a valid payload, as JSON text.
fn validate(payload: &Value, now_epoch_ms: u64) -> Checked<String> {
    let payload = payload
        .as_object()
        .filter(|object| object.get("schema").and_then(Value::as_str) == Some(STATUS_SCHEMA))
        .ok_or("network status schema is invalid")?;
    let host_platform = payload.get("host_platform");
    if host_platform.and_then(Value::as_str) != Some("unsupported") {
        require_enum(host_platform, &PLATFORMS)?;
    }
    let effective_grade = require_grade(payload.get("effective_grade"))?;
    let observed_grade = require_grade(payload.get("independently_observed_grade"))?;
    let protection_active =
        exact_bool(payload.get("protection_active")).ok_or("network status boolean is invalid")?;
    let independently_observed = exact_bool(payload.get("independently_observed"))
        .ok_or("network status boolean is invalid")?;
    if !is_safe_identifier(payload.get("reason_code")) {
        return Err("network status reason is invalid");
    }

    let backends = validate_backends(payload.get("backends"), host_platform)?;
    let active: Vec<&Backend> = backends.iter().filter(|backend| backend.active).collect();
    if protection_active == active.is_empty() {
        return Err("network protection summary is inconsistent");
    }
    if protection_active && active.len() != 1 {
        return Err("network protection requires one active backend");
    }
    if !protection_active && effective_grade != 0 {
        return Err("inactive network protection must be unavailable");
    }
    if protection_active
        && active
            .iter()
            .all(|backend| backend.grade != effective_grade)
    {
        return Err("network protection grade is inconsistent");
    }
    if independently_observed != (observed_grade != 0) {
        return Err("network observer summary is inconsistent");
    }
    let observed: Vec<usize> = backends
        .iter()
        .filter(|backend| backend.observed)
        .map(|backend| backend.grade)
        .collect();
    if observed.is_empty() == independently_observed {
        return Err("network backend observer summary is inconsistent");
    }
    if independently_observed {
        if observed.contains(&0) {
            return Err("observed network backend grade is invalid");
        }
        if observed.iter().max() != Some(&observed_grade) {
            return Err("network observer grade is inconsistent");
        }
    }

    let supervisor = match payload.get("supervisor") {
        None | Some(Value::Null) if protection_active => {
            return Err("active network protection requires supervisor proof");
        }
        None | Some(Value::Null) => None,
        Some(supervisor) => Some(validate_supervisor(
            supervisor,
            &Summary {
                now_epoch_ms,
                protection_active,
                independently_observed,
                effective_grade,
                active_ids: active.iter().map(|backend| backend.id).collect(),
            },
        )?),
    };
    let legacy = match payload.get("legacy_domain_policy") {
        None | Some(Value::Null) => None,
        Some(policy) => Some(legacy_policy(policy)?),
    };

    let mut fields = ordered_fields(payload, &HEADER_FIELDS);
    let projected: Vec<String> = backends
        .iter()
        .map(|backend| ordered(&ordered_fields(backend.fields, &BACKEND_FIELDS)))
        .collect();
    fields.push(("backends", format!("[{}]", projected.join(","))));
    if let Some(supervisor) = supervisor {
        fields.push((
            "supervisor",
            ordered(&ordered_fields(supervisor, &SUPERVISOR_FIELDS)),
        ));
    }
    if let Some(legacy) = legacy {
        fields.push(("legacy_domain_policy", legacy));
    }
    Ok(ordered(&fields))
}

struct Backend<'a> {
    fields: &'a Map<String, Value>,
    id: &'a str,
    active: bool,
    observed: bool,
    grade: usize,
}

fn validate_backends<'a>(
    raw: Option<&'a Value>,
    host_platform: Option<&Value>,
) -> Checked<Vec<Backend<'a>>> {
    let raw = raw
        .and_then(Value::as_array)
        .ok_or("network status backends are invalid")?;
    let mut backends: Vec<Backend<'a>> = Vec::with_capacity(raw.len());
    for candidate in raw {
        let backend = validate_backend(candidate, host_platform, &backends)?;
        backends.push(backend);
    }
    Ok(backends)
}

fn validate_backend<'a>(
    raw: &'a Value,
    host_platform: Option<&Value>,
    seen: &[Backend<'_>],
) -> Checked<Backend<'a>> {
    let fields = raw.as_object().ok_or("network status backend is invalid")?;
    let id = fields
        .get("backend_id")
        .filter(|value| is_safe_identifier(Some(value)))
        .and_then(Value::as_str)
        .ok_or("network status backend id is invalid")?;
    if seen.iter().any(|backend| backend.id == id) {
        return Err("network status backend id is duplicated");
    }
    require_enum(fields.get("platform"), &PLATFORMS)?;
    let advertised = require_grade(fields.get("advertised_maximum_grade"))?;
    let grade = require_grade(fields.get("effective_grade"))?;
    let mut flags = [false; BACKEND_FLAGS.len()];
    for (flag, name) in flags.iter_mut().zip(BACKEND_FLAGS) {
        *flag = exact_bool(fields.get(name)).ok_or("network status backend boolean is invalid")?;
    }
    let [supported, installed, verified, active, observed, production_ready, _] = flags;
    if !is_safe_identifier(fields.get("reason_code"))
        || !is_safe_identifier(fields.get("reference_reason_code"))
    {
        return Err("network status backend reason is invalid");
    }
    if verified && !installed {
        return Err("verified network backend must be installed");
    }
    if grade > advertised {
        return Err("network backend exceeds its advertised grade");
    }
    if active {
        if !supported || !verified {
            return Err("active network backend must be verified");
        }
        if !production_ready {
            return Err("active network backend must be production ready");
        }
        if fields.get("platform") != host_platform {
            return Err("active network backend must match the host");
        }
        if !enforces(grade) {
            return Err("active network backend must enforce");
        }
    } else if enforces(grade) {
        return Err("inactive network backend cannot enforce");
    }
    Ok(Backend {
        fields,
        id,
        active,
        observed,
        grade,
    })
}

struct Summary<'a> {
    now_epoch_ms: u64,
    protection_active: bool,
    independently_observed: bool,
    effective_grade: usize,
    active_ids: Vec<&'a str>,
}

fn validate_supervisor<'a>(raw: &'a Value, summary: &Summary) -> Checked<&'a Map<String, Value>> {
    let supervisor = raw.as_object().ok_or("network supervisor is invalid")?;
    if !SUPERVISOR_FIELDS
        .iter()
        .all(|field| supervisor.contains_key(*field))
    {
        return Err("network supervisor is incomplete");
    }
    let phase = require_enum(supervisor.get("phase"), &RECOVERY_PHASES)?;
    let grade = require_grade(supervisor.get("effective_grade"))?;

    let backend_id = supervisor.get("backend_id").unwrap_or(&Value::Null);
    let digest = supervisor.get("backend_digest").unwrap_or(&Value::Null);
    if !(backend_id.is_null() || backend_id.is_string())
        || !(digest.is_null() || digest.is_string())
    {
        return Err("network supervisor identity is invalid");
    }
    if !backend_id.is_null() && !is_safe_identifier(Some(backend_id)) {
        return Err("network supervisor backend id is invalid");
    }
    if !digest.as_str().is_none_or(is_digest) {
        return Err("network supervisor digest is invalid");
    }
    let healthy_until = match supervisor.get("healthy_until_epoch_ms") {
        None | Some(Value::Null) => None,
        Some(Value::Number(number)) => {
            Some(non_negative_integer(number).ok_or("network supervisor expiry is invalid")?)
        }
        Some(_) => return Err("network supervisor expiry is invalid"),
    };

    match supervisor.get("retry_attempt") {
        Some(Value::Number(number)) if non_negative_integer(number).is_some() => {}
        _ => return Err("network supervisor retry is invalid"),
    }
    match supervisor.get("next_retry_seconds") {
        Some(Value::Number(number))
            if number
                .as_f64()
                .is_some_and(|delay| delay.is_finite() && delay >= 0.0) => {}
        _ => return Err("network supervisor delay is invalid"),
    }
    let permits = exact_bool(supervisor.get("permits_enforcement"))
        .ok_or("network supervisor boolean is invalid")?;
    let observed = exact_bool(supervisor.get("independently_observed"))
        .ok_or("network supervisor boolean is invalid")?;

    let expected_permits = phase == "healthy" && enforces(grade);
    if permits != expected_permits {
        return Err("network supervisor enforcement is inconsistent");
    }
    if permits != summary.protection_active {
        return Err("network supervisor protection summary is inconsistent");
    }
    if observed != summary.independently_observed {
        return Err("network supervisor observer summary is inconsistent");
    }
    if summary.protection_active
        && (!expected_permits
            || grade != summary.effective_grade
            || digest.is_null()
            || healthy_until.is_none_or(|until| until <= u128::from(summary.now_epoch_ms))
            || !backend_id
                .as_str()
                .is_some_and(|id| summary.active_ids.contains(&id)))
    {
        return Err("network supervisor does not prove protection");
    }
    Ok(supervisor)
}

fn legacy_policy(raw: &Value) -> Checked<String> {
    let policy = raw
        .as_object()
        .ok_or("legacy network domain policy is invalid")?;
    let action = match policy.get("action") {
        Some(Value::String(action)) if NETWORK_ACTIONS.contains(&action.as_str()) => action,
        Some(Value::String(_)) => return Err("legacy network domain action is invalid"),
        _ => return Err("legacy network domain policy is invalid"),
    };
    let sandbox_required = exact_bool(policy.get("sandbox_required"))
        .ok_or("legacy network domain policy is invalid")?;
    Ok(ordered(&[
        ("action", Value::String(action.clone()).to_string()),
        (
            "sandbox_required",
            Value::Bool(sandbox_required).to_string(),
        ),
    ]))
}

fn require_enum<'a>(value: Option<&'a Value>, members: &[&str]) -> Checked<&'a str> {
    let text = value
        .and_then(Value::as_str)
        .ok_or("network status enum must be a string")?;
    if members.contains(&text) {
        Ok(text)
    } else {
        Err("network status enum is invalid")
    }
}

/// The grade's rank.
fn require_grade(value: Option<&Value>) -> Checked<usize> {
    let grade = require_enum(value, &GRADES)?;
    Ok(GRADES
        .iter()
        .position(|member| *member == grade)
        .unwrap_or_default())
}

/// Every grade above `observe` enforces.
fn enforces(rank: usize) -> bool {
    rank > 1
}

fn exact_bool(value: Option<&Value>) -> Option<bool> {
    value.and_then(Value::as_bool)
}

/// A JSON integer (no fraction or exponent) that is not negative, of any
/// size the request carries.
fn non_negative_integer(number: &Number) -> Option<u128> {
    let text = number.to_string();
    let text = if text == "-0" { "0".to_owned() } else { text };
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(text.parse::<u128>().unwrap_or(u128::MAX))
}

/// `[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*`, at most 128 characters.
fn is_safe_identifier(value: Option<&Value>) -> bool {
    let Some(text) = value.and_then(Value::as_str) else {
        return false;
    };
    let bytes = text.as_bytes();
    if bytes.len() > MAX_IDENTIFIER_CHARS || !bytes.first().is_some_and(u8::is_ascii_lowercase) {
        return false;
    }
    let mut after_separator = false;
    for byte in &bytes[1..] {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => after_separator = false,
            b'.' | b'_' | b'-' if !after_separator => after_separator = true,
            _ => return false,
        }
    }
    !after_separator
}

fn is_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn ordered_fields<'a>(object: &Map<String, Value>, names: &[&'a str]) -> Vec<(&'a str, String)> {
    names
        .iter()
        .map(|name| (*name, object.get(*name).unwrap_or(&Value::Null).to_string()))
        .collect()
}

/// A JSON object whose keys keep the given order.
fn ordered(fields: &[(&str, String)]) -> String {
    let members: Vec<String> = fields
        .iter()
        .map(|(name, value)| format!("{}:{value}", Value::String((*name).to_owned())))
        .collect();
    format!("{{{}}}", members.join(","))
}

#[cfg(test)]
#[path = "network_status_validation_tests.rs"]
mod tests;
