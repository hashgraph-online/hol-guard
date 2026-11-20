//! Publish one generation-bound snapshot to the resident and authenticate its ACK.
//!
//! The publisher composes the effective policy and owns the resident stream;
//! everything between is decided here. One process materializes the snapshot,
//! provisions a business declaration's verifier key once its content is
//! accepted, encodes the push envelope, checks the resident's answer, and
//! renews the generation once when the resident asks for a newer one.
//!
//! The exchange is newline-delimited JSON on stdin and stdout. The caller
//! sends the settings line and the materialize request line. Each push is
//! written as `{"push": <envelope text>, "timeout_ms": n}`; the caller relays
//! the envelope and answers `{"output": <resident text> | null, "failure":
//! <code> | null}`. The last line is `{"published": {"snapshot": ...,
//! "resident_generation": n}}` or `{"error": <code>}`.
#![forbid(unsafe_code)]

use crate::policy_store::policy_snapshot_materialize::{
    materialize, parse_request, runtime_directory,
};
use guard_policy_snapshot::{
    canonical_json_bytes, POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION, POLICY_SNAPSHOT_MAX_BYTES,
    POLICY_SNAPSHOT_PUSH_SCHEMA,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::io::{BufRead, Write};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const SCHEMA: &str = "guard-native-policy-publish.v1";
const ERROR: &str = "native_policy_snapshot_build_invalid";
const ACK_INVALID: &str = "native_policy_snapshot_ack_invalid";
const ACK_MISMATCH: &str = "native_policy_snapshot_ack_mismatch";
const DEADLINE_EXCEEDED: &str = "native_policy_snapshot_deadline_exceeded";
const MAX_ACK_BYTES: usize = 4 * 1024;
/// The resident accepts a push budget of at most this many milliseconds.
const MAX_PUSH_BUDGET_MS: u64 = 9_000;
/// The publisher's lock wait is this share of the remaining build budget, so
/// contention is reported as such and never cut off mid-commit.
const LOCK_WAIT_PERMILLE: u128 = 800;
const MAX_LOCK_WAIT_MS: u64 = 60_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    schema: String,
    version: u16,
    /// What remains of the publisher's build deadline when it sent the request.
    build_budget_ms: u64,
    /// The push window for this attempt: warm, or the resident startup window.
    publish_timeout_ms: u64,
    /// The window a renewal gets, since a renewal may restart the resident.
    startup_timeout_ms: u64,
    #[serde(default)]
    direct_lane: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Relay {
    output: Option<String>,
    #[serde(default)]
    failure: Option<String>,
}

struct Ack {
    renew: bool,
    generation: u64,
    policy_digest: String,
    resident_generation: u64,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "policy-snapshot-publish"
}

pub(crate) fn run(mut input: impl BufRead, mut output: impl Write) -> Result<(), String> {
    let started = Instant::now();
    let settings_line = read_line(&mut input)?;
    let settings: Settings =
        serde_json::from_slice(&settings_line).map_err(|_| ERROR.to_owned())?;
    if settings.schema != SCHEMA
        || settings.version != 1
        || !(1..=MAX_PUSH_BUDGET_MS).contains(&settings.publish_timeout_ms)
        || !(1..=MAX_PUSH_BUDGET_MS).contains(&settings.startup_timeout_ms)
    {
        return Err(ERROR.into());
    }
    let request = read_line(&mut input)?;
    let answer = match publish(&settings, &request, started, &mut input, &mut output) {
        Ok((snapshot, resident_generation)) => json!({"published": {
            "snapshot": snapshot,
            "resident_generation": resident_generation,
        }}),
        Err(code) => json!({"error": code}),
    };
    write_line(&mut output, &answer)
}

fn publish(
    settings: &Settings,
    request_bytes: &[u8],
    started: Instant,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<(Value, u64), String> {
    let mut renewal: Option<u64> = None;
    loop {
        let mut request = parse_request(request_bytes)?;
        // A renewal may restart the resident, so it gets the startup window
        // for both its build and its push, as a fresh publication would.
        let deadline = match renewal {
            None => started + Duration::from_millis(settings.build_budget_ms),
            Some(floor) => {
                request.renew_after_generation = Some(floor);
                Instant::now() + Duration::from_millis(settings.startup_timeout_ms)
            }
        };
        let remaining = remaining_ms(deadline)?;
        request.lock_wait_ms = u64::try_from(u128::from(remaining) * LOCK_WAIT_PERMILLE / 1000)
            .unwrap_or(MAX_LOCK_WAIT_MS)
            .min(MAX_LOCK_WAIT_MS);
        let business = request.business_policy.is_some();
        let key = Zeroizing::new(*request.verifier_key.bytes());
        let state_base = runtime_directory(&request.guard_home);
        let payload = materialize(request)?;
        if business {
            // A business declaration provisions the resident key only once
            // the runtime has accepted its content.
            crate::policy_verifier_key_provision::provision_derived_key(&state_base, &key)?;
        }
        let snapshot =
            crate::resident_protocol::strict_json_value(&payload).map_err(|_| ERROR.to_owned())?;
        let generation = snapshot.get("generation").and_then(Value::as_u64);
        let policy_digest = snapshot.get("policy_digest").and_then(Value::as_str);
        let (Some(generation), Some(policy_digest)) = (generation, policy_digest) else {
            return Err(ERROR.into());
        };
        let policy_digest = policy_digest.to_owned();
        // A business binding keeps one deadline for the build and the push;
        // otherwise the push gets its own full window.
        let push_timeout_ms = match (business, renewal) {
            (true, _) => remaining_ms(deadline)?,
            (false, None) => settings.publish_timeout_ms,
            (false, Some(_)) => settings.startup_timeout_ms,
        };
        let budget_ms = push_timeout_ms.min(MAX_PUSH_BUDGET_MS);
        let envelope = push_bytes(snapshot.clone(), budget_ms, settings.direct_lane.as_ref())?;
        let envelope = String::from_utf8(envelope).map_err(|_| ERROR.to_owned())?;
        write_line(
            output,
            &json!({"push": envelope, "timeout_ms": push_timeout_ms}),
        )?;
        let relay: Relay =
            serde_json::from_slice(&read_line(input)?).map_err(|_| ERROR.to_owned())?;
        let ack = match relay.output {
            Some(text) => ack_from_resident_output(text.as_bytes())?.ok_or(ACK_INVALID)?,
            None => {
                return Err(relay
                    .failure
                    .filter(|code| valid_code(code))
                    .unwrap_or_else(|| ACK_INVALID.to_owned()))
            }
        };
        if ack.renew {
            if renewal.is_some() || ack.generation < generation {
                return Err(ACK_MISMATCH.into());
            }
            renewal = Some(ack.generation);
            continue;
        }
        if ack.generation != generation || ack.policy_digest != policy_digest {
            return Err(ACK_MISMATCH.into());
        }
        return Ok((snapshot, ack.resident_generation));
    }
}

fn remaining_ms(deadline: Instant) -> Result<u64, String> {
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .as_millis();
    match u64::try_from(remaining) {
        Ok(0) => Err(DEADLINE_EXCEEDED.into()),
        Ok(remaining) => Ok(remaining),
        Err(_) => Ok(u64::MAX),
    }
}

/// The strict resident push envelope. The direct-lane binding is optional, so
/// an envelope too large with it is sent without it.
fn push_bytes(
    snapshot: Value,
    budget_ms: u64,
    direct_lane: Option<&Value>,
) -> Result<Vec<u8>, String> {
    let mut request = Map::new();
    request.insert("schema".into(), POLICY_SNAPSHOT_PUSH_SCHEMA.into());
    request.insert("snapshot".into(), snapshot);
    if let Some(direct_lane) = direct_lane {
        request.insert("direct_lane".into(), direct_lane.clone());
    }
    loop {
        let envelope = json!({
            "operation": "policy_snapshot_push",
            "deadline_budget_ms": budget_ms,
            "request": Value::Object(request.clone()),
        });
        let encoded = canonical_json_bytes(&envelope).map_err(|_| ERROR.to_owned())?;
        if encoded.len() <= POLICY_SNAPSHOT_MAX_BYTES {
            return Ok(encoded);
        }
        if request.remove("direct_lane").is_none() {
            return Err("native_policy_snapshot_too_large".into());
        }
    }
}

/// An error frame from the resident is its answer; anything else must be an
/// exact ACK.
fn ack_from_resident_output(output: &[u8]) -> Result<Option<Ack>, String> {
    let Ok(value) = crate::resident_protocol::strict_json_value(output) else {
        return Ok(None);
    };
    if let Some(object) = value.as_object() {
        if let Some(Value::String(error)) = object.get("error") {
            if !error.is_empty()
                && error != POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION
                && object
                    .keys()
                    .all(|key| key == "error" || key == "retryable")
            {
                return Err(error.clone());
            }
        }
    }
    if output.len() > MAX_ACK_BYTES {
        return Ok(None);
    }
    Ok(decode_ack(&value))
}

fn decode_ack(value: &Value) -> Option<Ack> {
    let object = value.as_object()?;
    const KEYS: [&str; 5] = [
        "status",
        "generation",
        "policy_digest",
        "idempotent",
        "resident_generation",
    ];
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return None;
    }
    let renew = match object.get("status")?.as_str()? {
        "accepted" => false,
        status if status == POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION => true,
        _ => return None,
    };
    let generation = positive(object.get("generation")?)?;
    let resident_generation = positive(object.get("resident_generation")?)?;
    let policy_digest = object.get("policy_digest")?.as_str()?;
    let idempotent = object.get("idempotent")?.as_bool()?;
    if !valid_digest(policy_digest) || (renew && idempotent) {
        return None;
    }
    Some(Ack {
        renew,
        generation,
        policy_digest: policy_digest.to_owned(),
        resident_generation,
    })
}

fn positive(value: &Value) -> Option<u64> {
    value.as_u64().filter(|value| *value > 0)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A failure code the caller relays; any other text collapses to the ACK error.
fn valid_code(code: &str) -> bool {
    (4..=80).contains(&code.len())
        && code.starts_with(|first: char| first.is_ascii_lowercase())
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Read one line into a buffer that is cleared on drop: the request line
/// carries the verifier key.
fn read_line(input: &mut impl BufRead) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut line = Zeroizing::new(Vec::with_capacity(POLICY_SNAPSHOT_MAX_BYTES + 1));
    loop {
        let available = input.fill_buf().map_err(|_| ERROR.to_owned())?;
        if available.is_empty() {
            break;
        }
        let (take, done) = match available.iter().position(|byte| *byte == b'\n') {
            Some(index) => (index, true),
            None => (available.len(), false),
        };
        if line.len() + take > POLICY_SNAPSHOT_MAX_BYTES {
            return Err(ERROR.into());
        }
        line.extend_from_slice(&available[..take]);
        input.consume(take + usize::from(done));
        if done {
            return Ok(line);
        }
    }
    if line.is_empty() {
        return Err(ERROR.into());
    }
    Ok(line)
}

fn write_line(output: &mut impl Write, value: &Value) -> Result<(), String> {
    let mut encoded = serde_json::to_vec(value).map_err(|_| ERROR.to_owned())?;
    encoded.push(b'\n');
    output
        .write_all(&encoded)
        .and_then(|()| output.flush())
        .map_err(|_| "native_policy_snapshot_publish_write_failed".to_owned())
}

#[cfg(test)]
#[path = "policy_snapshot_publish_tests.rs"]
mod tests;
