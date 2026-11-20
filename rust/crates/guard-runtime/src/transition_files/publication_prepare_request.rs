//! The checks on a runtime-transition request, ported from
//! `prepare_runtime_transition` and the coordinator's `activate` and `recover`.
//!
//! The caller still gathers the install rows and adapter files; what decides
//! whether the request itself is well formed lives here. Each `stage` is one
//! check the caller runs where the Python code ran it, so one bad request
//! reports the same reason in the same order.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::publication::Call;
use super::{Fault, Step};

const DEADLINE_INVALID: Fault = Fault::Transition("deadline_invalid");
const OPERATION_INVALID: Fault = Fault::Transition("operation_id_invalid");
const DIGEST_INVALID: Fault = Fault::Transition("artifact_digest_invalid");
const BINDINGS_MISSING: Fault = Fault::Transition("native_runtime_bindings_missing");
const IDENTITY_INVALID: Fault = Fault::Transition("artifact_identity_invalid");
/// The longest a preparation may run, on either clock.
const WINDOW_SECONDS: f64 = 60.0;
const SIDES: [&str; 2] = ["candidate", "predecessor"];

fn finite(call: &Call<'_>, key: &str) -> Step<f64> {
    call.args
        .get(key)
        .filter(|value| value.is_number())
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .ok_or(DEADLINE_INVALID)
}

/// `0 < deadline - now <= 60`.
fn within_window(deadline: f64, now: f64) -> bool {
    let remaining = deadline - now;
    remaining > 0.0 && remaining <= WINDOW_SECONDS
}

/// `{"deadline": ..}`: the caller's monotonic deadline, brought in to the
/// wall-clock `deadline_epoch` when that is sooner. Both must be finite and
/// less than a minute ahead of `now` and `wall`.
fn deadline(call: &Call<'_>) -> Step<Value> {
    let (deadline, now) = (finite(call, "deadline")?, finite(call, "now")?);
    let (epoch, wall) = (finite(call, "deadline_epoch")?, finite(call, "wall")?);
    if !within_window(deadline, now) || !within_window(epoch, wall) {
        return Err(DEADLINE_INVALID);
    }
    Ok(json!({"deadline": deadline.min(now + (epoch - wall))}))
}

/// A recovery's deadline: finite, and at most a minute ahead of `now`. One
/// already past is left for the deadline check to refuse as expired.
fn recovery(call: &Call<'_>) -> Step<Value> {
    let (deadline, now) = (finite(call, "deadline")?, finite(call, "now")?);
    if deadline - now > WINDOW_SECONDS {
        return Err(DEADLINE_INVALID);
    }
    Ok(Value::Null)
}

/// `{"deadline": ..}` for an activation: the plan's wall-clock expiry on the
/// caller's monotonic clock, brought in to the caller's own `deadline` when
/// one is given. A deadline given must be finite.
fn activation(call: &Call<'_>) -> Step<Value> {
    let (epoch, wall, now) = (
        finite(call, "deadline_epoch")?,
        finite(call, "wall")?,
        finite(call, "now")?,
    );
    let planned = now + (epoch - wall).max(0.0);
    match call.args.get("deadline") {
        None | Some(Value::Null) => Ok(json!({"deadline": planned})),
        Some(_) => Ok(json!({"deadline": planned.min(finite(call, "deadline")?)})),
    }
}

/// `str(uuid.UUID(value)) == value`: the lowercase, hyphenated 8-4-4-4-12 form.
fn canonical_uuid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, width)| {
            group.len() == width
                && group
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn operation(call: &Call<'_>) -> Step<Value> {
    match call.args.get("operation_id") {
        Some(Value::String(value)) if canonical_uuid(value) => Ok(Value::Null),
        _ => Err(OPERATION_INVALID),
    }
}

fn keys_are_sides(map: &Map<String, Value>) -> bool {
    map.len() == SIDES.len() && SIDES.iter().all(|side| map.contains_key(*side))
}

fn lower_hex_digest(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// The reviewed executable digests (when given) name exactly the two sides
/// and are sha-256 hex, and the native runtime bindings name them too.
fn bindings(call: &Call<'_>) -> Step<Value> {
    match call.args.get("executable_digests") {
        None | Some(Value::Null) => {}
        Some(Value::Object(digests)) => {
            if !keys_are_sides(digests) || !digests.values().all(lower_hex_digest) {
                return Err(DIGEST_INVALID);
            }
        }
        Some(_) => return Err(DIGEST_INVALID),
    }
    match call.args.get("native") {
        Some(Value::Object(native)) if keys_are_sides(native) => Ok(Value::Null),
        _ => Err(BINDINGS_MISSING),
    }
}

fn absolute(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|text| Path::new(text).is_absolute())
}

/// Each side names an absolute artifact path and a native runtime with an
/// absolute path.
fn identity(call: &Call<'_>) -> Step<Value> {
    let artifacts = call.args.get("artifacts").and_then(Value::as_object);
    let native = call.args.get("native").and_then(Value::as_object);
    for side in ["predecessor", "candidate"] {
        let artifact = artifacts
            .and_then(|map| map.get(side))
            .and_then(Value::as_object);
        let runtime = native
            .and_then(|map| map.get(side))
            .and_then(Value::as_object);
        if !absolute(artifact.and_then(|map| map.get("path")))
            || !absolute(runtime.and_then(|map| map.get("path")))
        {
            return Err(IDENTITY_INVALID);
        }
    }
    Ok(Value::Null)
}

/// `publication_prepare_request`, by `stage`: `deadline`, `operation`,
/// `recovery`, `activation`, `bindings` or `identity`. A stage that fails
/// refuses with its reason.
pub(super) fn prepare_op(call: &mut Call<'_>) -> Step<Value> {
    match call.text("stage")? {
        "deadline" => deadline(call),
        "operation" => operation(call),
        "recovery" => recovery(call),
        "activation" => activation(call),
        "bindings" => bindings(call),
        "identity" => identity(call),
        _ => Err(Fault::Transition("files_invalid")),
    }
}
