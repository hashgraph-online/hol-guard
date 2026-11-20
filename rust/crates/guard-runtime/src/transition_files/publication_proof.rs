//! What a sealed native proof must carry before a publication is committed or
//! its inverse retired, ported from `_commit_verified_hook_repair_publication`
//! and `verify_and_retire_codex_publication_inverse`.
//!
//! The caller still runs the configured hook and holds the proof; the runtime
//! decides whether the proof is the one this publication needs. Times are the
//! asking process's monotonic seconds: `publication` (when the files were
//! published), `started` (before the hook ran), the proof's `observed_monotonic`
//! and `now` (when the question was asked) must not run backwards.

use serde_json::Value;

use super::inspect::{decode, sha256_hex};
use super::publication::Call;
use super::python_equal::python_equal;
use super::{Fault, Step};

const INVERSE_INVALID: Fault = Fault::Transition("publication_inverse_native_verification_invalid");

fn number(value: Option<&Value>) -> Option<f64> {
    value
        .filter(|value| !value.is_boolean())
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
}

/// `publication <= started <= observed <= now`, each a finite number.
pub(super) fn ordered(call: &Call<'_>, observation: &Value) -> bool {
    let times = [
        number(call.args.get("publication")),
        number(call.args.get("started")),
        number(observation.get("observed_monotonic")),
        number(call.args.get("now")),
    ];
    let Some(times) = times.into_iter().collect::<Option<Vec<f64>>>() else {
        return false;
    };
    times.windows(2).all(|pair| pair[0] <= pair[1])
}

fn same(left: Option<&Value>, right: Option<&Value>) -> bool {
    matches!((left, right), (Some(left), Some(right)) if python_equal(left, right))
}

fn digest(call: &Call<'_>, key: &str) -> Step<String> {
    Ok(sha256_hex(&decode(call.args.get(key))?.unwrap_or_default()))
}

/// `publication_inverse_proof`: the proof retires the restored inverse only
/// when it is fresh, names this operation, generation, Guard home and runtime,
/// and saw the restored config and manifest.
pub(super) fn inverse(call: &mut Call<'_>) -> Step<Value> {
    let Some(observation) = call
        .args
        .get("observation")
        .filter(|value| value.is_object())
    else {
        return Err(INVERSE_INVALID);
    };
    let evidence = observation.get("installed_hook_evidence");
    let seen = |key: &str| evidence.and_then(|evidence| evidence.get(key));
    let valid = ordered(call, observation)
        && same(
            observation.get("operation_id"),
            call.args.get("operation_id"),
        )
        && same(observation.get("generation"), call.args.get("generation"))
        && same(observation.get("guard_home"), call.args.get("guard_home"))
        && same(
            observation.get("runtime_identity"),
            call.args.get("runtime_identity"),
        )
        && evidence.is_some_and(Value::is_object)
        && seen("harness").and_then(Value::as_str) == Some("codex")
        && seen("config_sha256").and_then(Value::as_str)
            == Some(digest(call, "config_after")?.as_str())
        && seen("manifest_sha256").and_then(Value::as_str)
            == Some(digest(call, "manifest_after")?.as_str());
    if valid {
        Ok(Value::Null)
    } else {
        Err(INVERSE_INVALID)
    }
}
