//! The policy of the review artifact's life, ported from
//! `write_codex_hook_repair_request` and `load_codex_hook_repair_request`.
//!
//! The artifact's bytes are sealed and written elsewhere; this decides when it
//! was created and expires, whether a loaded one still names the plan it
//! authorizes, and whether its review window is still open. The caller sends
//! its monotonic clock as a fact.

use serde_json::{json, Value};

use super::publication::Call;
use super::python_equal::python_equal;
use super::{Fault, Step};

/// `_REVIEW_SECONDS`: how long a review artifact stays valid.
const REVIEW_SECONDS: f64 = 300.0;
const PLAN_INVALID: Fault = Fault::Transition("authority_repair_request_plan_invalid");
const EXPIRED: Fault = Fault::Transition("authority_repair_request_expired");

fn number(call: &Call<'_>, key: &str) -> Step<f64> {
    call.args
        .get(key)
        .filter(|value| value.is_number())
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .ok_or(PLAN_INVALID)
}

/// `publication_request_policy`, by `stage`:
/// - `stamp`: `{created, expires}` for an artifact written at `now`.
/// - `plan`: the signed `signed_at` and `subject` must equal the rebuilt
///   plan's `operation_id` and `plan_subject`, else
///   `authority_repair_request_plan_invalid`.
/// - `window`: `created <= now < expires`, else
///   `authority_repair_request_expired`.
pub(super) fn policy_op(call: &mut Call<'_>) -> Step<Value> {
    match call.text("stage")? {
        "stamp" => {
            let now = number(call, "now")?;
            Ok(json!({"created": now, "expires": now + REVIEW_SECONDS}))
        }
        "plan" => {
            let pair = |left: &str, right: &str| match (call.args.get(left), call.args.get(right)) {
                (Some(left), Some(right)) => python_equal(left, right),
                _ => false,
            };
            if pair("signed_at", "operation_id") && pair("subject", "plan_subject") {
                Ok(Value::Null)
            } else {
                Err(PLAN_INVALID)
            }
        }
        "window" => {
            let (created, expires, now) = (
                number(call, "created")?,
                number(call, "expires")?,
                number(call, "now")?,
            );
            if created <= now && now < expires {
                Ok(Value::Null)
            } else {
                Err(EXPIRED)
            }
        }
        _ => Err(Fault::Transition("files_invalid")),
    }
}
