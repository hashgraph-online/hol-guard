//! The timing of a one-use authorization, ported from the Python
//! `authorize_codex_hook_repair` and `authorize_codex_publication_inverse`.
//!
//! The caller sends the clocks as facts (its monotonic seconds and the wall
//! clock) and the runtime decides: whether the caller's deadline is still
//! ahead, and how long the approved grant lets an authorization live. The
//! forward deadline is the earliest of the caller's, `now` plus the action's
//! cap, and the grant's own expiry.

use guard_command::attestation_timestamp::parse_attestation_timestamp;
use serde_json::{json, Value};

use super::publication::Call;
use super::{Fault, Step};

const EXCEEDED: Fault = Fault::Transition("deadline_exceeded");
const GRANT_INVALID: Fault = Fault::Transition("approval_grant_invalid");
/// `_FORWARD_CAP_SECONDS`: how long a repair authorization may run forward.
const REPAIR_CAP_SECONDS: f64 = 60.0;
/// The publication inverse's forward cap.
const INVERSE_CAP_SECONDS: f64 = 60.0;
const MICROS: f64 = 1_000_000.0;

pub(super) fn number(call: &Call<'_>, key: &str) -> Option<f64> {
    call.args
        .get(key)
        .filter(|value| value.is_number())
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
}

/// A deadline is usable while it is a finite number still ahead of `now`.
pub(super) fn ahead(deadline: Option<f64>, now: Option<f64>) -> Step<f64> {
    match (deadline, now) {
        (Some(deadline), Some(now)) if now < deadline => Ok(deadline),
        _ => Err(EXCEEDED),
    }
}

/// `publication_deadline`: `deadline_exceeded` unless `deadline` is a finite
/// number and `now` (the caller's monotonic seconds) is before it.
pub(super) fn deadline(call: &mut Call<'_>) -> Step<Value> {
    ahead(number(call, "deadline"), number(call, "now")).map(|_| Value::Null)
}

/// `publication_authorize`: `{deadline, retirement_seconds, retirement}` for
/// a grant that expires at `expires_at`, given the caller's `deadline` (already
/// judged by `publication_deadline`), its monotonic `now`, the `wall` clock in
/// epoch seconds and the action `kind` (`repair` or `inverse`). `retirement_seconds` is what remains of the grant,
/// `retirement` that moment on the caller's monotonic clock.
pub(super) fn plan(call: &mut Call<'_>) -> Step<Value> {
    let cap = match call.text("kind")? {
        "repair" => REPAIR_CAP_SECONDS,
        "inverse" => INVERSE_CAP_SECONDS,
        _ => return Err(Fault::Transition("files_invalid")),
    };
    let requested = number(call, "deadline").ok_or(EXCEEDED)?;
    let now = number(call, "now").ok_or(EXCEEDED)?;
    let wall = number(call, "wall").ok_or(GRANT_INVALID)?;
    let expires = parse_attestation_timestamp(call.text("expires_at")?).ok_or(GRANT_INVALID)?;
    let remaining = (expires as f64 / MICROS - wall).max(0.0);
    let retirement = now + remaining;
    let deadline = requested.min(now + cap).min(retirement);
    Ok(json!({
        "deadline": deadline,
        "retirement_seconds": remaining,
        "retirement": retirement,
    }))
}
