//! Resident-owned accounting for policy-source fence windows.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::policy_bundle_time::micros_to_utc_isoformat;
use crate::resident_protocol::encode_response;

pub(crate) const HOOK_POLICY_FENCE_WINDOW_FEATURE: &str = "hook-policy-fence-window-v1";
const REQUEST_SCHEMA: &str = "guard-hook-policy-fence-window-request.v1";
const RESULT_SCHEMA: &str = "guard-hook-policy-fence-window-result.v1";
const EVENT_NAME: &str = "policy_source_fence_window";
const MAX_WAIT_MS: u64 = 8_000;
const MAX_WINDOW_AGE_MICROS: i64 = 9_000_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookPolicyFenceWindowRequestV1 {
    pub(crate) schema: String,
    pub(crate) request_id: String,
    pub(crate) guard_home: String,
    pub(crate) action: String,
    #[serde(default)]
    pub(crate) admitted: Option<bool>,
    #[serde(default)]
    pub(crate) waited_ms: Option<u64>,
}

#[derive(Default)]
struct WindowState {
    started_micros: i64,
    waiting: u64,
    absorbed: u64,
    exhausted: u64,
}

static WINDOWS: OnceLock<Mutex<HashMap<String, WindowState>>> = OnceLock::new();

fn now_micros() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "hook_policy_fence_window_clock_invalid".to_owned())?;
    i64::try_from(duration.as_micros())
        .map_err(|_| "hook_policy_fence_window_clock_invalid".to_owned())
}

fn timestamp(micros: i64) -> Result<String, String> {
    micros_to_utc_isoformat(micros, "+00:00")
        .ok_or_else(|| "hook_policy_fence_window_clock_invalid".to_owned())
}

fn event(
    started_micros: i64,
    ended_micros: i64,
    absorbed: u64,
    exhausted: u64,
) -> Result<Value, String> {
    Ok(json!({
        "event_name": EVENT_NAME,
        "payload": {
            "started_at": timestamp(started_micros)?,
            "ended_at": timestamp(ended_micros)?,
            "absorbed_calls": absorbed,
            "exhausted_calls": exhausted,
        },
        "occurred_at": timestamp(ended_micros)?,
    }))
}

pub(crate) fn evaluate(request: &HookPolicyFenceWindowRequestV1) -> Result<Vec<u8>, String> {
    if request.schema != REQUEST_SCHEMA
        || request.request_id.is_empty()
        || request.request_id.len() > 128
        || request.guard_home.is_empty()
        || request.guard_home.len() > 4096
        || !matches!(request.action.as_str(), "enter" | "leave" | "absorb_direct")
    {
        return Err("hook_policy_fence_window_payload_invalid".to_owned());
    }
    let now = now_micros()?;
    let windows = WINDOWS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut windows = windows
        .lock()
        .map_err(|_| "hook_policy_fence_window_state_poisoned".to_owned())?;
    let state = windows.entry(request.guard_home.clone()).or_default();
    if state.waiting > 0 && now.saturating_sub(state.started_micros) > MAX_WINDOW_AGE_MICROS {
        state.started_micros = 0;
        state.waiting = 0;
        state.absorbed = 0;
        state.exhausted = 0;
    }
    let completed = match request.action.as_str() {
        "enter" => {
            if state.waiting == 0 {
                state.started_micros = now;
                state.absorbed = 0;
                state.exhausted = 0;
            }
            state.waiting = state.waiting.saturating_add(1);
            None
        }
        "leave" => {
            if state.waiting == 0 {
                None
            } else {
                state.waiting -= 1;
                if request.admitted == Some(true) {
                    state.absorbed = state.absorbed.saturating_add(1);
                } else {
                    state.exhausted = state.exhausted.saturating_add(1);
                }
                if state.waiting == 0 {
                    let value = event(state.started_micros, now, state.absorbed, state.exhausted)?;
                    state.started_micros = 0;
                    state.absorbed = 0;
                    state.exhausted = 0;
                    Some(value)
                } else {
                    None
                }
            }
        }
        "absorb_direct" => {
            let waited = request.waited_ms.unwrap_or(0).min(MAX_WAIT_MS);
            if state.waiting > 0 {
                state.absorbed = state.absorbed.saturating_add(1);
                None
            } else {
                let waited_micros = i64::try_from(waited)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1_000);
                let started = now.saturating_sub(waited_micros);
                Some(event(started, now, 1, 0)?)
            }
        }
        _ => unreachable!(),
    };
    encode_response(&json!({
        "schema": RESULT_SCHEMA,
        "result": {
            "request_id": request.request_id,
            "window_event": completed,
        },
    }))
}

#[cfg(test)]
#[path = "hook_policy_fence_window_op_tests.rs"]
mod tests;
