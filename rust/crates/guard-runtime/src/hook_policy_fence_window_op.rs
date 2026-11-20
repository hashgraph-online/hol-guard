//! Resident-owned accounting for policy-source fence windows.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::policy_bundle_time::micros_to_utc_isoformat;
use crate::resident_protocol::encode_response;

pub(crate) const HOOK_POLICY_FENCE_WINDOW_FEATURE: &str = "hook-policy-fence-window-v1";
pub(crate) const HOOK_POLICY_FENCE_WINDOW_WRITE_FEATURE: &str = "hook-policy-fence-window-write-v1";
const REQUEST_SCHEMA: &str = "guard-hook-policy-fence-window-request.v1";
const RESULT_SCHEMA: &str = "guard-hook-policy-fence-window-result.v1";
const EVENT_NAME: &str = "policy_source_fence_window";
const MAX_WAIT_MS: u64 = 8_000;
const MAX_WINDOW_AGE_MICROS: i64 = 9_000_000;
const MAX_PENDING_EVENTS: usize = 16;

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
    #[serde(default)]
    pub(crate) attempt_until_micros: Option<i64>,
    #[serde(default)]
    pub(crate) persist_events: bool,
}

#[derive(Serialize)]
struct FenceEvent {
    event_name: &'static str,
    payload: Value,
    occurred_at: String,
}

struct Waiter {
    started_micros: i64,
    attempt_until_micros: Option<i64>,
}

#[derive(Default)]
struct WindowState {
    started_micros: i64,
    waiters: HashMap<String, Waiter>,
    absorbed: u64,
    exhausted: u64,
    pending_events: VecDeque<FenceEvent>,
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
) -> Result<FenceEvent, String> {
    let ended_at = timestamp(ended_micros)?;
    Ok(FenceEvent {
        event_name: EVENT_NAME,
        payload: json!({
            "started_at": timestamp(started_micros)?,
            "ended_at": ended_at,
            "absorbed_calls": absorbed,
            "exhausted_calls": exhausted,
        }),
        occurred_at: ended_at,
    })
}

fn queue_event(state: &mut WindowState, value: FenceEvent) {
    if state.pending_events.len() < MAX_PENDING_EVENTS {
        state.pending_events.push_back(value);
    }
}

pub(crate) fn evaluate(request: &HookPolicyFenceWindowRequestV1) -> Result<Vec<u8>, String> {
    if request.schema != REQUEST_SCHEMA
        || request.request_id.is_empty()
        || request.request_id.len() > 128
        || request.guard_home.is_empty()
        || request.guard_home.len() > 4096
        || !matches!(
            request.action.as_str(),
            "enter" | "leave" | "attempt" | "absorb_direct"
        )
    {
        return Err("hook_policy_fence_window_payload_invalid".to_owned());
    }
    let now = now_micros()?;
    let window_state = WINDOWS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut windows = window_state
        .lock()
        .map_err(|_| "hook_policy_fence_window_state_poisoned".to_owned())?;
    let state = windows.entry(request.guard_home.clone()).or_default();
    if request.action == "attempt" {
        if let Some(waiter) = state.waiters.get_mut(&request.request_id) {
            waiter.attempt_until_micros = request.attempt_until_micros.filter(|until| *until > now);
        }
    }
    let mut completed = state.pending_events.pop_front();
    let mut live = HashMap::new();
    for (request_id, waiter) in state.waiters.drain() {
        if request.action == "leave" && request_id == request.request_id {
            live.insert(request_id, waiter);
            continue;
        }
        let expiry = waiter
            .attempt_until_micros
            .unwrap_or_else(|| waiter.started_micros.saturating_add(MAX_WINDOW_AGE_MICROS));
        if now > expiry {
            state.exhausted = state.exhausted.saturating_add(1);
        } else {
            live.insert(request_id, waiter);
        }
    }
    state.waiters = live;
    if state.waiters.is_empty() && state.started_micros != 0 && state.exhausted > 0 {
        let value = event(state.started_micros, now, state.absorbed, state.exhausted)?;
        if completed.is_none() {
            completed = Some(value);
        } else {
            queue_event(state, value);
        }
        state.started_micros = 0;
        state.absorbed = 0;
        state.exhausted = 0;
    }
    let completed = match request.action.as_str() {
        "enter" => {
            if state.waiters.is_empty() {
                state.started_micros = now;
                state.absorbed = 0;
                state.exhausted = 0;
            }
            state.waiters.insert(
                request.request_id.clone(),
                Waiter {
                    started_micros: now,
                    attempt_until_micros: None,
                },
            );
            completed
        }
        "attempt" => completed,
        "leave" => {
            if state.waiters.remove(&request.request_id).is_some() {
                if request.admitted == Some(true) {
                    state.absorbed = state.absorbed.saturating_add(1);
                } else {
                    state.exhausted = state.exhausted.saturating_add(1);
                }
                if state.waiters.is_empty() {
                    let value = event(state.started_micros, now, state.absorbed, state.exhausted)?;
                    state.started_micros = 0;
                    state.absorbed = 0;
                    state.exhausted = 0;
                    if completed.is_none() {
                        Some(value)
                    } else {
                        queue_event(state, value);
                        completed
                    }
                } else {
                    completed
                }
            } else {
                completed
            }
        }
        "absorb_direct" => {
            let waited = request.waited_ms.unwrap_or(0).min(MAX_WAIT_MS);
            if !state.waiters.is_empty() {
                state.absorbed = state.absorbed.saturating_add(1);
                completed
            } else {
                let waited_micros = i64::try_from(waited)
                    .unwrap_or(i64::MAX)
                    .saturating_mul(1_000);
                let started = now.saturating_sub(waited_micros);
                let value = event(started, now, 1, 0)?;
                if completed.is_none() {
                    Some(value)
                } else {
                    queue_event(state, value);
                    completed
                }
            }
        }
        _ => unreachable!(),
    };
    let mut window_events = Vec::new();
    if let Some(event) = completed {
        window_events.push(event);
    }
    while window_events.len() < MAX_PENDING_EVENTS {
        let Some(event) = state.pending_events.pop_front() else {
            break;
        };
        window_events.push(event);
    }
    drop(windows);
    if request.persist_events && !window_events.is_empty() {
        if persistence::write(&request.guard_home, &window_events).is_err() {
            if let Ok(mut windows) = window_state.lock() {
                let state = windows.entry(request.guard_home.clone()).or_default();
                // Retry these completed windows on the next call. The write
                // either committed the entire batch or left it untouched.
                for event in window_events.into_iter().rev() {
                    state.pending_events.push_front(event);
                }
                state.pending_events.truncate(MAX_PENDING_EVENTS);
            }
            return Err("hook_policy_fence_window_write_failed".to_owned());
        }
        window_events.clear();
    }
    encode_response(&json!({
        "schema": RESULT_SCHEMA,
        "result": {
            "request_id": request.request_id,
            "window_event": window_events.first(),
            "window_events": window_events,
        },
    }))
}

#[path = "hook_policy_fence_window_persistence.rs"]
mod persistence;

#[cfg(test)]
#[path = "hook_policy_fence_window_op_tests.rs"]
mod tests;
