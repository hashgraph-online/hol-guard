//! `POST /v1/settings`, `POST /v1/settings/import` and
//! `POST /v1/settings/reset`, written through the same native config update,
//! approval-gate checks and timeline events as the daemon's
//! `_apply_settings_payload` and `_handle_settings_reset`.
//!
//! A change the edge cannot finish goes to the daemon before any gate check
//! runs: approval-gate settings, context-assistance settings, and turning
//! cloud sync on, which needs the daemon's plan entitlement. Once the
//! resident may have checked the gate the edge never hands the request over,
//! so the check never runs twice.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use super::super::settings::{response, Loaded};
use super::super::{NativeReads, ReadConfig};
use super::gate::{self, Gate};
use super::DROPPED;
use crate::guard_store_guard_event::dumps;
use crate::managed_policy_floor::effective_managed_policy;
use crate::managed_policy_load::{load_managed_policy, ManagedPolicySource};
use crate::policy_bundle_time::micros_to_utc_isoformat;
use crate::pyjson::PyVal;

const UPDATE_SCHEMA: &str = "guard-config-update.v1";
const RESET_CONFIRMATION: &str = "reset-local-settings";
/// `_CLOUD_REVIEW_PRIVACY_PROJECTION_MARKER`.
const PRIVACY_PROJECTION_MARKER: &str = "cloud_review_privacy_projection_v2";
const PRESENTATION_KEYS: [&str; 4] = [
    "presentation_mode",
    "presentation_mode_explicit",
    "presentation_schema_version",
    "presentation_revision",
];
const CONTEXT_ASSISTANCE_TIMEOUT: Duration = Duration::from_secs(2);
const CONTEXT_ASSISTANCE_BUDGET_MS: u64 = 2_000;

static CONTEXT_REQUEST_IDS: AtomicU64 = AtomicU64::new(0);

/// `_apply_settings_payload(payload, missing_error=...)`.
pub(super) fn apply(
    payload: &[(String, PyVal)],
    json_payload: &Map<String, Value>,
    missing_error: &str,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let Some(PyVal::Dict(settings)) = lookup(payload, "settings") else {
        return Some((400, json!({"error": missing_error})));
    };
    if settings.iter().any(|(key, value)| {
        key == "approval_gate"
            || key == "context_assistance"
            || (key == "sync" && *value == PyVal::Bool(true))
    }) {
        return None;
    }
    // The answer reads the gate under the daemon's session; without one the
    // daemon answers before anything is written.
    config.session_signals.as_ref()?;
    let guard_home = Path::new(&config.guard_home);
    let previous = Loaded::read(guard_home)?;
    let presentation_only = !settings.is_empty()
        && settings
            .iter()
            .all(|(key, _)| PRESENTATION_KEYS.contains(&key.as_str()));
    if !presentation_only {
        // `require_high_risk` reads the proof from the top level only when
        // one is offered there; otherwise it runs with no input.
        let offered = ["approval_password", "approval_totp_code"]
            .iter()
            .any(|key| json_payload.get(*key).is_some_and(truthy));
        let input = if offered {
            json_payload.clone()
        } else {
            Map::new()
        };
        if let Some(refused) = settings_gate(&input, config)? {
            return Some(refused);
        }
    }
    let value = PyVal::Dict(settings.clone());
    let written = match update(guard_home, "settings", &value) {
        Ok(previous) => previous,
        Err(Some(message)) => {
            return Some((
                400,
                json!({"error": "invalid_settings", "message": message}),
            ))
        }
        Err(None) => return Some((DROPPED, Value::Null)),
    };
    Some(after_write(config, reads, &previous, Some(&written), false))
}

/// `_handle_settings_reset`.
pub(super) fn reset(
    json_payload: &Map<String, Value>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    if json_payload.get("confirm").and_then(Value::as_str) != Some(RESET_CONFIRMATION) {
        return Some((
            400,
            json!({"error": "confirmation_required", "confirm": RESET_CONFIRMATION}),
        ));
    }
    // The answer reads the gate under the daemon's session; without one the
    // daemon answers before anything is written.
    config.session_signals.as_ref()?;
    let guard_home = Path::new(&config.guard_home);
    let previous = Loaded::read(guard_home)?;
    if let Some(refused) = settings_gate(json_payload, config)? {
        return Some(refused);
    }
    if update(guard_home, "reset", &PyVal::Null).is_err() {
        return Some((DROPPED, Value::Null));
    }
    Some(after_write(config, reads, &previous, None, true))
}

/// `require_high_risk(purpose="settings_write")`, then the
/// `require_settings_write` check the config write runs with its grant.
/// `Some(Some(answer))` is a refusal to send; `None` goes to the daemon.
fn settings_gate(input: &Map<String, Value>, config: &ReadConfig) -> Option<Option<(u16, Value)>> {
    let grant = match gate::require_high_risk("settings_write", input, config)? {
        Gate::Refused(status, body) => return Some(Some((status, Value::Object(body)))),
        Gate::Passed(grant) => grant,
    };
    // The resident has run, so from here on nothing goes to the daemon. No
    // answer at all is a home that never configured the gate.
    match gate::require_settings_write(grant, config) {
        Some(Gate::Refused(status, body)) => Some(Some((status, Value::Object(body)))),
        Some(Gate::Passed(_)) | None => Some(None),
    }
}

/// Everything the daemon does once the config is written: reload, republish
/// the policy snapshot, record posture changes, requeue the cloud review
/// projection when the redaction level moved, and answer the new settings.
fn after_write(
    config: &ReadConfig,
    reads: &NativeReads,
    previous: &Loaded,
    written: Option<&Value>,
    hand_to_context_assistance: bool,
) -> (u16, Value) {
    let guard_home = Path::new(&config.guard_home);
    let Some(updated) = Loaded::read(guard_home) else {
        return (DROPPED, Value::Null);
    };
    reads.report_policy_mutation();
    if let Some(written) = written {
        if record_posture_events(config, reads, written, &updated).is_none() {
            return (DROPPED, Value::Null);
        }
    }
    let level = updated.get("receipt_redaction_level");
    if level != previous.get("receipt_redaction_level") {
        let Some(level) = level.as_str() else {
            return (DROPPED, Value::Null);
        };
        if requeue_privacy_projection(config, reads, level).is_none() {
            return (DROPPED, Value::Null);
        }
    }
    if hand_to_context_assistance {
        hand_settings_to_context_assistance(guard_home);
    }
    response(config, &updated).unwrap_or((DROPPED, Value::Null))
}

/// One `guard-config-update` write in process. `Err(Some(message))` is the
/// `ValueError` the daemon answers with 400; `Err(None)` a write it raises on.
fn update(guard_home: &Path, kind: &str, value: &PyVal) -> Result<Value, Option<String>> {
    let state = load_managed_policy(&ManagedPolicySource::native());
    let managed = effective_managed_policy(&state).map(|policy| {
        json!({
            "settings": policy.settings,
            "locked_settings": policy.locked_settings.iter().collect::<Vec<_>>(),
        })
    });
    let request = json!({
        "schema": UPDATE_SCHEMA,
        "guard_home": guard_home,
        "kind": kind,
        "value_text": dumps(value).ok_or(None)?,
        "managed": managed,
        "cloud_sync_entitled": false,
    });
    let encoded = serde_json::to_vec(&request).map_err(|_| None)?;
    let output = crate::guard_config_update::run_command(encoded.as_slice()).map_err(|_| None)?;
    let answer: Value = serde_json::from_slice(&output).map_err(|_| None)?;
    if answer.get("ok") == Some(&Value::Bool(true)) {
        return Ok(answer.get("previous").cloned().unwrap_or(Value::Null));
    }
    match answer.get("invalid").and_then(Value::as_str) {
        Some(message) if !message.is_empty() => Err(Some(message.to_owned())),
        _ => Err(None),
    }
}

/// `record_posture_change_if_needed` and
/// `record_harness_posture_changes_if_needed` with `event_source="settings"`.
fn record_posture_events(
    config: &ReadConfig,
    reads: &NativeReads,
    written: &Value,
    updated: &Loaded,
) -> Option<()> {
    let previous = written.get("previous")?.as_str()?;
    let previous_explicit = written.get("previous_explicit")?.as_bool()?;
    let selected = written.get("selected")?.as_bool()?;
    let next = updated.get("protection_posture");
    let next = next.as_str()?;
    let next_explicit = updated.get("protection_posture_explicit") == Value::Bool(true);
    let source = PyVal::Str("settings".to_owned());
    let text = |value: &str| PyVal::Str(value.to_owned());
    let mut events = Vec::new();
    if previous != next || (selected && next_explicit && !previous_explicit) {
        events.push((
            "guard.protection.posture_selected",
            vec![
                ("previous", text(previous)),
                ("value", text(next)),
                ("source", source.clone()),
                ("auto", PyVal::Bool(false)),
            ],
        ));
        if next == "watch" {
            events.push((
                "guard.protection.watch_entered",
                vec![("previous", text(previous)), ("source", source.clone())],
            ));
        } else if previous == "watch" {
            events.push((
                "guard.protection.watch_reverted",
                vec![("value", text(next)), ("source", source.clone())],
            ));
        }
    }
    let Value::Object(before) = written.get("harness_postures")? else {
        return None;
    };
    let after = updated.map("harness_postures");
    let mut harnesses: Vec<&String> = before.keys().chain(after.keys()).collect();
    harnesses.sort();
    harnesses.dedup();
    for harness in harnesses {
        let was = before.get(harness).and_then(Value::as_str);
        let now = after.get(harness).and_then(Value::as_str);
        if was == now {
            continue;
        }
        events.push((
            "guard.protection.harness_posture_selected",
            vec![
                ("harness", text(harness)),
                (
                    "previous",
                    text(was.filter(|v| !v.is_empty()).unwrap_or("inherit")),
                ),
                (
                    "value",
                    text(now.filter(|v| !v.is_empty()).unwrap_or("inherit")),
                ),
                ("source", source.clone()),
                ("auto", PyVal::Bool(false)),
            ],
        ));
    }
    for (event_name, fields) in events {
        let payload = PyVal::Dict(
            fields
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        );
        reads
            .store_write(
                config,
                "add_event",
                json!({
                    "event_name": event_name,
                    "payload_json": dumps(&payload)?,
                    "occurred_at": now_seconds()?,
                }),
            )
            .ok()?;
    }
    Some(())
}

/// `_requeue_cloud_review_privacy_projection(store, level=..., changed_at=_now())`.
fn requeue_privacy_projection(config: &ReadConfig, reads: &NativeReads, level: &str) -> Option<()> {
    let changed_at = super::now_isoformat()?;
    let before = format!(
        "{{\"level\": {}, \"updated_at\": {}, \"requeued\": ",
        dumps(&PyVal::Str(level.to_owned()))?,
        dumps(&PyVal::Str(changed_at.clone()))?,
    );
    reads
        .store_write(
            config,
            "requeue_pending_review_events_with_marker",
            json!({
                "changed_at": changed_at,
                "marker_key": PRIVACY_PROJECTION_MARKER,
                "marker_json_parts": [before, "}"],
                "require_binding": false,
                "only_retry_identity_drift": false,
                "request_ids": null,
                "request_snapshots": null,
                "native_replay": false,
            }),
        )
        .ok()?;
    Some(())
}

/// `_hand_settings_to_cigar`: ask the resident for the context-assistance
/// status so it reads the saved settings now. Failures are ignored, as the
/// daemon suppresses them.
fn hand_settings_to_context_assistance(guard_home: &Path) {
    let Ok(home) = std::fs::canonicalize(guard_home) else {
        return;
    };
    let Ok(state_dir) = std::fs::canonicalize(home.join("native-runtime")) else {
        return;
    };
    let frame = json!({
        "operation": "context_assistance",
        "deadline_budget_ms": CONTEXT_ASSISTANCE_BUDGET_MS,
        "request": {
            "schema": "guard-context-assistance-request.v1",
            "request_id": format!(
                "daemon-edge-context-assistance-{}",
                CONTEXT_REQUEST_IDS.fetch_add(1, Ordering::Relaxed)
            ),
            "query": {"kind": "status", "guard_home": home, "input": {}},
        },
    });
    if let Ok(encoded) = serde_json::to_vec(&frame) {
        let _ = crate::managed_resident::client_request(
            &state_dir,
            &encoded,
            CONTEXT_ASSISTANCE_TIMEOUT,
        );
    }
}

fn lookup<'a>(payload: &'a [(String, PyVal)], key: &str) -> Option<&'a PyVal> {
    payload
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

/// Python truthiness of a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// `datetime.now(timezone.utc).replace(microsecond=0).isoformat()`.
fn now_seconds() -> Option<String> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    micros_to_utc_isoformat(
        i64::try_from(seconds).ok()?.checked_mul(1_000_000)?,
        "+00:00",
    )
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_settings_write_tests.rs"]
mod tests;
