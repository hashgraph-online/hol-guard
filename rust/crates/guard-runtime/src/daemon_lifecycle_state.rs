//! Health payload, daemon state and approval-center locator classification.

use crate::approval_gate_state::constant_time_eq;
use guard_contracts::{
    DaemonHealthzCurrentQueryV1, DaemonHealthzHomeQueryV1, DaemonIdentityBindingQueryV1,
    DaemonLocatorBindingQueryV1, DaemonPayloadQueryV1, DaemonStateShapeQueryV1,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::daemon_lifecycle_facts::{as_int, is_compatible, Ctx};
use crate::daemon_lifecycle_text::py_strip;

const REQUIRED_TABLE: &str = "guard_connect_states";

fn non_blank(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !py_strip(text).is_empty())
}

/// Parse a health body. `None` is the JSON decode failure the caller surfaces.
fn health_object(raw: &str) -> Result<Option<Map<String, Value>>, ()> {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(object)) => Ok(Some(object)),
        Ok(_) => Ok(None),
        Err(_) => Err(()),
    }
}

fn tables_current(payload: &Map<String, Value>) -> bool {
    match payload.get("tables") {
        None | Some(Value::Null) => true,
        Some(Value::Array(tables)) => tables
            .iter()
            .any(|table| table.as_str() == Some(REQUIRED_TABLE)),
        Some(_) => false,
    }
}

pub(crate) fn healthz_current(query: &DaemonHealthzCurrentQueryV1) -> Value {
    match health_object(&query.raw_payload) {
        Err(()) => json!({"valid_json": false}),
        Ok(None) => json!({"valid_json": true, "result": false}),
        Ok(Some(payload)) => {
            let current =
                is_compatible(payload.get("compatibility_version")) && tables_current(&payload);
            json!({"valid_json": true, "result": current})
        }
    }
}

pub(crate) fn healthz_home(ctx: &Ctx, query: &DaemonHealthzHomeQueryV1) -> Value {
    match health_object(&query.raw_payload) {
        Err(()) => json!({"valid_json": false}),
        Ok(None) => json!({"valid_json": true, "result": false}),
        Ok(Some(payload)) => {
            let matches = non_blank(payload.get("guard_home"))
                .is_some_and(|home| ctx.same_path(home, &query.guard_home));
            json!({"valid_json": true, "result": matches})
        }
    }
}

/// `_looks_like_guard_daemon_state`.
pub(crate) fn state_shape(ctx: &Ctx, query: &DaemonStateShapeQueryV1) -> Value {
    let Some(payload) = query.payload.as_object() else {
        return json!({"result": false});
    };
    let shaped = is_compatible(payload.get("compatibility_version"))
        && non_blank(payload.get("source_root")).is_some()
        && non_blank(payload.get("runtime_fingerprint")).is_some();
    if !shaped {
        return json!({"result": false});
    }
    let result = match non_blank(payload.get("guard_home")) {
        Some(home) => ctx.same_path(home, &query.guard_home),
        None => true,
    };
    json!({"result": result})
}

/// `secrets.compare_digest` on two strings; non-ASCII text cannot be compared.
fn digests_equal(left: &str, right: &str) -> bool {
    left.is_ascii() && right.is_ascii() && constant_time_eq(left.as_bytes(), right.as_bytes())
}

/// `_load_authenticated_daemon_identity`: the token must bind the state.
pub(crate) fn identity_binding(query: &DaemonIdentityBindingQueryV1) -> Value {
    let payload = query.payload.as_object();
    let expected = payload
        .and_then(|object| object.get("auth_token_id"))
        .and_then(Value::as_str);
    let state_id = payload
        .and_then(|object| object.get("state_id"))
        .and_then(Value::as_str);
    let bound = match (&query.auth_token, expected, state_id) {
        (Some(token), Some(expected), Some(state_id)) if !state_id.is_empty() => {
            let actual = hex::encode(Sha256::digest(token.as_bytes()));
            digests_equal(&actual, expected)
        }
        _ => false,
    };
    json!({"bound": bound})
}

/// The state gates of `_live_guard_daemon_identity` that precede the health probe.
pub(crate) fn live_state_gate(ctx: &Ctx, query: &DaemonPayloadQueryV1) -> Value {
    let refused = json!({"ok": false});
    let Some(payload) = query.payload.as_object() else {
        return refused;
    };
    if !is_compatible(payload.get("compatibility_version")) {
        return refused;
    }
    let Some(port) = payload.get("port").and_then(as_int) else {
        return refused;
    };
    let Some(pid) = payload.get("pid").and_then(as_int).filter(|pid| *pid > 0) else {
        return refused;
    };
    if !ctx.boolean("pid_running", pid) {
        return refused;
    }
    json!({"ok": true, "port": port, "pid": pid})
}

/// `read_approval_center_locator` up to the command-identity check.
pub(crate) fn locator_shape(ctx: &Ctx, query: &DaemonPayloadQueryV1) -> Value {
    let refused = json!({"valid": false});
    let Some(payload) = query.payload.as_object() else {
        return refused;
    };
    let Some(pid) = payload.get("pid").and_then(as_int).filter(|pid| *pid > 0) else {
        return refused;
    };
    if !ctx.boolean("pid_running", pid) {
        return refused;
    }
    let all_strings = [
        "daemon_url",
        "approval_url_base",
        "started_at",
        "state_path",
        "guard_home",
    ]
    .iter()
    .all(|key| payload.get(*key).is_some_and(Value::is_string));
    if !all_strings {
        return refused;
    }
    json!({"valid": true, "pid": pid})
}

/// Whether the authenticated state vouches for a locator whose process
/// command did not prove the guard home.
pub(crate) fn locator_binding(query: &DaemonLocatorBindingQueryV1) -> Value {
    let state = query.state.as_object();
    let same_pid = state
        .and_then(|object| object.get("pid"))
        .and_then(Value::as_f64)
        .is_some_and(|state_pid| state_pid == query.pid as f64);
    let port = state.and_then(|object| object.get("port")).and_then(as_int);
    let bound =
        same_pid && port.is_some_and(|port| query.daemon_url == format!("http://127.0.0.1:{port}"));
    json!({"bound": bound})
}
