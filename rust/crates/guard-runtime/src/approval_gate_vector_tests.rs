//! Replays the language-neutral approval-gate parity vectors recorded from the
//! retired Python implementation against the Rust authority.
//!
//! The same file is replayed through the resident by
//! `tests/test_guard_approval_gate_native_parity.py`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::evaluate_approval_gate_request;
use crate::approval_gate_state::epoch;

const VECTORS: &str = include_str!("../../../../tests/fixtures/approval_gate/parity_vectors.json");
const SESSION_SIGNAL: &str = "sid=parity-vector";

fn temp_home(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "approval_gate_vectors_{}_{}_{}",
        std::process::id(),
        tag,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Resolves `{"$totp": {secret, at, offset}}` markers into live codes.
fn resolve_input(input: &Value, secrets: &HashMap<String, String>) -> Value {
    let Some(map) = input.as_object() else {
        return input.clone();
    };
    let mut out = Map::new();
    for (key, value) in map {
        let resolved = match value.get("$totp") {
            Some(spec) => {
                let secret = &secrets[spec["secret"].as_str().unwrap()];
                let at = epoch(spec["at"].as_str());
                let counter = (at / 30.0).floor() as i64 + spec["offset"].as_i64().unwrap();
                Value::String(crate::totp::totp_code_at_counter(secret, counter as u64))
            }
            None => value.clone(),
        };
        out.insert(key.clone(), resolved);
    }
    Value::Object(out)
}

/// Delete a file or a directory tree; an absent path is already deleted.
fn remove_path(path: &Path) {
    let removed = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(error) => Err(error),
    };
    if let Err(error) = removed {
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound, "{path:?}");
    }
}

fn apply_file_step(home: &Path, spec: &Value) {
    if let Some(name) = spec.get("write").and_then(Value::as_str) {
        std::fs::write(home.join(name), spec["content"].as_str().unwrap()).unwrap();
    } else if let Some(name) = spec.get("delete").and_then(Value::as_str) {
        remove_path(&home.join(name));
    } else if let Some(patch) = spec.get("patch_state").and_then(Value::as_object) {
        let path = home.join("approval-gate.json");
        let mut state: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for (key, value) in patch {
            state[key] = value.clone();
        }
        std::fs::write(path, state.to_string()).unwrap();
    }
}

/// `<random>` in the expectation matches any non-empty minted value.
fn matches(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::String(want), Value::String(got)) => match want.find("<random>") {
            Some(at) => got.len() > at && got.starts_with(&want[..at]),
            None => want == got,
        },
        (Value::Object(want), Value::Object(got)) => {
            want.len() == got.len()
                && want
                    .iter()
                    .all(|(key, value)| got.get(key).is_some_and(|other| matches(value, other)))
        }
        _ => expected == actual,
    }
}

fn request_for(home: &Path, call: &Value, input: Option<Value>, grant: Option<Value>) -> Value {
    let params = match &call["params"] {
        object @ Value::Object(_) => object.clone(),
        _ => json!({}),
    };
    let mut request = json!({
        "schema": "guard-approval-gate-request.v1",
        "request_id": "vector",
        "guard_home": home.to_string_lossy(),
        "method": call["method"],
        "params": params,
        "strict": call["strict"].as_bool().unwrap_or(false),
        "now": call["now"],
        "session_signals": [SESSION_SIGNAL],
    });
    for (field, value) in [
        ("approval_gate_input", input),
        ("approval_gate_grant", grant),
        ("purpose", call.get("purpose").cloned()),
        ("duration_seconds", call.get("duration_seconds").cloned()),
        ("device_label", call.get("device_label").cloned()),
    ] {
        if let Some(value) = value.filter(|v| !v.is_null()) {
            request[field] = value;
        }
    }
    request
}

fn scenarios() -> Vec<Value> {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(document["schema"], "guard-approval-gate-parity-vectors.v1");
    document["scenarios"].as_array().unwrap().clone()
}

/// The grant table is process-global and pruned against each request's clock,
/// so scenarios (which all start at the same fixed instant) run one at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn replay(scenario_name: &str) {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let scenario = scenarios()
        .into_iter()
        .find(|s| s["name"] == scenario_name)
        .unwrap_or_else(|| panic!("missing scenario {scenario_name}"));
    let mut failures: Vec<String> = Vec::new();
    {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(name);
        let mut grants: HashMap<String, Value> = HashMap::new();
        let mut secrets: HashMap<String, String> = HashMap::new();
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}[{index}] {}", step["call"]["method"]);
            let call = &step["call"];
            if let Some(file) = call.get("file") {
                apply_file_step(&home, file);
                continue;
            }
            let input = call.get("input").map(|v| resolve_input(v, &secrets));
            let grant = call
                .get("grant")
                .and_then(Value::as_str)
                .map(|g| grants[g].clone());
            let request = request_for(&home, call, input, grant);
            let typed = serde_json::from_value(request).unwrap_or_else(|e| panic!("{label}: {e}"));
            let bytes = evaluate_approval_gate_request(&typed).unwrap();
            let result: Value = serde_json::from_slice(&bytes).unwrap();
            let expect = &step["expect"];
            let mut problems = Vec::new();
            for field in ["status", "code"] {
                if result[field] != expect[field] {
                    problems.push(format!("{field}: {} != {}", result[field], expect[field]));
                }
            }
            if expect["status"] == "error" {
                for field in ["error_status", "message"] {
                    if result[field] != expect[field] {
                        problems.push(format!("{field}: {} != {}", result[field], expect[field]));
                    }
                }
            } else if result["status"] == "ok" {
                let payload = &result["payload"];
                if !matches(&expect["payload"], payload) {
                    problems.push(format!("payload: {payload} != {}", expect["payload"]));
                }
                if let (Some(bind), Some(grant)) = (call["bind"].as_str(), payload.get("grant")) {
                    grants.insert(bind.to_owned(), grant.clone());
                }
                if let Some(bind) = call["secret_bind"].as_str() {
                    let key = payload["manual_key"].as_str().unwrap();
                    secrets.insert(bind.to_owned(), key.to_owned());
                }
            }
            if !problems.is_empty() {
                failures.push(format!("{label}: {}", problems.join("; ")));
            }
        }
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

macro_rules! scenario_tests {
    ($($name:ident),+ $(,)?) => {
        $(#[test] fn $name() { replay(stringify!($name)); })+

        #[test]
        fn every_recorded_scenario_has_a_test() {
            let covered = [$(stringify!($name)),+];
            let recorded: Vec<String> = scenarios()
                .iter()
                .map(|s| s["name"].as_str().unwrap().to_owned())
                .collect();
            assert_eq!(recorded.len(), covered.len());
            for name in &recorded {
                assert!(covered.contains(&name.as_str()), "untested scenario {name}");
            }
        }
    };
}

scenario_tests!(
    unconfigured_home,
    enable_validation,
    password_gate_basics,
    strict_all_decisions,
    cooldown_flow,
    lockout,
    extension_control_and_cli_trust,
    rotation_revokes_grants,
    corrupt_state_fails_closed,
    totp_lifecycle,
    totp_lockout_and_missing_secret,
    totp_no_totp_enabled_no_code_paths,
    verifier_and_misc,
);

/// The recent-TOTP window is bound to the caller's session signals, so a code
/// satisfied in one session never satisfies another.
#[test]
fn recent_totp_is_bound_to_session_signals() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let home = temp_home("session_binding");
    const AT: &str = "2026-04-11T00:00:00+00:00";
    const LATER: &str = "2026-04-11T00:00:50+00:00";
    let send = |method: &str, signals: &str, now: &str, params: Value, input: Value| -> Value {
        let mut request = json!({
            "schema": "guard-approval-gate-request.v1",
            "request_id": "binding",
            "guard_home": home.to_string_lossy(),
            "method": method,
            "params": params,
            "strict": true,
            "now": now,
            "session_signals": [signals],
            "purpose": "policy_clear",
        });
        if !input.is_null() {
            request["approval_gate_input"] = input;
        }
        let typed = serde_json::from_value(request).unwrap();
        serde_json::from_slice(&evaluate_approval_gate_request(&typed).unwrap()).unwrap()
    };
    let password = "correct-password";
    let enabled = send(
        "update_settings",
        "sid=a",
        AT,
        json!({"enabled": true, "new_password": password, "confirm_password": password}),
        Value::Null,
    );
    assert_eq!(enabled["status"], "ok", "{enabled}");
    let begun = send(
        "begin_totp_enrollment",
        "sid=a",
        AT,
        json!({}),
        json!({"password": password}),
    );
    let secret = begun["payload"]["manual_key"].as_str().unwrap().to_owned();
    let code = |at: &str, offset: i64| {
        let counter = (epoch(Some(at)) / 30.0).floor() as i64 + offset;
        crate::totp::totp_code_at_counter(&secret, counter as u64)
    };
    let confirmed = send(
        "confirm_totp_enrollment",
        "sid=a",
        AT,
        json!({}),
        json!({"password": password, "totp_code": code(AT, 0)}),
    );
    assert_eq!(confirmed["status"], "ok", "{confirmed}");
    let verified = send(
        "require_high_risk",
        "sid=a",
        "2026-04-11T00:00:40+00:00",
        json!({}),
        json!({"totp_code": code("2026-04-11T00:00:40+00:00", 0)}),
    );
    assert_eq!(verified["status"], "ok", "{verified}");
    let satisfied = |signals: &str| {
        send(
            "recent_totp_satisfied",
            signals,
            LATER,
            json!({}),
            Value::Null,
        )["payload"]["satisfied"]
            .clone()
    };
    assert_eq!(satisfied("sid=a"), json!(true));
    assert_eq!(satisfied("sid=b"), json!(false));
    let _ = std::fs::remove_dir_all(&home);
}

/// The caller's session signals are part of the contract: a request without
/// them is rejected rather than bound to the resident's own process.
#[test]
fn a_request_without_session_signals_is_a_contract_error() {
    let request = json!({
        "schema": "guard-approval-gate-request.v1",
        "request_id": "missing-signals",
        "guard_home": "/synthetic",
        "method": "public_config",
    });
    assert!(
        serde_json::from_value::<guard_contracts::ApprovalGateRequestV1>(request.clone()).is_err()
    );
    let mut with_signals = request;
    with_signals["session_signals"] = json!([]);
    assert!(serde_json::from_value::<guard_contracts::ApprovalGateRequestV1>(with_signals).is_ok());
}
