//! Unit tests for the daemon lifecycle primitives and the request protocol.

use std::collections::BTreeMap;

use guard_contracts::{DaemonLifecycleDecisionRequestV1, DAEMON_LIFECYCLE_REQUEST_SCHEMA};
use serde_json::{json, Value};

use crate::daemon_lifecycle_decision_op::{decide, evaluate_daemon_lifecycle_decision};
use crate::daemon_lifecycle_text::{
    norm_path, ntpath_basename, py_splitlines, python_int, shlex_split,
};

fn request(query: Value, facts: Value) -> DaemonLifecycleDecisionRequestV1 {
    request_on("posix", query, facts)
}

fn request_on(platform: &str, query: Value, facts: Value) -> DaemonLifecycleDecisionRequestV1 {
    serde_json::from_value(json!({
        "schema": DAEMON_LIFECYCLE_REQUEST_SCHEMA,
        "request_id": "unit",
        "platform": platform,
        "facts": facts,
        "query": query,
    }))
    .unwrap()
}

#[test]
fn shlex_matches_posix_rules() {
    let split = |text: &str| shlex_split(text);
    assert_eq!(split("a 'b c' \"d\\\"e\"").unwrap(), ["a", "b c", "d\"e"]);
    assert_eq!(split("''").unwrap(), [""]);
    assert_eq!(split("a\\ b").unwrap(), ["a b"]);
    assert_eq!(split("  ").unwrap(), Vec::<String>::new());
    assert!(split("'open").is_none());
    assert!(split("trailing\\").is_none());
}

#[test]
fn ntpath_basename_names_launchers() {
    assert_eq!(
        ntpath_basename("C:\\Program Files\\HOL\\Hol-Guard.EXE"),
        "Hol-Guard.EXE"
    );
    assert_eq!(ntpath_basename("\\\\srv\\hol-guard"), "");
    assert_eq!(ntpath_basename("c:hol-guard"), "hol-guard");
    assert_eq!(ntpath_basename("/usr/local/bin/hol-guard"), "hol-guard");
}

#[test]
fn python_int_follows_int_text_rules() {
    assert_eq!(python_int(" 4_900 "), Some(4900));
    assert_eq!(python_int("+7"), Some(7));
    assert_eq!(python_int("4__9"), None);
    assert_eq!(python_int("_49"), None);
    assert_eq!(python_int("1e3"), None);
    assert_eq!(python_int("99999999999999999999"), None);
    assert_eq!(python_int("\u{ff15}\u{ff14}\u{ff11}\u{ff12}"), Some(5412));
    assert_eq!(python_int("\u{ff15}_\u{ff14}\u{ff11}\u{ff12}"), Some(5412));
    assert_eq!(python_int("\u{0665}\u{0664}\u{0661}\u{0662}"), Some(5412));
    assert_eq!(python_int("\u{00b2}"), None);
}

#[test]
fn splitlines_and_paths_follow_python() {
    assert_eq!(py_splitlines("a\r\nb\nc\u{2028}d"), ["a", "b", "c", "d"]);
    assert_eq!(norm_path("/h//dup/./x/"), "/h/dup/x");
    assert_eq!(norm_path("///a"), "/a");
    assert_eq!(norm_path("//a"), "//a");
    assert_eq!(norm_path(""), ".");
}

#[test]
fn missing_facts_are_requested_and_never_assumed() {
    let query = json!({"check": "locator_shape", "payload": {"pid": 9}});
    let reply = decide(&request(query.clone(), json!({})));
    assert_eq!(reply, json!({"need": "facts", "keys": ["pid_running:9"]}));
    let answered = decide(&request(query, json!({"pid_running:9": false})));
    assert_eq!(answered, json!({"valid": false}));
}

#[test]
fn unicode_decimal_digits_select_the_configured_and_command_ports() {
    let configured = decide(&request(
        json!({"check": "configured_port", "env_port": "\u{ff15}\u{ff14}\u{ff11}\u{ff12}", "guard_home": "/h"}),
        json!({}),
    ));
    assert_eq!(configured["port"], 5412);
    let command = decide(&request(
        json!({
            "check": "inspect_command",
            "command": "hol-guard daemon --serve --port \u{0665}\u{0664}\u{0661}\u{0662} --guard-home /h",
        }),
        json!({}),
    ));
    assert_eq!(command["port"], 5412);
    assert_eq!(command["guard_home"], "/h");
}

/// Python stops asking for lifecycle facts after eight rounds.
const PYTHON_NEED_ROUNDS: usize = 8;

#[test]
fn windows_inventory_collects_every_missing_argv_in_one_round() {
    let entries: Vec<Value> = (0..10)
        .map(|index| {
            json!([
                index + 1,
                format!(
                    "hol-guard.exe daemon --serve --port {} --guard-home C:\\g",
                    5000 + index
                )
            ])
        })
        .collect();
    let query = json!({
        "check": "process_inventory",
        "guard_home": "C:\\g",
        "implicit_home": "C:\\g",
        "own_pid": 0,
        "parent_pid": 0,
        "frozen_runtime": false,
        "entries": entries,
    });
    let mut facts = serde_json::Map::new();
    let mut rounds = 0;
    let payload = loop {
        rounds += 1;
        assert!(
            rounds <= PYTHON_NEED_ROUNDS,
            "inventory still asking after {PYTHON_NEED_ROUNDS} rounds"
        );
        let reply = decide(&request_on(
            "nt",
            query.clone(),
            Value::Object(facts.clone()),
        ));
        if reply.get("need").and_then(Value::as_str) != Some("facts") {
            break reply;
        }
        let keys = reply["keys"].as_array().expect("fact keys");
        if rounds == 1 {
            assert_eq!(keys.len(), 10, "first round keys: {keys:?}");
            assert!(keys
                .iter()
                .all(|key| { key.as_str().is_some_and(|text| text.starts_with("argv:")) }));
        }
        for key in keys {
            let key = key.as_str().unwrap();
            if let Some(command) = key.strip_prefix("argv:") {
                let parts: Vec<&str> = command.split(' ').collect();
                facts.insert(key.to_owned(), json!(parts));
            } else if let Some(path) = key.strip_prefix("resolve:") {
                facts.insert(key.to_owned(), json!(path));
            } else {
                facts.insert(key.to_owned(), Value::Null);
            }
        }
    };
    assert_eq!(payload["known"], true);
    assert_eq!(payload["processes"].as_array().unwrap().len(), 10);
}

#[test]
fn a_supplied_null_argv_still_makes_a_guard_daemon_unknown() {
    let command = "hol-guard.exe daemon --serve --port 9";
    let reply = decide(&request_on(
        "nt",
        json!({
            "check": "process_inventory",
            "guard_home": "C:\\g",
            "implicit_home": "C:\\g",
            "own_pid": 0,
            "parent_pid": 0,
            "frozen_runtime": false,
            "entries": [[4, command]],
        }),
        json!({format!("argv:{command}"): null}),
    ));
    assert_eq!(reply, json!({"known": false, "processes": []}));
}

#[test]
fn replies_bind_the_request_and_reject_other_schemas() {
    let good = request(
        json!({"check": "ephemeral_home", "guard_home": "/tmp/pytest-1"}),
        json!({}),
    );
    let bytes = evaluate_daemon_lifecycle_decision(&good).unwrap();
    let reply: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["payload"], json!({"ephemeral": true}));
    assert!(reply["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    let mut wrong = good;
    wrong.schema = "other".to_owned();
    let reply: Value =
        serde_json::from_slice(&evaluate_daemon_lifecycle_decision(&wrong).unwrap()).unwrap();
    assert_eq!(reply["status"], "error");
    assert_eq!(reply["payload"], Value::Null);
}

#[test]
fn unknown_fields_are_rejected() {
    let bad = serde_json::from_value::<DaemonLifecycleDecisionRequestV1>(json!({
        "schema": DAEMON_LIFECYCLE_REQUEST_SCHEMA,
        "query": {"check": "ephemeral_home", "guard_home": "/x", "extra": 1},
    }));
    assert!(bad.is_err());
    let _ = BTreeMap::<String, Value>::new();
}

#[test]
fn live_state_gate_requires_a_running_pid() {
    let query = json!({"check": "live_state_gate", "payload": {"compatibility_version": 2, "pid": 7, "port": 4781}});
    let running = decide(&request(query.clone(), json!({"pid_running:7": true})));
    assert_eq!(running, json!({"ok": true, "port": 4781, "pid": 7}));
    let gone = decide(&request(query, json!({"pid_running:7": false})));
    assert_eq!(gone, json!({"ok": false}));
}

#[test]
fn request_round_trips_unchanged_so_python_and_rust_digest_the_same_bytes() {
    let original = json!({
        "schema": DAEMON_LIFECYCLE_REQUEST_SCHEMA,
        "request_id": "unit",
        "platform": "posix",
        "facts": {},
        "query": {
            "check": "process_inventory",
            "guard_home": "/g",
            "implicit_home": "/h",
            "own_pid": 1,
            "parent_pid": 2,
            "frozen_runtime": false,
            "ps_output": "1 x",
        },
    });
    let parsed: DaemonLifecycleDecisionRequestV1 =
        serde_json::from_value(original.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), original);
}
