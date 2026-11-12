//! Replays `cursor_hook_config_vectors.json`, recorded from the original Python
//! helpers, through the native kind. Steps Python keeps (the live-script path
//! checks and the preToolUse matcher regex) are applied from the recorded
//! `existing` and `guards`, the way the Python shim applies them.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use crate::cursor_hook_config::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../testdata/cursor/cursor_hook_config_vectors.json");
const SCHEMA: &str = "guard-cursor-hook-config-vectors.v1";

fn strings(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("string list")
        .iter()
        .map(|item| item.as_str().expect("string").to_string())
        .collect()
}

fn request(case: &Value) -> Value {
    let mut request = Map::new();
    for key in ["op", "windows", "long_paths"] {
        request.insert(key.to_string(), case[key].clone());
    }
    for (key, value) in case["request"].as_object().expect("request object") {
        request.insert(key.clone(), value.clone());
    }
    Value::Object(request)
}

fn replay_commands(answer: &Value, existing: &BTreeSet<String>) -> Value {
    let kept: Vec<&Value> = answer["commands"]
        .as_array()
        .expect("commands")
        .iter()
        .filter(|found| existing.contains(found["script"].as_str().expect("script")))
        .collect();
    let commands: Vec<&Value> = kept.iter().map(|found| &found["command"]).collect();
    let frozen = kept.iter().any(|found| found["frozen"] == json!(true));
    json!({ "commands": commands, "frozen": frozen })
}

fn replay_intercept(answer: &Value, existing: &BTreeSet<String>, guards: &Value) -> Value {
    let Some(events) = answer["events"].as_array() else {
        assert!(answer["events"].is_null());
        return json!({ "intercept": false });
    };
    let guards: Vec<u64> = guards
        .as_array()
        .expect("guards")
        .iter()
        .map(|index| index.as_u64().expect("index"))
        .collect();
    let intercept = events.iter().all(|event| {
        let name = event[0].as_str().expect("event");
        event[1]
            .as_array()
            .expect("candidates")
            .iter()
            .any(|candidate| {
                let index = candidate[0].as_u64().expect("index");
                existing.contains(candidate[1].as_str().expect("script"))
                    && (name != "preToolUse" || guards.contains(&index))
            })
    });
    json!({ "intercept": intercept })
}

fn replay_install(answer: &Value, case: &Value) -> Value {
    if let Some(error) = answer.get("error") {
        return json!({ "error": error });
    }
    let payload = &case["request"]["payload"];
    let source = if payload["hooks"].is_object() {
        &payload["hooks"]
    } else {
        payload
    };
    let managed = case["managed_entries"].as_array().expect("managed entries");
    let hooks: Vec<Value> = answer["hooks"]
        .as_array()
        .expect("hooks")
        .iter()
        .map(|spec| {
            let event = spec[0].as_str().expect("event");
            let Some(kept) = spec[1].as_array() else {
                return json!([event, source[event]]);
            };
            let mut entries: Vec<Value> = kept
                .iter()
                .map(|index| source[event][index.as_u64().expect("index") as usize].clone())
                .collect();
            if spec[2] == json!(true) {
                let entry = managed
                    .iter()
                    .find(|pair| pair[0] == json!(event))
                    .expect("managed");
                entries.push(entry[1].clone());
            }
            json!([event, entries])
        })
        .collect();
    json!({ "version": answer["version"], "hooks": hooks })
}

#[test]
fn every_recorded_case_replays() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(document["schema"], json!(SCHEMA));
    let cases = document["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 210);
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let mut answer = dispatch(&request(case)).unwrap_or_else(|error| panic!("{name}: {error}"));
        let reported = strings(&answer["short_tokens"]);
        assert!(
            strings(&case["short_tokens"]).is_subset(&reported),
            "{name}: short tokens {reported:?}"
        );
        answer
            .as_object_mut()
            .expect("answer")
            .remove("short_tokens");
        let observed = match case["op"].as_str().expect("op") {
            "commands" => replay_commands(&answer, &strings(&case["existing"])),
            "intercept" => replay_intercept(&answer, &strings(&case["existing"]), &case["guards"]),
            "install" => replay_install(&answer, case),
            _ => answer,
        };
        assert_eq!(observed, case["expect"], "{name}");
    }
}

#[test]
fn a_short_name_resolves_only_once_python_sends_it() {
    let command = "C:\\PYTHON~1\\python.exe -I C:\\Users\\GUARD-~1\\HOL-GU~1.PY";
    let mut ask = json!({"op": "command", "windows": true, "long_paths": {}, "command": command});
    let first = dispatch(&ask).expect("answer");
    assert_eq!(first["structured"], json!(false));
    assert_eq!(
        first["short_tokens"],
        json!([
            "C:\\PYTHON~1\\python.exe",
            "C:\\Users\\GUARD-~1\\HOL-GU~1.PY"
        ])
    );
    ask["long_paths"] =
        json!({"C:\\Users\\GUARD-~1\\HOL-GU~1.PY": "C:\\Users\\g u\\hol-guard-cursor-hook.py"});
    let second = dispatch(&ask).expect("answer");
    assert_eq!(second["structured"], json!(true));
    assert_eq!(
        second["script"],
        json!("C:\\Users\\g u\\hol-guard-cursor-hook.py")
    );
}

#[test]
fn malformed_requests_are_refused() {
    let base = |op: &str| json!({"op": op, "windows": false, "long_paths": {}});
    let with = |op: &str, extra: Value| {
        let mut request = base(op);
        for (key, value) in extra.as_object().expect("extra") {
            request[key] = value.clone();
        }
        request
    };
    let payload = json!({"version": 1, "hooks": {"stop": []}});
    let install = |payload: &Value, top: Value, hooks: Value, managed: Value| {
        with(
            "install",
            json!({"payload": payload, "top_keys": top, "hooks_keys": hooks, "managed": managed, "script": "/s"}),
        )
    };
    let refused = [
        json!([]),
        json!({"windows": false, "long_paths": {}, "command": "x"}),
        with("unknown", json!({"command": "x"})),
        base("command"),
        with("command", json!({"command": "x", "extra": 1})),
        json!({"op": "command", "windows": "no", "long_paths": {}, "command": "x"}),
        json!({"op": "command", "windows": true, "long_paths": {"C:\\A~1": 1}, "command": "x"}),
        with("entries", json!({"entries": [], "command": 7})),
        with("commands", json!({"hooks": {"stop": []}})),
        with("intercept", json!({"hooks": [["stop"]]})),
        with("intercept", json!({"hooks": [[1, []]]})),
        with("script", json!({"source": null})),
        install(&json!([]), json!([]), json!(null), json!([])),
        install(&payload, json!(["hooks"]), json!(["stop"]), json!([])),
        install(
            &payload,
            json!(["version", "hooks", "hooks"]),
            json!(["stop"]),
            json!([]),
        ),
        install(
            &payload,
            json!(["version", "hooks"]),
            json!(null),
            json!([]),
        ),
        install(&json!({"stop": []}), json!(["stop"]), json!([]), json!([])),
        install(
            &payload,
            json!(["version", "hooks"]),
            json!(["stop"]),
            json!([["stop", "a"], ["stop", "b"]]),
        ),
        install(
            &payload,
            json!(["version", "hooks"]),
            json!(["stop"]),
            json!([["beforeWriteFile", "a"]]),
        ),
        install(
            &payload,
            json!(["version", "hooks"]),
            json!(["stop"]),
            json!([["stop"]]),
        ),
    ];
    for request in refused {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
