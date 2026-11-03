//! Replays `harness_hook_settings_vectors.json`, recorded from the original
//! Muse and Devin adapters, through the native kind. Each `hooks` object is
//! rebuilt from the request's own values and the recorded bridge command, the
//! way the Python shim rebuilds it.

use serde_json::{json, Map, Value};

use crate::harness_hook_settings::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str =
    include_str!("../../testdata/harness_hook_settings/harness_hook_settings_vectors.json");
const SCHEMA: &str = "guard-harness-hook-settings-vectors.v1";
const CASES: usize = 124;

fn ask(op: &str, request: &Value) -> Result<Value, &'static str> {
    let mut args = request.as_object().expect("request object").clone();
    args.insert("op".to_owned(), json!(op));
    dispatch(&Value::Object(args))
}

fn index(value: &Value) -> usize {
    usize::try_from(value.as_u64().expect("index")).expect("usize")
}

/// One list from its plan, over the caller's entries.
fn rebuild(entries: &Value, plan: &Value, handler: &Value) -> Value {
    let rebuilt = plan.as_array().expect("plan").iter().map(|step| {
        if step.is_u64() {
            return entries[index(step)].clone();
        }
        if let Some(position) = step.get("entry") {
            let entry = &entries[index(position)];
            let hooks: Vec<Value> = step["hooks"]
                .as_array()
                .expect("hooks plan")
                .iter()
                .map(|item| match item {
                    Value::Null => handler.clone(),
                    own => entry["hooks"][index(own)].clone(),
                })
                .collect();
            let mut copy: Map<String, Value> = entry.as_object().expect("copied entry").clone();
            copy.insert("hooks".to_owned(), Value::Array(hooks));
            return Value::Object(copy);
        }
        assert!(!handler.is_null(), "a new group needs Guard's handler");
        let mut group = Map::new();
        group.insert("hooks".to_owned(), json!([handler]));
        if let Some(matcher) = step["matcher"].as_str() {
            group.insert("matcher".to_owned(), json!(matcher));
        }
        Value::Object(group)
    });
    Value::Array(rebuilt.collect())
}

fn handler(command: &str, guard: &Value) -> Value {
    let mut handler = json!({ "type": "command", "command": command, "timeout": guard["timeout"] });
    if let Some(status) = guard["status"].as_str() {
        handler["statusMessage"] = json!(status);
    }
    handler
}

/// The `[[event, value], ...]` pairs an answer rebuilds to.
fn replay(request: &Value, command: Option<&str>, answer: &Value) -> Value {
    if answer.get("error").is_some() {
        return answer.clone();
    }
    let hooks = &request["hooks"];
    let pairs: Vec<Value> = answer["hooks"]
        .as_array()
        .expect("events")
        .iter()
        .map(|row| {
            let event = row[0].as_str().expect("event");
            let guard = row.get(2).unwrap_or(&Value::Null);
            let handler = match command {
                Some(command) if !guard.is_null() => handler(command, guard),
                _ => Value::Null,
            };
            let value = match &row[1] {
                Value::Null => hooks[event].clone(),
                plan => rebuild(&hooks[event], plan, &handler),
            };
            json!([event, value])
        })
        .collect();
    json!({ "hooks": pairs })
}

#[test]
fn every_recorded_case_replays() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    assert_eq!(vectors["schema"], SCHEMA);
    let cases = vectors["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), CASES);
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let op = case["op"].as_str().expect("op");
        let answer = ask(op, &case["request"]).unwrap_or_else(|error| panic!("{name}: {error}"));
        let replayed = match op {
            "managed" => answer,
            _ => replay(&case["request"], case["command"].as_str(), &answer),
        };
        assert_eq!(replayed, case["expect"], "{name}");
    }
}

#[test]
fn install_plans_name_events_in_their_final_order() {
    let request = json!({
        "harness": "devin",
        "hooks": {"Stop": null, "PreToolUse": [{"hooks": [{"command": "x # HOL_GUARD_MANAGED_DEVIN"}]}]},
        "hooks_keys": ["Stop", "PreToolUse"],
        "wait_seconds": u64::MAX,
    });
    let answer = ask("install", &request).expect("answer");
    let tools = "^(exec|read|write|edit|apply_patch|notebook_read|notebook_edit|grep|glob|webfetch|mcp_call_tool|mcp__.*)$";
    let wait = json!({"timeout": 605, "status": null});
    let short = json!({"timeout": 30, "status": null});
    assert_eq!(
        answer["hooks"],
        json!([
            ["Stop", null, null],
            ["PreToolUse", [{"matcher": tools}], wait],
            ["PermissionRequest", [{"matcher": tools}], short],
            ["UserPromptSubmit", [{"matcher": null}], short],
            ["PostToolUse", [{"matcher": tools}], wait],
        ])
    );
}

#[test]
fn malformed_requests_are_refused() {
    let muse = |extra: Value| {
        let mut request =
            json!({"harness": "muse", "hooks": {}, "hooks_keys": [], "bridge_seconds": 30});
        for (key, value) in extra.as_object().expect("extra") {
            if value.is_null() && key != "hooks" && key != "hooks_keys" {
                request.as_object_mut().expect("object").remove(key);
            } else {
                request[key] = value.clone();
            }
        }
        request
    };
    let refused = [
        ("install", muse(json!({"harness": "zcode"}))),
        ("install", muse(json!({"harness": null}))),
        ("install", muse(json!({"bridge_seconds": null}))),
        ("install", muse(json!({"bridge_seconds": 30.5}))),
        ("install", muse(json!({"bridge_seconds": "30"}))),
        ("install", muse(json!({"bridge_seconds": i64::MAX}))),
        ("install", muse(json!({"wait_seconds": 30}))),
        ("install", muse(json!({"hooks_keys": null}))),
        (
            "install",
            muse(json!({"hooks": {"Stop": []}, "hooks_keys": []})),
        ),
        (
            "install",
            muse(json!({"hooks": {"Stop": []}, "hooks_keys": ["Stop", "Stop"]})),
        ),
        (
            "install",
            muse(json!({"hooks": {"Stop": []}, "hooks_keys": ["Start"]})),
        ),
        (
            "install",
            muse(json!({"hooks": {"Stop": []}, "hooks_keys": [7]})),
        ),
        ("install", muse(json!({"hooks": null, "hooks_keys": []}))),
        ("install", muse(json!({"hooks": [], "hooks_keys": []}))),
        ("prune", muse(json!({}))),
        (
            "prune",
            muse(json!({"hooks": null, "hooks_keys": null, "bridge_seconds": null})),
        ),
        ("managed", json!({"harness": "muse", "commands": "x"})),
        (
            "managed",
            json!({"harness": "muse", "commands": [], "extra": 1}),
        ),
        ("uninstall", muse(json!({}))),
    ];
    for (op, request) in refused {
        assert_eq!(ask(op, &request), Err(ERR_INVALID), "{op} {request}");
    }
    assert_eq!(dispatch(&json!([])), Err(ERR_INVALID));
    assert_eq!(dispatch(&json!({"harness": "muse"})), Err(ERR_INVALID));
}

#[test]
fn refusals_name_the_first_event_that_is_not_a_list() {
    let request = json!({
        "harness": "muse",
        "hooks": {"Stop": null, "雪": "x", "Custom": {}},
        "hooks_keys": ["Stop", "雪", "Custom"],
        "bridge_seconds": 30,
    });
    let answer = ask("install", &request).expect("answer");
    assert_eq!(
        answer,
        json!({"error": "harness_hook_settings_event_not_list", "event": "雪"})
    );
    let devin = json!({"harness": "devin", "hooks": "x", "hooks_keys": null, "wait_seconds": 0});
    let answer = ask("install", &devin).expect("answer");
    assert_eq!(
        answer,
        json!({"error": "harness_hook_settings_hooks_not_object", "event": null})
    );
}
