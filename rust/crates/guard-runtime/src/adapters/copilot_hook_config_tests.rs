//! Replays `copilot_hook_config_vectors.json`, recorded from the original
//! Python helpers, through the native kind. Hooks objects are rebuilt from the
//! request's own entries, the way the Python shim rebuilds them.

use serde_json::{json, Map, Value};

use crate::copilot_hook_config::{dispatch, list2cmdline, shlex_join};
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../testdata/copilot/copilot_hook_config_vectors.json");
const SCHEMA: &str = "guard-copilot-hook-config-vectors.v1";
const INTERPRETER: &str = "/nonexistent-guard/bin/python3";
const SCRIPT: &str = "/nonexistent-guard/home/managed/bounded-hooks/copilot.py";
const LEGACY: &str = "python -m codex_plugin_scanner.cli guard hook --harness copilot";

fn index(value: &Value) -> usize {
    usize::try_from(value.as_u64().expect("index")).expect("usize")
}

/// The workspace file as Python normalizes it: `{"version", "hooks"}`.
fn normalized(job: &Value, plan: &Value) -> Value {
    let payload = &job["payload"];
    let version = if plan["version"].as_bool().expect("version flag") {
        payload["version"].clone()
    } else {
        json!(1)
    };
    let hooks = match &plan["hooks"] {
        Value::Null => payload["hooks"].clone(),
        lists => {
            let keys = job["keys"].as_array().expect("keys");
            let hooks: Map<String, Value> = lists
                .as_array()
                .expect("lists")
                .iter()
                .map(|position| {
                    let key = keys[index(position)].as_str().expect("key");
                    (key.to_owned(), payload[key].clone())
                })
                .collect();
            Value::Object(hooks)
        }
    };
    json!({ "version": version, "hooks": hooks })
}

/// One hooks object after an install (`entry` set) or an uninstall.
fn apply(hooks: &Value, plan: &Value, entry: Option<&Value>) -> Value {
    let mut result = hooks.as_object().expect("hooks object").clone();
    for step in plan["events"].as_array().expect("events") {
        let event = step[0].as_str().expect("event");
        let source = hooks.get(event).and_then(Value::as_array);
        let mut kept: Vec<Value> = step[1]
            .as_array()
            .expect("kept")
            .iter()
            .map(|position| source.expect("event list")[index(position)].clone())
            .collect();
        match entry {
            Some(entry) => kept.push(entry.clone()),
            None if kept.is_empty() => {
                result.remove(event);
                continue;
            }
            None => {}
        }
        result.insert(event.to_owned(), Value::Array(kept));
    }
    Value::Object(result)
}

#[test]
fn replays_every_recorded_plan() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors");
    assert_eq!(document["schema"], SCHEMA);
    let cases = document["cases"].as_array().expect("cases");
    assert!(cases.len() >= 10);
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let request = &case["request"];
        let answer = dispatch(request).unwrap_or_else(|error| panic!("{name}: {error}"));
        let plans = answer["jobs"].as_array().expect("jobs");
        let jobs = request["jobs"].as_array().expect("request jobs");
        let expected = case["expect"].as_array().expect("expect");
        assert_eq!(plans.len(), jobs.len(), "{name}");
        for ((job, plan), expect) in jobs.iter().zip(plans).zip(expected) {
            assert_eq!(plan["bash"], expect["bash"], "{name} bash");
            assert_eq!(
                plan["powershell"], expect["powershell"],
                "{name} powershell"
            );
            let hooks = match job.get("hooks") {
                Some(hooks) => hooks.clone(),
                None => {
                    let payload = normalized(job, plan);
                    assert_eq!(payload, expect["payload"], "{name} payload");
                    payload["hooks"].clone()
                }
            };
            let entry = json!({
                "type": "command",
                "bash": plan["bash"],
                "powershell": plan["powershell"],
                "guard": true,
            });
            assert_eq!(
                apply(&hooks, plan, Some(&entry)),
                expect["install"],
                "{name} install"
            );
            assert_eq!(
                apply(&hooks, plan, None),
                expect["uninstall"],
                "{name} uninstall"
            );
        }
    }
}

fn plan_one(job: Value) -> Result<Value, &'static str> {
    let request =
        json!({ "op": "plan", "interpreter": INTERPRETER, "script": SCRIPT, "jobs": [job] });
    dispatch(&request).map(|answer| answer["jobs"][0].clone())
}

#[test]
fn a_command_python_never_sent_is_never_guards() {
    // Python skipped a command whose JSON text and newline passed 512 KiB.
    let padding = |length: usize| format!("{LEGACY} {}", "x".repeat(length - LEGACY.len() - 3));
    let largest = padding(512 * 1024 - 1);
    let oversized = padding(512 * 1024);
    assert_eq!(
        serde_json::to_string(&largest).expect("json").len(),
        512 * 1024 - 1
    );
    let hooks = json!({ "preToolUse": [{ "command": largest }, { "command": oversized }] });
    let plan = plan_one(json!({ "parts": ["guard"], "hooks": hooks })).expect("plan");
    assert_eq!(plan["events"][1], json!(["preToolUse", [1]]));
}

#[test]
fn every_managed_event_is_answered_in_order() {
    let plan = plan_one(json!({ "parts": [], "hooks": {} })).expect("plan");
    let names: Vec<&str> = plan["events"]
        .as_array()
        .expect("events")
        .iter()
        .map(|step| step[0].as_str().expect("event"))
        .collect();
    assert_eq!(
        names,
        [
            "userPromptSubmitted",
            "preToolUse",
            "postToolUse",
            "permissionRequest",
            "permissionRequestV2"
        ]
    );
    assert_eq!(plan["bash"], "");
    assert_eq!(plan["powershell"], "");
}

#[test]
fn shell_spellings_match_python() {
    assert_eq!(
        shlex_join(&["a b", "", "it's", "-x=1"]),
        "'a b' '' 'it'\"'\"'s' -x=1"
    );
    assert_eq!(list2cmdline(&["a b", ""]), "\"a b\" \"\"");
    assert_eq!(list2cmdline(&["a\\\\\"b"]), "a\\\\\\\\\\\"b");
    assert_eq!(list2cmdline(&["tail\\"]), "tail\\");
    assert_eq!(list2cmdline(&["two words\\"]), "\"two words\\\\\"");
    assert_eq!(list2cmdline(&["a\\b c"]), "\"a\\b c\"");
}

#[test]
fn malformed_requests_are_refused() {
    let job = json!({ "parts": ["guard"], "hooks": {} });
    let refused = [
        json!({ "op": "plan", "interpreter": null, "script": null }),
        json!({ "op": "merge", "interpreter": null, "script": null, "jobs": [] }),
        json!({ "op": "plan", "interpreter": 1, "script": null, "jobs": [] }),
        json!({ "op": "plan", "interpreter": null, "script": null, "jobs": {} }),
        json!({ "op": "plan", "interpreter": null, "script": null, "jobs": [], "extra": 1 }),
        json!({ "op": "plan", "interpreter": null, "script": null, "jobs": [job, { "parts": [1], "hooks": {} }] }),
        json!({ "op": "plan", "interpreter": null, "script": null, "jobs": [{ "parts": ["g"], "hooks": [] }] }),
        json!({ "op": "plan", "interpreter": null, "script": null, "jobs": [{ "parts": ["g"] }] }),
        json!({ "op": "plan", "interpreter": null, "script": null,
            "jobs": [{ "parts": ["g"], "hooks": {}, "payload": {}, "keys": [] }] }),
        json!({ "op": "plan", "interpreter": null, "script": null,
            "jobs": [{ "parts": ["g"], "payload": { "a": 1 }, "keys": ["b"] }] }),
        json!({ "op": "plan", "interpreter": null, "script": null,
            "jobs": [{ "parts": ["g"], "payload": { "a": 1 }, "keys": ["a", "a"] }] }),
        json!({ "op": "plan", "interpreter": null, "script": null,
            "jobs": [{ "parts": ["g"], "payload": { "a": 1, "b": 2 }, "keys": ["a"] }] }),
    ];
    for request in refused {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}

#[test]
fn the_workspace_version_keeps_only_a_python_int() {
    for (version, kept) in [
        (json!(3), true),
        (json!(-0), true),
        (json!(true), true),
        (json!(1.0), false),
        (serde_json::from_str::<Value>("1e3").expect("number"), false),
        (json!("3"), false),
        (Value::Null, false),
    ] {
        let payload = json!({ "version": version, "hooks": {} });
        let plan =
            plan_one(json!({ "parts": [], "payload": payload, "keys": ["version", "hooks"] }))
                .expect("plan");
        assert_eq!(plan["version"], kept, "{payload}");
        assert_eq!(plan["hooks"], Value::Null);
    }
}
