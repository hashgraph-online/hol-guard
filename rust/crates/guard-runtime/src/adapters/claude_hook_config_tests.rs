//! Replays `claude_hook_config_vectors.json`, recorded from the original Python
//! helpers, through the native kind. List answers are rebuilt from the
//! request's own entries and handler, the way the Python shim rebuilds them.

use serde_json::{json, Map, Value};

use crate::claude_hook_config::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../testdata/claude_code/claude_hook_config_vectors.json");
const SCHEMA: &str = "guard-claude-hook-config-vectors.v1";

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
        let mut group = Map::new();
        group.insert("hooks".to_owned(), json!([handler]));
        if let Some(matcher) = step["matcher"].as_str() {
            group.insert("matcher".to_owned(), json!(matcher));
        }
        Value::Object(group)
    });
    Value::Array(rebuilt.collect())
}

fn replay(op: &str, request: &Value, answer: Value) -> Value {
    if answer.get("error").is_some() {
        return answer;
    }
    match op {
        "prune" => {
            let lists = request["lists"].as_array().expect("lists");
            let plans = answer["lists"].as_array().expect("list plans");
            assert_eq!(lists.len(), plans.len());
            let rebuilt: Vec<Value> = lists
                .iter()
                .zip(plans)
                .map(|(entries, plan)| rebuild(entries, plan, &Value::Null))
                .collect();
            json!({ "lists": rebuilt })
        }
        "merge" => {
            let jobs = request["jobs"].as_array().expect("jobs");
            let plans = answer["jobs"].as_array().expect("job plans");
            assert_eq!(jobs.len(), plans.len());
            let rebuilt: Vec<Value> = jobs
                .iter()
                .zip(plans)
                .map(|(job, plan)| rebuild(&job["entries"], plan, &job["handler"]))
                .collect();
            json!({ "jobs": rebuilt })
        }
        _ => answer,
    }
}

#[test]
fn replays_every_recorded_vector() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    assert_eq!(vectors["schema"], SCHEMA);
    let cases = vectors["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 287);
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let op = case["op"].as_str().expect("op");
        let answer = ask(op, &case["request"]).unwrap_or_else(|error| panic!("{name}: {error}"));
        let replayed = replay(op, &case["request"], answer);
        assert_eq!(replayed, case["expect"], "{name}");
    }
}

#[test]
fn covers_each_op_and_the_unhashable_answer() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    let cases = vectors["cases"].as_array().expect("cases");
    for op in ["text", "handler", "prune", "merge", "missing"] {
        assert!(cases.iter().any(|case| case["op"] == op), "{op}");
    }
    for op in ["prune", "merge", "missing"] {
        let unhashable = cases
            .iter()
            .any(|case| case["op"] == op && case["expect"].get("error").is_some());
        assert!(unhashable, "{op}");
    }
}

#[test]
fn refuses_malformed_requests() {
    let handler = json!({"type": "command", "command": "x", "args": []});
    let job = json!({"entries": [], "prune": false, "matchers": [], "handler": handler});
    let refused = [
        json!(null),
        json!({}),
        json!({"op": "other"}),
        json!({"op": "text"}),
        json!({"op": "text", "value": "x", "extra": 1}),
        json!({"op": "handler", "value": {}}),
        json!({"op": "prune", "lists": {}}),
        json!({"op": "prune", "lists": [[], "x"]}),
        json!({"op": "merge", "jobs": [job, {}]}),
        json!({"op": "merge", "jobs": [{"entries": [], "prune": 1, "matchers": [], "handler": {}}]}),
        json!({"op": "merge", "jobs": [{"entries": {}, "prune": false, "matchers": [], "handler": {}}]}),
        json!({"op": "merge", "jobs": [{"entries": [], "prune": false, "matchers": [], "handler": []}]}),
        json!({"op": "merge", "jobs": [{
            "entries": [], "prune": false, "matchers": [], "handler": {}, "extra": 1
        }]}),
        json!({"op": "missing", "payload": [], "events": [], "matcher": "Bash"}),
        json!({"op": "missing", "payload": {}, "events": [1], "matcher": "Bash"}),
        json!({"op": "missing", "payload": {}, "events": [], "matcher": null}),
    ];
    for request in refused {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}

#[test]
fn merging_into_a_group_it_added_keeps_one_handler() {
    let handler = json!({"type": "command", "command": "guard", "args": ["hook"]});
    let request = json!({"jobs": [{
        "entries": [{"matcher": "startup", "hooks": [{"type": "command", "command": "user"}]}],
        "prune": false,
        "matchers": ["resume", " resume ", "startup", "startup"],
        "handler": handler,
    }]});
    let answer = ask("merge", &request).expect("answer");
    assert_eq!(
        answer,
        json!({"jobs": [[{"entry": 0, "hooks": [0, null]}, {"matcher": "resume"}]]})
    );
}
