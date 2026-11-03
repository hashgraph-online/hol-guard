//! Replays `zcode/hook_settings_vectors.json`, recorded from the original
//! Python ZCode adapter, through the native kind. Every answer is applied over
//! the request's own `hooks` mapping the way the Python shim applies it, and
//! the result must equal what the Python left behind, key order included.

use guard_runtime_pyjson::{parse, PyVal};
use serde_json::{json, Value};

use crate::runner_authority_op::ERR_INVALID;
use crate::zcode_hook_settings::dispatch;

const VECTORS: &str = include_str!("../../testdata/zcode/hook_settings_vectors.json");

type Dict = Vec<(String, PyVal)>;

fn dict(value: &PyVal) -> Dict {
    value.as_dict().expect("object").to_vec()
}

fn set_key(target: &mut Dict, key: &str, value: PyVal) {
    match target.iter_mut().find(|(name, _)| name == key) {
        Some((_, slot)) => *slot = value,
        None => target.push((key.to_owned(), value)),
    }
}

fn remove_key(target: &mut Dict, key: &str) {
    target.retain(|(name, _)| name != key);
}

fn index(value: &Value) -> usize {
    usize::try_from(value.as_u64().expect("index")).expect("usize")
}

fn handler(handlers: &Value, name: &str) -> PyVal {
    parse(handlers[name].as_str().expect("handler text")).expect("handler")
}

/// The entry a `["events" | "hooks", i]` reference names.
fn referenced<'a>(hooks: &'a PyVal, name: &str, reference: &Value) -> &'a PyVal {
    let container = match reference[0].as_str().expect("source") {
        "events" => hooks.get("events").expect("events mapping"),
        "hooks" => hooks,
        other => panic!("unknown source {other}"),
    };
    let list = container
        .get(name)
        .and_then(PyVal::as_list)
        .expect("source list");
    &list[index(&reference[1])]
}

/// One event list from its plan, over the caller's own entries.
fn build(hooks: &PyVal, name: &str, plan: &Value, handlers: &Value) -> PyVal {
    let entries = plan.as_array().expect("plan").iter().map(|item| {
        if item.is_array() {
            return referenced(hooks, name, item).clone();
        }
        if let Some(matcher) = item.get("group") {
            let mut group: Dict = vec![(
                "hooks".to_owned(),
                PyVal::List(vec![handler(handlers, name)]),
            )];
            if let Some(matcher) = matcher.as_str() {
                group.push(("matcher".to_owned(), PyVal::Str(matcher.to_owned())));
            }
            return PyVal::Dict(group);
        }
        let entry = referenced(hooks, name, &item["copy"]);
        let own = entry
            .get("hooks")
            .and_then(PyVal::as_list)
            .unwrap_or_default();
        let kept = item["hooks"]
            .as_array()
            .expect("handler plan")
            .iter()
            .map(|position| match position.as_str() {
                Some("guard") => handler(handlers, name),
                _ => own[index(position)].clone(),
            })
            .collect();
        let mut copy = dict(entry);
        set_key(&mut copy, "hooks", PyVal::List(kept));
        PyVal::Dict(copy)
    });
    PyVal::List(entries.collect())
}

fn pairs(value: &Value) -> impl Iterator<Item = (&str, &Value)> {
    value
        .as_array()
        .expect("event plans")
        .iter()
        .map(|pair| (pair[0].as_str().expect("event name"), &pair[1]))
}

fn assign(target: &mut Dict, hooks: &PyVal, plans: &Value, handlers: &Value) {
    for (name, plan) in pairs(plans) {
        if plan.is_null() {
            remove_key(target, name);
        } else {
            set_key(target, name, build(hooks, name, plan, handlers));
        }
    }
}

fn install_after(hooks: &PyVal, answer: &Value, handlers: &Value) -> PyVal {
    let mut events = hooks
        .get("events")
        .and_then(PyVal::as_dict)
        .map(<[_]>::to_vec)
        .unwrap_or_default();
    assign(&mut events, hooks, &answer["events"], handlers);
    let mut after = dict(hooks);
    for name in answer["drop"].as_array().expect("drop") {
        remove_key(&mut after, name.as_str().expect("drop name"));
    }
    set_key(&mut after, "events", PyVal::Dict(events));
    PyVal::Dict(after)
}

fn uninstall_after(hooks: &PyVal, answer: &Value, handlers: &Value) -> PyVal {
    let mut after = dict(hooks);
    if let Some(events) = hooks.get("events").and_then(PyVal::as_dict) {
        let mut events = events.to_vec();
        assign(&mut events, hooks, &answer["events"], handlers);
        if events.is_empty() {
            remove_key(&mut after, "events");
        } else {
            set_key(&mut after, "events", PyVal::Dict(events));
        }
    }
    assign(&mut after, hooks, &answer["hooks"], handlers);
    PyVal::Dict(after)
}

/// The `enabled` record the answer names: the saved one, or the live flag.
fn enabled(hooks: &PyVal, answer: &Value) -> Value {
    if !answer.is_null() {
        return answer.clone();
    }
    let value = hooks.get("enabled");
    json!({
        "present": value.is_some(),
        "value": value.map_or(Value::Null, |value| value.to_json().expect("live value")),
    })
}

#[test]
fn replays_vectors_recorded_from_the_python_adapter() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    let handlers = &vectors["handlers"];
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() >= 100, "too few vectors: {}", cases.len());
    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let request = &case["request"];
        let expected = &case["expected"];
        let answer = dispatch(request).unwrap_or_else(|error| panic!("{name}: {error}"));
        let hooks = parse(request["hooks"].as_str().expect("hooks text")).expect("hooks");
        let after = if request["op"] == "install" {
            assert_eq!(answer["has_handlers"], expected["has_handlers"], "{name}");
            install_after(&hooks, &answer, handlers)
        } else {
            uninstall_after(&hooks, &answer, handlers)
        };
        let want = parse(expected["after"].as_str().expect("after text")).expect("after");
        assert_eq!(after, want, "{name}");
        assert_eq!(
            enabled(&hooks, &answer["enabled"]),
            expected["enabled"],
            "{name}"
        );
    }
}

fn install_request(hooks: &str) -> Value {
    json!({
        "op": "install",
        "hooks": hooks,
        "path": "/home/user/.zcode/cli/config.json",
        "history": null,
        "managed_config_path": null,
        "matchers": ["Bash"],
    })
}

#[test]
fn answers_index_plans_into_the_callers_lists() {
    let user = r#"{"events": {"Stop": [{"hooks": [{"command": "echo stop"}]}]}}"#;
    assert_eq!(
        dispatch(&install_request(user)),
        Ok(json!({
            "enabled": null,
            "has_handlers": true,
            "drop": [],
            "events": [
                ["PreToolUse", [{"group": "Bash"}]],
                ["UserPromptSubmit", [{"group": null}]],
            ],
        }))
    );
    let legacy = r#"{"Stop": [{"hooks": [{"command": "echo stop"}]}], "events": {}}"#;
    let mut request = install_request(legacy);
    request["op"] = json!("uninstall");
    request.as_object_mut().expect("request").remove("matchers");
    assert_eq!(
        dispatch(&request),
        Ok(json!({
            "enabled": null,
            "events": [],
            "hooks": [["Stop", [["hooks", 0]]]],
        }))
    );
}

#[test]
fn refuses_malformed_requests() {
    let good = install_request("{}");
    assert!(dispatch(&good).is_ok());
    let mut cases: Vec<Value> = Vec::new();
    for (key, value) in [
        ("op", json!("repair")),
        ("op", json!(1)),
        ("hooks", json!({})),
        ("hooks", json!("[]")),
        ("hooks", json!("{not json")),
        ("path", json!(null)),
        ("matchers", json!("Bash")),
        ("matchers", json!([1])),
    ] {
        let mut request = good.clone();
        request[key] = value;
        cases.push(request);
    }
    let mut extra = good.clone();
    extra["extra"] = json!(true);
    cases.push(extra);
    let mut missing = good.clone();
    missing.as_object_mut().expect("request").remove("history");
    cases.push(missing);
    let mut uninstall_with_matchers = good.clone();
    uninstall_with_matchers["op"] = json!("uninstall");
    cases.push(uninstall_with_matchers);
    cases.push(json!(["install"]));
    for request in cases {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
