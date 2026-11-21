use serde_json::{json, Value};

use super::answer;

const CREDENTIAL: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A resident that answers by action and records every message.
fn resident(
    log: &mut Vec<Value>,
    available: bool,
    tools: Value,
) -> impl FnMut(Value) -> Result<Value, String> + '_ {
    move |message: Value| {
        log.push(message.clone());
        match message["action"].as_str() {
            Some("discover") => Ok(json!({"available": available})),
            Some("begin") => Ok(json!({"credential": CREDENTIAL})),
            Some("status") => Ok(json!({"tools": tools.clone()})),
            Some("compile") => Ok(json!({"brief": "b"})),
            _ => Err("native_context_assistance_scope_denied".to_owned()),
        }
    }
}

#[test]
fn catalog_lists_every_tool_with_strict_schemas() {
    let mut ask = |_: Value| -> Result<Value, String> { panic!("catalog asked the resident") };
    let catalog = answer(&json!({"op": "catalog"}), &mut ask);
    let tools = catalog["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 7);
    for tool in tools {
        assert_eq!(tool["input_schema"]["additionalProperties"], false);
        assert_eq!(tool["annotations"]["open_world"], false);
    }
    let action = tools
        .iter()
        .find(|tool| tool["name"] == "explain_guard_action")
        .unwrap();
    assert_eq!(action["input_schema"]["required"], json!(["decision_id"]));
    let forget = tools
        .iter()
        .find(|tool| tool["name"] == "forget_guard_context_proposal")
        .unwrap();
    assert_eq!(forget["annotations"]["destructive"], true);
}

#[test]
fn tools_pair_once_and_show_only_allowed_tools() {
    let mut log = Vec::new();
    let mut ask = resident(
        &mut log,
        true,
        json!(["get_context_status", "get_guard_context"]),
    );
    let first = answer(&json!({"op": "tools", "session": null}), &mut ask);
    let names: Vec<&str> = first["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["get_context_status", "get_guard_context"]);
    assert_eq!(
        first["session"],
        json!({"credential": CREDENTIAL, "started": true})
    );
    let again = answer(
        &json!({"op": "tools", "session": first["session"]}),
        &mut ask,
    );
    assert_eq!(again["tools"].as_array().unwrap().len(), 2);
    drop(ask);
    assert_eq!(log.iter().filter(|m| m["action"] == "begin").count(), 1);
}

#[test]
fn a_failed_begin_is_not_retried() {
    let mut ask = |message: Value| match message["action"].as_str() {
        Some("discover") => Ok(json!({"available": true})),
        _ => Err("native_context_assistance_unavailable".to_owned()),
    };
    let first = answer(&json!({"op": "tools"}), &mut ask);
    assert_eq!(first["tools"], json!([]));
    assert_eq!(
        first["session"],
        json!({"credential": null, "started": true})
    );
    let mut began = 0;
    let mut ask = |message: Value| {
        if message["action"] == "begin" {
            began += 1;
        }
        Ok(json!({"available": true}))
    };
    answer(
        &json!({"op": "tools", "session": first["session"]}),
        &mut ask,
    );
    assert_eq!(began, 0);
}

#[test]
fn unknown_tools_in_status_hide_every_tool() {
    let mut log = Vec::new();
    let mut ask = resident(&mut log, true, json!(["get_context_status", "run_shell"]));
    assert_eq!(
        answer(&json!({"op": "tools"}), &mut ask)["tools"],
        json!([])
    );
}

#[test]
fn calls_return_the_data_or_a_fixed_refusal() {
    let mut log = Vec::new();
    let mut ask = resident(&mut log, true, json!([]));
    let session = json!({"credential": CREDENTIAL, "started": true});
    let ok = answer(
        &json!({"op": "call", "session": session, "name": "get_guard_context", "arguments": {"query": "q"}}),
        &mut ask,
    );
    let text: Value = serde_json::from_str(ok["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        text,
        json!({"ok": true, "data_role": true, "data": {"brief": "b"}})
    );
    let refused = answer(
        &json!({"op": "call", "session": session, "name": "explain_guard_context", "arguments": {}}),
        &mut ask,
    );
    let text: Value = serde_json::from_str(refused["text"].as_str().unwrap()).unwrap();
    assert_eq!(text["ok"], false);
    assert_eq!(
        text["error"]["code"],
        "native_context_assistance_scope_denied"
    );
    let unknown = answer(
        &json!({"op": "call", "session": session, "name": "search"}),
        &mut ask,
    );
    assert_eq!(unknown["known"], false);
    drop(ask);
    let compile = log.iter().find(|m| m["action"] == "compile").unwrap();
    assert_eq!(compile["credential"], CREDENTIAL);
    assert_eq!(compile["arguments"], json!({"query": "q"}));
}

#[test]
fn close_ends_the_pairing() {
    let mut log = Vec::new();
    let mut ask = resident(&mut log, true, json!([]));
    let closed = answer(
        &json!({"op": "close", "session": {"credential": CREDENTIAL, "started": true}}),
        &mut ask,
    );
    assert_eq!(closed["session"]["credential"], Value::Null);
    drop(ask);
    assert_eq!(log, [json!({"action": "close", "credential": CREDENTIAL})]);
}
