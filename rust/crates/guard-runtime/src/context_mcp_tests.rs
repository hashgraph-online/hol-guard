use serde_json::{json, Value};

use super::{answer, serve, Session};

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
    let catalog = answer(&json!({"op": "catalog"}), &mut Session::default(), &mut ask);
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
    let mut session = Session::default();
    let first = answer(&json!({"op": "tools"}), &mut session, &mut ask);
    let names: Vec<&str> = first["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["get_context_status", "get_guard_context"]);
    assert!(!first.to_string().contains(CREDENTIAL));
    let again = answer(&json!({"op": "tools"}), &mut session, &mut ask);
    assert_eq!(again["tools"].as_array().unwrap().len(), 2);
    drop(ask);
    assert_eq!(log.iter().filter(|m| m["action"] == "begin").count(), 1);
}

#[test]
fn a_failed_begin_is_not_retried() {
    let mut began = 0;
    let mut ask = |message: Value| match message["action"].as_str() {
        Some("discover") => Ok(json!({"available": true})),
        Some("begin") => {
            began += 1;
            Err("native_context_assistance_unavailable".to_owned())
        }
        _ => Ok(json!({"tools": []})),
    };
    let mut session = Session::default();
    let first = answer(&json!({"op": "tools"}), &mut session, &mut ask);
    assert_eq!(first["tools"], json!([]));
    answer(&json!({"op": "tools"}), &mut session, &mut ask);
    assert_eq!(began, 1);
}

#[test]
fn unknown_tools_in_status_hide_every_tool() {
    let mut log = Vec::new();
    let mut ask = resident(&mut log, true, json!(["get_context_status", "run_shell"]));
    assert_eq!(
        answer(&json!({"op": "tools"}), &mut Session::default(), &mut ask)["tools"],
        json!([])
    );
}

#[test]
fn calls_return_the_data_or_a_fixed_refusal() {
    let mut log = Vec::new();
    let mut ask = resident(&mut log, true, json!([]));
    let mut session = Session::default();
    let ok = answer(
        &json!({"op": "call", "name": "get_guard_context", "arguments": {"query": "q"}}),
        &mut session,
        &mut ask,
    );
    let text: Value = serde_json::from_str(ok["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        text,
        json!({"ok": true, "data_role": true, "data": {"brief": "b"}})
    );
    let refused = answer(
        &json!({"op": "call", "name": "explain_guard_context", "arguments": {}}),
        &mut session,
        &mut ask,
    );
    let text: Value = serde_json::from_str(refused["text"].as_str().unwrap()).unwrap();
    assert_eq!(text["ok"], false);
    assert_eq!(
        text["error"]["code"],
        "native_context_assistance_scope_denied"
    );
    let unknown = answer(
        &json!({"op": "call", "name": "search"}),
        &mut session,
        &mut ask,
    );
    assert_eq!(unknown["known"], false);
    drop(ask);
    let compile = log.iter().find(|m| m["action"] == "compile").unwrap();
    assert_eq!(compile["credential"], CREDENTIAL);
    assert_eq!(compile["arguments"], json!({"query": "q"}));
    assert_eq!(log.iter().filter(|m| m["action"] == "begin").count(), 1);
}

#[test]
fn one_process_keeps_the_pairing_and_closes_it_at_the_end_of_input() {
    let mut log = Vec::new();
    let mut ask = resident(&mut log, true, json!(["get_context_status"]));
    let input = concat!(
        "{\"op\":\"tools\"}\n",
        "\n",
        "not json\n",
        "{\"op\":\"call\",\"name\":\"get_guard_context\",\"arguments\":{}}\n",
    );
    let mut out = Vec::new();
    assert_eq!(serve(&mut input.as_bytes(), &mut out, &mut ask), 0);
    drop(ask);
    let lines: Vec<Value> = String::from_utf8(out.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["tools"][0]["name"], "get_context_status");
    assert_eq!(lines[1]["error"], "unknown_op");
    assert_eq!(lines[2]["known"], true);
    assert!(!String::from_utf8(out).unwrap().contains(CREDENTIAL));
    assert_eq!(log.iter().filter(|m| m["action"] == "begin").count(), 1);
    assert_eq!(
        log.last().unwrap(),
        &json!({"action": "close", "credential": CREDENTIAL})
    );
}

#[test]
fn close_ends_the_pairing_and_stops_reading() {
    let mut log = Vec::new();
    let mut ask = resident(&mut log, true, json!([]));
    let input = "{\"op\":\"tools\"}\n{\"op\":\"close\"}\n{\"op\":\"tools\"}\n";
    let mut out = Vec::new();
    assert_eq!(serve(&mut input.as_bytes(), &mut out, &mut ask), 0);
    drop(ask);
    let text = String::from_utf8(out).unwrap();
    assert_eq!(text.lines().count(), 2);
    assert!(text.lines().last().unwrap().contains("\"closed\":true"));
    let closes = log.iter().filter(|m| m["action"] == "close").count();
    assert_eq!(closes, 1);
}
