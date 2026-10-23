//! Pure reconciliation of already-captured OMP host events and SDK eval bridge
//! events. A matching transcript does not authenticate the producer, Guard
//! observations, physical effects, or provider usage.

use crate::{EvidenceError, Result};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const BAD_EVENTS: EvidenceError = EvidenceError::Invalid("invalid bounded host events");

fn field(row: &Value, key: &str) -> Value {
    row.get(key).cloned().unwrap_or(Value::Null)
}

fn task_arguments_match(expected: &Value, actual: &Value) -> bool {
    let (Some(expected), Some(actual)) = (expected.as_array(), actual.as_array()) else {
        return expected == actual;
    };
    if expected.len() != actual.len() {
        return false;
    }
    expected.iter().zip(actual).all(|(expected, actual)| {
        let (Some(expected), Some(actual)) = (expected.as_object(), actual.as_object()) else {
            return false;
        };
        let mut expected = expected.clone();
        let mut actual = actual.clone();
        if expected.get("outputSchema") == Some(&Value::Null)
            && !actual.contains_key("outputSchema")
        {
            expected.remove("outputSchema");
        }
        if !expected.contains_key("agent") && actual.get("agent") == Some(&json!("task")) {
            actual.remove("agent");
        }
        expected == actual
    })
}

struct PendingBridge {
    parent: String,
    event: Value,
}

fn bridge_calls(events: &[Value], parents: &[Value]) -> std::result::Result<Vec<Value>, ()> {
    let parent_ids: BTreeSet<&str> = parents
        .iter()
        .filter(|call| call.get("name") == Some(&json!("eval")))
        .filter_map(|call| call.get("id").and_then(Value::as_str))
        .collect();
    let mut active = BTreeSet::<String>::new();
    let mut pending = BTreeMap::<String, PendingBridge>::new();
    let mut seen = BTreeSet::<String>::new();
    let mut calls = Vec::new();
    for row in events {
        let kind = row.get("type").and_then(Value::as_str);
        let key = row.get("toolCallId").and_then(Value::as_str);
        if kind == Some("tool_execution_start") && key.is_some_and(|key| parent_ids.contains(key)) {
            active.insert(key.unwrap().to_owned());
        } else if kind == Some("tool_execution_end")
            && key.is_some_and(|key| parent_ids.contains(key))
        {
            let key = key.ok_or(())?;
            if !active.contains(key) || pending.values().any(|item| item.parent == key) {
                return Err(());
            }
            active.remove(key);
        } else if matches!(kind, Some("eval_bridge_start" | "eval_bridge_end")) {
            let parent = row
                .get("parentToolCallId")
                .and_then(Value::as_str)
                .ok_or(())?;
            if row.get("parentToolCallIds") != Some(&json!([parent]))
                || active.len() != 1
                || !active.contains(parent)
            {
                return Err(());
            }
            let event = row.get("event").and_then(Value::as_object).ok_or(())?;
            let key = event.get("toolCallId").and_then(Value::as_str).ok_or(())?;
            let name = event.get("toolName").and_then(Value::as_str).ok_or(())?;
            if !key.starts_with(&format!("js-{name}-")) {
                return Err(());
            }
            if kind == Some("eval_bridge_start") {
                if !seen.insert(key.to_owned())
                    || parents
                        .iter()
                        .any(|call| call.get("id") == Some(&json!(key)))
                    || event.get("type") != Some(&json!("tool_call"))
                    || !event.get("input").is_some_and(Value::is_object)
                {
                    return Err(());
                }
                pending.insert(
                    key.to_owned(),
                    PendingBridge {
                        parent: parent.to_owned(),
                        event: Value::Object(event.clone()),
                    },
                );
            } else {
                let start = pending.remove(key).ok_or(())?;
                if start.parent != parent
                    || start.event.get("toolName") != Some(&json!(name))
                    || event.get("type") != Some(&json!("tool_result"))
                    || !event.get("isError").is_some_and(Value::is_boolean)
                    || event.get("input") != start.event.get("input")
                {
                    return Err(());
                }
                calls.push(json!({
                    "id": key,
                    "name": name,
                    "args": field(&start.event, "input"),
                    "is_error": field(row.get("event").ok_or(())?, "isError"),
                    "result": {"content": field(row.get("event").ok_or(())?, "content"),
                               "details": field(row.get("event").ok_or(())?, "details")},
                    "bridge_parent_id": parent,
                }));
            }
        }
    }
    if !pending.is_empty() {
        return Err(());
    }
    Ok(calls)
}

/// Match Python `evidence.reconcile` and `bridge_evidence.bridge_calls` over
/// bounded, already-read events. The result is only an event-accounting input
/// for a later independently authenticated verdict.
pub fn reconcile_host_calls(events: &[Value]) -> Result<Value> {
    if events.len() > 50_000 || events.iter().any(|row| !row.is_object()) {
        return Err(BAD_EVENTS);
    }
    let mut starts = BTreeMap::<String, &Value>::new();
    let mut ends = BTreeMap::<String, &Value>::new();
    let mut requested = BTreeMap::<String, &Value>::new();
    let mut errors = BTreeSet::<String>::new();
    let mut sequence = Vec::<String>::new();
    for event in events {
        match event.get("type").and_then(Value::as_str) {
            Some("model_turn") => {
                let Some(calls) = event.get("calls").unwrap_or(&Value::Null).as_array() else {
                    if event.get("calls").is_none() {
                        continue;
                    }
                    return Err(BAD_EVENTS);
                };
                for call in calls {
                    let call_id = call
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|id| !id.is_empty());
                    if !call.is_object() {
                        return Err(BAD_EVENTS);
                    }
                    if let Some(call_id) = call_id.filter(|id| !requested.contains_key(*id)) {
                        requested.insert(call_id.to_owned(), call);
                    } else {
                        errors.insert("duplicate-or-missing-model-call-id".into());
                    }
                }
            }
            Some(kind @ ("tool_execution_start" | "tool_execution_end")) => {
                let call_id = event
                    .get("toolCallId")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty());
                let target = if kind == "tool_execution_start" {
                    &mut starts
                } else {
                    &mut ends
                };
                if let Some(call_id) = call_id.filter(|id| !target.contains_key(*id)) {
                    target.insert(call_id.to_owned(), event);
                    if kind == "tool_execution_start" {
                        if !requested.contains_key(call_id) {
                            errors.insert("start-before-model-request".into());
                        }
                        sequence.push(call_id.to_owned());
                    } else if !starts.contains_key(call_id) {
                        errors.insert("completion-before-start".into());
                    }
                } else {
                    errors.insert("duplicate-or-missing-host-call-id".into());
                }
            }
            _ => {}
        }
    }
    let start_ids: BTreeSet<_> = starts.keys().collect();
    let end_ids: BTreeSet<_> = ends.keys().collect();
    let requested_ids: BTreeSet<_> = requested.keys().collect();
    if start_ids != end_ids || start_ids != requested_ids {
        errors.insert("model-start-completion-inventory-mismatch".into());
    }
    let mut calls = Vec::new();
    for call_id in sequence {
        let start = starts.get(&call_id).copied().ok_or(BAD_EVENTS)?;
        let end = ends.get(&call_id).copied().unwrap_or(&Value::Null);
        let model = requested.get(&call_id).copied().unwrap_or(&Value::Null);
        let (args, model_args): (Map<String, Value>, Map<String, Value>) = match (
            start.get("args").and_then(Value::as_object),
            model.get("arguments").and_then(Value::as_object),
        ) {
            (Some(args), Some(model_args)) => (args.clone(), model_args.clone()),
            _ => {
                errors.insert("missing-tool-arguments".into());
                (Map::new(), Map::new())
            }
        };
        let name = field(start, "toolName");
        if name != field(model, "name")
            || (end.get("toolName").is_some_and(|value| !value.is_null())
                && field(end, "toolName") != name)
        {
            errors.insert("tool-name-mismatch".into());
        }
        for (key, value) in &model_args {
            let actual = args.get(key).unwrap_or(&Value::Null);
            let matches = if name == "task" && key == "tasks" {
                task_arguments_match(value, actual)
            } else {
                value == actual
            };
            if key != "i" && key != "intent" && !matches {
                errors.insert("model-host-arguments-mismatch".into());
            }
        }
        if !end.get("isError").is_some_and(Value::is_boolean) {
            errors.insert("missing-tool-completion-status".into());
        }
        calls.push(json!({"id": call_id, "name": name, "args": args,
                          "is_error": field(end, "isError"), "result": field(end, "result")}));
    }
    match bridge_calls(events, &calls) {
        Ok(mut bridge) => calls.append(&mut bridge),
        Err(()) => {
            errors.insert("invalid-sdk-bridge-evidence".into());
        }
    }
    Ok(json!({"calls": calls, "errors": errors}))
}
