//! Replays approval queue read vectors recorded from the original Python
//! implementation (see `testdata/guard_store/record_approval_read_vectors.py`).
//! Seeds, payloads and errors all come from Python, never from Rust output.
//! Python still attaches the temporary MCP and local tool hints and decodes
//! the page cursor, so the replay leaves both out.

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_approval_read_scope::UNAVAILABLE;
use crate::guard_store_cmd_vectors_tests::{insert_rows, temp_home};
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/approval_read_vectors.json");
const PAD: &str = "__pad__";
const HINTS: [&str; 2] = ["temporary_mcp_approval", "local_tool_approval"];

/// `approval_read_scenarios.padded_envelope`.
fn padded_envelope(pad: &Value) -> String {
    let (size, copies) = match pad {
        Value::Array(pair) => (pair[0].as_u64().unwrap(), pair[1].as_u64().unwrap()),
        size => (size.as_u64().unwrap(), 1),
    };
    let mut envelope = String::from("{\"command\":\"x\"");
    for index in 0..copies {
        let suffix = if index == 0 {
            String::new()
        } else {
            index.to_string()
        };
        envelope.push_str(&format!(
            ",\"pad{suffix}\":\"{}\"",
            "a".repeat(size as usize)
        ));
    }
    envelope.push('}');
    envelope
}

/// `approval_read_scenarios.expand`.
fn expand(value: &Value) -> Value {
    match value.get("repeat").and_then(Value::as_array) {
        Some(parts) => {
            let text = |index: usize| parts[index].as_str().unwrap();
            let count = parts[2].as_u64().unwrap() as usize;
            Value::String(format!("{}{}{}", text(0), text(1).repeat(count), text(3)))
        }
        None => value.clone(),
    }
}

pub(crate) fn seed(path: &std::path::Path, vectors: &Value, scenario: &Value) {
    let connection = Connection::open(path).unwrap();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    let rows: Vec<Value> = scenario["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let id = row["request_id"].as_str().unwrap();
            let cells = row.as_object().unwrap().iter().map(|(key, value)| {
                let cell = if value == PAD {
                    Value::String(padded_envelope(&scenario["pads"][id]))
                } else {
                    expand(value)
                };
                (key.clone(), cell)
            });
            Value::Object(cells.collect())
        })
        .collect();
    insert_rows(&connection, "approval_requests", &Value::Array(rows));
}

/// One store call: `Ok(payload)` or `Err((code, message))`.
pub(crate) fn store_call(
    home: &std::path::Path,
    source: &str,
    method: &str,
    args: Value,
) -> Result<Value, (String, String)> {
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: method.to_owned(),
        source: source.to_owned(),
        busy_timeout_ms: 5000,
        args: args.as_object().unwrap().clone(),
    };
    let reply: Value =
        serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap();
    if reply["status"] == "ok" {
        return Ok(reply["payload"].clone());
    }
    let message = reply["payload"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    Err((
        reply["code"].as_str().unwrap_or_default().to_owned(),
        message,
    ))
}

/// `record_approval_read_vectors.mark_long`, with numbers in one spelling.
pub(crate) fn normalized(value: Value, long_string: usize) -> Value {
    match value {
        Value::String(text) if text.chars().count() > long_string => {
            let digest = Sha256::digest(text.as_bytes());
            let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            Value::String(format!("__long__:{}:{hex}", text.chars().count()))
        }
        Value::Number(number) => match number.to_string().parse::<i128>() {
            Ok(_) => Value::Number(number),
            Err(_) => Value::String(format!("float:{:?}", number.as_f64().unwrap())),
        },
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| normalized(item, long_string))
                .collect(),
        ),
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .map(|(key, item)| (key, normalized(item, long_string)))
                .collect(),
        ),
        other => other,
    }
}

fn without_hints(value: &Value) -> Value {
    match value {
        Value::Object(fields) => {
            let mut fields = fields.clone();
            for hint in HINTS {
                fields.remove(hint);
            }
            Value::Object(fields)
        }
        Value::Array(items) => Value::Array(items.iter().map(without_hints).collect()),
        other => other.clone(),
    }
}

/// The recorded outcome as the store reply spells it.
pub(crate) fn expected(call: &Value, long_string: usize) -> Result<Value, (String, String)> {
    match call.get("error") {
        None => Ok(normalized(without_hints(&call["result"]), long_string)),
        Some(error) => {
            let message = error["message"].as_str().unwrap().to_owned();
            match error["type"].as_str().unwrap() {
                "ApprovalScopeUnavailableError" => {
                    assert_eq!(message, UNAVAILABLE);
                    Err(("native_guard_store_value_error".to_owned(), message))
                }
                "ValueError" => Err(("native_guard_store_value_error".to_owned(), message)),
                other => panic!("unexpected recorded error {other}"),
            }
        }
    }
}

fn list(home: &std::path::Path, source: &str, call: &Value) -> Result<Value, (String, String)> {
    let args = &call["args"];
    let mut items = Vec::new();
    let mut after = Value::Null;
    loop {
        let mut chunk = json!({
            "status": args["status"],
            "harness": args["harness"],
            "limit": args["limit"],
            "cursor": call["cursor_marker"],
            "search": args["search"],
            "taken": items.len(),
        });
        if !after.is_null() {
            chunk["after"] = after.clone();
        }
        let page = store_call(home, source, "list_approval_requests", chunk)?;
        let returned = page["items"].as_array().unwrap();
        items.extend(returned.iter().cloned());
        if page["complete"] == true {
            return Ok(Value::Array(items));
        }
        assert!(!returned.is_empty(), "an incomplete page returns items");
        after = page["after"].clone();
    }
}

#[test]
fn replays_every_recorded_approval_read() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-store-approval-read-vectors.v1");
    let source = vectors["source"].as_str().unwrap();
    let long_string = vectors["long_string"].as_u64().unwrap() as usize;
    let mut replayed = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(&format!("approval-read-{name}"));
        seed(&home.join("guard.db"), &vectors, scenario);
        for (index, call) in scenario["calls"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index}");
            let actual = if call["method"] == "get" {
                let mut args = Map::new();
                args.insert("request_id".to_owned(), call["request_id"].clone());
                args.insert("derive_scope".to_owned(), call["derive_scope"].clone());
                store_call(&home, source, "get_approval_request", Value::Object(args))
            } else if call["cursor_marker"].is_null() && !call["args"]["cursor"].is_null() {
                // Python rejects an undecodable cursor before the store call.
                continue;
            } else {
                list(&home, source, call)
            };
            let actual = actual.map(|value| normalized(value, long_string));
            assert_eq!(actual, expected(call, long_string), "{label}");
            replayed += 1;
        }
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(replayed >= 154, "replayed {replayed} calls");
}
