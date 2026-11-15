//! JSON-lines tools for cloud action packs: `cloud-action pack`.
//!
//! One request object per line, one result per line. Every request names an
//! `op`; the pack it works on is either a source `pack` (validated on read) or
//! a compiled `artifact` (digests re-checked on read).
//!
//! | op         | input                              | result                     |
//! |------------|------------------------------------|----------------------------|
//! | `validate` | `pack`                             | provider id, action count  |
//! | `test`     | `pack`                             | fixture report             |
//! | `compile`  | `pack`                             | artifact                   |
//! | `diff`     | `old`, `new` (pack or artifact)    | pack diff                  |
//! | `render`   | pack, `actionId`, `arguments`      | exact request              |
//! | `extract`  | pack, `actionId`, `arguments`      | action facts v2            |
//! | `project`  | pack, `actionId`, `response` text  | projection and labels      |
//! | `explain`  | `actionId`, `arguments`, optional pack | facts and preset decisions |
//! | `policy`   | `preset` name or `policyPack`      | fact rules and pack digest |
//! | `simulate` | `preset` or `policyPack`, stored `calls` | decision and matched rules per call |
//! | `classify` | `name`, optional `inputSchema`, `class`, `preset` or `policyPack` | class proposal, facts and unclassified action |
//!
//! Results are `{"ok":true,...}` or `{"ok":false,"error":{"code":..}}`. A
//! request never reaches the network: rendering builds a request a host sends.

use crate::cloud_action_canonical::parse_strict;
use crate::cloud_action_classifier::classify;
use crate::cloud_action_serve::{read_line, Line};
use crate::cloud_pack::{pack_from_value, CloudActionPack, PackAction, PackError};
use crate::cloud_pack_artifact::{compile, load_value, ARTIFACT_SCHEMA};
use crate::cloud_pack_diff::diff;
use crate::cloud_pack_explain::{explain, shipped_pack_for};
use crate::cloud_pack_facts::extract;
use crate::cloud_pack_fixtures::run;
use crate::cloud_pack_request::{check_arguments, render, ArgumentError};
use crate::cloud_pack_response::project;
use crate::cloud_pack_simulate::simulate;
use crate::cloud_policy_pack::{policy_pack_from_value, shipped, PolicyPack, Preset};
use guard_contracts::ActionClassV2;
use serde_json::{json, Map, Value};
use std::io::{self, Write};

pub(crate) fn serve_lines() {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut bytes = Vec::new();
        let response = match read_line(&mut input, &mut bytes) {
            Ok(Line::End) | Err(_) => break,
            Ok(Line::Request) => answer(&bytes),
            Ok(Line::Oversize) => refuse("limit", None),
        };
        if serde_json::to_writer(&mut output, &response).is_err()
            || writeln!(output).is_err()
            || output.flush().is_err()
        {
            break;
        }
    }
}

fn refuse(code: &str, pointer: Option<&str>) -> Value {
    let mut error = json!({ "code": code });
    if let Some(pointer) = pointer.filter(|pointer| !pointer.is_empty()) {
        error["pointer"] = json!(pointer);
    }
    json!({ "ok": false, "error": error })
}

fn pack_error(error: PackError) -> Value {
    refuse(error.code, Some(&error.pointer))
}

fn argument_error(error: ArgumentError) -> Value {
    let mut value = json!({ "ok": false, "error": { "code": error.code } });
    if let Some(argument) = error.argument {
        value["error"]["argument"] = json!(argument);
    }
    value
}

fn ok(mut fields: Map<String, Value>) -> Value {
    fields.insert("ok".into(), Value::Bool(true));
    Value::Object(fields)
}

/// Answer one request line.
pub fn answer(bytes: &[u8]) -> Value {
    let Ok(Value::Object(mut request)) = parse_strict(bytes) else {
        return refuse("request_invalid", None);
    };
    let op = match request.remove("op") {
        Some(Value::String(op)) => op,
        _ => return refuse("request_invalid", Some("/op")),
    };
    match answer_op(&op, request) {
        Ok(value) | Err(value) => value,
    }
}

fn answer_op(op: &str, mut request: Map<String, Value>) -> Result<Value, Value> {
    let result = match op {
        "validate" => {
            let pack = source(&mut request, "pack")?;
            json!({ "providerId": pack.provider.id, "actions": pack.actions.len() })
        }
        "test" => {
            let pack = source(&mut request, "pack")?;
            json!({ "report": run(&pack) })
        }
        "compile" => {
            let pack = source(&mut request, "pack")?;
            json!({ "artifact": compile(&pack).map_err(pack_error)? })
        }
        "diff" => {
            let old = either(&mut request, "old")?;
            let new = either(&mut request, "new")?;
            json!({ "diff": diff(&old, &new).map_err(pack_error)? })
        }
        "policy" => {
            let pack = policy(&mut request)?;
            json!({
                "preset": pack.preset,
                "packDigest": pack.digest(),
                "factRules": pack.fact_rules(),
                "unclassified": pack.unclassified,
            })
        }
        "simulate" => {
            let pack = policy(&mut request)?;
            let calls = request
                .remove("calls")
                .ok_or_else(|| refuse("request_invalid", Some("/calls")))?;
            simulate(&pack, calls).map_err(|(code, pointer)| refuse(code, Some(&pointer)))?
        }
        "generate" => crate::cloud_pack_generate::generate(&mut request)
            .map_err(|(code, pointer)| refuse(code, Some(pointer)))?,
        "classify" => {
            let Some(Value::String(name)) = request.remove("name") else {
                return Err(refuse("request_invalid", Some("/name")));
            };
            let schema = request.remove("inputSchema");
            let proposal = classify(&name, schema.as_ref());
            // The facts claim one class and nothing else, so every fact a rule
            // could lower a decision on stays unknown. The class is the
            // proposal's, or the one a workspace admin approved for the tool.
            let class = match request.remove("class") {
                None => proposal.class,
                Some(value) => serde_json::from_value::<ActionClassV2>(value)
                    .map_err(|_| refuse("request_invalid", Some("/class")))?,
            };
            let facts = crate::cloud_pack_facts::class_only_facts(class);
            let mut result = json!({ "proposal": proposal, "facts": facts });
            if request.contains_key("policyPack") || request.contains_key("preset") {
                let pack = policy(&mut request)?;
                result["action"] = json!(pack.unclassified_action(&proposal));
            }
            result
        }
        "render" | "extract" | "project" | "explain" => return answer_action(op, request),
        _ => return Err(refuse("op_unsupported", Some("/op"))),
    };
    Ok(ok(into_map(result)))
}

fn answer_action(op: &str, mut request: Map<String, Value>) -> Result<Value, Value> {
    let Some(Value::String(action_id)) = request.remove("actionId") else {
        return Err(refuse("request_invalid", Some("/actionId")));
    };
    let pack = if request.contains_key("artifact") {
        either(&mut request, "artifact")?
    } else if op == "explain" && !request.contains_key("pack") {
        shipped_pack_for(&action_id)
            .cloned()
            .ok_or_else(|| refuse("action_unknown", Some("/actionId")))?
    } else {
        source(&mut request, "pack")?
    };
    let action: &PackAction = pack
        .action(&action_id)
        .ok_or_else(|| refuse("action_unknown", Some("/actionId")))?;
    let result = match op {
        "project" => {
            let Some(Value::String(body)) = request.remove("response") else {
                return Err(refuse("request_invalid", Some("/response")));
            };
            let projection = project(action, body.as_bytes()).map_err(|code| refuse(code, None))?;
            json!({ "projection": projection })
        }
        _ => {
            let arguments = request.remove("arguments").unwrap_or_else(|| json!({}));
            if op == "explain" {
                Value::Object(explain(&pack, action, &arguments).map_err(argument_error)?)
            } else if op == "render" {
                json!({ "request": render(action, &arguments).map_err(argument_error)? })
            } else {
                let record = check_arguments(action, &arguments).map_err(argument_error)?;
                json!({ "facts": extract(action, record) })
            }
        }
    };
    Ok(ok(into_map(result)))
}

fn into_map(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn source(request: &mut Map<String, Value>, key: &str) -> Result<CloudActionPack, Value> {
    let value = request
        .remove(key)
        .ok_or_else(|| refuse("request_invalid", Some(&format!("/{key}"))))?;
    pack_from_value(value).map_err(pack_error)
}

/// A `policyPack` document, or a shipped `preset` by name.
fn policy(request: &mut Map<String, Value>) -> Result<PolicyPack, Value> {
    if let Some(name) = request.remove("preset") {
        return name
            .as_str()
            .and_then(Preset::parse)
            .map(|preset| shipped(preset).clone())
            .ok_or_else(|| refuse("preset_unknown", Some("/preset")));
    }
    let value = request
        .remove("policyPack")
        .ok_or_else(|| refuse("request_invalid", Some("/policyPack")))?;
    policy_pack_from_value(value).map_err(pack_error)
}

/// A source pack, or the pack inside a compiled artifact.
fn either(request: &mut Map<String, Value>, key: &str) -> Result<CloudActionPack, Value> {
    let value = request
        .remove(key)
        .ok_or_else(|| refuse("request_invalid", Some(&format!("/{key}"))))?;
    if value.get("schema").and_then(Value::as_str) == Some(ARTIFACT_SCHEMA) {
        return load_value(value)
            .map(|artifact| artifact.pack)
            .map_err(pack_error);
    }
    pack_from_value(value).map_err(pack_error)
}
