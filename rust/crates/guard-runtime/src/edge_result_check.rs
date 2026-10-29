//! The edge checks its own answer before it sends it.
//!
//! A pre-tool result must be internally coherent, and the decision receipt
//! must be valid and agree with the result it records. The hook client used
//! to re-check both on every answer; the edge owns the check now, so every
//! consumer of an edge result (the daemon, the direct hook path, approval
//! context) reads one answer that was checked where it was made.

use guard_command::native_command_extension_evidence::validate_native_command_observations;
use guard_contracts::GuardHookEdgeResultV2;
use serde_json::{Map, Value};

use crate::guard_store_guard_event::from_json;
use crate::native_decision_receipt;
use crate::pyjson;

const INVALID: &str = "native_hook_edge_response_invalid";
const RESULT_SCHEMA: &str = "guard-pre-tool-result.v1";
const ACTION_SCHEMA: &str = "guard-pre-tool-action.v1";
const MAX_RESULT_TEXT: usize = 2_048;
const MAX_HARNESS_CHARS: usize = 64;
const RESULT_FIELDS: [&str; 10] = [
    "schema",
    "version",
    "authority",
    "action",
    "decision",
    "policy_action",
    "minimum_action",
    "reason_code",
    "reason",
    "explicitly_benign",
];
/// Fields a result may carry beyond the required ones. The repair pair is
/// what `command_policy_repair` adds to a block the user can repair.
const RESULT_OPTIONAL_FIELDS: [&str; 4] = [
    "command_extensions",
    "prompt_risk_classes",
    "repair_url",
    "repair_status",
];
const ACTION_FIELDS: [&str; 8] = [
    "schema",
    "version",
    "harness",
    "event",
    "action_type",
    "operation",
    "bounded",
    "sensitive_target",
];
const POLICY_ACTIONS: [&str; 6] = [
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];

/// The operations an action type may name.
fn operations(action_type: &str) -> &'static [&'static str] {
    match action_type {
        "command" => &["execute"],
        "file_read" => &["read"],
        "file_write" => &["write"],
        "package" => &["install"],
        "mcp_tool" => &["call"],
        "network" => &["request"],
        "process_service" => &["start", "stop"],
        "browser" => &["navigate"],
        "config" => &["set"],
        "prompt" => &["submit"],
        "harness" => &["start", "stop", "set", "read"],
        "unknown" => &["unknown"],
        _ => &[],
    }
}

/// The typed pre-tool result, before the receipt is built from it.
pub(super) fn validate_pre_tool_result(result: &Value) -> Result<(), String> {
    let typed: guard_contracts::PreToolResultV1 = serde_json::from_value(result.clone())
        .map_err(|_| "native_hook_pre_tool_result_invalid".to_owned())?;
    if typed.schema != RESULT_SCHEMA || typed.authority != "rust" {
        return Err("native_hook_pre_tool_result_schema_invalid".to_owned());
    }
    Ok(())
}

/// Refuse an edge whose result or receipt a hook client could not trust.
pub(super) fn check(edge: &GuardHookEdgeResultV2) -> Result<(), String> {
    if checked(edge).unwrap_or(false) {
        Ok(())
    } else {
        Err(INVALID.to_owned())
    }
}

fn checked(edge: &GuardHookEdgeResultV2) -> Option<bool> {
    let event = edge.event_name.as_str();
    let harness = edge.harness.as_str();
    let kind = serde_json::to_value(&edge.payload_kind).ok()?;
    let kind = kind.as_str()?;
    let result = edge.result.as_object()?;
    let receipt = serde_json::to_value(&edge.receipt).ok()?;
    if harness.is_empty() || harness.chars().count() > MAX_HARNESS_CHARS {
        return Some(false);
    }
    let route = edge.containment_route.as_deref().unwrap_or("none");
    if !matches!(route, "none" | "sink" | "grant") || (event != "PreToolUse" && route != "none") {
        return Some(false);
    }
    let shaped = match event {
        "PreToolUse" => {
            matches!(kind, "inline" | "source_file_ref") && pre_tool_result(result, harness, event)
        }
        "UserPromptSubmit" => kind == "inline" && pre_tool_result(result, harness, event),
        "PostToolUse" => matches!(kind, "inline" | "source_file_ref" | "encrypted_payload_ref"),
        _ => false,
    };
    Some(shaped && receipt_agrees(edge, kind, result, &receipt))
}

fn bounded_text(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| !text.is_empty() && text.chars().count() <= MAX_RESULT_TEXT)
}

pub(super) fn pre_tool_result(result: &Map<String, Value>, harness: &str, event: &str) -> bool {
    let known = |key: &String| {
        RESULT_FIELDS.contains(&key.as_str()) || RESULT_OPTIONAL_FIELDS.contains(&key.as_str())
    };
    if !RESULT_FIELDS.iter().all(|name| result.contains_key(*name)) || !result.keys().all(known) {
        return false;
    }
    let field = |name: &str| result.get(name).unwrap_or(&Value::Null);
    if ["repair_url", "repair_status"]
        .iter()
        .any(|name| result.get(*name).is_some_and(|value| !value.is_string()))
    {
        return false;
    }
    if let Some(classes) = result.get("prompt_risk_classes") {
        if event != "UserPromptSubmit"
            || !from_json(classes)
                .is_some_and(|classes| native_decision_receipt::valid_prompt_risk_classes(&classes))
        {
            return false;
        }
    }
    let (Some(decision), Some(minimum), Some(benign)) = (
        field("decision").as_str(),
        field("minimum_action").as_str(),
        field("explicitly_benign").as_bool(),
    ) else {
        return false;
    };
    if let Some(extensions) = result.get("command_extensions") {
        // The floor for an uncertain match is the evaluator's to choose; a
        // structurally valid receipt only has to keep a failed evaluation blocked.
        if validate_native_command_observations(extensions).is_none()
            || (!extensions["evaluation_error"].is_null() && minimum != "block")
        {
            return false;
        }
    }
    if field("schema").as_str() != Some(RESULT_SCHEMA)
        || field("version").as_u64() != Some(1)
        || field("authority").as_str() != Some("rust")
        || !matches!(decision, "allow" | "deny")
        || !POLICY_ACTIONS.contains(&minimum)
        || field("policy_action").as_str() != Some(minimum)
        || !bounded_text(field("reason_code"))
        || !bounded_text(field("reason"))
        || !pre_tool_action(field("action"), harness, event)
    {
        return false;
    }
    // `warn` is an allow-with-warning floor; every stronger action denies.
    benign == (decision == "allow" && minimum == "allow")
        && decision
            == if matches!(minimum, "allow" | "warn") {
                "allow"
            } else {
                "deny"
            }
}

fn pre_tool_action(action: &Value, harness: &str, event: &str) -> bool {
    let Some(action) = action.as_object() else {
        return false;
    };
    if action.len() != ACTION_FIELDS.len()
        || !action
            .keys()
            .all(|key| ACTION_FIELDS.contains(&key.as_str()))
    {
        return false;
    }
    let text = |name: &str| action.get(name).and_then(Value::as_str);
    let flag = |name: &str| action.get(name).is_some_and(Value::is_boolean);
    let (Some(action_type), Some(operation)) = (text("action_type"), text("operation")) else {
        return false;
    };
    text("schema") == Some(ACTION_SCHEMA)
        && action.get("version").and_then(Value::as_u64) == Some(1)
        && text("harness") == Some(harness)
        && text("event") == Some(event)
        && (event != "UserPromptSubmit" || action_type == "prompt")
        && flag("bounded")
        && flag("sensitive_target")
        && operations(action_type).contains(&operation)
}

/// The receipt is valid and records exactly the result it accompanies.
fn receipt_agrees(
    edge: &GuardHookEdgeResultV2,
    kind: &str,
    result: &Map<String, Value>,
    receipt: &Value,
) -> bool {
    receipt_records(
        edge.event_name.as_str(),
        edge.harness.as_str(),
        edge.request_id.as_deref(),
        kind,
        result,
        receipt,
    )
}

/// A receipt handed back by a caller outside the edge: one read from the
/// store, or one carried by a queued review. Without an edge it must only be
/// valid; with one it must record exactly that result.
pub(crate) fn standalone_receipt(receipt: &Value, edge: &Value) -> bool {
    if edge.is_null() {
        return valid_receipt(receipt);
    }
    let Some(edge) = edge.as_object() else {
        return false;
    };
    let text = |name: &str| edge.get(name).and_then(Value::as_str);
    let request_id = match edge.get("request_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(request_id)) => Some(request_id.as_str()),
        Some(_) => return false,
    };
    let (Some(event), Some(harness), Some(kind), Some(result)) = (
        text("event_name"),
        text("harness"),
        text("payload_kind"),
        edge.get("result").and_then(Value::as_object),
    ) else {
        return false;
    };
    let action = result.get("action");
    let prompt = |name: &str| {
        action
            .and_then(|action| action.get(name))
            .and_then(Value::as_str)
    };
    if event == "UserPromptSubmit"
        && (prompt("event") != Some(event) || prompt("action_type") != Some("prompt"))
    {
        return false;
    }
    receipt_records(event, harness, request_id, kind, result, receipt)
}

fn valid_receipt(receipt: &Value) -> bool {
    // The validator reads the receipt as a hook client parses it off the wire.
    pyjson::parse(&receipt.to_string())
        .is_ok_and(|receipt| native_decision_receipt::valid(&receipt))
}

fn receipt_records(
    event: &str,
    harness: &str,
    request_id: Option<&str>,
    kind: &str,
    result: &Map<String, Value>,
    receipt: &Value,
) -> bool {
    if !valid_receipt(receipt) {
        return false;
    }
    let Some(receipt) = receipt.as_object() else {
        return false;
    };
    let pre_tool = event != "PostToolUse";
    let recorded = |name: &str| receipt.get(name).unwrap_or(&Value::Null);
    let answered = |name: &str| result.get(name).unwrap_or(&Value::Null);
    let present = |name: &str| result.get(name).filter(|value| !value.is_null());
    let model_output_action = if pre_tool {
        Value::from("not_applicable")
    } else {
        answered("model_output_action").clone()
    };
    let extensions = match present("command_extensions") {
        Some(evidence) if pre_tool && validate_native_command_observations(evidence).is_some() => {
            Some(&evidence["binding"])
        }
        Some(_) => return false,
        None => None,
    };
    let classes = present("prompt_risk_classes");
    if classes.is_some() && event != "UserPromptSubmit" {
        return false;
    }
    recorded("event_name").as_str() == Some(event)
        && recorded("harness").as_str() == Some(harness)
        && recorded("payload_kind").as_str() == Some(kind)
        && request_id.is_none_or(|request_id| recorded("request_id").as_str() == Some(request_id))
        && recorded("decision") == answered("decision")
        && recorded("model_output_action") == &model_output_action
        && recorded("policy_action") == answered("policy_action")
        && recorded("observed_policy_action") == answered("observed_policy_action")
        && recorded("reason_code") == answered("reason_code")
        && recorded("reviewed_output_sha256") == answered("reviewed_output_sha256")
        && recorded("observe_mode").as_bool()
            == Some(answered("observe_mode") == &Value::Bool(true))
        && receipt.get("command_extensions") == extensions
        && receipt.get("prompt_risk_classes") == classes
}
