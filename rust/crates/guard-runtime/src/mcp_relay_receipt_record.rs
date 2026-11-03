//! Which queued relay records are plain: the record shape the relay writes
//! and the native decision's checks, as the Python drain's `_decode` and
//! `_validated_decision` read them.

use serde_json::{Map, Value};

const KIND: &str = "mcp_tool_call";
/// The harnesses whose MCP proxy the relay replaces.
const RELAY_HARNESSES: [&str; 6] = ["cline", "codex", "copilot", "cursor", "hermes", "opencode"];
const RECORD_KEYS: [&str; 10] = [
    "kind",
    "harness",
    "outcome",
    "decision_source",
    "policy_action",
    "tool_name",
    "params",
    "arguments",
    "identity",
    "decision",
];
/// The post-claim check's evidence, the one optional key a plain record has.
const APPEND_KEY: &str = "evidence_append";
const IDENTITY_KEYS: [&str; 4] = [
    "artifact",
    "runtime_private_metadata",
    "artifact_hash",
    "risk_categories",
];
const ARTIFACT_KEYS: [&str; 9] = [
    "artifact_id",
    "name",
    "harness",
    "source_scope",
    "config_path",
    "command",
    "transport",
    "publisher",
    "metadata",
];
const TOKEN_PREFIX: &str = "guard-approval-context:v1:";
/// The native decision's keys, `_validated_decision`'s `_PAYLOAD_KEYS`. A
/// decision naming a connector setup also writes the review row, which the
/// daemon does.
const DECISION_KEYS: [&str; 16] = [
    "action",
    "policy_action",
    "source",
    "signals",
    "summary",
    "risk_categories",
    "normalization_reason_code",
    "original_action",
    "approval_reuse_status",
    "approval_reuse_reason_code",
    "current_action",
    "saved_action",
    "pending_approval_reuse_decision",
    "approval_reuse_claim_disposition",
    "post_claim_revalidated",
    "post_claim_authority",
];
const GUARD_ACTIONS: [&str; 6] = [
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];
const FORWARD_ACTIONS: [&str; 2] = ["allow", "warn"];
/// A policy block, and the two refusals of the client's inline prompt.
const BLOCK_SOURCES: [&str; 3] = ["policy-block", "inline-denied", "inline-invalid"];
/// `_NON_EXECUTED_TOOL_CALL_TAXONOMY`: the event and provenance of a block.
const BLOCK_TAXONOMY: [(&str, &str, &str); 4] = [
    (
        "review",
        "runtime_tool_call_review_required",
        "runtime tool call awaiting review",
    ),
    (
        "require-reapproval",
        "runtime_tool_call_reapproval_required",
        "runtime tool call awaiting fresh approval",
    ),
    (
        "sandbox-required",
        "runtime_tool_call_sandbox_required",
        "runtime tool call requires an enforceable sandbox",
    ),
    (
        "block",
        "runtime_tool_call_blocked",
        "runtime tool call blocked",
    ),
];

/// The fields of a record the resident can write the receipt of.
pub(super) struct Plain<'a> {
    pub(super) harness: &'a str,
    pub(super) forward: bool,
    pub(super) source: &'a str,
    pub(super) policy_action: &'a str,
    pub(super) tool_name: &'a str,
    pub(super) params: &'a Value,
    pub(super) artifact: &'a Map<String, Value>,
    pub(super) artifact_hash: &'a str,
    pub(super) firewall: &'a Value,
    pub(super) decision: &'a Map<String, Value>,
    pub(super) append: &'a [Value],
}

pub(super) fn plain(record: &Value) -> Option<Plain<'_>> {
    let record = record.as_object()?;
    if !RECORD_KEYS.iter().all(|key| record.contains_key(*key))
        || record
            .keys()
            .any(|key| key != APPEND_KEY && !RECORD_KEYS.contains(&key.as_str()))
    {
        return None;
    }
    let append = match record.get(APPEND_KEY) {
        None => &[][..],
        Some(Value::Array(items)) if items.iter().all(Value::is_object) => items.as_slice(),
        Some(_) => return None,
    };
    let text = |key: &str| record.get(key).and_then(Value::as_str);
    let harness = text("harness").filter(|harness| RELAY_HARNESSES.contains(harness))?;
    let source = text("decision_source")?;
    let policy_action = text("policy_action")?;
    let tool_name = text("tool_name")?;
    let params = &record["params"];
    if text("kind") != Some(KIND)
        || !params.is_object()
        || params.get("name").and_then(Value::as_str) != Some(tool_name)
    {
        return None;
    }
    let forward = match text("outcome")? {
        "forward" if FORWARD_ACTIONS.contains(&policy_action) => true,
        "block" if block_taxonomy(policy_action).is_some() && BLOCK_SOURCES.contains(&source) => {
            false
        }
        _ => return None,
    };
    let identity = exact_object(&record["identity"], &IDENTITY_KEYS)?;
    let artifact = exact_object(&identity["artifact"], &ARTIFACT_KEYS)?;
    let artifact_hash = identity["artifact_hash"]
        .as_str()
        .filter(|hash| hash.starts_with(TOKEN_PREFIX))?;
    // Without it the proxy enriches the artifact first, which the daemon does.
    let firewall = artifact["metadata"]
        .as_object()?
        .get("mcpSkillFirewall")
        .filter(|firewall| firewall.is_object())?;
    if !identity["runtime_private_metadata"].is_object()
        || !string_list(&identity["risk_categories"])
        || artifact["harness"].as_str() != Some(harness)
        || ["artifact_id", "name", "source_scope", "config_path"]
            .iter()
            .any(|key| !artifact[*key].is_string())
        || ["command", "transport", "publisher"]
            .iter()
            .any(|key| !(artifact[*key].is_string() || artifact[*key].is_null()))
    {
        return None;
    }
    let decision = exact_object(&record["decision"], &DECISION_KEYS)?;
    if !decision_fits(decision) || !arguments_fit(params, &record["arguments"]) {
        return None;
    }
    Some(Plain {
        harness,
        forward,
        source,
        policy_action,
        tool_name,
        params,
        artifact,
        artifact_hash,
        firewall,
        decision,
        append,
    })
}

/// `_validated_decision` and `_decision`: a well-formed native decision that
/// was not claimed under a fresh authority, which the daemon owns.
fn decision_fits(decision: &Map<String, Value>) -> bool {
    let action = |key: &str| {
        decision[key]
            .as_str()
            .is_some_and(|action| GUARD_ACTIONS.contains(&action))
    };
    let one_of = |key: &str, allowed: &[&str]| match &decision[key] {
        Value::Null => true,
        Value::String(text) => allowed.contains(&text.as_str()),
        _ => false,
    };
    action("action")
        && action("policy_action")
        && decision["source"].is_string()
        && decision["summary"].is_string()
        && string_list(&decision["signals"])
        && string_list(&decision["risk_categories"])
        && [
            "normalization_reason_code",
            "original_action",
            "approval_reuse_reason_code",
        ]
        .iter()
        .all(|key| decision[*key].is_null() || decision[*key].is_string())
        && one_of(
            "approval_reuse_status",
            &["accepted", "rejected", "not-applicable"],
        )
        && one_of("current_action", &GUARD_ACTIONS)
        && one_of("saved_action", &GUARD_ACTIONS)
        && (decision["pending_approval_reuse_decision"].is_null()
            || decision["pending_approval_reuse_decision"].is_object())
        && one_of(
            "approval_reuse_claim_disposition",
            &["consumed", "retained"],
        )
        && decision["post_claim_revalidated"] == Value::Bool(false)
        && decision["post_claim_authority"].is_null()
}

fn exact_object<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Map<String, Value>> {
    value.as_object().filter(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn string_list(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(Value::is_string))
}

/// `_ordered_params`: a mapping's host-ordered entries must name exactly the
/// decoded arguments.
fn arguments_fit(params: &Value, arguments: &Value) -> bool {
    if arguments.get("format").and_then(Value::as_str) != Some("mapping") {
        return true;
    }
    let (Some(entries), Some(current)) = (
        arguments.get("entries").and_then(Value::as_array),
        params.get("arguments").and_then(Value::as_object),
    ) else {
        return false;
    };
    let mut ordered = Map::new();
    for entry in entries {
        let Some([Value::String(key), value]) = entry.as_array().map(Vec::as_slice) else {
            return false;
        };
        ordered.insert(key.clone(), value.clone());
    }
    &ordered == current
}

pub(super) fn block_taxonomy(policy_action: &str) -> Option<(&'static str, &'static str)> {
    BLOCK_TAXONOMY
        .iter()
        .find(|(action, ..)| *action == policy_action)
        .map(|(_, event, provenance)| (*event, *provenance))
}
