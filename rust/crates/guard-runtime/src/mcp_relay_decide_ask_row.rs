//! The approval row an `ask` block writes: the projection it reads, the
//! evaluation item, the queue arguments and the bounded-grant hint.
//!
//! `review_artifact_payload` and `_queue_artifact` build what the decision
//! owner reads in the approval center, and `temporary_mcp_approval_payload`
//! adds the 15m/1h/5h choices a routine browser capability offers. The block
//! itself lives beside this module, which only shapes what it writes.

use guard_command::effect_decision::GuardAction;
use guard_contracts::{
    BrowserMcpArtifactV1, McpCallProjectionQueryV1, McpToolCallArtifactV1, McpToolRiskInputV1,
};
use serde_json::{json, Map, Value};

use super::McpRelayDecideRequestV1;
use crate::mcp_tool_policy_decision::Decision;

/// The artifact type a tool call is built with.
const ARTIFACT_TYPE: &str = "tool_call";
/// `_QUEUE_METADATA_KEYS`, which a tool-call artifact never carries.
const QUEUE_METADATA_KEYS: [&str; 4] = [
    "raw_command_text",
    "command_text",
    "command_rule_matches",
    "extension_allow_hint",
];
/// `TEMPORARY_MCP_GRANT_TARGETS`.
const GRANT_TARGETS: [&str; 3] = ["exact", "category", "server"];
/// `["once", *TEMPORARY_MCP_GRANT_DURATIONS]`.
const GRANT_DURATIONS: [&str; 4] = ["once", "15m", "1h", "5h"];
/// `_HARD_RISK_EXCLUSIONS`.
const HARD_RISK_EXCLUSIONS: [&str; 10] = [
    "browser_transfer",
    "browser_privileged",
    "browser_sensitive_surface",
    "browser_shared_profile",
    "secret_access",
    "filesystem_access",
    "command_execution",
    "destructive_mutation",
    "privileged_system_mutation",
    "tool_schema_mismatch",
];
/// `_INTENT_CATEGORIES`.
const INTENT_CATEGORIES: [(&str, &str); 3] = [
    ("browser.navigation", "browser_navigation"),
    ("browser.inspect", "browser_inspection"),
    ("browser.interact", "browser_interaction"),
];
/// The one `_INFORMATIONAL_CATEGORIES` entry.
const INFORMATIONAL_CATEGORY: &str = "browser_external_domain";

const ASK_PROJECTION: &str = "mcp_relay_ask_projection";

/// The `McpCallProjection` fields the queued item reads.
pub(super) struct Projection {
    /// `display_launch_target`.
    pub(super) launch_target: String,
    pub(super) risk_summary: String,
    pub(super) browser_intent: Option<Value>,
}

/// `self._call_projector.project(tool_name, params, artifact)`.
pub(super) fn project(
    request: &McpRelayDecideRequestV1,
    artifact: &McpToolCallArtifactV1,
) -> Result<Projection, &'static str> {
    let projected = crate::mcp_proxy_projection::call_projection(&McpCallProjectionQueryV1 {
        tool_name: request.build.tool_name.clone(),
        params: request.params.clone(),
        // `risk_input(artifact, params["arguments"])`, taken from the
        // arguments in the order the host sent them; the decoded params lost
        // that order, and the risk evidence reads it.
        risk: Some(McpToolRiskInputV1 {
            artifact: BrowserMcpArtifactV1 {
                name: artifact.name.clone(),
                command: artifact.command.clone(),
                metadata: artifact.metadata.clone(),
            },
            arguments: request.arguments.clone(),
            risk_categories: None,
            summary_code: None,
        }),
    })
    .map_err(|_| ASK_PROJECTION)?;
    let browser = projected.get("browser").filter(|value| !value.is_null());
    // `display_launch_target`: the browser label for a browser navigation,
    // else the plain target.
    let launch_target = match browser {
        Some(browser) => browser.get("launch_target"),
        None => projected.get("launch_target"),
    }
    .and_then(Value::as_str)
    .unwrap_or_default()
    .to_owned();
    let risk_summary = projected
        .get("risk")
        .and_then(|risk| risk.get("summary"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if launch_target.is_empty() || risk_summary.is_empty() {
        return Err(ASK_PROJECTION);
    }
    Ok(Projection {
        launch_target,
        risk_summary,
        browser_intent: browser.and_then(|browser| browser.get("intent")).cloned(),
    })
}

/// `review_artifact_payload`: the evaluation item a queued `tools/call` is
/// written to the inbox with.
pub(super) fn review_item(
    artifact: &McpToolCallArtifactV1,
    artifact_hash: &str,
    signals: &[String],
    projection: &Projection,
    policy_action: &str,
    decision: &Decision,
) -> Map<String, Value> {
    let mut changed_fields = vec![json!("runtime_tool_call")];
    if projection.browser_intent.is_some() {
        changed_fields.push(json!("runtime_browser_tool_call"));
    }
    let mut item = Map::new();
    item.insert("artifact_id".to_owned(), json!(artifact.artifact_id));
    item.insert("artifact_name".to_owned(), json!(artifact.name));
    item.insert("artifact_hash".to_owned(), json!(artifact_hash));
    item.insert("artifact_type".to_owned(), json!(ARTIFACT_TYPE));
    item.insert("source_scope".to_owned(), json!(artifact.source_scope));
    item.insert("config_path".to_owned(), json!(artifact.config_path));
    item.insert("changed_fields".to_owned(), Value::Array(changed_fields));
    item.insert("policy_action".to_owned(), json!(policy_action));
    item.insert("launch_target".to_owned(), json!(projection.launch_target));
    item.insert("risk_summary".to_owned(), json!(projection.risk_summary));
    item.insert(
        "risk_signals".to_owned(),
        Value::Array(signals.iter().map(|signal| json!(signal)).collect()),
    );
    if let Some(intent) = &projection.browser_intent {
        item.insert("browser_intent".to_owned(), intent.clone());
    }
    let evidence = scanner_evidence(decision);
    if !evidence.is_empty() {
        item.insert("scanner_evidence".to_owned(), Value::Array(evidence));
    }
    item
}

/// `tool_decision_scanner_evidence`: how the decision's action was reached,
/// without any of the call's payload.
fn scanner_evidence(decision: &Decision) -> Vec<Value> {
    let facts = crate::mcp_tool_policy_proxy::facts(decision);
    let effective = crate::mcp_proxy_actions::enforcement(&facts.action, &facts);
    let mut evidence = Vec::new();
    if let Some(reason_code) = &decision.normalization_reason_code {
        evidence.push(json!({
            "source": "guard_action_normalizer",
            "input_source": "stored_tool_policy",
            "reason_code": reason_code,
            "original_action": decision.original_action,
            "normalized_action": effective.as_str(),
        }));
    }
    if let Some(reason_code) = &decision.approval_reuse_reason_code {
        evidence.push(json!({
            "source": "approval_reuse",
            "status": decision.approval_reuse_status,
            "reason_code": reason_code,
            "current_action": decision.current_action.map(GuardAction::as_str),
            "saved_action": decision.saved_action.map(GuardAction::as_str),
            "effective_action": effective.as_str(),
        }));
    }
    evidence
}

/// The `queue_blocked_approvals` arguments for this one item.
pub(super) fn args(
    request: &McpRelayDecideRequestV1,
    item: Map<String, Value>,
    artifact: &McpToolCallArtifactV1,
    center: &str,
    now: &str,
    redaction_level: &str,
) -> Map<String, Value> {
    let mut artifacts = Map::new();
    artifacts.insert(
        artifact.artifact_id.clone(),
        Value::Object(queue_artifact(artifact)),
    );
    let mut args = Map::new();
    args.insert("harness".to_owned(), json!(request.build.harness));
    args.insert("items".to_owned(), json!([Value::Object(item)]));
    args.insert("artifacts".to_owned(), Value::Object(artifacts));
    args.insert("approval_center_url".to_owned(), json!(center));
    args.insert("now".to_owned(), json!(now));
    args.insert("prompt_shown".to_owned(), json!(true));
    args.insert("redaction_level".to_owned(), json!(redaction_level));
    args.insert("guard_version".to_owned(), json!(crate::PACKAGE_VERSION));
    args.insert("cwd".to_owned(), json!(request.cwd));
    // `continuation_offer_facts` for an operation the proxy offers no
    // continuation for: every fact is its default and the metadata is empty.
    args.insert(
        "continuation".to_owned(),
        json!({
            "harness": request.build.harness,
            "original_hook_attached": false,
            "wait_deadline": Value::Null,
            "opaque_target_id": Value::Null,
            "session_target_verified": false,
            "now": now,
            "correlation_candidates": [Value::Null, Value::Null],
        }),
    );
    args
}

/// `_queue_artifact`: the artifact facts the decision owner reads beside the
/// item. A tool-call artifact carries none of the command metadata, and the
/// item's own risk facts are non-empty, so the artifact's are never read.
fn queue_artifact(artifact: &McpToolCallArtifactV1) -> Map<String, Value> {
    let mut queued = Map::new();
    queued.insert("wire".to_owned(), wire_artifact(artifact));
    for key in QUEUE_METADATA_KEYS {
        queued.insert(key.to_owned(), Value::Null);
    }
    queued.insert("risk_summary".to_owned(), Value::Null);
    queued.insert("risk_signals".to_owned(), Value::Array(Vec::new()));
    queued
}

/// `wire_artifact`: none of the `_METADATA_KEYS` are ever set on a tool-call
/// artifact, so the wire metadata is the identity mark alone.
fn wire_artifact(artifact: &McpToolCallArtifactV1) -> Value {
    json!({
        "artifact_id": artifact.artifact_id,
        "name": artifact.name,
        "harness": artifact.harness,
        "artifact_type": ARTIFACT_TYPE,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "command": artifact.command,
        "args": [],
        "url": Value::Null,
        "transport": artifact.transport,
        "publisher": artifact.publisher,
        "metadata": {"mcp_tool_identity": true},
    })
}

/// `temporary_mcp_approval_payload`: the bounded-grant choices a routine
/// browser capability offers in the approval center.
pub(super) fn temporary_mcp_approval(row: &Map<String, Value>) -> Option<Value> {
    let intent = row.get("browser_intent")?.as_object()?;
    let identity_hash = nonempty(intent.get("mcp_server_identity_hash"))?;
    let server_name = nonempty(intent.get("mcp_server_name"))?;
    let named = nonempty(intent.get("intent"))?;
    let category = INTENT_CATEGORIES
        .iter()
        .find(|(name, _)| *name == named)
        .map(|(_, category)| *category)?;
    let risk_categories: Vec<&str> = intent
        .get("risk_categories")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if !risk_categories.contains(&category) {
        return None;
    }
    if !risk_categories
        .iter()
        .all(|item| *item == category || *item == INFORMATIONAL_CATEGORY)
    {
        return None;
    }
    let target_label =
        nonempty(intent.get("target_domain")).or_else(|| nonempty(intent.get("target_origin")));
    Some(json!({
        "version": 1,
        "eligible": true,
        "server_name": server_name,
        "server_identity_hash": identity_hash,
        "category": category,
        "target_label": target_label,
        "allowed_targets": GRANT_TARGETS,
        "allowed_durations": GRANT_DURATIONS,
        "hard_risk_exclusions": HARD_RISK_EXCLUSIONS,
    }))
}

/// `_nonempty_string`.
pub(super) fn nonempty(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

#[cfg(test)]
#[path = "mcp_relay_decide_ask_row_tests.rs"]
mod tests;
