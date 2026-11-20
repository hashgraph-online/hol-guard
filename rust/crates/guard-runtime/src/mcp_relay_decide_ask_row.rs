//! The approval row an `ask` block writes: the projection it reads, the
//! evaluation item, the queue arguments and the bounded-grant hint.
//!
//! `review_artifact_payload` and `_queue_artifact` build what the decision
//! owner reads in the approval center, and `temporary_mcp_approval_payload`
//! adds the 15m/1h/5h choices a routine browser capability offers. The block
//! itself lives beside this module, which only shapes what it writes.

use guard_command::effect_decision::GuardAction;
use guard_command::package_intent_common::GuardArtifact;
use guard_contracts::{
    BrowserMcpArtifactV1, McpCallProjectionQueryV1, McpToolCallArtifactV1, McpToolRiskInputV1,
};
use serde_json::{json, Map, Value};

use super::McpRelayDecideRequestV1;
use crate::mcp_tool_policy_decision::Decision;

/// The artifact type a tool call is built with.
pub(super) const ARTIFACT_TYPE: &str = "tool_call";
/// `_QUEUE_METADATA_KEYS`, which a tool-call artifact never carries.
const QUEUE_METADATA_KEYS: [&str; 4] = [
    "raw_command_text",
    "command_text",
    "command_rule_matches",
    "extension_allow_hint",
];
const ASK_PROJECTION: &str = "mcp_relay_ask_projection";

/// The `McpCallProjection` fields the queued item reads.
pub(crate) struct Projection {
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
    projection(&projected).ok_or(ASK_PROJECTION)
}

/// The `McpCallProjection` fields the queued item reads, from a call
/// projected with its artifact.
pub(crate) fn projection(projected: &Value) -> Option<Projection> {
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
        return None;
    }
    Some(Projection {
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
    item(
        &Named::tool(artifact),
        artifact_hash,
        signals,
        projection,
        policy_action,
        scanner_evidence(decision),
    )
}

/// The artifact fields `review_artifact_payload` names an item with.
struct Named<'a> {
    artifact_id: &'a str,
    name: &'a str,
    artifact_type: &'a str,
    source_scope: &'a str,
    config_path: &'a str,
}

impl<'a> Named<'a> {
    fn tool(artifact: &'a McpToolCallArtifactV1) -> Self {
        Self {
            artifact_id: &artifact.artifact_id,
            name: &artifact.name,
            artifact_type: ARTIFACT_TYPE,
            source_scope: &artifact.source_scope,
            config_path: &artifact.config_path,
        }
    }

    fn package(artifact: &'a GuardArtifact) -> Self {
        Self {
            artifact_id: &artifact.artifact_id,
            name: &artifact.name,
            artifact_type: &artifact.artifact_type,
            source_scope: &artifact.source_scope,
            config_path: &artifact.config_path,
        }
    }
}

/// The same item with its scanner evidence already drawn.
fn item(
    artifact: &Named<'_>,
    artifact_hash: &str,
    signals: &[String],
    projection: &Projection,
    policy_action: &str,
    evidence: Vec<Value>,
) -> Map<String, Value> {
    let mut changed_fields = vec![json!("runtime_tool_call")];
    if projection.browser_intent.is_some() {
        changed_fields.push(json!("runtime_browser_tool_call"));
    }
    let mut item = Map::new();
    item.insert("artifact_id".to_owned(), json!(artifact.artifact_id));
    item.insert("artifact_name".to_owned(), json!(artifact.name));
    item.insert("artifact_hash".to_owned(), json!(artifact_hash));
    item.insert("artifact_type".to_owned(), json!(artifact.artifact_type));
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
    if !evidence.is_empty() {
        item.insert("scanner_evidence".to_owned(), Value::Array(evidence));
    }
    item
}

/// `tool_decision_scanner_evidence`: how the decision's action was reached,
/// without any of the call's payload. The package lane leads its own receipt
/// evidence with this, as `_package_scanner_evidence` does.
pub(super) fn scanner_evidence(decision: &Decision) -> Vec<Value> {
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
    queue_args(
        request,
        item,
        &artifact.artifact_id,
        queue_artifact(artifact),
        center,
        now,
        redaction_level,
    )
}

/// The same arguments for an item whose artifact is not a tool call's, which
/// the package lane shapes itself (`mcp_relay_decide_package_ask.rs`).
pub(super) fn queue_args(
    request: &McpRelayDecideRequestV1,
    item: Map<String, Value>,
    artifact_id: &str,
    queued: Map<String, Value>,
    center: &str,
    now: &str,
    redaction_level: &str,
) -> Map<String, Value> {
    let queue = Queue {
        harness: &request.build.harness,
        cwd: json!(request.cwd),
        prompt_shown: true,
        center,
        now,
        redaction_level,
    };
    queue.args(item, artifact_id, queued)
}

/// The silent inbox row `record_unprompted_review` writes for a
/// safe-alternative block: `review_artifact_payload` with no connector setup,
/// queued with no prompt shown.
pub(crate) fn silent_review_args(
    queue: &Queue<'_>,
    artifact: &McpToolCallArtifactV1,
    artifact_hash: &str,
    signals: &[String],
    projection: &Projection,
    policy_action: &str,
    evidence: Vec<Value>,
) -> Map<String, Value> {
    let item = item(
        &Named::tool(artifact),
        artifact_hash,
        signals,
        projection,
        policy_action,
        evidence,
    );
    queue.args(item, &artifact.artifact_id, queue_artifact(artifact))
}

/// The same silent inbox row for a package request, whose item names the
/// package artifact and whose queued artifact is that artifact's own
/// (`package_ask::queue_artifact`).
pub(crate) fn package_silent_review_args(
    queue: &Queue<'_>,
    artifact: &GuardArtifact,
    artifact_hash: &str,
    signals: &[String],
    projection: &Projection,
    policy_action: &str,
    evidence: Vec<Value>,
) -> Option<Map<String, Value>> {
    let queued = super::package_ask::queue_artifact(artifact).ok()?;
    let item = item(
        &Named::package(artifact),
        artifact_hash,
        signals,
        projection,
        policy_action,
        evidence,
    );
    Some(queue.args(item, &artifact.artifact_id, queued))
}

/// The `queue_blocked_approvals` arguments shared by every item of one call.
pub(crate) struct Queue<'a> {
    pub(crate) harness: &'a str,
    /// The writing process's working directory, or null.
    pub(crate) cwd: Value,
    pub(crate) prompt_shown: bool,
    pub(crate) center: &'a str,
    pub(crate) now: &'a str,
    pub(crate) redaction_level: &'a str,
}

impl Queue<'_> {
    fn args(
        &self,
        item: Map<String, Value>,
        artifact_id: &str,
        queued: Map<String, Value>,
    ) -> Map<String, Value> {
        let Self {
            harness,
            cwd,
            prompt_shown,
            center,
            now,
            redaction_level,
        } = self;
        let mut artifacts = Map::new();
        artifacts.insert(artifact_id.to_owned(), Value::Object(queued));
        let mut args = Map::new();
        args.insert("harness".to_owned(), json!(harness));
        args.insert("items".to_owned(), json!([Value::Object(item)]));
        args.insert("artifacts".to_owned(), Value::Object(artifacts));
        args.insert("approval_center_url".to_owned(), json!(center));
        args.insert("now".to_owned(), json!(now));
        args.insert("prompt_shown".to_owned(), json!(prompt_shown));
        args.insert("redaction_level".to_owned(), json!(redaction_level));
        args.insert("guard_version".to_owned(), json!(crate::PACKAGE_VERSION));
        args.insert("cwd".to_owned(), cwd.clone());
        // `continuation_offer_facts` for an operation the proxy offers no
        // continuation for: every fact is its default and the metadata is empty.
        args.insert(
            "continuation".to_owned(),
            json!({
                "harness": harness,
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
    crate::temporary_mcp_grant::approval(row.get("browser_intent"))
}

/// `_nonempty_string`.
pub(super) fn nonempty(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

#[cfg(test)]
#[path = "mcp_relay_decide_ask_row_tests.rs"]
mod tests;
