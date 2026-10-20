//! The queued package approval a blocked package request takes under
//! `blocked_request_mode = "ask"`.
//!
//! Port of the `ask` branch of `_queue_package_approval_response`
//! (`runtime_mcp.py:2196`). Under `safe-alternative` the proxy blocks the
//! request in place and leaves the silent inbox row; under `ask` it writes a
//! *package-shaped* approval request instead, raises the desktop notice and
//! the approval center, and blocks the call on that request. The agent is told
//! which request to approve and that retrying the same action is what resumes
//! it.
//!
//! The row is not the tool call's. `queue_blocked_approvals` is given the
//! package request's own artifact and an item that carries the supply-chain
//! evaluation, its reason signals and the package decision — fields a tool
//! call's item never holds:
//!
//! - `artifact_type` is the artifact's own `package_request`, and
//!   `changed_fields` names both `runtime_tool_call` and `package_request`;
//! - `launch_target` is the plain projection of the call, with neither the
//!   artifact nor the browser label a tool call's row reads, and Python checks
//!   it for nothing, so an empty target is written rather than deferred;
//! - `risk_summary` is the evaluation's, not the projected risk's;
//! - `risk_signals` are the evaluation's reason signals alone, which is also
//!   what the block receipt records — the `safe-alternative` branch is the one
//!   that leads them with the risk summary;
//! - `decision_v2_json` is `build_decision_v2` over the reasons' own V2
//!   signals, with the evaluation's user copy written over its text;
//! - `supply_chain_evaluation` is the evaluation as the lane settled it, not
//!   the block restatement the `safe-alternative` answer carries.
//!
//! The artifacts map beside it is `_queue_artifact` of a package artifact,
//! whose risk facts — unlike a tool call's — are real: the artifact carries a
//! command summary the `artifact_risk` derivation reads.
//!
//! Everything the row shares with a tool call's is reused from the `ask`
//! modules beside this one: the queue arguments and their continuation
//! snapshot, the store write under the shared storage gate, the read-back
//! through `get_approval_request`, and the link `first_approval_url` resolves.
//!
//! What the resident cannot reproduce defers, and a package-lane defer hands
//! the server to the proxy. The bindings this needs are the same ones the tool
//! call's queue needs — an approval-center origin, a review OAuth source and a
//! bound receipt redaction level, which the daemon publishes together — plus
//! the approval-context token the request hashed to.

use guard_command::decisions::{decision_from_legacy_policy_action, parse_signals};
use guard_command::package_intent_common::GuardArtifact;
use guard_contracts::{GuardAction, McpCallProjectionQueryV1, McpPackageReasonSignalsQueryV1};
use serde_json::{json, Map, Value};

use super::ask;
use super::ask_row;
use super::package_lane::PackageAnswer;
use super::{Admitted, McpRelayDecideRequestV1, Resolved};
use crate::mcp_tool_policy_decision::Decision;

/// The `decision` the proxy's event names for this leg.
pub(super) const DECISION_LABEL: &str = "queue-package-approval";

/// `consumer.projection._METADATA_KEYS` a package-request artifact can carry.
/// The other four are never set on one, and neither is `mcp_tool_identity`,
/// so the wire metadata is these two when the artifact holds them.
const WIRE_METADATA_KEYS: [&str; 2] = ["request_summary", "runtime_request_summary"];
/// `risk._LIST_KEYS | risk._SCALAR_KEYS` a package-request artifact can carry,
/// in the sorted order `_wire_artifact` emits them.
const RISK_METADATA_KEYS: [&str; 4] = [
    "request_summary",
    "runtime_request_reason",
    "runtime_request_signals",
    "runtime_request_summary",
];
/// `_QUEUE_METADATA_KEYS`, which a package-request artifact never carries.
const QUEUE_METADATA_KEYS: [&str; 4] = [
    "raw_command_text",
    "command_text",
    "command_rule_matches",
    "extension_allow_hint",
];

/// A binding or an identity this leg cannot reproduce, which hands the server
/// to the proxy rather than guessing the row.
const PACKAGE_ASK_UNSUPPORTED: &str = "mcp_relay_package_ask_unsupported";
/// The row could not be written, read back or shaped.
const PACKAGE_ASK_FAILED: &str = "mcp_relay_package_ask_failed";

/// Write this package request's approval row and block the call on it.
///
/// `answer` is the lane's own answer for the queued route, already carrying
/// the policy action, the reason signals and the receipt facts; this fills in
/// the block it is answered with and the approval surface the drain raises.
pub(super) fn queue(
    request: &McpRelayDecideRequestV1,
    admitted: &Admitted,
    resolved: &Resolved,
    artifact: &GuardArtifact,
    answer: &PackageAnswer,
) -> Result<PackageAnswer, &'static str> {
    let review = &admitted.binding.review;
    let (Some(center), Some(oauth_source), Some(redaction_level)) = (
        review.approval_center_origin.as_deref(),
        review.review_oauth_source.as_deref(),
        resolved.redaction_level.as_deref(),
    ) else {
        return Err(PACKAGE_ASK_UNSUPPORTED);
    };
    let action =
        GuardAction::from_canonical(&answer.policy_action).ok_or(PACKAGE_ASK_UNSUPPORTED)?;
    let evaluation = Value::Object(answer.evaluation.clone());
    let item = review_item(request, artifact, answer, action, &resolved.decision)?;
    let now = ask::now_isoformat().ok_or(PACKAGE_ASK_FAILED)?;
    let args = ask_row::queue_args(
        request,
        item,
        &artifact.artifact_id,
        queue_artifact(artifact)?,
        center,
        &now,
        redaction_level,
    );
    let (request_id, notice) =
        ask::write(request, oauth_source, args).map_err(|_| PACKAGE_ASK_FAILED)?;
    let row = ask::read_back(request, &request_id).map_err(|_| PACKAGE_ASK_FAILED)?;
    let review_url = ask::review_url(&row, center, &request_id);
    let message = format!(
        "HOL Guard stopped package install request {} from {}. Approve request {request_id} at \
         {review_url}, then retry the same action.",
        request.build.tool_name, request.build.server_name
    );
    let data = json!({
        "approvalCenterUrl": center,
        "approvalRequests": [Value::Object(row)],
        "guardPolicyAction": answer.policy_action,
        "reviewUrl": review_url,
        "supplyChainEvaluation": evaluation,
    });
    Ok(PackageAnswer {
        block: Some((message, data)),
        // What `_notify_pending_approval` and `_maybe_open_approval_center`
        // raise once the row is written, which the drain owns.
        approval: Some(json!({
            "approval_center_url": center,
            "review_url": review_url,
            "request_id": request_id,
            "workspace": admitted.workspace,
            "notices": [notice],
        })),
        ..answer.clone()
    })
}

/// The evaluation item the package request is queued with.
fn review_item(
    request: &McpRelayDecideRequestV1,
    artifact: &GuardArtifact,
    answer: &PackageAnswer,
    action: GuardAction,
    decision: &Decision,
) -> Result<Map<String, Value>, &'static str> {
    let mut item = Map::new();
    item.insert("artifact_id".to_owned(), json!(artifact.artifact_id));
    item.insert("artifact_name".to_owned(), json!(artifact.name));
    item.insert("artifact_hash".to_owned(), json!(answer.artifact_hash));
    item.insert("artifact_type".to_owned(), json!(artifact.artifact_type));
    item.insert("source_scope".to_owned(), json!(artifact.source_scope));
    item.insert("config_path".to_owned(), json!(artifact.config_path));
    item.insert(
        "changed_fields".to_owned(),
        json!(["runtime_tool_call", "package_request"]),
    );
    item.insert("policy_action".to_owned(), json!(answer.policy_action));
    item.insert("launch_target".to_owned(), json!(launch_target(request)?));
    item.insert(
        "risk_summary".to_owned(),
        answer
            .evaluation
            .get("risk_summary")
            .cloned()
            .unwrap_or_else(|| json!("")),
    );
    item.insert("risk_signals".to_owned(), json!(answer.signals));
    item.insert("decision_v2_json".to_owned(), decision_v2(answer, action)?);
    // `_package_scanner_evidence`: the tool decision's own evidence, then the
    // package half the lane held for the receipt.
    let mut evidence = ask_row::scanner_evidence(decision);
    evidence.extend(answer.evidence.iter().cloned());
    item.insert("scanner_evidence".to_owned(), Value::Array(evidence));
    item.insert(
        "supply_chain_evaluation".to_owned(),
        Value::Object(answer.evaluation.clone()),
    );
    Ok(item)
}

/// `self._call_projector.project(tool_name, params).launch_target`: the plain
/// projection, with neither the artifact's risk input nor the browser label a
/// tool call's row displays. Python reads it without checking it, so an empty
/// target is written as the empty string it is.
fn launch_target(request: &McpRelayDecideRequestV1) -> Result<String, &'static str> {
    let projected = crate::mcp_proxy_projection::call_projection(&McpCallProjectionQueryV1 {
        tool_name: request.build.tool_name.clone(),
        params: request.params.clone(),
        risk: None,
    })
    .map_err(|_| PACKAGE_ASK_FAILED)?;
    Ok(projected
        .get("launch_target")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned())
}

/// `_package_decision_v2`: the decision the reasons' own V2 signals compose,
/// with the evaluation's user copy written over its text.
pub(super) fn decision_v2(
    answer: &PackageAnswer,
    action: GuardAction,
) -> Result<Value, &'static str> {
    let reasons = answer
        .evaluation
        .get("reasons")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let projected =
        crate::mcp_proxy_signals::reason_signals(&McpPackageReasonSignalsQueryV1 { reasons });
    let signals = parse_signals(&projected["signals"]).map_err(|_| PACKAGE_ASK_FAILED)?;
    let mut payload =
        decision_from_legacy_policy_action(action, action.as_str(), &signals).to_value();
    let user_copy = answer
        .evaluation
        .get("user_copy")
        .and_then(Value::as_object);
    let copy = |key: &str| {
        user_copy
            .and_then(|copy| copy.get(key))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let fields = payload.as_object_mut().ok_or(PACKAGE_ASK_FAILED)?;
    fields.insert("user_title".to_owned(), copy("title"));
    fields.insert("user_body".to_owned(), copy("summary"));
    fields.insert("harness_message".to_owned(), copy("harness_message"));
    fields.insert("dashboard_primary_detail".to_owned(), copy("summary"));
    Ok(payload)
}

/// `_queue_artifact` for a package-request artifact: the projection wire the
/// capability and incident logic read, the command metadata it never carries,
/// and the artifact's own derived risk facts.
pub(super) fn queue_artifact(artifact: &GuardArtifact) -> Result<Map<String, Value>, &'static str> {
    let risk = guard_command::artifact_risk::artifact_risk(&risk_wire(artifact))
        .map_err(|_| PACKAGE_ASK_FAILED)?;
    let signals: Vec<Value> = risk["signals"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|signal| signal["explanation"].clone())
        .collect();
    let mut queued = Map::new();
    queued.insert("wire".to_owned(), wire_artifact(artifact));
    for key in QUEUE_METADATA_KEYS {
        queued.insert(key.to_owned(), metadata(artifact, key));
    }
    queued.insert("risk_summary".to_owned(), risk["summary"].clone());
    queued.insert("risk_signals".to_owned(), Value::Array(signals));
    Ok(queued)
}

/// `consumer.projection.wire_artifact`: the full launch definition with the
/// metadata filtered to the keys the capability logic reads. A package-request
/// artifact's summaries are always strings, so none of them travel under
/// `capability_text_summaries`.
fn wire_artifact(artifact: &GuardArtifact) -> Value {
    json!({
        "artifact_id": artifact.artifact_id,
        "name": artifact.name,
        "harness": artifact.harness,
        "artifact_type": artifact.artifact_type,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "command": artifact.command,
        "args": artifact.args,
        "url": artifact.url,
        "transport": artifact.transport,
        "publisher": artifact.publisher,
        "metadata": filtered(artifact, &WIRE_METADATA_KEYS),
    })
}

/// `risk._wire_artifact`: the fields the `artifact_risk` derivation accepts,
/// which reject anything else, with the metadata filtered to its own keys.
fn risk_wire(artifact: &GuardArtifact) -> Value {
    json!({
        "name": artifact.name,
        "command": artifact.command,
        "url": artifact.url,
        "args": artifact.args,
        "metadata": filtered(artifact, &RISK_METADATA_KEYS),
    })
}

/// The artifact metadata narrowed to the keys one wire carries, leaving out
/// the keys the artifact does not hold.
fn filtered(artifact: &GuardArtifact, keys: &[&str]) -> Value {
    let mut metadata = Map::new();
    for key in keys {
        if let Some(value) = artifact.metadata.get(*key) {
            metadata.insert((*key).to_owned(), value.clone());
        }
    }
    Value::Object(metadata)
}

/// One metadata value, as `null` when the artifact does not carry it.
fn metadata(artifact: &GuardArtifact, key: &str) -> Value {
    artifact.metadata.get(key).cloned().unwrap_or(Value::Null)
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_ask_tests.rs"]
mod tests;
