//! The observed approval requests a forwarded package call is queued with
//! under `mode = "observe"`.
//!
//! Port of the `observe_forward` branch of `_handle_package_request`
//! (`runtime_mcp.py:1619`). In observe mode the proxy forwards the call under
//! the action it would have *executed* — the most restrictive action either
//! policy permits — and writes the approval requests the actions it did not
//! permit would have blocked it on, so the decision owner still sees what the
//! enforced policy would have stopped. The forward itself is the ordinary one:
//! the allow receipt the drain writes, under `policy-observe` rather than the
//! action's own source, with the observe evidence appended to it.
//!
//! Two rows at most, in the order the proxy writes them
//! (`_queue_observed_approval_requests`, :3365): the tool call's own, then the
//! package request's (`_queue_observed_package_request`, :2112). Each is
//! written with the same `queue_blocked_approvals` arguments as the `ask`
//! lane's row, so everything they share is reused from the modules beside this
//! one — the queue arguments, the continuation snapshot, the store write under
//! the shared storage gate and the read-back through `get_approval_request`.
//!
//! What the observed rows do *not* share with that lane is the surface. The
//! call is forwarded rather than blocked on them, so there is no approval
//! center to open and nothing to answer the client with: the proxy raises the
//! desktop notice alone, through the `notify=True` its queue takes by default.
//! The relay carries those notices on the forward's receipt for the drain to
//! raise, which is where every other surface this lane leaves is raised.
//!
//! Two differences from the `ask` row are the proxy's own, and both are kept:
//!
//! - the projection's risk summary is not read. The tool row states the
//!   decision's own summary and signals, and the package row the evaluation's,
//!   so an empty projected risk is written rather than deferred — unlike the
//!   `ask` lane, which falls back to the artifact's risk facts and so defers;
//! - the tool row always carries `scanner_evidence`, even when the decision
//!   reached its action with none, because the observed branch passes the key
//!   whether or not the evidence is empty.
//!
//! The observed actions are only ever `review` or `require-reapproval`: the
//! composition answers a terminal observed action as a terminal leg before it
//! reaches this branch, and a permitted one queues nothing. Anything else
//! defers rather than writing a row the store would drop unqueued.

use guard_command::package_intent_common::GuardArtifact;
use guard_contracts::{
    BrowserMcpArtifactV1, GuardAction, McpCallProjectionQueryV1, McpToolRiskInputV1,
};
use serde_json::{json, Map, Value};

use super::ask;
use super::ask_row;
use super::package_ask;
use super::package_lane::PackageAnswer;
use super::{Admitted, McpRelayDecideRequestV1, Resolved};

/// `decision_source` the observed forward's receipt is recorded under, which
/// names the mode rather than the action the call was forwarded with.
pub(super) const OBSERVE_SOURCE: &str = "policy-observe";

/// The observe answer named a leg this port cannot write, which hands the
/// server to the proxy rather than forwarding without the row.
const PACKAGE_OBSERVE_UNSUPPORTED: &str = "mcp_relay_package_observe_unsupported";
/// A row could not be written, read back or shaped.
const PACKAGE_OBSERVE_FAILED: &str = "mcp_relay_package_observe_failed";

/// What the observe composition decided: the action the call is forwarded
/// under, the observed requests to queue first, and the evidence the forward's
/// receipt records the override with.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Observed {
    /// `executed_action`: the action the forward is recorded under.
    pub(super) executed_action: String,
    /// `queue_observed_tool`: the action the tool policy would have stopped
    /// the call with, which its observed row is written for.
    pub(super) tool: Option<String>,
    /// `queue_observed_package`: the same for the package policy.
    pub(super) package: Option<String>,
    /// `evidence_append`: the observe-mode entry the receipt's scanner
    /// evidence ends with, which only an overridden observation leaves.
    pub(super) evidence_append: Vec<Value>,
}

/// The observe answer as the route reads it.
pub(super) fn observed(answer: &Value) -> Result<Observed, &'static str> {
    let action = |key: &str| match answer.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(action)) => Ok(Some(action.clone())),
        Some(_) => Err(PACKAGE_OBSERVE_UNSUPPORTED),
    };
    Ok(Observed {
        executed_action: answer
            .get("executed_action")
            .and_then(Value::as_str)
            .ok_or(PACKAGE_OBSERVE_UNSUPPORTED)?
            .to_owned(),
        tool: action("queue_observed_tool")?,
        package: action("queue_observed_package")?,
        evidence_append: answer
            .get("evidence_append")
            .and_then(Value::as_array)
            .cloned()
            .ok_or(PACKAGE_OBSERVE_UNSUPPORTED)?,
    })
}

/// Write this call's observed approval requests and complete the forward's
/// answer with the notices they raise and the evidence they are observed with.
pub(super) fn queue(
    request: &McpRelayDecideRequestV1,
    admitted: &Admitted,
    resolved: &Resolved,
    artifact: &GuardArtifact,
    answer: &PackageAnswer,
    observed: &Observed,
) -> Result<PackageAnswer, &'static str> {
    let mut notices = Vec::new();
    if observed.tool.is_some() || observed.package.is_some() {
        let review = &admitted.binding.review;
        let (Some(center), Some(oauth_source), Some(redaction_level)) = (
            review.approval_center_origin.as_deref(),
            review.review_oauth_source.as_deref(),
            resolved.redaction_level.as_deref(),
        ) else {
            return Err(PACKAGE_OBSERVE_UNSUPPORTED);
        };
        if let Some(action) = &observed.tool {
            let tool = &resolved.identity.artifact;
            let now = ask::now_isoformat().ok_or(PACKAGE_OBSERVE_FAILED)?;
            let args = ask_row::args(
                request,
                tool_item(request, resolved, action)?,
                tool,
                center,
                &now,
                redaction_level,
            );
            notices.push(write(request, oauth_source, action, args)?);
        }
        if let Some(action) = &observed.package {
            let now = ask::now_isoformat().ok_or(PACKAGE_OBSERVE_FAILED)?;
            let args = ask_row::queue_args(
                request,
                package_item(request, resolved, artifact, answer, action)?,
                &artifact.artifact_id,
                package_ask::queue_artifact(artifact)?,
                center,
                &now,
                redaction_level,
            );
            notices.push(write(request, oauth_source, action, args)?);
        }
    }
    // `(*fresh_scanner_evidence, *composed["evidence_append"])`: the receipt's
    // evidence ends with the observation, after the rows the lane queued from
    // the evidence as it stood.
    let mut evidence = answer.evidence.clone();
    evidence.extend(observed.evidence_append.iter().cloned());
    Ok(PackageAnswer {
        evidence,
        observed_notices: notices,
        ..answer.clone()
    })
}

/// Write one observed row and read it back, as the proxy's queue loop does,
/// keeping the desktop notice it raises for the drain.
fn write(
    request: &McpRelayDecideRequestV1,
    oauth_source: &str,
    action: &str,
    args: Map<String, Value>,
) -> Result<Value, &'static str> {
    if !ask::REVIEWABLE.contains(&action) {
        return Err(PACKAGE_OBSERVE_UNSUPPORTED);
    }
    let (request_id, notice) =
        ask::write(request, oauth_source, args).map_err(|_| PACKAGE_OBSERVE_FAILED)?;
    // `RuntimeError("Persisted approval request not found")`: the proxy raises
    // on a row it cannot read back rather than forwarding the call.
    ask::read_back(request, &request_id).map_err(|_| PACKAGE_OBSERVE_FAILED)?;
    Ok(notice)
}

/// The observed row of the tool call itself: the fresh tool decision's own
/// summary, signals and scanner evidence, against the tool artifact.
fn tool_item(
    request: &McpRelayDecideRequestV1,
    resolved: &Resolved,
    action: &str,
) -> Result<Map<String, Value>, &'static str> {
    let artifact = &resolved.identity.artifact;
    let decision = &resolved.decision;
    let launch = launch(
        request,
        BrowserMcpArtifactV1 {
            name: artifact.name.clone(),
            command: artifact.command.clone(),
            metadata: artifact.metadata.clone(),
        },
    )?;
    let mut extra = Map::new();
    // `extra_fields={"scanner_evidence": list(fresh_tool_evidence)}`, which is
    // written whether or not the decision left any.
    extra.insert(
        "scanner_evidence".to_owned(),
        Value::Array(ask_row::scanner_evidence(decision)),
    );
    Ok(payload(
        Row {
            artifact_id: &artifact.artifact_id,
            artifact_name: &artifact.name,
            artifact_hash: resolved
                .identity
                .artifact_hash
                .as_deref()
                .ok_or(PACKAGE_OBSERVE_UNSUPPORTED)?,
            artifact_type: ask_row::ARTIFACT_TYPE,
            source_scope: &artifact.source_scope,
            config_path: &artifact.config_path,
            policy_action: action,
            risk_summary: json!(decision.summary),
            risk_signals: json!(decision.signals),
        },
        &launch,
        extra,
    ))
}

/// The observed row of the package request: the evaluation's own risk facts
/// and decision, against the package artifact, as the `ask` lane's row carries
/// them.
fn package_item(
    request: &McpRelayDecideRequestV1,
    resolved: &Resolved,
    artifact: &GuardArtifact,
    answer: &PackageAnswer,
    action: &str,
) -> Result<Map<String, Value>, &'static str> {
    let guard_action = GuardAction::from_canonical(action).ok_or(PACKAGE_OBSERVE_UNSUPPORTED)?;
    let launch = launch(
        request,
        BrowserMcpArtifactV1 {
            name: artifact.name.clone(),
            command: artifact.command.clone(),
            metadata: artifact
                .metadata
                .as_object()
                .cloned()
                .unwrap_or_else(Map::new),
        },
    )?;
    // `_package_scanner_evidence`: the tool decision's own evidence leads the
    // package half the lane held for the receipt.
    let mut evidence = ask_row::scanner_evidence(&resolved.decision);
    evidence.extend(answer.evidence.iter().cloned());
    let mut extra = Map::new();
    extra.insert(
        "changed_fields".to_owned(),
        json!(["runtime_tool_call", "package_request"]),
    );
    extra.insert("scanner_evidence".to_owned(), Value::Array(evidence));
    extra.insert(
        "supply_chain_evaluation".to_owned(),
        Value::Object(answer.evaluation.clone()),
    );
    extra.insert(
        "decision_v2_json".to_owned(),
        package_ask::decision_v2(answer, guard_action)?,
    );
    Ok(payload(
        Row {
            artifact_id: &artifact.artifact_id,
            artifact_name: &artifact.name,
            artifact_hash: &answer.artifact_hash,
            artifact_type: &artifact.artifact_type,
            source_scope: &artifact.source_scope,
            config_path: &artifact.config_path,
            policy_action: action,
            risk_summary: answer
                .evaluation
                .get("risk_summary")
                .cloned()
                .unwrap_or_else(|| json!("")),
            risk_signals: json!(answer.signals),
        },
        &launch,
        extra,
    ))
}

/// The identity fields one observed row names its subject by.
struct Row<'a> {
    artifact_id: &'a str,
    artifact_name: &'a str,
    artifact_hash: &'a str,
    artifact_type: &'a str,
    source_scope: &'a str,
    config_path: &'a str,
    policy_action: &'a str,
    risk_summary: Value,
    risk_signals: Value,
}

/// `artifact_payload`: the evaluation item both observed rows are built as,
/// with the fields the caller adds written over it last.
fn payload(row: Row<'_>, launch: &Launch, extra: Map<String, Value>) -> Map<String, Value> {
    let mut changed_fields = vec![json!("runtime_tool_call")];
    if launch.intent.is_some() {
        changed_fields.push(json!("runtime_browser_tool_call"));
    }
    let mut item = Map::new();
    item.insert("artifact_id".to_owned(), json!(row.artifact_id));
    item.insert("artifact_name".to_owned(), json!(row.artifact_name));
    item.insert("artifact_hash".to_owned(), json!(row.artifact_hash));
    item.insert("artifact_type".to_owned(), json!(row.artifact_type));
    item.insert("source_scope".to_owned(), json!(row.source_scope));
    item.insert("config_path".to_owned(), json!(row.config_path));
    item.insert("changed_fields".to_owned(), Value::Array(changed_fields));
    item.insert("policy_action".to_owned(), json!(row.policy_action));
    item.insert("launch_target".to_owned(), json!(launch.target));
    item.insert("risk_summary".to_owned(), row.risk_summary);
    item.insert("risk_signals".to_owned(), row.risk_signals);
    if let Some(intent) = &launch.intent {
        item.insert("browser_intent".to_owned(), intent.clone());
    }
    item.extend(extra);
    item
}

/// The projection fields an observed row displays its subject with.
struct Launch {
    /// `display_launch_target`.
    target: String,
    /// `browser_intent`, which adds the browser entry to `changed_fields`.
    intent: Option<Value>,
}

/// `self._call_projector.project(tool_name, params, artifact)` for a row that
/// reads only its launch target. Unlike the `ask` lane's projection, an empty
/// target is written as the empty string it is: the observed branch checks it
/// for nothing, and the row's risk facts are the decision's own rather than
/// the projection's.
fn launch(
    request: &McpRelayDecideRequestV1,
    artifact: BrowserMcpArtifactV1,
) -> Result<Launch, &'static str> {
    let projected = crate::mcp_proxy_projection::call_projection(&McpCallProjectionQueryV1 {
        tool_name: request.build.tool_name.clone(),
        params: request.params.clone(),
        // `risk_input(artifact, params["arguments"])`, taken from the
        // arguments in the order the host sent them.
        risk: Some(McpToolRiskInputV1 {
            artifact,
            arguments: request.arguments.clone(),
            risk_categories: None,
            summary_code: None,
        }),
    })
    .map_err(|_| PACKAGE_OBSERVE_FAILED)?;
    let browser = projected.get("browser").filter(|value| !value.is_null());
    let target = match browser {
        Some(browser) => browser.get("launch_target"),
        None => projected.get("launch_target"),
    }
    .and_then(Value::as_str)
    .unwrap_or_default()
    .to_owned();
    Ok(Launch {
        target,
        intent: browser.and_then(|browser| browser.get("intent")).cloned(),
    })
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_observe_tests.rs"]
mod tests;
