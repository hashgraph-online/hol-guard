//! The receipt one answered package call leaves for the drain to write.
//!
//! A relayed package call is recorded against the package request's own
//! artifact, not the tool's: `_record_package_block` (`runtime_mcp.py:2327`)
//! and `_record_package_forward` (:2025) write `block_tool_call` and
//! `allow_tool_call` with the package artifact, the approval-context token the
//! request hashed to, the evaluation's reason signals, and the package scanner
//! evidence `_package_scanner_evidence` (:2009) composed. The tool legs of the
//! same lane are recorded as the plain tool-policy blocks they are, so they
//! keep the `mcp_tool_call` record the rest of the decide path leaves.
//!
//! So a package leg carries its own record kind. It names the package artifact
//! by id and the workspace the proxy parsed it from, rather than shipping the
//! artifact itself: `to_dict` redacts args, url and metadata, and a receipt
//! written from redacted fields is not the receipt the proxy writes. The drain
//! rebuilds the artifact from the call the record carries — the same parser
//! input the resident read — and drops the record when the rebuilt artifact is
//! not the one this decided.
//!
//! That parser input includes the `PATH` the intent was resolved under, which
//! decides the manager a command names. The drain runs in the daemon, whose
//! own `PATH` is not the relaying proxy's, so the record carries the proxy's
//! and the drain parses under it. A record that names none is dropped there
//! rather than parsed under whatever the daemon happens to hold.
//!
//! The evidence is the package half only. The tool half is
//! `tool_decision_scanner_evidence` of the decision the record already carries,
//! which the drain derives for every relayed call.
//!
//! A request the package policy queued under the `safe-alternative`
//! blocked-request mode also leaves the silent inbox row
//! `_queue_approval_center_response` writes, so its record carries the receipt
//! redaction level that row is written with, as a relayed tool call's does.
//! One queued under `ask` leaves the written approval row's surface instead,
//! which the drain raises after the same block receipt
//! (`mcp_relay_decide_package_ask.rs`).

use serde_json::{json, Map, Value};

use super::package_lane::PackageAnswer;
use super::package_observe;
use super::package_policy::PackagePolicy;
use super::{McpRelayDecideRequestV1, IDENTITY_FAILED};
use crate::mcp_tool_policy_decision::Decision;
use guard_command::package_intent_common::GuardArtifact;

/// The evidence kind the drain records a relayed package call under.
pub(super) const PACKAGE_CALL_EVIDENCE_KIND: &str = "mcp_package_call";

/// The package half of `_package_scanner_evidence`: the execution context the
/// approval identity is bound to, then one entry per reason that carries an
/// approval reuse, in the order the evaluation reported them.
pub(super) fn evidence(policy: &PackagePolicy) -> Vec<Value> {
    let mut evidence = vec![policy.execution_context.to_evidence()];
    let reasons = policy
        .evaluation
        .get("reasons")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for reason in reasons {
        let Some(reuse) = reason.get("approval_reuse").and_then(Value::as_object) else {
            continue;
        };
        let mut entry = Map::new();
        entry.insert("source".to_owned(), json!("approval_reuse"));
        entry.extend(reuse.clone());
        evidence.push(Value::Object(entry));
    }
    evidence
}

/// The record the drain writes one answered package call's receipt from.
///
/// `artifact` is the package request's artifact and `workspace` the directory
/// its intent was parsed against, which is what the drain rebuilds it from,
/// together with the `PATH` the gate parsed under (`package_gate`).
pub(super) fn record(
    request: &McpRelayDecideRequestV1,
    identity: &Value,
    decision: &Decision,
    artifact: &GuardArtifact,
    workspace: &str,
    answer: &PackageAnswer,
) -> Result<Value, &'static str> {
    // A forward is the only route whose receipt binds the policy workspace,
    // because only `allow_tool_call` is given one.
    let forwarded = answer.block.is_none();
    let mut package = json!({
        "artifact_id": artifact.artifact_id,
        "artifact_hash": answer.artifact_hash,
        "workspace": workspace,
        // The gate binds no environment for an absent or empty `PATH`, and
        // resolves the manager under the resident's own. Both are stated the
        // same way so the drain rebuilds the call the same unbound way.
        "path": request.path.as_deref().filter(|path| !path.is_empty()),
        "evaluation": Value::Object(answer.evaluation.clone()),
        "evidence": Value::Array(answer.evidence.clone()),
        "signals": answer.signals.clone(),
    });
    if forwarded {
        package["policy_workspace"] = json!(answer.policy_workspace);
    }
    let mut record = json!({
        "kind": PACKAGE_CALL_EVIDENCE_KIND,
        "harness": request.build.harness,
        "outcome": if forwarded { "forward" } else { "block" },
        "decision_source": answer.decision_source,
        "policy_action": answer.policy_action,
        "tool_name": request.build.tool_name,
        "params": request.params,
        // The arguments in host key order, which the decoded params lost.
        "arguments": serde_json::to_value(&request.arguments).map_err(|_| IDENTITY_FAILED)?,
        "identity": identity,
        "decision": decision.to_value(),
        "package": package,
    });
    // The silent inbox row the drain writes after a queued request's block
    // receipt, which only the queued leg leaves.
    if let Some(level) = &answer.redaction_level {
        record["review"] = json!({"redaction_level": level});
    }
    // The approval surface the drain raises after a queued request's block
    // receipt, which only the `ask` queued leg leaves. A record carries one or
    // the other, never both: the two modes queue the same request differently.
    if let Some(approval) = &answer.approval {
        record["approval"] = approval.clone();
    }
    // The observed approval requests the forward was queued with, which only
    // `mode = "observe"` leaves. The call reached the child, so the drain
    // raises their desktop notices and no approval center beside them, and the
    // key states the empty list when the observed actions queued nothing.
    if answer.decision_source == package_observe::OBSERVE_SOURCE {
        record["observed"] = json!({"notices": answer.observed_notices.clone()});
    }
    Ok(record)
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_receipt_tests.rs"]
mod tests;
