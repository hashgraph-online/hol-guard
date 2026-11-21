//! What a relayed package call answers with once its route is decided.
//!
//! Port of the package lane's own response renderers in `runtime_mcp.py`:
//! `_stored_package_block_response` (:2450), `_terminal_package_response`
//! (:2352), the `safe-alternative` half of `_queue_package_approval_response`
//! (:2157) and the receipt side of `_record_package_forward` (:2025). The legs
//! the tool policy decides are rendered by the plain tool-policy responses, so
//! they are a `ToolLeg` the caller answers through the tool lane and never
//! reach this module.
//!
//! Only the text and the payload belong here. The block receipt, the allow
//! receipt and the forwarded message itself stay with the caller: the relay
//! holds its evidence for the drain to record, which is how every other route
//! in this lane already answers.

use serde_json::{json, Value};

use super::package_observe;
use super::package_policy::PackagePolicy;
use super::package_route::PackageRoute;
use super::queue;
use crate::mcp_proxy_package_answer as answer;

/// `block_tool_call(decision_source="policy-block")`, which every stopped
/// package call records under.
pub(super) const BLOCK_SOURCE: &str = "policy-block";

/// The message and payload a stopped call answers with, carrying the
/// evaluation the lane settled on as the proxy's `supplyChainEvaluation`.
///
/// `signals` are the receipt signals of this route, which the queued leg also
/// writes into its guidance text.
pub(super) fn block(
    route: &PackageRoute,
    tool: &str,
    server: &str,
    policy: &PackagePolicy,
    signals: &[String],
) -> Option<(String, Value)> {
    // The queued leg is answered by `_queue_approval_center_response`, which
    // renders the plain tool-call guidance and the not-forwarded payload, and
    // only then has the package evaluation written over it.
    if let PackageRoute::QueuePackage { .. } = route {
        let (message, mut data) = queue::safe_alternative_block(tool, server, signals);
        data["supplyChainEvaluation"] = queued_evaluation(policy, &message);
        return Some((message, data));
    }
    let message = match route {
        PackageRoute::StoredPackageBlock => answer::stored_package_block_message(tool, server),
        PackageRoute::TerminalPackage { policy_action } => {
            answer::terminal_package_message(tool, server, policy_action)
        }
        PackageRoute::QueuePackage { .. }
        | PackageRoute::Forward { .. }
        // The observed forward is the ordinary forward: the call reaches the
        // child, and the rows the enforced policies would have blocked it on
        // are queued beside it rather than answered to the client.
        | PackageRoute::ObserveForward(_) => return None,
    };
    Some((
        message,
        json!({
            "approvalRequests": [],
            "guardPolicyAction": policy_action(route),
            "supplyChainEvaluation": Value::Object(policy.evaluation.clone()),
        }),
    ))
}

/// The evaluation a queued request is answered with: the one the lane settled
/// on, restated as the block the agent was actually given, with the guidance
/// text as its own next step.
fn queued_evaluation(policy: &PackagePolicy, message: &str) -> Value {
    answer::blocked_package_evaluation(&policy.evaluation, message)
}

/// The action the answer reports, which a stored block always states as
/// `block` and a terminal leg takes from the composed policy.
pub(super) fn policy_action(route: &PackageRoute) -> &str {
    match route {
        PackageRoute::StoredPackageBlock => "block",
        PackageRoute::TerminalPackage { policy_action }
        | PackageRoute::QueuePackage { policy_action }
        | PackageRoute::Forward { policy_action } => policy_action,
        // `policy_action=executed_action`: observe mode records the call under
        // the action it was actually forwarded with, not the one the enforced
        // policy would have stopped it with.
        PackageRoute::ObserveForward(observed) => &observed.executed_action,
    }
}

/// `decision_source` the receipt records: a stopped call is a policy block, a
/// forwarded one is the action it was permitted under. The relay never spends
/// a saved approval, so the remembered source a claimed forward would carry is
/// not one of these.
pub(super) fn decision_source(route: &PackageRoute) -> String {
    match route {
        PackageRoute::Forward { policy_action } => format!("policy-{policy_action}"),
        // `decision_source="policy-observe"`: the observed forward is recorded
        // under the mode rather than the action it was forwarded with, which
        // is how the receipt states that no policy enforced it.
        PackageRoute::ObserveForward(_) => package_observe::OBSERVE_SOURCE.to_owned(),
        // The queued leg is recorded by the tool lane's own queue response,
        // against the package artifact it was asked with.
        PackageRoute::QueuePackage { .. } => queue::SAFE_ALTERNATIVE_SOURCE.to_owned(),
        _ => BLOCK_SOURCE.to_owned(),
    }
}

/// The `decision` the proxy's own event names, which the drain records for the
/// answered call.
pub(super) fn decision_label(route: &PackageRoute) -> String {
    match route {
        PackageRoute::StoredPackageBlock => "package-block-stored".to_owned(),
        PackageRoute::TerminalPackage { policy_action } => {
            format!("terminal-package-{policy_action}")
        }
        PackageRoute::QueuePackage { .. } => "safe-alternative".to_owned(),
        PackageRoute::Forward { policy_action } => format!("package-{policy_action}"),
        // `{**observe_event, "decision": executed_action}`: the proxy's event
        // names the executed action itself rather than a package label.
        PackageRoute::ObserveForward(observed) => observed.executed_action.clone(),
    }
}

/// The signals this route's receipt records, and the queued leg's guidance
/// text states. `_queue_package_approval_response` leads the queued leg's
/// with the evaluation's own risk summary; every other route records the
/// reason signals alone.
pub(super) fn signals(route: &PackageRoute, policy: &PackagePolicy) -> Vec<String> {
    let reasons = reason_signals(policy);
    match route {
        PackageRoute::QueuePackage { .. } => {
            let summary = policy
                .evaluation
                .get("risk_summary")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            std::iter::once(summary).chain(reasons).collect()
        }
        _ => reasons,
    }
}

/// The reason signals of the evaluation: each reason's message, its code when
/// it carries no message, and an empty string when it carries neither, in the
/// order the evaluation reported them.
pub(super) fn reason_signals(policy: &PackagePolicy) -> Vec<String> {
    answer::reason_signals(&policy.evaluation)
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_answer_tests.rs"]
mod tests;
