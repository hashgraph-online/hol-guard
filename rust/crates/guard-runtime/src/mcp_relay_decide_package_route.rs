//! The route a relayed package call takes once its stored policy is resolved.
//!
//! Port of `_handle_package_request`'s two decide legs (`runtime_mcp.py:1486`,
//! `:1543`): the precheck on the policy resolved before the tool is
//! re-resolved, and the composition of the freshly re-resolved tool and
//! package policies. Both answers are the resident's own
//! (`mcp_proxy_package.rs`), asked here with the facts the proxy sends
//! (`native_mcp_proxy_decision.py` `tool_facts`, `package_facts`), so the
//! relay and the proxy decide a package call by one algorithm rather than two.
//!
//! The route names every leg; three of them are answered beyond it, because
//! each writes rows before the call is answered:
//!
//! * a queued package request, which under the `ask` blocked-request mode
//!   writes the package-shaped approval row `_queue_package_approval_response`
//!   queues (`mcp_relay_decide_package_ask.rs`). Under `safe-alternative` the
//!   same leg blocks in place;
//! * an observed forward, whose observed approval requests are queued before
//!   the call is forwarded (`mcp_relay_decide_package_observe.rs`);
//! * a forward whose policies left a saved approval pending, which the claim
//!   lane spends (`mcp_relay_decide_package_claim.rs`).
//!
//! A queued *tool* leg does not defer. `_queue_approval_center_response`
//! answers it exactly as it answers a plain blocked tool call, so the relay
//! takes it through the tool lane's own queue route
//! (`mcp_relay_decide_ask.rs`, `mcp_relay_decide_queue.rs`).
//!
//! The composition names its legs apart for that reason. Three of them are
//! decided by the tool policy and rendered by the plain tool-policy responses
//! — `_stored_tool_block_response`, `_terminal_tool_response` and
//! `_queue_approval_center_response` — against the tool call's own artifact,
//! so they are a separate type the package answer cannot be asked for.
//!
//! A kind neither answer names is the proxy's `NativeMcpProxyDecisionError`;
//! here it defers, because a relayed call never guesses at a verdict.

use guard_contracts::{McpPackageComposeQueryV1, McpPackageFactsV1, McpPackagePrecheckQueryV1};
use serde_json::Value;

use super::package_observe;
use super::package_policy::PackagePolicy;
use crate::mcp_tool_policy_decision::Decision;

/// The call needs the package-shaped approval request
/// `_queue_package_approval_response` writes under the `ask` mode.
pub(super) const PACKAGE_QUEUE: &str = "mcp_relay_package_queue";
/// The observe answer named a forward this port cannot read the observed
/// requests out of.
pub(super) const PACKAGE_OBSERVE: &str = "mcp_relay_package_observe";
/// An answer naming a kind this port does not know, which the proxy raises
/// `native_mcp_proxy_decision_{precheck,compose}_unknown` for.
pub(super) const PACKAGE_ROUTE_UNKNOWN: &str = "mcp_relay_package_route_unknown";
/// The resolved evaluation carries no policy action to decide on.
pub(super) const PACKAGE_ACTION_MISSING: &str = "mcp_relay_package_action_missing";

/// `_has_saved_package_block`: the reason code a saved block leaves.
const SAVED_PACKAGE_BLOCK: &str = "saved_package_block";

/// What the relay does with a package call the package policy decided. Each
/// variant names the proxy response it answers with, which renders the package
/// evaluation and records the receipt against the package request's artifact.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum PackageRoute {
    /// `_stored_package_block_response`: authenticated saved policy already
    /// blocks this exact request.
    StoredPackageBlock,
    /// `_terminal_package_response`: the package policy itself stops the call.
    TerminalPackage { policy_action: String },
    /// `_queue_package_approval_response`: the package policy wants this
    /// request reviewed. The blocked-request mode decides what that is, and
    /// the lane answers only the `safe-alternative` block.
    QueuePackage { policy_action: String },
    /// `_record_package_forward`: neither policy stops the call and no saved
    /// approval is pending.
    Forward { policy_action: String },
    /// `mode = "observe"`: the same forward, recorded under the action the
    /// enforced policies would have taken, once the observed approval
    /// requests they would have blocked it on are queued
    /// (`mcp_relay_decide_package_observe.rs`).
    ObserveForward(package_observe::Observed),
}

/// A leg of the package lane the tool policy decided. Each names the proxy
/// response it takes, which is the one a call carrying no package request
/// takes: the tool call's own artifact, the tool decision's signals and risk
/// categories, and the `mcp_tool_call` receipt the tool lane leaves.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum ToolLeg {
    /// `_stored_tool_block_response` with `package_request = True`.
    StoredBlock,
    /// `_terminal_tool_response`: the tool policy stops the call carrying the
    /// package request.
    Terminal { policy_action: String },
    /// `_queue_approval_center_response`: the tool policy wants this call
    /// reviewed, and the proxy queues it as it queues any other tool call.
    Queue { policy_action: String },
}

/// What the composition decided: the lane's own route, or the leg the tool
/// policy owns and the tool lane answers.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Decided {
    Package(PackageRoute),
    Tool(ToolLeg),
    /// The forward both policies agree on, where at least one of them left a
    /// saved approval the forward spends. The proxy claims those rows and
    /// revalidates before it answers, so this is not an answer and carries no
    /// action: what the call does is decided again after the claim, from the
    /// resolutions the claimed store reports
    /// (`mcp_relay_decide_package_spend.rs`).
    ClaimPackage,
}

/// `package_precheck`. `None` is the proxy's `proceed`: the call goes on to
/// the fresh tool authority and the fresh package policy.
pub(super) fn precheck(
    mode: &str,
    policy: &PackagePolicy,
) -> Result<Option<PackageRoute>, &'static str> {
    let answer = crate::mcp_proxy_package::package_precheck(&McpPackagePrecheckQueryV1 {
        mode: mode.to_owned(),
        saved_policy_blocks: saved_policy_blocks(policy),
        policy_action: policy_action(policy)?.to_owned(),
    });
    match kind(&answer)? {
        "proceed" => Ok(None),
        "stored_package_block" => Ok(Some(PackageRoute::StoredPackageBlock)),
        "terminal" => Ok(Some(PackageRoute::TerminalPackage {
            policy_action: answered_action(&answer)?,
        })),
        "queue" => Ok(Some(PackageRoute::QueuePackage {
            policy_action: answered_action(&answer)?,
        })),
        _ => Err(PACKAGE_ROUTE_UNKNOWN),
    }
}

/// `package_compose` over the freshly re-resolved tool and package policies.
pub(super) fn compose(
    mode: &str,
    tool: &Decision,
    policy: &PackagePolicy,
) -> Result<Decided, &'static str> {
    let answer = crate::mcp_proxy_package::package_compose(&McpPackageComposeQueryV1 {
        mode: mode.to_owned(),
        tool: crate::mcp_tool_policy_proxy::facts(tool),
        package: package_facts(policy)?,
    });
    match kind(&answer)? {
        "stored_tool_block" => Ok(Decided::Tool(ToolLeg::StoredBlock)),
        "stored_package_block" => Ok(Decided::Package(PackageRoute::StoredPackageBlock)),
        "terminal_tool" => Ok(Decided::Tool(ToolLeg::Terminal {
            policy_action: answered_action(&answer)?,
        })),
        "terminal_package" => Ok(Decided::Package(PackageRoute::TerminalPackage {
            policy_action: answered_action(&answer)?,
        })),
        "queue_tool" => Ok(Decided::Tool(ToolLeg::Queue {
            policy_action: answered_action(&answer)?,
        })),
        "queue_package" => Ok(Decided::Package(PackageRoute::QueuePackage {
            policy_action: answered_action(&answer)?,
        })),
        "observe_forward" => Ok(Decided::Package(PackageRoute::ObserveForward(
            package_observe::observed(&answer).map_err(|_| PACKAGE_OBSERVE)?,
        ))),
        "proceed" => match answer.get("pending_claims").and_then(Value::as_bool) {
            Some(false) => Ok(Decided::Package(PackageRoute::Forward {
                policy_action: answer
                    .get("authoritative_action")
                    .and_then(Value::as_str)
                    .ok_or(PACKAGE_ROUTE_UNKNOWN)?
                    .to_owned(),
            })),
            Some(true) => Ok(Decided::ClaimPackage),
            None => Err(PACKAGE_ROUTE_UNKNOWN),
        },
        _ => Err(PACKAGE_ROUTE_UNKNOWN),
    }
}

/// `package_facts`: the decision-relevant facts of one resolved package
/// policy.
pub(super) fn package_facts(policy: &PackagePolicy) -> Result<McpPackageFactsV1, &'static str> {
    Ok(McpPackageFactsV1 {
        saved_policy_blocks: saved_policy_blocks(policy),
        current_action: Some(policy.current_action.as_str().to_owned()),
        policy_action: policy_action(policy)?.to_owned(),
        // The saved row the resolution reported without consuming, which is
        // the claim a forward would spend.
        has_pending: policy.reused_decision.is_some(),
    })
}

/// `_has_saved_package_block(evaluation.reasons)`.
fn saved_policy_blocks(policy: &PackagePolicy) -> bool {
    policy
        .evaluation
        .get("reasons")
        .and_then(Value::as_array)
        .is_some_and(|reasons| {
            reasons.iter().any(|reason| {
                reason.get("code").and_then(Value::as_str) == Some(SAVED_PACKAGE_BLOCK)
            })
        })
}

/// `evaluation.policy_action`, which both answers read.
fn policy_action(policy: &PackagePolicy) -> Result<&str, &'static str> {
    policy
        .evaluation
        .get("policy_action")
        .and_then(Value::as_str)
        .ok_or(PACKAGE_ACTION_MISSING)
}

fn kind(answer: &Value) -> Result<&str, &'static str> {
    answer
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(PACKAGE_ROUTE_UNKNOWN)
}

/// The action a terminal or queued answer carries, which the proxy passes to
/// the response it renders. Both answers compose it from a `GuardAction`, so
/// the text is one of that enum's.
fn answered_action(answer: &Value) -> Result<String, &'static str> {
    answer
        .get("policy_action")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(PACKAGE_ROUTE_UNKNOWN)
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_route_tests.rs"]
mod tests;
