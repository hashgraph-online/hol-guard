//! The package lane of one relayed `tools/call`, from the resolved policies to
//! the answer and the facts its receipt records.
//!
//! Port of `_handle_package_request`'s own order (`runtime_mcp.py:1486`): the
//! precheck answers on the policy the lane resolved first, and only a call it
//! lets through re-resolves the tool authority and the package policy and is
//! composed from both (`:1543`). The route is `mcp_relay_decide_package_route.rs`
//! and the text and payload are `mcp_relay_decide_package_answer.rs`; this
//! module is the order they are asked in, and what one answered call leaves for
//! the drain to record.
//!
//! The re-resolution is the caller's, because it reads the store and the policy
//! view the decide path already holds. The lane asks for it only once the
//! precheck did not answer, exactly as the proxy re-resolves nothing for a call
//! its precheck stopped.
//!
//! A queued package request is answered by the blocked-request mode the
//! call's configs bound. Under `safe-alternative` the proxy blocks it in place
//! and leaves the silent inbox row, so the lane answers it and carries the
//! bound receipt redaction level for the drain to write that row with. Under
//! `ask` it writes the package-shaped approval row and blocks the call on it,
//! which the caller performs because the write reads the store this lane does
//! not hold (`mcp_relay_decide_package_ask.rs`).
//!
//! A forward is answered rather than forwarded when its evaluation only
//! permits a request bound to the external archives it verified. The relay
//! retains no verified blob, so that binding is refused and the call takes the
//! terminal block the proxy answers a refused binding with
//! (`mcp_relay_decide_package_archive.rs`).
//!
//! Not every leg of this lane is a package answer. The three the tool policy
//! decides — `_stored_tool_block_response`, `_terminal_tool_response` and
//! `_queue_approval_center_response` — are the plain tool-policy responses the
//! proxy renders for any other call, and each records the tool call's own
//! receipt against the tool artifact rather than the package request's. The
//! lane names them apart so the caller routes them through the tool lane it
//! already has, and only the package legs leave the `mcp_package_call` record.

use serde_json::{Map, Value};

use super::package_answer;
use super::package_archive;
use super::package_ask;
use super::package_claim;
use super::package_observe;
use super::package_policy::PackagePolicy;
use super::package_receipt;
use super::package_route::{self, Decided, PackageRoute, ToolLeg};
use super::queue;
use super::{ask, ASK_MODE};
use crate::mcp_tool_policy_decision::Decision;

/// What one decided package call leaves the caller: the lane's own answer, or
/// a leg the tool policy decided, which the tool lane answers and records.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum PackageOutcome {
    Answered(PackageAnswer),
    /// A queued request the bound `ask` mode answers, whose row the caller
    /// writes before the answer is complete.
    AskPackage(PackageAnswer),
    /// A forward `mode = "observe"` recorded under the action the enforced
    /// policies would have taken, whose observed approval requests the caller
    /// writes before the answer is complete.
    ObservePackage {
        answer: PackageAnswer,
        observed: package_observe::Observed,
    },
    ToolLeg(ToolLeg),
    /// A forward with a saved approval still to spend. The lane decides
    /// nothing further: the caller holds the rows and raises the claim whose
    /// spend decides the call again on the claimed store.
    ClaimPackage(Box<package_claim::ClaimLeg>),
}

impl PackageOutcome {
    /// The answer this outcome carries, for a caller with evidence to append
    /// to the receipt it is recorded with; a leg the tool lane answers carries
    /// none.
    pub(super) fn answer_mut(&mut self) -> Option<&mut PackageAnswer> {
        match self {
            Self::Answered(answer)
            | Self::AskPackage(answer)
            | Self::ObservePackage { answer, .. } => Some(answer),
            Self::ToolLeg(_) | Self::ClaimPackage(_) => None,
        }
    }
}

/// One answered package call: what the client is told, and what the receipt the
/// drain writes records for it.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct PackageAnswer {
    /// The message and payload a stopped call is answered with; `None`
    /// forwards it.
    pub(super) block: Option<(String, Value)>,
    /// `guardPolicyAction`, which the receipt records as the policy action.
    pub(super) policy_action: String,
    /// `decision_source` the receipt records.
    pub(super) decision_source: String,
    /// The `decision` the proxy's event names. The receipt records the tool
    /// decision itself, so only the event the relay does not emit reads this.
    #[allow(dead_code)]
    pub(super) decision: String,
    /// The receipt signals, one per reason the evaluation reported.
    pub(super) signals: Vec<String>,
    /// The one workspace identity the package lookup was valid for, which the
    /// receipt binds the decision to.
    pub(super) policy_workspace: Option<String>,
    /// The approval-context token the answered request hashes to.
    pub(super) artifact_hash: String,
    /// The evaluation the lane settled on, as the answer reported it.
    pub(super) evaluation: Map<String, Value>,
    /// The package half of the receipt's scanner evidence.
    pub(super) evidence: Vec<Value>,
    /// The receipt redaction level the silent inbox row is written with,
    /// which only the `safe-alternative` queued leg leaves.
    pub(super) redaction_level: Option<String>,
    /// The approval-center surface raised once a queued row is written, which
    /// only the `ask` queued leg leaves.
    pub(super) approval: Option<Value>,
    /// The desktop notices the observed approval requests raise, which only an
    /// observed forward leaves. The call is forwarded rather than blocked on
    /// them, so they are the whole surface this leg leaves.
    pub(super) observed_notices: Vec<Value>,
}

/// The review binding one queued package request is answered under: the
/// blocked-request mode the call's configs agree on, and the receipt
/// redaction level bound with it.
#[derive(Debug, Clone, Copy)]
pub(super) struct QueueBinding<'a> {
    pub(super) blocked_request_mode: Option<&'a str>,
    pub(super) redaction_level: Option<&'a str>,
}

/// Decide one relayed package call. `re_resolve` is the proxy's second
/// resolution: the fresh tool authority and the fresh package policy, read by
/// the caller that holds the store.
pub(super) fn decide_package<F>(
    mode: &str,
    tool: &str,
    server: &str,
    resolved: &PackagePolicy,
    binding: QueueBinding<'_>,
    re_resolve: F,
) -> Result<PackageOutcome, &'static str>
where
    F: FnOnce() -> Result<(Decision, PackagePolicy), &'static str>,
{
    if let Some(route) = package_route::precheck(mode, resolved)? {
        // The precheck answers on the package policy alone, so every leg it
        // decides is this lane's own.
        return answered(&route, tool, server, resolved, binding);
    }
    let (authority, policy) = re_resolve()?;
    match package_route::compose(mode, &authority, &policy)? {
        Decided::Package(route) => answered(&route, tool, server, &policy, binding),
        Decided::Tool(leg) => Ok(PackageOutcome::ToolLeg(leg)),
        Decided::ClaimPackage => Ok(PackageOutcome::ClaimPackage(Box::new(
            package_claim::claim_leg(&authority, &policy),
        ))),
    }
}

/// The answer and the receipt facts of one decided package route.
pub(super) fn answered(
    route: &PackageRoute,
    tool: &str,
    server: &str,
    policy: &PackagePolicy,
    binding: QueueBinding<'_>,
) -> Result<PackageOutcome, &'static str> {
    let facts = |signals: Vec<String>| PackageAnswer {
        block: None,
        policy_action: package_answer::policy_action(route).to_owned(),
        decision_source: package_answer::decision_source(route),
        decision: package_answer::decision_label(route),
        signals,
        policy_workspace: policy.policy_workspace.clone(),
        artifact_hash: policy.artifact_hash.clone(),
        evaluation: policy.evaluation.clone(),
        evidence: package_receipt::evidence(policy),
        redaction_level: None,
        approval: None,
        observed_notices: Vec::new(),
    };
    if let PackageRoute::Forward { .. } = route {
        if package_archive::requires_binding(&policy.evaluation) {
            // `_bound_external_archive_mcp_request` (`runtime_mcp.py:1747`): a
            // forward whose evaluation resolved a package from an external
            // tarball is bound to the blobs that evaluation verified before it
            // is written to the child. The relay retains no blob, so the
            // binding is refused and the call is the terminal `mcp_unbound`
            // block (`:1755`). The replacement route is not a forward, so the
            // answer it is rendered from settles here.
            let refused = package_archive::unbound(policy)?;
            let blocked = PackageRoute::TerminalPackage {
                policy_action: "block".to_owned(),
            };
            return answered(&blocked, tool, server, &refused, binding);
        }
    }
    if let PackageRoute::QueuePackage { .. } = route {
        if binding.blocked_request_mode == Some(ASK_MODE) {
            // The row, the block and the approval surface are the caller's,
            // which holds the store the write and the read-back go through.
            return Ok(PackageOutcome::AskPackage(PackageAnswer {
                decision_source: ask::APPROVAL_PENDING_SOURCE.to_owned(),
                decision: package_ask::DECISION_LABEL.to_owned(),
                ..facts(package_answer::reason_signals(policy))
            }));
        }
    }
    let redaction_level = match route {
        PackageRoute::QueuePackage { .. } => Some(queued_redaction_level(binding)?),
        _ => None,
    };
    let signals = package_answer::signals(route, policy);
    let answer = PackageAnswer {
        block: package_answer::block(route, tool, server, policy, &signals),
        redaction_level,
        ..facts(signals)
    };
    if let PackageRoute::ObserveForward(observed) = route {
        // The observed rows are written against the store the caller holds,
        // and the notices they raise complete this answer there.
        return Ok(PackageOutcome::ObservePackage {
            answer,
            observed: observed.clone(),
        });
    }
    Ok(PackageOutcome::Answered(answer))
}

/// `_queue_package_approval_response` under `safe-alternative`: the request is
/// blocked in place and the inbox row is written with the bound receipt
/// redaction level. `ask` is answered before this, and every other mode is one
/// the relay has no answer for.
fn queued_redaction_level(binding: QueueBinding<'_>) -> Result<String, &'static str> {
    match (binding.blocked_request_mode, binding.redaction_level) {
        (Some(queue::SAFE_ALTERNATIVE_MODE), Some(level)) => Ok(level.to_owned()),
        _ => Err(package_route::PACKAGE_QUEUE),
    }
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_lane_tests.rs"]
mod tests;
