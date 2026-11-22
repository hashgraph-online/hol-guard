//! Settle a routed answer: the evidence it queues or holds and the reply.

use super::package_route::ToolLeg;
use super::*;
use serde_json::json;
use std::time::Instant;

/// Answer a forward or block route and queue or hold its evidence; a claimed
/// call's evidence also carries what the post-claim check appended.
pub(super) fn settle(
    request: &McpRelayDecideRequestV1,
    resolved: &Resolved,
    routed: Routed,
    evidence_append: Option<Vec<Value>>,
    policy_store: &PolicySnapshotStore,
) -> Result<Answer, &'static str> {
    let (identity, decision) = (&resolved.identity, &resolved.decision);
    let harness = request.build.harness.as_str();
    let tool = &request.build.tool_name;
    let server = &request.build.server_name;
    let mut review = None;
    let mut approval = None;
    let mut remembered = false;
    let (blocked, outcome, source, policy_action) = match routed {
        Routed::Forward {
            source,
            policy_action,
            remember,
        } => {
            // The artifact allow the inline prompt approved, which the drain
            // saves before it records the forward.
            if remember {
                remembered = true;
            }
            (None, "forward", source, policy_action)
        }
        Routed::Terminal { policy_action } => {
            let message = crate::mcp_proxy_package_answer::terminal_tool_message(
                tool,
                server,
                &policy_action,
            );
            let data = json!({"approvalRequests": [], "guardPolicyAction": policy_action});
            (
                Some(Answer::Block { message, data }),
                "block",
                "policy-block".to_owned(),
                policy_action,
            )
        }
        Routed::StoredBlock { package_request } => (
            Some(Answer::Block {
                message: crate::mcp_proxy_package_answer::stored_tool_block_message(
                    tool,
                    server,
                    package_request,
                ),
                data: json!({"approvalRequests": [], "guardPolicyAction": "block"}),
            }),
            "block",
            "policy-block".to_owned(),
            "block".to_owned(),
        ),
        Routed::SafeAlternative {
            policy_action,
            redaction_level,
            center,
        } => {
            // The center lets the resident write the row itself; the daemon
            // links a row to its own origin and ignores it.
            let mut fields = json!({"redaction_level": redaction_level});
            if let Some(center) = center {
                fields["approval_center_url"] = json!(center);
            }
            review = Some(fields);
            let (message, data) = queue::safe_alternative_block(tool, server, &decision.signals);
            (
                Some(Answer::Block { message, data }),
                "block",
                queue::SAFE_ALTERNATIVE_SOURCE.to_owned(),
                policy_action,
            )
        }
        Routed::Asked {
            policy_action,
            message,
            data,
            approval: raised,
        } => {
            approval = Some(raised);
            (
                Some(Answer::Block { message, data }),
                "block",
                ask::APPROVAL_PENDING_SOURCE.to_owned(),
                policy_action,
            )
        }
        Routed::InlineDenied { source } => (
            Some(Answer::Block {
                message: inline::block_message(source, tool, server),
                data: json!({"approvalRequests": [], "guardPolicyAction": "block"}),
            }),
            "block",
            source.to_owned(),
            "block".to_owned(),
        ),
        Routed::Claim { .. } | Routed::Queue { .. } | Routed::ObserveForward | Routed::Elicit => {
            return Err(ROUTE_UNSUPPORTED)
        }
    };
    let mut evidence = json!({
        "kind": "mcp_tool_call",
        "harness": harness,
        "outcome": outcome,
        "decision_source": source,
        "policy_action": policy_action,
        "tool_name": tool,
        "params": request.params,
        // The arguments in host key order, which the decoded params lost.
        "arguments": serde_json::to_value(&request.arguments).map_err(|_| IDENTITY_FAILED)?,
        "identity": serde_json::to_value(identity).map_err(|_| IDENTITY_FAILED)?,
        "decision": decision.to_value(),
    });
    // `allow_tool_call(remember=True, emit_runtime_evidence=False)`, which the
    // drain performs before the forward's own record.
    if remembered {
        evidence["remember"] = json!(true);
    }
    if let Some(append) = evidence_append {
        evidence["evidence_append"] = Value::Array(append);
    }
    // The silent inbox row the drain writes after the block receipt.
    if let Some(review) = review {
        evidence["review"] = review;
    }
    // The approval-center surface the proxy raises once the row is written.
    if let Some(approval) = approval {
        evidence["approval"] = approval;
    }
    match blocked {
        // The relay commits the ticket once the child answered the forward.
        None => policy_store
            .mcp_relay_pending()
            .hold(evidence, Instant::now())
            .map(|ticket| Answer::Forward { ticket })
            .ok_or(EVIDENCE_FULL),
        Some(block) if policy_store.direct_evidence().offer(evidence) => Ok(block),
        Some(_) => Err(EVIDENCE_FULL),
    }
}

/// Answer one decided package call.
///
/// A leg the package policy decided is answered here and queues the receipt
/// the drain writes it from: the package request's own, not the tool call's.
/// A leg the tool policy decided is the plain tool-policy response the proxy
/// renders for any other call, so it goes through `settle` and leaves the
/// ordinary `mcp_tool_call` receipt against the tool artifact. The decision it
/// is answered under is `resolved.decision`, which is the re-resolution the
/// lane composed from: both are `run_policy` over the same subject on the
/// snapshot this decide still holds.
pub(super) fn settle_package(
    request: &McpRelayDecideRequestV1,
    admitted: &Admitted,
    resolved: &Resolved,
    packaged: &package_leg::Packaged,
    policy_store: &PolicySnapshotStore,
) -> Result<Answer, &'static str> {
    let queued;
    let answer = match &packaged.outcome {
        package_lane::PackageOutcome::Answered(answer) => answer,
        // The row the bound `ask` mode writes reads the store this holds, so
        // the answer is only completed here.
        package_lane::PackageOutcome::AskPackage(asked) => {
            queued = package_ask::queue(request, admitted, resolved, &packaged.artifact, asked)?;
            &queued
        }
        // So do the observed rows the forward is queued with, which the
        // answer carries the notices of once they are written.
        package_lane::PackageOutcome::ObservePackage { answer, observed } => {
            queued = package_observe::queue(
                request,
                admitted,
                resolved,
                &packaged.artifact,
                answer,
                observed,
            )?;
            &queued
        }
        // Nothing is answered and nothing is written: the rows are held
        // against a ticket, and the call is decided again once the claim that
        // spends them commits.
        package_lane::PackageOutcome::ClaimPackage(leg) => {
            let claimed = package_claim::claimed(leg, resolved, &packaged.artifact)?;
            let context = PackageClaimContext {
                request: request.clone(),
                admitted: admitted.clone(),
                claimed,
            };
            return policy_store
                .mcp_relay_claims()
                .hold(HeldClaim::Package(context), Instant::now())
                .map(|ticket| Answer::Claim { ticket })
                .ok_or(EVIDENCE_FULL);
        }
        package_lane::PackageOutcome::ToolLeg(leg) => {
            let routed = match leg {
                ToolLeg::StoredBlock => Routed::StoredBlock {
                    package_request: true,
                },
                ToolLeg::Terminal { policy_action } => Routed::Terminal {
                    policy_action: policy_action.clone(),
                },
                ToolLeg::Queue { policy_action } => {
                    let mode = admitted.blocked_request_mode();
                    match mode {
                        Some(ASK_MODE) => {
                            ask::queue(request, admitted, resolved, policy_action.clone())?
                        }
                        _ => queue::safe_alternative(
                            mode,
                            resolved.redaction_level.as_deref(),
                            admitted.binding.review.approval_center_origin.as_deref(),
                            policy_action.clone(),
                        )?,
                    }
                }
            };
            return settle(request, resolved, routed, None, policy_store);
        }
    };
    let identity = serde_json::to_value(&resolved.identity).map_err(|_| IDENTITY_FAILED)?;
    let evidence = package_receipt::record(
        request,
        &identity,
        &resolved.decision,
        &packaged.artifact,
        &packaged.workspace,
        answer,
        admitted.binding.review.approval_center_origin.as_deref(),
    )?;
    let mut evidence = evidence;
    // The forward an inline approval led to, as `_record_package_forward`
    // records it. The observed forward is recorded without it.
    let forwarded =
        answer.block.is_none() && answer.decision_source != package_observe::OBSERVE_SOURCE;
    if let Some(remembered) = request.inline.remembered.as_ref().filter(|_| forwarded) {
        package_prompt::mark_forward(remembered, &mut evidence);
    }
    match answer.block.clone() {
        // As for a tool call, the relay commits the ticket once the child
        // answered the forward.
        None => policy_store
            .mcp_relay_pending()
            .hold(evidence, Instant::now())
            .map(|ticket| Answer::Forward { ticket })
            .ok_or(EVIDENCE_FULL),
        Some((message, data)) if policy_store.direct_evidence().offer(evidence) => {
            Ok(Answer::Block { message, data })
        }
        Some(_) => Err(EVIDENCE_FULL),
    }
}
