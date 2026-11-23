//! One decide request, from admission to its settled answer.

use super::*;
use crate::mcp_relay_receipt::remember::{save_now, Allow};
use guard_contracts::{McpInlineApprovalV1, McpToolPolicyProxyInputV1};
use rusqlite::Connection;
use std::time::Instant;

/// The evaluation leg of a package call, when this decide is one.
///
/// The package lane decides from an evaluation whose archive and registry
/// rounds the relay performs, which no single round trip can hold. So the
/// first decide of a package call asks for it, and the relay decides the same
/// call again with the evaluation attached. A relay whose rounds did not
/// settle says so instead, and that decide is the refusal: asking again for an
/// evaluation that is not coming would only ask the relay for the rounds it
/// already failed. The call is refused in place, and the server stays with the
/// relay.
pub(super) fn evaluation_leg(
    request: &McpRelayDecideRequestV1,
    is_package: bool,
) -> Option<Result<Answer, &'static str>> {
    if !is_package || request.package_evaluation.is_some() {
        return None;
    }
    if request.package_evaluation_unsettled {
        return Some(Err(package_leg::EVALUATION_ABSENT));
    }
    Some(Ok(Answer::Evaluate { ticket: None }))
}

pub(super) fn decide(
    request: &McpRelayDecideRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<Answer, &'static str> {
    let mut again = None;
    let answer = decide_once(request, policy_store, &mut again);
    // An inline approval of a package call saved the tool allow; the call is
    // decided once more, with the approval marked and every lease and
    // snapshot of the first pass released.
    match (answer, again) {
        (Err(package_prompt::AGAIN), Some(marked)) => decide_once(&marked, policy_store, &mut None),
        (Err(package_prompt::AGAIN), None) => Err(ROUTE_UNSUPPORTED),
        (answer, _) => answer,
    }
}

fn decide_once(
    request: &McpRelayDecideRequestV1,
    policy_store: &PolicySnapshotStore,
    again: &mut Option<McpRelayDecideRequestV1>,
) -> Result<Answer, &'static str> {
    policy_store
        .require_guard_home(&request.guard_home)
        .map_err(|_| BINDING_INCOMPLETE)?;
    let admitted = admit(request, policy_store)?;
    // Keep authority fixed through routing and evidence finalization, not
    // only while the tool policy is evaluated.
    let _command_lease = policy_store
        .command_authority_lease(&admitted.snapshot)
        .map_err(|_| BINDING_INCOMPLETE)?;
    let intent = package::package_gate(request)?;
    if let Some(answer) = evaluation_leg(request, intent.is_some()) {
        return answer;
    }
    let connection = store::open(Path::new(&request.guard_home))?;
    // One read snapshot for the store checks and every lookup they gate, so a
    // row or state the daemon commits between them cannot slip past.
    let snapshot = connection
        .as_deref()
        .map(Connection::unchecked_transaction)
        .transpose()
        .map_err(|_| store::STORE_UNREADABLE)?;
    let mut audit = Vec::new();
    let resolved = resolve(
        request,
        &admitted,
        connection.as_deref(),
        intent.as_ref().map(PackageLeg::Decide),
        policy_store,
        &mut audit,
    );
    drop(snapshot);
    // The proxy's lookups write these before the call is answered, and keep
    // them when a later step fails, so a deferred call records them too.
    let written = store::write_audit(&request.guard_home, &audit);
    let (mut resolved, legged) = resolved?;
    written?;
    let asks = admitted.blocked_request_mode() == Some(ASK_MODE);
    // A package call is answered by its own lane, under the package policy and
    // the tool authority together, so none of the tool-only route below runs
    // for it, except the inline elicitation that route raises first under
    // `ask`. A saved package block skips it, and so does the second pass of an
    // approval already acted on.
    if let Some(packaged) = legged.as_ref().and_then(Legged::decided) {
        let prompted = asks
            && request.inline.remembered.is_none()
            && !packaged.saved_policy_blocks
            && package_prompt::prompts(request, &resolved);
        if !prompted {
            return settle_package(request, &admitted, &resolved, packaged, policy_store);
        }
        match request.inline.answer.map(inline::Reply::contract) {
            None => {
                return Ok(Answer::Elicit {
                    params: inline::prompt(
                        &request.build.server_name,
                        &request.build.tool_name,
                        &resolved.decision.summary,
                    ),
                })
            }
            Some(McpInlineApprovalV1::Fallthrough) => {
                return settle_package(request, &admitted, &resolved, packaged, policy_store)
            }
            Some(McpInlineApprovalV1::Allow) => {
                return package_prompt::approved(request, &admitted, &resolved, policy_store, again)
            }
            // A denied or invalid answer blocks the call as the tool route
            // below answers a plain call's.
            Some(McpInlineApprovalV1::Denied) => {}
        }
    }
    let proxy = crate::mcp_tool_policy_proxy::proxy_payload(
        &McpToolPolicyProxyInputV1 {
            catalog_state: request.catalog_state.clone(),
            mode: resolved.mode.clone(),
            package_present: false,
            asks_for_approval: asks,
            // `_inline_prompt_available`: the client declared the capability
            // and the proxy class raises the prompt. `OpenCodeMcpGuardProxy`
            // takes the base class's no-op, so it never prompts inline.
            inline_available: request.inline.available && request.build.harness != ask::OPENCODE,
            tool_name: request.build.tool_name.clone(),
            // The answer to the prompt the relay already raised; without one
            // the route names the `inline_approval` fact and the relay asks.
            inline_approval: request.inline.answer.map(inline::Reply::contract),
        },
        &resolved.decision,
        // What `_allow_after_native_prompt` answers for this harness, so the
        // route takes the prompt's own answer instead of naming the
        // `native_prompt` fact the resident cannot gather. The proxy asks it
        // about the decision the route names, gate and override included.
        |tool| asks.then(|| ask::native_prompt_allows(&request.build.harness, tool)),
    );
    let (proxy, downgraded) = observe::downgrade(proxy, &resolved.mode, &resolved.decision)?;
    let routed = route(
        &proxy,
        downgraded.as_ref().unwrap_or(&resolved.decision),
        request.inline.answer,
    )?;
    if routed == Routed::ObserveForward {
        // `_observe_tool_forward` records the decision without the downgrade.
        let mode = admitted.blocked_request_mode();
        let (routed, append) = observe::forward(mode, &resolved.decision)?;
        return settle(request, &resolved, routed, append, policy_store);
    }
    if let Some(decision) = downgraded {
        resolved.decision = decision;
    }
    match routed {
        Routed::Claim {
            source,
            policy_action,
        } => {
            let claimed = Claimed {
                artifact_id: resolved.identity.artifact.artifact_id.clone(),
                artifact_hash: resolved
                    .identity
                    .artifact_hash
                    .clone()
                    .ok_or(IDENTITY_FAILED)?,
                pending: resolved.decision.pending.clone().ok_or(ROUTE_UNSUPPORTED)?,
                disposition: resolved.decision.claim_disposition,
                source,
                policy_action,
            };
            let context = ClaimContext {
                request: request.clone(),
                admitted,
                claimed,
            };
            policy_store
                .mcp_relay_claims()
                .hold(HeldClaim::Tool(context), Instant::now())
                .map(|ticket| Answer::Claim { ticket })
                .ok_or(EVIDENCE_FULL)
        }
        // Phase one of the inline prompt: the relay raises it and decides the
        // call again with the answer. No evidence is written for this pass,
        // so the second decide is an ordinary full decide of the same call.
        Routed::Elicit => Ok(Answer::Elicit {
            params: inline::prompt(
                &request.build.server_name,
                &request.build.tool_name,
                &resolved.decision.summary,
            ),
        }),
        Routed::Forward {
            source,
            policy_action,
            remember: true,
        } => {
            if !policy_store
                .mcp_relay_pending()
                .has_headroom(Instant::now())
            {
                return Err(EVIDENCE_FULL);
            }
            // The remembered allow is an artifact-scoped policy write, and the
            // approval gate holds every allow to a decision while it is
            // enabled. `upsert_policy` raising `ApprovalGateError` is what
            // sends the proxy to the re-approval queue, so the resident asks
            // the gate before it forwards. The proxy wrote the allow before
            // it forwarded, so the resident saves it now too and an identical
            // repeat call reads it; when that write fails, the forward keeps
            // its flag and the drain retries the write.
            let routed =
                if ask::remembered_write_refused(&request.guard_home, &resolved.identity.artifact)?
                {
                    room_for_row(policy_store)?;
                    ask::queue(
                        request,
                        &admitted,
                        &resolved,
                        "require-reapproval".to_owned(),
                    )?
                } else {
                    let saved = remember_now(&request.guard_home, &resolved).is_some();
                    Routed::Forward {
                        source,
                        policy_action,
                        remember: !saved,
                    }
                };
            settle(request, &resolved, routed, None, policy_store)
        }
        Routed::Queue { policy_action } => {
            let mode = admitted.blocked_request_mode();
            let routed = match mode {
                // The row is written before the block is answered, as the
                // proxy queues it before it replies to the client.
                Some(ASK_MODE) => {
                    room_for_row(policy_store)?;
                    ask::queue_with_connector_setup(
                        request,
                        &admitted,
                        &resolved,
                        policy_action,
                        resolved.connector_setup.as_ref(),
                    )?
                }
                _ => queue::safe_alternative(
                    mode,
                    resolved.redaction_level.as_deref(),
                    admitted.binding.review.approval_center_origin.as_deref(),
                    policy_action,
                )?,
            };
            settle(request, &resolved, routed, None, policy_store)
        }
        routed => settle(request, &resolved, routed, None, policy_store),
    }
}

/// Save the artifact allow an inline approval remembers, before the call is
/// answered. The generation it was finalized at, or `None` when it was not
/// saved.
fn remember_now(guard_home: &str, resolved: &Resolved) -> Option<u64> {
    let artifact = &resolved.identity.artifact;
    let allow = Allow {
        harness: &artifact.harness,
        artifact_id: &artifact.artifact_id,
        artifact_hash: resolved.identity.artifact_hash.as_deref()?,
        command: artifact.command.as_deref(),
        workspace: None,
    };
    save_now(guard_home, &allow)
}
