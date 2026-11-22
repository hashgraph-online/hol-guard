//! One decide request, from admission to its settled answer.

use super::*;
use guard_contracts::McpToolPolicyProxyInputV1;
use rusqlite::Connection;
use std::time::Instant;

/// The evaluation leg of a package call, when this decide is one.
///
/// The package lane decides from an evaluation whose archive and registry
/// rounds the relay performs, which no single round trip can hold. So the
/// first decide of a package call asks for it, and the relay decides the same
/// call again with the evaluation attached. A relay whose rounds did not
/// settle says so instead, and that decide is the refusal: asking again for an
/// evaluation that is not coming would refuse the call in every later session
/// too, where the refusal hands the server to the proxy.
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
    // for it. The inline elicitation that route raises first under `ask` is
    // the proxy's.
    if let Some(packaged) = legged.as_ref().and_then(Legged::decided) {
        if asks
            && ask::prompts_before_package(
                &request.catalog_state,
                &resolved.mode,
                &request.build.tool_name,
                &request.build.harness,
                request.inline.available,
                &resolved.decision,
            )
        {
            return Err(ask::PACKAGE_PROMPT);
        }
        return settle_package(request, &admitted, &resolved, packaged, policy_store);
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
            // The remembered allow is an artifact-scoped policy write, and the
            // approval gate holds every allow to a decision while it is
            // enabled. `upsert_policy` raising `ApprovalGateError` is what
            // sends the proxy to the re-approval queue, so the resident asks
            // the gate before it forwards and the drain performs the write.
            let routed =
                if ask::remembered_write_refused(&request.guard_home, &resolved.identity.artifact)?
                {
                    ask::queue(
                        request,
                        &admitted,
                        &resolved,
                        "require-reapproval".to_owned(),
                    )?
                } else {
                    Routed::Forward {
                        source,
                        policy_action,
                        remember: true,
                    }
                };
            settle(request, &resolved, routed, None, policy_store)
        }
        Routed::Queue { policy_action } => {
            let mode = admitted.blocked_request_mode();
            let routed = match mode {
                // The row is written before the block is answered, as the
                // proxy queues it before it replies to the client.
                Some(ASK_MODE) => ask::queue(request, &admitted, &resolved, policy_action)?,
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
