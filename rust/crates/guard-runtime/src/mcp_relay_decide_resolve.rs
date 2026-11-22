//! Resolving a relayed call: its identity, its tool policy over the saved
//! rows the store holds, and its package leg, all on one read snapshot.

use super::policy::run_policy;
use super::{
    package_lane, package_leg, provider, store, subject, view, Admitted, Legged,
    McpRelayDecideRequestV1, PackageLeg, Resolved, BINDING_INCOMPLETE, IDENTITY_FAILED,
};
use crate::policy_decision_lookup_op::AuditEvent;
use crate::policy_store::PolicySnapshotStore;
use guard_contracts::{McpToolCallHashInputV1, McpToolCallIdentityPayloadV1};
use rusqlite::Connection;

/// Build the identity and run the tool policy, reading saved lookups on
/// `connection`, held in one transaction. A call the gate found a package
/// intent in also resolves its package leg, on that same snapshot: the lane's
/// second resolution reads the store again, so it belongs inside it. What
/// that leg is depends on who asked — a route for the decide path, the policy
/// alone for a claim that routes it by the post-claim revalidation instead.
/// The audit events its lookups raised are appended to `audit` whether or not
/// the call resolves, for the caller to write once it can
/// (`store::write_audit`): a lookup that refused a row recorded the refusal
/// even when a later step defers the call, as the proxy's lookup does.
pub(super) fn resolve(
    request: &McpRelayDecideRequestV1,
    admitted: &Admitted,
    connection: Option<&Connection>,
    leg: Option<PackageLeg<'_>>,
    policy_store: &PolicySnapshotStore,
    audit: &mut Vec<AuditEvent>,
) -> Result<(Resolved, Option<Legged>), &'static str> {
    policy_store
        .require_guard_home(&request.guard_home)
        .map_err(|_| BINDING_INCOMPLETE)?;
    let _command_lease = policy_store
        .command_authority_lease(&admitted.snapshot)
        .map_err(|_| BINDING_INCOMPLETE)?;
    let binding = &admitted.binding;
    let control_digest = binding
        .exact_action_control_digest
        .clone()
        .ok_or(BINDING_INCOMPLETE)?;
    let view = view::bound_harness_view(binding, &request.build.harness)?;
    let saved = match connection {
        Some(connection) => store::saved(
            connection,
            binding,
            &request.guard_home,
            &request.build.harness,
        )?,
        None => None,
    };
    let resolved = resolve_saved(
        request,
        admitted,
        connection,
        leg,
        &view,
        control_digest,
        saved.as_ref(),
    );
    if let Some(saved) = saved {
        audit.extend(saved.into_audit());
    }
    resolved
}

/// `resolve` once the saved rows are read: everything after the store checks.
fn resolve_saved(
    request: &McpRelayDecideRequestV1,
    admitted: &Admitted,
    connection: Option<&Connection>,
    leg: Option<PackageLeg<'_>>,
    view: &view::HarnessView,
    control_digest: String,
    saved: Option<&store::Saved<'_>>,
) -> Result<(Resolved, Option<Legged>), &'static str> {
    let binding = &admitted.binding;
    let identity = identity(request, view, control_digest.clone(), connection)?;
    let subject = subject::subject(request, &identity, view)?;
    let catalog = crate::contributed_mcp_decision_op::Catalog {
        guard_home: &request.guard_home,
        controls: admitted.snapshot.command_extensions.as_ref(),
    };
    let decision = run_policy(&subject, saved, connection, &catalog)?;
    let packaged = match leg {
        Some(PackageLeg::Decide(intent)) => {
            let inputs = package_leg::package_inputs(
                request,
                view,
                saved,
                &control_digest,
                &identity,
                intent,
                request.package_evaluation.as_ref(),
            )?;
            Some(Legged::Decided(Box::new(package_leg::decide_package_leg(
                request,
                inputs,
                &subject,
                &catalog,
                // The queue route of the package lane is answered by the same
                // mode and redaction level the tool lane's queue route is: the
                // bound ones, else the session config's.
                package_lane::QueueBinding {
                    blocked_request_mode: admitted.blocked_request_mode(),
                    redaction_level: admitted
                        .redaction_level(view.receipt_redaction_level.as_deref()),
                },
            )?)))
        }
        Some(PackageLeg::Claimed(intent, evaluation)) => Some(Legged::Reresolved(Box::new(
            package_leg::reresolve_package_leg(
                request,
                view,
                saved,
                &control_digest,
                &identity,
                intent,
                evaluation,
            )?,
        ))),
        None => None,
    };
    Ok((
        Resolved {
            identity,
            decision,
            mode: view.mode.clone(),
            redaction_level: admitted
                .redaction_level(view.receipt_redaction_level.as_deref())
                .map(str::to_owned),
        },
        packaged,
    ))
}

/// The artifact and approval-context token `build_tool_call_identity` makes.
pub(super) fn identity(
    request: &McpRelayDecideRequestV1,
    view: &view::HarnessView,
    control_digest: String,
    connection: Option<&Connection>,
) -> Result<McpToolCallIdentityPayloadV1, &'static str> {
    let mut build = request.build.clone();
    build.provider_catalog_hash = provider_catalog_hash(request, connection)?;
    let (artifact, private) =
        crate::mcp_tool_call_identity_build::build_artifact(&build).map_err(|_| IDENTITY_FAILED)?;
    let input = McpToolCallHashInputV1 {
        arguments: guard_command::mcp_tool_signals::risk_arguments(&request.arguments),
        config: Some(view.hash_config.clone()),
        workspace: Some(request.hash_workspace.clone()),
        extension_control_digest: Some(control_digest),
    };
    let hashed = crate::context_digest::build_mcp_tool_approval(
        &crate::mcp_tool_call_identity_op::hash_request(&artifact, &input),
    )
    .map_err(|_| IDENTITY_FAILED)?;
    Ok(McpToolCallIdentityPayloadV1 {
        artifact,
        runtime_private_metadata: private,
        artifact_hash: Some(hashed.token_or_digest),
        risk_categories: hashed.risk_categories,
    })
}

/// The provider catalog hash a Composio wrapper's identity binds, which the
/// proxy reads from the store (`read_mcp_provider_authority_hash`) and no
/// other tool carries. A Composio call from a relay that did not leave the
/// hash to this resident is refused rather than hashed without it.
pub(super) fn provider_catalog_hash(
    request: &McpRelayDecideRequestV1,
    connection: Option<&Connection>,
) -> Result<Option<String>, &'static str> {
    if !crate::mcp_relay_servers::composio_tool(&request.build.tool_name) {
        return Ok(None);
    }
    if !request.resident_provider_catalog {
        return Err(IDENTITY_FAILED);
    }
    provider::authority_hash(connection)
}
