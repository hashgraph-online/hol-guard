//! `HookDecide` — the generic hook path's decisions, answered by the resident.
//!
//! The Python hook transport gathers facts and renders host output; this op
//! owns event and action normalization, composition of the current action,
//! the lookups it permits, the final action, receipt/activity dispositions and
//! the response directive. Every query is pure and fails closed: a malformed
//! request yields a `native_hook_decision_*` error, never a default verdict.

use guard_contracts::{
    HookCompositionV1, HookDecisionPayloadV1, HookDecisionQueryV1, HookDecisionRequestV1,
    HookDecisionResultV1, HookTokenCompositionV1, HOOK_DECISION_REQUEST_SCHEMA,
    HOOK_DECISION_RESULT_SCHEMA,
};

use crate::hook_decision_compose::{compose, Composed};
use crate::hook_decision_finalize::{finalize, post_claim};

pub(crate) fn evaluate_hook_decision_request(
    request: &HookDecisionRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != HOOK_DECISION_REQUEST_SCHEMA {
        return Err("native_hook_decision_schema_mismatch".to_owned());
    }
    // A rejected query is a bound `error` reply carrying its specific code, so
    // the transport can tell a malformed request from a resident outage.
    let (status, code, payload) = match decide(&request.query) {
        Ok(payload) => ("ok", "ok".to_owned(), Some(payload)),
        Err(code) => ("error", code, None),
    };
    crate::resident_protocol::encode_response(&HookDecisionResultV1 {
        schema: HOOK_DECISION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code,
        payload,
    })
}

fn request_digest(request: &HookDecisionRequestV1) -> Result<String, String> {
    let invalid = || "native_hook_decision_request_invalid".to_owned();
    let material = serde_json::to_value(request).map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| invalid())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

pub(crate) fn decide(query: &HookDecisionQueryV1) -> Result<HookDecisionPayloadV1, String> {
    match query {
        HookDecisionQueryV1::ComposeCurrent { inputs } => Ok(match compose(inputs) {
            Err(missing) => HookDecisionPayloadV1::ComposeCurrent {
                event_name: guard_contracts::hook_event_name(&inputs.event_fields),
                needs_facts: vec![missing.to_owned()],
                composition: None,
            },
            Ok(composed) => HookDecisionPayloadV1::ComposeCurrent {
                event_name: composed.event_name.clone(),
                needs_facts: Vec::new(),
                composition: Some(Box::new(composition(inputs.has_command_text, &composed))),
            },
        }),
        HookDecisionQueryV1::PostClaimReuse { inputs } => {
            let (action, reason) = post_claim(inputs)?;
            Ok(HookDecisionPayloadV1::PostClaimReuse {
                current_action: action.as_str().to_owned(),
                validation_reason: reason.map(str::to_owned),
            })
        }
        HookDecisionQueryV1::Finalize { inputs, settled } => {
            let composed =
                compose(inputs).map_err(|_| "native_hook_decision_facts_missing".to_owned())?;
            Ok(HookDecisionPayloadV1::Finalize(Box::new(finalize(
                inputs, &composed, settled,
            )?)))
        }
    }
}

fn composition(has_command_text: bool, c: &Composed) -> HookCompositionV1 {
    let blocked_by_edge = c.edge == Some(guard_contracts::GuardAction::Block);
    let after = |granted: guard_contracts::GuardAction| {
        if blocked_by_edge {
            guard_contracts::GuardAction::Block
        } else {
            granted
        }
    };
    let own = |item: Option<&guard_contracts::GuardActionNormalization>| {
        item.map(|entry| entry.action.as_str().to_owned())
    };
    let eligibility_needed = c.event_name.as_deref() == Some("PreToolUse") && has_command_text;
    // A grant only lowers the action where a lookup is permitted and an
    // eligibility exists; otherwise the grant cannot apply.
    let granted_action = if c.grant_lookups_allowed && eligibility_needed {
        guard_contracts::GuardAction::Allow
    } else {
        c.composed
    };
    HookCompositionV1 {
        event_name: c.event_name.clone(),
        effective_event_name: c.effective_event.clone(),
        composed_action: c.composed.as_str().to_owned(),
        grant_lookups_allowed: c.grant_lookups_allowed,
        tool_eligibility_needed: eligibility_needed,
        action_with_tool_grant: after(granted_action).as_str().to_owned(),
        action_without_tool_grant: after(c.composed).as_str().to_owned(),
        permission_decision_reason: c.permission_reason.clone(),
        daemon_failure_reason: c.daemon_failure_reason.clone(),
        token: HookTokenCompositionV1 {
            current_config_action: c.current_config.as_str().to_owned(),
            daemon_hint_disposition: c.daemon_disposition.map(str::to_owned),
            daemon_hint_reason_code: c.daemon_reason_code.map(str::to_owned),
            trusted_cli_action: own(c.cli.as_ref()),
            untrusted_payload_action: own(c.payload.as_ref()),
            untrusted_payload_action_disposition: c.payload_disposition.map(str::to_owned),
            untrusted_payload_action_reason: c.ignored_payload_reason.map(str::to_owned),
        },
    }
}

#[cfg(test)]
#[path = "hook_decision_op_tests.rs"]
mod tests;
