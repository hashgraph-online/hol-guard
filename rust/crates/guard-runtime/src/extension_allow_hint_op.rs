//! `extension_allow_hint` -- resident op naming the configurable extension
//! permissions whose Allow state would let a reviewed command run.
//!
//! The decision re-runs the command evaluator the `command_effect_decide` op
//! uses, under the resident's own admitted control snapshot, with hypothetical
//! enabled permissions. It never mutates authority and answers catalog
//! identifiers only. A hint is offered only when the review is an extension
//! review: not under an authority failure (a device that never enrolled is
//! judged as it will be once enrolled), not under a fixed PreTool floor, and
//! only when enabling the matched configurable permissions makes the command
//! allow. The set is then minimized so a rule that does not gate is not named.

use std::time::{Duration, Instant};

use guard_command::native_command_controls::CompiledNativeCommandControls;
use guard_contracts::{
    CommandEffectRequestV1, ExtensionAllowHintPayloadV1, ExtensionAllowHintQueryV1,
    ExtensionAllowHintRequestV1, ExtensionAllowHintResultV1, ExtensionAllowHintV1,
    COMMAND_EFFECT_REQUEST_SCHEMA, EXTENSION_ALLOW_HINT_MAX_BYTES,
    EXTENSION_ALLOW_HINT_MAX_PERMISSIONS, EXTENSION_ALLOW_HINT_MAX_RELIED,
    EXTENSION_ALLOW_HINT_QUERY_KIND, EXTENSION_ALLOW_HINT_REQUEST_SCHEMA,
    EXTENSION_ALLOW_HINT_RESULT_SCHEMA, EXTENSION_ALLOW_HINT_SCHEMA,
};
use serde_json::Value;

use crate::command_effect::{
    evaluate_composite_under, with_store, AuthorityView, EvaluatedCommand,
};
use crate::package_authority_op::request_digest_with_limit;

/// The only reason code of a native review that an extension Allow can settle.
const EXTENSION_REVIEW_REASON: &str = "native_command_review_required";

/// The first matched rule that named a permission, and the extension owning it.
struct Owner {
    permission_id: String,
    rule_id: String,
    extension_id: String,
}

pub(crate) fn evaluate_with_store(
    request: &ExtensionAllowHintRequestV1,
    store: Option<&crate::policy_store::PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    with_store(store, |controls| {
        evaluate_extension_allow_hint(request, controls)
    })
}

pub(crate) fn evaluate_extension_allow_hint(
    request: &ExtensionAllowHintRequestV1,
    controls: Option<&CompiledNativeCommandControls>,
) -> Result<Vec<u8>, String> {
    // Bound the complete canonical request before any decision work; an
    // oversized request has no digest to bind.
    let request_sha256 = request_digest_with_limit(request, EXTENSION_ALLOW_HINT_MAX_BYTES)
        .map_err(|_| "native_extension_allow_hint_too_large".to_owned())?;
    let (status, code, payload) = match decide(request, controls) {
        Ok(hint) => (
            "ok",
            "ok".to_owned(),
            Some(ExtensionAllowHintPayloadV1 {
                kind: EXTENSION_ALLOW_HINT_QUERY_KIND.to_owned(),
                hint,
            }),
        ),
        Err(code) => ("error", code, None),
    };
    crate::encode_response(&ExtensionAllowHintResultV1 {
        schema: EXTENSION_ALLOW_HINT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code,
        payload,
    })
}

fn decide(
    request: &ExtensionAllowHintRequestV1,
    controls: Option<&CompiledNativeCommandControls>,
) -> Result<Option<ExtensionAllowHintV1>, String> {
    if request.schema != EXTENSION_ALLOW_HINT_REQUEST_SCHEMA {
        return Err("native_extension_allow_hint_schema_mismatch".to_owned());
    }
    let query = &request.query;
    if query.kind != EXTENSION_ALLOW_HINT_QUERY_KIND {
        return Err("native_extension_allow_hint_kind_invalid".to_owned());
    }
    // A fixed floor needs no evaluation, and none is run under the lease for it.
    if !is_extension_review(&query.native_extension_evidence) {
        return Ok(None);
    }
    let started = Instant::now();
    let base = evaluate_with(query, &[], controls)?;
    if base.authority_failure
        || !matches!(
            base.evaluation.decision_plane.action.as_str(),
            "review" | "require-reapproval"
        )
    {
        return Ok(None);
    }
    let Some((owners, relied)) = candidate_permissions(&base) else {
        return Ok(None);
    };
    let allows = |permission_ids: &[String]| -> bool {
        evaluate_with(query, permission_ids, controls).is_ok_and(|counterfactual| {
            counterfactual.evaluation.decision_plane.action.as_str() == "allow"
                && counterfactual.evaluation.minimum_action.as_str() == "allow"
        })
    };
    let mut permission_ids: Vec<String> = owners
        .iter()
        .map(|owner| owner.permission_id.clone())
        .collect();
    if !allows(&permission_ids) {
        return Ok(None);
    }
    // A matched rule that does not gate (for example a disabled-by-default one)
    // must not be named: keep only the permissions the Allow actually needs.
    let budget = query
        .reduction_budget_ms
        .map(|milliseconds| Duration::from_millis(u64::from(milliseconds)));
    for candidate in permission_ids.clone() {
        if budget.is_some_and(|limit| started.elapsed() >= limit) {
            break;
        }
        let remaining: Vec<String> = permission_ids
            .iter()
            .filter(|permission_id| **permission_id != candidate)
            .cloned()
            .collect();
        if !remaining.is_empty() && allows(&remaining) {
            permission_ids = remaining;
        }
    }
    let mut rule_ids: Vec<String> = Vec::new();
    let mut extension_ids: Vec<String> = Vec::new();
    for permission_id in &permission_ids {
        let Some(owner) = owners
            .iter()
            .find(|owner| owner.permission_id == *permission_id)
        else {
            continue;
        };
        if !rule_ids.contains(&owner.rule_id) {
            rule_ids.push(owner.rule_id.clone());
        }
        if !extension_ids.contains(&owner.extension_id) {
            extension_ids.push(owner.extension_id.clone());
        }
    }
    Ok(Some(ExtensionAllowHintV1 {
        schema: EXTENSION_ALLOW_HINT_SCHEMA.to_owned(),
        permission_ids,
        rule_ids,
        extension_ids,
        relied_permission_ids: relied,
        catalog_digest: base.registry.catalog_digest.clone(),
    }))
}

/// A fixed PreTool floor (sensitive access, Guard self-protection, ...) reviews
/// whatever the extensions say, so no extension Allow can settle it and no hint
/// may promise otherwise. Real native results always carry the reason; its
/// absence is not the extension review either.
fn is_extension_review(evidence: &Value) -> bool {
    let Some(object) = evidence.as_object() else {
        return true;
    };
    object.get("minimum_action").and_then(Value::as_str) != Some("block")
        && object.get("reason_code").and_then(Value::as_str) == Some(EXTENSION_REVIEW_REASON)
}

/// The configurable permissions the matched rules name, in match order, and the
/// already-enabled ones the answer relies on. `None` when no permission change
/// could apply or the hint would exceed its bounds.
fn candidate_permissions(base: &EvaluatedCommand) -> Option<(Vec<Owner>, Vec<String>)> {
    let enabled = &base
        .evaluation
        .control_resolution
        .explicitly_enabled_permission_ids;
    let mut owners: Vec<Owner> = Vec::new();
    let mut relied: Vec<String> = Vec::new();
    for owned in &base.evaluation.matches {
        let rule_id = &owned.rule.rule_id;
        let Some(permission) = base.registry.permission_for_rule_id(rule_id) else {
            continue;
        };
        if !permission.configurable {
            continue;
        }
        if enabled.contains(&permission.permission_id) {
            // The counterfactual only holds while this permission stays enabled.
            if !relied.contains(&permission.permission_id) {
                relied.push(permission.permission_id.clone());
            }
            continue;
        }
        if !owners
            .iter()
            .any(|owner| owner.permission_id == permission.permission_id)
        {
            owners.push(Owner {
                permission_id: permission.permission_id.clone(),
                rule_id: rule_id.clone(),
                extension_id: permission.extension_id.clone(),
            });
        }
    }
    if owners.is_empty()
        || owners.len() > EXTENSION_ALLOW_HINT_MAX_PERMISSIONS
        || relied.len() > EXTENSION_ALLOW_HINT_MAX_RELIED
    {
        return None;
    }
    Some((owners, relied))
}

/// Evaluate the query's command with `permission_ids` hypothetically enabled,
/// as the device would judge it once its authority is enrolled. A device that
/// never enrolled gets the answer it would get after setup, and the
/// recommendation says setup comes first. Any other authority failure still
/// has no hint.
fn evaluate_with(
    query: &ExtensionAllowHintQueryV1,
    permission_ids: &[String],
    controls: Option<&CompiledNativeCommandControls>,
) -> Result<EvaluatedCommand, String> {
    evaluate_composite_under(
        &CommandEffectRequestV1 {
            schema: COMMAND_EFFECT_REQUEST_SCHEMA.to_owned(),
            request_id: String::new(),
            command_text: query.command_text.clone(),
            canonical_command: query.canonical_command.clone(),
            compatibility_action_class: None,
            compatibility_reason: None,
            native_extension_evidence: query.native_extension_evidence.clone(),
            control_snapshot: query.control_snapshot.clone(),
            workflow_authorization: None,
            cwd: query.cwd.clone(),
            home_dir: query.home_dir.clone(),
            counterfactual_enabled_permission_ids: permission_ids.to_vec(),
        },
        controls,
        AuthorityView::OnceEnrolled,
    )
}

#[cfg(test)]
#[path = "extension_allow_hint_op_tests.rs"]
mod tests;
