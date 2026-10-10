//! `HookArtifactCompose` — resident decision composition for artifact hooks.
//!
//! Python gathers evidence; this op owns every verdict: the current-action
//! lattice composition (config, trusted CLI action, untrusted payload hint,
//! native floors, package, data-flow, scanner), local-grant eligibility and
//! settlement, and the risk copy that accompanies the composed action. The
//! reuse, override, and copy queries live in `hook_artifact_compose_reuse`.
//! Every query is pure and fails closed: unknown actions normalize to review.

use guard_contracts::{
    normalize_guard_action, normalize_guard_action_result, GrantSettleQueryV1, GuardAction,
    HookArtifactComposeQueryV1, HookArtifactComposeRequestV1, HookArtifactComposeResultV1,
    PolicyStackQueryV1, HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA, HOOK_ARTIFACT_COMPOSE_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::hook_artifact_compose_reuse as reuse;

pub(crate) fn evaluate_hook_artifact_compose_request(
    request: &HookArtifactComposeRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA {
        return Err("native_hook_artifact_compose_schema_mismatch".to_owned());
    }
    crate::resident_protocol::encode_response(&HookArtifactComposeResultV1 {
        schema: HOOK_ARTIFACT_COMPOSE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(compose(&request.query)),
    })
}

fn request_digest(request: &HookArtifactComposeRequestV1) -> Result<String, String> {
    let invalid = || "native_hook_artifact_compose_request_invalid".to_owned();
    let material = serde_json::to_value(request).map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| invalid())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

pub(crate) fn compose(query: &HookArtifactComposeQueryV1) -> Value {
    match query {
        HookArtifactComposeQueryV1::PolicyStack(query) => policy_stack(query),
        HookArtifactComposeQueryV1::ToolGrantApply => json!({
            "current_policy_action": "allow",
            "policy_action": "allow",
            "approval_context_policy_action": "allow",
        }),
        HookArtifactComposeQueryV1::GrantSettle(query) => grant_settle(query),
        HookArtifactComposeQueryV1::SavedReuse(query) => reuse::saved_reuse(query),
        HookArtifactComposeQueryV1::SavedBlockReuse {
            current_action,
            policy_action,
            stored_artifact_hash,
        } => reuse::saved_block_reuse(current_action, policy_action, stored_artifact_hash),
        HookArtifactComposeQueryV1::TrustedOverride(query) => reuse::trusted_override(query),
        HookArtifactComposeQueryV1::ClaimedReuse(query) => reuse::claimed_reuse(query),
        HookArtifactComposeQueryV1::DecisionCopy(query) => reuse::decision_copy(query),
    }
}

pub(crate) fn act(value: &Value) -> GuardAction {
    normalize_guard_action(value, GuardAction::Review)
}

pub(crate) fn coerce(value: &Value) -> Option<GuardAction> {
    value.as_str().and_then(GuardAction::from_canonical)
}

pub(crate) fn name(action: GuardAction) -> Value {
    Value::String(action.as_str().to_owned())
}

pub(crate) use guard_contracts::most_restrictive_of as stricter;

fn present(value: &Value) -> Option<GuardAction> {
    (!value.is_null()).then(|| act(value))
}

fn dedup(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for item in items {
        if !seen.contains(&item) {
            seen.push(item);
        }
    }
    seen
}

fn policy_stack(query: &PolicyStackQueryV1) -> Value {
    let cli = (!query.cli_action.is_null())
        .then(|| normalize_guard_action_result(&query.cli_action, GuardAction::RequireReapproval));
    let payload = query.payload_action_present.then(|| {
        normalize_guard_action_result(&query.payload_action, GuardAction::RequireReapproval)
    });
    let config_action = coerce(&query.config_action).unwrap_or(GuardAction::Warn);
    let context_config = coerce(&query.approval_context_config_action).unwrap_or(GuardAction::Warn);
    let native_floor = [present(&query.native_floor), present(&query.edge_floor)]
        .into_iter()
        .flatten()
        .reduce(stricter);
    // Hook payloads are untrusted hints: they may make a decision stricter but
    // can never lower current local policy or suppress later scanners.
    let hints: Vec<GuardAction> = [
        cli.as_ref().map(|item| item.action),
        payload.as_ref().map(|item| item.action),
        native_floor,
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut policy = hints.iter().copied().fold(config_action, stricter);
    let mut context = hints.iter().copied().fold(context_config, stricter);

    let package_action = query.has_package.then(|| act(&query.package_policy_action));
    if let Some(package) = package_action {
        policy = stricter(policy, package);
        context = stricter(context, package);
    }
    let mut data_flow_action = None;
    let mut context_data_flow_action = None;
    if query.has_data_flow {
        let configured = coerce(&query.data_flow_configured_action);
        let flow = configured.unwrap_or(policy);
        let context_flow = configured.unwrap_or(context);
        policy = stricter(policy, flow);
        context = stricter(context, context_flow);
        data_flow_action = Some(flow);
        context_data_flow_action = Some(context_flow);
    }
    let pre_scanner = policy;
    let package_controls =
        package_action.is_some_and(|package| package.severity() >= pre_scanner.severity());
    let mut scanner_action = None;
    if query.has_scanner {
        let scanner = act(&query.scanner_action);
        policy = stricter(policy, scanner);
        context = stricter(context, scanner);
        scanner_action = Some(scanner);
    }
    let scanner_raised_to_block =
        policy == GuardAction::Block && pre_scanner != GuardAction::Block && query.has_scanner;
    let local_grants_allowed = !query.current_action_override_present
        && cli.is_none()
        && payload.is_none()
        && !query.has_data_flow
        && !query.has_scanner
        && package_action != Some(GuardAction::Block);
    let (risk_signals, risk_summary) = risk_copy(query, package_controls, scanner_raised_to_block);
    let normalizer_evidence: Vec<Value> = [
        ("trusted_cli_override", cli.as_ref()),
        ("untrusted_hook_payload_hint", payload.as_ref()),
    ]
    .into_iter()
    .filter_map(|(input_source, item)| Some((input_source, item?)))
    .filter(|(_, item)| !item.recognized())
    .map(|(input_source, item)| {
        json!({
            "source": "guard_action_normalizer",
            "input_source": input_source,
            "reason_code": item.reason_code,
            "original_action": item.original_action,
            "original_type": item.original_type,
            "normalized_action": item.action.as_str(),
        })
    })
    .collect();
    let requested = cli.as_ref().or(payload.as_ref());
    json!({
        "policy_action": policy.as_str(),
        "approval_context_policy_action": context.as_str(),
        "current_config_action": config_action.as_str(),
        "approval_context_config_action": context_config.as_str(),
        "trusted_cli_action": cli.as_ref().map(|item| item.action.as_str()),
        "untrusted_payload_action": payload.as_ref().map(|item| item.action.as_str()),
        "requested_policy_action": requested.and_then(|item| item.original_action.clone()),
        "package_policy_action": package_action.map(GuardAction::as_str),
        "data_flow_action": data_flow_action.map(GuardAction::as_str),
        "approval_context_data_flow_action": context_data_flow_action.map(GuardAction::as_str),
        "scanner_action": scanner_action.map(GuardAction::as_str),
        "scanner_raised_to_block": scanner_raised_to_block,
        "local_grants_allowed": local_grants_allowed,
        "native_floor": native_floor.map(GuardAction::as_str),
        "normalizer_evidence": normalizer_evidence,
        "risk_signals": risk_signals,
        "risk_summary": risk_summary,
    })
}

fn risk_copy(
    query: &PolicyStackQueryV1,
    package_controls: bool,
    scanner_raised_to_block: bool,
) -> (Vec<String>, String) {
    let compound = query.has_compound_findings;
    let mut signals = dedup(
        query
            .artifact_risk_signals
            .iter()
            .chain(&query.data_flow_reasons)
            .cloned(),
    );
    let mut summaries = vec![query.artifact_risk_summary.clone()];
    if let Some(summary) = query.data_flow_summary.as_ref().filter(|_| !compound) {
        summaries.push(summary.clone());
    }
    if let Some(package_summary) = &query.package_risk_summary {
        let package = query.package_risk_signals.clone();
        if compound && package_controls {
            signals = dedup(package.into_iter().chain(signals));
            summaries.insert(0, package_summary.clone());
        } else if compound {
            signals = dedup(signals.into_iter().chain(package));
            summaries.push(package_summary.clone());
        } else if package_controls {
            signals = package;
            summaries = vec![package_summary.clone()];
        }
    }
    let mut summary = dedup(summaries.into_iter().filter(|item| !item.is_empty())).join(" ");
    if let Some(primary) = query.scanner_risk_signals.first() {
        signals = dedup(
            signals
                .into_iter()
                .chain(query.scanner_risk_signals.iter().cloned()),
        );
        if scanner_raised_to_block {
            summary = if compound {
                dedup([primary.clone(), summary]).join(" ")
            } else {
                primary.clone()
            };
        }
    }
    (signals, summary)
}

fn grant_settle(query: &GrantSettleQueryV1) -> Value {
    let current = act(&query.current_action);
    let granted = act(&query.granted_action);
    let (mut current, mut policy, mut context) = (
        current,
        act(&query.policy_action),
        act(&query.approval_context_action),
    );
    if granted != current {
        current = granted;
        policy = granted;
        context = granted;
    }
    // The floor already entered the composed action, so only the approval
    // context is re-floored: it binds the identity of the review the floor
    // demanded so saved approvals still match exactly, while re-flooring the
    // policy action would re-flag a settled request forever.
    if let Some(floor) = present(&query.native_floor) {
        context = stricter(context, floor);
    }
    let mut result = Map::new();
    result.insert("current_policy_action".into(), name(current));
    result.insert("policy_action".into(), name(policy));
    result.insert("approval_context_policy_action".into(), name(context));
    Value::Object(result)
}

#[cfg(test)]
#[path = "hook_artifact_compose_op_tests.rs"]
mod tests;
