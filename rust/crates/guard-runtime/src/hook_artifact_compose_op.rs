//! `HookArtifactCompose` — resident decision composition for artifact hooks.
//!
//! Python gathers evidence; this op owns every verdict: the current-action
//! lattice composition (config, trusted CLI action, untrusted payload hint,
//! native floors, package, data-flow, scanner), local-grant eligibility and
//! settlement, and the risk copy that accompanies the composed action. The
//! reuse, override, and copy queries live in `hook_artifact_compose_reuse`,
//! and the prompt-request reason in `hook_artifact_compose_prompt`.
//! Every query is pure and fails closed: unknown actions normalize to review.

use guard_contracts::{
    compose_action_from_signals, normalize_guard_action, normalize_guard_action_result,
    GrantSettleQueryV1, GuardAction, HookArtifactComposeQueryV1, HookArtifactComposeRequestV1,
    HookArtifactComposeResultV1, HookNativeEdgeV1, NativeEdgeFactsV1,
    ObserveExecutableActionQueryV1, PolicyStackQueryV1, RiskSignalV2, SignalCompositionQueryV1,
    HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA, HOOK_ARTIFACT_COMPOSE_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::hook_artifact_compose_package_firewall as package_firewall;
use crate::hook_artifact_compose_package_firewall_entitlement as package_firewall_entitlement;
use crate::hook_artifact_compose_policy_lookup as lookup;
use crate::hook_artifact_compose_policy_tail as policy_tail;
use crate::hook_artifact_compose_prompt as prompt;
use crate::hook_artifact_compose_reuse as reuse;
use crate::hook_decision_compose::{edge_action, edge_floor, is_hard};
use crate::hook_policy_config::{artifact_policy_action, data_flow_configured_action};

pub(crate) fn evaluate_hook_artifact_compose_request(
    request: &HookArtifactComposeRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != HOOK_ARTIFACT_COMPOSE_REQUEST_SCHEMA {
        return Err("native_hook_artifact_compose_schema_mismatch".to_owned());
    }
    let (status, code, payload) = match compose(&request.query) {
        Ok(payload) => ("ok", "ok", payload),
        Err(message) => (
            "error",
            "native_hook_artifact_compose_validation_refused",
            json!({"error_type": "ValueError", "message": message.chars().take(1024).collect::<String>()}),
        ),
    };
    crate::resident_protocol::encode_response(&HookArtifactComposeResultV1 {
        schema: HOOK_ARTIFACT_COMPOSE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload: Some(payload),
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

pub(crate) fn compose(query: &HookArtifactComposeQueryV1) -> Result<Value, String> {
    Ok(match query {
        HookArtifactComposeQueryV1::PolicyStack(query) => policy_stack(query),
        HookArtifactComposeQueryV1::ConfigAction(query) => {
            let mut events = Vec::new();
            let action = artifact_policy_action(&query.policy_config, &query.artifact, &mut events);
            json!({"action": action.as_str(), "auto_stop_events": events})
        }
        HookArtifactComposeQueryV1::ToolGrantApply => json!({
            "current_policy_action": "allow",
            "policy_action": "allow",
            "approval_context_policy_action": "allow",
        }),
        HookArtifactComposeQueryV1::GrantSettle(query) => grant_settle(query),
        HookArtifactComposeQueryV1::ObserveExecutableAction(query) => {
            observe_executable_action(query)
        }
        HookArtifactComposeQueryV1::SavedReuse(query) => reuse::saved_reuse(query),
        HookArtifactComposeQueryV1::SavedBlockReuse {
            current_action,
            policy_action,
            stored_artifact_hash,
        } => reuse::saved_block_reuse(current_action, policy_action, stored_artifact_hash),
        HookArtifactComposeQueryV1::TrustedOverride(query) => reuse::trusted_override(query),
        HookArtifactComposeQueryV1::ClaimedReuse(query) => reuse::claimed_reuse(query),
        HookArtifactComposeQueryV1::DecisionCopy(query) => reuse::decision_copy(query),
        HookArtifactComposeQueryV1::DecisionBuildCopy(query) => reuse::decision_build_copy(query)?,
        HookArtifactComposeQueryV1::PolicyLookupSelect(query) => {
            lookup::policy_lookup_select(query)?
        }
        HookArtifactComposeQueryV1::PromptRequestReason(query) => {
            prompt::prompt_request_reason(query)
        }
        HookArtifactComposeQueryV1::RememberedRuleReason(query) => {
            reuse::remembered_rule_reason(query)
        }
        HookArtifactComposeQueryV1::PackageReuseSettle(query) => reuse::package_reuse_settle(query),
        HookArtifactComposeQueryV1::PackageFirewallEntitlement(query) => {
            package_firewall_entitlement::package_firewall_entitlement(query)?
        }
        HookArtifactComposeQueryV1::PackageFirewallAccess(query) => {
            package_firewall::package_firewall_access(query)?
        }
        HookArtifactComposeQueryV1::SignalComposition(query) => signal_composition(query)?,
        HookArtifactComposeQueryV1::PolicyComposition(query) => {
            policy_tail::policy_composition(query)
        }
    })
}

/// `compose_action_from_signals` over a detector run. The signals decode
/// strictly: a payload the detector contract rejects refuses the request
/// rather than composing over a signal this side guessed at.
fn signal_composition(query: &SignalCompositionQueryV1) -> Result<Value, String> {
    let mut signals = Vec::with_capacity(query.signals.len());
    for (index, payload) in query.signals.iter().enumerate() {
        let signal = RiskSignalV2::decode(payload)
            .map_err(|error| format!("signals[{index}] is not a risk signal: {}", error.0))?;
        signals.push(signal);
    }
    let composed = compose_action_from_signals(&signals, &query.base_action);
    Ok(json!({
        "action": composed.action.as_str(),
        "reason": composed.reason,
        "downgraded": composed.downgraded,
        "upgraded": composed.upgraded,
        "normalization_reason_code": composed.normalization_reason_code,
        "original_action": composed.original_action,
    }))
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

/// The native edge verdict as a floor on the artifact composition. Before
/// execution only a hard verdict floors; after it a hard verdict keeps the
/// output reviewable rather than undoing the finished action.
fn native_edge_floor(
    edge: &NativeEdgeFactsV1,
    default_action: Option<&str>,
) -> Option<GuardAction> {
    let event = edge.event_name.as_deref();
    if event == Some("PreToolUse")
        && edge.package_request
        && edge.reason_code.as_str() == Some("native_command_extension_evaluation_failed")
    {
        // Package requests have their own fail-closed evaluator. A generic
        // command-control failure is not a second package verdict.
        return None;
    }
    match event {
        Some("PreToolUse") => {
            // Only an explicit hard verdict floors before execution; a bare
            // deny stays provenance for native command review to price.
            let explicit = HookNativeEdgeV1 {
                policy_action: edge.policy_action.clone(),
                minimum_action: edge.minimum_action.clone(),
                decision: Value::Null,
                reason_code: edge.reason_code.clone(),
            };
            edge_floor(Some(&explicit), event)
        }
        Some("PostToolUse") => {
            let typed = HookNativeEdgeV1 {
                policy_action: edge.policy_action.clone(),
                minimum_action: edge.minimum_action.clone(),
                decision: edge.decision.clone(),
                reason_code: edge.reason_code.clone(),
            };
            if default_action == Some("warn") && is_hard(edge_action(&typed)) {
                // The edge still masks output already priced as warn-tier evidence.
                return None;
            }
            edge_floor(Some(&typed), event)
        }
        // Other events take their floors from native review and artifact
        // classes; the edge verdict is provenance there.
        _ => None,
    }
}

fn policy_stack(query: &PolicyStackQueryV1) -> Value {
    let cli = (!query.cli_action.is_null())
        .then(|| normalize_guard_action_result(&query.cli_action, GuardAction::RequireReapproval));
    let payload = query.payload_action_present.then(|| {
        normalize_guard_action_result(&query.payload_action, GuardAction::RequireReapproval)
    });
    let mut auto_stop_events = Vec::new();
    let config_action =
        artifact_policy_action(&query.policy_config, &query.runtime, &mut auto_stop_events);
    let context_config = artifact_policy_action(
        &query.policy_config,
        &query.approval_context,
        &mut auto_stop_events,
    );
    let edge = query
        .native_edge
        .as_ref()
        .and_then(|edge| native_edge_floor(edge, query.runtime.guard_default_action.as_deref()));
    let native_floor = [present(&query.native_floor), edge]
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
        let configured = data_flow_configured_action(&query.policy_config, query.data_flow_strong);
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
        "local_eligibility_required": policy_tail::local_eligibility_required(query),
        "native_floor": native_floor.map(GuardAction::as_str),
        "normalizer_evidence": normalizer_evidence,
        "risk_signals": risk_signals,
        "risk_summary": risk_summary,
        "auto_stop_events": auto_stop_events,
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
    let floor = present(&query.native_floor);
    // A CLI grant vouches for the CLI a command launches, not for the
    // privileged wrapper around it: a require-reapproval floor asks for this
    // exact command to be approved again, so a grant never settles below it.
    let granted = match floor {
        Some(GuardAction::RequireReapproval) => {
            stricter(act(&query.granted_action), GuardAction::RequireReapproval)
        }
        _ => act(&query.granted_action),
    };
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
    if let Some(floor) = floor {
        context = stricter(context, floor);
    }
    let mut result = Map::new();
    result.insert("current_policy_action".into(), name(current));
    result.insert("policy_action".into(), name(policy));
    result.insert("approval_context_policy_action".into(), name(context));
    Value::Object(result)
}

/// The action observe mode records as the one that would have executed.
///
/// Observe mode removes the gates that would have stopped the work, so the
/// answer is composed only from sources that let work through: an `allow` or a
/// `warn`. A source that asked for a review or a block is exactly what observe
/// mode suppressed, so it names nothing here. With no executable source the
/// answer is `allow` -- nothing stood between the harness and the work.
fn observe_executable_action(query: &ObserveExecutableActionQueryV1) -> Value {
    let sources = [
        &query.current_config_action,
        &query.current_action_override,
        &query.trusted_cli_override,
        &query.untrusted_hook_payload_hint,
        &query.package_action,
        &query.data_flow_action,
        &query.scanner_action,
        &query.package_evaluation_action,
    ];
    let executable = sources
        .into_iter()
        .filter_map(coerce)
        .filter(|action| matches!(action, GuardAction::Allow | GuardAction::Warn))
        .fold(GuardAction::Allow, stricter);
    json!({ "executable_action": name(executable) })
}

#[cfg(test)]
#[path = "hook_artifact_compose_op_tests.rs"]
mod tests;
